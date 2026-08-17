#!/usr/bin/env python3
"""G6b 回归测试：核心操作（test_ops.py）。

覆盖 G1-G6 各阶段核心行为：
- situation_update version 递增 + evidence_strength 校验 + progress 降级 + timeline 追加
- directive 编号 + 确定性解析器 + 状态推进 + repeat 冻结提示 + preflight
- conflict 状态机 + tree_node 标记 + disproved 级联 + stats
- freeze 四触发条件（显式/违规/待办/重复）+ release
- verification 抽样回写 + command_hint
- snapshot 角色裁剪 + truncated
- artifact 往返 + 路径穿越防护 + 截断
- tree_mark/unmark + tree_render 编号
- findings_search use_fts + 置信度快捷过滤
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

PARENT = "role:parent|agent:parent-1|tool:ida"
SUB = "role:discovery|agent:sub-1|tool:ghidra"


def seed_observation(mod, project, fact="observed: sub_4012a0 does X",
                     source=SUB, **kw):
    r = mod.store_finding(project=project, fact=fact, confidence="confirmed-observed",
                          source=source, type_="observation", **kw)
    return r["id"]


class TestSituation(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_sit"

    def test_get_default_empty_situation(self):
        s = self.mod.situation_get(self.p)
        self.assertEqual(s["version"], 1)
        self.assertEqual(s["objective"], "")
        self.assertEqual(s["progress"], [])
        self.assertEqual(s["active_work"], {})
        self.assertIsNone(s["frozen"])

    def test_version_increments_on_each_update(self):
        s1 = self.mod.situation_update(self.p, objective="solve it")
        self.assertEqual(s1["version"], 2, "首次 INSERT 也算一次更新 → 1→2")
        self.assertEqual(s1["objective"], "solve it")
        s2 = self.mod.situation_update(self.p, objective="solve it harder")
        self.assertEqual(s2["version"], 3)

    def test_project_meta_roundtrip_and_merge_semantics(self):
        # 默认空局面 project_meta = {}
        self.assertEqual(self.mod.situation_get(self.p)["project_meta"], {})
        meta = {"workdir": "/workspace/x", "repo": "https://github.com/a/b",
                "engine": "gdb", "api": "openai", "background": "RE 挑战"}
        s = self.mod.situation_update(self.p, project_meta=meta)
        self.assertEqual(s["project_meta"], meta, "整体覆盖写入后读回一致")
        # 不传 project_meta → 不覆盖（只改 objective）
        s2 = self.mod.situation_update(self.p, objective="keep meta")
        self.assertEqual(s2["project_meta"], meta, "不传 project_meta 时保留原值")
        # 整体覆盖：传新 dict 替换旧 dict
        s3 = self.mod.situation_update(self.p, project_meta={"workdir": "/new"})
        self.assertEqual(s3["project_meta"], {"workdir": "/new"}, "传 dict 整体覆盖")

    def test_project_meta_non_dict_rejected(self):
        with self.assertRaises(ValueError):
            self.mod.situation_update(self.p, project_meta=["not", "a", "dict"])
        with self.assertRaises(ValueError):
            self.mod.situation_update(self.p, project_meta="workdir=/x")
        # 非法值不落库：仍为空
        self.assertEqual(self.mod.situation_get(self.p)["project_meta"], {})

    def test_project_meta_noop_when_all_none(self):
        # 全 None → 不建行、不 bump version（既有 P1b 语义），project_meta 同样遵循
        s = self.mod.situation_update(self.p)
        self.assertEqual(s["version"], 1, "全 None 不建行不 bump")
        self.assertEqual(s["project_meta"], {})

    def test_candidate_directions_evidence_strength_validation(self):
        with self.assertRaises(ValueError):
            self.mod.situation_update(self.p, candidate_directions=[
                {"direction": "x"}])  # 缺 evidence_strength
        with self.assertRaises(ValueError):
            self.mod.situation_update(self.p, candidate_directions=[
                {"direction": "x", "evidence_strength": "huge"}])  # 非法级别
        s = self.mod.situation_update(self.p, candidate_directions=[
            {"direction": "trace", "evidence_strength": "high"}])
        self.assertEqual(s["candidate_directions"][0]["evidence_strength"], "high")

    def test_progress_degradation_for_missing_finding(self):
        kid = seed_observation(self.mod, self.p, fact="real finding")
        s = self.mod.situation_update(self.p, progress=[
            {"id": "no-such-id", "summary": "ghost progress", "confidence": "likely"},
            {"id": kid, "summary": "real progress", "confidence": "confirmed-observed"},
        ])
        ghost = [p for p in s["progress"] if p.get("summary") == "ghost progress"][0]
        real = [p for p in s["progress"] if p.get("summary") == "real progress"][0]
        self.assertNotIn("id", ghost, "引用不存在的 finding → 降级去掉 id")
        self.assertEqual(real["id"], kid, "引用存在的 finding → 保留 id")

    def test_timeline_event_append(self):
        s = self.mod.situation_update(self.p, timeline_event={"event": "handoff", "actor": "parent-1"})
        self.assertEqual(len(s["timeline"]), 1)
        ev = s["timeline"][0]
        self.assertEqual(ev["event"], "handoff")
        self.assertEqual(ev["actor"], "parent-1")
        self.assertIn("T", ev["time"], "time 由服务端补 _now()")
        with self.assertRaises(ValueError):
            self.mod.situation_update(self.p, timeline_event={"event": "no-actor"})

    def test_situation_report_lines(self):
        kid = seed_observation(self.mod, self.p, fact="report target")
        self.mod.situation_update(
            self.p, objective="solve challenge",
            progress=[{"id": kid, "summary": "done step1", "confidence": "confirmed-observed"}],
            active_work={"agent": "detector-2", "task": "FSM 追踪"},
            candidate_directions=[{"direction": "try dynamic", "evidence_strength": "mid"}])
        self.mod.directive_create(self.p, "先做 FSM")
        conn = self.mod._get_conn(self.p)
        try:
            conn.execute(
                "INSERT INTO conflicts (id, project, conflict_type, party_a_id, "
                "party_a_summary, party_a_evidence, party_b_id, party_b_summary, "
                "party_b_evidence, reporter, status) VALUES (?, ?, 1, 'a', 'sa', 'ea', "
                "'b', 'sb', 'eb', 'detector-1', 'pending')",
                ("C-9001", self.p))
            conn.commit()
        finally:
            conn.close()
        text = self.mod.situation_report(self.p)
        self.assertIn("📊 局面：solve challenge", text)
        self.assertIn("✅ 已完成：", text)
        self.assertIn("🔄 活跃：detector-2 在FSM 追踪", text)
        self.assertIn("⚠️ 冲突 1 项：C-9001", text)
        self.assertIn("📌 待办指令 1 条：D-0001", text)
        self.assertIn("（无开放式提问）", text)


class TestDirective(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_dir"

    def test_parse_directive_types(self):
        self.assertEqual(self.mod.parse_directive("停止这项分析")["type"], "stop")
        self.assertEqual(self.mod.parse_directive("应该优先做 FSM")["type"], "redirect")
        self.assertEqual(self.mod.parse_directive("验证一下 sub_4012a0")["type"], "verify")
        self.assertEqual(self.mod.parse_directive("为什么没有结果？")["type"], "question")
        self.assertEqual(self.mod.parse_directive("纯信息补充")["type"], "info")
        self.assertEqual(self.mod.parse_directive("")["type"], "redirect", "空文本兜底 redirect")
        # node X.Y 引用 → verify + 锚定；传入 anchor 优先
        p = self.mod.parse_directive("node 1.2 再查一下")
        self.assertEqual(p["type"], "verify")
        self.assertEqual(p["anchor"], "node 1.2")
        p2 = self.mod.parse_directive("看看 node 1.2", anchor="node 2.1")
        self.assertEqual(p2["anchor"], "node 2.1", "显式 anchor 优先于 node 提取")

    def test_create_numbering_and_inference(self):
        d1 = self.mod.directive_create(self.p, "先做 FSM 追踪")
        d2 = self.mod.directive_create(self.p, "停止字符串扫描")
        self.assertEqual(d1["id"], "D-0001")
        self.assertEqual(d1["type"], "redirect", "解析器推断类型")
        self.assertEqual(d2["id"], "D-0002")
        self.assertEqual(d2["type"], "stop")
        self.assertEqual(d1["status"], "received")

    def test_info_skipped_not_stored(self):
        r = self.mod.directive_create(self.p, "补充背景信息即可")
        self.assertTrue(r["skipped"])
        self.assertEqual(r["reason"], "info 不入待办")
        self.assertEqual(len(self.mod.directive_list(self.p)), 0, "info 不落库")

    def test_list_update_status_flow(self):
        self.mod.directive_create(self.p, "先做 A")
        self.mod.directive_create(self.p, "先做 B")
        self.assertEqual([d["id"] for d in self.mod.directive_list(self.p)],
                         ["D-0001", "D-0002"])
        self.assertEqual(len(self.mod.directive_list(self.p, status="!resolved")), 2)
        upd = self.mod.directive_update(self.p, "D-0001", status="resolved",
                                        outcome="done", resolved_by="parent-1")
        self.assertEqual(upd["status"], "resolved")
        self.assertIsNotNone(upd["resolved_at"], "resolved 自动补 resolved_at")
        self.assertEqual(len(self.mod.directive_list(self.p, status="!resolved")), 1)
        with self.assertRaises(ValueError):
            self.mod.directive_update(self.p, "D-0001", status="done")
        with self.assertRaises(ValueError):
            self.mod.directive_update(self.p, "D-9999", status="resolved")

    def test_repeat_freeze_hint_and_freeze_status(self):
        self.mod.directive_create(self.p, "先做 A")
        r1 = self.mod.directive_repeat(self.p, "D-0001")
        self.assertEqual(r1["repeat_count"], 1)
        self.assertFalse(r1["freeze_hint"])
        r2 = self.mod.directive_repeat(self.p, "D-0001")
        self.assertEqual(r2["repeat_count"], 2)
        self.assertTrue(r2["freeze_hint"])
        self.assertIn("重复指令", r2["message"])
        st = self.mod.freeze_status(self.p)
        self.assertTrue(st["frozen"])
        self.assertIn("存在 repeat_count≥2 的指令", st["reason"])

    def test_preflight_check(self):
        self.mod.situation_update(self.p, active_work={"agent": "discovery-3", "task": "FSM 追踪"})
        self.mod.directive_create(self.p, "先做 FSM")
        pf = self.mod.preflight_check(self.p)
        self.assertIsInstance(pf["freeze"], dict)
        self.assertEqual(len(pf["unresolved_directives"]), 1)
        self.assertEqual(pf["unresolved_directives"][0]["id"], "D-0001")
        self.assertEqual(pf["situation_summary"]["active_work"], "discovery-3 FSM 追踪")
        self.assertEqual(pf["situation_summary"]["conflicts_pending"], 0)


class TestConflict(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_conf"

    def _report(self, ctype=1, node=None, party_a="obs:1", party_b="obs:2", reporter="detector-1"):
        return self.mod.conflict_report(
            project=self.p, conflict_type=ctype,
            party_a_id=party_a, party_a_summary="sumA", party_a_evidence="evA",
            party_b_id=party_b, party_b_summary="sumB", party_b_evidence="evB",
            reporter=reporter, tree_node_id=node)

    def test_report_validation(self):
        with self.assertRaises(ValueError):
            self._report(ctype=9)
        with self.assertRaises(ValueError):
            self._report(reporter="  ")

    def test_report_numbering_and_tree_marker(self):
        self.mod.tree_store(self.p, "node_a")
        c1 = self._report(node=f"{self.p}>node_a")
        c2 = self._report()
        self.assertEqual(c1["id"], "C-0001")
        self.assertEqual(c1["status"], "pending")
        self.assertEqual(c2["id"], "C-0002")
        node = self.mod.tree_get(self.p, f"{self.p}>node_a")
        self.assertIn("conflict", node["markers"], "report 时给节点加 conflict 标记")

    def test_report_marker_failure_still_stored(self):
        # P1b 修复 8：先落库再标记——节点不存在时冲突仍落库，返回 warning（不再 ValueError + 不落库）
        c = self._report(node="no-such-node")
        self.assertEqual(len(self.mod.conflict_list(self.p)), 1,
                         "标记失败冲突仍落库（先落库后标记）")
        self.assertIn("warning", c, "标记失败返回 warning 提示")

    def test_update_terminal_requires_strategy_resolution(self):
        self._report()
        with self.assertRaises(ValueError):
            self.mod.conflict_update(self.p, "C-0001", status="adjudicated")
        with self.assertRaises(ValueError):
            self.mod.conflict_update(self.p, "C-0001", status="adjudicated",
                                     strategy="judge")
        r = self.mod.conflict_update(self.p, "C-0001", status="adjudicated",
                                     strategy="judge", resolution="party B 正确")
        self.assertEqual(r["status"], "adjudicated")
        self.assertIsNotNone(r["resolved_at"], "终态自动补 resolved_at")

    def test_disproved_resolution_cascades(self):
        # 链：observation A → claim X（parent 批准）→ hypothesis Y（依赖 X）
        obs_a = seed_observation(self.mod, self.p, fact="base observation rc4 loop")
        x = self.mod.store_finding(
            project=self.p, fact="claim: rc4 key from seed", confidence="confirmed-inferred",
            source=PARENT, type_="claim", based_on=obs_a,
            evidence="agent:alpha 复核一致；agent:beta 复核一致")
        y = self.mod.store_finding(
            project=self.p, fact="hyp: derive next byte test_plan: run decrypt",
            confidence="likely", source=SUB, type_="hypothesis", based_on=x["id"])
        self._report(ctype=2, party_a=x["id"])
        r = self.mod.conflict_update(self.p, "C-0001", status="adjudicated",
                                     strategy="judge", resolution="实测推翻，disproved")
        self.assertEqual(r["status"], "adjudicated")
        # party_a 被联动标 disproved
        self.assertEqual(self.mod.get_finding(self.p, x["id"])["confidence"], "disproved")
        # 依赖 X 的 Y 级联降级为 speculative + invalidated 标签
        dep = self.mod.get_finding(self.p, y["id"])
        self.assertEqual(dep["confidence"], "speculative")
        self.assertIn("invalidated", dep["tags"])

    def test_stats_counts_and_by_type(self):
        self._report(ctype=1)
        self._report(ctype=5)
        self.mod.conflict_update(self.p, "C-0001", status="under_review")
        stats = self.mod.conflict_stats(self.p)
        self.assertEqual(stats["pending"], 1)
        self.assertEqual(stats["under_review"], 1)
        self.assertEqual(stats["adjudicated"], 0)
        self.assertEqual(stats["by_type"], {"1": 1, "5": 1}, "by_type 用 str key")


class TestFreeze(harness.HarnessTestCase):

    def test_status_default(self):
        st = self.mod.freeze_status("fz_empty")
        self.assertFalse(st["frozen"])
        self.assertEqual(st["reason"], [])
        self.assertEqual(st["counts"]["violations"], 0)

    def test_violation_threshold_trigger(self):
        p = "fz_viol"
        for i in range(3):
            self.mod.audit_violation(p, actor="parent", rule_id="R1", detail=f"v{i}")
        st = self.mod.freeze_status(p)
        self.assertTrue(st["frozen"])
        self.assertIn("违规计数≥3(实际3)", st["reason"])

    def test_unresolved_directives_threshold_trigger(self):
        p = "fz_dir"
        for i in range(3):
            self.mod.directive_create(p, f"先做任务 {i}")
        st = self.mod.freeze_status(p)
        self.assertTrue(st["frozen"])
        self.assertIn("未解决待办≥3(实际3)", st["reason"])

    def test_explicit_trigger_and_release(self):
        p = "fz_exp"
        st = self.mod.freeze_trigger(p, "需要人工介入")
        self.assertTrue(st["frozen"])
        self.assertIn("显式冻结: 需要人工介入", st["reason"])
        self.assertIsNotNone(st.get("frozen_at"))
        # R5 自动记入审计
        stats = self.mod.audit_stats(p)
        self.assertEqual(stats["by_rule"].get("R5"), 1)
        # 清掉 R5 审计行，避免自动触发干扰 release 断言
        conn = self.mod._get_conn(p)
        try:
            conn.execute("DELETE FROM audit_log")
            conn.commit()
        finally:
            conn.close()
        st2 = self.mod.freeze_release(p)
        self.assertFalse(st2["frozen"])
        self.assertIsNotNone(st2.get("released_at"))


class TestVerification(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_ver"

    def test_check_sample_size_and_command_hint(self):
        with self.assertRaises(ValueError):
            self.mod.verification_check(self.p, sample_size=0)
        # 单条 → command_hint 必然命中抽样
        self.mod.store_finding(project=self.p, fact="candidate x",
                               confidence="confirmed-observed",
                               source="role:detector|tool:ida|tool:ghidra",
                               type_="observation")
        r = self.mod.verification_check(self.p, sample_size=1)
        self.assertEqual(len(r["sample"]), 1)
        self.assertEqual(r["sample"][0]["command_hint"], "重跑: ida, ghidra")

    def test_check_sample_size_capped_at_20(self):
        for i in range(25):
            self.mod.store_finding(project=self.p, fact=f"bulk finding {i}",
                                   confidence="confirmed-observed",
                                   source=SUB, type_="observation")
        r = self.mod.verification_check(self.p, sample_size=25)
        self.assertEqual(len(r["sample"]), 20, "sample_size 截断到 20")

    def test_report_tags_and_mismatch_and_skipped(self):
        kid = seed_observation(self.mod, self.p, fact="verify target")
        r1 = self.mod.verification_report(self.p, [
            {"finding_id": kid, "verified": True, "actual_output": "ok"},
            {"finding_id": "no-such", "verified": True, "actual_output": ""},
            {"finding_id": kid, "verified": False, "actual_output": "diff"},
        ])
        self.assertEqual(r1["verified"], 1)
        self.assertEqual(r1["tagged"], [kid])
        self.assertEqual(r1["mismatch"], 1)
        self.assertEqual(len(r1["mismatches"]), 1)
        self.assertEqual(r1["skipped"], [{"finding_id": "no-such"}])
        tags = json.loads(self.mod.get_finding(self.p, kid)["tags"])
        self.assertIn("regression_verified", tags)
        # 幂等：重复 verified 不重复打标签
        r2 = self.mod.verification_report(self.p, [
            {"finding_id": kid, "verified": True, "actual_output": "ok"}])
        self.assertEqual(r2["verified"], 1)


class TestSnapshot(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_snap"

    def test_role_cropping(self):
        obs_id = seed_observation(self.mod, self.p, fact="snap base obs")
        self.mod.store_finding(project=self.p, fact="snap claim",
                               confidence="confirmed-inferred", source=PARENT,
                               type_="claim", based_on=obs_id, evidence_uri="artifact://tool_output/x/aaaaaaaaaaaaaaaa.txt",
                               evidence="agent:alpha 复核一致；agent:beta 复核一致")
        self.mod.store_finding(project=self.p, fact="snap hyp test_plan: run",
                               confidence="likely", source=SUB, type_="hypothesis",
                               based_on=obs_id)
        with self.assertRaises(ValueError):
            self.mod.findings_snapshot(self.p, role="hacker")
        # discovery：裁剪到 id/fact/confidence/type
        disc = self.mod.findings_snapshot(self.p, role="discovery")["snapshot"]
        self.assertTrue(disc, "discovery 快照非空")
        for item in disc:
            self.assertEqual(set(item.keys()), {"id", "fact", "confidence", "type"})
        # judge：带 evidence_uri（仅存在时）
        judge = self.mod.findings_snapshot(self.p, role="judge")["snapshot"]
        claim = [i for i in judge if i["type"] == "claim"][0]
        self.assertIn("evidence_uri", claim)
        obs_j = [i for i in judge if i["type"] == "observation"][0]
        self.assertNotIn("evidence_uri", obs_j, "judge 无 evidence_uri 时不带该键")
        # analyst：展开 based_on_fact
        ana = self.mod.findings_snapshot(self.p, role="analyst")["snapshot"]
        hyp = [i for i in ana if i["type"] == "hypothesis"][0]
        self.assertEqual(hyp["based_on"], obs_id)
        self.assertEqual(hyp["based_on_fact"], "snap base obs")

    def test_truncated_flag(self):
        for i in range(3):
            seed_observation(self.mod, self.p, fact=f"snap item {i}")
        r = self.mod.findings_snapshot(self.p, role="discovery", limit=2)
        self.assertTrue(r["truncated"])
        self.assertEqual(len(r["snapshot"]), 2)

    def test_project_meta_injected(self):
        # 无局面行 → project_meta = {}
        r0 = self.mod.findings_snapshot(self.p, role="discovery")
        self.assertEqual(r0["project_meta"], {})
        # 写入局面元信息后 → snapshot 附带
        meta = {"workdir": "/w", "repo": "r", "engine": "ida", "background": "bg"}
        self.mod.situation_update(self.p, project_meta=meta)
        r1 = self.mod.findings_snapshot(self.p, role="judge")
        self.assertEqual(r1["project_meta"], meta, "snapshot 注入 project_meta 供委派模板引用")
        # 各角色裁剪均不影响 project_meta 字段
        self.assertEqual(self.mod.findings_snapshot(self.p, role="analyst")["project_meta"], meta)


class TestFindingDelete(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_del"

    def test_delete_basic_and_not_found(self):
        kid = seed_observation(self.mod, self.p, fact="to delete")
        r = self.mod.delete_finding(self.p, kid)
        self.assertEqual(r["deleted_id"], kid)
        self.assertEqual(r["orphaned_dependents"], 0)
        self.assertIsNone(self.mod.get_finding(self.p, kid), "删除后 get 返回 None")
        # 再次删除 → 抛错（目标不存在）
        with self.assertRaises(ValueError):
            self.mod.delete_finding(self.p, kid)
        # 跨项目 id 不存在 → 抛错（project 维度隔离）
        with self.assertRaises(ValueError):
            self.mod.delete_finding("other_project", kid)

    def test_delete_orphans_dependents_via_fk(self):
        # 链：observation → claim based_on 它
        obs = seed_observation(self.mod, self.p, fact="base obs")
        claim = self.mod.store_finding(
            project=self.p, fact="claim depends on base", confidence="confirmed-inferred",
            source=PARENT, type_="claim", based_on=obs,
            evidence="agent:alpha 复核一致；agent:beta 复核一致")
        r = self.mod.delete_finding(self.p, obs)
        self.assertEqual(r["orphaned_dependents"], 1)
        dep = self.mod.get_finding(self.p, claim["id"])
        self.assertIsNone(dep["based_on"], "FK ON DELETE SET NULL 自动置空 based_on")
        # 目标 observation 已删除
        self.assertIsNone(self.mod.get_finding(self.p, obs))

    def test_delete_cleans_task_meta(self):
        # type=task 写 task_meta → 删除后 task_meta 一并清理
        task = self.mod.store_finding(
            project=self.p, fact="task: do x", confidence="likely", source=SUB,
            type_="task", task_budget={"budget_tool_calls": 5, "budget_tokens": 100,
                                        "budget_seconds": 30})
        conn = self.mod._get_conn(self.p)
        try:
            n_before = conn.execute(
                "SELECT COUNT(*) FROM task_meta WHERE finding_id = ?", (task["id"],)
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n_before, 1, "task finding 落 task_meta")
        self.mod.delete_finding(self.p, task["id"])
        conn = self.mod._get_conn(self.p)
        try:
            n_after = conn.execute(
                "SELECT COUNT(*) FROM task_meta WHERE finding_id = ?", (task["id"],)
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n_after, 0, "删除后 task_meta 关联行清理")

    def test_delete_syncs_fts_index(self):
        # FTS 触发器同步删除：删除后 use_fts 搜索不应再命中
        kid = seed_observation(self.mod, self.p, fact="unique fts deletion marker")
        self.assertEqual(len(self.mod.search_findings(self.p, query="deletion marker", use_fts=True)), 1)
        self.mod.delete_finding(self.p, kid)
        self.assertEqual(len(self.mod.search_findings(self.p, query="deletion marker", use_fts=True)), 0,
                         "FTS 索引同步删除，搜索不再命中")


class TestArtifact(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_art"

    def test_roundtrip(self):
        output = "# 0x4012a0: push rbp\n# second comment\nmov eax, 1\nret\n"
        st = self.mod.artifact_store(self.p, tool="ida", command="idat64 -A", output=output)
        self.assertTrue(st["uri"].startswith("artifact://tool_output/ops_art/"))
        self.assertTrue(st["uri"].endswith(".txt"))
        self.assertEqual(st["uri"].count("/"), 4)
        got = self.mod.artifact_get(st["uri"])
        self.assertEqual(got["tool"], "ida")
        self.assertEqual(got["command"], "idat64 -A")
        self.assertEqual(got["output"], output, "以 # 开头的正文不被元数据解析吞掉")
        self.assertIn("stored_at", got)

    def test_invalid_uri_rejected(self):
        with self.assertRaises(ValueError):
            self.mod.artifact_get("artifact://tool_output/ops_art/short.txt")
        with self.assertRaises(ValueError):
            self.mod.artifact_get("artifact://tool_output/../aaaaaaaaaaaaaaaa.txt")
        with self.assertRaises(ValueError):
            self.mod.artifact_get("not-a-uri")

    def test_large_output_truncated(self):
        big = "A" * (512 * 1024 + 5)
        st = self.mod.artifact_store(self.p, tool="ida", command="dump", output=big)
        self.assertTrue(st["truncated"])
        self.assertEqual(st["bytes"], 512 * 1024)
        got = self.mod.artifact_get(st["uri"])
        self.assertEqual(len(got["output"]), 512 * 1024)


class TestTree(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_tree"
        self.mod.tree_store(self.p, "a")
        self.mod.tree_store(self.p, "b")
        self.mod.tree_store(self.p, "a>a1")

    def test_mark_unmark(self):
        a = f"{self.p}>a"
        r1 = self.mod.tree_mark(self.p, a, "active")
        self.assertEqual(r1["markers"], ["active"])
        r2 = self.mod.tree_mark(self.p, a, "active")
        self.assertEqual(r2["markers"], ["active"], "重复标记去重")
        r3 = self.mod.tree_mark(self.p, a, "conflict")
        self.assertEqual(r3["markers"], ["active", "conflict"])
        r4 = self.mod.tree_unmark(self.p, a, "active")
        self.assertEqual(r4["markers"], ["conflict"])
        with self.assertRaises(ValueError):
            self.mod.tree_mark(self.p, a, "not-a-marker")
        with self.assertRaises(ValueError):
            self.mod.tree_mark(self.p, f"{self.p}>no-such-node", "active")

    def test_render_numbering_and_icons(self):
        seed_observation(self.mod, self.p, fact="alpha observed", tree_path="a")
        self.mod.store_finding(
            project=self.p, fact="L" * 70, confidence="speculative",
            source=PARENT, type_="observation", tree_path="a")
        self.mod.tree_mark(self.p, f"{self.p}>a", "active")
        self.mod.tree_mark(self.p, f"{self.p}>a", "conflict")
        text = self.mod.tree_render(self.p)
        lines = text.split("\n")
        self.assertEqual(lines[0], "ops_tree", "根行无编号")
        self.assertIn("├── 1 a ⚠️ 🔄", text, "节点编号 + markers 图标（MARKER_ORDER 序）")
        self.assertIn("← 1.1", text, "finding 行带编号")
        self.assertIn("[obs] alpha observed (confirmed-observed)", text)
        self.assertIn("🔒", text, "speculative finding 图标")
        self.assertIn("…", text, "超长 fact 截断")
        self.assertIn("└── 1.3 a1", text, "findings 与子节点共享编号序列")
        self.assertIn("└── 2 b", text)


class TestSearch(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "ops_search"

    def test_use_fts_and_like(self):
        self.mod.store_finding(project=self.p, fact="rc4 keystream at sub_4012a0",
                               confidence="confirmed-observed", source=SUB,
                               type_="observation", tags=["crypto"])
        self.mod.store_finding(project=self.p, fact="unrelated string table",
                               confidence="confirmed-observed", source=SUB,
                               type_="observation")
        self.mod.store_finding(project=self.p, fact="pending guess",
                               confidence="likely", source=SUB, type_="observation")
        # FTS trigram 子串匹配
        fts = self.mod.search_findings(self.p, query="4012", use_fts=True)
        self.assertEqual(len(fts), 1)
        self.assertEqual(fts[0]["id"], self.mod.search_findings(self.p, query="rc4")[0]["id"])
        # LIKE 路径同样命中
        like = self.mod.search_findings(self.p, query="keystream")
        self.assertEqual(len(like), 1)
        # 置信度快捷过滤：verified 含 confirmed-observed，不含 likely
        verified = self.mod.search_findings(self.p, confidence="verified")
        self.assertEqual(len(verified), 2)
        # tag 过滤
        tagged = self.mod.search_findings(self.p, tag="crypto")
        self.assertEqual(len(tagged), 1)
        self.assertIn("crypto", tagged[0]["tags"])

    def test_use_fts_empty_query_falls_back(self):
        self.mod.store_finding(project=self.p, fact="fallback target",
                               confidence="confirmed-observed", source=SUB,
                               type_="observation")
        res = self.mod.search_findings(self.p, query="", use_fts=True)
        self.assertEqual(len(res), 1, "use_fts 空 query → 回退 LIKE 全量")


if __name__ == "__main__":
    unittest.main()
