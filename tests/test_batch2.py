#!/usr/bin/env python3
"""G6c 回归测试：batch2 — project 绑定 + situation_update 追加（test_batch2.py）。

覆盖 v1.1-batch2 两条建议：
- #1 project 绑定：situation_update/directive_create 激活活动项目后，
  子 Agent 落库 project 必须等于活动项目（fail-open 兼容旧流程；parent 豁免）
- #6 situation_update 追加：progress_append / candidate_directions_append
  追加到现有列表末尾（空列表无操作；与覆盖版同时传先覆盖后追加）
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

PARENT = "role:parent|agent:parent-1|tool:ida"
SUB_DISCOVERY = "role:discovery|agent:sub-1|tool:ghidra"
SUB_DETECTOR = "role:detector|agent:sub-2|tool:strings"


def seed_observation(mod, project, fact="observed: sub_4012a0 does X",
                     source=SUB_DISCOVERY, **kw):
    """造一条 observation（type 必须显式传，否则默认 claim 触发 based_on 校验）。"""
    r = mod.store_finding(project=project, fact=fact, confidence="confirmed-observed",
                          source=source, type_="observation", **kw)
    return r["id"]


class TestProjectBinding(harness.HarnessTestCase):
    """#1 project 绑定：write_gate 第五层。"""

    def setUp(self):
        super().setUp()
        self.main = "proj_main"
        self.other = "proj_other"

    def _store(self, project, source=SUB_DISCOVERY):
        return self.mod.store_finding(
            project=project, fact="f", confidence="confirmed-observed",
            source=source, type_="observation")

    def test_inactive_fail_open(self):
        """未激活活动项目时，子 Agent 写任意 project 放行（兼容旧流程）。"""
        r = self._store(self.other)
        self.assertIn("id", r)

    def test_subagent_mismatch_rejected_after_activate(self):
        """situation_update 激活后，子 Agent 写非活动项目被 write_gate 拒绝。"""
        self.mod.situation_update(project=self.main, objective="act")
        with self.assertRaises(ValueError) as ctx:
            self._store(self.other)
        msg = str(ctx.exception)
        self.assertIn("write_gate_violation", msg)
        self.assertIn("活动项目", msg)
        self.assertIn(self.main, msg)

    def test_subagent_match_allowed(self):
        """子 Agent 写活动项目放行。"""
        self.mod.situation_update(project=self.main, objective="act")
        r = self._store(self.main)
        self.assertIn("id", r)

    def test_parent_exempt(self):
        """role=parent 写非活动项目豁免（父 Agent 有全局视角，可做迁移/清理）。"""
        self.mod.situation_update(project=self.main, objective="act")
        r = self._store(self.other, source=PARENT)
        self.assertIn("id", r)

    def test_directive_create_activates(self):
        """directive_create 也是活动项目锚点。"""
        self.mod.directive_create(project=self.main, text="提交前必须质疑（D-0001 规则）")
        with self.assertRaises(ValueError):
            self._store(self.other)
        r = self._store(self.main)
        self.assertIn("id", r)

    def test_switch_active_project(self):
        """切换活动项目后，旧项目拒绝、新项目放行。"""
        self.mod.situation_update(project=self.main, objective="phase1")
        self.mod.situation_update(project=self.other, objective="phase2")
        with self.assertRaises(ValueError):
            self._store(self.main)
        r = self._store(self.other)
        self.assertIn("id", r)

    def test_activation_persists_in_db(self):
        """活动项目持久化在全局 app_state 库（跨项目连接可见）。"""
        self.mod.situation_update(project=self.main, objective="act")
        self.assertEqual(self.mod._get_active_project(), self.main)

    def test_tree_store_not_gated(self):
        """边界文档化：tree_store 无 source 参数，不做 project 绑定（findings 为主入口）。"""
        self.mod.situation_update(project=self.main, objective="act")
        r = self.mod.tree_store(project=self.other, path="x>y")
        self.assertIn("id", r)

    def test_rejected_write_does_not_create_db_file(self):
        """P1-2：绑定拒绝路径不创建 {project}.db（前置检查在 _get_conn 之前）。"""
        self.mod.situation_update(project=self.main, objective="act")
        with self.assertRaises(ValueError):
            self._store(self.other)
        import os
        self.assertFalse(os.path.exists(os.path.join(self.mod.DB_DIR, self.other + ".db")))
        # project_list 不列出幽灵项目
        names = [p["project"] for p in self.mod.project_list()]
        self.assertNotIn(self.other, names)

    def test_update_gated_by_binding(self):
        """P1-1：findings_update 同样受 project 绑定约束（README 声称五层 gate）。"""
        # 先造一条 activity 项目的 finding 供 update
        self.mod.situation_update(project=self.main, objective="act")
        fid = seed_observation(self.mod, self.main, source=SUB_DISCOVERY)
        # 子 Agent update 非活动项目（存在该 id 的项目也不放行——项目级绑定）
        # 造一个 other 项目的 finding：父 Agent 先建（parent 豁免）
        fid_other = seed_observation(self.mod, self.other, source=PARENT)
        with self.assertRaises(ValueError) as ctx:
            self.mod.update_finding(project=self.other, kid=fid_other,
                                    fact="tampered", source=SUB_DISCOVERY)
        self.assertIn("write_gate_violation", str(ctx.exception))
        # update 活动项目放行
        r = self.mod.update_finding(project=self.main, kid=fid,
                                    fact="ok", source=SUB_DISCOVERY)
        self.assertIn("id", r)
        # parent 豁免
        r2 = self.mod.update_finding(project=self.other, kid=fid_other,
                                     fact="ok2", source=PARENT)
        self.assertIn("id", r2)

    def test_update_binding_does_not_create_db(self):
        """P1-1+P1-2：update 拒绝路径也不创建 db 文件。"""
        self.mod.situation_update(project=self.main, objective="act")
        import os
        with self.assertRaises(ValueError):
            self.mod.update_finding(project=self.other, kid="x",
                                    fact="f", source=SUB_DISCOVERY)
        self.assertFalse(os.path.exists(os.path.join(self.mod.DB_DIR, self.other + ".db")))


class TestSituationAppend(harness.HarnessTestCase):
    """#6 situation_update 追加模式。"""

    def setUp(self):
        super().setUp()
        self.p = "proj_append"

    def test_progress_append_appends(self):
        """progress_append 追加到现有 progress 末尾。"""
        self.mod.situation_update(project=self.p, progress=[{"summary": "a", "confidence": "high"}])
        s = self.mod.situation_update(project=self.p, progress_append=[{"summary": "b", "confidence": "mid"}])
        self.assertEqual([x["summary"] for x in s["progress"]], ["a", "b"])

    def test_append_without_existing(self):
        """无现有 progress 时 append 直接成为列表。"""
        s = self.mod.situation_update(project=self.p, progress_append=[{"summary": "x"}])
        self.assertEqual([x["summary"] for x in s["progress"]], ["x"])

    def test_empty_append_noop(self):
        """空列表 append = 无操作（version 不 bump）。"""
        self.mod.situation_update(project=self.p, objective="v1")
        s1 = self.mod.situation_get(self.p)
        s2 = self.mod.situation_update(project=self.p, progress_append=[])
        self.assertEqual(s2["version"], s1["version"])
        self.assertEqual(s2["progress"], [])

    def test_cover_then_append(self):
        """progress 与 progress_append 同时传：先整体覆盖后追加。"""
        self.mod.situation_update(project=self.p, progress=[{"summary": "old1"}, {"summary": "old2"}])
        s = self.mod.situation_update(
            project=self.p,
            progress=[{"summary": "new1"}],
            progress_append=[{"summary": "app1"}, {"summary": "app2"}],
        )
        self.assertEqual([x["summary"] for x in s["progress"]], ["new1", "app1", "app2"])

    def test_candidate_directions_append(self):
        """candidate_directions_append 追加且校验 evidence_strength。"""
        self.mod.situation_update(
            project=self.p,
            candidate_directions=[{"direction": "d1", "evidence_strength": "high"}],
        )
        s = self.mod.situation_update(
            project=self.p,
            candidate_directions_append=[{"direction": "d2", "evidence_strength": "low"}],
        )
        self.assertEqual([x["direction"] for x in s["candidate_directions"]], ["d1", "d2"])

    def test_candidate_append_invalid_strength_rejected(self):
        """append 版同样强制 evidence_strength 合法。"""
        self.mod.situation_update(project=self.p, objective="act")
        with self.assertRaises(ValueError) as ctx:
            self.mod.situation_update(
                project=self.p,
                candidate_directions_append=[{"direction": "d", "evidence_strength": "nope"}],
            )
        self.assertIn("evidence_strength", str(ctx.exception))

    def test_candidate_append_missing_strength_rejected(self):
        """append 版缺 evidence_strength 拒绝。"""
        self.mod.situation_update(project=self.p, objective="act")
        with self.assertRaises(ValueError) as ctx:
            self.mod.situation_update(
                project=self.p,
                candidate_directions_append=[{"direction": "d"}],
            )
        self.assertIn("evidence_strength", str(ctx.exception))

    def test_append_id_downgrade(self):
        """append 项 id 引用不存在的 finding → 降级纯文本（去掉 id）。"""
        self.mod.situation_update(project=self.p, objective="act")
        s = self.mod.situation_update(
            project=self.p,
            progress_append=[{"id": "ghost-0000", "summary": "t"}],
        )
        self.assertNotIn("id", s["progress"][0])
        self.assertEqual(s["progress"][0]["summary"], "t")

    def test_append_activates_project(self):
        """append 也是局面更新 → 激活活动项目（与 #1 联动）。"""
        self.mod.situation_update(project=self.p, progress_append=[{"summary": "x"}])
        with self.assertRaises(ValueError):
            self.mod.store_finding(
                project="other_proj", fact="f", confidence="confirmed-observed",
                source=SUB_DISCOVERY, type_="observation")

    def test_append_non_list_rejected_valueerror(self):
        """P2-8：append 传非 list 抛 ValueError（而非 TypeError）。"""
        self.mod.situation_update(project=self.p, objective="act")
        for bad in (5, "str", {"a": 1}):
            with self.assertRaises(ValueError):
                self.mod.situation_update(project=self.p, progress_append=bad)
            with self.assertRaises(ValueError):
                self.mod.situation_update(project=self.p, candidate_directions_append=bad)


if __name__ == "__main__":
    unittest.main()
