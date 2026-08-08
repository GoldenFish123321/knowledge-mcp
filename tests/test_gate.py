#!/usr/bin/env python3
"""G6b 回归测试：写库 gate（test_gate.py）。

覆盖 v1.1 §1.3 四层结构校验：
- ① 角色权责：子 Agent 禁标 confirmed-inferred/speculative；role 缺失默认拒绝；
  confirmed-observed/likely/disproved 不受角色限制（不误伤）
- ② type 校验：claim 必须 based_on observation；hypothesis 必须含 test_plan:；
  task 必须带 budget 三字段；非法 type 拒绝
- ③ confirmed-inferred 交叉验证：evidence 必须含两个不同 agent:<id>
- update 版 gate：仅显式改高置信时触发（G0b 回归：已批准的 confirmed-inferred
  条目只改 evidence/tags 不误拒）
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


class TestStoreRoleAuthority(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "gate_role"

    def _store(self, confidence, source):
        return self.mod.store_finding(
            project=self.p, fact="f", confidence=confidence,
            source=source, type_="observation")

    def test_subagent_confirmed_inferred_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._store("confirmed-inferred", SUB_DISCOVERY)
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_subagent_speculative_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._store("speculative", SUB_DETECTOR)
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_missing_role_rejected(self):
        # role 缺失/无法解析 → 宁严勿松
        with self.assertRaises(ValueError) as ctx:
            self._store("confirmed-inferred", "agent:sub-1|tool:ida")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_unknown_role_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self._store("confirmed-inferred", "role:intern|tool:ida")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_parent_uppercase_role_accepted(self):
        # 大小写不敏感：role:PARENT 大写通过
        r = self.mod.store_finding(
            project=self.p, fact="f", confidence="confirmed-inferred",
            source="role:PARENT|agent:p|tool:ida", type_="observation",
            evidence="agent:alpha 复核一致；agent:beta 复核一致")
        self.assertEqual(r["confidence"], "confirmed-inferred")

    def test_subagent_not_gated_levels_accepted(self):
        # 不误伤：likely / confirmed-observed / disproved 子 Agent 可标
        self.assertEqual(self._store("likely", SUB_DISCOVERY)["confidence"], "likely")
        self.assertEqual(self._store("confirmed-observed", SUB_DETECTOR)["confidence"],
                         "confirmed-observed")
        self.assertEqual(self._store("disproved", SUB_DISCOVERY)["confidence"], "disproved")


class TestStoreTypeValidation(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "gate_type"

    def test_claim_without_based_on_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="claim f",
                                   confidence="confirmed-observed",
                                   source=PARENT, type_="claim")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_claim_based_on_nonexistent_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="claim f",
                                   confidence="confirmed-observed",
                                   source=PARENT, type_="claim",
                                   based_on="no-such-id")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_claim_based_on_non_observation_rejected(self):
        hyp = self.mod.store_finding(
            project=self.p, fact="hyp f test_plan: step1",
            confidence="likely", source=SUB_DISCOVERY, type_="hypothesis")
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="claim f",
                                   confidence="confirmed-observed",
                                   source=PARENT, type_="claim",
                                   based_on=hyp["id"])
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_claim_based_on_observation_accepted(self):
        obs_id = seed_observation(self.mod, self.p)
        r = self.mod.store_finding(project=self.p, fact="claim f",
                                   confidence="confirmed-observed",
                                   source=PARENT, type_="claim", based_on=obs_id)
        self.assertEqual(r["based_on"], obs_id)

    def test_hypothesis_without_test_plan_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="hyp f no plan",
                                   confidence="likely", source=SUB_DISCOVERY,
                                   type_="hypothesis")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_hypothesis_with_test_plan_accepted(self):
        r = self.mod.store_finding(project=self.p, fact="hyp f test_plan: run gdb",
                                   confidence="likely", source=SUB_DISCOVERY,
                                   type_="hypothesis")
        self.assertEqual(r["type"], "hypothesis")

    def test_invalid_type_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="f",
                                   confidence="likely", source=SUB_DISCOVERY,
                                   type_="memo")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_task_without_budget_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="task f",
                                   confidence="likely", source=SUB_DISCOVERY,
                                   type_="task")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_task_budget_missing_field_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(project=self.p, fact="task f",
                                   confidence="likely", source=SUB_DISCOVERY,
                                   type_="task",
                                   task_budget={"budget_tool_calls": 5})
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_task_full_budget_stores_task_meta(self):
        r = self.mod.store_finding(
            project=self.p, fact="task f", confidence="likely",
            source=SUB_DISCOVERY, type_="task",
            task_budget={"budget_tool_calls": 5, "budget_tokens": 8000,
                         "budget_seconds": 300},
            task_agent="detector-7", task_dependencies=["dep-a", "dep-b"])
        self.assertEqual(r["type"], "task")
        conn = self.mod._get_conn(self.p)
        try:
            m = conn.execute("SELECT * FROM task_meta WHERE finding_id=?",
                             (r["id"],)).fetchone()
            self.assertEqual(m["budget_tool_calls"], 5)
            self.assertEqual(m["budget_tokens"], 8000)
            self.assertEqual(m["budget_seconds"], 300)
            self.assertEqual(m["agent"], "detector-7")
            self.assertEqual(m["task_status"], "todo")
            self.assertEqual(m["dependencies_json"], '["dep-a", "dep-b"]')
        finally:
            conn.close()


class TestCrossValidation(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "gate_cross"

    def test_confirmed_inferred_single_agent_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(
                project=self.p, fact="f", confidence="confirmed-inferred",
                source=PARENT, type_="observation",
                evidence="agent:alpha 复核一致")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_confirmed_inferred_two_agents_accepted(self):
        r = self.mod.store_finding(
            project=self.p, fact="f", confidence="confirmed-inferred",
            source=PARENT, type_="observation",
            evidence="agent:alpha 复核一致；agent:beta 复核一致")
        self.assertEqual(r["confidence"], "confirmed-inferred")

    def test_duplicate_agent_ids_do_not_count_twice(self):
        # 两个相同 agent id 去重后仍 <2 → 拒绝
        with self.assertRaises(ValueError) as ctx:
            self.mod.store_finding(
                project=self.p, fact="f", confidence="confirmed-inferred",
                source=PARENT, type_="observation",
                evidence="agent:alpha 一次；agent:alpha 两次")
        self.assertIn("write_gate_violation", str(ctx.exception))


class TestUpdateGate(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "gate_update"
        # 一条已由父 Agent 批准的 confirmed-inferred 条目（G0b 回归场景的主角）
        self.kid = self.mod.store_finding(
            project=self.p, fact="approved inference", confidence="confirmed-inferred",
            source=PARENT, type_="observation",
            evidence="agent:alpha 复核一致；agent:beta 复核一致")["id"]

    def test_subagent_promotes_to_confirmed_inferred_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.mod.update_finding(project=self.p, kid=self.kid,
                                    confidence="confirmed-inferred",
                                    source=SUB_DISCOVERY)
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_parent_promotes_with_double_agent_accepted(self):
        r = self.mod.update_finding(
            project=self.p, kid=self.kid, confidence="confirmed-inferred",
            source=PARENT,
            evidence="agent:alpha 复核一致；agent:beta 复核一致；agent:gamma 复核一致")
        self.assertEqual(r["confidence"], "confirmed-inferred")

    def test_update_without_source_rejected(self):
        # update 请求不带 source → 无法解析 role → 拒绝（改高置信时）
        with self.assertRaises(ValueError) as ctx:
            self.mod.update_finding(project=self.p, kid=self.kid,
                                    confidence="speculative")
        self.assertIn("write_gate_violation", str(ctx.exception))

    def test_subagent_marks_disproved_accepted(self):
        # 证伪不设角色门槛（不误伤）
        r = self.mod.update_finding(project=self.p, kid=self.kid,
                                    confidence="disproved",
                                    source=SUB_DISCOVERY)
        self.assertEqual(r["confidence"], "disproved")

    def test_evidence_only_update_not_rejected(self):
        # G0b 回归：已 confirmed-inferred 条目，子 Agent 只补 evidence → 不触发 gate
        r = self.mod.update_finding(project=self.p, kid=self.kid,
                                    evidence="agent:gamma 补充复核一致",
                                    source=SUB_DISCOVERY)
        self.assertEqual(r["confidence"], "confirmed-inferred")
        self.assertIn("gamma", r["evidence"])

    def test_tags_only_update_not_rejected(self):
        r = self.mod.update_finding(project=self.p, kid=self.kid,
                                    tags=["regression_verified"],
                                    source=SUB_DISCOVERY)
        self.assertEqual(r["confidence"], "confirmed-inferred")
        self.assertIn("regression_verified", r["tags"])

    def test_low_confidence_change_not_gated(self):
        # 显式改为 likely（非受限级别）→ 子 Agent 可改，无需 source
        r = self.mod.update_finding(project=self.p, kid=self.kid,
                                    confidence="likely", source=SUB_DISCOVERY)
        self.assertEqual(r["confidence"], "likely")


if __name__ == "__main__":
    unittest.main()
