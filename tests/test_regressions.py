#!/usr/bin/env python3
"""P0 审查修复回归测试（test_regressions.py）。

覆盖独立审查发现的 8 个数据正确性问题（均在修复前实测复现）：
- P1 级联死代码：先 UPDATE 降级再查 dependents → 二级依赖链永不降级；环状依赖死循环风险
- P2 非终态误降级：conflict_update 只看 resolution 文本不看 status → under_review 就标 disproved
- P3 连接泄漏：store_finding/update_finding/tree_store 异常路径连接不关闭
- P4 并发 id 碰撞：_next_directive_id/_next_conflict_id 非原子 → 并发 IntegrityError 丢数据
- P5 迁移崩溃路径：列数不匹配 / dangling based_on 在 FK ON 下迁移 → 首连永久失败
- P6 迁移后索引丢失：knowledge 三索引建在 _migrate_schema 前 → RENAME+DROP 带走
- P7 confirmed 僵尸置信度：旧 'confirmed' 值不映射 → 搜索/过滤不可见
- P8 纯中文冲突检测失效：词提取正则无 CJK → 中文 fact 静默 return []
"""

import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

PARENT = "role:parent|agent:pa|tool:ida"


def seed(mod, project, fact, confidence="confirmed-observed", type_="observation",
         based_on=None, source=PARENT, **kw):
    r = mod.store_finding(project=project, fact=fact, confidence=confidence,
                          source=source, type_=type_, based_on=based_on, **kw)
    return r["id"]


# ── P1 级联死代码 ─────────────────────────────────────────────────
class TestCascadeInvalidate(harness.HarnessTestCase):
    def test_second_level_dependency_chain_downgraded(self):
        """A(obs)→B(claim 依赖 A)→C(obs 依赖 B)：证伪 A 后 B 与 C 全部降级 + invalidated + reason。"""
        p = "reg_p1_chain"
        a = seed(self.mod, p, "obs A 触发点")
        b = seed(self.mod, p, "claim B 依赖 A", type_="claim", based_on=a)
        c = seed(self.mod, p, "obs C 依赖 B", based_on=b)
        self.mod.update_finding(p, a, confidence="disproved")
        bb = self.mod.get_finding(p, b)
        cc = self.mod.get_finding(p, c)
        self.assertEqual(bb["confidence"], "speculative")
        self.assertIn("invalidated", json.loads(bb["tags"]))
        self.assertEqual(cc["confidence"], "speculative", "二级依赖必须递归降级（原实现死代码只降一级）")
        self.assertIn("invalidated", json.loads(cc["tags"]))
        self.assertIn("被证伪", cc["invalidation_reason"] or "")

    def test_cycle_does_not_infinite_loop(self):
        """A→B→A 环状依赖：证伪 A 不死循环，且 B 被降级。"""
        p = "reg_p1_cycle"
        a = seed(self.mod, p, "obs A 环起点")
        b = seed(self.mod, p, "obs B 环终点", based_on=a)
        conn = self.mod._get_conn(p)
        conn.execute("UPDATE knowledge SET based_on = ? WHERE id = ?", (b, a))
        conn.commit()
        conn.close()
        self.mod.update_finding(p, a, confidence="disproved")  # 若死循环则超时/RecursionError
        self.assertEqual(self.mod.get_finding(p, b)["confidence"], "speculative")


# ── P2 非终态误降级 ───────────────────────────────────────────────
class TestConflictUpdateLinkage(harness.HarnessTestCase):
    def _report_conflict(self, p, party_a_id):
        r = self.mod.conflict_report(p, 1, party_a_id, "sumA", "evA",
                                     "party-b", "sumB", "evB", "judge-1")
        return r["id"]

    def test_nonterminal_resolution_does_not_disprove(self):
        """under_review + resolution 含 disproved → 不降级；adjudicated 终态才降级。"""
        p = "reg_p2_nonterminal"
        a = seed(self.mod, p, "obs A2 被审查")
        cid = self._report_conflict(p, a)
        self.mod.conflict_update(p, cid, status="under_review",
                                 resolution="A 的结论疑似 disproved 待查")
        self.assertEqual(self.mod.get_finding(p, a)["confidence"], "confirmed-observed",
                         "非终态 resolution 含 disproved 只是待查记录，不得联动降级")
        self.mod.conflict_update(p, cid, status="adjudicated", strategy="judge",
                                 resolution="重跑证实 A 结论被推翻 disproved")
        self.assertEqual(self.mod.get_finding(p, a)["confidence"], "disproved")

    def test_linkage_failure_returns_warning(self):
        """party_a 非 knowledge 条目：联动失败不静默吞异常，返回 warning 字段。"""
        p = "reg_p2_warning"
        cid = self._report_conflict(p, "observation:ghost")
        out = self.mod.conflict_update(p, cid, status="adjudicated", strategy="judge",
                                       resolution="该结论已 disproved")
        self.assertIn("warning", out)
        self.assertIn("disproved", out["warning"])


# ── P3 连接泄漏 ───────────────────────────────────────────────────
class _TrackedConn(sqlite3.Connection):
    """factory 子类：追踪尚未 close 的连接。"""
    _open = set()

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        _TrackedConn._open.add(self)

    def close(self):
        _TrackedConn._open.discard(self)
        super().close()


class TestNoConnLeak(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self._orig_connect = sqlite3.connect
        self._TrackedConn = _TrackedConn
        self._TrackedConn._open.clear()

        def counting_connect(*a, **k):
            return self._orig_connect(*a, **k, factory=self._TrackedConn)

        sqlite3.connect = counting_connect
        self.addCleanup(self._restore_connect)

    def _restore_connect(self):
        sqlite3.connect = self._orig_connect

    def test_exception_paths_do_not_leak_connections(self):
        p = "reg_p3_leak"
        base = len(_TrackedConn._open)

        # 1) store_finding tree_path=">" → _ensure_tree_path ValueError
        with self.assertRaises(ValueError):
            self.mod.store_finding(p, "f1", "confirmed-observed", PARENT,
                                   type_="observation", tree_path=">")
        # 2) tags 不可序列化 → json.dumps TypeError（预序列化，开连接前抛）
        with self.assertRaises(TypeError):
            self.mod.store_finding(p, "f2", "confirmed-observed", PARENT,
                                   type_="observation", tags=[object()])
        # 3) INSERT 绑定失败 → sqlite3 异常
        with self.assertRaises(Exception):
            self.mod.store_finding(p, {"not": "str"}, "confirmed-observed", PARENT,
                                   type_="observation")
        # 4) tree_store path=">" → ValueError
        with self.assertRaises(ValueError):
            self.mod.tree_store(p, ">")
        # 5) update_finding tree_path=">" → ValueError
        aid = seed(self.mod, p, "f3")
        with self.assertRaises(ValueError):
            self.mod.update_finding(p, aid, tree_path=">")

        self.assertEqual(len(_TrackedConn._open), base,
                         "所有异常路径后连接数不得增长（finally 必须关闭连接）")


# ── P4 并发 id 碰撞 ───────────────────────────────────────────────
class TestConcurrentIds(harness.HarnessTestCase):
    def test_concurrent_directive_create_no_collision(self):
        """15 线程 × 5 次 directive_create：无异常、75 条、id 全唯一（撞号重试）。"""
        p = "reg_p4_directive"
        errors = []

        def worker(i):
            try:
                for j in range(5):
                    self.mod.directive_create(p, f"directive {i}-{j}", type="stop")
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"并发 directive_create 不得抛异常: {errors[:3]}")
        dl = self.mod.directive_list(p, limit=200)
        self.assertEqual(len(dl), 75, "15×5 条指令全部落库，不得因撞号丢数据")
        self.assertEqual(len({x["id"] for x in dl}), 75, "D-XXXX id 必须全局唯一")

    def test_concurrent_conflict_report_no_collision(self):
        """15 线程并发 conflict_report：无异常、15 条、id 全唯一。"""
        p = "reg_p4_conflict"
        errors = []

        def worker(i):
            try:
                self.mod.conflict_report(p, 1, f"a-{i}", "sumA", "evA",
                                         "party-b", "sumB", "evB", "judge-1")
            except Exception as e:  # noqa: BLE001
                errors.append(repr(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(15)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [], f"并发 conflict_report 不得抛异常: {errors[:3]}")
        cl = self.mod.conflict_list(p, limit=200)
        self.assertEqual(len(cl), 15)
        self.assertEqual(len({x["id"] for x in cl}), 15, "C-XXXX id 必须全局唯一")


# ── P5/P6/P7 迁移 ─────────────────────────────────────────────────
OLD_SQL_10 = """
CREATE TABLE knowledge (
    id          TEXT PRIMARY KEY,
    project     TEXT NOT NULL,
    fact        TEXT NOT NULL,
    confidence  TEXT NOT NULL CHECK (confidence IN ('confirmed','disproved','likely','speculative')),
    source      TEXT NOT NULL,
    evidence    TEXT NOT NULL DEFAULT '',
    based_on    TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (based_on) REFERENCES knowledge(id) ON DELETE SET NULL
)
"""


def build_old_db(dbpath, with_tree_node_id=False, dangling=False):
    """构造旧版 4 级置信度库（外键关闭期写入，模拟旧时代数据）。"""
    os.makedirs(os.path.dirname(dbpath), exist_ok=True)
    c = sqlite3.connect(dbpath)
    try:
        c.execute("PRAGMA foreign_keys=OFF")
        if with_tree_node_id:
            c.execute(OLD_SQL_10.replace(
                "tags        TEXT NOT NULL DEFAULT '[]',",
                "tags        TEXT NOT NULL DEFAULT '[]',\n    tree_node_id TEXT,"))
        else:
            c.execute(OLD_SQL_10)
        rows = [
            ("legacy-1", "legacy", "旧库观测 confirmed", "confirmed",
             "tool:old", "旧证据", None),
            ("legacy-2", "legacy", "旧库假设 likely", "likely",
             "tool:old", "旧证据2", "legacy-1"),
        ]
        if dangling:
            rows.append(("legacy-d", "legacy", "悬空 based_on", "speculative",
                         "tool:old", "旧证据3", "ghost-id"))
        for rid, proj, fact, conf, src, ev, based_on in rows:
            c.execute(
                "INSERT INTO knowledge (id, project, fact, confidence, source, evidence, based_on, tags, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, '[]', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
                (rid, proj, fact, conf, src, ev, based_on))
        if with_tree_node_id:
            c.execute("UPDATE knowledge SET tree_node_id = 'legacy>node' WHERE id = 'legacy-1'")
        c.commit()
    finally:
        c.close()


class _MigrationBase(harness.HarnessTestCase):
    """迁移类测试基类：先造旧库再加载 server（加载时 FINDINGS_DB_DIR 须指向含旧库的目录）。"""

    def load_with_old_db(self, **build_kw):
        d = tempfile.mkdtemp(prefix="kmcp_mig_")
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        build_old_db(os.path.join(d, "legacy.db"), **build_kw)
        os.environ["FINDINGS_DB_DIR"] = d
        self.mod = harness.load_server()
        return d


class TestMigrationCrashPaths(_MigrationBase):
    def test_migrate_intermediate_db_with_tree_node_id(self):
        """M4：4 级 CHECK + tree_node_id 并存的中间态库 → 首连迁移成功、数据保留。"""
        self.load_with_old_db(with_tree_node_id=True)
        rows = self.mod.search_findings("legacy")  # 首连即迁移；修复前抛 OperationalError
        facts = {r["fact"] for r in rows}
        self.assertIn("旧库观测 confirmed", facts)
        self.assertIn("旧库假设 likely", facts)

    def test_migrate_db_with_dangling_based_on(self):
        """M5：旧库带 dangling based_on → FK ON 下迁移不抛 IntegrityError，悬空引用被清洗为 NULL。"""
        self.load_with_old_db(dangling=True)
        rows = self.mod.search_findings("legacy")  # 修复前首连抛 IntegrityError
        self.assertEqual(len(rows), 3, "含悬空行的 3 条数据全部保留")
        conn = self.mod._get_conn("legacy")
        try:
            left = conn.execute(
                "SELECT COUNT(*) AS c FROM knowledge WHERE based_on = 'ghost-id'"
            ).fetchone()["c"]
        finally:
            conn.close()
        self.assertEqual(left, 0, "dangling based_on 必须被清洗为 NULL")


class TestMigrationIndexes(_MigrationBase):
    def test_migrate_keeps_knowledge_indexes(self):
        """P6：迁移完成后同一连接内 knowledge 4 个索引齐全（原实现索引建在迁移前被 RENAME+DROP 带走）。"""
        self.load_with_old_db()
        conn = self.mod._get_conn("legacy")  # 第一次连接即触发迁移，随后立即查索引
        try:
            idx = {r["name"] for r in conn.execute("PRAGMA index_list(knowledge)").fetchall()}
        finally:
            conn.close()
        for expected in ("idx_project_conf", "idx_project_tags", "idx_based_on",
                         "idx_knowledge_tree_node"):
            self.assertIn(expected, idx)


class TestMigrationConfirmedMapping(_MigrationBase):
    def test_old_confirmed_mapped_to_confirmed_observed(self):
        """P7：旧 'confirmed' 行迁移后映射为 'confirmed-observed'，可按 confirmed 快捷过滤搜到。"""
        self.load_with_old_db()
        self.mod.search_findings("legacy")  # 触发迁移
        f = self.mod.get_finding("legacy", "legacy-1")
        self.assertEqual(f["confidence"], "confirmed-observed",
                         "旧 4 级 'confirmed' 必须映射到 5 级枚举，否则成为搜索不可见的僵尸数据")
        rows = self.mod.search_findings("legacy", confidence="confirmed")
        self.assertTrue(any(r["id"] == "legacy-1" for r in rows))


# ── P8 纯中文冲突检测 ─────────────────────────────────────────────
class TestChineseConflictDetection(harness.HarnessTestCase):
    def test_chinese_fact_conflict_detected(self):
        """纯中文 fact 能检测到共享 4-gram 的冲突候选；无共享词不误报。"""
        p = "reg_p8_chinese"
        a = seed(self.mod, p, "栈溢出导致控制流劫持")
        r2 = self.mod.store_finding(p, "堆溢出导致控制流劫持", "confirmed-observed",
                                    PARENT, type_="observation")
        r3 = self.mod.store_finding(p, "无共享词汇的条目", "confirmed-observed",
                                    PARENT, type_="observation")
        self.assertIn("_conflicts", r2, "纯中文 fact 必须检测到冲突（原实现提 0 词静默 return []）")
        self.assertTrue(any(x["id"] == a for x in r2["_conflicts"]))
        self.assertNotIn("_conflicts", r3)


if __name__ == "__main__":
    unittest.main()
