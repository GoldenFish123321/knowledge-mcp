#!/usr/bin/env python3
"""G6b 回归测试：FTS5 全文索引（test_fts.py）。

覆盖：
- trigram 分词器 MATCH（子串匹配）
- 触发器三向同步：INSERT / UPDATE / DELETE 后 FTS 与 knowledge 保持一致
- 存量数据回填：旧库首连建 FTS 时自动索引已有行
"""

import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402


class TestFtsTriggers(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()
        self.p = "fts_trig"

    def _fts_count(self, term):
        """直接对 FTS 表 MATCH 计数（绕过 search_findings 的 WHERE project 过滤）。"""
        conn = self.mod._get_conn(self.p)
        try:
            return conn.execute(
                "SELECT count(*) FROM knowledge_fts WHERE knowledge_fts MATCH ?",
                (f'"{term}"',)).fetchone()[0]
        finally:
            conn.close()

    def test_trigram_tokenizer(self):
        conn = self.mod._get_conn(self.p)
        try:
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name='knowledge_fts'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertIn("trigram", sql, "分词器应为 trigram（支持子串 MATCH）")

    def test_insert_sync(self):
        r = self.mod.store_finding(
            project=self.p, fact="decrypt routine at sub_4012a0",
            confidence="confirmed-observed", source="role:discovery|tool:ida",
            type_="observation", tags=["crypto"])
        self.assertEqual(self._fts_count("sub_4012a0"), 1, "INSERT 触发器同步")
        # trigram 子串：4012 命中 sub_4012a0
        res = self.mod.search_findings(self.p, query="4012", use_fts=True)
        self.assertEqual([x["id"] for x in res], [r["id"]])
        # tags 也被索引
        self.assertGreaterEqual(self._fts_count("crypto"), 1)

    def test_update_sync(self):
        r = self.mod.store_finding(
            project=self.p, fact="old token xylophone_alpha",
            confidence="confirmed-observed", source="role:discovery|tool:ida",
            type_="observation")
        self.assertEqual(self._fts_count("xylophone_alpha"), 1)
        self.mod.update_finding(project=self.p, kid=r["id"],
                                fact="new token xylophone_beta")
        self.assertEqual(self._fts_count("xylophone_alpha"), 0,
                         "UPDATE 触发器删除旧行索引")
        self.assertEqual(self._fts_count("xylophone_beta"), 1,
                         "UPDATE 触发器插入新行索引")

    def test_delete_sync(self):
        r = self.mod.store_finding(
            project=self.p, fact="doomed token zephyr_77",
            confidence="confirmed-observed", source="role:discovery|tool:ida",
            type_="observation")
        self.assertEqual(self._fts_count("zephyr_77"), 1)
        conn = self.mod._get_conn(self.p)
        try:
            conn.execute("DELETE FROM knowledge WHERE id = ?", (r["id"],))
            conn.commit()
        finally:
            conn.close()
        self.assertEqual(self._fts_count("zephyr_77"), 0, "DELETE 触发器同步移除")
        self.assertEqual(len(self.mod.search_findings(self.p, query="zephyr", use_fts=True)), 0)

    def test_match_query_with_weird_token_falls_back(self):
        # 非常规 token（MATCH 语法异常）→ 回退 LIKE 不抛错
        self.mod.store_finding(project=self.p, fact="normal token 0x41414141",
                               confidence="confirmed-observed",
                               source="role:discovery|tool:ida", type_="observation")
        res = self.mod.search_findings(self.p, query="(", use_fts=True)
        self.assertIsInstance(res, list, "异常 MATCH 表达式应回退 LIKE 而非抛错")


class TestFtsBackfill(harness.HarnessTestCase):
    def setUp(self):
        super().setUp()

    def test_backfill_existing_rows(self):
        """旧库只有 knowledge 表（无 FTS）→ 首连自动建 FTS 并回填存量。"""
        db_path = os.path.join(self.tmp, "old.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE knowledge (
                id          TEXT PRIMARY KEY,
                project     TEXT NOT NULL,
                fact        TEXT NOT NULL,
                confidence  TEXT NOT NULL,
                source      TEXT NOT NULL,
                evidence    TEXT NOT NULL DEFAULT '',
                based_on    TEXT,
                tags        TEXT NOT NULL DEFAULT '[]',
                tree_node_id TEXT,
                type        TEXT NOT NULL DEFAULT 'claim',
                evidence_uri TEXT,
                invalidation_reason TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        for i in range(3):
            conn.execute(
                "INSERT INTO knowledge (id, project, fact, confidence, source) "
                "VALUES (?, 'old', ?, 'confirmed-observed', 's')",
                (f"o{i}", f"pre-existing fact number {i}"))
        conn.commit()
        conn.close()

        conn = self.mod._get_conn("old")
        try:
            idx = conn.execute("SELECT count(*) FROM knowledge_fts_idx").fetchone()[0]
            self.assertGreater(idx, 0, "FTS 应回填存量数据")
        finally:
            conn.close()
        res = self.mod.search_findings("old", query="number", use_fts=True)
        self.assertEqual(len(res), 3, "回填后 use_fts 搜索命中全部旧行")

    def test_backfill_idempotent_on_reconnect(self):
        """重复连接不重复回填（knowledge_fts_idx 非空则跳过）。"""
        db_path = os.path.join(self.tmp, "old2.db")
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE knowledge (
                id          TEXT PRIMARY KEY,
                project     TEXT NOT NULL,
                fact        TEXT NOT NULL,
                confidence  TEXT NOT NULL,
                source      TEXT NOT NULL,
                evidence    TEXT NOT NULL DEFAULT '',
                based_on    TEXT,
                tags        TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.execute(
            "INSERT INTO knowledge (id, project, fact, confidence, source) "
            "VALUES ('k1', 'old2', 'idempotent token quasar_9', 'confirmed-observed', 's')")
        conn.commit()
        conn.close()

        self.mod._get_conn("old2")
        conn = self.mod._get_conn("old2")  # 第二次连接
        try:
            n = conn.execute(
                "SELECT count(*) FROM knowledge_fts WHERE knowledge_fts MATCH '\"quasar_9\"'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 1, "回填幂等：不产生重复索引行")


if __name__ == "__main__":
    unittest.main()
