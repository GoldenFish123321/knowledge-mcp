#!/usr/bin/env python3
"""G6b 回归测试：schema 迁移（test_schema.py）。

覆盖：
- 新库：8 张核心表齐全 + knowledge/tree_nodes 新列 + 列默认值
- 旧库（v1 四级置信度）：迁移后数据保留 + 新列补齐 + FTS 回填
- 旧库（v2 时代，有 tree_node_id 但缺 v1.1 列）：列补齐带默认值 + FTS 回填
"""

import os
import sqlite3
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harness  # noqa: E402

# v1 时代旧 schema（4 级置信度 + CHECK 约束，无 tree_node_id）
_LEGACY_KNOWLEDGE_SQL = """
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
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
)
"""

# v2 时代 schema：有 tree_node_id，但缺 v1.1 列（type/evidence_uri/invalidation_reason）
_V2_KNOWLEDGE_SQL = """
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
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

_V2_TREE_NODES_SQL = """
CREATE TABLE tree_nodes (
    id          TEXT PRIMARY KEY,
    project     TEXT NOT NULL,
    parent_id   TEXT,
    node_type   TEXT NOT NULL,
    name        TEXT NOT NULL,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (parent_id) REFERENCES tree_nodes(id) ON DELETE CASCADE
);
"""

# v1.1 旧版 situations 表（缺 project_meta_json 列，batch1 前）
_V11_SITUATIONS_SQL = """
CREATE TABLE situations (
    project        TEXT PRIMARY KEY,
    objective      TEXT NOT NULL DEFAULT '',
    progress_json  TEXT NOT NULL DEFAULT '[]',
    active_work_json TEXT NOT NULL DEFAULT '{}',
    conflict_queue_json TEXT NOT NULL DEFAULT '[]',
    candidate_directions_json TEXT NOT NULL DEFAULT '[]',
    risks_json     TEXT NOT NULL DEFAULT '[]',
    user_directives_json TEXT NOT NULL DEFAULT '[]',
    timeline_json  TEXT NOT NULL DEFAULT '[]',
    version        INTEGER NOT NULL DEFAULT 1,
    frozen         TEXT,
    frozen_at      TEXT,
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# v1.1 新库应包含的 8 张核心表
_CORE_TABLES = {
    "knowledge", "tree_nodes", "situations", "directives",
    "conflicts", "audit_log", "task_meta", "knowledge_fts",
}


def _make_legacy_db(db_path, sql, rows):
    """按给定旧 schema 建库并插入行，返回连接的 cursor 无——直接关闭。"""
    conn = sqlite3.connect(db_path)
    conn.executescript(sql)
    for row in rows:
        conn.execute(
            "INSERT INTO knowledge (id, project, fact, confidence, source) "
            "VALUES (?, ?, ?, ?, ?)", row)
    conn.commit()
    conn.close()


class TestNewDbSchema(harness.HarnessTestCase):

    def test_core_tables_present(self):
        conn = self.mod._get_conn("fresh")
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        self.assertTrue(_CORE_TABLES <= tables,
                        f"缺表: {_CORE_TABLES - tables}")

    def test_knowledge_new_columns(self):
        conn = self.mod._get_conn("fresh")
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(knowledge)")}
        finally:
            conn.close()
        self.assertTrue({"type", "evidence_uri", "invalidation_reason",
                         "tree_node_id"} <= cols, f"缺列: {cols}")

    def test_tree_nodes_new_columns(self):
        conn = self.mod._get_conn("fresh")
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(tree_nodes)")}
        finally:
            conn.close()
        self.assertTrue({"status", "markers_json"} <= cols, f"缺列: {cols}")

    def test_column_defaults(self):
        conn = self.mod._get_conn("fresh")
        try:
            conn.execute(
                "INSERT INTO knowledge (id, project, fact, confidence, source) "
                "VALUES ('k1', 'fresh', 'f', 'likely', 's')")
            row = conn.execute(
                "SELECT * FROM knowledge WHERE id='k1'").fetchone()
            self.assertEqual(row["type"], "claim", "type 默认值应为 claim")
            self.assertEqual(row["tags"], "[]")
            self.assertEqual(row["evidence"], "")
            self.assertIsNone(row["evidence_uri"])

            conn.execute(
                "INSERT INTO tree_nodes (id, project, node_type, name) "
                "VALUES ('fresh>n1', 'fresh', 'function', 'n1')")
            trow = conn.execute(
                "SELECT * FROM tree_nodes WHERE id='fresh>n1'").fetchone()
            self.assertEqual(trow["status"], "normal")
            self.assertEqual(trow["markers_json"], "[]")
        finally:
            conn.close()

    def test_fts_table_and_trigram(self):
        conn = self.mod._get_conn("fresh")
        try:
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE name='knowledge_fts'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertIn("trigram", sql, "FTS5 分词器应为 trigram")


class TestLegacyMigration(harness.HarnessTestCase):
    """v1 旧库（4 级置信度 + CHECK）→ 迁移后数据保留 + 列补齐 + FTS 回填。"""

    def setUp(self):
        super().setUp()
        self.db_path = os.path.join(self.tmp, "legacy.db")
        _make_legacy_db(self.db_path, _LEGACY_KNOWLEDGE_SQL, [
            ("l1", "legacy", "old fact alpha 0x7f00", "confirmed", "role:parent|tool:ida"),
            ("l2", "legacy", "old fact beta", "likely", "role:discovery|tool:ghidra"),
        ])

    def test_data_preserved_after_migration(self):
        conn = self.mod._get_conn("legacy")
        try:
            rows = conn.execute(
                "SELECT id, fact, confidence FROM knowledge ORDER BY id").fetchall()
            self.assertEqual(len(rows), 2, "迁移后数据行数不变")
            self.assertEqual(rows[0]["fact"], "old fact alpha 0x7f00")
            self.assertEqual(rows[0]["confidence"], "confirmed-observed")
            self.assertEqual(rows[1]["confidence"], "likely")
        finally:
            conn.close()

    def test_columns_added(self):
        conn = self.mod._get_conn("legacy")
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(knowledge)")}
            self.assertTrue({"tree_node_id", "type", "evidence_uri",
                             "invalidation_reason"} <= cols)
            row = conn.execute(
                "SELECT type FROM knowledge WHERE id='l1'").fetchone()
            self.assertEqual(row["type"], "claim", "迁移后旧行 type 补默认 claim")
        finally:
            conn.close()

    def test_fts_backfill_for_legacy_data(self):
        conn = self.mod._get_conn("legacy")
        try:
            # FTS 索引已回填：影子表非空
            idx = conn.execute("SELECT count(*) FROM knowledge_fts_idx").fetchone()[0]
            self.assertGreater(idx, 0, "FTS 应已回填存量数据")
        finally:
            conn.close()
        res = self.mod.search_findings("legacy", query="alpha", use_fts=True)
        self.assertEqual(len(res), 1, "FTS 回填后 use_fts 搜索应命中旧数据")
        self.assertEqual(res[0]["id"], "l1")

    def test_fts_backfill_direct_match(self):
        conn = self.mod._get_conn("legacy")
        try:
            n = conn.execute(
                "SELECT count(*) FROM knowledge_fts f "
                "JOIN knowledge k ON k.rowid = f.rowid "
                "WHERE knowledge_fts MATCH '\"beta\"'").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(n, 1, "FTS 表内应能直接 MATCH 旧行")


class TestV2EraMigration(harness.HarnessTestCase):
    """v2 时代库（有 tree_node_id、缺 v1.1 列）→ 列补齐带默认值 + FTS 回填。"""

    def setUp(self):
        super().setUp()
        db_path = os.path.join(self.tmp, "v2.db")
        conn = sqlite3.connect(db_path)
        conn.executescript(_V2_KNOWLEDGE_SQL + _V2_TREE_NODES_SQL)
        conn.execute(
            "INSERT INTO knowledge (id, project, fact, confidence, source, tree_node_id) "
            "VALUES ('v1', 'v2', 'pre v11 fact sub_4012a0', 'confirmed-observed', 's', 'v2>node1')")
        conn.execute(
            "INSERT INTO tree_nodes (id, project, parent_id, node_type, name) "
            "VALUES ('v2>node1', 'v2', NULL, 'function', 'node1')")
        conn.commit()
        conn.close()

    def test_v11_columns_added_with_defaults(self):
        conn = self.mod._get_conn("v2")
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(knowledge)")}
            self.assertTrue({"type", "evidence_uri", "invalidation_reason"} <= cols)
            row = conn.execute(
                "SELECT type, evidence_uri FROM knowledge WHERE id='v1'").fetchone()
            self.assertEqual(row["type"], "claim")
            self.assertIsNone(row["evidence_uri"])

            tcols = {r[1] for r in conn.execute("PRAGMA table_info(tree_nodes)")}
            self.assertTrue({"status", "markers_json"} <= tcols)
            trow = conn.execute(
                "SELECT status, markers_json FROM tree_nodes WHERE id='v2>node1'").fetchone()
            self.assertEqual(trow["status"], "normal")
            self.assertEqual(trow["markers_json"], "[]")
        finally:
            conn.close()

    def test_v2_data_preserved_and_fts_backfilled(self):
        self.mod._get_conn("v2")
        res = self.mod.search_findings("v2", query="sub_4012a0", use_fts=True)
        self.assertEqual(len(res), 1, "v2 旧数据应保留且 FTS 回填")
        self.assertEqual(res[0]["id"], "v1")


class TestBatch1SituationsMigration(harness.HarnessTestCase):
    """batch1 旧库（situations 缺 project_meta_json）→ 迁移 5 补列带默认值 + 数据保留。"""

    def setUp(self):
        super().setUp()
        db_path = os.path.join(self.tmp, "v11.db")
        conn = sqlite3.connect(db_path)
        conn.executescript(_V2_KNOWLEDGE_SQL + _V2_TREE_NODES_SQL + _V11_SITUATIONS_SQL)
        conn.execute(
            "INSERT INTO situations (project, objective) VALUES ('v11', 'old objective')")
        conn.commit()
        conn.close()

    def test_project_meta_json_column_added_with_default(self):
        conn = self.mod._get_conn("v11")
        try:
            cols = {r[1] for r in conn.execute("PRAGMA table_info(situations)")}
            self.assertIn("project_meta_json", cols, "迁移 5 应补 project_meta_json 列")
            row = conn.execute(
                "SELECT project_meta_json, objective FROM situations WHERE project='v11'"
            ).fetchone()
            self.assertEqual(row["project_meta_json"], "{}", "旧行补默认 '{}'")
            self.assertEqual(row["objective"], "old objective", "迁移保留原数据")
        finally:
            conn.close()

    def test_situation_get_parses_migrated_meta(self):
        s = self.mod.situation_get("v11")
        self.assertEqual(s["project_meta"], {}, "迁移后旧局面读回 project_meta={}")
        self.assertEqual(s["objective"], "old objective")


if __name__ == "__main__":
    unittest.main()
