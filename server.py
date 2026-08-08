#!/usr/bin/env python3
"""
Findings MCP Server — 轻量级 Agent 推理发现存储，带可信度标注与推理链

五级置信度（适配 CTF 逆向多 Agent 工作流）:
  confirmed-observed — 可复现的原始工具输出，零推理，子 Agent 直接提交
  confirmed-inferred  — 基于观察推理的结论，需两个独立子 Agent 交叉验证 + 父 Agent 裁决
  likely              — 子 Agent 的单项推断，尚未交叉验证
  speculative         — 父 Agent 的假设/猜测，子 Agent 无权提出
  disproved           — 已证伪（矛盾/新证据推翻），触发级联降级

工具:
  findings_store  — 存储一条发现
  findings_search — 搜索发现
  findings_get    — 获取单条
  findings_update — 更新（含级联降级 + 冲突检测）
"""

import os
import sys
import json
import uuid
import sqlite3
import asyncio
from pathlib import Path
from datetime import datetime, timezone

from mcp.server.lowlevel import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server

# ─── 配置 ──────────────────────────────────────────────────────────
DB_DIR = Path(os.environ.get("FINDINGS_DB_DIR", os.path.expanduser("~/.hermes/findings")))
DB_DIR.mkdir(parents=True, exist_ok=True)

VALID_CONFIDENCE = {
    "confirmed-observed",
    "confirmed-inferred",
    "likely",
    "speculative",
    "disproved",
}
MAX_FACT_LENGTH = 4000

# 树节点类型
VALID_NODE_TYPES = {"project", "file", "function", "class", "section"}

# 树节点路径分隔符
TREE_SEP = ">"

# 需要冲突检测的置信度——所有"已确认/已证伪"的级别
_CONFLICT_CHECK_CONFIDENCE = {"confirmed-observed", "confirmed-inferred", "disproved"}

# ─── v1.1 写库 gate 常量 ───────────────────────────────────────────
# 信息对象四类 type（v2 §6.4 / v1.1 §1.3 ②）
VALID_TYPES = {"observation", "claim", "hypothesis", "task"}

# 子 Agent 角色——禁止标记 confirmed-inferred / speculative（v1.1 §1.3 ①）
_SUBAGENT_ROLES = {"discovery", "detector", "judge", "analyst", "leaf"}

# 角色受限置信度——仅父 Agent（role=parent）可标记；
# role 缺失/无法解析 → 默认拒绝（宁严勿松）；confirmed-observed/likely/disproved 不受角色限制
_ROLE_GATED_CONFIDENCE = {"confirmed-inferred", "speculative"}

# ─── SQLite 数据层 ────────────────────────────────────────────────

def _get_db_path(project: str) -> Path:
    """返回项目数据库文件路径。非法项目名抛出 ValueError。"""
    import re
    if not re.match(r'^[\w\-\.]+$', project):
        raise ValueError(f"Invalid project name: {project}")
    return DB_DIR / f"{project}.db"


def _migrate_schema(conn: sqlite3.Connection):
    """
    检测并迁移旧版 schema。
    1. 旧版 4 级置信度 → 新版 5 级（移除 CHECK 约束）
    2. 添加 tree_node_id 列（v2 → v3 树状结构支持）
    3. knowledge 表添加 v1.1 列：type / evidence_uri / invalidation_reason
    4. tree_nodes 表添加 v1.1 列：status / markers_json
    （6 张新表 + FTS5 由 _get_conn 的 CREATE TABLE IF NOT EXISTS 与 _ensure_fts_index 负责，
      此处只做"列级增量迁移"，保证旧 DB 首连自动升级且不抛异常。）
    """
    cursor = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='knowledge'"
    )
    row = cursor.fetchone()
    if not row:
        return
    schema_sql = row[0]

    # ── 迁移 1：旧版 4 级置信度 → 新版 5 级 ──
    if "'confirmed','disproved','likely','speculative'" in schema_sql:
        conn.execute("ALTER TABLE knowledge RENAME TO knowledge_old")
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
                updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (based_on) REFERENCES knowledge(id) ON DELETE SET NULL
            )
        """)
        conn.execute("INSERT INTO knowledge SELECT * FROM knowledge_old")
        conn.execute("DROP TABLE knowledge_old")
        conn.commit()
        # 重新读取 schema
        schema_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='knowledge'"
        ).fetchone()[0]

    # ── 迁移 2：添加 tree_node_id 列 ──
    if "tree_node_id" not in schema_sql:
        conn.execute("ALTER TABLE knowledge ADD COLUMN tree_node_id TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_knowledge_tree_node "
            "ON knowledge(project, tree_node_id)"
        )
        conn.commit()

    # ── 迁移 3：knowledge 表添加 v1.1 新列 ──
    # SQLite 不支持 ALTER TABLE ADD COLUMN IF NOT EXISTS，需先查 pragma 判断列是否存在
    knowledge_cols = {r[1] for r in conn.execute("PRAGMA table_info(knowledge)").fetchall()}
    if "type" not in knowledge_cols:
        conn.execute("ALTER TABLE knowledge ADD COLUMN type TEXT NOT NULL DEFAULT 'claim'")
    if "evidence_uri" not in knowledge_cols:
        conn.execute("ALTER TABLE knowledge ADD COLUMN evidence_uri TEXT")
    if "invalidation_reason" not in knowledge_cols:
        conn.execute("ALTER TABLE knowledge ADD COLUMN invalidation_reason TEXT")

    # ── 迁移 4：tree_nodes 表添加 v1.1 新列 ──
    tree_cols = {r[1] for r in conn.execute("PRAGMA table_info(tree_nodes)").fetchall()}
    if "status" not in tree_cols:
        conn.execute("ALTER TABLE tree_nodes ADD COLUMN status TEXT NOT NULL DEFAULT 'normal'")
    if "markers_json" not in tree_cols:
        conn.execute("ALTER TABLE tree_nodes ADD COLUMN markers_json TEXT NOT NULL DEFAULT '[]'")
    conn.commit()


def _get_conn(project: str) -> sqlite3.Connection:
    """获取项目数据库连接，自动建表并迁移旧 schema。"""
    db_path = _get_db_path(project)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS knowledge (
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
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (based_on) REFERENCES knowledge(id) ON DELETE SET NULL
        )
    """)
    conn.execute("CREATE TABLE IF NOT EXISTS tree_nodes ("
        "id          TEXT PRIMARY KEY,"
        "project     TEXT NOT NULL,"
        "parent_id   TEXT,"
        "node_type   TEXT NOT NULL,"
        "name        TEXT NOT NULL,"
        "sort_order  INTEGER NOT NULL DEFAULT 0,"
        "status      TEXT NOT NULL DEFAULT 'normal',"
        "markers_json TEXT NOT NULL DEFAULT '[]',"
        "created_at  TEXT NOT NULL DEFAULT (datetime('now')),"
        "FOREIGN KEY (parent_id) REFERENCES tree_nodes(id) ON DELETE CASCADE"
        ")")

    # ── v1.1 新增表 ──
    # situations：局面对象（状态层核心），每项目一行，version 用于 HANDOFF 版本化
    conn.execute("CREATE TABLE IF NOT EXISTS situations ("
        "project        TEXT PRIMARY KEY,"
        "objective      TEXT NOT NULL DEFAULT '',"
        "progress_json  TEXT NOT NULL DEFAULT '[]',"
        "active_work_json TEXT NOT NULL DEFAULT '{}',"
        "conflict_queue_json TEXT NOT NULL DEFAULT '[]',"
        "candidate_directions_json TEXT NOT NULL DEFAULT '[]',"
        "risks_json     TEXT NOT NULL DEFAULT '[]',"
        "user_directives_json TEXT NOT NULL DEFAULT '[]',"
        "timeline_json  TEXT NOT NULL DEFAULT '[]',"
        "version        INTEGER NOT NULL DEFAULT 1,"
        "frozen         TEXT,"
        "frozen_at      TEXT,"
        "updated_at     TEXT NOT NULL DEFAULT (datetime('now'))"
        ")")
    # directives：用户指令待办（指挥层核心），D-XXXX 递增编号
    conn.execute("CREATE TABLE IF NOT EXISTS directives ("
        "id          TEXT PRIMARY KEY,"
        "project     TEXT NOT NULL,"
        "text        TEXT NOT NULL,"
        "anchor      TEXT,"
        "type        TEXT NOT NULL,"
        "status      TEXT NOT NULL DEFAULT 'received',"
        "repeat_count INTEGER NOT NULL DEFAULT 0,"
        "created_at  TEXT NOT NULL DEFAULT (datetime('now')),"
        "resolved_at TEXT,"
        "outcome     TEXT,"
        "resolved_by TEXT"
        ")")
    # conflicts：冲突对象（状态机），C-XXXX 递增编号
    conn.execute("CREATE TABLE IF NOT EXISTS conflicts ("
        "id            TEXT PRIMARY KEY,"
        "project       TEXT NOT NULL,"
        "conflict_type INTEGER NOT NULL,"
        "party_a_id    TEXT NOT NULL,"
        "party_a_summary TEXT NOT NULL,"
        "party_a_evidence TEXT NOT NULL,"
        "party_b_id    TEXT NOT NULL,"
        "party_b_summary TEXT NOT NULL,"
        "party_b_evidence TEXT NOT NULL,"
        "reporter      TEXT NOT NULL,"
        "status        TEXT NOT NULL DEFAULT 'pending',"
        "strategy      TEXT,"
        "resolution    TEXT,"
        "created_at    TEXT NOT NULL DEFAULT (datetime('now')),"
        "updated_at    TEXT NOT NULL DEFAULT (datetime('now')),"
        "resolved_at   TEXT"
        ")")
    # audit_log：违规审计（监督层），自增 ID
    conn.execute("CREATE TABLE IF NOT EXISTS audit_log ("
        "id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "project     TEXT NOT NULL,"
        "actor       TEXT NOT NULL,"
        "rule_id     TEXT NOT NULL,"
        "detail      TEXT NOT NULL,"
        "created_at  TEXT NOT NULL DEFAULT (datetime('now'))"
        ")")
    # task_meta：task 专属元数据，finding_id 关联 knowledge.id
    conn.execute("CREATE TABLE IF NOT EXISTS task_meta ("
        "finding_id      TEXT PRIMARY KEY,"
        "hypothesis_id   TEXT,"
        "agent           TEXT,"
        "budget_tool_calls INTEGER,"
        "budget_tokens   INTEGER,"
        "budget_seconds  INTEGER,"
        "task_status     TEXT NOT NULL DEFAULT 'todo',"
        "dependencies_json TEXT NOT NULL DEFAULT '[]'"
        ")")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_project_conf ON knowledge(project, confidence)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_project_tags ON knowledge(project, tags)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_based_on ON knowledge(project, based_on)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tree_project ON tree_nodes(project)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tree_parent ON tree_nodes(project, parent_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tree_type ON tree_nodes(project, node_type)")
    conn.commit()

    # 迁移旧 schema（必须在 tree_node_id 索引之前，因为旧 DB 还没有该列）
    _migrate_schema(conn)

    # tree_node_id 索引在迁移之后创建（迁移会添加该列）
    conn.execute("CREATE INDEX IF NOT EXISTS idx_knowledge_tree_node ON knowledge(project, tree_node_id)")
    conn.commit()

    # FTS5 全文索引（放在迁移之后：迁移 1 可能 RENAME 重建 knowledge 表，必须先完成再建 FTS）
    _ensure_fts_index(conn)
    return conn


def _ensure_fts_index(conn: sqlite3.Connection):
    """
    创建 knowledge_fts 全文索引（FTS5 外部内容表）+ 同步触发器 + 存量数据回填。

    - content='knowledge' 外部内容表，索引 fact + evidence + tags 三列
    - 分词器优先 trigram（SQLite ≥3.34，支持子串/LIKE 类匹配，适合代码/符号搜索）；
      若当前 SQLite 编译版本不支持 trigram，回退 unicode61
    - knowledge 主键是 TEXT id（非 WITHOUT ROWID 表），rowid 隐式存在，可作为 FTS rowid
    - 幂等：虚拟表 IF NOT EXISTS、触发器 IF NOT EXISTS；存量回填仅在 FTS 为空时执行
    """
    # 建虚拟表（trigram 优先，失败回退 unicode61）
    try:
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                fact, evidence, tags,
                content='knowledge', content_rowid='rowid', tokenize='trigram'
            )
        """)
    except sqlite3.OperationalError:
        # 回退：老 SQLite / 未编译 trigram 时使用 unicode61
        conn.execute("DROP TABLE IF EXISTS knowledge_fts")
        conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_fts USING fts5(
                fact, evidence, tags,
                content='knowledge', content_rowid='rowid', tokenize='unicode61'
            )
        """)

    # 同步触发器：INSERT / DELETE / UPDATE 三向同步
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS knowledge_ai AFTER INSERT ON knowledge BEGIN
            INSERT INTO knowledge_fts(rowid, fact, evidence, tags)
            VALUES (new.rowid, new.fact, new.evidence, new.tags);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS knowledge_ad AFTER DELETE ON knowledge BEGIN
            INSERT INTO knowledge_fts(knowledge_fts, rowid, fact, evidence, tags)
            VALUES ('delete', old.rowid, old.fact, old.evidence, old.tags);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS knowledge_au AFTER UPDATE ON knowledge BEGIN
            INSERT INTO knowledge_fts(knowledge_fts, rowid, fact, evidence, tags)
            VALUES ('delete', old.rowid, old.fact, old.evidence, old.tags);
            INSERT INTO knowledge_fts(rowid, fact, evidence, tags)
            VALUES (new.rowid, new.fact, new.evidence, new.tags);
        END
    """)

    # 存量数据回填：触发器只对新写入生效，旧库已有数据需在此手动同步一次
    # 注意：FTS5 外部内容表的 COUNT(*) 会读取 content 表（knowledge），索引为空时
    # 也返回 content 行数，无法判断索引是否为空 —— 改用 FTS5 影子表 knowledge_fts_idx
    # （索引分段表，空索引时为 0 行）判断是否需要回填。
    idx_count = conn.execute("SELECT count(*) FROM knowledge_fts_idx").fetchone()[0]
    if idx_count == 0:
        conn.execute("""
            INSERT INTO knowledge_fts(rowid, fact, evidence, tags)
            SELECT rowid, fact, evidence, tags FROM knowledge
        """)
    conn.commit()


def _row_to_dict(row: sqlite3.Row) -> dict:
    """将 sqlite3.Row 转为普通 dict。"""
    return dict(row)


def _now() -> str:
    """返回 UTC 时间字符串。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── 树状结构核心逻辑 ──────────────────────────────────────────────

def _parse_tree_path(path: str) -> list[str]:
    """将 tree_path 字符串解析为路径段列表。

    "challenge.exe>sub_4012a0" → ["challenge.exe", "sub_4012a0"]
    """
    return [s.strip() for s in path.split(TREE_SEP) if s.strip()]


def _build_tree_id(project: str, segments: list[str]) -> str:
    """从项目名和路径段构建节点 ID。

    ("HITCON2024_rev1", ["challenge.exe", "sub_4012a0"])
    → "HITCON2024_rev1>challenge.exe>sub_4012a0"
    """
    if not segments:
        return project
    return TREE_SEP.join([project] + segments)


def _parent_tree_id(node_id: str) -> str | None:
    """获取父节点 ID。根节点（只有 project 名）返回 None。"""
    parts = node_id.split(TREE_SEP)
    if len(parts) <= 1:
        return None
    return TREE_SEP.join(parts[:-1])


def _ensure_tree_path(conn: sqlite3.Connection, project: str,
                      path: str, node_type: str = "function") -> str:
    """确保树路径存在，逐层自动创建缺失节点。

    返回最终叶子节点的 ID。
    """
    segments = _parse_tree_path(path)
    if not segments:
        raise ValueError("tree_path cannot be empty")

    # 确保根节点（project 自身）存在
    now = _now()
    conn.execute("""
        INSERT OR IGNORE INTO tree_nodes (id, project, parent_id, node_type, name, created_at)
        VALUES (?, ?, NULL, 'project', ?, ?)
    """, (project, project, project, now))

    # 逐层创建
    parent_id = project
    for i, seg in enumerate(segments):
        node_id = _build_tree_id(project, segments[:i+1])
        # 如果 segment 是最后一个且 node_type 指定了，用它；否则默认 'section'
        seg_type = node_type if i == len(segments) - 1 else "section"
        conn.execute("""
            INSERT OR IGNORE INTO tree_nodes (id, project, parent_id, node_type, name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (node_id, project, parent_id, seg_type, seg, now))
        parent_id = node_id

    conn.commit()
    return parent_id


def tree_store(project: str, path: str, node_type: str = "function",
               parent_path: str | None = None) -> dict:
    """创建或更新树节点。

    自动创建路径上所有缺失的中间节点。
    parent_path 可选：指定父路径而非从 project 根开始。
    """
    if node_type not in VALID_NODE_TYPES:
        raise ValueError(f"Invalid node_type: {node_type}. Must be one of {VALID_NODE_TYPES}")

    conn = _get_conn(project)

    # 构建完整路径
    if parent_path:
        segments = _parse_tree_path(parent_path) + _parse_tree_path(path)
    else:
        segments = _parse_tree_path(path)

    if not segments:
        conn.close()
        raise ValueError("path cannot be empty")

    node_id = _ensure_tree_path(conn, project,
                                TREE_SEP.join(segments), node_type)

    # 获取完整节点信息
    row = conn.execute(
        "SELECT * FROM tree_nodes WHERE id = ?", (node_id,)
    ).fetchone()
    result = _row_to_dict(row)

    conn.close()
    return result


def tree_get(project: str, node_id: str) -> dict | None:
    """获取树节点及其子节点、挂载的 findings。"""
    conn = _get_conn(project)

    row = conn.execute(
        "SELECT * FROM tree_nodes WHERE id = ? AND project = ?",
        (node_id, project)
    ).fetchone()
    if not row:
        conn.close()
        return None

    result = _row_to_dict(row)

    # 子节点
    children = conn.execute(
        "SELECT * FROM tree_nodes WHERE parent_id = ? ORDER BY sort_order, name",
        (node_id,)
    ).fetchall()
    result["children"] = [_row_to_dict(r) for r in children]

    # 直接挂载的 findings
    findings = conn.execute(
        "SELECT * FROM knowledge WHERE tree_node_id = ? ORDER BY created_at DESC",
        (node_id,)
    ).fetchall()
    result["findings"] = [_row_to_dict(r) for r in findings]

    # 父节点信息
    parent_id = result.get("parent_id")
    if parent_id:
        parent_row = conn.execute(
            "SELECT id, name, node_type FROM tree_nodes WHERE id = ?",
            (parent_id,)
        ).fetchone()
        if parent_row:
            result["parent"] = _row_to_dict(parent_row)

    conn.close()
    return result


def tree_search(project: str, query: str = "", node_type: str | None = None,
                parent_id: str | None = None, limit: int = 50) -> list[dict]:
    """搜索树节点。"""
    conn = _get_conn(project)

    conditions = ["project = ?"]
    params = [project]

    if query:
        conditions.append("name LIKE ?")
        params.append(f"%{query}%")
    if node_type:
        if node_type not in VALID_NODE_TYPES:
            conn.close()
            raise ValueError(f"Invalid node_type: {node_type}")
        conditions.append("node_type = ?")
        params.append(node_type)
    if parent_id:
        conditions.append("parent_id = ?")
        params.append(parent_id)

    where = " AND ".join(conditions)
    sql = f"SELECT * FROM tree_nodes WHERE {where} ORDER BY node_type, name LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    results = [_row_to_dict(r) for r in rows]
    conn.close()
    return results


def tree_delete(project: str, node_id: str) -> dict:
    """删除树节点。

    级联删除所有子节点（ON DELETE CASCADE）。
    挂载的 findings 的 tree_node_id 置 NULL（保留数据）。
    """
    conn = _get_conn(project)

    existing = conn.execute(
        "SELECT * FROM tree_nodes WHERE id = ? AND project = ?",
        (node_id, project)
    ).fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Tree node not found: {node_id}")

    # 把子节点的 findings 也置 NULL
    # 先收集所有将被删除的节点 ID（包括自身和所有子孙）
    def _collect_descendants(nid: str) -> list[str]:
        ids = [nid]
        children = conn.execute(
            "SELECT id FROM tree_nodes WHERE parent_id = ?", (nid,)
        ).fetchall()
        for c in children:
            ids.extend(_collect_descendants(c["id"]))
        return ids

    all_ids = _collect_descendants(node_id)

    # 置 NULL 所有挂载在这些节点上的 findings
    placeholders = ",".join(["?" for _ in all_ids])
    conn.execute(
        f"UPDATE knowledge SET tree_node_id = NULL "
        f"WHERE tree_node_id IN ({placeholders})",
        all_ids
    )

    # 删除节点（级联删除子节点）
    conn.execute("DELETE FROM tree_nodes WHERE id = ?", (node_id,))
    conn.commit()

    result = {
        "deleted_node": _row_to_dict(existing),
        "deleted_descendants_count": len(all_ids) - 1,
    }
    conn.close()
    return result


# ─── 监督层（v1.1 §3.6 E 组）：audit 审计 + freeze 冻结状态 ──────────
# 规则编号（v1.1 §1.2 ⑥）：
#   R1 委派前无 search | R2 同假设失败≥2 | R3 汇报无置信度 | R4 委派 context 无验证 | R5 冻结触发
# 自动冻结条件（v1.1 §3.6）：违规计数≥3 OR 未解决待办≥3 OR 存在 repeat_count≥2 的指令；
# 显式冻结由 freeze_trigger 写 situations.frozen（非空）触发。MCP 侧只做状态存储与查询原语，
# "冻结拦截" 属平台层 hook（gap-plan §6.3：MCP 边界 = 状态存储 + 查询）。

FREEZE_VIOLATION_THRESHOLD = 3      # 违规计数阈值（audit_log count）
FREEZE_UNRESOLVED_THRESHOLD = 3     # 未解决待办阈值（directives status != 'resolved'）
FREEZE_REPEAT_THRESHOLD = 2         # 重复指令阈值（directives repeat_count）
_EXPLICIT_FREEZE_PREFIX = "显式冻结"  # reason 中显式冻结项前缀，与自动触发项区分


def audit_violation(project: str, actor: str, rule_id: str, detail: str) -> dict:
    """记一条违规到 audit_log，返回完整记录（含自增 id）。

    rule_id 取值（v1.1 §1.2 ⑥）：
      R1 委派前无 search | R2 同假设失败≥2 | R3 汇报无置信度 |
      R4 委派 context 无验证 | R5 冻结触发（freeze_trigger 自动记录）
    """
    conn = _get_conn(project)
    try:
        cur = conn.execute(
            "INSERT INTO audit_log (project, actor, rule_id, detail, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (project, actor, rule_id, detail, _now()),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM audit_log WHERE id = ?", (cur.lastrowid,)
        ).fetchone()
        return _row_to_dict(row)
    finally:
        conn.close()


def audit_list(project: str, rule_id: str | None = None, limit: int = 50) -> list[dict]:
    """列出审计日志，按 created_at 倒序（id 倒序作同秒 tiebreaker）。"""
    conn = _get_conn(project)
    try:
        if rule_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE project = ? AND rule_id = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (project, rule_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE project = ? "
                "ORDER BY created_at DESC, id DESC LIMIT ?",
                (project, limit),
            ).fetchall()
        return [_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def audit_stats(project: str) -> dict:
    """审计统计：{by_rule: {R1: N, ...}, total: N, recent: [最近5条摘要]}。

    recent 每条含 id/rule_id/detail（超 80 字符截断为摘要）/created_at。
    """
    conn = _get_conn(project)
    try:
        by_rule_rows = conn.execute(
            "SELECT rule_id, COUNT(*) AS cnt FROM audit_log "
            "WHERE project = ? GROUP BY rule_id ORDER BY rule_id",
            (project,),
        ).fetchall()
        by_rule = {r["rule_id"]: r["cnt"] for r in by_rule_rows}
        total = conn.execute(
            "SELECT COUNT(*) AS cnt FROM audit_log WHERE project = ?", (project,)
        ).fetchone()["cnt"]
        recent_rows = conn.execute(
            "SELECT id, rule_id, detail, created_at FROM audit_log "
            "WHERE project = ? ORDER BY created_at DESC, id DESC LIMIT 5",
            (project,),
        ).fetchall()
        recent = [
            {
                "id": r["id"],
                "rule_id": r["rule_id"],
                "detail": r["detail"] if len(r["detail"]) <= 80 else r["detail"][:80] + "…",
                "created_at": r["created_at"],
            }
            for r in recent_rows
        ]
        return {"by_rule": by_rule, "total": total, "recent": recent}
    finally:
        conn.close()


def freeze_status(project: str) -> dict:
    """冻结状态检查：{frozen: bool, reason: [触发条件...], counts: {...}}。

    冻结条件（任一满足即 frozen=true，frozen=false 时 reason=[]）：
      - 显式冻结：situations.frozen 非空（freeze_trigger 写入的原因）
      - 违规计数 ≥ FREEZE_VIOLATION_THRESHOLD（audit_log count）
      - 未解决待办 ≥ FREEZE_UNRESOLVED_THRESHOLD（directives status != 'resolved'）
      - 存在 repeat_count ≥ FREEZE_REPEAT_THRESHOLD 的指令
    """
    conn = _get_conn(project)
    try:
        sit = conn.execute(
            "SELECT frozen FROM situations WHERE project = ?", (project,)
        ).fetchone()
        explicit_frozen = sit["frozen"] if sit else None

        violations = conn.execute(
            "SELECT COUNT(*) AS cnt FROM audit_log WHERE project = ?", (project,)
        ).fetchone()["cnt"]
        unresolved = conn.execute(
            "SELECT COUNT(*) AS cnt FROM directives "
            "WHERE project = ? AND status != 'resolved'",
            (project,),
        ).fetchone()["cnt"]
        repeated = conn.execute(
            "SELECT COUNT(*) AS cnt FROM directives "
            "WHERE project = ? AND repeat_count >= ?",
            (project, FREEZE_REPEAT_THRESHOLD),
        ).fetchone()["cnt"]

        reasons = []
        if explicit_frozen is not None:
            reasons.append(f"{_EXPLICIT_FREEZE_PREFIX}: {explicit_frozen}")
        if violations >= FREEZE_VIOLATION_THRESHOLD:
            reasons.append(f"违规计数≥{FREEZE_VIOLATION_THRESHOLD}(实际{violations})")
        if unresolved >= FREEZE_UNRESOLVED_THRESHOLD:
            reasons.append(f"未解决待办≥{FREEZE_UNRESOLVED_THRESHOLD}(实际{unresolved})")
        if repeated > 0:
            reasons.append(f"存在 repeat_count≥{FREEZE_REPEAT_THRESHOLD} 的指令")

        frozen = (
            explicit_frozen is not None
            or violations >= FREEZE_VIOLATION_THRESHOLD
            or unresolved >= FREEZE_UNRESOLVED_THRESHOLD
            or repeated > 0
        )
        return {
            "frozen": frozen,
            "reason": reasons,
            "counts": {
                "violations": violations,
                "unresolved_directives": unresolved,
                "repeated_directives": repeated,
            },
        }
    finally:
        conn.close()


def freeze_trigger(project: str, reason: str) -> dict:
    """显式冻结：situations upsert 写 frozen=reason + frozen_at=_now()，
    同时 audit_violation 记一条 R5（actor='parent'，detail=reason）。

    返回当前冻结状态（freeze_status 输出），并附 frozen_at 字段
    （规格 §3.6 响应格式 {"frozen": true, "frozen_at": "..."}）。
    """
    conn = _get_conn(project)
    try:
        now = _now()
        conn.execute(
            "INSERT INTO situations (project, frozen, frozen_at, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(project) DO UPDATE SET "
            "frozen = excluded.frozen, frozen_at = excluded.frozen_at, "
            "updated_at = excluded.updated_at",
            (project, reason, now, now),
        )
        conn.commit()
    finally:
        conn.close()

    audit_violation(project, actor="parent", rule_id="R5", detail=reason)

    status = freeze_status(project)
    conn = _get_conn(project)
    try:
        sit = conn.execute(
            "SELECT frozen_at FROM situations WHERE project = ?", (project,)
        ).fetchone()
        if sit and sit["frozen_at"]:
            status["frozen_at"] = sit["frozen_at"]
    finally:
        conn.close()
    return status


def freeze_release(project: str) -> dict:
    """解除显式冻结：清空 situations.frozen/frozen_at。

    返回当前冻结状态（freeze_status 输出）；解除成功时附 released_at
    （规格 §3.6 响应格式 {"frozen": false, "released_at": "..."}）。
    注意：自动触发的冻结（违规/待办/重复指令）由对应计数变化决定，本工具只清显式标记。
    """
    conn = _get_conn(project)
    try:
        conn.execute(
            "UPDATE situations SET frozen = NULL, frozen_at = NULL, updated_at = ? "
            "WHERE project = ?",
            (_now(), project),
        )
        conn.commit()
    finally:
        conn.close()

    status = freeze_status(project)
    if not status["frozen"]:
        status["released_at"] = _now()
    return status


# ─── 核心逻辑 ──────────────────────────────────────────────────────

def _cascade_invalidate(conn: sqlite3.Connection, parent_id: str):
    """
    将被推翻条目的所有 based_on 依赖者降级为 speculative + 追加 invalidated 标签。
    递归处理二级依赖链。
    仅对非 speculative 条目降级（已是 speculative 或 disproved 的跳过）。
    """
    conn.execute("""
        UPDATE knowledge 
        SET confidence = 'speculative',
            tags = CASE
                WHEN tags NOT LIKE '%invalidated%' 
                THEN json_insert(tags, '$[#]', 'invalidated')
                ELSE tags
            END,
            updated_at = ?
        WHERE based_on = ? AND confidence NOT IN ('speculative', 'disproved')
    """, (_now(), parent_id))
    
    # 递归处理被降级条目——它们降级后，依赖它们的也需要降级
    dependents = conn.execute(
        "SELECT id FROM knowledge WHERE based_on = ? AND confidence NOT IN ('speculative', 'disproved')",
        (parent_id,)
    ).fetchall()
    for dep in dependents:
        _cascade_invalidate(conn, dep["id"])
    
    conn.commit()


def _check_conflicts(conn: sqlite3.Connection, project: str, fact: str,
                     exclude_id: str | None = None) -> list[dict]:
    """
    简单冲突检测：在 confirmed-observed / confirmed-inferred / disproved 中
    搜索与 fact 共现关键词的条目。
    exclude_id: 排除自身 ID（存储后检测时传入）。
    返回冲突条目列表（不含自身）。
    """
    import re
    words = re.findall(r'[a-zA-Z0-9_]{3,}', fact)
    if not words:
        return []
    
    conditions = [
        "project = ?",
        "confidence IN ('confirmed-observed', 'confirmed-inferred', 'disproved')",
    ]
    params = [project]
    
    word_clauses = " OR ".join(["fact LIKE ?" for _ in words])
    conditions.append(f"({word_clauses})")
    for w in words:
        params.append(f"%{w}%")
    
    if exclude_id:
        conditions.append("id != ?")
        params.append(exclude_id)
    
    where = " AND ".join(conditions)
    sql = f"SELECT id, fact, confidence, created_at FROM knowledge WHERE {where} LIMIT 5"
    rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


# ─── v1.1 写库 gate ────────────────────────────────────────────────
# ④ 只做结构校验，不做语义校验（职责边界，v1.1 §1.3 / gap-plan D2 末条）：
#    MCP 校验的是"结构存在性"——based_on 引用的 ID 存在吗？是 observation 类型吗？
#    evidence 里有两个不同 agent-id 标记吗？fact 含 'test_plan:' 吗？budget 三字段齐全吗？
#    "evidence 是否真的支持 statement"、"claim 结论是否与 observation 一致"这类语义匹配
#    是检测型子 Agent 的职责（v2 §6.4：真实存在归 MCP，匹配 statement 归检测型），
#    MCP 不假装理解语义——这是职责边界，不是疏漏。

def _parse_source_role(source: str | None) -> str | None:
    """从 source 解析 role（约定格式 agent:<id>|role:<role>|tool:<tool>）。

    大小写不敏感，返回小写 role；role 缺失/格式无法解析返回 None。
    """
    import re
    if not source:
        return None
    m = re.search(r'role:([A-Za-z0-9_\-]+)', source)
    return m.group(1).lower() if m else None


def _check_role_authority(source: str | None, confidence: str) -> None:
    """① 角色权责（v1.1 §1.3 ① / v2 §5.1）：
    - 子 Agent（discovery/detector/judge/analyst/leaf）标 confirmed-inferred / speculative → 拒绝
    - role=parent → 允许
    - role 缺失/无法解析 → 默认拒绝（宁严勿松）
    - confirmed-observed / likely / disproved 不受角色限制（子 Agent 可标）
    通过返回 None；失败 raise ValueError（write_gate_violation 格式）。
    """
    role = _parse_source_role(source)
    if confidence not in _ROLE_GATED_CONFIDENCE:
        return
    if role is None:
        raise ValueError(
            "write_gate_violation: source 无法解析 role（缺失或格式不符），"
            f"{confidence} 仅限父 Agent（role=parent）标记 | "
            "suggestion: 在 source 中带上 role:parent，或改由父 Agent 提交"
        )
    if role in _SUBAGENT_ROLES:
        if confidence == "confirmed-inferred":
            suggestion = "改为 likely 提交，由父 Agent 交叉验证后升级"
        else:
            suggestion = "由父 Agent 提出"
        raise ValueError(
            f"write_gate_violation: role={role} 无权标记 {confidence} | "
            f"suggestion: {suggestion}"
        )
    if role != "parent":
        raise ValueError(
            f"write_gate_violation: 未知 role={role} 无权标记 {confidence} | "
            "suggestion: 使用 role:parent，或由父 Agent 提交"
        )


def _check_cross_validation(evidence: str) -> None:
    """③ confirmed-inferred 交叉验证标记：evidence 必须含两个不同 agent-id。"""
    import re
    agent_ids = re.findall(r'agent:([A-Za-z0-9_\-]+)', evidence or "")
    if len(set(agent_ids)) < 2:
        raise ValueError(
            "write_gate_violation: confirmed-inferred 需两个独立子 Agent 交叉验证"
            "（evidence 必须含两个不同 agent:<id> 标记） | "
            "suggestion: 在 evidence 中追加第二个独立 agent 的验证记录，"
            "如 'agent:xxx 复核一致'"
        )


def _validate_write_gate(conn: sqlite3.Connection, confidence: str, type_: str,
                         based_on: str | None, source: str | None, fact: str,
                         task_budget: dict | None = None,
                         evidence: str = "") -> None:
    """写库 gate：四层结构校验（v1.1 §1.3 / gap-plan D2）。

    ① 角色权责：子 Agent 禁标 confirmed-inferred/speculative；role 缺失默认拒绝
    ② type 校验：claim 必须 based_on ≥1 条 observation（ID 存在且 type=observation）；
       hypothesis 必须含 'test_plan:'；task 必须带完整 budget 三字段；type 必须是合法枚举
    ③ confirmed-inferred：evidence 必须含两个不同 agent-id（交叉验证标记）
    ④ 只做结构校验，不做语义校验（见上方职责边界注释）

    通过返回 None；失败 raise ValueError，消息格式：
    "write_gate_violation: <reason> | suggestion: <suggestion>"
    """
    # ① 角色权责
    _check_role_authority(source, confidence)

    # ② type 校验
    if type_ not in VALID_TYPES:
        raise ValueError(
            f"write_gate_violation: 非法 type={type_!r}，合法值: "
            "observation/claim/hypothesis/task | "
            "suggestion: 改为合法 type 后重试"
        )
    if type_ == "claim":
        if not based_on:
            raise ValueError(
                "write_gate_violation: claim 必须引用 ≥1 observation（based_on 为空） | "
                "suggestion: 补充 based_on 指向一条 observation 的 finding ID"
            )
        ref = conn.execute(
            "SELECT type FROM knowledge WHERE id = ?", (based_on,)
        ).fetchone()
        if ref is None:
            raise ValueError(
                f"write_gate_violation: claim 的 based_on 引用不存在的 finding: {based_on} | "
                "suggestion: 先存储对应的 observation，再引用其 ID"
            )
        if ref["type"] != "observation":
            raise ValueError(
                f"write_gate_violation: claim 的 based_on 必须引用 observation"
                f"（{based_on} 的类型是 {ref['type']}） | "
                "suggestion: 将 based_on 改为指向 observation 类型的 finding"
            )
    elif type_ == "hypothesis":
        if "test_plan:" not in fact:
            raise ValueError(
                "write_gate_violation: hypothesis 的 fact 必须含 'test_plan:' 段 | "
                "suggestion: 在 fact 中追加 test_plan: <验证步骤>"
            )
    elif type_ == "task":
        if not isinstance(task_budget, dict):
            raise ValueError(
                "write_gate_violation: task 必须提供 task_budget"
                "（含 budget_tool_calls/budget_tokens/budget_seconds） | "
                "suggestion: 传入 task_budget={'budget_tool_calls': N, "
                "'budget_tokens': N, 'budget_seconds': N}"
            )
        missing = [k for k in ("budget_tool_calls", "budget_tokens", "budget_seconds")
                   if k not in task_budget]
        if missing:
            raise ValueError(
                f"write_gate_violation: task 的 task_budget 缺失字段: {missing} | "
                "suggestion: 补齐 budget_tool_calls/budget_tokens/budget_seconds 三字段"
            )

    # ③ confirmed-inferred 交叉验证标记
    if confidence == "confirmed-inferred":
        _check_cross_validation(evidence)


def store_finding(project: str, fact: str, confidence: str, source: str,
                  evidence: str = "", based_on: str | None = None,
                  tags: list[str] | None = None,
                  tree_path: str | None = None,
                  type_: str = "claim",
                  task_budget: dict | None = None,
                  task_dependencies: list | None = None,
                  task_agent: str | None = None) -> dict:
    """存储一条发现。tree_path 可选，自动创建关联的树节点。

    v1.1 写库 gate：INSERT 前做四层结构校验（角色权责 / type 校验 /
    confirmed-inferred 交叉验证标记），失败 raise ValueError（write_gate_violation）。
    type=task 时同步写入 task_meta（budget 三字段 + agent + dependencies_json）。
    """
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"Invalid confidence: {confidence}. Must be one of {VALID_CONFIDENCE}")
    if len(fact) > MAX_FACT_LENGTH:
        raise ValueError(f"Fact too long ({len(fact)} chars). Max is {MAX_FACT_LENGTH}")

    conn = _get_conn(project)

    # ── 写库 gate（INSERT 前，v1.1 §1.3）──
    try:
        _validate_write_gate(conn, confidence, type_, based_on, source, fact,
                             task_budget=task_budget, evidence=evidence)
    except ValueError:
        conn.close()
        raise

    kid = str(uuid.uuid4())
    now = _now()
    tags_json = json.dumps(tags or [], ensure_ascii=False)

    # 处理 tree_path：自动创建树节点
    tree_node_id = None
    if tree_path:
        tree_node_id = _ensure_tree_path(conn, project, tree_path)

    # 非 claim 类型若 based_on 引用不存在条目，静默置空（兼容旧行为；
    # claim 的 based_on 已由 gate 保证存在且为 observation 类型）
    if based_on and type_ != "claim":
        exists = conn.execute("SELECT 1 FROM knowledge WHERE id = ?", (based_on,)).fetchone()
        if not exists:
            based_on = None

    conn.execute("""
        INSERT INTO knowledge (id, project, fact, confidence, source, evidence,
                               based_on, tags, tree_node_id, type, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (kid, project, fact, confidence, source, evidence, based_on, tags_json,
          tree_node_id, type_, now, now))

    # type=task：同步写入 task_meta（budget 三字段 + agent + dependencies_json，hypothesis_id 可空）
    if type_ == "task":
        conn.execute("""
            INSERT INTO task_meta (finding_id, agent, budget_tool_calls,
                                   budget_tokens, budget_seconds, dependencies_json)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (kid, task_agent, task_budget["budget_tool_calls"],
              task_budget["budget_tokens"], task_budget["budget_seconds"],
              json.dumps(task_dependencies or [], ensure_ascii=False)))

    conn.commit()

    # 冲突检测
    conflicts = _check_conflicts(conn, project, fact, exclude_id=kid) \
        if confidence in _CONFLICT_CHECK_CONFIDENCE else []

    # 获取完整记录
    row = conn.execute("SELECT * FROM knowledge WHERE id = ?", (kid,)).fetchone()
    result = _row_to_dict(row)

    if conflicts:
        result["_conflicts"] = conflicts

    conn.close()
    return result


def search_findings(project: str, query: str = "", confidence: str | None = None,
                    tag: str | None = None, tree_node_id: str | None = None,
                    limit: int = 20) -> list[dict]:
    """搜索发现。tree_node_id 可选，过滤特定树节点下的 findings。"""
    conn = _get_conn(project)

    conditions = ["project = ?"]
    params = [project]

    if query:
        conditions.append("(fact LIKE ? OR evidence LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    if confidence:
        if confidence == "verified":
            conditions.append(
                "confidence IN ('confirmed-observed', 'confirmed-inferred', 'disproved')"
            )
        elif confidence == "confirmed":
            conditions.append(
                "confidence IN ('confirmed-observed', 'confirmed-inferred')"
            )
        else:
            conditions.append("confidence = ?")
            params.append(confidence)
    if tag:
        conditions.append("tags LIKE ?")
        params.append(f"%{tag}%")
    if tree_node_id:
        conditions.append("tree_node_id = ?")
        params.append(tree_node_id)

    where = " AND ".join(conditions)
    sql = f"SELECT * FROM knowledge WHERE {where} ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(sql, params).fetchall()
    results = [_row_to_dict(r) for r in rows]
    conn.close()
    return results


def get_finding(project: str, kid: str) -> dict | None:
    """获取单条发现，包含依赖计数。"""
    conn = _get_conn(project)
    row = conn.execute("SELECT * FROM knowledge WHERE id = ?", (kid,)).fetchone()
    if not row:
        conn.close()
        return None
    
    result = _row_to_dict(row)
    
    # 添加依赖计数
    dep_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM knowledge WHERE based_on = ?", (kid,)
    ).fetchone()
    result["dependent_count"] = dep_count["cnt"]
    
    conn.close()
    return result


def update_finding(project: str, kid: str, fact: str | None = None,
                   confidence: str | None = None, evidence: str | None = None,
                   tags: list[str] | None = None,
                   tree_path: str | None = None,
                   source: str | None = None) -> dict:
    """更新发现条目。标 disproved 时触发级联降级。tree_path 可选，关联到树节点。

    v1.1 写库 gate（update 版）：只校验角色权责 + confirmed-inferred 交叉验证标记——
    type 在 store 时已校验，update 一般只改置信度/证据，不重新做 type 校验。
    """
    conn = _get_conn(project)

    existing = conn.execute("SELECT * FROM knowledge WHERE id = ?", (kid,)).fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Finding not found: {kid}")

    # ── 写库 gate（update 版，v1.1 §1.3）：只校验角色权责（标 confirmed-inferred/speculative 时）
    #    仅当调用方显式传入 confidence 且目标级别受限时才触发——只改 evidence/tags 不触发，
    #    避免误拒父 Agent 已批准的 confirmed-inferred 条目补证据。
    #    若改为 confirmed-inferred，还需 evidence 双 agent 交叉验证标记 ──
    new_confidence = confidence if confidence is not None else existing["confidence"]
    new_evidence = evidence if evidence is not None else existing["evidence"]
    if confidence is not None and confidence in _ROLE_GATED_CONFIDENCE:
        try:
            _check_role_authority(source, new_confidence)
            if new_confidence == "confirmed-inferred":
                _check_cross_validation(new_evidence)
        except ValueError:
            conn.close()
            raise

    updates = []
    params = []

    if fact is not None:
        if len(fact) > MAX_FACT_LENGTH:
            conn.close()
            raise ValueError(f"Fact too long ({len(fact)} chars)")
        updates.append("fact = ?")
        params.append(fact)
    if confidence is not None:
        if confidence not in VALID_CONFIDENCE:
            conn.close()
            raise ValueError(f"Invalid confidence: {confidence}")
        updates.append("confidence = ?")
        params.append(confidence)
    if evidence is not None:
        updates.append("evidence = ?")
        params.append(evidence)
    if tags is not None:
        updates.append("tags = ?")
        params.append(json.dumps(tags, ensure_ascii=False))
    if tree_path is not None:
        tree_node_id = _ensure_tree_path(conn, project, tree_path)
        updates.append("tree_node_id = ?")
        params.append(tree_node_id)

    if not updates:
        conn.close()
        return _row_to_dict(existing)

    updates.append("updated_at = ?")
    params.append(_now())
    params.append(kid)

    conn.execute(f"UPDATE knowledge SET {', '.join(updates)} WHERE id = ?", params)
    conn.commit()

    # 如果标为 disproved，级联降级依赖者
    if confidence == "disproved" and existing["confidence"] != "disproved":
        _cascade_invalidate(conn, kid)

    # 冲突检测
    new_fact = fact if fact is not None else existing["fact"]
    new_confidence = confidence if confidence is not None else existing["confidence"]
    conflicts = _check_conflicts(conn, project, new_fact, exclude_id=kid) \
        if new_confidence in _CONFLICT_CHECK_CONFIDENCE else []
    
    # 获取更新后记录
    row = conn.execute("SELECT * FROM knowledge WHERE id = ?", (kid,)).fetchone()
    result = _row_to_dict(row)
    
    # 依赖计数
    dep_count = conn.execute("SELECT COUNT(*) as cnt FROM knowledge WHERE based_on = ?", (kid,)).fetchone()
    result["dependent_count"] = dep_count["cnt"]
    
    if conflicts:
        result["_conflicts"] = conflicts
    
    conn.close()
    return result


# ─── MCP Server ────────────────────────────────────────────────────

server = Server("findings-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="findings_store",
            description="""存储一条带可信度标注的推理发现。

置信度级别:
  confirmed-observed — 可复现的原始工具输出，零推理，直接提交（子 Agent 可提出/确认）
  confirmed-inferred  — 基于观察推理的结论，需两个独立子 Agent 交叉验证 + 父 Agent 裁决（仅父 Agent 可提出/确认）
  likely              — 子 Agent 的单项推断，尚未交叉验证（子 Agent 提出，父 Agent 裁决）
  speculative         — 父 Agent 的假设/猜测（仅父 Agent 可提出，子 Agent 无权）
  disproved           — 已证伪，发现矛盾即标记（任意角色可提出/识别）

存储成功后自动检测与已有 confirmed-observed/confirmed-inferred/disproved 发现的潜在冲突。

参数:
  project     — 项目名（如 'HITCON2024_rev1'），自动创建独立数据库
  fact        — 事实陈述（自然语言，≤4000字符）
  confidence  — 置信度：confirmed-observed|confirmed-inferred|likely|speculative|disproved
  source      — 来源描述（如 'tool:ida'、'inference:cross-validated'、'user:stated'）
  evidence    — 证据摘要（工具输出/反汇编片段/用户原话，≤500字符推荐）
  based_on    — 推理来源的 finding ID，用于追溯推理链
  tags        — 标签列表（如 ['crypto','rc4']）
  tree_path   — 树状结构路径，如 'challenge.exe>sub_4012a0'（> 分隔层级），自动创建路径上所有缺失节点""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "fact": {"type": "string", "description": "事实陈述"},
                    "confidence": {"type": "string", "enum": sorted(VALID_CONFIDENCE)},
                    "source": {"type": "string", "description": "来源描述"},
                    "evidence": {"type": "string", "default": "", "description": "证据摘要"},
                    "based_on": {"type": "string", "description": "推理来源 finding ID"},
                    "tags": {"type": "array", "items": {"type": "string"}, "description": "标签列表"},
                    "tree_path": {"type": "string", "description": "树状结构路径，如 'challenge.exe>sub_4012a0'"},
                },
                "required": ["project", "fact", "confidence", "source"],
            },
        ),
        Tool(
            name="findings_search",
            description="""搜索推理发现。

搜索规则:
  - query 对 fact 和 evidence 字段做文本匹配
  - confidence 过滤置信度级别：
    'verified' 快捷匹配 confirmed-observed + confirmed-inferred + disproved（所有已验证条目）
    'confirmed' 快捷匹配 confirmed-observed + confirmed-inferred（兼容旧版）
  - tag 过滤标签
  - tree_node_id 过滤特定树节点下的 findings
  - 多条件 AND 逻辑
  - 按创建时间倒序

参数:
  project       — 项目名
  query         — 搜索关键词（可选，留空返回全部）
  confidence    — 置信度过滤
  tag           — 标签过滤
  tree_node_id  — 树节点 ID，过滤该节点下的所有 findings
  limit         — 返回上限（默认20）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "query": {"type": "string", "default": "", "description": "搜索关键词"},
                    "confidence": {"type": "string", "description": "置信度过滤"},
                    "tag": {"type": "string", "description": "标签过滤"},
                    "tree_node_id": {"type": "string", "description": "树节点 ID"},
                    "limit": {"type": "integer", "default": 20, "minimum": 1, "maximum": 100},
                },
                "required": ["project"],
            },
        ),
        Tool(
            name="findings_get",
            description="""获取单条发现的完整信息，包含 dependent_count（有多少条目依赖它）。

参数:
  project — 项目名
  id      — finding ID""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string"},
                    "id": {"type": "string"},
                },
                "required": ["project", "id"],
            },
        ),
        Tool(
            name="findings_update",
            description="""更新发现条目的置信度、证据、标签或树节点关联。

⚠️ tree_path 一般情况不得使用——新 findings 应通过 findings_store 的 tree_path 参数直接挂载。
仅当用户明确要求整理已有 findings 的树结构时才传入此参数。

将条目标记为 disproved 时自动级联：
  - 所有 based_on 指向此条目的推断 → 降级为 speculative
  - 追加 'invalidated' 标签
  - 递归处理二级依赖

更新 confirmed-observed/confirmed-inferred/disproved 条目后自动检测潜在冲突。

参数:
  project    — 项目名
  id         — finding ID
  fact       — 新的事实陈述（可选）
  confidence — 新的置信度（可选）
  evidence   — 新的证据（可选）
  tags       — 新的标签列表（可选，完整替换）
  tree_path  — 树路径，如 'challenge.exe>sub_4012a0'（⚠️ 一般不用，仅用户要求时使用）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string"},
                    "id": {"type": "string"},
                    "fact": {"type": "string"},
                    "confidence": {"type": "string", "enum": sorted(VALID_CONFIDENCE)},
                    "evidence": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "tree_path": {"type": "string", "description": "树路径，如 'challenge.exe>sub_4012a0'（⚠️ 一般不用）"},
                },
                "required": ["project", "id"],
            },
        ),
        Tool(
            name="tree_store",
            description="""创建或更新树节点。自动创建路径上所有缺失的中间节点。

树节点类型（node_type）:
  project   — 项目根节点
  file      — 文件
  function  — 函数
  class     — 类
  section   — 通用层级/段落

路径使用 '>' 分隔层级，如 'challenge.exe>sub_4012a0>loop_body'。

参数:
  project      — 项目名
  path         — 树路径，如 'challenge.exe>sub_4012a0'（> 分隔层级）
  node_type    — 叶子节点类型（默认 'function'）
  parent_path  — 父路径（可选，指定后 path 拼接到父路径下）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "path": {"type": "string", "description": "树路径，如 'challenge.exe>sub_4012a0'"},
                    "node_type": {
                        "type": "string",
                        "enum": sorted(VALID_NODE_TYPES),
                        "default": "function",
                        "description": "节点类型"
                    },
                    "parent_path": {"type": "string", "description": "父路径（可选）"},
                },
                "required": ["project", "path"],
            },
        ),
        Tool(
            name="tree_get",
            description="""获取树节点详细信息，包含子节点列表、挂载的 findings、父节点摘要。

参数:
  project  — 项目名
  node_id  — 树节点 ID（完整路径，如 'HITCON2024_rev1>challenge.exe>sub_4012a0'）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "node_id": {"type": "string", "description": "树节点 ID"},
                },
                "required": ["project", "node_id"],
            },
        ),
        Tool(
            name="tree_search",
            description="""搜索树节点。

搜索规则:
  - query 对 name 字段做文本匹配
  - node_type 过滤节点类型
  - parent_id 过滤直接子节点
  - 多条件 AND 逻辑

参数:
  project    — 项目名
  query      — 搜索关键词（可选）
  node_type  — 节点类型过滤（可选）
  parent_id  — 父节点 ID 过滤（可选）
  limit      — 返回上限（默认50）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "query": {"type": "string", "default": "", "description": "搜索关键词"},
                    "node_type": {"type": "string", "enum": sorted(VALID_NODE_TYPES), "description": "节点类型过滤"},
                    "parent_id": {"type": "string", "description": "父节点 ID"},
                    "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
                },
                "required": ["project"],
            },
        ),
        Tool(
            name="tree_delete",
            description="""删除树节点。级联删除所有子节点，挂载的 findings 的 tree_node_id 置 NULL（保留数据不丢失）。

参数:
  project  — 项目名
  node_id  — 树节点 ID""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "node_id": {"type": "string", "description": "树节点 ID"},
                },
                "required": ["project", "node_id"],
            },
        ),
        # ── 监督层（v1.1 §3.6 E 组）──
        Tool(
            name="audit_violation",
            description="""记录一条违规到审计日志（监督层，v1.1 §3.6）。

规则编号（rule_id）:
  R1 — 委派前未调 findings_search（无证据基线）
  R2 — 同一假设连续失败≥2 仍继续
  R3 — 汇报结论未附置信度
  R4 — 委派 context 未附验证要求
  R5 — 冻结触发（freeze_trigger 自动记录，一般无需手动调用）

违规计数 ≥3 时 freeze_status 将返回 frozen=true。记录带自增 id，
可用 audit_list / audit_stats 查询。

参数:
  project — 项目名
  actor   — 违规方标识（'parent' 或 'agent:<id>'）
  rule_id — 规则编号 R1-R5
  detail  — 违规详情描述""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "actor": {"type": "string", "description": "违规方标识（parent 或 agent:<id>）"},
                    "rule_id": {"type": "string", "enum": ["R1", "R2", "R3", "R4", "R5"], "description": "规则编号"},
                    "detail": {"type": "string", "description": "违规详情描述"},
                },
                "required": ["project", "actor", "rule_id", "detail"],
            },
        ),
        Tool(
            name="audit_list",
            description="""列出审计日志，按创建时间倒序（监督层，v1.1 §3.6）。

参数:
  project — 项目名
  rule_id — 按规则编号过滤（可选，如 'R1'）
  limit   — 返回上限（默认50）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "rule_id": {"type": "string", "description": "规则编号过滤（可选）"},
                    "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
                },
                "required": ["project"],
            },
        ),
        Tool(
            name="audit_stats",
            description="""审计统计：按规则分组的违规计数 + 最近 5 条记录摘要（监督层，v1.1 §3.6）。

响应: {"by_rule": {"R1": N, ...}, "total": N, "recent": [{id, rule_id, detail, created_at}]}

参数:
  project — 项目名""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                },
                "required": ["project"],
            },
        ),
        Tool(
            name="freeze_status",
            description="""冻结状态检查（监督层，v1.1 §3.6）。父 Agent 委派新方向前可调用。

任一条件满足即 frozen=true：
  - 显式冻结：situations.frozen 非空（freeze_trigger 写入）
  - 违规计数 ≥3（audit_log 记录数）
  - 未解决待办 ≥3（directives.status != 'resolved'）
  - 存在 repeat_count ≥2 的指令（重复指令需用户决策）

frozen=false 时 reason 为空列表。响应:
  {"frozen": bool, "reason": ["触发条件..."], "counts": {"violations": N, "unresolved_directives": N, "repeated_directives": N}}

参数:
  project — 项目名""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                },
                "required": ["project"],
            },
        ),
        Tool(
            name="freeze_trigger",
            description="""显式冻结项目（监督层，v1.1 §3.6）：
写入 situations.frozen（冻结原因）+ frozen_at，并自动在 audit_log 记一条 R5 违规（actor=parent）。

响应: {"frozen": true, "reason": [...], "counts": {...}, "frozen_at": "..."}

参数:
  project — 项目名
  reason  — 冻结原因（如 "连续 3 次同假设失败，需用户决策"）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "reason": {"type": "string", "description": "冻结原因"},
                },
                "required": ["project", "reason"],
            },
        ),
        Tool(
            name="freeze_release",
            description="""解除显式冻结（监督层，v1.1 §3.6）：清空 situations.frozen/frozen_at。

自动触发的冻结（违规计数/未解决待办/重复指令）解除条件由对应计数变化决定，
本工具只清除显式冻结标记。响应: {"frozen": false, "reason": [], "counts": {...}, "released_at": "..."}

参数:
  project — 项目名""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                },
                "required": ["project"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "findings_store":
            result = store_finding(
                project=arguments["project"],
                fact=arguments["fact"],
                confidence=arguments["confidence"],
                source=arguments["source"],
                evidence=arguments.get("evidence", ""),
                based_on=arguments.get("based_on"),
                tags=arguments.get("tags"),
                tree_path=arguments.get("tree_path"),
                type_=arguments.get("type", "claim"),
                task_budget=arguments.get("task_budget"),
                task_dependencies=arguments.get("task_dependencies"),
                task_agent=arguments.get("task_agent"),
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "findings_search":
            result = search_findings(
                project=arguments["project"],
                query=arguments.get("query", ""),
                confidence=arguments.get("confidence"),
                tag=arguments.get("tag"),
                tree_node_id=arguments.get("tree_node_id"),
                limit=arguments.get("limit", 20),
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "findings_get":
            result = get_finding(
                project=arguments["project"],
                kid=arguments["id"],
            )
            if result is None:
                return [TextContent(type="text", text=json.dumps({"error": "not found", "id": arguments["id"]}))]
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "findings_update":
            result = update_finding(
                project=arguments["project"],
                kid=arguments["id"],
                fact=arguments.get("fact"),
                confidence=arguments.get("confidence"),
                evidence=arguments.get("evidence"),
                tags=arguments.get("tags"),
                tree_path=arguments.get("tree_path"),
                source=arguments.get("source"),
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "tree_store":
            result = tree_store(
                project=arguments["project"],
                path=arguments["path"],
                node_type=arguments.get("node_type", "function"),
                parent_path=arguments.get("parent_path"),
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "tree_get":
            result = tree_get(
                project=arguments["project"],
                node_id=arguments["node_id"],
            )
            if result is None:
                return [TextContent(type="text", text=json.dumps(
                    {"error": "not found", "node_id": arguments["node_id"]}))]
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "tree_search":
            result = tree_search(
                project=arguments["project"],
                query=arguments.get("query", ""),
                node_type=arguments.get("node_type"),
                parent_id=arguments.get("parent_id"),
                limit=arguments.get("limit", 50),
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "tree_delete":
            result = tree_delete(
                project=arguments["project"],
                node_id=arguments["node_id"],
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "audit_violation":
            result = audit_violation(
                project=arguments["project"],
                actor=arguments["actor"],
                rule_id=arguments["rule_id"],
                detail=arguments["detail"],
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "audit_list":
            result = audit_list(
                project=arguments["project"],
                rule_id=arguments.get("rule_id"),
                limit=arguments.get("limit", 50),
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "audit_stats":
            result = audit_stats(project=arguments["project"])
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "freeze_status":
            result = freeze_status(project=arguments["project"])
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "freeze_trigger":
            result = freeze_trigger(
                project=arguments["project"],
                reason=arguments["reason"],
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        elif name == "freeze_release":
            result = freeze_release(project=arguments["project"])
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ValueError as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, ensure_ascii=False))]
    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": f"Internal error: {str(e)}"}, ensure_ascii=False))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
