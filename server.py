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
        "created_at  TEXT NOT NULL DEFAULT (datetime('now')),"
        "FOREIGN KEY (parent_id) REFERENCES tree_nodes(id) ON DELETE CASCADE"
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
    return conn


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


def store_finding(project: str, fact: str, confidence: str, source: str,
                  evidence: str = "", based_on: str | None = None,
                  tags: list[str] | None = None,
                  tree_path: str | None = None) -> dict:
    """存储一条发现。tree_path 可选，自动创建关联的树节点。"""
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"Invalid confidence: {confidence}. Must be one of {VALID_CONFIDENCE}")
    if len(fact) > MAX_FACT_LENGTH:
        raise ValueError(f"Fact too long ({len(fact)} chars). Max is {MAX_FACT_LENGTH}")

    conn = _get_conn(project)
    kid = str(uuid.uuid4())
    now = _now()
    tags_json = json.dumps(tags or [], ensure_ascii=False)

    # 处理 tree_path：自动创建树节点
    tree_node_id = None
    if tree_path:
        tree_node_id = _ensure_tree_path(conn, project, tree_path)

    # 如果 based_on 引用了不存在条目，置空
    if based_on:
        exists = conn.execute("SELECT 1 FROM knowledge WHERE id = ?", (based_on,)).fetchone()
        if not exists:
            based_on = None

    conn.execute("""
        INSERT INTO knowledge (id, project, fact, confidence, source, evidence,
                               based_on, tags, tree_node_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (kid, project, fact, confidence, source, evidence, based_on, tags_json,
          tree_node_id, now, now))
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
                   tree_path: str | None = None) -> dict:
    """更新发现条目。标 disproved 时触发级联降级。tree_path 可选，关联到树节点。"""
    conn = _get_conn(project)

    existing = conn.execute("SELECT * FROM knowledge WHERE id = ?", (kid,)).fetchone()
    if not existing:
        conn.close()
        raise ValueError(f"Finding not found: {kid}")

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
