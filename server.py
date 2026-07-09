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
    检测并迁移旧版 4 级置信度 schema → 新版 5 级。
    旧版有 CHECK(confidence IN ('confirmed','disproved','likely','speculative'))，
    新版移除此 CHECK 约束（完全由应用层 VALID_CONFIDENCE 校验）。
    """
    cursor = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='knowledge'"
    )
    row = cursor.fetchone()
    if not row:
        return
    schema_sql = row[0]
    # 检测旧版 CHECK：含单个 'confirmed'（新版是 'confirmed-observed'）
    if "'confirmed','disproved','likely','speculative'" not in schema_sql:
        return  # 已是新版或无需迁移

    # 重建表：去掉 CHECK，应用层校验
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
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (based_on) REFERENCES knowledge(id) ON DELETE SET NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_project_conf ON knowledge(project, confidence)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_project_tags ON knowledge(project, tags)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_based_on ON knowledge(project, based_on)")
    conn.commit()

    # 迁移旧 schema（无操作幂等）
    _migrate_schema(conn)
    return conn


def _row_to_dict(row: sqlite3.Row) -> dict:
    """将 sqlite3.Row 转为普通 dict。"""
    return dict(row)


def _now() -> str:
    """返回 UTC 时间字符串。"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
                  tags: list[str] | None = None) -> dict:
    """存储一条发现。"""
    if confidence not in VALID_CONFIDENCE:
        raise ValueError(f"Invalid confidence: {confidence}. Must be one of {VALID_CONFIDENCE}")
    if len(fact) > MAX_FACT_LENGTH:
        raise ValueError(f"Fact too long ({len(fact)} chars). Max is {MAX_FACT_LENGTH}")
    
    conn = _get_conn(project)
    kid = str(uuid.uuid4())
    now = _now()
    tags_json = json.dumps(tags or [], ensure_ascii=False)
    
    # 如果 based_on 引用了不存在条目，置空
    if based_on:
        exists = conn.execute("SELECT 1 FROM knowledge WHERE id = ?", (based_on,)).fetchone()
        if not exists:
            based_on = None
    
    conn.execute("""
        INSERT INTO knowledge (id, project, fact, confidence, source, evidence, based_on, tags, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (kid, project, fact, confidence, source, evidence, based_on, tags_json, now, now))
    conn.commit()
    
    # 冲突检测：confirmed-observed / confirmed-inferred / disproved 时检测
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
                    tag: str | None = None, limit: int = 20) -> list[dict]:
    """搜索发现。"""
    conn = _get_conn(project)
    
    conditions = ["project = ?"]
    params = [project]
    
    if query:
        conditions.append("(fact LIKE ? OR evidence LIKE ?)")
        params.extend([f"%{query}%", f"%{query}%"])
    if confidence:
        if confidence == "verified":
            # 快捷方式：verified = confirmed-observed + confirmed-inferred + disproved
            conditions.append(
                "confidence IN ('confirmed-observed', 'confirmed-inferred', 'disproved')"
            )
        elif confidence == "confirmed":
            # 快捷方式：confirmed = confirmed-observed + confirmed-inferred（兼容旧版）
            conditions.append(
                "confidence IN ('confirmed-observed', 'confirmed-inferred')"
            )
        else:
            conditions.append("confidence = ?")
            params.append(confidence)
    if tag:
        conditions.append("tags LIKE ?")
        params.append(f"%{tag}%")
    
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
                   tags: list[str] | None = None) -> dict:
    """更新发现条目。标 disproved 时触发级联降级。"""
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
  source      — 来源描述（如 'tool:ida:sub_4012a0'、'inference:cross-validated'、'user:stated'）
  evidence    — 证据摘要（工具输出/反汇编片段/用户原话，≤500字符推荐）
  based_on    — 推理来源的 finding ID，用于追溯推理链
  tags        — 标签列表（如 ['binary:challenge.exe','crypto','rc4']）""",
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
  - 多条件 AND 逻辑
  - 按创建时间倒序

参数:
  project    — 项目名
  query      — 搜索关键词（可选，留空返回全部）
  confidence — 置信度过滤
  tag        — 标签过滤
  limit      — 返回上限（默认20）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string", "description": "项目名"},
                    "query": {"type": "string", "default": "", "description": "搜索关键词"},
                    "confidence": {"type": "string", "description": "置信度过滤"},
                    "tag": {"type": "string", "description": "标签过滤"},
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
            description="""更新发现条目的置信度、证据或标签。

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
  tags       — 新的标签列表（可选，完整替换）""",
            inputSchema={
                "type": "object",
                "properties": {
                    "project": {"type": "string"},
                    "id": {"type": "string"},
                    "fact": {"type": "string"},
                    "confidence": {"type": "string", "enum": sorted(VALID_CONFIDENCE)},
                    "evidence": {"type": "string"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["project", "id"],
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
            )
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
        
        elif name == "findings_search":
            result = search_findings(
                project=arguments["project"],
                query=arguments.get("query", ""),
                confidence=arguments.get("confidence"),
                tag=arguments.get("tag"),
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
