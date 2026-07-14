#!/usr/bin/env python3
"""
回填脚本：为旧 findings 补上 tree_path，建立树状结构。

用法：
  1. 复制一份 DB 到可写目录（原 DB 可能只读）
  2. 按项目自定义 extract_location() 函数
  3. 运行：FINDINGS_DB_DIR=/tmp/dbs python3 backfill_tree.py <project_name>

安全：先 dry-run，确认无误后再去掉 dry_run=True 正式写入。
"""

import sys
import os
import re

# 使用 server.py 的逻辑
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from server import _get_conn, _now, TREE_SEP

DRY_RUN = False  # True: 只打印不写入，False: 正式写入


def extract_location(finding: dict) -> str | None:
    """
    从 finding 的 tags / source / fact 中提取树路径。

    返回 tree_path（如 "challenge.exe>sub_4012a0"），返回 None 表示无法提取。

    ─── 请按你的项目约定修改此函数 ───
    """
    import json

    project = finding["project"]
    source = finding["source"]
    tags = json.loads(finding["tags"])
    fact = finding["fact"]

    # ── 模式 1：逆向项目，tags 里有 binary:<文件名> ──
    # 示例：tags = ["binary:emailmessage.dll", "email", "MIME"]
    for tag in tags:
        if tag.startswith("binary:"):
            binary = tag.split(":", 1)[1]
            # 尝试从 fact/source 中提取函数名
            func_match = re.search(r'\b(sub_[0-9a-fA-F]+|[A-Z][a-zA-Z0-9]*(?:Decrypt|Encrypt|Parse|Process|Handler|Export)[a-zA-Z0-9]*)\b', fact)
            if func_match:
                return f"{binary}>{func_match.group(1)}"
            return binary  # 只有文件级，没有函数级

    # ── 模式 2：CTF Web，source 里有 tool:curl:<target_id> ──
    # 示例：source = "tool:curl:10007 SSTI probing"
    match = re.match(r'tool:\w+:(\S+)', source)
    if match:
        target = match.group(1)
        return str(target)

    # ── 模式 3：自定义 ──
    # 在此添加你的项目特定规则

    return None


def backfill_project(project: str, dry_run: bool = False):
    """回填单个项目的所有 findings。"""
    conn = _get_conn(project)
    rows = conn.execute(
        "SELECT * FROM knowledge WHERE tree_node_id IS NULL"
    ).fetchall()

    if not rows:
        print(f"[{project}] 无需回填（所有 findings 已有 tree_node_id）")
        conn.close()
        return

    print(f"[{project}] 找到 {len(rows)} 条未关联树节点的 finding")

    updated = 0
    skipped = 0
    for row in rows:
        finding = dict(row)
        tree_path = extract_location(finding)

        if tree_path is None:
            skipped += 1
            if skipped <= 5:  # 只打印前5条跳过的
                fact_preview = finding["fact"][:60]
                print(f"  ⏭ 跳过（无法提取位置）: {fact_preview}...")
            continue

        if dry_run:
            fact_preview = finding["fact"][:60]
            print(f"  → {tree_path} : {fact_preview}...")
            updated += 1
            continue

        # 正式写入：创建树节点 + 关联 finding
        now = _now()
        segments = tree_path.split(TREE_SEP)

        # 确保根节点存在
        conn.execute("""
            INSERT OR IGNORE INTO tree_nodes (id, project, parent_id, node_type, name, created_at)
            VALUES (?, ?, NULL, 'project', ?, ?)
        """, (project, project, project, now))

        # 逐层创建
        parent_id = project
        for i, seg in enumerate(segments):
            node_id = TREE_SEP.join([project] + segments[:i+1])
            node_type = "file" if i == len(segments) - 1 else "section"
            conn.execute("""
                INSERT OR IGNORE INTO tree_nodes (id, project, parent_id, node_type, name, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (node_id, project, parent_id, node_type, seg, now))
            parent_id = node_id

        # 更新 findings 的 tree_node_id
        conn.execute(
            "UPDATE knowledge SET tree_node_id = ?, updated_at = ? WHERE id = ?",
            (parent_id, now, finding["id"])
        )
        updated += 1

    conn.commit()
    conn.close()

    if dry_run:
        print(f"[{project}] dry-run 完成：将更新 {updated} 条，跳过 {skipped} 条")
    else:
        print(f"[{project}] 回填完成：更新 {updated} 条，跳过 {skipped} 条")


def main():
    if len(sys.argv) < 2:
        print("用法: python3 backfill_tree.py <project_name> [--dry-run]")
        print("示例: python3 backfill_tree.py ctf-targets --dry-run")
        print("      python3 backfill_tree.py outlook-re")
        sys.exit(1)

    project = sys.argv[1]
    dry_run = "--dry-run" in sys.argv

    # 临时覆盖 DB 目录
    if "FINDINGS_DB_DIR" not in os.environ:
        print("⚠ 未设置 FINDINGS_DB_DIR，使用默认目录")
        print("  如需指定: FINDINGS_DB_DIR=/path/to/dbs python3 backfill_tree.py ...")

    backfill_project(project, dry_run=dry_run)


if __name__ == "__main__":
    main()
