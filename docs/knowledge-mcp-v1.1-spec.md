# knowledge-mcp 完整规格 v1.1（存储结构 + MCP 工具 + 调用格式 + 使用例）

> 依据：`knowledge-mcp-v2-gap-plan.md` v1.1（2026-08-04）
> 本文档 = 实现蓝图：所有表结构、36 个 MCP 工具、调用格式、使用例。
> 现状基线：server.py 969 行（8 工具），本规格在**不破坏现有签名**前提下扩展。

---

## 1. 存储层总览

### 1.1 数据模型全景

```
~/.hermes/findings/  (FINDINGS_DB_DIR)
├── <project>.db                        # 每项目独立 SQLite (WAL)
│   ├── knowledge      # 发现表（证据层核心）
│   ├── tree_nodes     # 树节点表
│   ├── situations     # 局面对象（状态层核心）      ← 新增
│   ├── directives     # 用户指令待办（指挥层核心）   ← 新增
│   ├── conflicts      # 冲突对象（状态机）          ← 新增
│   ├── audit_log      # 违规审计（监督层）          ← 新增
│   ├── task_meta      # task 专属元数据             ← 新增
│   └── knowledge_fts  # FTS5 全文索引               ← 新增
└── artifacts/
    └── <project>/<sha1>.txt             # 原始工具输出快照（artifact://）
```

### 1.2 表结构明细

#### ① knowledge（现有 + 3 个新列）

```sql
CREATE TABLE knowledge (
    id          TEXT PRIMARY KEY,        -- uuid4
    project     TEXT NOT NULL,
    fact        TEXT NOT NULL,           -- 事实陈述 ≤4000 字符
    confidence  TEXT NOT NULL,           -- confirmed-observed|confirmed-inferred|likely|speculative|disproved
    source      TEXT NOT NULL,           -- 约定格式 agent:<id>|role:<role>|tool:<tool>
    evidence    TEXT NOT NULL DEFAULT '',-- 证据摘要 ≤500 推荐
    based_on    TEXT,                    -- DAG 推理链：父 finding ID
    tags        TEXT NOT NULL DEFAULT '[]',
    tree_node_id TEXT,                   -- 树挂载（v3 已有）
    type        TEXT NOT NULL DEFAULT 'claim',   -- ← 新增: observation|claim|hypothesis|task
    evidence_uri TEXT,                   -- ← 新增: artifact://... 原始输出引用
    invalidation_reason TEXT,            -- ← 新增: 级联降级原因
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    FOREIGN KEY (based_on) REFERENCES knowledge(id) ON DELETE SET NULL
);
```

#### ② tree_nodes（现有 + 2 个新列）

```sql
CREATE TABLE tree_nodes (
    id          TEXT PRIMARY KEY,        -- "project>seg1>seg2"
    project     TEXT NOT NULL,
    parent_id   TEXT,
    node_type   TEXT NOT NULL,           -- project|file|function|class|section
    name        TEXT NOT NULL,
    sort_order  INTEGER NOT NULL DEFAULT 0,
    status      TEXT NOT NULL DEFAULT 'normal',   -- ← 新增
    markers_json TEXT NOT NULL DEFAULT '[]',      -- ← 新增: ["conflict","active","disproved","candidate","directive","unverified"]
    created_at  TEXT NOT NULL
);
```

#### ③ situations（新增，局面对象）

```sql
CREATE TABLE situations (
    project        TEXT PRIMARY KEY,
    objective      TEXT NOT NULL DEFAULT '',
    progress_json  TEXT NOT NULL DEFAULT '[]',      -- [{id, summary, confidence}]
    active_work_json TEXT NOT NULL DEFAULT '{}',    -- {agent, task, last_heartbeat}
    conflict_queue_json TEXT NOT NULL DEFAULT '[]', -- [{conflict_id, summary}]
    candidate_directions_json TEXT NOT NULL DEFAULT '[]', -- [{direction, evidence_strength}]
    risks_json     TEXT NOT NULL DEFAULT '[]',
    user_directives_json TEXT NOT NULL DEFAULT '[]',-- directives 冗余视图（只读）
    timeline_json  TEXT NOT NULL DEFAULT '[]',      -- [{time, event, actor}]
    version        INTEGER NOT NULL DEFAULT 1,      -- HANDOFF 版本化
    frozen         TEXT,                            -- NULL=未冻结; 非空=冻结原因
    frozen_at      TEXT,
    updated_at     TEXT NOT NULL
);
```

#### ④ directives（新增，用户指令待办）

```sql
CREATE TABLE directives (
    id          TEXT PRIMARY KEY,        -- D-0001 递增
    project     TEXT NOT NULL,
    text        TEXT NOT NULL,
    anchor      TEXT,                    -- 树节点 ID 或 finding ID
    type        TEXT NOT NULL,           -- verify|redirect|stop|question|info
    status      TEXT NOT NULL DEFAULT 'received',  -- received→acknowledged→in_progress→resolved|needs_clarify
    repeat_count INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    resolved_at TEXT,
    outcome     TEXT,
    resolved_by TEXT                     -- agent-id | user
);
```

#### ⑤ conflicts（新增，冲突对象）

```sql
CREATE TABLE conflicts (
    id            TEXT PRIMARY KEY,      -- C-0001 递增
    project       TEXT NOT NULL,
    conflict_type INTEGER NOT NULL,      -- 1数值|2因果|3前提|4指令|5原始数据
    party_a_id    TEXT NOT NULL,         -- finding ID 或 observation:<id>
    party_a_summary TEXT NOT NULL,
    party_a_evidence TEXT NOT NULL,
    party_b_id    TEXT NOT NULL,
    party_b_summary TEXT NOT NULL,
    party_b_evidence TEXT NOT NULL,
    reporter      TEXT NOT NULL,         -- detector-agent-id
    status        TEXT NOT NULL DEFAULT 'pending', -- pending→under_review→adjudicated / resolved_by_rerun
    strategy      TEXT,                  -- rerun_tool|cross_tool|dynamic_trace|judge|debate|human
    resolution    TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    resolved_at   TEXT
);
```

#### ⑥ audit_log（新增，违规审计）

```sql
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project     TEXT NOT NULL,
    actor       TEXT NOT NULL,           -- parent | agent:<id>
    rule_id     TEXT NOT NULL,           -- R1委派前无search|R2同假设失败≥2|R3汇报无置信度|R4委派context无验证|R5冻结触发
    detail      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
```

#### ⑦ task_meta（新增，task 专属）

```sql
CREATE TABLE task_meta (
    finding_id      TEXT PRIMARY KEY,
    hypothesis_id   TEXT,
    agent           TEXT,
    budget_tool_calls INTEGER, budget_tokens INTEGER, budget_seconds INTEGER,
    task_status     TEXT NOT NULL DEFAULT 'todo',  -- todo|running|done|failed
    dependencies_json TEXT NOT NULL DEFAULT '[]'
);
```

#### ⑧ knowledge_fts（新增，FTS5 索引）

```sql
CREATE VIRTUAL TABLE knowledge_fts USING fts5(
    fact, evidence, tags, content='knowledge', content_rowid='rowid'
);
-- 触发器同步 INSERT/UPDATE/DELETE
```

### 1.3 写库 gate（store/update 内强制，§D2）

```
① 角色权责：source 解析 role；子 Agent 禁标 confirmed-inferred/speculative；role 缺失默认拒绝
② type 校验：claim 必须 based_on ≥1 observation；hypothesis 必须含 'test_plan:'; task 必须带 budget
③ confirmed-inferred：evidence 必须含两个不同 agent-id
④ 只做结构校验，不做语义校验（语义匹配归检测型子 Agent）
失败 → {error:"write_gate_violation", reason, suggestion}，拒绝写入
```

---

## 2. MCP 工具总览（36 个）

### 2.1 现有 8 个（签名不变，findings_store/update 增加参数与 gate）

| # | 工具 | 分类 | 说明 |
|---|------|------|------|
| 1 | findings_store | 证据 | 存储发现（+type/evidence_uri +gate） |
| 2 | findings_search | 证据 | 搜索（+use_fts） |
| 3 | findings_get | 证据 | 获取单条（+dependent_count） |
| 4 | findings_update | 证据 | 更新（+gate +级联原因） |
| 5 | tree_store | 树 | 创建/更新节点（+status/markers） |
| 6 | tree_get | 树 | 获取节点 |
| 7 | tree_search | 树 | 搜索节点 |
| 8 | tree_delete | 树 | 删除节点 |

### 2.2 新增 28 个

| # | 工具 | 分组 | 调用者 |
|---|------|------|--------|
| 9 | situation_get | A 状态层 | 父 Agent / 用户 |
| 10 | situation_update | A 状态层 | 父 Agent |
| 11 | situation_report | A 状态层 | 父 Agent（推送） |
| 12 | tree_mark | A 状态层 | 父 Agent |
| 13 | tree_unmark | A 状态层 | 父 Agent |
| 14 | directive_create | B 指挥层 | 父 Agent（含解析） |
| 15 | directive_list | B 指挥层 | 父 Agent |
| 16 | directive_update | B 指挥层 | 父 Agent |
| 17 | directive_repeat | B 指挥层 | 父 Agent |
| 18 | directive_parse | B 指挥层 | 父 Agent |
| 19 | conflict_report | C 冲突存储 | 检测型子 Agent |
| 20 | conflict_list | C 冲突存储 | 父 Agent |
| 21 | conflict_update | C 冲突存储 | 裁决型子 Agent |
| 22 | conflict_stats | C 冲突存储 | 父 Agent |
| 23 | audit_violation | E 监督层 | 父 Agent / 监督 |
| 24 | audit_list | E 监督层 | 父 Agent |
| 25 | audit_stats | E 监督层 | 父 Agent |
| 26 | freeze_status | E 监督层 | 父 Agent |
| 27 | freeze_trigger | E 监督层 | 父 Agent |
| 28 | freeze_release | E 监督层 | 父 Agent |
| 29 | tree_render | F 交互层 | 用户 / 父 Agent |
| 30 | findings_snapshot | F 交互层 | 父 Agent（委派前） |
| 31 | preflight_check | F 交互层 | 父 Agent（委派前） |
| 32 | project_list | F 交互层 | 用户 / 父 Agent |
| 33 | artifact_store | G 证据增强 | 任意（原始输出落盘） |
| 34 | artifact_get | G 证据增强 | 裁决型子 Agent |
| 35 | verification_check | G 证据增强 | 发现型子 Agent |
| 36 | verification_report | G 证据增强 | 发现型子 Agent |

### 2.3 角色→工具权限矩阵（谁可以调什么）

| 角色 | 可调用 | 禁调 |
|------|--------|------|
| 用户 | tree_render, situation_get, project_list | 一切写工具 |
| 父 Agent | 全部 | — |
| 发现型 | findings_store(≤likely), findings_search/get, tree_*, verification_check/report, artifact_store | findings_update 高置信, directive_*, conflict_update |
| 检测型 | findings_*(读), conflict_report, tree_*, situation_get | conflict_update（裁决是裁决型的活） |
| 裁决型 | findings_*(读), findings_update(disproved), conflict_update, artifact_get | conflict_report |
| 分析型 | findings_*(读), situation_update(candidate_directions) | 写 findings（gate 后父 Agent 写） |

> 注：权限矩阵是**方案约定**（Hermes 平台层可做参数校验，MCP 侧以 source role 解析 + gate 兜底）。

---

## 3. 工具调用格式与使用例

> 以下所有调用均为 MCP 标准 JSON-RPC 的 `arguments` 部分；响应为工具返回的 TextContent（JSON 字符串）。示例基于虚拟项目 `D3CTF2026_d3llvm`（与真实知识库命名规范一致）。

### 3.1 证据类（现有）

#### findings_store — 存储发现

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "fact": "sub_4012a0 在 0x401310 处读取 qword_40A0，与 0x9E3779B9 异或，符合 TEA 解密特征",
  "confidence": "confirmed-observed",
  "source": "agent:a7f3|role:discovery|tool:ida",
  "evidence": "mov rax,[rip+0x40A0]; xor rax,0x9E3779B9; 循环 32 轮",
  "type": "observation",
  "based_on": null,
  "tags": ["crypto", "tea"],
  "tree_path": "challenge.exe>sub_4012a0",
  "evidence_uri": "artifact://tool_output/D3CTF2026_d3llvm/3fa2b1c9.txt"
}
```

```json
// 响应
{
  "id": "9f1c2e3a-...",
  "project": "D3CTF2026_d3llvm",
  "fact": "sub_4012a0 ...",
  "confidence": "confirmed-observed",
  "type": "observation",
  "tree_node_id": "D3CTF2026_d3llvm>challenge.exe>sub_4012a0",
  "_conflicts": [],          // 关键词共现提示（低置信辅助）
  "created_at": "2026-08-04T12:00:00Z"
}
```

**gate 拒绝示例**（子 Agent 越权标 confirmed-inferred）：

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "fact": "sub_4012a0 是 flag 检查器",
  "confidence": "confirmed-inferred",
  "source": "agent:b2e8|role:discovery",
  "type": "claim",
  "based_on": null
}
// 响应
{"error": "write_gate_violation", "reason": "role=discovery 无权标记 confirmed-inferred",
 "suggestion": "改为 likely 提交，由父 Agent 交叉验证后升级"}
```

#### findings_search — 搜索

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "query": "TEA",
  "confidence": "verified",
  "tag": "crypto",
  "tree_node_id": "D3CTF2026_d3llvm>challenge.exe>sub_4012a0",
  "limit": 20
}
```

```json
// 响应
[
  {"id": "9f1c2e3a-...", "fact": "sub_4012a0 ... TEA 解密特征", "confidence": "confirmed-observed", "type": "observation", "created_at": "..."},
  {"id": "b7d4f1aa-...", "fact": "key=0x9E3779B9, 16轮", "confidence": "likely", "type": "claim", "created_at": "..."}
]
```

#### findings_get — 获取单条

```json
// 请求
{"project": "D3CTF2026_d3llvm", "id": "9f1c2e3a-..."}
// 响应：完整记录 + {"dependent_count": 2}
```

#### findings_update — 更新（标 disproved 触发级联）

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "id": "b7d4f1aa-...",
  "confidence": "disproved",
  "evidence": "rerun 后 key 实际为 0x61C88647（GDB 断点 0x401310 实测）"
}
// 响应：更新后记录 + dependent_count
// 级联副作用：所有 based_on 该条目的推断 → speculative + invalidated 标签 + invalidation_reason="上游 b7d4f1aa 被证伪: ..."
// 联动：tree_node 自动加 disproved 标记
```

### 3.2 树类（现有 + 新增）

#### tree_store — 创建/更新节点

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "path": "challenge.exe>sub_4012a0>loop_body",
  "node_type": "function",
  "status": "active",
  "markers": ["unverified"]
}
// 响应：完整节点记录（含自动创建的中间节点）
```

#### tree_mark / tree_unmark — 状态标记

```json
// 请求（标记冲突）
{"project": "D3CTF2026_d3llvm", "node_id": "D3CTF2026_d3llvm>challenge.exe>sub_4012a0", "marker": "conflict"}
// 响应：{"node_id": "...", "markers": ["conflict"]}

// 请求（移除）
{"project": "D3CTF2026_d3llvm", "node_id": "...", "marker": "conflict"}
// 响应：{"node_id": "...", "markers": []}
```

### 3.3 局面对象（A 组）

#### situation_get — 获取局面

```json
// 请求
{"project": "D3CTF2026_d3llvm"}
// 响应
{
  "project": "D3CTF2026_d3llvm",
  "objective": "解出 d3llvm 的 flag（O-LLVM 混淆还原 → 求解输入）",
  "progress": [
    {"id": "9f1c2e3a-...", "summary": "TEA 解密特征确认", "confidence": "confirmed-observed"},
    {"id": "b7d4f1aa-...", "summary": "key=0x9E3779B9", "confidence": "disproved"}
  ],
  "active_work": {"agent": "discovery-3", "task": "FSM 状态图追踪", "last_heartbeat": "2026-08-04T12:05:00Z"},
  "conflict_queue": [{"conflict_id": "C-0001", "summary": "key 数值 0x9E3779B9 vs 0x61C88647"}],
  "candidate_directions": [
    {"direction": "用 0x61C88647 重新解密", "evidence_strength": "high"},
    {"direction": "验证 sub_402000 是否为 dispatcher", "evidence_strength": "mid"}
  ],
  "risks": ["模拟器未过二进制交叉验证"],
  "user_directives": [{"id": "D-0001", "text": "node 1.1 的 key 再验证一下", "status": "in_progress"}],
  "timeline": [
    {"time": "2026-08-04T11:30:00Z", "event": "用户指示优先验证 key", "actor": "user"},
    {"time": "2026-08-04T12:00:00Z", "event": "检测型报警 C-0001", "actor": "detector"}
  ],
  "version": 7,
  "frozen": null,
  "updated_at": "2026-08-04T12:05:00Z"
}
```

#### situation_update — 更新局面

```json
// 请求（追加候选方向 + 时间线事件）
{
  "project": "D3CTF2026_d3llvm",
  "candidate_directions": [{"direction": "用 0x61C88647 重新解密", "evidence_strength": "high"}],
  "timeline_event": {"event": "裁决型定案 C-0001：key=0x61C88647", "actor": "judge"}
}
// 响应：完整局面对象（version=8）
// 校验：candidate_directions 缺 evidence_strength → 拒绝
```

#### situation_report — 推送渲染

```json
// 请求
{"project": "D3CTF2026_d3llvm"}
// 响应（文本，供直接推送用户）
"📊 局面：解出 d3llvm 的 flag
✅ 已完成：TEA 解密特征（confirmed-observed）｜key 已证伪（disproved）
🔄 活跃：discovery-3 在追踪 FSM 状态图
⚠️ 冲突 1 项：C-0001 key 数值
🎯 候选方向（high）：用 0x61C88647 重新解密
📌 待办指令 1 条：D-0001 key 再验证
（无开放式提问）"
```

### 3.4 指令待办（B 组）

#### directive_create — 创建（可带解析）

```json
// 请求（type 省略 → 服务端解析）
{
  "project": "D3CTF2026_d3llvm",
  "text": "node 1.1 的 key 再验证一下",
  "anchor": "challenge.exe>sub_4012a0"
}
// 响应
{
  "id": "D-0001",
  "text": "node 1.1 的 key 再验证一下",
  "anchor": "challenge.exe>sub_4012a0",
  "type": "verify",            // 解析器命中"验证一下"
  "status": "received",
  "repeat_count": 0,
  "created_at": "2026-08-04T12:06:00Z"
}
// 联动：anchor 树节点自动加 directive 标记
```

#### directive_parse — 纯解析（不落库）

```json
// 请求
{"project": "D3CTF2026_d3llvm", "text": "不要继续追 sub_402000 了"}
// 响应
{"type": "stop", "anchor": null, "matched_keywords": ["不要"]}
```

#### directive_list — 待办清单

```json
// 请求
{"project": "D3CTF2026_d3llvm", "status": "received"}
// 响应
[{"id": "D-0001", "text": "...", "type": "verify", "status": "received", "repeat_count": 0}]
```

#### directive_update — 状态推进

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "id": "D-0001",
  "status": "resolved",
  "outcome": "key 重验为 0x61C88647（GDB 实测）",
  "resolved_by": "judge-1"
}
// 响应：更新后 directive；联动移除 anchor 的 directive 标记
```

#### directive_repeat — 用户重复指令

```json
// 请求
{"project": "D3CTF2026_d3llvm", "id": "D-0001"}
// 响应（第 2 次重复）
{
  "id": "D-0001", "repeat_count": 2,
  "freeze_hint": true,
  "message": "重复指令 ≥2，触发强制停止：先向用户汇报局面并请求决策"
}
```

### 3.5 冲突存储（C 组）

#### conflict_report — 检测型上报（落库）

```json
// 请求（检测型子 Agent 发现数值矛盾后调用）
{
  "project": "D3CTF2026_d3llvm",
  "conflict_type": 1,
  "party_a_id": "9f1c2e3a-...",
  "party_a_summary": "TEA key=0x9E3779B9（静态反汇编）",
  "party_a_evidence": "mov rax,[rip+0x40A0]; xor rax,0x9E3779B9（ida 0x401310）",
  "party_b_id": "observation:b7d4f1aa",
  "party_b_summary": "GDB 实测 key=0x61C88647",
  "party_b_evidence": "break *0x401310; r; x/gx $rax → 0x61C88647",
  "reporter": "detector-2"
}
// 响应
{
  "id": "C-0001",
  "conflict_type": 1,
  "party_a_id": "9f1c2e3a-...",
  "party_b_id": "observation:b7d4f1aa",
  "reporter": "detector-2",
  "status": "pending",
  "created_at": "2026-08-04T12:07:00Z"
}
// 联动：关联树节点自动加 conflict 标记；situation.conflict_queue 追加
// 注意：服务端不校验"谁对"——只有字段合法性
```

#### conflict_list / conflict_stats — 查询

```json
// 请求
{"project": "D3CTF2026_d3llvm", "status": "pending"}
// 响应：[{...C-0001...}]

// 请求
{"project": "D3CTF2026_d3llvm"}
// 响应
{"pending": 1, "under_review": 0, "adjudicated": 2, "by_type": {"1": 2, "5": 1}}
```

#### conflict_update — 裁决型定案记录

```json
// 请求（裁决型子 Agent 看完原始数据后）
{
  "project": "D3CTF2026_d3llvm",
  "id": "C-0001",
  "status": "adjudicated",
  "strategy": "dynamic_trace",
  "resolution": "B 方正确（GDB 实测为 ground truth）；A 方静态反汇编遗漏了前置 XOR；A 方建议标 disproved"
}
// 响应：更新后 conflict；联动：
//   ① 关联节点移除 conflict 标记
//   ② resolution 含 "disproved" → 自动级联降级 A 方（findings_update 同款副作用）
```

### 3.6 监督层（E 组）

#### audit_violation — 记违规

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "actor": "parent",
  "rule_id": "R1",
  "detail": "委派 discovery-4 前未调 findings_search（无证据基线）"
}
// 响应：{"id": 12, "rule_id": "R1", "created_at": "..."}
```

#### freeze_status — 冻结检查

```json
// 请求
{"project": "D3CTF2026_d3llvm"}
// 响应
{
  "frozen": true,
  "reason": ["违规计数≥3(实际4)", "存在 repeat_count≥2 的指令"],
  "counts": {"violations": 4, "unresolved_directives": 2, "repeated_directives": 1}
}
```

#### freeze_trigger / freeze_release — 显式操作

```json
// 请求
{"project": "D3CTF2026_d3llvm", "reason": "连续 3 次同假设失败，需用户决策"}
// 响应：{"frozen": true, "frozen_at": "..."}

// 请求
{"project": "D3CTF2026_d3llvm"}
// 响应：{"frozen": false, "released_at": "..."}
```

### 3.7 交互/共享（F 组）

#### tree_render — 缩进树视图

```json
// 请求
{"project": "D3CTF2026_d3llvm", "node_id": null, "max_depth": 4, "with_findings": true}
// 响应（文本）
"D3CTF2026_d3llvm
├── 1 challenge.exe
│   ├── 1.1 sub_4012a0 🔒
│   │   ├── [obs] TEA 解密特征 (confirmed-observed)      ← 1.1.1
│   │   └── [claim] key=0x9E3779B9 (disproved) ❌         ← 1.1.2
│   └── 1.2 sub_402000
│       └── [claim] 疑似 dispatcher (likely) 🎯           ← 1.2.1
└── 2 data.bin
    └── [obs] 前 16 字节是 IV (confirmed-observed)        ← 2.1
（节点过多时自动截断，提示用 node_id 下钻）"
```

#### findings_snapshot — 按角色裁剪

```json
// 请求（发现型：只给摘要防锚定）
{"project": "D3CTF2026_d3llvm", "role": "discovery", "tree_node_id": "D3CTF2026_d3llvm>challenge.exe"}
// 响应
{"truncated": false,
 "snapshot": [
   {"id": "9f1c2e3a-...", "fact": "sub_4012a0 TEA 解密特征", "confidence": "confirmed-observed"},
   {"id": "b7d4f1aa-...", "fact": "key 数值矛盾已裁决", "confidence": "disproved"}
 ]}

// 请求（裁决型：完整证据 + 原始输出 URI）
{"project": "D3CTF2026_d3llvm", "role": "judge", "tree_node_id": "...>sub_4012a0"}
// 响应：完整 fact+evidence+source+evidence_uri 列表
```

#### preflight_check — 委派前总检查

```json
// 请求
{"project": "D3CTF2026_d3llvm"}
// 响应
{
  "freeze": {"frozen": false, "counts": {"violations": 1, "unresolved_directives": 1, "repeated_directives": 0}},
  "unresolved_directives": [{"id": "D-0001", "text": "key 再验证", "status": "received"}],
  "situation_summary": {"objective": "解出 flag", "active_work": "discovery-3 FSM 追踪", "conflicts_pending": 1}
}
// 用途：父 Agent 每次委派前唯一必须调用；非空待办 → 先处理再委派
```

#### project_list — 项目总览

```json
// 请求
{}
// 响应
[{"project": "D3CTF2026_d3llvm", "findings_count": 42, "tree_nodes_count": 15, "updated_at": "2026-08-04T12:07:00Z"},
 {"project": "NepCTF2026_ZhiE", "findings_count": 87, "tree_nodes_count": 31, "updated_at": "2026-08-03T18:22:00Z"}]
```

### 3.8 证据增强（G 组）

#### artifact_store — 原始输出落盘

```json
// 请求
{
  "project": "D3CTF2026_d3llvm",
  "tool": "gdb",
  "command": "break *0x401310; run; x/gx $rax",
  "output": "0x61C88647"
}
// 响应
{"uri": "artifact://tool_output/D3CTF2026_d3llvm/3fa2b1c9.txt", "bytes": 12}
```

#### artifact_get — 取回原始输出

```json
// 请求（裁决型用）
{"uri": "artifact://tool_output/D3CTF2026_d3llvm/3fa2b1c9.txt"}
// 响应：{"uri": "...", "tool": "gdb", "command": "...", "output": "0x61C88647", "stored_at": "..."}
```

#### verification_check — 回归抽样

```json
// 请求
{"project": "D3CTF2026_d3llvm", "sample_size": 3, "confidence": "confirmed-observed"}
// 响应
{"sample": [
  {"finding_id": "9f1c2e3a-...", "fact": "TEA 解密特征", "source": "tool:ida", "evidence_uri": "artifact://..."},
  {"finding_id": "5d9a...", "fact": "入口点 0x401000", "source": "tool:readelf", "evidence_uri": null}
 ]}
```

#### verification_report — 回归回写

```json
// 请求（发现型子 Agent 重跑工具后）
{
  "project": "D3CTF2026_d3llvm",
  "results": [
    {"finding_id": "9f1c2e3a-...", "verified": true, "actual_output": "xor rax,0x9E3779B9 确认"},
    {"finding_id": "5d9a...", "verified": false, "actual_output": "readelf 显示入口点 0x401030"}
  ]
}
// 响应：{"verified": 1, "mismatch": 1, "tagged_regression_verified": 1}
// 联动：verified=false 的条目 → 发现型子 Agent 应调 conflict_report(conflict_type=5) 上报（不自动生成）
```

---

## 4. 端到端工作流示例（串起全部工具）

场景：d3llvm 逆向中，检测型子 Agent 发现 key 数值矛盾，用户介入，裁决后继续。

```
① 发现型子 Agent 提交观察
   findings_store(project, fact="TEA 特征", confidence="confirmed-observed", type="observation",
                  source="agent:a7f3|role:discovery|tool:ida", tree_path="challenge.exe>sub_4012a0",
                  evidence_uri=artifact_store(...))
   → 返回 finding 9f1c2e3a + _conflicts=[]（低置信提示）

② 父 Agent 更新局面
   situation_update(project, progress=[{id:"9f1c2e3a", summary:"TEA 特征", confidence:"confirmed-observed"}],
                    timeline_event={event:"发现型提交 TEA 特征", actor:"discovery"})

③ 检测型子 Agent 比对发现矛盾 → conflict_report(project, conflict_type=1, ...)
   → C-0001 pending；树节点自动 ⚠️

④ 父 Agent 委派前 preflight_check(project)
   → {freeze:false, unresolved_directives:[], ...} → 可以委派裁决

⑤ 裁决型子 Agent：findings_snapshot(role="judge") 拿双方完整证据 + artifact_get(uri) 看原始输出
   → conflict_update(project, id="C-0001", status="adjudicated", strategy="dynamic_trace",
                      resolution="B 方正确... A 方建议标 disproved")
   → 自动级联降级 A 方

⑥ 用户发来 "node 1.1 的 key 再验证一下"
   → directive_create(project, text, anchor="challenge.exe>sub_4012a0") → D-0001 received

⑦ 父 Agent 委派前 preflight_check → unresolved_directives=[D-0001] → 先处理 D-0001
   → 委派发现型重验 → 返回后 directive_update(status="resolved", outcome="key=0x61C88647", resolved_by="...")

⑧ 用户再次催 "key 验证好了吗？"
   → directive_repeat(project, id="D-0001")（若该指令已 resolved 则新建；若未 resolved → repeat_count=2 → freeze_hint=true）
   → 父 Agent 停止并汇报局面，请求用户决策

⑨ 收尾 tree_render(project) → 用户 1 分钟掌握全局面
```

---

## 5. 实施顺序与依赖

| 阶段 | 内容 | 依赖 |
|------|------|------|
| G0 | 全部新表/新列 + FTS5 + gate 骨架 | 无 |
| G1 | audit_* + freeze_* | G0 |
| G2 | situation_* + tree_mark/unmark + tree_render | G0 |
| G3 | directive_* + directive_parse + preflight_check | G0 |
| G4 | conflict_* + verification_* | G0 |
| G5 | findings_snapshot + project_list + artifact_* + gate 全量启用 | G0 |
| G6 | README/System Prompt 更新 + 回归测试集 | 全部 |

**关键设计不变式**（实现时不可破坏）：
1. 现有 8 个工具签名零变化（只加可选参数）
2. MCP 不做检测/裁决判断（§3 原则 6）
3. 写库 gate 只做结构校验
4. 所有新表通过 `_migrate_schema` 增量迁移，旧 DB 首连自动升级
