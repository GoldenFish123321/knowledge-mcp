# knowledge-mcp 与 CTF 编排 v2 方案差距分析与实现方案

> 分析对象：`https://github.com/GoldenFish123321/knowledge-mcp`（Findings MCP Server，commit 2026-07-14）
> 对标文档：`/root/tools/agent-research/ctf-reverse-orchestrator-v2.md`（v1.0，2026-08-04）
> 本文档：差距矩阵 + 分组功能设计 + 实施路线。状态：**待确认**（未开始编码）

---

## 1. 现状盘点：knowledge-mcp 已实现

| 能力 | 实现方式 | 备注 |
|------|---------|------|
| 五级置信度 | `knowledge.confidence` 字段 | confirmed-observed / confirmed-inferred / likely / speculative / disproved |
| DAG 推理链 | `based_on` 字段（自引用 FK） | findings_get 返回 dependent_count |
| 级联降级 | `_cascade_invalidate()` | 标 disproved → 依赖者降 speculative + `invalidated` 标签，递归二级 |
| 冲突检测 | `_check_conflicts()` | **仅关键词共现**（fact 中 ≥3 字符词 LIKE 匹配），限 confirmed/disproved |
| 树状结构 | `tree_nodes` 表 + `tree_node_id` | tree_store/get/search/delete 四个工具 |
| 存储/搜索/更新 | findings_store / search / get / update | 搜索：fact/evidence LIKE，confidence 快捷方式 verified/confirmed |
| 项目隔离 | 每项目独立 SQLite 文件 | `~/.hermes/findings/<project>.db` |
| 部署 | Docker + GitHub Actions + stdio MCP | mcp>=1.20.0，python:3.12-slim |

**一句话**：knowledge-mcp 是完整的"证据层"（v2 §6.1 的下半部分），但 v2 方案的其余两层（状态层局面对象、指挥层指令待办）与所有硬机制（监督、冲突管线、写库 gate）均未实现。

---

## 2. 差距矩阵：v2 方案需求 vs knowledge-mcp 现状

### 2.1 总体缺口视图

```
v2 方案功能需求
├── 证据层 findings 树 ────────── ✅ 已实现（knowledge-mcp 全部）
│     ├── 五级置信度              ✅
│     ├── DAG 推理链 + 级联降级    ✅
│     ├── 树状结构                ✅
│     └── 冲突检测                ⚠️ 仅关键词共现，无类型/状态机
├── 状态层 局面对象 ───────────── ❌ 完全缺失（situation 表 + 工具）
│     ├── objective/progress/active_work/conflict_queue/candidate_directions/risks/user_directives/timeline
│     └── 树节点状态标记（⚠️🔄❌🎯📌🔒） ❌ 缺失
├── 指挥层 用户指令待办 ───────── ❌ 完全缺失（directive 表 + 确定性解析器 + 三条强制义务）
├── 执行层 四角色支撑 ─────────── ⚠️ 部分缺失
│     ├── 信息对象四类 type（observation/claim/hypothesis/task） ❌ 缺失
│     ├── 写库 gate（claim 须有 observation 支撑等）            ❌ 缺失
│     ├── 信息共享协议（按角色快照裁剪）                         ❌ 缺失
│     └── 冲突对象 + 状态机（pending→under_review→adjudicated） ❌ 缺失
├── 交互层 树状 UI ───────────── ❌ 缺失（tree_render 缩进树 + 节点编号）
├── 三层监督 ─────────────────── ❌ 缺失（audit 违规记录 + 计数 + 冻结）
└── 证据增强 ─────────────────── ❌ 缺失（evidence_uri/artifact、FTS5、回归验证、项目列表）
```

### 2.2 逐项差距明细（编号对应下文方案分组）

| # | v2 需求（章节） | knowledge-mcp 现状 | 差距等级 | 方案 |
|---|----------------|-------------------|:---:|------|
| 1 | 局面对象 schema（§6.2） | 无 | 🔴 核心 | A1 |
| 2 | 树节点状态标记（§6.3） | tree_nodes 无 status/markers 字段 | 🔴 核心 | A2 |
| 3 | 节点四级下钻（§7.2） | fact/evidence/source 已有，缺"原始输出引用"字段 | 🟡 增强 | A3 |
| 4 | 用户指令待办 schema（§8.2/B） | 无 | 🔴 核心 | B1 |
| 5 | 确定性解析器（§8.2 写入时机） | 无 | 🔴 核心 | B2 |
| 6 | 三条强制处理义务（§8.2 规则1-3） | 无 | 🔴 核心 | B3 |
| 7 | 冲突上报 schema（附录 C） | `_conflicts` 只是列表，无对象/状态机 | 🔴 核心 | C1 |
| 8 | 冲突类型清单 5 类（§5.4） | 无类型枚举字段（类型清单本身是**检测型子 Agent 的 prompt 内容**，非服务端算法） | 🟡 增强 | C1 枚举 |
| 9 | 冲突解决六策略（§5.5b） | 无 strategy 字段（策略选择是**裁决型/父 Agent 的判断**，工具只记录） | 🟡 增强 | C1 |
| 10 | 级联降级 + 原因记录 | 有级联，无 invalidation_reason | 🟡 增强 | C3 |
| 11 | 信息对象四类 type（§6.4） | knowledge 无 type 字段 | 🔴 核心 | D1 |
| 12 | 分析型写库 gate（§5.6） | store 无校验 | 🔴 核心 | D2 |
| 13 | 角色权责强制（子 Agent 禁标 confirmed-inferred/speculative） | README 有规则文本，代码不校验 | 🔴 核心 | D2 |
| 14 | 信息共享协议：按角色快照裁剪 ≤3KB（§5.3/11.2） | 无 | 🔴 核心 | F2 |
| 15 | 树状 UI：/tree 缩进树 + 节点编号（§7.3） | 无渲染工具 | 🔴 核心 | F1 |
| 16 | 项目列表/统计 | 无 | 🟢 便利 | F3 |
| 17 | 三层监督：规则/计数/冻结（§9.1-9.3） | 无 audit 表、无冻结状态 | 🔴 核心 | E1/E2 |
| 18 | evidence_uri / artifact 原始输出存储（§6.4 observation） | 无 | 🟡 增强 | G2 |
| 19 | FTS5 全文搜索（中文支持） | LIKE 匹配，中文分词差 | 🟢 便利 | G1 |
| 20 | 回归验证（轮子问题，§11.6 差异化空白） | 无（重跑对照是**发现型子 Agent 的职责**，MCP 只缺抽样/回写原语） | 🟡 增强 | G3 |
| 21 | 上报推送格式（§7.4 现状表+候选方向） | 无 | 🟡 增强 | A1 的 situation_report |
| 22 | timeline 关键决策点（局面对象内） | 无 | 🟡 增强 | A1 |
| 23 | 重复指令检测（§8.2 规则3） | 无 | 🟡 增强 | B1 repeat_count |
| 24 | HANDOFF / 局面版本化（§11.4） | 无 | 🟢 便利 | A1 version 字段 |

---

## 3. 设计原则（贯穿全部功能）

1. **确定性来自结构**：所有强制义务做成 schema 校验 + 状态机，不依赖 LLM 自觉（v2 §3.2）。
2. **MCP 工具是原子操作**：每个工具做一件事、schema 强制字段；父 Agent 组合它们实现编排。
3. **向后兼容**：全部新表/新列通过 `_migrate_schema` 增量迁移，旧 DB 首连自动升级；旧工具签名不变。
4. **体积上限硬编码**：快照 ≤3KB（v2 §11.2），防止上下文污染复发（rubik 92KB 教训）。
5. **角色来源可信**：`source` 字段约定格式 `agent:<id>|role:<role>`，服务端解析 role 做权责校验；无法解析时默认拒绝高置信级写入。
6. **职责边界：MCP = 存储层，Agent = 判断层**。冲突识别（检测型）、冲突裁决（裁决型）、回归对照（发现型）都是子 Agent 的智力工作（v2 §5.1 角色定义）；MCP 只提供**落库 + 状态机 + 查询原语**与**低置信自动提示**（关键词共现、结构校验），绝不实现"检测/裁决算法"。检测型子 Agent 判断出冲突 → 调 conflict_report **落库**；裁决型子 Agent 定案 → 调 conflict_update **记录**。工具不抢 Agent 的判断职责。

---

## 4. 分组功能设计

### A. 状态层：局面对象 + 树状态标记（v2 P2）

#### A1. 局面对象（Situation Object）

**新表 `situations`（每项目一行）**：

```sql
CREATE TABLE IF NOT EXISTS situations (
    project        TEXT PRIMARY KEY,
    objective      TEXT NOT NULL DEFAULT '',
    progress_json  TEXT NOT NULL DEFAULT '[]',   -- [{id, summary, confidence}]
    active_work_json TEXT NOT NULL DEFAULT '{}', -- {agent, task, last_heartbeat}
    conflict_queue_json TEXT NOT NULL DEFAULT '[]', -- [{conflict_id, summary}]
    candidate_directions_json TEXT NOT NULL DEFAULT '[]', -- [{direction, evidence_strength}]
    risks_json     TEXT NOT NULL DEFAULT '[]',   -- [speculative 中支撑后续方向的假设]
    user_directives_json TEXT NOT NULL DEFAULT '[]', -- [{id, text, status}]（冗余视图，主存储见 B1）
    timeline_json  TEXT NOT NULL DEFAULT '[]',   -- [{time, event, actor}]
    version        INTEGER NOT NULL DEFAULT 1,   -- HANDOFF 版本化（每次 update +1）
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**MCP 工具**：

- `situation_get(project)` → 完整局面对象（含 version）。
- `situation_update(project, objective?, progress?, active_work?, candidate_directions?, risks?, timeline_event?)` → 更新任一字段；`timeline_event` 以 `{time, event, actor}` 追加进 timeline；version+1；返回完整对象。
- `situation_report(project)` → **推送专用渲染**（v2 §7.4）：输出文本 = 现状表（progress 摘要）+ 2-3 候选方向 + 各方向证据强度 + 冲突队列 + 待办指令数。禁止开放式技术提问。

**校验规则**：`candidate_directions` 每项必须含 `evidence_strength ∈ {high, mid, low}`（写库时校验，缺失拒绝）。`progress` 每项必须含 `id`（引用已有 finding ID，引用不存在时拒绝或降级为纯文本摘要）。

#### A2. 树节点状态标记

**tree_nodes 表加列**：

```sql
ALTER TABLE tree_nodes ADD COLUMN status TEXT NOT NULL DEFAULT 'normal';
ALTER TABLE tree_nodes ADD COLUMN markers_json TEXT NOT NULL DEFAULT '[]';
-- markers 元素 ∈ {conflict, active, disproved, candidate, directive, unverified}
```

**MCP 工具**：

- `tree_store(..., status?, markers?)` → 扩展参数。
- `tree_mark(project, node_id, marker)` / `tree_unmark(project, node_id, marker)` → 增删标记。
- `tree_get` 返回值增加 `status`、`markers`；渲染时对应图标（⚠️/🔄/❌/🎯/📌/🔒）。

**联动规则**（在服务端实现，非 LLM）：
- findings 标 disproved 且其 tree_node_id 非空 → 自动给该节点加 `disproved` 标记。
- conflict 上报关联节点 → 自动加 `conflict` 标记；conflict 状态变为 adjudicated → 自动移除。
- directive 创建带 anchor（树节点）→ 自动加 `directive` 标记；resolved → 自动移除。

#### A3. 节点四级下钻：原始输出引用字段

**knowledge 表加列 `evidence_uri`**：

```sql
ALTER TABLE knowledge ADD COLUMN evidence_uri TEXT;
-- 格式：artifact://tool_output/<project>/<sha1>.txt（见 G2）
```

tree_get / findings_get 返回该字段，实现 v2 §7.2 的"详情3（原始输出引用）"。

---

### B. 指挥层：用户指令待办 + 确定性解析器（v2 P3，核心机制）

#### B1. UserDirective 存储

**新表 `directives`**：

```sql
CREATE TABLE IF NOT EXISTS directives (
    id          TEXT PRIMARY KEY,          -- D-0001 递增
    project     TEXT NOT NULL,
    text        TEXT NOT NULL,
    anchor      TEXT,                      -- 树节点 ID 或 finding ID
    type        TEXT NOT NULL,             -- verify|redirect|stop|question|info
    status      TEXT NOT NULL DEFAULT 'received',
    -- received → acknowledged → in_progress → resolved | needs_clarify
    repeat_count INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL,
    resolved_at TEXT,
    outcome     TEXT,
    resolved_by TEXT                       -- agent-id | user
);
```

**MCP 工具**：

- `directive_create(project, text, anchor?, type?)` → type 可省略，省略时服务端调用确定性解析器（B2）推断；返回完整 directive（含自动生成的 D-xxxx id）。
- `directive_list(project, status?)` → 待办清单，默认按 created_at 升序（最旧优先）。
- `directive_update(project, id, status?, outcome?, resolved_by?)` → 状态推进；resolved 时自动记 resolved_at。
- `directive_repeat(project, id)` → 用户重复同一指令时调用，repeat_count+1；**返回重复次数，≥2 时附带 FREEZE 提示**（对接 E2 冻结）。

**生命周期闭环示例**（v2 §8.2）：

```
用户: "node 3.2 这个 key 你再验证一下"
  → 父 Agent 调 directive_create(text, anchor="加密算法>key提取", type=verify)
  → 返回 D-0007 (status=received)
  → 委派前调 directive_list(status!=resolved) → 非空 → 先处理 D-0007
  → 委派验证任务 → 完成后 directive_update(D-0007, status=resolved, outcome=..., resolved_by=...)
  → situation_update(timeline_event={event:"D-0007 已处理", actor:"agent"})
```

#### B2. 确定性解析器（纯规则，无 LLM）

实现为独立模块 `directive_parser.py` + MCP 工具 `directive_parse(text, anchor?)`。

```python
KEYWORD_RULES = [
    # (regex, type)
    (r'不要|停止|别再|暂停', 'stop'),
    (r'应该|必须|优先|先做', 'redirect'),
    (r'验证一下|再查|确认|检查|重跑|翻源码|看下', 'verify'),
    (r'为什么|怎么回事|什么情况', 'question'),
    (r'你确定吗|没有结果|？', 'question'),
    (r'node\s+[\d.]+', 'verify'),   # 引用节点号 → 默认 verify + 锚定
]
# 优先级：stop > redirect > verify > question
# 都不匹配 → type=info（纯信息补充，不入待办）
# anchor 提取：node X.Y → 解析树节点；含"node 3.2"等模式
# 无法确定 → 一律按指令入待办（type=redirect），宁多勿漏（v2 §8.2 兜底规则）
```

**关键决策**：解析器放在 **server.py 服务端**而不是父 Agent 内——保证"用户信号进结构性存储"是确定性行为，不依赖父 Agent 自觉。

#### B3. 三条强制义务的检查工具

- `directive_blocking_check(project)` → 返回 `{has_unresolved: bool, unresolved_count: N, oldest: {...}}`。父 Agent 在委派新方向前必须调用（v2 §8.2 规则1）；**服务端不强制拦截**（拦截需要 Hermes 平台层 hook，属 v2 §10.3 待验证问题 1，MCP 侧先提供查询原语）。
- `directive_repeat` 的重复计数 + 冻结提示即规则3 的存储支撑。

---

### C. 冲突存储与状态机（v2 P4）

> ⚠️ **职责边界（v2 §5.1）**：冲突**识别**是检测型子 Agent 的活（比对新发现 vs 已有 findings、按 §5.4 五类清单报警），冲突**裁决**是裁决型子 Agent 的活（看原始数据定案）。本节 MCP 只做**落库 + 状态机 + 查询**——它不判断"有没有冲突""谁对谁错"，只保证"冲突一旦被 Agent 发现，就进入结构化存储、状态可追踪、不会被跳过"。

#### C1. conflict 对象 + 状态机

**新表 `conflicts`**：

```sql
CREATE TABLE IF NOT EXISTS conflicts (
    id            TEXT PRIMARY KEY,       -- C-0001
    project       TEXT NOT NULL,
    conflict_type INTEGER NOT NULL,       -- 1 数值不一致 | 2 因果矛盾 | 3 前提矛盾 | 4 用户指令矛盾 | 5 原始数据矛盾
    party_a_id    TEXT NOT NULL,          -- finding ID 或 'observation:<id>'
    party_a_summary TEXT NOT NULL,
    party_a_evidence TEXT NOT NULL,       -- 原始输出引用/摘录
    party_b_id    TEXT NOT NULL,
    party_b_summary TEXT NOT NULL,
    party_b_evidence TEXT NOT NULL,
    reporter      TEXT NOT NULL,          -- detector-agent-id
    status        TEXT NOT NULL DEFAULT 'pending',
    -- pending → under_review → adjudicated
    -- pending → resolved_by_rerun（策略1 直接解决）
    strategy      TEXT,                   -- rerun_tool|cross_tool|dynamic_trace|judge|debate|human
    resolution    TEXT,                   -- 裁决结论 + 支撑证据引用
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    resolved_at   TEXT
);
```

**MCP 工具**（全部为落库/查询原语，判断由子 Agent 完成）：

- `conflict_report(project, conflict_type, party_a_id, party_a_summary, party_a_evidence, party_b_id, party_b_summary, party_b_evidence, reporter)` → **检测型子 Agent 判断出冲突后调用的落库工具**。服务端硬校验：`conflict_type` 枚举 1-5（存储合法性，不判断语义）；`reporter` 角色必须是 detector（source 解析）；返回完整 conflict 对象 + 自动给关联树节点加 `conflict` 标记。**识别"这是不是冲突、属于哪类"由子 Agent 完成，工具不代劳。**
- `conflict_list(project, status?)` → 冲突队列（供父 Agent 查看、供 situation_report 汇总）。
- `conflict_update(project, id, status?, strategy?, resolution?)` → **裁决型子 Agent 定案后的记录工具**：状态机推进 pending→under_review→adjudicated / resolved_by_rerun；adjudicated 时必须填 resolution + strategy（由裁决型给出）；自动移除关联节点的 `conflict` 标记，resolution 含"disproved"字样时联动 C3 级联降级。**"谁对谁错"由裁决型子 Agent 判断，工具只记录结论。**
- `conflict_stats(project)` → `{pending: N, under_review: N, adjudicated: N, by_type: {...}}`，供 situation_report 展示。

**检测型输出格式约束**（v2 §5.5）：conflict_report 的 description 中写明"禁止倾向性建议"是 prompt 层面；**服务端做的是字段强制**——不提供"哪方对"的输入槽，从 schema 上杜绝（检测型只报冲突、不裁决，与 §3 原则 6 一致）。

#### C2. 服务端自动提示（低置信辅助，非检测职责）

**职责澄清**：MCP **不做**冲突检测——检测是检测型子 Agent 的活。服务端只保留两类**低置信自动提示**，作为检测型的输入线索（误报无害，由子 Agent 过滤）：

1. 现有 `_check_conflicts` 关键词共现（store 时返回 `_conflicts` 候选）——**保留原样**，语义为"可能相关条目提示"，不做类型判断、不进入 conflicts 表。
2. 结构校验类提示（D2 的 gate 校验、type 枚举校验）——写入时返回，阻断的是**格式错误**，不判断**内容对错**。

**明确不实现**（避免与子 Agent 职责重叠）：
- ❌ 数值/地址正则比对自动报类型 1（v2 §5.4 的类型清单是给检测型子 Agent 的 prompt，不是服务端算法）
- ❌ 用户指令方向冲突自动判断（语义判断归检测型/父 Agent）
- ❌ conflict_detect 工具（无此工具——检测是 Agent 行为，不是工具行为）

#### C3. 级联降级增强：原因记录

- `_cascade_invalidate` 目前只加 `invalidated` 标签。**增强**：knowledge 表加 `invalidation_reason TEXT`；标 disproved 时传入 reason，级联时把 `"上游 <parent_id> 被证伪: <reason>"` 写入依赖者的 invalidation_reason。
- findings_update 标 disproved 且 tree_node_id 非空 → 自动给树节点加 `disproved` 标记（A2 联动）。

---

### D. 信息模型四类对象 + 写库 gate（v2 P4）

#### D1. type 字段 + task 专属表

**knowledge 表加列 `type`**：

```sql
ALTER TABLE knowledge ADD COLUMN type TEXT NOT NULL DEFAULT 'claim';
-- observation | claim | hypothesis | task
```

**新表 `task_meta`**：

```sql
CREATE TABLE IF NOT EXISTS task_meta (
    finding_id      TEXT PRIMARY KEY,
    hypothesis_id   TEXT,
    agent           TEXT,
    budget_tool_calls INTEGER, budget_tokens INTEGER, budget_seconds INTEGER,
    task_status     TEXT NOT NULL DEFAULT 'todo',  -- todo|running|done|failed
    dependencies_json TEXT NOT NULL DEFAULT '[]'
);
```

**type 语义**（v2 §6.4）：
- `observation`：工具直接输出，最高可信。evidence 必须含精确命令 + 原始摘录。写入后**不参与关键词冲突检测的置信度过滤**（已是最高级）。
- `claim`：解释/推断。`based_on` 必须引用 ≥1 条 observation（D2 强制）。
- `hypothesis`：待验证假设。fact 必须含 `test_plan:` 前缀段（D2 强制）。
- `task`：可执行任务。必须同时写入 task_meta（budget 三字段必填），status 由编排推进。

#### D2. 写库 gate（store_finding / update_finding 内强制校验）

```python
def _validate_write_gate(confidence, type_, based_on, source, fact, role, task_budget=None):
    # ① 角色权责（v2 §5.1）：解析 source 中 role
    #    子 Agent（role=discovery/detector/judge/analyst/leaf）→ 禁标 confirmed-inferred / speculative
    #    role 缺失 → 默认拒绝 confirmed-inferred/speculative（宁严勿松）
    # ② type 校验（v2 §6.4）：
    #    claim 且 based_on 为空 或 based_on 无 observation 类型 → 拒绝写入，提示"claim 必须引用 ≥1 observation"
    #    hypothesis 且 'test_plan:' 不在 fact → 拒绝
    #    task 且 task_budget 缺失任一 budget_* → 拒绝
    # ③ confirmed-inferred 需 evidence 含两个独立来源标记：
    #    evidence 中必须出现两个不同 agent-id（正则提取），否则拒绝并提示"需两个独立子 Agent 交叉验证"
    # ④ 校验通过才允许 INSERT / UPDATE
```

**校验失败行为**：返回 `{error: "write_gate_violation", reason: "...", suggestion: "..."}`，**不静默降级**（宁拒绝，不写错）。降级路径由调用方（父 Agent）显式决定——这是与"自动降级 speculative"的区别：v2 §5.6 要求"否则拒绝写入，降级为 speculative"，这里选择**拒绝 + 显式建议**，因为自动降级会掩盖问题、让错误静默进入库。

**⚠️ gate 只做结构校验，不做语义校验**（职责边界，v2 §6.4 末条）：
- MCP 校验的是**结构存在性**：`based_on` 引用的 finding ID 存在吗？引用的是 observation 类型吗？evidence 字段非空吗？两个 agent-id 标记存在吗？
- **语义匹配**（"evidence 是否真的支持 statement""claim 的结论是否与 observation 一致"）是**检测型子 Agent 的活**（v2 §6.4："检测型新增校验：claim 的 evidence 是否真实存在**且匹配 statement**"——"真实存在"归 MCP，"匹配 statement"归检测型）。MCP 无法理解语义，也不假装理解。

---

### E. 三层监督存储（v2 P1）

#### E1. 违规审计

**新表 `audit_log`**：

```sql
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project     TEXT NOT NULL,
    actor       TEXT NOT NULL,            -- parent | agent:<id>
    rule_id     TEXT NOT NULL,            -- R1 委派前无findings_search | R2 同假设失败≥2 | R3 汇报无置信度 | R4 委派context无验证 | R5 冻结触发
    detail      TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
```

**MCP 工具**：
- `audit_violation(project, rule_id, detail)` → 记一条违规（父 Agent 自报 + 外部监督可报）。
- `audit_list(project, rule_id?, limit?)` → 违规记录。
- `audit_stats(project)` → 违规计数 by rule_id + 最近 N 条，供 E2 判断。

#### E2. 冻结层

**situations 表加列 `frozen`（TEXT NULL = 未冻结；非空 = 冻结原因）+ `frozen_at`**。

**MCP 工具**：
- `freeze_status(project)` → 检查并返回：
  ```
  frozen = (违规计数 ≥3) OR (未解决待办 ≥3) OR (存在 repeat_count ≥2 的指令)
  → {frozen: bool, reason: [...], counts: {violations: N, unresolved_directives: N, repeated_directives: N}}
  ```
- `freeze_trigger(project, reason)` / `freeze_release(project)` → 显式操作。
- **调用时机约定**：父 Agent 每次委派前调 freeze_status（与 B3 的 blocking_check 合并为一次调用 `preflight_check(project)` 更佳——见 F3 合并建议）。

---

### F. 交互层与共享协议

#### F1. tree_render：缩进树 + 节点编号（v2 §7.3 MVP）

**MCP 工具 `tree_render(project, node_id?, max_depth=4, with_findings=true)`** → 返回文本树：

```
HITCON2024_rev1
├── 1 challenge.exe
│   ├── 1.1 sub_4012a0
│   │   ├── [obs] TEA 解密特征 (confirmed-observed)         ← 1.1.1
│   │   └── [claim] 密钥来自 0x403000 (likely) ⚠️ 冲突       ← 1.1.2
│   └── 1.2 sub_402000
│       └── [obs] VirtualAlloc 调用 (confirmed-observed)    ← 1.2.1
└── 2 data.bin
    └── [obs] 前 16 字节是 IV (confirmed-observed)           ← 2.1
```

规则：
- 节点编号 = 深度优先递增序号（1、1.1、1.1.1 格式），与 v2 §7.3 "node 3.2" 引用格式一致。
- finding 行格式：`[type] fact 摘要 (confidence) + 状态标记`；fact 超 60 字符截断 + "…"。
- 树节点状态标记图标：⚠️ conflict / 🔄 active / ❌ disproved / 🎯 candidate / 📌 directive / 🔒 unverified。
- 体积上限：超过 ~6KB 自动截断并提示"节点过多，请用 node_id 下钻"（防上下文污染）。

#### F2. findings_snapshot：按角色裁剪（v2 §5.3 信息共享协议）

**MCP 工具 `findings_snapshot(project, role, tree_node_id?, limit?)`**：

| role | 返回内容 | 体积目标 |
|------|---------|:---:|
| discovery（发现型） | findings **摘要**：id + 一句话 fact + confidence，不带 evidence | ≤3KB |
| detector（检测型） | **完整** findings（fact+evidence+source）+ 新发现输入 | ≤8KB |
| judge（裁决型） | 冲突双方完整证据 + evidence_uri 指向的原始输出 | 按需 |
| analyst（分析型） | findings 完整证据链（含 based_on 展开） | ≤8KB |

实现：服务端按 role 裁剪字段 + 截断长文本；超过体积上限的自动截断 + 返回 `truncated: true`。

#### F3. 合并建议：preflight_check

把 B3（directive_blocking_check）+ E2（freeze_status）+ situation 摘要合并为一个工具：

- `preflight_check(project)` → `{freeze: {...}, unresolved_directives: [...], situation_summary: {...}}`
- 父 Agent 的"委派前检查"从 3 次调用变 1 次，降低被跳过概率（一次调用 = 一个确定性 hook 点）。

#### F4. project_list：项目总览

- `project_list()` → 遍历 DB_DIR 下 *.db，返回 `[{project, findings_count, tree_nodes_count, updated_at}]`，按最近更新排序。

---

### G. 证据增强

#### G1. FTS5 全文搜索

- 为 knowledge 建 FTS5 虚拟表（`knowledge_fts`，content 列 = fact + evidence + tags），触发器同步。
- `findings_search` 增加 `use_fts=true` 参数走 FTS5（支持中文/词序），默认仍走 LIKE 兼容。
- 迁移：首次连接时 `CREATE VIRTUAL TABLE IF NOT EXISTS` + 重建索引。

#### G2. artifact 原始输出存储（evidence_uri）

- `artifact_store(project, tool, command, output)` → 将原始工具输出存到 `DB_DIR/artifacts/<project>/<sha1>.txt`，返回 `artifact://...` URI。
- `artifact_get(uri)` → 取回原始输出全文（裁决型用，v2 §5.3 "裁决型必须看原始数据"）。
- 体积限制：单文件 ≤512KB，超限截断并标记。

#### G3. 回归验证：抽样原语（轮子问题）

**职责边界（v2 §5.1 发现型）**："周期性回归验证：随机抽 N 条 confirmed-observed，**重新跑工具对照**"是发现型子 Agent 的职责。MCP 只提供**抽样 + 回写**两个原语，重跑工具、比对、判定由子 Agent 执行：

- `verification_check(project, sample_size=3, confidence='confirmed-observed')` → **抽样原语**：随机返回 N 条 confirmed-observed 的 `[{finding_id, fact, source, evidence_uri}]`（含工具命令提示），交给发现型子 Agent 去重跑对照。
- `verification_report(project, results)` → **回写存储**：发现型子 Agent 跑完后把每条的 `{finding_id, verified: true|false, actual_output}` 存回（一致的标记 `regression_verified` 标签）。**不一致时不自动生成 conflict**——由发现型子 Agent 走正常上报路径：调 `conflict_report(conflict_type=5, ...)`（C1）。

---

## 5. 实施路线（与 v2 §10.1 对齐）

| 阶段 | 内容 | MCP 新增/修改 | 验证标准 |
|------|------|--------------|---------|
| **G0 数据模型扩展** | type/evidence_uri/status/markers/invalidation_reason 列 + situations/directives/conflicts/audit_log/task_meta 表 + FTS5 | schema 迁移 + gate 函数骨架 | 旧 DB 首连无异常；store 可写全字段 |
| **G1 监督层**（v2 P1） | audit_violation/audit_list/audit_stats/freeze_status/trigger/release | 5 个新工具 | 违规 ≥3 触发冻结返回 frozen=true |
| **G2 状态层**（v2 P2） | situation_get/update/report + tree_mark/unmark + tree_render | 6 个新工具 | 用户 1 分钟掌握局面（树渲染 + 局面摘要） |
| **G3 指挥层**（v2 P3） | directive_create/list/update/repeat + directive_parse + preflight_check | 6 个新工具 | 待办 0 积压；重复指令 ≥2 触发冻结提示 |
| **G4 冲突存储 + 回归原语**（v2 P4） | conflict_report/list/update/stats（落库+状态机）+ verification_check/report（抽样+回写） | 6 个新工具 | 冲突不跳过：检测型 report → 裁决型 adjudicated 全流程走通 |
| **G5 写库 gate + 快照** | D2 gate 全量启用 + findings_snapshot + project_list + artifact | 3 个新工具 + store 改造 | 违反 gate 的写入被拒绝并返回明确原因 |
| **G6 打磨** | FTS5 默认化、体积上限调优、README/System Prompt 更新 | 文档 | 回归测试集（11 周错误案例）通过 |

**依赖关系**：G0 →（G1 | G2 | G3 | G4 并行）→ G5 → G6。G1-G4 都只依赖 G0 的 schema，可并行开发。

---

## 6. 落地注意事项与风险

1. **角色来源的可信度问题**：D2 依赖 `source` 字段格式约定解析 role。若子 Agent 伪造 source 绕过，需配合 Hermes 平台层的委派参数校验（v2 §10.3 待验证问题 1）。MCP 侧先做"信任但不盲信"：role=parent 才允许 confirmed-inferred/speculative，且 audit_log 记录每次高置信写入。
2. **确定性解析器误判率**：B2 的关键词规则需要真实用户输入样本校准（v2 §10.3 问题 3）。先按"宁多勿漏"上线，观察 directive 类型分布再调。
3. **冻结拦截是 MCP 不能独立完成的**：`freeze_status` 只返回状态；"冻结工具调用"需要 Hermes 插件层 hook。本方案明确 MCP 边界 = 状态存储 + 查询原语，拦截留给平台层（文档中标注为 v2 P1 的待验证点）。
4. **Situation 冗余一致性**：user_directives_json 是 directives 表的冗余视图，写入走 directive 工具、situation 只读，避免双写不一致；conflict_queue_json 同理。
5. **性能**：每项目独立 SQLite + WAL，findings 万级规模无压力；FTS5 为中文搜索兜底（LIKE 对中文子串也有效，FTS5 提升的是 token 化质量）。
6. **不破坏现有工作流**：所有增强向后兼容——旧工具签名不变、旧 DB 自动迁移；现有 skill 中的 findings 用法（mcp_knowledge_* 工具）零改动可用。

---

## 7. 总结：优先实现 Top 5

按 v2 方案的"核心机制"排序，MCP 侧最该先做的是：

1. **directive 管道（B1+B2+B3）** —— v2 三大 100% 复现错误的"用户信号被无视"的唯一结构性解药；
2. **situation + tree_render（A1+F1）** —— 用户实时掌控局面的基础设施；
3. **写库 gate（D2）** —— "断言代替证据"的直接阻断器；
4. **conflict 存储与状态机（C1）** —— 保证"冲突一旦被检测型子 Agent 发现，就进入结构化存储、状态可追踪、不会被跳过"；识别与裁决归子 Agent，工具只管落库与状态推进。
5. **freeze_status + audit（E1+E2）** —— 三层监督的存储底座。

这五项完成后，knowledge-mcp 从"证据层存储"升级为 v2 方案的"状态层 + 指挥层 + 监督层"完整底座，父 Agent 的编排逻辑（prompt 层）才有硬机制可依。

---

## 文档元信息

- 文档版本：v1.1（2026-08-04）——v1.1 修正：明确职责边界（MCP=存储层，Agent=判断层），移除 C2 类型化检测与 G3 自动生成冲突（冲突识别归检测型、裁决归裁决型、回归对照归发现型），gate 补充"只做结构校验不做语义校验"
- 状态：设计方案（待用户确认后进入 G0 实现）
- 位置：/root/tools/agent-research/knowledge-mcp-v2-gap-plan.md
- 关联：ctf-reverse-orchestrator-v2.md（对标）、knowledge-mcp 仓库（实现对象）
