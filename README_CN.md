# Findings MCP Server（knowledge-mcp）

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> 轻量级 Agent 推理发现存储 MCP 工具 — 带可信度标注、推理链追溯、级联降级、冲突检测。
> 同时支持 **DAG 推理链**和**树状项目结构**两个维度组织信息。
> 专为 CTF 逆向多 Agent 工作流设计，区分观察与推断，防止幻觉级联。
> v1.1 新增：监督层（审计/冻结）、状态层（局面/树标记）、指挥层（指令待办）、冲突存储、快照裁剪与 artifact 证据存储，共 **37 个 MCP 工具**。

[English docs / 英文文档](README.md)

---


## 设计理念

**不是记忆系统、不是知识图谱、不是向量搜索。** 就是一个带可信度标签的事实存储。

Agent 每完成一步推理，记录一条发现。核心价值：
- **区分事实与推断**：confirmed-observed（工具原始输出）≠ confirmed-inferred（交叉验证后的推断）
- **推理链可追溯**：推翻一条，所有下游推断自动失效
- **证据不丢失**：推翻结论后原始证据仍可召回（v1.1 起支持 artifact:// URI 引用完整工具输出）
- **角色权责分明**：子 Agent 可标 confirmed-observed / likely，但不可标 confirmed-inferred / speculative

### 职责边界：MCP = 存储层，Agent = 判断层

这是 v1.1 的核心架构原则：

| 层 | 职责 | 举例 |
|----|------|------|
| **MCP（存储层）** | 只做结构校验、状态存储、查询原语 | 写库 gate 只检查"格式对不对"（角色、type、交叉验证标记是否齐全），不做语义判断 |
| **Agent（判断层）** | 语义判断、交叉验证、冲突裁决 | "谁对谁错"由检测型/裁决型子 Agent 判断；工具只记录结论 |

**服务端永不假装理解语义**：conflict_report 只校验字段合法性，不判断哪方正确；findings_store 只校验 type/based_on 结构，不判断事实真假。语义层全部留给 Agent 工作流。

### 二维信息组织：DAG + Tree

每条发现同时参与两个维度的结构：

| 维度 | 含义 | 问题 | 实现 |
|------|------|------|------|
| **DAG（推理链）** | 结论之间的推导依赖（"因为 A 所以 B"） | **怎么推出来的？** | `based_on` 字段 |
| **Tree（结构树）** | 结论所在的项目/文件/函数位置 | **在哪里发现的？** | `tree_nodes` 表 + `tree_node_id` |

```
                    DAG（推理链）
          [观察] ──→ [推断] ──→ [结论]
                        ↓ 推翻！
                    [级联失效]

                    Tree（结构树）
          Project
            ├── challenge.exe
            │     ├── sub_4012a0
            │     │     ├── Finding: "TEA 解密特征"
            │     │     └── Finding: "密钥来自 0x403000"
            │     └── sub_402000
            │           └── Finding: "VirtualAlloc 调用"
            └── data.bin
                  └── Finding: "前 16 字节是 IV"
```

---

## 五级置信度

| 级别 | 含义 | 谁可提出 | 谁可确认 | 判定规则 |
|------|------|---------|---------|----------|
| `confirmed-observed` | 可复现的原始工具输出 | 子 Agent | 子 Agent | 零推理，直接提交。evidence 须含精确命令 + 原始输出摘录 |
| `confirmed-inferred` | 交叉验证后的推理结论 | 父 Agent（唯一） | 父 Agent（唯一） | 两个独立子 Agent + 不同工具家族 + 活跃代码路径 + 反对派质疑通过 |
| `likely` | 子 Agent 的单项推断 | 子 Agent | 父 Agent | 尚未交叉验证；禁止子 Agent 直接标 confirmed-inferred |
| `speculative` | 父 Agent 的假设/猜测 | 父 Agent（唯一） | 父 Agent（唯一） | 子 Agent 无权提出 |
| `disproved` | 已证伪 | 任意角色 | 任意识别者 | 发现矛盾即标记；触发级联降级 |

---

## 写库 gate（v1.1 角色权责）

findings_store / findings_update 落库前做**五层结构校验**（只做结构不做语义）：

| 层 | 规则 | 失败示例 |
|----|------|---------|
| ① 角色权责 | source 中 `role:xxx` 决定权限。子 Agent（discovery/detector/judge/analyst/leaf）**禁标 confirmed-inferred / speculative**；role=parent 允许；**role 缺失/无法解析 → 默认拒绝**（宁严勿松）。confirmed-observed / likely / disproved 不受角色限制（不误伤子 Agent 正常提交） | `role:discovery` 标 confirmed-inferred → `write_gate_violation` |
| ② type 校验 | `claim` 必须 based_on 非空、ID 存在、且该 finding type=observation；`hypothesis` 的 fact 必须含 `test_plan:`；`task` 必须 task_budget 含 budget_tool_calls/budget_tokens/budget_seconds 三字段；type 非枚举 → 拒绝 | `hypothesis` 无 test_plan → 拒绝 |
| ③ 交叉验证标记 | `confirmed-inferred` 的 evidence 必须含 ≥2 个不同 `agent:<id>` 标记 | 只有 1 个 agent 标记 → 拒绝 |
| ④ 只结构不语义 | 服务端不判断事实真假，语义匹配归检测型子 Agent | — |
| ⑤ project 绑定（batch2 #1） | 父 Agent 通过 `situation_update` / `directive_create` **激活活动项目**后，子 Agent `findings_store`/`findings_update` 写入其他项目 → 拒绝。未激活 → 放行（兼容旧流程）；role=parent / role 无法解析 → 豁免。活动项目存全局 `_app_state.db`（非项目库），**单活动项目模型**——父 Agent 并行派子 Agent 到不同项目时后激活者生效，需串行切换编排（P2-7） | 激活 `projA` 后子 Agent 写 `projB` → `write_gate_violation` |

失败响应：`{"error": "write_gate_violation: <原因> | suggestion: <建议>"}`。
update 版 gate 只校验 ① + ③（type 在 store 时已校验），且仅在显式改受限置信度时触发（补证据/改标签不误拒）。

---

## MCP 工具（37 个）

### 分组总览

| 分组 | 工具 | 作用 |
|------|------|------|
| **基础 9** | findings_store / search / get / update / delete + tree_store / get / search / delete | 证据存储、搜索、树结构 |
| **G1 监督层 6** | audit_violation / list / stats + freeze_status / trigger / release | 违规审计 + 冻结状态机 |
| **G2 状态层 6** | situation_get / update / report + tree_mark / unmark / render | 局面对象 + 树标记 + 树渲染 |
| **G3 指挥层 6** | directive_create / list / update / repeat / parse + preflight_check | 用户指令待办 + 委派前检查 |
| **G4 冲突存储 6** | conflict_report / list / update / stats + verification_check / report | 冲突状态机 + 回归抽样 |
| **G5 快照裁剪 4** | findings_snapshot / project_list / artifact_store / get | 角色裁剪快照 + artifact 证据库 |

### 基础 9 个

#### findings_store — 存储发现

```json
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

v1.1 新增参数：
- `type` — 信息对象类型：`observation` | `claim` | `hypothesis` | `task`（默认 `claim`，受写库 gate ② 约束；type=task 时同步写 task_meta：task_budget / task_dependencies / task_agent）
- `evidence_uri` — artifact:// URI，指向原始工具输出（配合 artifact_store 落盘后引用）
- `tree_path` — 树状结构路径，`>` 分隔层级（如 `"challenge.exe>sub_4012a0"`），自动创建缺失节点并挂载

存入 `confirmed-observed` / `confirmed-inferred` / `disproved` 时自动检测与已有条目冲突，返回 `_conflicts` 列表。

#### findings_search — 搜索

```json
{
  "project": "D3CTF2026_d3llvm",
  "query": "TEA",
  "confidence": "verified",
  "tag": "crypto",
  "tree_node_id": "D3CTF2026_d3llvm>challenge.exe>sub_4012a0",
  "limit": 20,
  "use_fts": true
}
```

搜索规则：`query` 对 fact/evidence 做文本匹配。confidence 快捷方式：
- `"verified"` → confirmed-observed + confirmed-inferred + disproved（全部已验证条目）
- `"confirmed"` → confirmed-observed + confirmed-inferred（兼容旧版快捷方式）
- 具体值如 `"likely"` → 精确匹配该置信度

v1.1 新增参数：
- `use_fts` — 是否使用 FTS5 全文索引（默认 false）。true 时 query 按空白拆词 AND 匹配，命中精度更高；query 为空或 MATCH 语法异常时自动回退 LIKE
- `type` — 按信息对象类型过滤（observation/claim/hypothesis/task）

多条件 AND 逻辑，按创建时间倒序。

#### findings_get — 获取单条

返回完整记录 + `dependent_count`（有多少条目依赖它）。

#### findings_update — 更新（含级联降级）

v1.1 新增参数：`evidence_uri`（新的 artifact:// URI，不传不覆盖）。

将条目标为 `disproved` 时自动触发：
- 所有 `based_on` 指向此 ID 的条目 → 降级为 `speculative` + 追加 `invalidated` 标签
- 递归处理二级依赖

#### findings_delete — 删除（纠正误写/幽灵库残留）

删除单条发现，返回 `{deleted_id, orphaned_dependents}`。删除副作用：

- 依赖它的条目（`based_on` 指向它）的 `based_on` 被自动置 NULL（FK ON DELETE SET NULL），`orphaned_dependents` 告知数量
- `type=task` 的 `task_meta` 关联行一并清理；全文索引（FTS）自动同步删除
- 不可恢复，删除前建议先 `findings_get` 确认目标；目标不存在（project+id 不匹配）拒绝

#### tree_store / tree_get / tree_search / tree_delete — 树结构

- **tree_store** — 创建/更新树节点：`path`（`>` 分隔层级）+ `node_type`（project|file|function|class|section）+ `parent_path`（可选，拼接前缀）。自动创建缺失中间节点
- **tree_get** — 获取节点：`node_id`（完整路径）。返回节点信息 + 子节点 + 挂载的 findings + 父节点摘要；`markers` 为解析后的列表
- **tree_search** — 搜索节点：`query` / `node_type` / `parent_id` 过滤
- **tree_delete** — 删除节点：级联删除所有子节点，挂载的 findings 保留（`tree_node_id` 置 NULL），数据不丢失

### G1 监督层（审计 + 冻结）

| 工具 | 一句话说明 | 关键参数 |
|------|-----------|---------|
| `audit_violation` | 记录一条违规到审计日志 | `actor`（parent 或 agent:<id>）、`rule_id`（R1-R5）、`detail` |
| `audit_list` | 审计日志列表（倒序） | `rule_id` 过滤、`limit` |
| `audit_stats` | 按规则分组的违规计数 + 最近 5 条 | `project` |
| `freeze_status` | 冻结状态检查：违规≥3 / 未解决待办≥3 / 重复指令≥2 / 显式冻结任一满足即 frozen=true，reason 列出触发条件 | `project` |
| `freeze_trigger` | 显式冻结：写 situations.frozen + 自动记 R5 违规 | `project`、`reason` |
| `freeze_release` | 解除显式冻结（自动冻结由计数变化决定，不在此清除） | `project` |

**规则编号**：R1 委派前未 search / R2 同假设失败≥2 / R3 汇报无置信度 / R4 委派 context 无验证 / R5 冻结触发。

```json
// freeze_status 示例
{
  "project": "D3CTF2026_d3llvm"
}
// 响应
{
  "frozen": true,
  "reason": ["违规计数≥3(实际4)"],
  "counts": {"violations": 4, "unresolved_directives": 2, "repeated_directives": 0}
}
```

### G2 状态层（局面对象 + 树标记 + 树渲染）

| 工具 | 一句话说明 | 关键参数 |
|------|-----------|---------|
| `situation_get` | 获取项目局面对象（objective/project_meta/progress/active_work/conflict_queue/candidate_directions/risks/timeline/version/frozen）；无记录返回默认空局面（project_meta={}），不自动建行 | `project` |
| `situation_update` | 更新局面：version 每次 +1，timeline_event 追加，candidate_directions 每项必须含 evidence_strength∈{high,mid,low}；project_meta 为慢变元信息（约定 {workdir, repo, engine, api, background}），整体覆盖、不传不覆盖。**batch2 #6**：`progress_append` / `candidate_directions_append` 追加到现有列表末尾（空列表=无操作；与覆盖版同时传时先覆盖后追加）。副作用：激活/切换活动项目（见写库 gate ⑤） | `project` + 各局面字段 |
| `situation_report` | 生成局面推送文本（📊/✅/🔄/⚠️/🎯/📌 行格式），可直接推送给用户 | `project` |
| `tree_mark` | 给树节点加状态标记（conflict/active/disproved/candidate/directive/unverified），去重 | `node_id`、`marker` |
| `tree_unmark` | 移除节点标记（无副作用） | `node_id`、`marker` |
| `tree_render` | 渲染缩进树视图，深度优先编号（1、1.1、1.1.1），finding 与子节点共享编号序列；图标：markers（⚠️🔄❌🎯📌🔒）+ finding 置信度（disproved=❌、speculative=🔒）；体积超 ~6000 字符截断提示下钻 | `node_id`（可选）、`max_depth`（默认4）、`with_findings` |

```json
// tree_render 示例
{
  "project": "D3CTF2026_d3llvm",
  "node_id": "D3CTF2026_d3llvm>challenge.exe",
  "max_depth": 4
}
// 响应（示意）
D3CTF2026_d3llvm
└── challenge.exe
    ├── [obs] sub_4012a0 TEA 解密循环 (confirmed-observed) ← 1
    ├── 1. sub_4012a0 (function)
    │   └── [obs] TEA 解密特征 (confirmed-observed) ← 1.1
    └── 2. sub_402000 (function)
```

### G3 指挥层（指令待办 + 确定性解析器 + preflight）

| 工具 | 一句话说明 | 关键参数 |
|------|-----------|---------|
| `directive_create` | 创建用户指令待办：type 省略时服务端用确定性解析器推断（stop>redirect>verify>question，纯规则无 LLM）；type=info 不落库返回 skipped；id 按 D-XXXX 递增 | `text`、`anchor`、`type` |
| `directive_list` | 待办清单（created_at 升序），status 支持否定式如 `"!resolved"` | `status`、`limit` |
| `directive_update` | 状态推进（received/acknowledged/in_progress/resolved/needs_clarify），resolved 自动记 resolved_at | `id`、`status`、`outcome`、`resolved_by` |
| `directive_repeat` | 用户重复同一指令：repeat_count+1，≥2 返回 freeze_hint=true + 强制停止提示 | `id` |
| `directive_parse` | 纯解析指令不落库（优先级 stop>redirect>verify>question；node X.Y 引用→verify+锚定；空文本兜底 redirect） | `text`、`anchor` |
| `preflight_check` | **父 Agent 每次委派前唯一必须调用**：返回 {freeze, unresolved_directives, situation_summary}，未解决指令非空 → 先处理再委派 | `project` |

```json
// directive_create 示例
{
  "project": "D3CTF2026_d3llvm",
  "text": "停止当前方向，先验证 sub_4012a0 的解密结论",
  "anchor": "challenge.exe>sub_4012a0"
}
// 响应（示意）
{"id": "D-0001", "type": "stop", "status": "received", "anchor": "challenge.exe>sub_4012a0"}
```

### G4 冲突存储（conflict 状态机 + 回归原语）

| 工具 | 一句话说明 | 关键参数 |
|------|-----------|---------|
| `conflict_report` | 检测型子 Agent 上报冲突：落库 + 可选关联树节点加 conflict 标记；服务端只校验字段合法性，不判断谁对谁错 | `conflict_type`（1数值\|2因果\|3前提\|4指令\|5原始数据）、`party_a_*`、`party_b_*`、`reporter`、`tree_node_id` |
| `conflict_list` | 冲突队列（created_at 升序，status 精确过滤） | `status`、`limit` |
| `conflict_update` | 裁决型子 Agent 定案：状态机推进（pending→under_review→adjudicated/resolved_by_rerun，可跳转）；终态必须 strategy+resolution；resolution 含 "disproved" 自动联动 party_a 标 disproved（级联降级） | `id`、`status`、`strategy`（rerun_tool\|cross_tool\|dynamic_trace\|judge\|debate\|human）、`resolution` |
| `conflict_stats` | 按状态 + 按类型计数 | `project` |
| `verification_check` | 回归抽样：ORDER BY RANDOM() 取 N 条（上限 20）指定置信度 findings，交发现型子 Agent 重跑对照；command_hint 从 source 提取 tool:xxx | `sample_size`、`confidence` |
| `verification_report` | 回归回写：verified=true → 追加 regression_verified 标签；false → 记录 mismatches（不自动建 conflict，走 conflict_report 正常路径） | `results`（[{finding_id, verified, actual_output}]） |

```json
// conflict_report 示例
{
  "project": "D3CTF2026_d3llvm",
  "conflict_type": 1,
  "party_a_id": "9f1c2e3a-...",
  "party_a_summary": "sub_4012a0 是 TEA 解密",
  "party_a_evidence": "artifact://tool_output/D3CTF2026_d3llvm/3fa2b1c9.txt",
  "party_b_id": "5d9a2c1e-...",
  "party_b_summary": "sub_4012a0 是自定义 XOR 混淆",
  "party_b_evidence": "artifact://tool_output/D3CTF2026_d3llvm/8c2f4d1a.txt",
  "reporter": "detector-2",
  "tree_node_id": "D3CTF2026_d3llvm>challenge.exe>sub_4012a0"
}
// 响应（示意：返回 conflicts 表行；tree_node_id 传入时会先给该节点加 conflict 标记，但响应中无 tree_marked 字段）
{"id": "C-0001", "status": "pending", "conflict_type": 1, "reporter": "detector-2", "created_at": "2026-08-04T12:07:00Z"}
```

### G5 快照裁剪 + artifact（4 个）

| 工具 | 一句话说明 | 关键参数 |
|------|-----------|---------|
| `findings_snapshot` | 按角色裁剪的 findings 快照：discovery 仅 id+fact+confidence+type（防锚定）；detector 完整字段；judge 加 evidence_uri；analyst 加 based_on 展开（based_on_fact）。返回附带 `project_meta`（从局面对象读取，无局面行为 {}），供委派模板直接引用项目元信息 | `role`、`tree_node_id`、`limit` |
| `project_list` | 项目总览：列出 DB_DIR 下所有项目 + findings_count/tree_nodes_count/updated_at | 无参数 |
| `artifact_store` | 原始工具输出落盘：写入 DB_DIR/artifacts/<project>/<sha1>.txt，返回 artifact:// URI 供 evidence_uri 引用；超 512KB 截断标记 truncated | `tool`、`command`、`output` |
| `artifact_get` | 按 artifact:// URI 取回原始输出（裁决型用） | `uri` |

---

## artifact:// URI 说明

v1.1 起，原始工具输出可整体落盘并引用：

```
artifact://tool_output/<project>/<sha1>.txt
```

- 由 `artifact_store` 生成（sha1 = 输出内容 SHA1 前 16 位）
- 通过 findings_store / findings_update 的 `evidence_uri` 字段挂到 finding 上
- `artifact_get` 按 URI 取回（含 tool/command/stored_at 元数据），供裁决型子 Agent 复核
- 设计目的：evidence 字段存摘要（≤500 字符推荐），完整输出走 artifact——证据不因摘要截断而丢失

---

## 存储结构

```
~/.hermes/findings/               # 可通过 FINDINGS_DB_DIR 环境变量修改
├── HITCON2024_rev1.db            # 每个项目独立 SQLite 文件
└── artifacts/<project>/<sha1>.txt # 原始工具输出落盘目录
```

每个项目数据库包含以下表：

| 表 | 用途 |
|----|------|
| `knowledge` | 发现主表（fact/confidence/source/evidence/based_on/tags/tree_node_id/**type**/**evidence_uri**/invalidation_reason） |
| `tree_nodes` | 树节点表（自引用层级 + status/markers_json） |
| `situations` | 局面对象（每项目一行：objective/**project_meta_json**/progress/active_work/conflict_queue/candidate_directions/risks/user_directives/timeline/version/frozen） |
| `directives` | 用户指令待办（type/status/anchor/repeat_count/resolved_at） |
| `conflicts` | 冲突记录（状态机 pending→under_review→adjudicated/resolved_by_rerun + strategy/resolution） |
| `audit_log` | 监督审计日志（rule_id/actor/detail，违规计数驱动冻结） |
| `task_meta` | 任务扩展表（type=task 的 budget 三字段/agent/dependencies_json） |
| `knowledge_fts` | FTS5 全文索引（findings_search use_fts=true 时使用） |

其中 `situations`/`directives`/`conflicts`/`audit_log`/`task_meta`/`knowledge_fts` 为 v1.1 新增（首次连接自动创建）。

---

## 部署

### 直接运行

```bash
pip install -r requirements.txt   # requirements 已钉 mcp>=2.0,<3（server.py 使用 mcp 2.0 API）
python server.py
```

### Docker

```bash
# 预构建镜像（推荐）
docker run -i --rm -v ~/.hermes/findings:/data gfishx/findings-mcp

# 从源码构建
docker build -t findings-mcp .
docker run -i --rm -v ~/.hermes/findings:/data findings-mcp
```

### Hermes Agent 配置

```yaml
# 直接运行
mcp_servers:
  findings:
    command: python
    args: ["/path/to/findings-mcp/server.py"]
    env:
      FINDINGS_DB_DIR: /home/agent/.hermes/findings
```

```yaml
# Docker（预构建镜像）
mcp_servers:
  findings:
    command: docker
    args: ["run", "-i", "--rm", "-v", "/home/agent/.hermes/findings:/data", "gfishx/findings-mcp"]
```

---

## System Prompt 建议

```
## 发现记录规则

每次推理步骤后有可复用的发现时，调用 findings_store。

置信度规则：
- confirmed-observed: 工具实际输出、可复现的精确命令+原始摘录，零推理
- confirmed-inferred: 仅父 Agent 使用，需两个独立子 Agent 交叉验证通过后方可标此级
- likely: 子 Agent 的单项推断，尚未交叉验证（子 Agent 不得自行标 confirmed-inferred）
- speculative: 仅父 Agent 使用，假设/猜测
- disproved: 已验证为假、被新证据推翻的旧结论

子 Agent 注意：你只能标 confirmed-observed 或 likely，永远不要标 confirmed-inferred 或 speculative。
交叉验证和 speculative 假设是父 Agent 的特权。

重要结论前，先调用 findings_search 检查是否有 confirmed 直接答案或 disproved 冲突。

## 写库 gate（服务端强制，主动遵守）

- claim 必须基于 observation：based_on 填 observation 型 finding 的 ID
- hypothesis 的 fact 必须包含 test_plan: 段
- task 必须带 task_budget（budget_tool_calls/budget_tokens/budget_seconds）
- 标 confirmed-inferred 时 evidence 里必须有两个不同 agent:<id> 的交叉验证标记
- source 里注明角色：agent:<id>|role:<角色>|tool:<工具>

## 树状结构使用

推荐在 findings_store 时传入 tree_path 参数，将发现挂载到对应的项目结构中：
- 路径格式：">" 分隔层级，如 "challenge.exe>sub_4012a0>loop_body"
- 叶子节点类型默认 function，中间节点自动创建为 section
- 查询时通过 tree_node_id 精确过滤：findings_search(project, tree_node_id="...")
- 浏览结构：tree_render(project) 看全局；tree_get(project, node_id="...") 下钻单节点
- 树节点可打状态标记（tree_mark）：conflict/active/disproved/candidate/directive/unverified

## 快照 / 冲突 / 指令

- 委派前先跑 preflight_check（冻结/未解决指令/局面摘要）；冻结中或有待办指令 → 先处理再委派
- 发现结论冲突 → conflict_report 上报（服务端不判断对错，裁决归裁决型子 Agent）
- 用户指令 → directive_create 落待办，完成后 directive_update 标记 resolved
- 原始工具输出先 artifact_store 落盘，再把返回的 artifact:// URI 填进 evidence_uri
- 周期用 verification_check + verification_report 做回归抽样

tags 只保留语义标签（如 "crypto"、"rc4"），位置信息由 tree_path 编码。
```

---

## 从 v3 迁移到 v1.1

v1.1 在 v3（8 工具 + 树结构）基础上新增了监督/状态/指挥/冲突/快照五组工具与 6 张新表（situations/directives/conflicts/audit_log/task_meta/knowledge_fts）。

**迁移完全自动，无需手动操作**：旧数据库首次连接时 `_migrate_schema` 自动执行——知识表列级增量迁移（type/evidence_uri/invalidation_reason）、tree_nodes 列级迁移（status/markers_json），新表由 CREATE TABLE IF NOT EXISTS 自动创建，FTS5 索引自动建立。旧数据零丢失，功能完全向后兼容：
- `findings_search` 的 `confidence="confirmed"` 快捷匹配 confirmed-observed + confirmed-inferred（v2 拆分兼容）
- `confidence="verified"` 匹配 confirmed-observed + confirmed-inferred + disproved
- 旧 findings 的 `tree_node_id` 为 NULL，不影响现有功能，可后续通过 findings_update 补充树关联

---

## 许可证

MIT
