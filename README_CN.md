# Findings MCP Server

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> 轻量级 Agent 推理发现存储 MCP 工具 — 带可信度标注、推理链追溯、级联降级、冲突检测。
> 同时支持 **DAG 推理链**和**树状项目结构**两个维度组织信息。
> 专为 CTF 逆向多 Agent 工作流设计，区分观察与推断，防止幻觉级联。

[English docs / 英文文档](README.md)

---

## 设计理念

**不是记忆系统、不是知识图谱、不是向量搜索。** 就是一个带可信度标签的事实存储。

Agent 每完成一步推理，记录一条发现。核心价值：
- **区分事实与推断**：confirmed-observed（工具原始输出）≠ confirmed-inferred（交叉验证后的推断）
- **推理链可追溯**：推翻一条，所有下游推断自动失效
- **证据不丢失**：推翻结论后原始证据仍可召回
- **角色权责分明**：子 Agent 可标 confirmed-observed / likely，但不可标 confirmed-inferred / speculative

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

## MCP 工具

### findings_store — 存储发现

```json
{
  "project": "HITCON2024_rev1",
  "fact": "sub_4012a0 在 0x401310 处读取 qword_40A0，与 0x9E3779B9 异或，符合 TEA 解密特征",
  "confidence": "confirmed-observed",
  "source": "tool:ida",
  "evidence": "mov rax,[rip+0x40A0]; xor rax,0x9E3779B9; 循环 32 轮",
  "based_on": "<parent-finding-id>",
  "tags": ["crypto", "tea"],
  "tree_path": "challenge.exe>sub_4012a0"
}
```

新增可选参数：
- `tree_path` — 树状结构路径，`>` 分隔层级（如 `"challenge.exe>sub_4012a0"`）。自动创建路径上所有缺失节点，并将 finding 挂载到叶子节点。

存入 `confirmed-observed` / `confirmed-inferred` / `disproved` 时自动检测与已有条目冲突，返回 `_conflicts` 列表。

### findings_search — 搜索

```json
{
  "project": "HITCON2024_rev1",
  "query": "TEA",
  "confidence": "verified",
  "tag": "crypto",
  "tree_node_id": "HITCON2024_rev1>challenge.exe>sub_4012a0",
  "limit": 20
}
```

新增可选参数：
- `tree_node_id` — 过滤特定树节点下所有 findings

搜索规则：`query` 对 fact/evidence 做文本匹配。confidence 快捷方式：
- `"verified"` → confirmed-observed + confirmed-inferred + disproved（全部已验证条目）
- `"confirmed"` → confirmed-observed + confirmed-inferred（兼容旧版快捷方式）
- 具体值如 `"likely"` → 精确匹配该置信度

多条件 AND 逻辑，按创建时间倒序。

### findings_get — 获取单条

返回完整记录 + `dependent_count`（有多少条目依赖它）。

### findings_update — 更新（含级联降级）

将条目标为 `disproved` 时自动触发：
- 所有 `based_on` 指向此 ID 的条目 → 降级为 `speculative` + 追加 `invalidated` 标签
- 递归处理二级依赖

---

### tree_store — 创建/更新树节点

```json
{
  "project": "HITCON2024_rev1",
  "path": "challenge.exe>sub_4012a0>loop_body",
  "node_type": "function",
  "parent_path": null
}
```

自动创建路径上所有缺失的中间节点（中间节点默认类型为 `section`）。

节点类型：`project` | `file` | `function` | `class` | `section`

`parent_path` 可选：指定父路径后，`path` 拼接到父路径下。

### tree_get — 获取树节点

```json
{
  "project": "HITCON2024_rev1",
  "node_id": "HITCON2024_rev1>challenge.exe>sub_4012a0"
}
```

返回节点信息 + 子节点列表 + 直接挂载的 findings + 父节点摘要。

### tree_search — 搜索树节点

```json
{
  "project": "HITCON2024_rev1",
  "query": "sub_401",
  "node_type": "function",
  "parent_id": "HITCON2024_rev1>challenge.exe",
  "limit": 50
}
```

按名称、类型、父节点过滤。

### tree_delete — 删除树节点

```json
{
  "project": "HITCON2024_rev1",
  "node_id": "HITCON2024_rev1>challenge.exe>sub_4012a0"
}
```

级联删除所有子节点。挂载的 findings 保留（`tree_node_id` 置 NULL），数据不丢失。

---

## 部署

### 直接运行

```bash
pip install mcp>=1.20.0
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

## 存储结构

```
~/.hermes/findings/               # 可通过 FINDINGS_DB_DIR 环境变量修改
├── HITCON2024_rev1.db            # 每个项目独立 SQLite 文件
│   ├── knowledge                 # 发现表（含 tree_node_id）
│   └── tree_nodes                # 树节点表（自引用层级结构）
├── pbb_new.db
└── some-project.db
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

## 树状结构使用

推荐在 findings_store 时传入 tree_path 参数，将发现挂载到对应的项目结构中：
- 路径格式：">" 分隔层级，如 "challenge.exe>sub_4012a0>loop_body"
- 叶子节点类型默认 function，中间节点自动创建为 section
- 需要指定文件类型时用 tree_store 预先创建：tree_store(project, path, node_type="file")
- 查询时通过 tree_node_id 精确过滤：findings_search(project, tree_node_id="HITCON2024>challenge.exe>sub_4012a0")
- 浏览结构：tree_get(project, node_id="HITCON2024>challenge.exe") 查看文件下所有函数和发现

tags 只保留语义标签（如 "crypto"、"rc4"），位置信息由 tree_path 编码。
```

---

## 从 v2（5 级置信度）迁移

v3 新增了树状结构支持。已有数据库在首次连接时自动迁移（添加 `tree_node_id` 列和 `tree_nodes` 表）。

已有 findings 的 `tree_node_id` 为 NULL，不影响现有功能。可后续通过 `findings_update` 补充树节点关联。

### v1（4 级）→ v2（5 级）迁移

v2 将 `confirmed` 拆分为 `confirmed-observed` 和 `confirmed-inferred`。向后兼容：
- `findings_search` 中 `confidence="confirmed"` 快捷匹配 confirmed-observed + confirmed-inferred
- `confidence="verified"` 匹配 confirmed-observed + confirmed-inferred + disproved

---

## 许可证

MIT
