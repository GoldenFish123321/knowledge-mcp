# Findings MCP Server

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> 轻量级 Agent 推理发现存储 MCP 工具 — 带可信度标注、推理链追溯、级联降级、冲突检测。
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
  "source": "tool:ida:sub_4012a0",
  "evidence": "mov rax,[rip+0x40A0]; xor rax,0x9E3779B9; 循环 32 轮",
  "based_on": "<parent-finding-id>",
  "tags": ["binary:challenge.exe", "crypto", "tea"]
}
```

存入 `confirmed-observed` / `confirmed-inferred` / `disproved` 时自动检测与已有条目冲突，返回 `_conflicts` 列表。

### findings_search — 搜索

```json
{
  "project": "HITCON2024_rev1",
  "query": "TEA",
  "confidence": "verified",
  "tag": "crypto",
  "limit": 20
}
```

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
```

---

## 从 v1（4 级）迁移

v2 将 `confirmed` 拆分为 `confirmed-observed` 和 `confirmed-inferred`，并新增了角色权限语义。
已有数据库在首次连接时自动迁移（移除旧 CHECK 约束，应用层校验代替）。

向后兼容：
- `findings_search` 中 `confidence="confirmed"` 快捷匹配 confirmed-observed + confirmed-inferred
- `confidence="verified"` 匹配 confirmed-observed + confirmed-inferred + disproved
- 已有 `confirmed` 数据保留在 DB 中，只是再存入时需用新值

---

## 许可证

MIT
