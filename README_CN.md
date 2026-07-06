# Findings MCP Server

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> 轻量级 Agent 推理发现存储 MCP 工具 — 带可信度标注、推理链追溯、级联降级、冲突检测。

[English docs / 英文文档](README.md)

---

## 设计理念

**不是记忆系统、不是知识图谱、不是向量搜索。** 就是一个带可信度标签的事实存储。

Agent 每完成一步推理，记录一条发现。核心价值：
- **区分事实与推断**：confirmed（已验证）vs likely（推导）vs speculative（猜测）
- **推理链可追溯**：推翻一条，所有下游推断自动失效
- **证据不丢失**：推翻结论后原始证据仍可召回

---

## 四级置信度

| 级别 | 含义 | 判定规则 |
|------|------|----------|
| `confirmed` | 已验证为真 | 工具实际输出、用户明确陈述、代码/配置字面值 |
| `disproved` | 已验证为假 | 尝试后明确失败、新证据推翻旧结论 |
| `likely` | 未验证但合理推导 | 多线索推断、常见默认行为、行业惯例 |
| `speculative` | 纯猜测 | 无证据支撑、"可能""也许"的假设 |

---

## MCP 工具

### findings_store — 存储发现

```json
{
  "project": "HITCON2024_rev1",
  "fact": "sub_4012a0 使用 256 字节 S-box，是 RC4 KSA",
  "confidence": "confirmed",
  "source": "tool:ida:sub_4012a0",
  "evidence": "mov edx,[rbp+sbox]; inc eax; mov cl,[rdx+rax]; 循环 256 次",
  "based_on": "<parent-finding-id>",
  "tags": ["binary:challenge.exe", "crypto", "rc4"]
}
```

存入 `confirmed`/`disproved` 时自动检测与已有条目冲突，返回 `_conflicts` 列表。

### findings_search — 搜索

```json
{
  "project": "HITCON2024_rev1",
  "query": "RC4",
  "confidence": "verified",
  "tag": "crypto",
  "limit": 20
}
```

搜索规则：`query` 对 fact/evidence 做文本匹配，`confidence: "verified"` 快捷匹配 confirmed + disproved，多条件 AND。

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
pip install mcp
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

打分规则：
- confirmed: 工具实际返回、用户原话、文件/配置中读到的字面值
- disproved: 已验证为假、被新证据推翻的旧结论
- likely: 从已知信息推导但未直接验证
- speculative: 无证据的猜测

重要结论前，先调用 findings_search 检查是否有 confirmed 直接答案或 disproved 冲突。
```

---

## 许可证

MIT
