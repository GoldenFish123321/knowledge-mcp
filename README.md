# Knowledge MCP Server

> 轻量级 Agent 知识存储 MCP 工具 — 带可信度标注、推理链追溯、级联降级、冲突检测。
>
> *Lightweight agent knowledge store — confidence labeling, reasoning chains, cascade invalidation, conflict detection.*

---

## 设计理念 / Design Philosophy

**不是记忆系统、不是知识图谱、不是向量搜索。** 就是一个带可信度标签的事实存储。

Agent 每完成一步推理，记录一条知识。核心价值：
- **区分事实与推断**：confirmed（已验证）vs likely（推导）vs speculative（猜测）
- **推理链可追溯**：推翻一条，所有下游推断自动失效
- **证据不丢失**：推翻结论后原始证据仍可召回

> *Not a memory system, not a knowledge graph, not vector search. Just fact storage with confidence labels.*
>
> *The agent records one piece of knowledge per reasoning step. Core values:*
> - *Separate facts from inferences*
> - *Traceable reasoning chains — invalidate one node, all downstream auto-expire*
> - *Evidence never lost — original tool output survives conclusion overturns*

---

## 四级置信度 / Four Confidence Levels

| 级别 Level | 含义 Meaning | 判定规则 / Criteria |
|------------|-------------|---------------------|
| `confirmed` | 已验证为真 / Verified true | 工具实际输出、用户明确陈述、代码/配置字面值 |
| `disproved` | 已验证为假 / Verified false | 尝试后明确失败、新证据推翻旧结论 |
| `likely` | 未验证但合理推导 / Plausible | 多线索推断、常见默认行为、行业惯例 |
| `speculative` | 纯猜测 / Pure guess | 无证据支撑、"可能""也许"的假设 |

---

## MCP 工具 / Tools

### knowledge_store — 存储知识 / Store

```json
{
  "project": "HITCON2024_rev1",
  "fact": "sub_4012a0 使用 256 字节 S-box，是 RC4 KSA",
  "confidence": "confirmed",
  "source": "tool:ida:sub_4012a0",
  "evidence": "mov edx,[rbp+sbox]; inc eax; mov cl,[rdx+rax]; 循环 256 次",
  "based_on": "<parent-knowledge-id>",
  "tags": ["binary:challenge.exe", "crypto", "rc4"]
}
```

存入 `confirmed`/`disproved` 时自动检测与已有条目冲突，返回 `_conflicts` 列表。

> *Auto-detects conflicts with existing confirmed/disproved entries on store.*

### knowledge_search — 搜索 / Search

```json
{
  "project": "HITCON2024_rev1",
  "query": "RC4",
  "confidence": "verified",
  "tag": "crypto",
  "limit": 20
}
```

搜索规则：`query` 对 fact/evidence 做文本匹配，`confidence: "verified"` 快捷匹配 confirmed + disproved，多条件 AND 逻辑。

> *Text-match search on fact/evidence. `confidence: "verified"` matches both confirmed + disproved. Multi-condition AND.*

### knowledge_get — 获取单条 / Get Single Entry

返回完整记录 + `dependent_count`（有多少条目依赖它）。

> *Returns full entry + dependent_count.*

### knowledge_update — 更新 / Update

将条目标为 `disproved` 时自动级联降级：
- 所有 `based_on` 指向此 ID 的条目 → 降级为 `speculative` + 追加 `invalidated` 标签
- 递归处理二级依赖

> *Cascade invalidation: marking an entry as disproved → all dependents → speculative + [invalidated] tag. Recursive.*

---

## 部署 / Deployment

### 方式一：直接运行 / Direct

```bash
pip install mcp
python server.py
```

### 方式二：Docker

```bash
docker build -t knowledge-mcp .
docker run -i --rm -v ~/.hermes/knowledge:/data knowledge-mcp
```

### Hermes Agent 配置 / Hermes Config

```yaml
# 直接运行 / Direct
mcp_servers:
  knowledge:
    command: python
    args: ["/path/to/knowledge-mcp/server.py"]
    env:
      KNOWLEDGE_DB_DIR: /home/agent/.hermes/knowledge
```

```yaml
# Docker
mcp_servers:
  knowledge:
    command: docker
    args: ["run", "-i", "--rm", "-v", "/home/agent/.hermes/knowledge:/data", "knowledge-mcp"]
```

---

## 存储结构 / Storage

```
~/.hermes/knowledge/             # 可通过 KNOWLEDGE_DB_DIR 环境变量修改
├── HITCON2024_rev1.db           # 每个项目独立 SQLite 文件
├── pbb_new.db                   # One SQLite file per project
└── some-project.db
```

---

## System Prompt 建议 / Suggested Prompt

```
## 知识记录规则 / Knowledge Recording Rules

每次推理步骤后有可复用的发现时，调用 knowledge_store。
Call knowledge_store after each reasoning step with reusable findings.

打分规则 / Confidence rules:
- confirmed: 工具实际返回、用户原话、文件/配置中读到的字面值
- disproved: 已验证为假、被新证据推翻的旧结论
- likely: 从已知信息推导但未直接验证
- speculative: 无证据的猜测

重要结论前，先调用 knowledge_search 检查是否有 confirmed 直接答案或 disproved 冲突。
Before any important conclusion, search for confirmed answers or disproved contradictions.
```

---

## 许可证 / License

MIT
