# Knowledge MCP Server

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/knowledge-mcp)](https://hub.docker.com/r/gfishx/knowledge-mcp)

> Lightweight agent knowledge store — confidence labeling, reasoning chains, cascade invalidation, conflict detection.

[中文文档 / Chinese docs](README_CN.md)

---

## Design Philosophy

Not a memory system, not a knowledge graph, not vector search. Just fact storage with confidence labels.

The agent records one piece of knowledge per reasoning step. Core values:
- **Separate facts from inferences**: confirmed (verified) vs likely (deduced) vs speculative (guess)
- **Traceable reasoning chains**: invalidate one node, all downstream auto-expire
- **Evidence never lost**: original tool output survives conclusion overturns

---

## Four Confidence Levels

| Level | Meaning | Criteria |
|-------|---------|----------|
| `confirmed` | Verified true | Tool output, user statement, literal config/code value |
| `disproved` | Verified false | Tried and failed, new evidence overturns old conclusion |
| `likely` | Plausible (unverified) | Multi-clue inference, common defaults, conventions |
| `speculative` | Pure guess | No evidence, "maybe"/"perhaps" assumptions |

---

## MCP Tools

### knowledge_store — Store knowledge

```json
{
  "project": "HITCON2024_rev1",
  "fact": "sub_4012a0 uses 256-byte S-box with swap loop, likely RC4 KSA",
  "confidence": "confirmed",
  "source": "tool:ida:sub_4012a0",
  "evidence": "mov edx,[rbp+sbox]; inc eax; mov cl,[rdx+rax]; loops 256 times",
  "based_on": "<parent-knowledge-id>",
  "tags": ["binary:challenge.exe", "crypto", "rc4"]
}
```

When storing `confirmed`/`disproved`, auto-detects conflicts with existing entries. Returns `_conflicts` list when found.

### knowledge_search — Search

```json
{
  "project": "HITCON2024_rev1",
  "query": "RC4",
  "confidence": "verified",
  "tag": "crypto",
  "limit": 20
}
```

Text-match on `fact`/`evidence`. `confidence: "verified"` matches both confirmed + disproved. Multi-condition AND logic.

### knowledge_get — Get single entry

Returns full entry + `dependent_count` (how many entries depend on it).

### knowledge_update — Update (with cascade)

Marking an entry as `disproved` triggers cascade invalidation:
- All entries with `based_on` pointing to this ID → downgraded to `speculative` + `invalidated` tag
- Recursive (second-level dependents also invalidated)

---

## Deployment

### Direct

```bash
pip install mcp
python server.py
```

### Docker

```bash
# Pre-built image (recommended)
docker run -i --rm -v ~/.hermes/knowledge:/data gfishx/knowledge-mcp

# Build from source
docker build -t knowledge-mcp .
docker run -i --rm -v ~/.hermes/knowledge:/data knowledge-mcp
```

### Hermes Agent Config

```yaml
# Direct
mcp_servers:
  knowledge:
    command: python
    args: ["/path/to/knowledge-mcp/server.py"]
    env:
      KNOWLEDGE_DB_DIR: /home/agent/.hermes/knowledge
```

```yaml
# Docker (pre-built)
mcp_servers:
  knowledge:
    command: docker
    args: ["run", "-i", "--rm", "-v", "/home/agent/.hermes/knowledge:/data", "gfishx/knowledge-mcp"]
```

---

## Storage

```
~/.hermes/knowledge/             # Override with KNOWLEDGE_DB_DIR env
├── HITCON2024_rev1.db           # One SQLite file per project
├── pbb_new.db
└── some-project.db
```

---

## Suggested System Prompt

```
## Knowledge Recording Rules

Call knowledge_store after each reasoning step with reusable findings.

Confidence rules:
- confirmed: tool output, user statement, literal config/code values
- disproved: verified false, overtaken by new evidence
- likely: deduced from known info but not directly verified
- speculative: no evidence

Before any important conclusion, search for confirmed answers or disproved contradictions
using knowledge_search.
```

---

## License

MIT
