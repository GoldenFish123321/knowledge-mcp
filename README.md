# Findings MCP Server

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> Lightweight agent reasoning findings store — confidence labeling, reasoning chains, cascade invalidation, conflict detection.
> Designed for CTF reverse engineering multi-agent workflows: separates observation from inference, prevents hallucination cascade.

[中文文档 / Chinese docs](README_CN.md)

---

## Design Philosophy

Not a memory system, not a knowledge graph, not vector search. Just fact storage with confidence labels.

The agent records one finding per reasoning step. Core values:
- **Separate observation from inference**: confirmed-observed (raw tool output) ≠ confirmed-inferred (cross-validated conclusion)
- **Traceable reasoning chains**: invalidate one node, all downstream auto-expire
- **Evidence never lost**: original tool output survives conclusion overturns
- **Role-based authority**: sub-agents can mark confirmed-observed / likely, but never confirmed-inferred / speculative

---

## Five Confidence Levels

| Level | Meaning | Who proposes | Who confirms | Criteria |
|-------|---------|-------------|-------------|----------|
| `confirmed-observed` | Reproducible raw tool output | Sub-agent | Sub-agent | Zero inference. evidence must include exact command + raw output excerpt |
| `confirmed-inferred` | Cross-validated inference | Parent agent (only) | Parent agent (only) | Two independent sub-agents + different tool families + active code path + challenger round passed |
| `likely` | Single sub-agent inference | Sub-agent | Parent agent | Not yet cross-validated; sub-agents must not mark as confirmed-inferred |
| `speculative` | Parent agent hypothesis | Parent agent (only) | Parent agent (only) | Sub-agents have no authority to propose |
| `disproved` | Falsified | Any role | Any recognizer | Contradiction found; triggers cascade invalidation |

---

## MCP Tools

### findings_store — Store a finding

```json
{
  "project": "HITCON2024_rev1",
  "fact": "sub_4012a0 reads qword_40A0 at 0x401310, XORs with 0x9E3779B9, matching TEA decryption",
  "confidence": "confirmed-observed",
  "source": "tool:ida:sub_4012a0",
  "evidence": "mov rax,[rip+0x40A0]; xor rax,0x9E3779B9; 32 rounds",
  "based_on": "<parent-finding-id>",
  "tags": ["binary:challenge.exe", "crypto", "tea"]
}
```

When storing `confirmed-observed` / `confirmed-inferred` / `disproved`, auto-detects conflicts with existing entries. Returns `_conflicts` list when found.

### findings_search — Search

```json
{
  "project": "HITCON2024_rev1",
  "query": "TEA",
  "confidence": "verified",
  "tag": "crypto",
  "limit": 20
}
```

Text-match on `fact`/`evidence`. Confidence shortcuts:
- `"verified"` → confirmed-observed + confirmed-inferred + disproved (all verified entries)
- `"confirmed"` → confirmed-observed + confirmed-inferred (backward-compatible shortcut)
- Specific value like `"likely"` → exact match

Multi-condition AND logic, ordered by creation time descending.

### findings_get — Get single entry

Returns full entry + `dependent_count` (how many entries depend on it).

### findings_update — Update (with cascade)

Marking an entry as `disproved` triggers cascade invalidation:
- All entries with `based_on` pointing to this ID → downgraded to `speculative` + `invalidated` tag
- Recursive (second-level dependents also invalidated)

---

## Deployment

### Direct

```bash
pip install mcp>=1.20.0
python server.py
```

### Docker

```bash
# Pre-built image (recommended)
docker run -i --rm -v ~/.hermes/findings:/data gfishx/findings-mcp

# Build from source
docker build -t findings-mcp .
docker run -i --rm -v ~/.hermes/findings:/data findings-mcp
```

### Hermes Agent Config

```yaml
# Direct
mcp_servers:
  findings:
    command: python
    args: ["/path/to/findings-mcp/server.py"]
    env:
      FINDINGS_DB_DIR: /home/agent/.hermes/findings
```

```yaml
# Docker (pre-built)
mcp_servers:
  findings:
    command: docker
    args: ["run", "-i", "--rm", "-v", "/home/agent/.hermes/findings:/data", "gfishx/findings-mcp"]
```

---

## Storage

```
~/.hermes/findings/               # Override with FINDINGS_DB_DIR env
├── HITCON2024_rev1.db            # One SQLite file per project
├── pbb_new.db
└── some-project.db
```

---

## Suggested System Prompt

```
## Findings Recording Rules

Call findings_store after each reasoning step with reusable findings.

Confidence rules:
- confirmed-observed: actual tool output, reproducible exact command + raw excerpt, zero inference
- confirmed-inferred: parent-agent-only, requires two independent sub-agents cross-validation
- likely: sub-agent's single inference, not yet cross-validated (sub-agents must never self-mark as confirmed-inferred)
- speculative: parent-agent-only, hypothesis/guess
- disproved: verified false, overtaken by new evidence

Sub-agent note: you may only mark confirmed-observed or likely.
Never mark confirmed-inferred or speculative — those are parent-agent privileges.

Before any important conclusion, search for confirmed answers or disproved contradictions
using findings_search.
```

---

## Migrating from v1 (4-level)

v2 splits `confirmed` into `confirmed-observed` and `confirmed-inferred`, adding role-based authority semantics.
Existing databases are auto-migrated on first connection (old CHECK constraint removed, app-level validation instead).

Backward compatibility:
- `findings_search` with `confidence="confirmed"` matches confirmed-observed + confirmed-inferred
- `confidence="verified"` matches confirmed-observed + confirmed-inferred + disproved
- Existing `confirmed` data remains in DB; new inserts must use new values

---

## License

MIT
