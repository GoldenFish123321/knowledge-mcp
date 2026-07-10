# Findings MCP Server

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> Lightweight agent reasoning findings store — confidence labeling, reasoning chains, cascade invalidation, conflict detection.
> Now with **dual-dimensional organization**: DAG (reasoning chain) + Tree (project structure).
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

### Dual-Dimensional Organization: DAG + Tree

Each finding participates in two orthogonal structures:

| Dimension | Meaning | Question | Implementation |
|-----------|---------|----------|----------------|
| **DAG (reasoning chain)** | Derivation dependencies ("A implies B") | **How was this derived?** | `based_on` field |
| **Tree (structure)** | Project/file/function location | **Where was this found?** | `tree_nodes` table + `tree_node_id` |

```
                    DAG (Reasoning Chain)
         [Observation] ──→ [Inference] ──→ [Conclusion]
                               ↓ disproved!
                          [Cascade invalidated]

                    Tree (Project Structure)
          Project
            ├── challenge.exe
            │     ├── sub_4012a0
            │     │     ├── Finding: "TEA decryption pattern"
            │     │     └── Finding: "Key from 0x403000"
            │     └── sub_402000
            │           └── Finding: "VirtualAlloc call"
            └── data.bin
                  └── Finding: "First 16 bytes are IV"
```

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
  "source": "tool:ida",
  "evidence": "mov rax,[rip+0x40A0]; xor rax,0x9E3779B9; 32 rounds",
  "based_on": "<parent-finding-id>",
  "tags": ["crypto", "tea"],
  "tree_path": "challenge.exe>sub_4012a0"
}
```

New optional parameter:
- `tree_path` — tree structure path, `>`-separated hierarchy (e.g. `"challenge.exe>sub_4012a0"`). Auto-creates all missing nodes in the path and links the finding to the leaf node.

When storing `confirmed-observed` / `confirmed-inferred` / `disproved`, auto-detects conflicts with existing entries. Returns `_conflicts` list when found.

### findings_search — Search

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

New optional parameter:
- `tree_node_id` — filter findings under a specific tree node

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

### tree_store — Create/update tree node

```json
{
  "project": "HITCON2024_rev1",
  "path": "challenge.exe>sub_4012a0>loop_body",
  "node_type": "function",
  "parent_path": null
}
```

Auto-creates all missing intermediate nodes (default type: `section`).

Node types: `project` | `file` | `function` | `class` | `section`

Optional `parent_path`: prepend a parent path to `path`.

### tree_get — Get tree node

```json
{
  "project": "HITCON2024_rev1",
  "node_id": "HITCON2024_rev1>challenge.exe>sub_4012a0"
}
```

Returns node info + children list + attached findings + parent summary.

### tree_search — Search tree nodes

```json
{
  "project": "HITCON2024_rev1",
  "query": "sub_401",
  "node_type": "function",
  "parent_id": "HITCON2024_rev1>challenge.exe",
  "limit": 50
}
```

Filter by name, type, or parent node.

### tree_delete — Delete tree node

```json
{
  "project": "HITCON2024_rev1",
  "node_id": "HITCON2024_rev1>challenge.exe>sub_4012a0"
}
```

Cascade-deletes all children. Attached findings are preserved (`tree_node_id` set to NULL), no data loss.

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
│   ├── knowledge                 # Findings table (with tree_node_id)
│   └── tree_nodes                # Tree nodes table (self-referencing hierarchy)
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

## Tree Structure Usage

Prefer passing tree_path when calling findings_store to link findings to project structure:
- Path format: ">"-separated hierarchy, e.g. "challenge.exe>sub_4012a0>loop_body"
- Leaf node defaults to type "function", intermediate nodes auto-created as "section"
- Use tree_store to pre-create file nodes: tree_store(project, path, node_type="file")
- Filter by tree_node_id: findings_search(project, tree_node_id="HITCON2024>challenge.exe>sub_4012a0")
- Browse structure: tree_get(project, node_id="HITCON2024>challenge.exe") to see all functions and findings

Keep tags for semantic labels only (e.g. "crypto", "rc4"). Location info goes in tree_path.
```

---

## Migrating from v2 (5-level confidence)

v3 adds tree structure support. Existing databases are auto-migrated on first connection (adds `tree_node_id` column and `tree_nodes` table).

Existing findings have `tree_node_id` = NULL — no impact on current functionality. You can populate tree associations later via `findings_update`.

### v1 (4-level) → v2 (5-level)

v2 splits `confirmed` into `confirmed-observed` and `confirmed-inferred`. Backward compatibility:
- `findings_search` with `confidence="confirmed"` matches confirmed-observed + confirmed-inferred
- `confidence="verified"` matches confirmed-observed + confirmed-inferred + disproved

---

## License

MIT
