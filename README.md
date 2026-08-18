# Findings MCP Server (knowledge-mcp)

[![Docker Pulls](https://img.shields.io/docker/pulls/gfishx/findings-mcp)](https://hub.docker.com/r/gfishx/findings-mcp)

> Lightweight agent reasoning findings store — confidence labeling, reasoning chains, cascade invalidation, conflict detection.
> Dual-dimensional organization: **DAG** (reasoning chain) + **Tree** (project structure).
> Designed for CTF reverse engineering multi-agent workflows: separates observation from inference, prevents hallucination cascade.
> v1.1 adds supervision (audit/freeze), situation state, directive backlog, conflict storage, snapshots & artifact evidence — **37 MCP tools** in total.

[中文文档 / Chinese docs](README_CN.md) — full documentation (Chinese)

---


## Design Philosophy

Not a memory system, not a knowledge graph, not vector search. Just fact storage with confidence labels.

The agent records one finding per reasoning step. Core values:
- **Separate observation from inference**: confirmed-observed (raw tool output) ≠ confirmed-inferred (cross-validated conclusion)
- **Traceable reasoning chains**: invalidate one node, all downstream auto-expire
- **Evidence never lost**: original tool output survives conclusion overturns (v1.1: `artifact://` URIs reference full tool outputs)
- **Role-based authority**: sub-agents can mark confirmed-observed / likely, but never confirmed-inferred / speculative

### Responsibility Boundary: MCP = Storage Layer, Agent = Judgment Layer

The core v1.1 architectural principle:

| Layer | Responsibility | Example |
|-------|----------------|---------|
| **MCP (storage)** | Structural validation, state storage, query primitives | Write gate checks *format* (role, type, cross-validation markers), never semantics |
| **Agent (judgment)** | Semantic judgment, cross-validation, conflict adjudication | "Who is right" is decided by detection/adjudication sub-agents; tools only record the conclusion |

The server never pretends to understand semantics: `conflict_report` validates field legality only; `findings_store` checks type/based_on structure only.

### Dual-Dimensional Organization: DAG + Tree

Each finding participates in two orthogonal structures:

| Dimension | Meaning | Question | Implementation |
|-----------|---------|----------|----------------|
| **DAG (reasoning chain)** | Derivation dependencies ("A implies B") | **How was this derived?** | `based_on` field |
| **Tree (structure)** | Project/file/function location | **Where was this found?** | `tree_nodes` table + `tree_node_id` |

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

## Write Gate (v1.1 role authority)

`findings_store` / `findings_update` run 5-layer structural validation before writing:

1. **Role authority** — `role:xxx` in `source`. Sub-agents (discovery/detector/judge/analyst/leaf) may NOT mark `confirmed-inferred`/`speculative`; `role=parent` allowed; **missing/unparseable role → rejected** (strict by default). confirmed-observed/likely/disproved are never role-gated.
2. **Type validation** — `claim` requires non-empty `based_on` pointing to an existing `observation`; `hypothesis` fact must contain `test_plan:`; `task` requires `task_budget` (budget_tool_calls/budget_tokens/budget_seconds); non-enum type rejected.
3. **Cross-validation markers** — `confirmed-inferred` evidence must contain ≥2 distinct `agent:<id>` markers.
4. **Structure only, never semantics** — semantic matching belongs to detection sub-agents.
5. **Project binding (batch2 #1)** — after the parent agent activates a project (via `situation_update` / `directive_create`), sub-agent `findings_store` writes to any other project are rejected with `write_gate_violation`. Fail-open when no project is active (backward compatible); `role=parent` and unparseable roles are exempt. Active project is stored in the global `_app_state.db` (not per-project DBs).

Failure: `{"error": "write_gate_violation: <reason> | suggestion: <suggestion>"}`.
The update gate validates only ① + ③, and only when explicitly raising to a gated confidence (adding evidence/tags never misfires).

---

## MCP Tools (37)

### Group Overview

| Group | Tools | Purpose |
|-------|-------|---------|
| **Core 9** | findings_store / search / get / update / delete + tree_store / get / search / delete | Evidence storage, search, tree structure |
| **G1 Supervision 6** | audit_violation / list / stats + freeze_status / trigger / release | Violation audit + freeze state machine |
| **G2 Situation 6** | situation_get / update / report + tree_mark / unmark / render | Situation object + tree markers + tree rendering |
| **G3 Command 6** | directive_create / list / update / repeat / parse + preflight_check | User directive backlog + pre-delegation check |
| **G4 Conflict 6** | conflict_report / list / update / stats + verification_check / report | Conflict state machine + regression sampling |
| **G5 Snapshot 4** | findings_snapshot / project_list / artifact_store / get | Role-trimmed snapshots + artifact evidence store |

### Core 9

- **findings_store** — store a finding. v1.1 params: `type` (observation|claim|hypothesis|task, default claim; task writes task_meta), `evidence_uri` (artifact:// URI), `tree_path` (auto-creates tree nodes). Auto conflict detection for confirmed-observed/confirmed-inferred/disproved (`_conflicts` in response).
- **findings_search** — text match on fact/evidence; confidence shortcuts `verified` / `confirmed` / exact; v1.1 param `use_fts` (FTS5 full-text, auto-fallback to LIKE). Multi-condition AND, newest first.
- **findings_get** — full entry + `dependent_count`.
- **findings_update** — v1.1 param `evidence_uri` (won't overwrite when omitted). Marking `disproved` cascades: dependents → speculative + `invalidated` tag, recursive.
- **findings_delete** — delete a single finding; returns `{deleted_id, orphaned_dependents}`. Dependents' `based_on` auto-NULL (FK ON DELETE SET NULL), `task_meta` rows cleaned, FTS index synced. Irreversible; missing target is rejected.
- **tree_store** — create/update node (`path` with `>` levels, `node_type`, optional `parent_path`), auto-creates missing intermediates.
- **tree_get** — node info + children + attached findings + parent summary; `markers` as parsed list.
- **tree_search** — filter by name / node_type / parent_id.
- **tree_delete** — cascade-delete children; attached findings preserved (tree_node_id → NULL).

### G1 Supervision (audit + freeze)

- **audit_violation** — log a violation (rule_id R1-R5: R1 no search before delegation / R2 same hypothesis failed ≥2 / R3 report without confidence / R4 context without verification / R5 freeze triggered).
- **audit_list / audit_stats** — list (desc) / per-rule counts + recent 5.
- **freeze_status** — frozen=true when: explicit freeze, violations ≥3, unresolved directives ≥3, repeated directives ≥2; returns reason list + counts.
- **freeze_trigger** — explicit freeze (writes situations.frozen + auto R5 audit).
- **freeze_release** — clears explicit freeze only (auto freezes resolve via counts).

### G2 Situation (situation object + tree markers + render)

- **situation_get** — situation object (objective/project_meta/progress/active_work/conflict_queue/candidate_directions/risks/timeline/version/frozen); default empty object (project_meta={}) when absent, no auto-insert.
- **situation_update** — version+1 each write; timeline_event append; candidate_directions require evidence_strength ∈ {high,mid,low}; `project_meta` is slow-changing metadata (convention `{workdir, repo, engine, api, background}`), whole-object overwrite, preserved when omitted. **batch2 #6**: `progress_append` / `candidate_directions_append` append to the existing list (empty list = no-op; if passed alongside the overwrite form, overwrite-then-append). Side effect: activates/switches the active project (see Write Gate ⑤).
- **situation_report** — user-facing push text (📊/✅/🔄/⚠️/🎯/📌 rows).
- **tree_mark / tree_unmark** — add/remove node markers (conflict/active/disproved/candidate/directive/unverified).
- **tree_render** — indented tree view, depth-first numbering (1, 1.1, 1.1.1), findings share numbering with children; icons for markers + confidence (disproved=❌, speculative=🔒); truncates >~6000 chars with drill-down hint.

### G3 Command (directive backlog + deterministic parser + preflight)

- **directive_create** — create directive todo; type inferred by deterministic parser (stop>redirect>verify>question, rules only, no LLM) when omitted; type=info → skipped (not stored); id D-XXXX per project.
- **directive_list** — backlog oldest-first; status supports negation (`"!resolved"`).
- **directive_update** — status progression (received/acknowledged/in_progress/resolved/needs_clarify); resolved auto-stamps resolved_at.
- **directive_repeat** — repeat_count+1; ≥2 → freeze_hint=true + forced-stop message.
- **directive_parse** — pure parse, no persistence; node X.Y reference → verify + anchor; empty text → redirect fallback.
- **preflight_check** — **the only mandatory call before every delegation**: {freeze, unresolved_directives, situation_summary}; non-empty unresolved → handle first.

### G4 Conflict (state machine + regression primitives)

- **conflict_report** — detection sub-agent reports conflict (conflict_type 1数值|2因果|3前提|4指令|5原始数据, party_a_*/party_b_*, reporter); optional tree_node_id adds conflict marker; server validates fields only, never judges.
- **conflict_list / conflict_stats** — queue (oldest-first, status filter) / counts by status + type.
- **conflict_update** — adjudication (pending→under_review→adjudicated/resolved_by_rerun, jumps allowed); terminal states require strategy (rerun_tool|cross_tool|dynamic_trace|judge|debate|human) + resolution; resolution containing "disproved" auto-marks party_a disproved (cascade).
- **verification_check** — random sample N (cap 20) findings by confidence for re-run comparison; command_hint extracted from `tool:xxx`.
- **verification_report** — write-back: verified=true → append `regression_verified` tag; false → mismatches only (use conflict_report for formal conflict).

### G5 Snapshot + Artifact

- **findings_snapshot** — role-trimmed snapshot: discovery (id+fact+confidence+type, anti-anchoring), detector (full), judge (+evidence_uri), analyst (+based_on expansion as based_on_fact). Response also carries `project_meta` (from the situation object, `{}` when absent) for delegation templates.
- **project_list** — all projects + findings_count/tree_nodes_count/updated_at.
- **artifact_store** — persist raw tool output to DB_DIR/artifacts/<project>/<sha1>.txt, returns `artifact://` URI; >512KB truncated.
- **artifact_get** — fetch raw output by URI (for adjudication).

---

## artifact:// URIs

```
artifact://tool_output/<project>/<sha1>.txt
```

Generated by `artifact_store` (sha1 = first 16 hex of output SHA1); attached via `evidence_uri` on findings_store/update; fetched with `artifact_get`. Purpose: keep `evidence` as a short summary (≤500 chars), full outputs live as artifacts — evidence survives truncation.

---

## Storage

```
~/.hermes/findings/               # Override with FINDINGS_DB_DIR env
├── <project>.db                  # One SQLite file per project
└── artifacts/<project>/<sha1>.txt
```

Per-project tables: `knowledge` (findings, incl. type/evidence_uri), `tree_nodes`, plus v1.1-new `situations` (incl. `project_meta_json`) / `directives` / `conflicts` / `audit_log` / `task_meta` / `knowledge_fts` (FTS5). All auto-created on first connection.

---

## Deployment

### Direct

```bash
pip install "mcp>=1.20,<2.0"     # server.py uses mcp 1.x API
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

## Write Gate (server-enforced, comply proactively)

- claim must be based on an observation: based_on = an observation-type finding ID
- hypothesis fact must contain a test_plan: section
- task must carry task_budget (budget_tool_calls/budget_tokens/budget_seconds)
- confirmed-inferred evidence must contain two distinct agent:<id> cross-validation markers
- annotate source with role: agent:<id>|role:<role>|tool:<tool>

## Tree Structure Usage

Prefer passing tree_path when calling findings_store to link findings to project structure:
- Path format: ">"-separated hierarchy, e.g. "challenge.exe>sub_4012a0>loop_body"
- Leaf node defaults to "function", intermediates auto-created as "section"
- Filter by tree_node_id in findings_search; browse with tree_render (global) and tree_get (drill-down)
- Node markers via tree_mark: conflict/active/disproved/candidate/directive/unverified

## Snapshot / Conflict / Directive

- Run preflight_check before every delegation (freeze/unresolved directives/situation summary);
  if frozen or backlog non-empty, handle first
- Conflicting conclusions → conflict_report (server never judges; adjudication belongs to the adjudication sub-agent)
- User directives → directive_create, then directive_update on completion
- Persist raw tool output with artifact_store first, then reference the artifact:// URI via evidence_uri
- Periodically regression-sample with verification_check + verification_report

Keep tags for semantic labels only (e.g. "crypto", "rc4"). Location info goes in tree_path.
```

---

## Migrating from v3 to v1.1

v1.1 adds supervision/situation/command/conflict/snapshot tool groups and 6 new tables (situations/directives/conflicts/audit_log/task_meta/knowledge_fts).

**Migration is fully automatic — no manual steps.** On first connection `_migrate_schema` runs: column-level migrations on `knowledge` (type/evidence_uri/invalidation_reason) and `tree_nodes` (status/markers_json); new tables via CREATE TABLE IF NOT EXISTS; FTS5 index auto-built. Zero data loss, fully backward compatible:
- `findings_search` `confidence="confirmed"` matches confirmed-observed + confirmed-inferred (v2 split compatibility)
- `confidence="verified"` matches confirmed-observed + confirmed-inferred + disproved
- Legacy findings keep `tree_node_id` = NULL; attach tree links later via findings_update

---

## License

MIT
