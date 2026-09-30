# TraceHunt — SE6014 Group Project

Agentic threat hunting on the Elastic Stack (ELK). 6-week group project: a schema-aware agent ingests Windows Security EVTX, Sysmon (via Winlogbeat), and Zeek network logs into ELK, then runs a structured hunt workflow — hypothesis → coverage checklist → typed read-only MCP tool calls with an evidence ledger → verification → verdict (confirmed / rejected / inconclusive) — and finishes with a frozen two-run repeatability experiment.

## Roles

| Role | Module | Scope |
|------|--------|-------|
| M1 | ELK + integration | Docker Compose, index templates, access control |
| M2 | Connectors | Pull (EVTX drop folder), push (Sysmon/Winlogbeat), stream (Zeek) |
| M3 | Schema + data quality | Registry, parser selection/creation, ECS mapping, classifier, quarantine |
| M4 | MCP server + search tools | Tool schemas, input validation, evidence ledger (query, hash, doc IDs) |
| M5 | Hunt workflow | State machine, coverage checklist, verifier, verdict |
| M6 | Experiment + product | Ground truth manifest (M6-only), decoy traffic, two-run comparison, pitch |

Review pairs: M1↔M6, M2↔M3, M4↔M5 — every PR is reviewed by its pair.

## How we work

- **No direct pushes to `main`.** Every change goes through a pull request: it gets an author, a diff, and a timestamp automatically.
- **Branch naming:** `<role>/<short-topic>` — e.g. `m1/elk-setup`, `m2/sysmon-connector`, `m4/mcp-tools`.
- **One task = one issue**, assigned to its owner, labelled `M1`–`M6`, attached to a milestone. Acceptance criteria go in the issue body.
- **PR description must include `closes #<issue>`** so milestones update themselves.
- **Blocked?** Add the `blocked` label and say why in a comment — that's the early-warning signal, not a failure.

## Milestones

| Milestone | Gate |
|-----------|------|
| W1 — Design freeze | Architecture + role boundaries agreed |
| W2 — Ingestion baseline | All three sources landing in ELK |
| W3 — Schema + MCP core | Validated parsers + typed read-only tools + evidence ledger |
| W4 — Hunt workflow | Hypothesis → verdict runs end to end |
| W5 — Repeatability | Frozen two-run experiment with overlap metrics |
| W6 — Report + demo | Final deliverables |

## Repo layout

```
docs/          design notes, decisions, weekly updates
evidence/      hunt run artifacts (ledger exports, verdicts)
lab/           scenario files: benign logon, encoded PowerShell, HTTP beacon, decoys
m1-elk/        M1 work
m2-connectors/ M2 work
m3-schema/     M3 work
m4-mcp/        M4 work
m5-hunt/       M5 work
m6-experiment/ M6 work
```

## Ground truth policy

The lab scenario ground-truth manifest is held by **M6 only** and is not committed to this repo. Hunt verdicts are scored against it after the frozen runs complete.
