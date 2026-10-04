# Mnemosyne sync payload

source: tracehunt_m4_progress_20261004  
scope: global  
importance: 0.98  
updated_at: 2026-10-04T18:27:00+07:00

## Durable memory

Project: SE6014 Security Monitoring, TraceHunt.

Repository: `sodiptabadiabanurea/ntu-se6014-tracehunt`.

The user owns role M4 and is also the final PR reviewer/gatekeeper for the TraceHunt repository. Team members work through role branches or forks, open pull requests, and the user reviews member PRs before merge. Do not merge member PRs without the user's explicit instruction.

M4 owns the MCP server, typed read-only search tools, input validation, Elasticsearch read-only access, and the evidence ledger.

M4 PR #2, titled `[M4] MCP server with typed read-only tools and evidence ledger`, was reviewed, hardened, and merged into `main` on 4 October 2026.

M4 merge commit: `5fac4b6d262a1cf97db1107a597c9e6465e49a4c`.

Issue #1 was closed as completed after the merge.

The merged M4 module exposes seven tools:
1. `list_data_sources`
2. `get_time_bounds`
3. `search_events`
4. `aggregate_events`
5. `run_sequence_query`
6. `fetch_evidence`
7. `get_query_history`

Important M4 correctness decisions:
- Invalid, rejected, and backend-failed calls are recorded in the evidence ledger.
- Ledger entries use stable 64-character SHA-256 query hashes.
- Successful searches store exact Elasticsearch read requests and returned document IDs.
- `run_sequence_query` enforces strictly increasing event timestamps; simple set intersection is not sufficient.
- Sequence matches return timestamps and document IDs that prove the ordered chain.
- Incomplete sequence scans report `complete: false` so absence of a match is not treated as proof when the scan was truncated or required fields were missing.
- `date_histogram` respects the requested field.
- evidence document-ID limits follow `TRACEHUNT_MAX_DOC_IDS`.
- aggregation truncation is surfaced explicitly.
- field validation rejects wildcard/raw-DSL-style input.
- ECS-style fields used by M3, including `event.code`, `host.name`, `user.name`, `source.ip`, `destination.ip`, and `process.command_line`, are covered by regression tests.

Compatibility decision:
- M1 shared stack: Elasticsearch 8.12.0.
- M4 dev stack: Elasticsearch 8.12.0.
- M4 Python client: `elasticsearch>=8.12,<9`.
- Do not move M4 to a different Elasticsearch major independently of M1.

Final M4 verification before merge:
- unit tests passed
- Elasticsearch 8.12 dev stack booted successfully
- seeded lab dataset loaded successfully
- Elasticsearch integration tests passed
- real MCP stdio smoke test passed
- all seven MCP tools were advertised and exercised
- invalid-input rejection was exercised
- final smoke output: `SMOKE TEST PASSED`

M5 should treat `m4-mcp/tracehunt_mcp/validation.py`, `m4-mcp/tracehunt_mcp/tools.py`, `m4-mcp/README.md`, and the evidence-ledger format as stable M4 interface contracts. Incompatible changes should go through a reviewed PR.

The repository GitHub Wiki feature is disabled. The versioned project wiki now lives under `docs/`. Wiki update PR #10 was merged after M4, creating `docs/README.md` and `docs/M4.md`.

Wiki merge commit: `12ecfaf9f84b2c1ad141d3de98c7ff286eae5872`.

As of 4 October 2026, M3 PR #7 is still open for review. M1 also has newer work arriving through separate PRs. M2, M5, and M6 do not yet have merged implementations.

When Claude Code or another agent recalls TraceHunt, use this memory together with the current GitHub state. GitHub is authoritative for live PR/branch status; this Mnemosyne entry is the durable project context and M4 contract.
