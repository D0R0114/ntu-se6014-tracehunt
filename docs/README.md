# TraceHunt project wiki

Last updated: 4 October 2026.

This folder is the versioned project wiki. The repository's GitHub Wiki feature is currently disabled, so durable project notes live under `docs/` and go through normal repository review history.

## Review workflow

- Members work in their own role branch or fork.
- All implementation changes arrive through pull requests.
- The project lead reviews member PRs before merge.
- `main` is the integration source of truth.
- A PR is not considered done until the relevant tests and integration checks pass.

## Current role status

| Role | Scope | Status |
|---|---|---|
| M1 | ELK stack, integration, index templates, access control | Baseline implementation is in `main`; additional M1 work may arrive through separate PRs |
| M2 | Windows EVTX, Sysmon, and Zeek connectors | No merged implementation yet |
| M3 | Schema agent, ECS mapping, parser registry, validation, quarantine | PR #7 is open for review |
| M4 | MCP server, typed read-only tools, validation, evidence ledger | **Merged to `main` via PR #2** |
| M5 | Hunt workflow state machine and verifier | No merged implementation yet |
| M6 | Ground truth, repeatability experiment, decoy traffic, final experiment | No merged implementation yet |

## M4 milestone

M4 was merged on 4 October 2026.

- Pull request: #2
- Merge commit: `5fac4b6d262a1cf97db1107a597c9e6465e49a4c`
- Issue #1 closed as completed
- Elasticsearch target aligned with M1: Elasticsearch 8.12.0
- Python client: `elasticsearch>=8.12,<9`
- GitHub Actions covers unit tests, seeded Elasticsearch integration tests, and a real MCP stdio smoke test

See [M4 status and interface](./M4.md) for the detailed contract that M5 and later integration work should use.

## Upcoming integration focus

1. Review M3 PR #7 and freeze the schema/interface contract.
2. Keep M4 tool contracts stable for M5.
3. Integrate M2 log ingestion with the M3 ECS mapping and M4 search layer.
4. Build the M5 hunt workflow against the merged M4 MCP interface.
5. Preserve evidence-ledger semantics for M6 repeatability experiments.
