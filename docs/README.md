# TraceHunt project wiki

Last updated: 4 October 2026.

This folder is the versioned project wiki. The repository's GitHub Wiki feature is currently disabled, so durable project notes live under `docs/` and go through normal repository history.

## Review workflow

- Members work in their own role branch or fork.
- All implementation changes arrive through pull requests.
- The project lead reviews member PRs before merge.
- `main` is the integration source of truth.
- A member PR must not be merged without the project lead's explicit instruction.
- A PR is not considered done until the relevant tests and integration checks pass.

## Current role status

| Role | Scope | Status |
|---|---|---|
| M1 | ELK stack, integration, index templates, access control | Replacement PR #12 is open. GitHub CI is green, but a VPS portability failure in `security-setup` means **do not merge yet**. |
| M2 | Windows EVTX, Sysmon, and Zeek connectors | No merged implementation yet. |
| M3 | Schema agent, ECS mapping, parser registry, validation, quarantine | PR #7 is open. Latest code is materially improved and independently test-verified; author still needs to sync with `main`, add CI, and later test real M2 connector output. **Do not merge yet.** |
| M4 | MCP server, typed read-only tools, validation, evidence ledger | **Merged to `main` via PR #2.** |
| M5 | Hunt workflow state machine and verifier | No merged implementation yet. |
| M6 | Ground truth, repeatability experiment, decoy traffic, final experiment | No merged implementation yet. |

## M3 review status

M3 PR #7 currently points to:

`44df901c85753d88b9072ef6c2ae48c2e8041b4c`

Independent verification on the VPS confirmed:

- 101/101 unit and regression tests passed.
- Mutation check: 4,830 pipeline mutations plus 4,830 frozen-agent mutations.
- Unexpected mutation failures: 0.
- A temporary merge simulation with current `main` and the M1 replacement kept the M3 tests and mutation checks green.
- M3's proposed Elasticsearch mapping is identical to the normalized production mapping currently used by the M1 replacement.
- Five known mixed M3 fixture records normalized successfully and bulk-indexed into the secured Elasticsearch mapping without mapping errors.

Remaining M3 work belongs to the M3 author:

1. Sync PR #7 with the latest `main`; it was 12 commits behind at the latest review.
2. Add GitHub Actions CI for the 101-test suite and mutation check.
3. Once M2 is ready, test against real connector output rather than only synthetic fixtures.

See [M3 review](./M3_REVIEW.md).

## M1 replacement status

M1 PR #12 is open at:

`dce673e50f5c862d73038306a65a2d04179d1eeb`

GitHub Actions passed the clean-stack integration flow, including Elasticsearch startup, security bootstrap, Logstash ingestion, M3-shaped indexing, M4 read access, and denied M4 write access.

However, an independent VPS portability run exposed a blocking difference: the `security-setup` container exited 0 without creating the expected roles, users, or templates. The observed container mount for `/setup/setup_security.sh` behaved as a directory rather than the intended file on that host. Because the security resources were absent, `tracehunt_ro` authentication failed with HTTP 401.

Therefore PR #12 is **not ready to merge** until that portability issue is fixed and the M3 -> M1 -> M4 end-to-end path is rerun successfully on the VPS.

See [M1 replacement review](./M1_REVIEW.md).

## M4 milestone

M4 was merged on 4 October 2026.

- Pull request: #2
- Merge commit: `5fac4b6d262a1cf97db1107a597c9e6465e49a4c`
- Issue #1 closed as completed
- Elasticsearch target aligned with M1: Elasticsearch 8.12.0
- Python client: `elasticsearch>=8.12,<9`
- GitHub Actions covers unit tests, seeded Elasticsearch integration tests, and a real MCP stdio smoke test

See [M4 status and interface](./M4.md).

## Current integration order

1. Keep M3 PR #7 review-only until its author syncs `main`, adds CI, and submits the updated result.
2. Do not merge M3 unless the project lead explicitly asks for it.
3. Fix the M1 `security-setup` portability failure.
4. Re-run M3 -> M1 -> M4 end to end on the VPS.
5. Merge M1 only after both GitHub CI and the independent VPS path are green.
6. Continue M2/M5/M6 integration without changing the frozen M3/M4 contracts silently.
