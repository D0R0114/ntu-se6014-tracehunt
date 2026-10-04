# Mnemosyne sync payload

source: tracehunt_project_progress_20261004_2034  
scope: global  
importance: 0.99  
updated_at: 2026-10-04T20:34:00+07:00

## Durable memory

Project: SE6014 Security Monitoring, TraceHunt.

Repository: `sodiptabadiabanurea/ntu-se6014-tracehunt`.

The user owns M4 and is the final reviewer/gatekeeper for member pull requests. Member PRs must not be merged unless the user explicitly instructs it. In particular, M3 PR #7 is currently review-only; do not modify or merge the M3 member's branch unless the user later asks or the member requests help.

M4 remains merged in `main` through PR #2 at merge commit `5fac4b6d262a1cf97db1107a597c9e6465e49a4c`.

### M3 latest review

M3 PR #7 head reviewed: `44df901c85753d88b9072ef6c2ae48c2e8041b4c`.

The latest M3 code is materially improved and does not need a rewrite.

Independent VPS evidence:

- run `37205262630`: 101/101 unit and regression tests passed in 3.423 seconds.
- run `37205334790`: 4,830 pipeline mutations plus 4,830 agent mutations, zero unexpected failures.
- run `37205417843`: temporary current-main + M3 + M1 replacement merge simulation passed the 101 tests, mutation checks, and M1 Compose config.
- M3 `template.mappings` is identical to the M1 replacement normalized Elasticsearch mapping.
- M3 normalized five known mixed fixture records with 5 accepted, 0 quarantined.
- the M3 bulk export indexed successfully into the M1 Elasticsearch normalized mapping with no bulk mapping errors.

Remaining M3 work must be done by the M3 author unless the user explicitly requests assistance:

- sync PR #7 with latest `main`; at the latest review it was 12 commits behind.
- add GitHub Actions CI for the 101-test suite.
- add CI for `tests/mutation_check.py`.
- rerun the CI after sync.
- when M2 exists, test M3 against real connector output.

Do not merge M3 yet.

### M1 replacement status

M1 replacement PR #12 is open at head `dce673e50f5c862d73038306a65a2d04179d1eeb`.

GitHub Actions pull-request run `37204742115` passed the clean-stack integration path, including raw Logstash ingestion, M3-shaped indexing, M4 read access, and denied M4 write access.

However, an independent VPS run found a portability blocker. On Docker 29.6.1 / Docker Compose v5.3.1, the `security-setup` service exited 0 without creating its Elasticsearch roles, users, or templates. The expected `/setup/setup_security.sh` bind-mount target behaved as a directory rather than the expected file in that container. The following resources were absent with HTTP 404: `tracehunt_logstash_writer` role, `tracehunt_mcp_readonly` role, `logstash_writer` user, `tracehunt_ro` user, and the normalized index template.

Because `tracehunt_ro` was not created, the M3 -> M1 -> M4 integration check later received HTTP 401. This is an M1 portability problem, not an M3 failure.

Therefore M1 PR #12 is not ready to merge despite green GitHub CI.

Required M1 next steps:

- make the security bootstrap portable and fail closed instead of silently exiting 0;
- assert the roles/users/templates exist after bootstrap;
- rerun M3 -> M1 -> M4 on the VPS;
- require successful M4 read access and denied write access;
- merge only after GitHub CI and VPS integration are both green.

### Wiki

The repository's GitHub Wiki feature is disabled. Durable project notes live under `docs/`.

Current wiki pages include:

- `docs/README.md`
- `docs/M4.md`
- `docs/M3_REVIEW.md`
- `docs/M1_REVIEW.md`
- `docs/MNEMOSYNE_SYNC.md`

When Claude Code or another agent recalls TraceHunt, GitHub remains authoritative for live branch/PR state. Mnemosyne stores durable project context, review decisions, and validated evidence.
