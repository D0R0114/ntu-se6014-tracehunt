# M1 replacement PR #12 review

Last updated: 4 October 2026.

## Scope

PR #12: `M1: clean rebuild of secured ELK integration`

Current reviewed head:

`dce673e50f5c862d73038306a65a2d04179d1eeb`

## GitHub CI evidence

The replacement passed GitHub Actions on the current head.

Pull-request run: `37204742115`

The integration job passed:

- static JSON, shell, and Compose validation
- Elasticsearch 8.12 startup
- one-shot security bootstrap
- Logstash pipeline readiness
- Kibana reachability
- synthetic raw Logstash ingestion
- M3-shaped normalized event indexing
- M4 read-only retrieval
- negative write test for the M4 read-only account
- clean stack shutdown

The end-to-end log finished with:

```text
[SUCCESS] TraceHunt M1 ELK integration checks passed.
```

## Independent VPS portability finding

A later VPS integration review found a portability blocker that did not appear on the GitHub-hosted runner.

Observed host:

- Docker 29.6.1
- Docker Compose v5.3.1

The `security-setup` service exited with code 0, but produced no setup logs and created none of the required Elasticsearch resources.

Independent checks returned HTTP 404 for:

- `_security/role/tracehunt_logstash_writer`
- `_security/role/tracehunt_mcp_readonly`
- `_security/user/logstash_writer`
- `_security/user/tracehunt_ro`
- `_index_template/tracehunt_normalized`

A container inspection showed the expected host bind-mount source:

`m1-elk/setup_security.sh -> /setup/setup_security.sh`

but copying the target back from the container showed `/setup/setup_security.sh` behaving as a directory rather than the expected script file.

This means the one-shot bootstrap did not actually run on that host even though the container exit code was 0.

## M3 compatibility evidence

Before the M4 credential check, M3's real bulk export path was exercised against the running M1 Elasticsearch mapping.

M3 normalized five fixture records:

```json
{"accepted":5,"processed":5,"quarantined":0}
```

The generated bulk request was accepted with no Elasticsearch mapping errors.

Therefore the M3-to-M1 field contract is compatible. The later HTTP 401 for `tracehunt_ro` was caused by the absent M1 security user on the VPS, not by M3.

## Current verdict

**Do not merge PR #12 yet.**

GitHub CI is green, but the independent VPS portability failure is a real blocker.

Required next steps:

1. fix the `security-setup` file-mount/bootstrap behavior so failure cannot silently exit 0;
2. verify the required Elasticsearch roles, users, and templates exist after bootstrap;
3. rerun M3 -> M1 -> M4 on the VPS;
4. require successful M4 read access and denied M4 write access;
5. only merge after both GitHub CI and the independent VPS path are green.
