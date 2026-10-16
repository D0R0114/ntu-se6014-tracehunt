# Member 2 - Ingestion Connectors

M2 implements the three TraceHunt ingestion modes:

- Pull: Windows Security events
- Push: Sysmon events
- Stream: Zeek network logs

## Connectors

### Windows Security Pull

Location:

`windows-pull/windows_pull.ps1`

Supported input:

- `.evtx`
- `.ndjson`

The connector preserves the original input and emits an M3-compatible event structure.

Example:

```powershell
.\windows-pull\windows_pull.ps1
```

### Sysmon Push

Location:

`sysmon-push/sysmon_push.ps1`

The connector continuously reads Sysmon Event ID 1 records.

Features:

- Persistent RecordId checkpoint
- Processes all events newer than the checkpoint
- Advances the checkpoint only after a successful send
- Retry handling
- Rejected-record retention
- Prevents replay after restart

One-scan test:

```powershell
.\sysmon-push\sysmon_push.ps1 -Once
```

### Zeek Stream

Location:

`zeek-stream/zeek_stream.ps1`

The connector streams newline-delimited Zeek JSON logs.

Features:

- Persistent byte-offset checkpoints
- Incomplete-line protection
- File replacement/rotation detection using prefix SHA-256
- Malformed-record rejection without stopping later records
- Retry handling
- Raw-line preservation

One-scan test:

```powershell
.\zeek-stream\zeek_stream.ps1 -Once
```

## M3 Schema Compatibility

The M2 adapter is located at:

`common/m3_adapter.ps1`

Windows Security, Sysmon, and Zeek connector payloads were tested against the M3 SchemaPipeline from PR #7.

All three payload types were accepted:

- Windows Security: `accepted`
- Sysmon: `accepted`
- Zeek: `accepted`

The normalized M3 results included expected hunt fields such as:

- `host.name`
- `user.name`
- `process.executable`
- `process.command_line`
- `source.ip`
- `destination.ip`

## Regression Tests

Run locally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\run_tests.ps1
```

Expected result:

```text
Passed: 7
Failed: 0
```

GitHub Actions runs the M2 regression tests on Windows and Ubuntu.

## Runtime State

Runtime state and rejected records are not committed.

Ignored directories include:

- `sysmon-push/state/`
- `sysmon-push/rejected/`
- `zeek-stream/state/`
- `zeek-stream/rejected/`
- `zeek-stream/input/`