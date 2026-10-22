# Connector Validation

Connector replay validation is complete. All checks passed locally on
22 October 2026 with Windows and Python 3.12. The same replay is included in
the Windows/Ubuntu × Python 3.11/3.12 CI matrix.

## Reproduce

Run from `m3-schema` with Python 3.11+ and PowerShell (`pwsh` preferred):

```powershell
python tests/check_m2_integration.py
```

The runner copies the unmodified connector scripts into a temporary directory,
captures their TCP output on `127.0.0.1` at an ephemeral port, and processes the
payloads through M3 without source hints. It does not contact shared Logstash,
change connector state in the repository, or write to Elasticsearch.

Outputs go to a new `output/m2-integration/` directory. For another run, choose
a new directory with `--output output/m2-integration-next`.

## Data and results

| Source | Input and execution | Result |
|---|---|---|
| Windows Security | The 20-record repository sample passes through the actual NDJSON pull connector and adapter. Its README identifies Windows Security Event Log as the source. | 20 accepted, 0 quarantined |
| Sysmon | The repository process sample passes through the actual push connector and adapter. `Get-WinEvent`, RecordId, provider, and the `M3-REPLAY-HOST` computer metadata are simulated. | 1 accepted, 0 quarantined |
| Zeek | Synthetic conn/DNS/HTTP fixtures pass through the actual stream connector and adapter. | 3 accepted, 0 quarantined |

Each source also passes checks for parser selection, index routing, retained
TCP payload text, normalized scenario fields, identical frozen-agent results,
and stable document IDs. A separately corrupted record is quarantined between
two accepted records without generating a replacement parser.

`report.json` contains the completed checks, results, and SHA-256 hashes of replay
scripts and samples. The directory also contains TCP payloads, accepted ECS
results, quarantine probes, and connector logs. Generated artifacts are ignored
by Git and uploaded by CI.

## Supplied connector captures

To validate additional connector output, place UTF-8 NDJSON payloads in a
directory using these names:

- `windows-security.ndjson`
- `sysmon.ndjson`
- `zeek.ndjson`

Then run:

```powershell
python tests/check_m2_integration.py --capture-dir PATH_TO_CAPTURES --output output/capture-check
```

This mode validates the supplied payloads directly without replaying or changing
their metadata. The report records input hashes and the checks completed.
