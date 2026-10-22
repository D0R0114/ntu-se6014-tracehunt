# M3 Continuous Integration

The workflow is defined in [m3-schema.yml](../.github/workflows/m3-schema.yml).
It runs on pushes to `main` or `m3/**`, pull requests targeting `main`, and manual
dispatch after the workflow is available on the repository's default branch.

Each job runs the offline automated suite, field-mutation check, and M2 connector
replay on Windows and Ubuntu with Python 3.11 and 3.12. Replay uses PowerShell
and a temporary loopback TCP receiver. No third-party Python dependencies, live
model, or Elasticsearch service are needed. Mutation and connector checks still
run after a suite failure if Python setup succeeded. Non-zero check exits fail
the job.

From `m3-schema`, reproduce the checks with:

```powershell
python -m unittest discover -s tests -v
python tests/mutation_check.py
python tests/check_m2_integration.py
```

In GitHub, open **Actions > M3 schema checks** and select the relevant commit.
Logs and the mutation summary are retained as separate report artifacts for
each operating-system/Python combination for 14 days. Pull-request workflows
from forks may require maintainer approval.

The connector report records sample origins and SHA-256 hashes. Windows uses
the repository sample, Sysmon replays the repository sample with a simulated
event-log reader and metadata, and Zeek uses synthetic conn/DNS/HTTP fixtures.
The checks completed successfully in local verification. See
[connector validation](INTEGRATION.md) for the results and reproduction steps.
