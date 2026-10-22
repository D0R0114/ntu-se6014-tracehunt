# M3 v1.0.0 Review Updates

Compared with the original pull request containing 61 offline automated tests,
this revision corrects field semantics, strengthens validation, and keeps
malformed records from interrupting unrelated records.

## Follow-up review: 23 October 2026

- Fixed the guarded Sysmon signature to include `process_name` and `command_line`
  when native `UtcTime` or `ProcessGuid` provenance is present. Generic aliases
  and event numbers alone still do not establish the source.
- Valid alias records reuse the bundled parser and retain available executable,
  command-line, and process entity ID fields. Directory-only paths and missing
  creation-event executables stay on the Sysmon quarantine path, with no custom
  parser generation.
- Added eight regression tests covering flat, nested, dotted, and mixed native
  provenance, independent alias detection, mixed batches, and frozen reuse.
  The bundled parser definitions and versions are unchanged.

Current verification: **130 automated tests passed**, with no skips. Both
**4,968-case** mutation checks completed without unexpected failures. The full
demo and connector replay passed, accepting **20 Windows**, **1 Sysmon**, and
**3 Zeek** records.

## Follow-up review: 22 October 2026

- Removed event-number and generic process/logon heuristics that could claim
  custom records as Windows Security or Sysmon. Explicit hints, recognized
  connector `source_type`, established metadata, and distinctive native fields
  still select the bundled parsers, including for malformed known records.
- Provider/channel matching uses recognized names; dataset prefixes respect
  namespace boundaries. Lookalikes such as `sysmonish.events` stay unclassified.
- Added the custom `event_id` alias to candidate mapping, preserving event codes
  during onboarding. Ambiguous aliases still require explicit review.
- Added the three reported lookalikes as a fixture, with API/CLI onboarding,
  frozen reuse, provenance, and known-parser quarantine regression coverage.
- Added explicit datasets to generic legacy fixtures and tests so they declare
  their source instead of depending on event-number guesses.
- Added bounded connector replay and caller-supplied capture validation, with
  payload/result artifacts, input hashes, repeated-output checks, and quarantine
  probes. The CI matrix now runs connector replay and uploads its reports.

Verification at that review: **122 automated tests passed**, plus **4,968 pipeline**
and **4,968 frozen-agent** field variations without unexpected failures. The
mutation count increased because the fixtures now contain provenance fields.
Connector replay accepted **20 Windows**, **1 Sysmon**, and **3 Zeek** records.
The current review fixes and local verification are complete. Reproducible
connector results are documented in [INTEGRATION.md](INTEGRATION.md).

## Changes

| Area | Before | After |
|---|---|---|
| Zeek HTTP Host | Bare `host` could populate the computer name | HTTP Host supplies `url.domain`; its port is removed and IPv6 brackets are retained. Computer metadata uses explicit `host.name`. Invalid authorities are quarantined. |
| Empty identifiers and paths | Whitespace-only usernames and executable paths could be accepted | Empty keyword values are rejected. Executable paths must contain a filename; internal spaces remain valid. |
| Windows event codes | Leading zeros could bypass logon/process requirements | Windows Security and Sysmon codes become canonical decimal strings. Account and executable requirements apply after canonicalization. |
| Numeric fields | Integers above the output mapping's range could be accepted | Integer fields use the non-negative signed 64-bit range; ports retain the 0-65535 range. |
| Source classification | Flat Sysmon aliases were missed; damaged known records could enter custom onboarding | Flat and mixed-field Sysmon records are detected. Distinctive source fields retain known validation paths, and malformed source metadata is rejected during automatic classification. |
| Field representation | Some mixtures of dotted keys and nested objects were not resolved; conflicting values could be silently selected | Mixed paths are resolved. Equal representations share a signature; conflicting values are quarantined. ECS host objects no longer hide a valid flat `Computer` alias. |
| Batch resilience | Some encoding, depth, Unicode, or Python API errors could stop a batch | Invalid records are isolated, and later valid records continue. Invalid UTF-8 lines retain original bytes in `raw_bytes_base64`; invalid API values have serializable failure representations. |
| Registry and model errors | Duplicate keys, unsafe parser metadata, numeric version errors, or registration conflicts had incomplete handling | Registry/configuration readers reject duplicate keys and accept UTF-8 BOMs. Definitions are checked before registration. Registration conflicts isolate the affected group; deeply nested model responses follow bounded failure handling. |
| Output files | Path checks missed file aliases and some configuration/registry collisions | Outputs cannot modify input, configuration, or parser definitions, including through hard links. Outputs must stay outside parser registry directories. |

## Earlier review validation

- Original tests: 61; added regression tests in the earlier review: 40;
  total at that review: **101 passed**.
- Mutation checks: **4,830 variations** through the pipeline and another 4,830
  through the frozen agent, with **zero unexpected failures**. These check
  resilience and serialization, rather than semantic correctness of every variant.
- Full offline demo: passed, including normalization, quarantine, candidate
  generation, approval, automatic registration, and frozen parser reuse.

Run from `m3-schema`:

```powershell
python -m unittest discover -s tests -v
python tests/mutation_check.py
python tests/check_m2_integration.py
.\run_demo.ps1
```

Generated verification artifacts remain under `output/`, which is excluded from
Git. The original fixtures are synthetic and model responses are mocked.
The follow-up connector replay uses the documented repository samples and
fixtures. All checks listed in this report completed successfully.
