# M3: Schema and Data Quality

Version **1.0.0**. Requires Python **3.11+**, with no third-party runtime dependencies.

This module classifies JSON security logs, selects or creates versioned parsers,
maps fields to an ECS subset, validates records, and separates failures into
quarantine. The default Schema Agent uses offline rules; an LLM is optional.

## Features

- Bundled parsers for Windows Security, Sysmon, and Zeek conn/DNS/HTTP JSON.
- UTC timestamps, required-field checks, IP/port validation, and raw input retention.
- An immutable parser registry with schema versions and definition hashes.
- Automatic candidate generation, bounded repair, validation, registration, and reuse.
- Decision logs, stable document IDs, ECS NDJSON exports, and Elasticsearch bulk files.

## Quick start

Run from `m3-schema`:

```powershell
python -m unittest discover -s tests -v
python -m tracehunt_schema schemas
.\run_demo.ps1
```

The demo creates a new directory under `output/` and exercises normalization,
quarantine, manual approval, automatic onboarding, and frozen parser reuse.
All fixtures are synthetic. The 61 tests run offline; model responses are mocked.

## Process logs

Normalize records using registered parsers:

```powershell
python -m tracehunt_schema normalize `
  --input fixtures/known-mixed.ndjson `
  --output output/known/accepted.jsonl `
  --quarantine output/known/quarantine.jsonl `
  --events-output output/known/events.ndjson
```

Select existing parsers or automatically create validated custom parsers:

```powershell
python -m tracehunt_schema onboard `
  --input fixtures/custom-unknown.ndjson `
  --output output/agent/accepted.jsonl `
  --quarantine output/agent/quarantine.jsonl `
  --audit output/agent/decisions.jsonl `
  --registry output/registry
```

The examples accept 5 and 2 records respectively. Onboarding creates one custom
parser; later runs reuse it. Known-format validation failures are quarantined
without generating replacement parsers.

| Command | Purpose |
|---|---|
| `normalize` | Apply registered parsers and validate records |
| `onboard` | Select or generate, validate, register, and apply parsers |
| `infer` | Save a candidate and validation report without activation |
| `approve` | Revalidate candidate samples and register the parser |
| `schemas` | List parsers or inspect an ID/version |

Use `python -m tracehunt_schema COMMAND --help` for arguments. Onboarding supports
`--review-only` (save candidates without activation) and `--frozen` (disable
generation). Unknown formats are quarantined in either mode. `normalize` can
pin a parser with `--schema-id` and `--schema-version`.

## Outputs and configuration

| Argument | Output |
|---|---|
| `--output` | Accepted result envelopes containing the ECS event and routing metadata |
| `--events-output` | Plain ECS event documents |
| `--bulk-output` | Elasticsearch bulk metadata/document pairs with stable `_id` values |
| `--quarantine` | Append-only failures with original input and structured errors |
| `--audit` | Onboarding decisions, candidates, attempts, and validation results |

Exports must use new file paths; choose a new run directory for repeated commands.
The quarantine file is created when failures occur. Bulk files are exports;
no Elasticsearch requests are sent.

Pass `--config config.example.json` to set the ECS version, source-to-index
routes, and an explicit timezone offset for timestamps without timezone data.
The default ECS label is `8.11.0`. Naive timestamps are rejected unless configured;
Sysmon's `UtcTime` is treated as UTC. Parser definitions and configuration must
remain unchanged for repeatable document IDs.

Exit codes: `0` = success; `2` = quarantined records or failed candidate validation;
`1` = command, configuration, file, or approval error.

## Optional model generator

For a configured Ollama service, add `--generator ollama --model MODEL_NAME`
to `onboard`. The endpoint defaults to `http://localhost:11434/api/chat` and can
be set with `--model-endpoint`. The model name and endpoint also support
`TRACEHUNT_SCHEMA_MODEL` and `TRACEHUNT_SCHEMA_MODEL_ENDPOINT`.
Only unregistered formats send samples to the selected endpoint.
Live-model generation has not been tested.

## Files description

- `tracehunt_schema/`: Python API, agent, parsers, and registry.
- `fixtures/` and `tests/`: synthetic examples and automated checks.
- `config.example.json`: timestamp and routing settings.
- `es/index-template.example.json`: mapping template for emitted fields; not installed automatically.
- [Interface reference](INTERFACE.md): implemented inputs, outputs, and Python APIs.

There is a problem that the module has not yet been validated against real-world data, and some parts of the code still require adjustment.

