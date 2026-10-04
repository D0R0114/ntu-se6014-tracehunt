# M4: TraceHunt MCP server

Member 4 owns the read-only MCP boundary between the hunt workflow and Elasticsearch. The module exposes typed tools for source discovery, search, aggregation, ordered sequence checks, evidence retrieval, and query history.

## Tools

| Tool | Purpose |
|---|---|
| `list_data_sources` | Show allowlisted indices, availability, and counts |
| `get_time_bounds` | Return earliest/latest `@timestamp` for one index |
| `search_events` | Run a bounded search with typed filters |
| `aggregate_events` | Run terms or date-histogram aggregation |
| `run_sequence_query` | Prove a strictly time-ordered sequence for the same entity |
| `fetch_evidence` | Fetch full documents by returned document ID |
| `get_query_history` | Show the evidence-ledger audit trail for the current run |

## Guardrails

- Only concrete indices in `TRACEHUNT_INDICES` are accepted.
- Time windows, result sizes, sequence scans, evidence IDs, and aggregation buckets are bounded.
- Filters are typed `{field, op, value}` objects. Supported operations are `eq`, `match`, and `exists`; raw Elasticsearch DSL is not accepted.
- Field names are validated and wildcard field names such as `*` are rejected.
- The MCP backend exposes only read operations.
- `es/readonly_role.json` grants only `read` and `view_index_metadata` on the hunt indices.
- Successful calls record the exact Elasticsearch read request in the evidence ledger.
- Rejected and failed calls are also recorded with `status: "error"`, the attempted typed input, error text, and a stable SHA-256 query hash.
- `run_sequence_query` requires strictly increasing timestamps. Merely finding an entity in every step is not treated as a sequence.
- Sequence matches include the document IDs and timestamps used to prove the order.
- If a sequence scan is incomplete because of the configured scan cap or missing entity/timestamp fields, the response returns `complete: false`; absence of a match must not be treated as proof.

## M3 field compatibility

Unit regression tests cover ECS-style paths emitted by the M3 schema interface, including `event.code`, `host.name`, `user.name`, `source.ip`, `destination.ip`, and `process.command_line`. The seeded development stack keeps the original lab fixture for stable end-to-end smoke testing.

## Elasticsearch compatibility

M1's shared stack on `main` currently uses Elasticsearch 8.12.0. M4 is aligned with it:

- dev container: Elasticsearch `8.12.0`
- Python client: `elasticsearch>=8.12,<9`

Do not move M4 to another Elasticsearch client major independently of M1.

## Quick start

```bash
cd m4-mcp
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest tests/

docker compose -f dev/docker-compose.yml up -d
python dev/seed_lab.py http://127.0.0.1:19200
TRACEHUNT_IT=1 TRACEHUNT_ES_URL=http://127.0.0.1:19200 \
  python -m pytest tests/test_integration.py
TRACEHUNT_ES_URL=http://127.0.0.1:19200 python dev/smoke_stdio.py
```

The GitHub workflow `.github/workflows/m4-tests.yml` runs the unit suite, starts Elasticsearch 8.12, seeds the lab dataset, runs the real integration tests, and executes the MCP stdio smoke test.

## Configuration

| Variable | Default |
|---|---|
| `TRACEHUNT_ES_URL` | `http://localhost:9200` |
| `TRACEHUNT_INDICES` | `windows-security,sysmon,zeek` |
| `TRACEHUNT_LEDGER_PATH` | `evidence/ledger.jsonl` |
| `TRACEHUNT_RUN_ID` | generated |
| `TRACEHUNT_DEFAULT_SIZE` | `50` |
| `TRACEHUNT_MAX_SIZE` | `500` |
| `TRACEHUNT_MAX_WINDOW_HOURS` | `72` |
| `TRACEHUNT_REQUEST_TIMEOUT_S` | `10` |
| `TRACEHUNT_MAX_SCAN` | `2000` |
| `TRACEHUNT_MAX_DOC_IDS` | `50` |
| `TRACEHUNT_MAX_SEQ_STEPS` | `5` |
| `TRACEHUNT_MAX_AGG_BUCKETS` | `100` |

## Evidence ledger

Each call appends one JSON object. A successful search stores the exact read request, stable query hash, result count, and returned document IDs. Failed calls store the attempted input and error. Ledger rows are flushed and fsynced; do not edit them by hand.

Use one stable `TRACEHUNT_RUN_ID` per frozen hunt run so M5 can cite evidence and M6 can compare repeated runs.
