"""Integration tests against the seeded Elasticsearch 8.12 dev stack."""

from __future__ import annotations

import os

import pytest

from tracehunt_mcp.backend import EsBackend
from tracehunt_mcp.config import Config
from tracehunt_mcp.errors import ToolInputError
from tracehunt_mcp.ledger import EvidenceLedger
from tracehunt_mcp.tools import ToolSet

RUN = os.environ.get("TRACEHUNT_IT") == "1"
pytestmark = pytest.mark.skipif(not RUN, reason="set TRACEHUNT_IT=1 to run integration tests")


@pytest.fixture()
def stack(tmp_path):
    cfg = Config(
        es_url=os.environ.get("TRACEHUNT_ES_URL", "http://localhost:19200"),
        es_username=os.environ.get("TRACEHUNT_ES_USERNAME"),
        es_password=os.environ.get("TRACEHUNT_ES_PASSWORD"),
        es_ca_cert=None,
        indices=("windows-security", "sysmon", "zeek"),
        ledger_path=str(tmp_path / "it-ledger.jsonl"),
        run_id="run-it-1",
        default_size=50,
        max_size=100,
        max_window_hours=72,
        request_timeout_s=10,
        max_scan=100,
        max_doc_ids=50,
        max_seq_steps=5,
        max_agg_buckets=100,
    )
    backend = EsBackend(cfg)
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    tools = ToolSet(cfg, backend, ledger)
    yield tools, ledger
    backend.close()


def test_full_ecs_lab_story(stack):
    tools, ledger = stack

    sources = tools.list_data_sources()
    assert all(s["available"] for s in sources["sources"])
    counts = {s["index"]: s["doc_count"] for s in sources["sources"]}
    assert counts == {"windows-security": 11, "sysmon": 2, "zeek": 4}

    bounds = tools.get_time_bounds("windows-security")
    assert bounds["earliest"].startswith("2026-09-30")

    failed = tools.search_events(
        "windows-security",
        "2026-09-30T07:00:00Z",
        "2026-09-30T07:30:00Z",
        filters=[
            {"field": "user.name", "op": "eq", "value": "lab-user"},
            {"field": "event.code", "op": "eq", "value": "4625"},
        ],
    )
    assert failed["total_matches"] == 8

    ps = tools.search_events(
        "sysmon",
        "2026-09-30T07:00:00Z",
        "2026-09-30T07:30:00Z",
        filters=[{"field": "process.command_line", "op": "match", "value": "EncodedCommand"}],
    )
    assert ps["total_matches"] == 1
    ps_id = ps["doc_ids"][0]

    http_out = tools.search_events(
        "zeek",
        "2026-09-30T07:00:00Z",
        "2026-09-30T07:30:00Z",
        filters=[{"field": "destination.ip", "op": "eq", "value": "10.10.10.50"}],
    )
    assert http_out["total_matches"] == 1

    seq = tools.run_sequence_query(
        "windows-security",
        "2026-09-30T06:30:00Z",
        "2026-09-30T08:00:00Z",
        entity_field="user.name",
        steps=[
            {"name": "failed", "filters": [{"field": "event.code", "op": "eq", "value": "4625"}]},
            {"name": "success", "filters": [{"field": "event.code", "op": "eq", "value": "4624"}]},
        ],
    )
    assert seq["complete"] is True
    assert seq["entities_matching_all_steps"] == ["lab-user"]
    chain = seq["matches"][0]["sequence"]
    assert chain[0]["timestamp"] < chain[1]["timestamp"]
    assert all(item["doc_id"] for item in chain)

    ev = tools.fetch_evidence("sysmon", [ps_id])
    assert ev["found"] == 1
    assert "EncodedCommand" in ev["documents"][0]["process"]["command_line"]

    agg = tools.aggregate_events(
        "windows-security",
        "2026-09-30T06:30:00Z",
        "2026-09-30T08:30:00Z",
        kind="terms",
        field="user.name",
    )
    buckets = {b["bucket"]: b["count"] for b in agg["buckets"]}
    assert buckets["lab-user"] == 9

    hist = tools.get_query_history()
    assert hist["call_count"] == 8
    assert all(len(c["query_hash"]) == 64 for c in hist["calls"])
    assert all(c["status"] == "ok" for c in hist["calls"])


def test_rejections_are_audited_without_touching_data(stack):
    tools, ledger = stack
    with pytest.raises(ToolInputError):
        tools.search_events("not-allowed", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
    with pytest.raises(ToolInputError):
        tools.search_events("zeek", "2026-09-01T00:00:00Z", "2026-09-30T09:00:00Z")
    records = ledger.history()
    assert len(records) == 2
    assert all(r["status"] == "error" for r in records)
    assert all(r["result_count"] == 0 for r in records)
