"""Unit tests for the seven tools against the ECS-shaped fake backend."""

from dataclasses import replace

import pytest

from conftest import FakeBackend, LAB_DOCS
from tracehunt_mcp.errors import BackendError, ToolInputError
from tracehunt_mcp.ledger import EvidenceLedger
from tracehunt_mcp.tools import ToolSet


def test_list_data_sources(toolset):
    tools, backend, ledger = toolset
    out = tools.list_data_sources()
    assert out["run_id"] == "run-test-1"
    by_index = {s["index"]: s for s in out["sources"]}
    assert by_index["windows-security"]["available"] is True
    assert by_index["windows-security"]["doc_count"] == 5
    assert by_index["zeek"]["doc_count"] == 0
    assert ledger.history()[0]["status"] == "ok"


def test_list_data_sources_backend_down_is_audited(toolset):
    tools, backend, ledger = toolset
    backend.set_fail(True)
    with pytest.raises(BackendError, match="simulated outage"):
        tools.list_data_sources()
    rec = ledger.history()[0]
    assert rec["tool"] == "list_data_sources"
    assert rec["status"] == "error"


def test_get_time_bounds(toolset):
    tools, backend, ledger = toolset
    out = tools.get_time_bounds("windows-security")
    assert out["earliest"] == "2026-09-30T06:40:00Z"
    assert out["latest"] == "2026-09-30T08:10:00Z"
    assert out["doc_count"] == 5


def test_search_events_ecs_fields_and_exact_request_ledger(toolset):
    tools, backend, ledger = toolset
    out = tools.search_events(
        "windows-security",
        "2026-09-30T06:00:00Z",
        "2026-09-30T09:00:00Z",
        filters=[{"field": "user.name", "op": "eq", "value": "lab-user"}],
    )
    assert out["total_matches"] == 3
    assert all(e["user"]["name"] == "lab-user" for e in out["events"])
    rec = ledger.history()[0]
    assert rec["query"]["request"]["body"]["track_total_hits"] is True
    assert rec["doc_ids"] == out["doc_ids"]


def test_rejected_call_is_audited(toolset):
    tools, backend, ledger = toolset
    with pytest.raises(ToolInputError, match="not allowed"):
        tools.search_events("*", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
    assert backend.calls == []
    rec = ledger.history()[0]
    assert rec["status"] == "error"
    assert rec["tool"] == "search_events"
    assert rec["query"]["input"]["index"] == "*"


def test_search_events_match_op(toolset):
    tools, backend, ledger = toolset
    out = tools.search_events(
        "sysmon", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        filters=[{"field": "process.command_line", "op": "match", "value": "EncodedCommand"}],
    )
    assert out["total_matches"] == 1


def test_aggregate_terms(toolset):
    tools, backend, ledger = toolset
    out = tools.aggregate_events(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        kind="terms", field="user.name",
    )
    counts = {b["bucket"]: b["count"] for b in out["buckets"]}
    assert counts == {"lab-user": 3, "office-user": 1, "intern": 1}
    assert out["truncated"] is False


def test_aggregate_limit_reports_truncation(cfg):
    small = replace(cfg, max_agg_buckets=2)
    backend = FakeBackend({k: [dict(d) for d in v] for k, v in LAB_DOCS.items()})
    ledger = EvidenceLedger(small.ledger_path, small.run_id)
    tools = ToolSet(small, backend, ledger)
    out = tools.aggregate_events(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        kind="terms", field="user.name",
    )
    assert out["bucket_count"] == 2
    assert out["truncated"] is True


def test_sequence_query_enforces_chronological_order(toolset):
    tools, backend, ledger = toolset
    backend.docs["windows-security"].extend(
        [
            {
                "_id": "reverse-success",
                "@timestamp": "2026-09-30T06:50:00Z",
                "event": {"code": "4624"},
                "user": {"name": "reverse-user"},
            },
            {
                "_id": "reverse-failure",
                "@timestamp": "2026-09-30T08:00:00Z",
                "event": {"code": "4625"},
                "user": {"name": "reverse-user"},
            },
        ]
    )
    out = tools.run_sequence_query(
        "windows-security", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z",
        entity_field="user.name",
        steps=[
            {"name": "failed", "filters": [{"field": "event.code", "op": "eq", "value": "4625"}]},
            {"name": "success", "filters": [{"field": "event.code", "op": "eq", "value": "4624"}]},
        ],
    )
    assert out["entities_matching_all_steps"] == ["lab-user"]
    assert "reverse-user" not in out["entities_matching_all_steps"]
    assert out["complete"] is True
    assert len(out["matches"][0]["sequence"]) == 2
    seq = out["matches"][0]["sequence"]
    assert seq[0]["timestamp"] < seq[1]["timestamp"]
    rec = ledger.history()[0]
    assert rec["doc_ids"] == [seq[0]["doc_id"], seq[1]["doc_id"]]


def test_fetch_evidence_roundtrip(toolset):
    tools, backend, ledger = toolset
    found = tools.search_events(
        "windows-security", "2026-09-30T07:00:00Z", "2026-09-30T08:00:00Z",
        filters=[{"field": "event.code", "op": "eq", "value": "4625"}],
    )
    out = tools.fetch_evidence("windows-security", found["doc_ids"])
    assert out["found"] == 2
    assert all(d["event"]["code"] == "4625" for d in out["documents"])


def test_query_history_includes_failed_calls(toolset):
    tools, backend, ledger = toolset
    tools.search_events("sysmon", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
    with pytest.raises(ToolInputError):
        tools.search_events("*", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
    hist = tools.get_query_history()
    assert [c["status"] for c in hist["calls"]] == ["ok", "error"]
    assert all(len(c["query_hash"]) == 64 for c in hist["calls"])


def test_backend_failure_surfaces_and_is_audited(toolset):
    tools, backend, ledger = toolset
    backend.set_fail(True)
    with pytest.raises(BackendError, match="simulated outage"):
        tools.search_events("sysmon", "2026-09-30T06:00:00Z", "2026-09-30T09:00:00Z")
    rec = ledger.history()[0]
    assert rec["status"] == "error"
    assert "simulated outage" in rec["error"]