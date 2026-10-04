"""Unit tests for input validation."""

import pytest

from tracehunt_mcp.errors import ToolInputError
from tracehunt_mcp import validation as v


def test_validate_index_allows_only_allowlist(cfg):
    assert v.validate_index(cfg, "sysmon") == "sysmon"
    for bad in ("everything", "*"):
        with pytest.raises(ToolInputError, match="not allowed"):
            v.validate_index(cfg, bad)


def test_parse_time_accepts_iso_with_z(cfg):
    dt = v.parse_time("2026-09-30T07:00:00Z", "start")
    assert dt.isoformat() == "2026-09-30T07:00:00+00:00"


def test_parse_time_rejects_garbage(cfg):
    for bad in ("", "not-a-time", "2026-13-45T99:99:99"):
        with pytest.raises(ToolInputError):
            v.parse_time(bad, "start")


def test_window_rejects_end_before_start(cfg):
    with pytest.raises(ToolInputError, match="strictly after"):
        v.validate_window(cfg, "2026-09-30T09:00:00Z", "2026-09-30T08:00:00Z")


def test_window_rejects_too_wide(cfg):
    with pytest.raises(ToolInputError, match="maximum of 24 hours"):
        v.validate_window(cfg, "2026-09-28T00:00:00Z", "2026-09-30T00:00:00Z")


def test_size_bounds(cfg):
    assert v.validate_size(cfg, None) == 50
    assert v.validate_size(cfg, 10) == 10
    for bad in (0, 101):
        with pytest.raises(ToolInputError, match="between 1 and 100"):
            v.validate_size(cfg, bad)
    with pytest.raises(ToolInputError, match="integer"):
        v.validate_size(cfg, "10")


def test_filters_typed_only_and_ecs_fields(cfg):
    good = [{"field": "user.name", "op": "eq", "value": "lab-user"}]
    assert v.validate_filters(cfg, good) == good
    assert v.validate_filters(cfg, None) == []
    with pytest.raises(ToolInputError, match="not allowed"):
        v.validate_filters(cfg, [{"field": "x", "op": "script", "value": "evil"}])
    with pytest.raises(ToolInputError, match="required"):
        v.validate_filters(cfg, [{"field": "x", "op": "eq"}])
    with pytest.raises(ToolInputError, match="letters"):
        v.validate_filters(cfg, [{"field": "*", "op": "exists"}])
    with pytest.raises(ToolInputError, match="at most 10"):
        v.validate_filters(cfg, [{"field": "x", "op": "eq", "value": 1}] * 11)
    with pytest.raises(ToolInputError, match="too long"):
        v.validate_filters(cfg, [{"field": "x", "op": "match", "value": "a" * 513}])


def test_agg_validation(cfg):
    assert v.validate_agg(cfg, "terms", "user.name", None) == {"kind": "terms", "field": "user.name"}
    spec = v.validate_agg(cfg, "date_histogram", "event.created", "5m")
    assert spec == {"kind": "date_histogram", "field": "event.created", "interval": "5m"}
    with pytest.raises(ToolInputError, match="kind"):
        v.validate_agg(cfg, "cardinality", "user.name", None)
    with pytest.raises(ToolInputError, match="interval is required"):
        v.validate_agg(cfg, "date_histogram", "@timestamp", None)


def test_doc_ids_use_configured_limit(cfg):
    assert v.validate_doc_ids(cfg, ["a", "b"]) == ["a", "b"]
    with pytest.raises(ToolInputError, match="non-empty"):
        v.validate_doc_ids(cfg, [])
    with pytest.raises(ToolInputError, match="at most 50"):
        v.validate_doc_ids(cfg, [f"id{i}" for i in range(51)])


def test_seq_steps(cfg):
    steps = [
        {"name": "failed", "filters": [{"field": "event.code", "op": "eq", "value": "4625"}]},
        {"name": "success", "filters": [{"field": "event.code", "op": "eq", "value": "4624"}]},
    ]
    out = v.validate_seq_steps(cfg, steps)
    assert [s["name"] for s in out] == ["failed", "success"]
    with pytest.raises(ToolInputError, match="at least 2"):
        v.validate_seq_steps(cfg, [steps[0]])
