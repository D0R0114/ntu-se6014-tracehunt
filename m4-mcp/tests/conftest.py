"""Shared fixtures for the M4 unit tests."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from tracehunt_mcp.backend import EsBackend
from tracehunt_mcp.config import Config
from tracehunt_mcp.errors import BackendError
from tracehunt_mcp.ledger import EvidenceLedger
from tracehunt_mcp.tools import ToolSet


def get_field(doc: dict, path: str):
    current = doc
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


class FakeBackend(EsBackend):
    """In-memory stand-in for Elasticsearch using the query shapes M4 builds."""

    def __init__(self, docs: dict[str, list[dict]]):
        self.docs = {k: [dict(d, _id=f"{k}-{i}") for i, d in enumerate(v)] for k, v in docs.items()}
        self.calls: list[tuple[str, dict]] = []
        self._fail = False

    def set_fail(self, fail: bool) -> None:
        self._fail = fail

    def _match(self, doc: dict, clause: dict) -> bool:
        if "range" in clause:
            field, spec = next(iter(clause["range"].items()))
            value = get_field(doc, field)
            if value is None:
                return False
            if "gte" in spec and not (value >= spec["gte"]):
                return False
            if "lt" in spec and not (value < spec["lt"]):
                return False
            return True
        if "term" in clause:
            field, value = next(iter(clause["term"].items()))
            return get_field(doc, field) == value
        if "match_phrase" in clause:
            field, value = next(iter(clause["match_phrase"].items()))
            doc_value = get_field(doc, field)
            return isinstance(doc_value, str) and str(value) in doc_value
        if "exists" in clause:
            return get_field(doc, clause["exists"]["field"]) is not None
        if "match_all" in clause:
            return True
        raise AssertionError(f"unexpected clause {clause}")

    def _hits(self, index: str, query: dict) -> list[dict]:
        if "match_all" in query:
            return list(self.docs.get(index, []))
        filters = query.get("bool", {}).get("filter", [])
        return [d for d in self.docs.get(index, []) if all(self._match(d, c) for c in filters)]

    def index_exists(self, index: str) -> bool:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("exists", {"index": index}))
        return index in self.docs

    def count(self, index: str, query: dict) -> int:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("count", {"index": index, "query": query}))
        return len(self._hits(index, query))

    def mget(self, index: str, ids: list[str]) -> list[dict]:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("mget", {"index": index, "ids": ids}))
        by_id = {d["_id"]: d for d in self.docs.get(index, [])}
        return [
            {
                "_index": index,
                "_id": i,
                "_source": {k: v for k, v in by_id[i].items() if k != "_id"},
                "found": True,
            }
            if i in by_id
            else {"_index": index, "_id": i, "_source": None, "found": False}
            for i in ids
        ]

    def search(self, index: str, body: dict) -> dict:
        if self._fail:
            raise BackendError("simulated outage")
        self.calls.append(("search", {"index": index, "body": body}))
        query = body.get("query", {"match_all": {}})
        hits = self._hits(index, query)
        size = body.get("size", 10)
        sort = body.get("sort")
        if sort and hits:
            field = next(iter(sort[0]))
            order = sort[0][field].get("order", "asc")
            hits = sorted(
                hits,
                key=lambda d: (str(get_field(d, field) or ""), str(d.get("_id", ""))),
                reverse=(order == "desc"),
            )
        resp: dict = {
            "hits": {
                "total": {"value": len(hits), "relation": "eq"},
                "hits": [
                    {
                        "_index": index,
                        "_id": d["_id"],
                        "_source": {k: v for k, v in d.items() if k != "_id"},
                    }
                    for d in hits[:size]
                ],
            }
        }
        aggs = body.get("aggs")
        if aggs:
            resp["aggregations"] = {}
            for name, spec in aggs.items():
                if "min" in spec:
                    field = spec["min"]["field"]
                    values = [get_field(d, field) for d in hits if get_field(d, field) is not None]
                    value = min(values) if values else None
                    resp["aggregations"][name] = {"value": value, "value_as_string": value}
                elif "max" in spec:
                    field = spec["max"]["field"]
                    values = [get_field(d, field) for d in hits if get_field(d, field) is not None]
                    value = max(values) if values else None
                    resp["aggregations"][name] = {"value": value, "value_as_string": value}
                elif "terms" in spec:
                    field = spec["terms"]["field"]
                    limit = spec["terms"].get("size", 10)
                    counts: dict[str, int] = {}
                    for d in hits:
                        key = get_field(d, field)
                        if key is not None:
                            counts[str(key)] = counts.get(str(key), 0) + 1
                    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
                    visible = ordered[:limit]
                    resp["aggregations"][name] = {
                        "buckets": [{"key": k, "doc_count": c} for k, c in visible],
                        "sum_other_doc_count": sum(c for _, c in ordered[limit:]),
                    }
                elif "date_histogram" in spec:
                    field = spec["date_histogram"]["field"]
                    resp["aggregations"][name] = {
                        "buckets": [
                            {"key": i, "key_as_string": str(get_field(d, field)), "doc_count": 1}
                            for i, d in enumerate(hits)
                            if get_field(d, field) is not None
                        ]
                    }
                else:
                    raise AssertionError(f"unexpected agg {spec}")
        return resp


LAB_DOCS = {
    "windows-security": [
        {
            "@timestamp": "2026-09-30T06:40:00Z",
            "event": {"code": "4624", "outcome": "success"},
            "host": {"name": "WS-02"},
            "user": {"name": "office-user"},
        },
        {
            "@timestamp": "2026-09-30T07:00:00Z",
            "event": {"code": "4625", "outcome": "failure"},
            "host": {"name": "WS-01"},
            "user": {"name": "lab-user"},
        },
        {
            "@timestamp": "2026-09-30T07:05:00Z",
            "event": {"code": "4625", "outcome": "failure"},
            "host": {"name": "WS-01"},
            "user": {"name": "lab-user"},
        },
        {
            "@timestamp": "2026-09-30T07:09:00Z",
            "event": {"code": "4624", "outcome": "success"},
            "host": {"name": "WS-01"},
            "user": {"name": "lab-user"},
        },
        {
            "@timestamp": "2026-09-30T08:10:00Z",
            "event": {"code": "4625", "outcome": "failure"},
            "host": {"name": "WS-03"},
            "user": {"name": "intern"},
        },
    ],
    "sysmon": [
        {
            "@timestamp": "2026-09-30T07:12:00Z",
            "event": {"code": "1"},
            "host": {"name": "WS-01"},
            "user": {"name": "lab-user"},
            "process": {"command_line": "powershell.exe -NoProfile -EncodedCommand SQBuAHYAbwBrAGUALQ=="},
        },
    ],
    "zeek": [],
}


@pytest.fixture()
def cfg(tmp_path) -> Config:
    return Config(
        es_url="http://fake:9200",
        es_username=None,
        es_password=None,
        es_ca_cert=None,
        indices=("windows-security", "sysmon", "zeek"),
        ledger_path=str(tmp_path / "ledger.jsonl"),
        run_id="run-test-1",
        default_size=50,
        max_size=100,
        max_window_hours=24,
        request_timeout_s=5,
        max_scan=100,
        max_doc_ids=50,
        max_seq_steps=5,
        max_agg_buckets=100,
    )


@pytest.fixture()
def toolset(cfg) -> tuple[ToolSet, FakeBackend, EvidenceLedger]:
    backend = FakeBackend({k: [dict(d) for d in v] for k, v in LAB_DOCS.items()})
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    return ToolSet(cfg, backend, ledger), backend, ledger
