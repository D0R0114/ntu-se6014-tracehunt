"""The seven typed read-only tools used by the hunt workflow.

Every public tool is audited. Successful calls record the exact Elasticsearch
request body (or exact read operation); rejected and failed calls record the
attempted input and error. The agent never supplies raw Elasticsearch DSL.
"""

from __future__ import annotations

import functools
import inspect
from datetime import datetime
from typing import Any, Callable

from . import queries as q
from . import validation as v
from .backend import EsBackend
from .config import Config
from .errors import BackendError, ToolInputError
from .ledger import EvidenceLedger, timed


def _attempted_input(fn: Callable, self: "ToolSet", args: tuple, kwargs: dict) -> dict:
    try:
        bound = inspect.signature(fn).bind(self, *args, **kwargs)
        bound.apply_defaults()
        data = dict(bound.arguments)
        data.pop("self", None)
        return {"input": data}
    except Exception:
        return {"args": list(args), "kwargs": kwargs}


def audited(tool_name: str):
    """Record every failed/rejected tool call exactly once before re-raising."""

    def decorate(fn: Callable):
        @functools.wraps(fn)
        def wrapper(self: "ToolSet", *args, **kwargs):
            timer = timed()
            try:
                return fn(self, *args, **kwargs)
            except Exception as exc:
                try:
                    self.ledger.record_error(
                        tool_name,
                        _attempted_input(fn, self, args, kwargs),
                        str(exc),
                        timer.elapsed_ms(),
                    )
                except Exception:
                    pass
                raise

        return wrapper

    return decorate


def _source_value(source: dict, path: str):
    current: Any = source
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _event_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return v.parse_time(value, "@timestamp")
    except ToolInputError:
        return None


class ToolSet:
    def __init__(self, cfg: Config, backend: EsBackend, ledger: EvidenceLedger):
        self.cfg = cfg
        self.backend = backend
        self.ledger = ledger

    @audited("list_data_sources")
    def list_data_sources(self) -> dict:
        timer = timed()
        sources = []
        requests = []
        for index in self.cfg.indices:
            requests.append({"op": "indices.exists", "index": index})
            exists = self.backend.index_exists(index)
            entry: dict[str, Any] = {"index": index, "available": exists, "doc_count": None}
            if exists:
                match_all = {"match_all": {}}
                requests.append({"op": "count", "index": index, "body": {"query": match_all}})
                entry["doc_count"] = self.backend.count(index, match_all)
            sources.append(entry)
        result = {
            "run_id": self.cfg.run_id,
            "sources": sources,
            "indices_allowlist": list(self.cfg.indices),
        }
        self.ledger.record_ok(
            "list_data_sources", {"requests": requests}, len(sources), [], timer.elapsed_ms()
        )
        return result

    @audited("get_time_bounds")
    def get_time_bounds(self, index: str) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        body = {
            "size": 0,
            "track_total_hits": True,
            "aggs": {
                "min_ts": {"min": {"field": "@timestamp"}},
                "max_ts": {"max": {"field": "@timestamp"}},
            },
        }
        resp = self.backend.search(idx, body)
        aggs = resp.get("aggregations", {})
        total = resp.get("hits", {}).get("total", {})
        doc_count = int(total.get("value", 0))
        result = {
            "index": idx,
            "earliest": (aggs.get("min_ts") or {}).get("value_as_string"),
            "latest": (aggs.get("max_ts") or {}).get("value_as_string"),
            "doc_count": doc_count,
        }
        self.ledger.record_ok(
            "get_time_bounds",
            {"request": {"op": "search", "index": idx, "body": body}},
            1,
            [],
            timer.elapsed_ms(),
        )
        return result

    @audited("search_events")
    def search_events(
        self,
        index: str,
        start: str,
        end: str,
        filters: list[dict] | None = None,
        size: int | None = None,
        sort: str | None = None,
    ) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        start_dt, end_dt = v.validate_window(self.cfg, start, end)
        checked_filters = v.validate_filters(self.cfg, filters)
        n = v.validate_size(self.cfg, size)
        order = v.validate_sort(self.cfg, sort)

        query = q.build_query(start_dt, end_dt, checked_filters)
        body = q.search_body(query, n, order)
        resp = self.backend.search(idx, body)
        hits = resp.get("hits", {}).get("hits", [])
        total = resp.get("hits", {}).get("total", {})
        doc_ids = [h.get("_id") for h in hits if h.get("_id") is not None]
        events = [{"_id": h.get("_id"), **(h.get("_source") or {})} for h in hits]
        result = {
            "index": idx,
            "total_matches": int(total.get("value", 0)),
            "total_relation": total.get("relation", "eq"),
            "returned": len(events),
            "events": events,
            "doc_ids": doc_ids,
        }
        self.ledger.record_ok(
            "search_events",
            {"request": {"op": "search", "index": idx, "body": body}},
            result["total_matches"],
            doc_ids,
            timer.elapsed_ms(),
        )
        return result

    @audited("aggregate_events")
    def aggregate_events(
        self,
        index: str,
        start: str,
        end: str,
        kind: str,
        field: str,
        interval: str | None = None,
        filters: list[dict] | None = None,
    ) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        start_dt, end_dt = v.validate_window(self.cfg, start, end)
        agg_spec = v.validate_agg(self.cfg, kind, field, interval)
        checked_filters = v.validate_filters(self.cfg, filters)

        query = q.build_query(start_dt, end_dt, checked_filters)
        bucket_limit = self.cfg.max_agg_buckets + 1
        body = {
            "size": 0,
            "query": query,
            "aggs": {"result": q.build_agg(agg_spec, bucket_limit=bucket_limit)},
        }
        resp = self.backend.search(idx, body)
        agg_result = resp.get("aggregations", {}).get("result") or {}
        buckets = agg_result.get("buckets", [])
        parsed = []
        for b in buckets:
            if b.get("key_as_string") is not None and kind == "date_histogram":
                parsed.append({"bucket": b["key_as_string"], "count": b["doc_count"]})
            else:
                parsed.append({"bucket": b.get("key"), "count": b["doc_count"]})
        other_docs = int(agg_result.get("sum_other_doc_count", 0) or 0)
        returned = parsed[: self.cfg.max_agg_buckets]
        truncated = len(parsed) > self.cfg.max_agg_buckets or other_docs > 0
        result = {
            "index": idx,
            "agg": agg_spec,
            "bucket_count": len(returned),
            "buckets": returned,
            "truncated": truncated,
        }
        self.ledger.record_ok(
            "aggregate_events",
            {"request": {"op": "search", "index": idx, "body": body}},
            len(returned),
            [],
            timer.elapsed_ms(),
        )
        return result

    @audited("run_sequence_query")
    def run_sequence_query(
        self,
        index: str,
        start: str,
        end: str,
        entity_field: str,
        steps: list[dict],
    ) -> dict:
        """Find chronologically ordered step sequences for the same entity."""
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        start_dt, end_dt = v.validate_window(self.cfg, start, end)
        ent = v.validate_entity_field(entity_field)
        checked_steps = v.validate_seq_steps(self.cfg, steps)

        per_step_maps: list[dict[str, list[dict]]] = []
        per_step_summary: list[dict] = []
        requests = []
        incomplete = False

        for step in checked_steps:
            query = q.build_query(start_dt, end_dt, step["filters"])
            body = q.search_body(
                query,
                self.cfg.max_scan,
                "asc",
                source_fields=["@timestamp", ent],
            )
            requests.append({"step": step["name"], "op": "search", "index": idx, "body": body})
            resp = self.backend.search(idx, body)
            hit_block = resp.get("hits", {})
            hits = hit_block.get("hits", [])
            total = hit_block.get("total", {})
            total_value = int(total.get("value", 0))
            relation = total.get("relation", "eq")
            truncated = relation != "eq" or total_value > len(hits)

            by_entity: dict[str, list[dict]] = {}
            skipped = 0
            for hit in hits:
                source = hit.get("_source") or {}
                entity_value = _source_value(source, ent)
                raw_ts = source.get("@timestamp")
                parsed_ts = _event_time(raw_ts)
                doc_id = hit.get("_id")
                if entity_value is None or parsed_ts is None or doc_id is None:
                    skipped += 1
                    continue
                by_entity.setdefault(str(entity_value), []).append(
                    {"timestamp": raw_ts, "dt": parsed_ts, "doc_id": str(doc_id)}
                )

            for events in by_entity.values():
                events.sort(key=lambda e: (e["dt"], e["doc_id"]))

            if truncated or skipped:
                incomplete = True
            per_step_maps.append(by_entity)
            per_step_summary.append(
                {
                    "step": step["name"],
                    "total_matches": total_value,
                    "returned": len(hits),
                    "entity_count": len(by_entity),
                    "truncated": truncated,
                    "skipped_missing_fields": skipped,
                }
            )

        candidate_sets = [set(step_map) for step_map in per_step_maps]
        candidates = set.intersection(*candidate_sets) if candidate_sets else set()
        matches = []
        ledger_doc_ids: list[str] = []

        for entity in sorted(candidates):
            previous: datetime | None = None
            chain = []
            for step, step_map in zip(checked_steps, per_step_maps):
                chosen = next(
                    (
                        event
                        for event in step_map[entity]
                        if previous is None or event["dt"] > previous
                    ),
                    None,
                )
                if chosen is None:
                    chain = []
                    break
                previous = chosen["dt"]
                chain.append(
                    {
                        "step": step["name"],
                        "timestamp": chosen["timestamp"],
                        "doc_id": chosen["doc_id"],
                    }
                )
            if chain:
                matches.append({"entity": entity, "sequence": chain})
                ledger_doc_ids.extend(item["doc_id"] for item in chain)

        ledger_doc_ids = list(dict.fromkeys(ledger_doc_ids))
        result = {
            "index": idx,
            "entity_field": ent,
            "steps_checked": len(checked_steps),
            "per_step": per_step_summary,
            "entities_matching_all_steps": [m["entity"] for m in matches],
            "matched_entity_count": len(matches),
            "matches": matches,
            "complete": not incomplete,
        }
        if incomplete:
            result["warning"] = (
                "Sequence scan was incomplete because a step exceeded TRACEHUNT_MAX_SCAN "
                "or returned events missing the entity/timestamp fields. Narrow the query before "
                "using absence of a match as evidence."
            )

        self.ledger.record_ok(
            "run_sequence_query",
            {"requests": requests},
            len(matches),
            ledger_doc_ids,
            timer.elapsed_ms(),
        )
        return result

    @audited("fetch_evidence")
    def fetch_evidence(self, index: str, doc_ids: list[str]) -> dict:
        timer = timed()
        idx = v.validate_index(self.cfg, index)
        ids = v.validate_doc_ids(self.cfg, doc_ids)
        docs = self.backend.mget(idx, ids)
        found = [d for d in docs if d.get("found")]
        missing = [d["_id"] for d in docs if not d.get("found")]
        result = {
            "index": idx,
            "requested": len(ids),
            "found": len(found),
            "missing_ids": missing,
            "documents": [
                {"_id": d["_id"], **(d.get("_source") or {})} for d in found
            ],
        }
        found_ids = [d["_id"] for d in found]
        self.ledger.record_ok(
            "fetch_evidence",
            {"request": {"op": "mget", "index": idx, "body": {"ids": ids}}},
            len(found),
            found_ids,
            timer.elapsed_ms(),
        )
        return result

    @audited("get_query_history")
    def get_query_history(self) -> dict:
        timer = timed()
        history = self.ledger.history(only_this_run=True)
        result = {
            "run_id": self.cfg.run_id,
            "call_count": len(history),
            "calls": [
                {
                    "seq": h.get("seq"),
                    "ts": h.get("ts"),
                    "tool": h.get("tool"),
                    "status": h.get("status"),
                    "query_hash": h.get("query_hash"),
                    "result_count": h.get("result_count"),
                }
                for h in history
            ],
        }
        self.ledger.record_ok(
            "get_query_history",
            {"ledger_run_id": self.cfg.run_id},
            len(history),
            [],
            timer.elapsed_ms(),
        )
        return result
