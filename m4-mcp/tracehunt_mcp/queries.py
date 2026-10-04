"""Build Elasticsearch DSL from typed tool arguments.

The agent never sends raw DSL. It sends typed filters ({field, op, value})
and this module translates them into bounded query bodies.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


def time_range_clause(start: datetime, end: datetime, field: str = "@timestamp") -> dict:
    return {
        "range": {
            field: {
                "gte": start.isoformat(),
                "lt": end.isoformat(),
            }
        }
    }


def filter_clauses(filters: list[dict]) -> list[dict]:
    clauses: list[dict] = []
    for f in filters:
        field_name = f["field"]
        op = f["op"]
        value = f["value"]
        if op == "eq":
            clauses.append({"term": {field_name: value}})
        elif op == "match":
            clauses.append({"match_phrase": {field_name: value}})
        elif op == "exists":
            clauses.append({"exists": {"field": field_name}})
        else:  # pragma: no cover - validation blocks unknown ops
            raise ValueError(f"unsupported op {op!r}")
    return clauses


def build_query(start: datetime, end: datetime, filters: list[dict]) -> dict[str, Any]:
    must: list[dict] = [time_range_clause(start, end)]
    must.extend(filter_clauses(filters))
    return {"bool": {"filter": must}}


def build_agg(agg: dict, bucket_limit: int = 100) -> dict[str, Any]:
    if agg["kind"] == "terms":
        return {"terms": {"field": agg["field"], "size": bucket_limit}}
    if agg["kind"] == "date_histogram":
        return {
            "date_histogram": {
                "field": agg["field"],
                "fixed_interval": agg["interval"],
            }
        }
    raise ValueError(f"unsupported agg kind {agg['kind']!r}")  # pragma: no cover


def search_body(
    query: dict,
    size: int,
    sort: str = "asc",
    source_fields: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "query": query,
        "size": size,
        "sort": [{"@timestamp": {"order": sort}}],
        "_source": True if source_fields is None else source_fields,
        "track_total_hits": True,
    }
