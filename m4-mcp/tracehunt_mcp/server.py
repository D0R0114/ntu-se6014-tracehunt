"""TraceHunt MCP server: stdio transport, seven typed read-only tools."""

from __future__ import annotations

import functools
import logging

from mcp.server.mcpserver import MCPServer

from .backend import EsBackend
from .config import Config
from .errors import BackendError, ToolInputError
from .ledger import EvidenceLedger
from .tools import ToolSet

logger = logging.getLogger("tracehunt_mcp")


def build(cfg: Config | None = None) -> tuple[MCPServer, ToolSet]:
    cfg = cfg or Config.from_env()
    backend = EsBackend(cfg)
    ledger = EvidenceLedger(cfg.ledger_path, cfg.run_id)
    tools = ToolSet(cfg, backend, ledger)
    mcp = MCPServer(
        "tracehunt",
        instructions=(
            "TraceHunt read-only ELK search tools with an evidence ledger. "
            "Every call is recorded with its exact read request, hash, result count, "
            "and returned document ids. Use get_query_history to audit a hunt run."
        ),
    )

    def register(name: str, fn, doc: str):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except ToolInputError as exc:
                return {"error": "invalid_input", "message": str(exc)}
            except BackendError as exc:
                return {"error": "backend_unavailable", "message": str(exc)}
            except Exception:
                logger.exception("unexpected failure in MCP tool %s", name)
                return {"error": "internal_error", "message": "unexpected tool failure; see server logs"}

        mcp.tool(name=name, description=doc)(wrapper)

    register(
        "list_data_sources",
        tools.list_data_sources,
        "List allowlisted log indices, availability, and document counts. No arguments.",
    )
    register(
        "get_time_bounds",
        tools.get_time_bounds,
        "Earliest/latest @timestamp and document count for one allowlisted index. Args: index.",
    )
    register(
        "search_events",
        tools.search_events,
        "Bounded event search. Args: index, start, end, filters ({field, op: eq|match|exists, value}), "
        "size, sort. Returns events, total_matches, and document IDs for citations.",
    )
    register(
        "aggregate_events",
        tools.aggregate_events,
        "Bounded aggregation. Args: index, start, end, kind (terms|date_histogram), field, interval, filters.",
    )
    register(
        "run_sequence_query",
        tools.run_sequence_query,
        "Find a strictly time-ordered sequence of named steps for the same entity. Args: index, start, end, "
        "entity_field (for example user.name), steps ({name, filters}). Returns matched entities and the "
        "document IDs/timestamps proving each ordered sequence.",
    )
    register(
        "fetch_evidence",
        tools.fetch_evidence,
        "Fetch full source documents by ID, subject to TRACEHUNT_MAX_DOC_IDS. Args: index, doc_ids.",
    )
    register(
        "get_query_history",
        tools.get_query_history,
        "Audit trail for this hunt run: tool, status, query hash, timestamp, and result count. No arguments.",
    )

    return mcp, tools


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    mcp, _ = build()
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
