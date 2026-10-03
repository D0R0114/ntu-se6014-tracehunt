"""Connector-facing API. Every input becomes an accepted or quarantined result."""

from copy import deepcopy

from .classifier import classify
from .config import Config
from .errors import RecordError, SchemaError
from .fields import canonical_json, digest
from .parser import normalize
from .registry import SchemaRegistry


class SchemaPipeline:
    def __init__(self, registry: SchemaRegistry | None = None, config: Config | None = None):
        self.registry = registry or SchemaRegistry()
        self.config = config or Config()

    def process(self, record, source_hint: str | None = None, raw_text: str | None = None,
                schema_id: str | None = None, schema_version: str | None = None) -> dict:
        source = source_hint
        spec = None
        safe_record = record
        try:
            if schema_version and not schema_id:
                raise RecordError("invalid_schema_pin", "schema_version requires schema_id")
            if not isinstance(record, dict):
                raise RecordError("invalid_record", "each event must be a JSON object")
            try:
                canonical_json(record)
            except (ValueError, TypeError) as exc:
                safe_record = None
                if raw_text is None:
                    raw_text = repr(record)
                raise RecordError("invalid_record", "event must contain finite JSON values") from exc
            source = classify(record, source_hint)
            if schema_id:
                spec = self.registry.get_schema(schema_id, schema_version)
                if source is not None and spec["source"] != source:
                    raise RecordError("source_mismatch", "pinned parser and source hint/detection disagree")
                if spec["source"] == "custom-json":
                    from .fields import leaf_paths
                    if leaf_paths(record) != spec["signature"]:
                        raise RecordError("signature_mismatch", "record fields differ from the approved sample")
                source = spec["source"]
            else:
                spec = self.registry.select(source, record)
            if spec is None:
                raise RecordError("unknown_format", "no approved parser; infer and validate a candidate first")
            index = self.config.routes.get(spec["source"])
            if index is None:
                raise RecordError("missing_route", "no output index configured for this source")
            event = normalize(record, spec, self.config, raw_text)
            doc_id = digest({"source": spec["source"], "schema_id": spec["id"],
                             "schema_version": spec["version"], "schema_hash": digest(spec),
                             "ecs_version": self.config.ecs_version,
                             "naive_timezone": self.config.naive_timezone,
                             "record": record})
            return {"status": "accepted", "source": spec["source"], "index": index,
                    "document_id": doc_id, "schema_id": spec["id"],
                    "schema_version": spec["version"], "event": event}
        except (RecordError, SchemaError) as exc:
            issue = exc.as_dict() if isinstance(exc, RecordError) else {
                "code": "schema_error", "field": None, "message": str(exc)}
            # Preserve the input text even when the input could not be decoded.
            return {"status": "quarantined", "source": source,
                    "schema_id": spec["id"] if spec else None,
                    "schema_version": spec["version"] if spec else None,
                    "errors": [issue], "raw_record": deepcopy(safe_record), "raw_text": raw_text}
