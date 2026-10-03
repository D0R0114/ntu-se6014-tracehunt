"""Streaming NDJSON input, durable quarantine, and explicit export formats."""

import json
import os
from pathlib import Path

from .errors import RecordError, SchemaError
from .fields import canonical_json


def _reject_constant(value):
    raise ValueError(f"non-finite JSON constant is not allowed: {value}")


def _unique_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON field: {key}")
        out[key] = value
    return out


def decode(text: str):
    return json.loads(text, parse_constant=_reject_constant, object_pairs_hook=_unique_keys)


def read_ndjson(path: str | Path):
    with Path(path).open(encoding="utf-8-sig") as stream:
        for line_number, text in enumerate(stream, 1):
            text = text.rstrip("\r\n")
            if not text.strip():
                continue
            try:
                yield line_number, text, decode(text), None
            except (ValueError, RecursionError) as exc:
                yield line_number, text, None, RecordError("invalid_json", str(exc))


def load_samples(path: str | Path) -> list[dict]:
    samples = []
    for number, _, record, issue in read_ndjson(path):
        if issue or not isinstance(record, dict):
            raise SchemaError(f"sample line {number} is not a valid JSON object")
        samples.append(record)
    if not samples:
        raise SchemaError("sample file is empty")
    return samples


def open_new_output(path: str | Path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Output replacement must be deliberate; repeated runs use a new directory.
    return path.open("x", encoding="utf-8", newline="\n")


def write_line(stream, value) -> None:
    stream.write(canonical_json(value) + "\n")


class QuarantineWriter:
    """Append-only JSONL failures. No records are silently discarded."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def append(self, failure: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            write_line(stream, failure)
            stream.flush()
            os.fsync(stream.fileno())
