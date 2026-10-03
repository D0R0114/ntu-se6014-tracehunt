"""Helpers for both nested JSON and literal dotted field names."""

import hashlib
import json

MISSING = object()


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def get_field(record: dict, path: str, default=MISSING):
    current = record
    parts = path.split(".")
    for position, part in enumerate(parts):
        if not isinstance(current, dict):
            return default
        # Zeek uses keys such as id.orig_h. ECS input may also be dotted.
        remainder = ".".join(parts[position:])
        if remainder in current:
            return current[remainder]
        if part not in current:
            return default
        current = current[part]
    return current


def set_field(record: dict, path: str, value) -> None:
    parts = path.split(".")
    current = record
    for part in parts[:-1]:
        if part not in current:
            current[part] = {}
        if not isinstance(current[part], dict):
            raise ValueError(f"field path conflicts with a scalar: {path}")
        current = current[part]
    current[parts[-1]] = value


def leaf_paths(record: dict, prefix: str = "") -> list[str]:
    paths = []
    for key, value in record.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict) and value:
            paths.extend(leaf_paths(value, path))
        else:
            paths.append(path)
    return sorted(paths)
