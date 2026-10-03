"""Schema configuration for ECS version, timestamp handling, and output routes."""

from dataclasses import dataclass, field
import json
from pathlib import Path
import re

from .errors import SchemaError


@dataclass(frozen=True)
class Config:
    ecs_version: str = "8.11.0"
    naive_timezone: str | None = None
    routes: dict[str, str] = field(default_factory=lambda: {
        "windows-security": "windows-security",
        "sysmon": "sysmon",
        "zeek": "zeek",
        "custom-json": "custom-json",
    })

    def __post_init__(self):
        if not re.fullmatch(r"\d+\.\d+\.\d+", self.ecs_version):
            raise SchemaError("ecs_version must be a three-part version")
        if self.naive_timezone is not None and not re.fullmatch(
            r"[+-](?:0\d|1[0-3]):[0-5]\d|[+-]14:00", self.naive_timezone
        ):
            raise SchemaError("naive_timezone must be null or an offset such as +08:00")
        if not isinstance(self.routes, dict) or not self.routes:
            raise SchemaError("routes must be a non-empty object")
        for source, index in self.routes.items():
            if not isinstance(source, str) or not isinstance(index, str) or not re.fullmatch(
                r"[a-z0-9][a-z0-9_-]{0,127}", index
            ):
                raise SchemaError("routes must map source names to concrete lowercase indices")

    @classmethod
    def load(cls, path: str | Path | None = None):
        if path is None:
            return cls()
        return cls(**json.loads(Path(path).read_text(encoding="utf-8")))
