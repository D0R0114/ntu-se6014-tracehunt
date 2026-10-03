"""Conservative source detection; connector-provided source hints take priority."""

from .fields import get_field, MISSING
from .errors import RecordError

SOURCES = ("windows-security", "sysmon", "zeek", "custom-json")


def classify(record: dict, source_hint: str | None = None) -> str | None:
    if source_hint is not None:
        if source_hint not in SOURCES:
            raise RecordError("invalid_source", f"source must be one of {SOURCES}")
        return source_hint

    provider = str(get_field(record, "winlog.provider_name", ""))
    provider += " " + str(get_field(record, "event.provider", ""))
    channel = str(get_field(record, "winlog.channel", "")).lower()
    dataset = str(get_field(record, "event.dataset", "")).lower()
    if "sysmon" in provider.lower() or "sysmon" in channel or dataset.startswith("sysmon"):
        return "sysmon"
    if channel == "security" or "security-auditing" in provider.lower() or dataset == "windows.security":
        return "windows-security"
    if dataset.startswith("zeek.") or record.get("log_type") in ("conn", "dns", "http"):
        return "zeek"
    if get_field(record, "id.orig_h") is not MISSING and get_field(record, "id.resp_h") is not MISSING:
        return "zeek"

    event_code = get_field(record, "event.code", record.get("event_id", MISSING))
    if event_code is MISSING:
        event_code = get_field(record, "winlog.event_id")
    try:
        code = int(event_code)
    except (TypeError, ValueError):
        return None
    if 4600 <= code <= 4999:
        return "windows-security"
    if 1 <= code <= 29 and any(get_field(record, field) is not MISSING for field in (
        "process.executable", "process_name", "winlog.event_data.Image", "command_line"
    )):
        return "sysmon"
    return None
