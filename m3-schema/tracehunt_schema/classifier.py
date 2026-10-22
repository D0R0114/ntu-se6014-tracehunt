"""Conservative source detection; connector-provided source hints take priority."""

from .fields import get_field, MISSING
from .errors import RecordError

SOURCES = ("windows-security", "sysmon", "zeek", "custom-json")


def metadata_text(record: dict, field: str) -> str:
    value = get_field(record, field, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RecordError("invalid_field", "source metadata must be a string", field)
    return value.strip()


def classify(record: dict, source_hint: str | None = None) -> str | None:
    if source_hint is not None:
        if source_hint not in SOURCES:
            raise RecordError("invalid_source", f"source must be one of {SOURCES}")
        return source_hint

    providers = {metadata_text(record, field).lower() for field in (
        "winlog.provider_name", "event.provider"
    )}
    channel = metadata_text(record, "winlog.channel").lower()
    dataset = metadata_text(record, "event.dataset").lower()
    declared_source = metadata_text(record, "source_type")
    if declared_source in SOURCES:
        return declared_source
    if providers & {"microsoft-windows-sysmon", "sysmon"} or channel == "microsoft-windows-sysmon/operational" or (
        dataset == "sysmon" or dataset.startswith("sysmon.")
    ):
        return "sysmon"
    if channel == "security" or dataset == "windows.security" or providers & {
        "microsoft-windows-security-auditing", "security-auditing"
    }:
        return "windows-security"
    if dataset.startswith("zeek.") or record.get("log_type") in ("conn", "dns", "http"):
        return "zeek"
    if get_field(record, "id.orig_h") is not MISSING and get_field(record, "id.resp_h") is not MISSING:
        return "zeek"
    if "log_type" in record and any(get_field(record, field) is not MISSING for field in (
        "source.ip", "src_ip"
    )) and any(get_field(record, field) is not MISSING for field in ("destination.ip", "dst_ip")):
        return "zeek"
    # Distinctive source fields still identify malformed known records. They
    # must fail the bundled parser instead of onboarding as a custom format.
    if any(get_field(record, field) is not MISSING for field in (
        "UtcTime", "winlog.event_data.UtcTime", "ProcessGuid", "winlog.event_data.ProcessGuid"
    )) and any(
        get_field(record, field) is not MISSING for field in (
            "Image", "winlog.event_data.Image", "process.executable", "process_name",
            "CommandLine", "winlog.event_data.CommandLine", "process.command_line", "command_line"
        )
    ):
        return "sysmon"
    if any(get_field(record, field) is not MISSING for field in (
        "winlog.event_data.TargetUserName", "TargetUserName", "winlog.event_data.LogonType", "LogonType"
    )):
        return "windows-security"

    # Event numbers and generic process fields also occur in custom applications.
    # Without provenance, leave the format available for reviewed onboarding.
    return None
