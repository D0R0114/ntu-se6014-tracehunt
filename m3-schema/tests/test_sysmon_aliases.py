"""Native Sysmon provenance must retain the bundled parser's process aliases."""

from copy import deepcopy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaPipeline
from tracehunt_schema.classifier import classify
from tracehunt_schema.fields import MISSING, get_field

GUID = "{11111111-1111-1111-1111-111111111111}"
UTC_TIME = "2026-09-30 07:00:00.000"


def native_cases():
    return (
        ("flat-time", {"UtcTime": UTC_TIME}),
        ("flat-guid", {"ProcessGuid": GUID}),
        ("nested-time", {"winlog": {"event_data": {"UtcTime": UTC_TIME}}}),
        ("nested-guid", {"winlog": {"event_data": {"ProcessGuid": GUID}}}),
        ("dotted-time", {"winlog.event_data.UtcTime": UTC_TIME}),
        ("dotted-guid", {"winlog.event_data.ProcessGuid": GUID}),
        ("mixed-time", {"winlog.event_data": {"UtcTime": UTC_TIME}}),
        ("mixed-guid", {"winlog": {"event_data.ProcessGuid": GUID}}),
    )


def record_with(provenance, **fields):
    record = {"@timestamp": "2026-09-30T07:00:00Z", "event_id": 1, "host.name": "WS-01"}
    record.update(deepcopy(provenance))
    record.update(fields)
    return record


class NativeSysmonAliasTests(unittest.TestCase):
    def assert_entity_id(self, result, record):
        present = any(get_field(record, field) is not MISSING for field in
                      ("ProcessGuid", "winlog.event_data.ProcessGuid"))
        if present:
            self.assertEqual(get_field(result["event"], "process.entity_id"), GUID)

    def test_process_name_preserves_bundled_executable_and_entity_fields(self):
        for name, provenance in native_cases():
            with self.subTest(provenance=name):
                record = record_with(provenance, process_name="tool.exe")
                original = deepcopy(record)
                self.assertEqual(classify(record), "sysmon")
                batch = SchemaAgent().process_batch([record])
                self.assertEqual(batch["summary"], {"processed": 1, "accepted": 1,
                                                   "quarantined": 0, "created_schemas": 0})
                result = batch["results"][0]
                self.assertEqual((result["source"], result["schema_id"]), ("sysmon", "sysmon"))
                self.assertEqual(get_field(result["event"], "process.executable"), "tool.exe")
                self.assertEqual(get_field(result["event"], "process.name"), "tool.exe")
                self.assert_entity_id(result, record)
                self.assertEqual(record, original)
                self.assertEqual(batch["decisions"][0]["decision"], "reuse")

    def test_directory_only_process_name_is_quarantined_without_generation(self):
        for name, provenance in native_cases():
            for executable in ("C:\\Windows\\", "C:\\", "   "):
                with self.subTest(provenance=name, executable=executable):
                    record = record_with(provenance, process_name=executable)
                    batch = SchemaAgent().process_batch([record])
                    self.assertEqual(batch["summary"], {"processed": 1, "accepted": 0,
                                                       "quarantined": 1, "created_schemas": 0})
                    result = batch["results"][0]
                    self.assertEqual((result["source"], result["schema_id"]), ("sysmon", "sysmon"))
                    self.assertEqual(result["errors"][0]["code"], "invalid_field")
                    self.assertEqual(result["errors"][0]["field"], "process.executable")
                    self.assertEqual(result["raw_record"], record)

    def test_command_line_alone_preserves_fields_for_non_creation_events(self):
        for name, provenance in native_cases():
            with self.subTest(provenance=name):
                record = record_with(provenance, event_id=3, command_line="tool.exe --demo")
                self.assertEqual(classify(record), "sysmon")
                batch = SchemaAgent().process_batch([record])
                self.assertEqual(batch["summary"]["accepted"], 1)
                self.assertEqual(batch["summary"]["created_schemas"], 0)
                result = batch["results"][0]
                self.assertEqual(result["schema_id"], "sysmon")
                self.assertEqual(get_field(result["event"], "process.command_line"), "tool.exe --demo")
                self.assert_entity_id(result, record)

    def test_command_line_alone_cannot_bypass_creation_executable_requirement(self):
        for name, provenance in native_cases():
            with self.subTest(provenance=name):
                record = record_with(provenance, command_line="tool.exe --demo")
                batch = SchemaAgent().process_batch([record])
                self.assertEqual(batch["summary"]["quarantined"], 1)
                self.assertEqual(batch["summary"]["created_schemas"], 0)
                result = batch["results"][0]
                self.assertEqual(result["schema_id"], "sysmon")
                self.assertEqual(result["errors"][0]["code"], "missing_field")
                self.assertEqual(result["errors"][0]["field"], "process.executable")

    def test_both_generic_aliases_preserve_all_available_process_fields(self):
        for name, provenance in native_cases():
            with self.subTest(provenance=name):
                record = record_with(provenance, process_name="tool.exe", command_line="tool.exe --demo")
                result = SchemaPipeline().process(record)
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(result["schema_id"], "sysmon")
                self.assertEqual(get_field(result["event"], "process.executable"), "tool.exe")
                self.assertEqual(get_field(result["event"], "process.command_line"), "tool.exe --demo")
                self.assert_entity_id(result, record)

    def test_malformed_alias_does_not_stop_later_records_or_create_parsers(self):
        for name, provenance in native_cases():
            with self.subTest(provenance=name):
                good = record_with(provenance, process_name="tool.exe", command_line="tool.exe --demo")
                bad = dict(good, process_name="C:\\Windows\\")
                batch = SchemaAgent().process_batch([good, bad, deepcopy(good)])
                self.assertEqual(batch["summary"], {"processed": 3, "accepted": 2,
                                                   "quarantined": 1, "created_schemas": 0})
                self.assertEqual([row["status"] for row in batch["results"]],
                                 ["accepted", "quarantined", "accepted"])
                self.assertEqual(batch["results"][1]["errors"][0]["field"], "process.executable")
                self.assertEqual(batch["results"][0]["document_id"], batch["results"][2]["document_id"])

    def test_weak_aliases_and_event_number_still_do_not_establish_sysmon(self):
        for alias in ("process_name", "command_line"):
            for has_code in (True, False):
                with self.subTest(alias=alias, has_code=has_code):
                    record = record_with({}, **{alias: "tool.exe"})
                    if not has_code:
                        del record["event_id"]
                    self.assertIsNone(classify(record))
                    batch = SchemaAgent().process_batch([record])
                    self.assertEqual(batch["summary"]["accepted"], 1)
                    self.assertEqual(batch["results"][0]["source"], "custom-json")

    def test_frozen_agent_reuses_builtin_parser_for_native_generic_aliases(self):
        for name, provenance in native_cases():
            with self.subTest(provenance=name):
                record = record_with(provenance, process_name="tool.exe", command_line="tool.exe --demo")
                automatic = SchemaPipeline().process(record)
                pinned = SchemaPipeline().process(record, source_hint="sysmon")
                frozen = SchemaAgent(frozen=True).process_batch([record])
                self.assertEqual(automatic, pinned)
                self.assertEqual(frozen["summary"], {"processed": 1, "accepted": 1,
                                                    "quarantined": 0, "created_schemas": 0})
                self.assertEqual(frozen["results"][0], pinned)


if __name__ == "__main__":
    unittest.main()
