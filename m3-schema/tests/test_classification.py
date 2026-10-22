"""Source provenance and custom-format fallback regression tests."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaPipeline, SchemaRegistry
from tracehunt_schema.classifier import classify
from tracehunt_schema.fields import get_field
from tracehunt_schema.io import load_samples


def custom_windows(code=4625):
    return {"@timestamp": "2026-09-30T07:00:00Z", "event_id": code,
            "host_name": "custom-system", "username": "alice"}


def custom_process():
    return {"@timestamp": "2026-09-30T07:00:00Z", "event_id": 1,
            "hostname": "custom-system", "command_line": "echo hello"}


class ProvenanceTests(unittest.TestCase):
    def test_windows_event_numbers_do_not_establish_windows_provenance(self):
        for field in ("event_id", "EventID", "event.code", "winlog.event_id"):
            for code in (4625, 4700, "004625"):
                with self.subTest(field=field, code=code):
                    record = custom_windows()
                    del record["event_id"]
                    record[field] = code
                    self.assertIsNone(classify(record))

    def test_sysmon_event_numbers_and_generic_process_fields_are_insufficient(self):
        for field in ("command_line", "process.command_line", "process.executable",
                      "process_name", "Image", "CommandLine"):
            with self.subTest(field=field):
                record = {"event_id": 1, field: "tool.exe"}
                self.assertIsNone(classify(record))

    def test_event_number_boundaries_never_select_a_parser_on_their_own(self):
        for code in (0, 1, 29, 30, 4599, 4600, 4700, 4999, 5000, True, 1.5, "broken"):
            with self.subTest(code=code):
                self.assertIsNone(classify({"event_id": code, "command_line": "echo hello"}))

    def test_generic_logon_type_does_not_establish_windows_provenance(self):
        record = dict(custom_windows(), logon_type=3)
        self.assertIsNone(classify(record))
        self.assertEqual(SchemaAgent().process_batch([record])["summary"]["accepted"], 1)

    def test_native_windows_field_names_keep_invalid_codes_on_known_parser(self):
        for field in ("TargetUserName", "LogonType", "winlog.event_data.TargetUserName"):
            with self.subTest(field=field):
                record = {"@timestamp": "2026-09-30T07:00:00Z", "host.name": "WS-01", field: "3"}
                self.assertEqual(classify(record), "windows-security")
                batch = SchemaAgent().process_batch([record])
                self.assertEqual(batch["summary"]["created_schemas"], 0)
                self.assertEqual(batch["results"][0]["errors"][0]["field"], "event.code")

    def test_invalid_connector_metadata_is_quarantined_without_generation(self):
        record = dict(custom_process(), source_type={"name": "sysmon"})
        batch = SchemaAgent().process_batch([record])
        self.assertEqual(batch["summary"]["created_schemas"], 0)
        self.assertEqual(batch["results"][0]["errors"][0]["field"], "source_type")

    def test_explicit_provider_channel_and_dataset_select_known_sources(self):
        markers = (
            ("event.provider", "Microsoft-Windows-Security-Auditing", "windows-security"),
            ("winlog.provider_name", "Microsoft-Windows-Security-Auditing", "windows-security"),
            ("winlog.channel", "Security", "windows-security"),
            ("event.dataset", "windows.security", "windows-security"),
            ("event.provider", "Microsoft-Windows-Sysmon", "sysmon"),
            ("winlog.channel", "Microsoft-Windows-Sysmon/Operational", "sysmon"),
            ("event.dataset", "sysmon.events", "sysmon"),
            ("event.dataset", "zeek.conn", "zeek"),
        )
        for field, value, expected in markers:
            with self.subTest(field=field, value=value):
                self.assertEqual(classify({field: value.upper()}), expected)

    def test_connector_source_type_is_explicit_provenance(self):
        for source in ("windows-security", "sysmon", "zeek", "custom-json"):
            with self.subTest(source=source):
                self.assertEqual(classify(dict(custom_process(), source_type=source)), source)
        self.assertIsNone(classify(dict(custom_process(), source_type="application")))

    def test_lookalike_metadata_does_not_establish_known_provenance(self):
        markers = (
            ("event.provider", "my-sysmon-service"),
            ("event.provider", "Microsoft-Windows-Sysmon-Clone"),
            ("event.provider", "Security-Auditing-custom"),
            ("winlog.channel", "Custom-Sysmon-Log"),
            ("event.dataset", "sysmonish.events"),
            ("event.dataset", "zeekish.http"),
        )
        for field, value in markers:
            with self.subTest(field=field, value=value):
                self.assertIsNone(classify(dict(custom_process(), **{field: value})))

    def test_source_hint_takes_priority_over_record_metadata(self):
        record = dict(custom_process(), source_type="sysmon", **{"event.dataset": "sysmon.events"})
        self.assertEqual(classify(record, "custom-json"), "custom-json")
        self.assertEqual(classify(record, "windows-security"), "windows-security")

    def test_native_flat_sysmon_signatures_still_select_the_builtin_parser(self):
        for record in load_samples(ROOT / "fixtures/sysmon-flat.ndjson"):
            with self.subTest(code=record["EventID"]):
                result = SchemaPipeline().process(record)
                self.assertEqual(result["status"], "accepted")
                self.assertEqual(result["schema_id"], "sysmon")

    def test_malformed_flat_sysmon_stays_on_known_validation_path(self):
        record = load_samples(ROOT / "fixtures/sysmon-flat.ndjson")[0]
        del record["Image"]
        batch = SchemaAgent().process_batch([record])
        self.assertEqual(batch["summary"]["created_schemas"], 0)
        self.assertEqual(batch["decisions"][0]["decision"], "reuse")
        self.assertEqual(batch["results"][0]["errors"][0]["field"], "process.executable")

    def test_invalid_known_event_code_cannot_trigger_custom_generation(self):
        record = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        record["event_id"] = "broken"
        batch = SchemaAgent().process_batch([record])
        self.assertEqual(batch["summary"]["created_schemas"], 0)
        self.assertEqual(batch["decisions"][0]["decision"], "reuse")
        self.assertEqual(batch["results"][0]["errors"][0]["field"], "event.code")

    def test_known_provenance_does_not_bypass_missing_required_fields(self):
        for record, source in ((custom_windows(), "windows-security"), (custom_process(), "sysmon")):
            with self.subTest(source=source):
                batch = SchemaAgent().process_batch([dict(record, source_type=source)])
                self.assertEqual(batch["summary"]["created_schemas"], 0)
                self.assertEqual(batch["results"][0]["status"], "quarantined")
                self.assertEqual(batch["results"][0]["errors"][0]["field"], "host.name")


class CustomFallbackTests(unittest.TestCase):
    def test_reported_windows_lookalikes_are_onboarded_without_a_hint(self):
        records = [custom_windows(4625), custom_windows(4700)]
        batch = SchemaAgent().process_batch(records)
        self.assertEqual(batch["summary"], {"processed": 2, "accepted": 2,
                                           "quarantined": 0, "created_schemas": 1})
        for record, result in zip(records, batch["results"]):
            self.assertEqual(result["source"], "custom-json")
            self.assertEqual(get_field(result["event"], "host.name"), "custom-system")
            self.assertEqual(get_field(result["event"], "user.name"), "alice")
            self.assertEqual(get_field(result["event"], "event.code"), str(record["event_id"]))

    def test_reported_process_lookalike_is_onboarded_without_a_hint(self):
        batch = SchemaAgent().process_batch([custom_process()])
        self.assertEqual(batch["summary"]["accepted"], 1)
        result = batch["results"][0]
        self.assertEqual(result["source"], "custom-json")
        self.assertEqual(get_field(result["event"], "process.command_line"), "echo hello")
        self.assertEqual(get_field(result["event"], "host.name"), "custom-system")
        self.assertEqual(get_field(result["event"], "event.code"), "1")

    def test_plain_pipeline_quarantines_unregistered_custom_format_as_unknown(self):
        for record in (custom_windows(), custom_process()):
            with self.subTest(record=record):
                result = SchemaPipeline().process(record)
                self.assertEqual(result["status"], "quarantined")
                self.assertEqual(result["errors"][0]["code"], "unknown_format")

    def test_registered_custom_parser_is_reused_after_restart_in_frozen_mode(self):
        with tempfile.TemporaryDirectory() as folder:
            records = [custom_windows(), custom_windows(4700), custom_process()]
            initial = SchemaAgent(SchemaRegistry(folder)).process_batch(records)
            frozen = SchemaAgent(SchemaRegistry(folder), frozen=True).process_batch(records)
            self.assertEqual(initial["summary"]["created_schemas"], 2)
            self.assertEqual(frozen["summary"]["created_schemas"], 0)
            self.assertEqual(frozen["summary"]["accepted"], 3)
            self.assertEqual(initial["results"], frozen["results"])

    def test_mixed_known_and_custom_formats_keep_order_and_existing_parsers(self):
        known = load_samples(ROOT / "fixtures/known-mixed.ndjson")[0]
        records = [custom_windows(), known, custom_process(), deepcopy(known)]
        original = deepcopy(records)
        registry = SchemaRegistry()
        definitions = registry.list_schemas()
        batch = SchemaAgent(registry).process_batch(records)
        self.assertEqual(batch["summary"]["accepted"], 4)
        self.assertEqual([row["source"] for row in batch["results"]],
                         ["custom-json", "windows-security", "custom-json", "windows-security"])
        self.assertEqual(records, original)
        for definition in definitions:
            self.assertEqual(registry.get_schema(definition["id"], definition["version"]), definition)

    def test_ambiguous_custom_event_code_aliases_require_review(self):
        record = dict(custom_windows(), code=4700)
        batch = SchemaAgent().process_batch([record])
        self.assertEqual(batch["summary"]["created_schemas"], 0)
        self.assertEqual(batch["results"][0]["errors"][0]["code"], "candidate_failed")

    def test_cli_onboarding_and_frozen_replay_cover_all_reported_examples(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            runs = []
            for name, extra in (("first", []), ("frozen", ["--frozen"])):
                command = [sys.executable, "-m", "tracehunt_schema", "onboard",
                           "--input", str(ROOT / "fixtures/custom-lookalikes.ndjson"),
                           "--registry", str(path / "registry"),
                           "--output", str(path / f"{name}.jsonl"),
                           "--quarantine", str(path / f"{name}-quarantine.jsonl"),
                           "--audit", str(path / f"{name}-audit.jsonl"), *extra]
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["accepted"], 3)
                runs.append((path / f"{name}.jsonl").read_bytes())
            self.assertEqual(runs[0], runs[1])


if __name__ == "__main__":
    unittest.main()
