"""Replay unmodified M2 connectors into M3, or validate supplied TCP captures.

Replay sources, simulated metadata, and completed checks are recorded in the
report. The receiver uses a temporary loopback TCP endpoint.
"""

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
M2 = REPO / "m2-connectors"
sys.path.insert(0, str(ROOT))

from tracehunt_schema import SchemaAgent, SchemaPipeline
from tracehunt_schema.fields import get_field
from tracehunt_schema.io import load_samples

SOURCES = ("windows-security", "sysmon", "zeek")


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_rows(path, rows):
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


class TcpCapture:
    """Bounded loopback recorder; it never connects to a shared Logstash."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.lines = []
        self.errors = []
        self.received = threading.Condition()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.receive, daemon=True)

    def receive(self):
        try:
            while not self.stop.is_set():
                try:
                    client, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with client:
                    client.settimeout(5)
                    with client.makefile("rb") as stream:
                        for line in stream:
                            with self.received:
                                self.lines.append(line.rstrip(b"\r\n").decode("utf-8"))
                                self.received.notify_all()
        except Exception as exc:
            self.errors.append(str(exc))

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(timeout=6)
        self.listener.close()
        require(not self.thread.is_alive(), "TCP capture did not stop")
        require(not self.errors, f"TCP capture failed: {self.errors}")


def run_connector(shell, script, directory, output, source, expected_count, extra=()):
    with TcpCapture() as capture:
        command = [shell, "-NoProfile", "-NonInteractive", "-File", str(script)]
        if source == "sysmon":
            command += ["-Connector", str(directory / "sysmon-push/sysmon_push.ps1"),
                        "-Sample", str(M2 / "samples/sysmon/sysmon_sample.ndjson"),
                        "-Port", str(capture.port)]
        else:
            command += ["-LogstashHost", "127.0.0.1", "-LogstashPort", str(capture.port), *extra]
        completed = subprocess.run(command, cwd=directory, capture_output=True, timeout=45,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        (output / f"{source}-connector.txt").write_text(
            completed.stdout.decode("utf-8", errors="replace") +
            completed.stderr.decode("utf-8", errors="replace"), encoding="utf-8")
        require(completed.returncode == 0, f"{source} connector exited with {completed.returncode}")
        # The connector closes its TCP connections before exiting. Allow the
        # recorder to drain buffered connections before stopping it.
        with capture.received:
            require(capture.received.wait_for(lambda: len(capture.lines) >= expected_count, timeout=5),
                    f"{source} emitted fewer than {expected_count} records")
    require(capture.lines, f"{source} connector emitted no records")
    return capture.lines


def replay(output):
    shell = shutil.which("pwsh") or shutil.which("powershell.exe")
    require(shell is not None, "PowerShell is required for connector replay")
    connector_paths = ("common/m3_adapter.ps1", "windows-pull/windows_pull.ps1",
                       "sysmon-push/sysmon_push.ps1", "zeek-stream/zeek_stream.ps1")
    source_paths = [M2 / path for path in connector_paths]
    source_paths += [M2 / "samples/windows/windows_security_sample.ndjson",
                     M2 / "samples/sysmon/sysmon_sample.ndjson", ROOT / "fixtures/zeek.ndjson",
                     ROOT / "tests/replay_sysmon.ps1"]
    for path in source_paths:
        require(path.is_file(), f"Missing replay input: {path}")
    origins = {
        "windows-security": "Repository Windows sample replayed through the M2 NDJSON pull connector.",
        "sysmon": "Repository Sysmon sample replayed through M2; Get-WinEvent, RecordId, provider, and host metadata are simulated.",
        "zeek": "Synthetic M3 conn/DNS/HTTP fixtures replayed through the M2 Zeek stream connector.",
    }
    captures = {}
    with tempfile.TemporaryDirectory(prefix="connector-", dir=output) as folder:
        directory = Path(folder)
        for relative in connector_paths:
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(M2 / relative, target)
        drop = directory / "windows-pull/drop"
        drop.mkdir()
        shutil.copyfile(source_paths[4], drop / "security.ndjson")
        windows_count = len(load_samples(source_paths[4]))
        captures["windows-security"] = run_connector(
            shell, directory / "windows-pull/windows_pull.ps1", directory, output, "windows-security", windows_count)
        require(len(captures["windows-security"]) == windows_count, "Windows replay record count changed")
        captures["sysmon"] = run_connector(shell, ROOT / "tests/replay_sysmon.ps1",
                                            directory, output, "sysmon", 1)
        require(len(captures["sysmon"]) == 1, "Sysmon sample replay must emit exactly one record")
        zeek_input = directory / "zeek-stream/input"
        zeek_input.mkdir()
        for kind, record in zip(("conn", "dns", "http"), load_samples(ROOT / "fixtures/zeek.ndjson")):
            write_rows(zeek_input / f"{kind}.log", [record])
        captures["zeek"] = run_connector(shell, directory / "zeek-stream/zeek_stream.ps1",
                                          directory, output, "zeek", 3, ["-Once", "-RetryCount", "1"])
        require(len(captures["zeek"]) == 3, "Zeek replay must emit conn, DNS, and HTTP records")
    hashes = {path.relative_to(REPO).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in source_paths}
    return captures, origins, hashes


def validate_source(source, lines, output, replay_mode):
    require(bool(lines), f"No records supplied for {source}")
    pipeline = SchemaPipeline()
    records = [json.loads(line) for line in lines]
    results = []
    for record, line in zip(records, lines):
        # Intentionally omit source_hint so connector provenance is tested.
        result = pipeline.process(record, raw_text=line)
        require(result["status"] == "accepted", f"{source} validation failed: {result.get('errors')}")
        require(result["source"] == source and result["schema_id"] == source, f"Wrong parser for {source}")
        require(result["index"] == source, f"Wrong output index for {source}")
        require(get_field(result["event"], "event.original") == line, "Original TCP payload was not retained")
        if replay_mode and source in ("windows-security", "sysmon"):
            require(get_field(result["event"], "host.name") == get_field(record, "host.name"), "Computer name changed")
            require(get_field(result["event"], "event.code") == str(int(get_field(record, "event.code"))), "Event code changed")
        if replay_mode and source == "windows-security":
            require(get_field(result["event"], "user.name") == get_field(record, "winlog.event_data.TargetUserName"), "Logon username changed")
            require(get_field(result["event"], "source.ip") == get_field(record, "winlog.event_data.IpAddress"), "Logon source IP changed")
        elif replay_mode and source == "sysmon":
            require(get_field(result["event"], "process.executable") == get_field(record, "winlog.event_data.Image"), "Executable changed")
            require(get_field(result["event"], "process.command_line") == get_field(record, "winlog.event_data.CommandLine"), "Command line changed")
        elif replay_mode:
            require(get_field(result["event"], "source.ip") == record["id.orig_h"], "Zeek origin IP changed")
            require(get_field(result["event"], "destination.ip") == record["id.resp_h"], "Zeek destination IP changed")
            if record["log_type"] == "http":
                require("host" not in result["event"], "HTTP Host was mapped to a computer name")
                require(get_field(result["event"], "url.domain") == record["host"].split(":")[0], "HTTP domain changed")
        results.append(result)
    frozen = SchemaAgent(frozen=True).process_batch(records, raw_texts=lines)
    require(frozen["results"] == results, "Frozen agent changed normalized output or document IDs")
    require(frozen["summary"]["created_schemas"] == 0, "Known connector formats generated a replacement parser")

    bad = deepcopy(records[0])
    if source in ("windows-security", "sysmon"):
        bad["host"] = {"name": "   "}
    else:
        bad["destination.port"] = 65536
    mixed = SchemaAgent().process_batch([records[0], bad, records[-1]])
    require([row["status"] for row in mixed["results"]] == ["accepted", "quarantined", "accepted"],
            f"Invalid {source} record was not isolated")
    require(mixed["summary"]["created_schemas"] == 0, "Invalid connector data triggered parser generation")
    require(mixed["results"][1]["raw_record"] == bad, "Quarantine did not preserve the failed connector record")

    (output / f"{source}.ndjson").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_rows(output / f"{source}-accepted.jsonl", results)
    write_rows(output / f"{source}-quarantine-probe.jsonl", [mixed["results"][1]])
    return {"processed": len(results), "accepted": len(results), "quarantined": 0,
            "frozen_replay_identical": True, "invalid_record_isolated": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "output/m2-integration")
    parser.add_argument("--capture-dir", type=Path,
                        help="Validate windows-security.ndjson, sysmon.ndjson, and zeek.ndjson from this directory instead of replaying connectors.")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {"mode": "supplied-captures" if args.capture_dir else "connector-replay", "passed": False}
    try:
        if args.capture_dir:
            paths = {source: args.capture_dir / f"{source}.ndjson" for source in SOURCES}
            captures = {source: [line for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
                        for source, path in paths.items()}
            origins = {source: "Caller-supplied connector capture." for source in SOURCES}
            hashes = {str(path.resolve()): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths.values()}
        else:
            captures, origins, hashes = replay(output)
        report.update(origins=origins, input_sha256=hashes)
        report["sources"] = {source: validate_source(source, captures[source], output, not args.capture_dir)
                             for source in SOURCES}
        report["passed"] = True
        report["completed_checks"] = ["Automatic source detection and bundled parser selection",
                                      "Index routing and original TCP payload retention",
                                      "Identical frozen replay and stable document IDs",
                                      "Invalid-record isolation without replacement parsers"]
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
