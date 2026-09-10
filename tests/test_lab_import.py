import hashlib
import json
from pathlib import Path
import pytest


def bundle(path):
    files = {
        "manifest.json": {"run_id": "course_test", "classification": "controlled_emulation", "started_utc": "2026-09-10T13:34:50Z"},
        "office-timeline.json": [{"TimeUtc": "2026-09-10T13:35:15Z", "Stage": "complete"}],
        "firewall-live-raw.json": [{"__timestamp__": "2026-09-10T21:35:11", "action": "block", "src": "192.168.70.20", "dst": "192.168.80.60", "srcport": "12345", "dstport": "3389", "protoname": "tcp"}],
        "office-security.json": [{"timestamp": "2026-09-10T13:35:00Z", "event_id": 4663, "record_id": 44, "host": "officepc01", "fields": {"ObjectName": "C:\\lab.txt"}}],
    }
    for name, data in files.items():
        (path / name).write_text(json.dumps(data), encoding="utf-8")
    (path / "web-events.jsonl").write_text('\n'.join(json.dumps(x) for x in [
        {"timestamp": "2026-09-10T20:00:00+0800", "event": "login_attempt", "success": True},
        {"timestamp": "2026-09-10T21:34:51+0800", "event": "login_attempt", "success": False, "source_ip": "192.168.56.10"}]), encoding="utf-8")
    seal(path)


def seal(path):
    manifest = [{"file": p.name, "bytes": p.stat().st_size, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in path.iterdir() if p.name != "sha256-manifest.json"]
    (path / "sha256-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def loader():
    import importlib.util
    assert importlib.util.find_spec("collectors.lab") is not None, "lab importer missing"
    from collectors.lab import import_bundle
    return import_bundle


def test_verified_bounded_import(tmp_path):
    bundle(tmp_path)
    events, report = loader()(tmp_path)
    assert len(events) == 3
    assert report["excluded_outside_window"] == 1
    boundary = next(e for e in events if e.source == "opnsense")
    assert boundary.timestamp == "2026-09-10T13:35:11+00:00"
    assert boundary.action == "firewall_block"
    assert all(e.metadata["classification"] == "controlled_emulation" for e in events)
    assert all(e.metadata["raw_reference"]["sha256"] for e in events)
    assert events == loader()(tmp_path)[0]


def test_hash_tamper_rejected(tmp_path):
    bundle(tmp_path)
    (tmp_path / "office-security.json").write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="hash|integrity"):
        loader()(tmp_path)


def test_manifest_traversal_rejected(tmp_path):
    bundle(tmp_path)
    (tmp_path / "sha256-manifest.json").write_text('[{"file":"../outside","bytes":0,"sha256":"bad"}]')
    with pytest.raises(ValueError, match="path"):
        loader()(tmp_path)


def test_unhashed_file_rejected(tmp_path):
    bundle(tmp_path)
    (tmp_path / "core-security.json").write_text("[]")
    with pytest.raises(ValueError, match="manifest"):
        loader()(tmp_path)


def test_pcap_and_strace_are_observations(tmp_path):
    from scapy.all import Ether, IP, TCP, wrpcap
    bundle(tmp_path)
    packet = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.168.70.20", dst="192.168.80.60")/TCP(sport=40000, dport=3389, flags="S")
    packet.time = 1789047301
    wrpcap(str(tmp_path / "office-network.pcap"), [packet, packet])
    (tmp_path / "web-syscalls.strace").write_text('2326  1789047296.672874 execve("/usr/bin/python3", ["python3"], 0x0) = 0\n2326  1789047296.673387 access("/missing", R_OK) = -1 ENOENT\n')
    seal(tmp_path)
    events, report = loader()(tmp_path)
    flows = [e for e in events if e.source == "pcap_scapy"]
    assert len(flows) == 1
    assert flows[0].action == "network_observed"
    assert flows[0].metadata["packets"] == 2
    assert flows[0].metadata["connection_success_proven"] is False
    calls = [e for e in events if e.source == "strace"]
    assert len(calls) == 2
    assert calls[0].action == "process_exec"
    assert calls[0].process.pid == 2326
    assert calls[1].action == "syscall"
    assert calls[1].metadata["success"] is False


def test_trace_declares_emulation():
    from common.models import NormalizedEvent
    from correlation.pipeline import analyze
    e = NormalizedEvent(event_id="evt_emulation", task_id="task_lab", timestamp="2026-09-10T13:35:00Z",
        source_type="host_log", source="test", action="file_access", metadata={"classification": "controlled_emulation"})
    trace = analyze("task_lab", [e])[3]
    assert trace.attribution["data_classification"] == ["controlled_emulation"]
    assert "controlled" in trace.summary.lower()
