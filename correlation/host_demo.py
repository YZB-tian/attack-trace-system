"""Synthetic Windows/Linux acceptance fixtures; commands are data, never executed."""
import argparse
import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from common.models import NormalizedEvent
from .pipeline import analyze
from .validate_public_data import validate_and_write


def examples():
    encoded = base64.b64encode("Write-Output 'course-demo'".encode("utf-16-le")).decode()
    win = NormalizedEvent(event_id="evt_windows_positive", task_id="task_host_windows",
        timestamp="2026-09-10T10:00:00+08:00", source_type="host_log", source="sysmon",
        host_id="officepc01", user="lab_user", action="process_create",
        process={"pid": 1200, "name": "powershell.exe", "path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"},
        metadata={"command_line": f"powershell.exe -NoProfile -EncodedCommand {encoded}"},
        raw_event={"ProcessGuid": "synthetic-powershell-instance"}, labels=["synthetic"])
    linux = NormalizedEvent(event_id="evt_linux_positive", task_id="task_host_linux",
        timestamp="2026-09-10T10:01:00+08:00", source_type="host_log", source="auditd",
        host_id="coreserver01", user="lab_user", action="command_args",
        process={"name": "auditctl", "path": "/sbin/auditctl"},
        object={"type": "command", "name": "/sbin/auditctl -e 0"},
        metadata={"audit_type": "EXECVE", "audit_seq": "fixture-1"}, labels=["synthetic"])
    normal_win = win.model_copy(deep=True)
    normal_win.event_id, normal_win.task_id = "evt_windows_normal", "task_host_windows_normal"
    normal_win.metadata["command_line"] = "powershell.exe -NoProfile -Command Get-Date"
    normal_linux = linux.model_copy(deep=True)
    normal_linux.event_id, normal_linux.task_id = "evt_linux_normal", "task_host_linux_normal"
    normal_linux.object.name = "/sbin/auditctl -s"
    beacon = [NormalizedEvent(event_id=f"evt_beacon_{n:02}", task_id="task_graph_review",
        timestamp=(datetime(2026, 9, 10, tzinfo=timezone.utc) + timedelta(seconds=n * 60)).isoformat(),
        source_type="network_flow", source="zeek", host_id="officepc01",
        src_ip="10.10.2.50", src_port=40000+n, dst_ip="198.51.100.20", dst_port=443,
        action="network_connect", network={"protocol": "tcp", "bytes_out": 100,
        "bytes_in": 50, "session_id": f"session_{n}"}, raw_event={"orig_bytes": 100, "resp_bytes": 50},
        labels=["synthetic"]) for n in range(10)]
    return {"windows": ([win], ["HOST-WIN-POWERSHELL-ENCODED"]),
            "linux": ([linux], ["HOST-LINUX-AUDIT-DISABLE"]),
            "windows_normal": ([normal_win], []), "linux_normal": ([normal_linux], []),
            "beacon": (beacon, ["NET-BEACON"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("correlation/output/host_graph_demo"))
    args = parser.parse_args()
    report = {"synthetic": True, "commands_executed": False, "cases": {}}
    for name, (events, expected) in examples().items():
        result = analyze(events[0].task_id, events)
        actual = [a.rule_id for a in result[1]]
        if actual != expected:
            raise AssertionError((name, actual, expected))
        checks = validate_and_write(result, args.output / name)
        report["cases"][name] = {"task_id": events[0].task_id, "events": len(result[0]),
            "rules": actual, "nodes": len(result[2].nodes), "edges": len(result[2].edges),
            "stages": len(result[3].attack_chain), **checks}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
