"""Import the kernel-level monitoring bundle from the Ubuntu DMZ host.

The evidence was produced with bpftrace tracepoints on real syscalls
(execve, openat, connect, sendto) during a controlled, authorized
post-exploitation sequence. Monotonic nsecs values are anchored to the host
boot time recorded in boot.txt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collectors.linux import normalize_linux_records  # noqa: E402
from common.models import NormalizedEvent  # noqa: E402
from correlation.pipeline import analyze  # noqa: E402
from detection.attack_stix import AttackKnowledge  # noqa: E402

TRACE = re.compile(r"^(exec|open|connect|sendto)\|(\d+)\|(\d+)\|([^|]*)(?:\|(.*))?$")


def read_boot_time(path: Path) -> float:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("btime"):
            return float(line.split()[1])
    raise ValueError("boot.txt has no btime line")


def stamp(event: NormalizedEvent, task: str, name: str, index: int, run: str) -> None:
    event.event_id = "evt_" + hashlib.sha256(f"{task}|{name}|{index}".encode()).hexdigest()[:24]
    event.task_id = task
    event.labels = sorted(set(event.labels + ["real_lab", "real_observation"]))
    event.metadata.update(classification="real_observation", run_id=run, source="bpftrace",
                          raw_reference={"file": name, "record": index})


def trace_events(path: Path, task: str, run: str, boot: float, name: str) -> list:
    out = []
    for index, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        match = TRACE.match(line.strip())
        if not match:
            continue
        kind, millis, pid, comm, rest = match.groups()
        rest = rest or ""
        timestamp = datetime.fromtimestamp(boot + int(millis) / 1000.0, timezone.utc).isoformat()
        process = {"pid": int(pid), "name": comm or None}
        base = dict(event_id="evt_pending", task_id=task, timestamp=timestamp,
                    source_type="host_behavior", source="bpftrace", host_id="webserver01",
                    process=process, raw_event={"raw": line.strip()})
        if kind == "exec":
            # execve is the process-creation boundary; the correlation layer uses
            # this action to anchor a PID's lifetime when no GUID is available.
            event = NormalizedEvent(**base, action="process_create",
                                    object={"type": "file", "name": Path(rest).name, "path": rest},
                                    labels=["host_behavior", "process", "syscall"],
                                    metadata={"syscall": "execve", "executable": rest,
                                              "event_type": "process_create"})
        elif kind == "open":
            event = NormalizedEvent(**base, action="file_access",
                                    object={"type": "file", "name": Path(rest).name, "path": rest},
                                    labels=["host_behavior", "file", "syscall"],
                                    metadata={"syscall": "openat", "path": rest})
        elif kind == "connect":
            fields = rest.split("|")
            dst_ip = fields[0] if fields and fields[0] not in ("", "other") else None
            dst_port = int(fields[1]) if dst_ip and len(fields) > 1 else None
            event = NormalizedEvent(**base, action="network_connect", dst_ip=dst_ip, dst_port=dst_port,
                                    labels=["host_behavior", "network", "syscall"],
                                    network={"protocol": "tcp"} if dst_ip else None,
                                    metadata={"syscall": "connect", "address_family": "inet" if dst_ip else "other"})
        else:
            event = NormalizedEvent(**base, action="network_write",
                                    labels=["host_behavior", "network", "syscall"],
                                    metadata={"syscall": "sendto", "bytes": int(rest or 0)})
        stamp(event, task, name, index, run)
        out.append(event)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stix", type=Path)
    args = parser.parse_args()

    raw = args.evidence_dir / "raw"
    boot = read_boot_time(raw / "boot.txt")
    task, run = args.task_id, args.run_id
    events = trace_events(raw / "kernel-trace.log", task, run, boot, "kernel-trace.log")

    auth = raw / "web-auth.log"
    if auth.exists():
        for index, line in enumerate(auth.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            for event in normalize_linux_records([line], task, tz_offset_hours=0, year=2026):
                event.host_id = "webserver01"
                stamp(event, task, "web-auth.log", index, run)
                events.append(event)

    c2 = raw / "c2-events.jsonl"
    if c2.exists():
        for index, line in enumerate(c2.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            if (record.get("payload") or {}).get("run_id") != run:
                continue
            event = NormalizedEvent(
                event_id="evt_pending", task_id=task,
                timestamp=datetime.fromisoformat(record["timestamp"]).astimezone(timezone.utc).isoformat(),
                source_type="boundary_log", source="c2_receiver", host_id="c2server01",
                src_ip=record.get("source_ip"), dst_ip="192.168.56.40", dst_port=8080,
                action="data_transfer_received", raw_event=record, labels=["c2", "receiver_side"],
                network={"protocol": "tcp", "direction": "inbound"},
                metadata={"path": record.get("path"), "payload": record.get("payload")})
            stamp(event, task, "c2-events.jsonl", index, run)
            events.append(event)

    unique = {}
    for event in events:
        unique[event.event_id] = event
    events = sorted(unique.values(), key=lambda e: (e.timestamp, e.event_id))
    knowledge = AttackKnowledge(args.stix) if args.stix else None
    normalized, alerts, graph, trace = analyze(task, events, knowledge=knowledge)

    args.output.mkdir(parents=True, exist_ok=True)
    for value, name in ((normalized, "normalized_events"), (alerts, "alerts"),
                        ([graph], "attack_graph"), ([trace], "trace_result")):
        data = [v.model_dump(mode="json") for v in value]
        (args.output / (name + ".json")).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "task_id": task,
        "events": len(normalized),
        "alerts": [a.rule_id for a in alerts],
        "graph_nodes": len(graph.nodes),
        "stages": [f"{s.tactic}:{s.technique_id or 'unmapped'}" for s in (trace.attack_chain or [])],
        "path_analysis": {k: len(v) for k, v in trace.attribution["path_analysis"].items()},
        "data_paths": len(trace.attribution["data_access_to_network_candidates"]),
    }, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
