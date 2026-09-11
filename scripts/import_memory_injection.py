"""Import the Windows memory-injection bundle collected with Sysmon.

Sysmon event 8 (CreateRemoteThread) and event 10 (ProcessAccess) are the
observable traces of process-memory manipulation; event 1 anchors the process
that performed it. Nothing is inferred beyond those records.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.models import NormalizedEvent  # noqa: E402
from correlation.pipeline import analyze  # noqa: E402
from detection.attack_stix import AttackKnowledge  # noqa: E402

WRITE_ACCESS_BITS = (0x0020, 0x0008, 0x0002, 0x001F0FFF, 0x1F3FFF, 0x1F0FFF)


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def base_name(value):
    return value.rsplit("\\", 1)[-1] if value else None


def build_event(record, task, run, index):
    data = record.get("data") or {}
    event_id = record["event_id"]
    common = dict(
        event_id="evt_pending",
        task_id=task,
        timestamp=utc(record["time_utc"]).isoformat(),
        source_type="host_behavior",
        source="sysmon",
        host_id="coreserver01",
        user=data.get("User"),
        raw_event=record,
    )
    if event_id == 1:
        image = data.get("Image")
        return NormalizedEvent(
            **common, action="process_create",
            process={"pid": int(data["ProcessId"]) if data.get("ProcessId") else None,
                     "ppid": int(data["ParentProcessId"]) if data.get("ParentProcessId") else None,
                     "name": base_name(image), "path": image},
            labels=["host_behavior", "sysmon", "process"],
            metadata={"windows_event_id": 1, "command_line": data.get("CommandLine"),
                      "parent_image": data.get("ParentImage"), "image": image})
    if event_id == 8:
        return NormalizedEvent(
            **common, action="remote_thread_create",
            labels=["host_behavior", "sysmon", "memory"],
            metadata={"windows_event_id": 8, "source_image": data.get("SourceImage"),
                      "target_image": data.get("TargetImage"),
                      "new_thread_id": data.get("NewThreadId"),
                      "start_address": data.get("StartAddress"),
                      "start_module": data.get("StartModule")})
    if event_id == 10:
        try:
            granted = int(str(data.get("GrantedAccess", "0x0")), 16)
        except ValueError:
            granted = 0
        return NormalizedEvent(
            **common, action="process_access",
            labels=["host_behavior", "sysmon", "memory"],
            metadata={"windows_event_id": 10, "source_image": data.get("SourceImage"),
                      "target_image": data.get("TargetImage"),
                      "granted_access": data.get("GrantedAccess"),
                      "granted_access_value": granted,
                      "write_capable": granted in WRITE_ACCESS_BITS or bool(granted & 0x0020),
                      "call_trace": data.get("CallTrace")})
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--stix", type=Path)
    args = parser.parse_args()

    raw = args.evidence_dir / "raw" / "memory-injection-events.json"
    records = json.loads(raw.read_text(encoding="utf-8-sig"))
    events = []
    for index, record in enumerate(records, 1):
        if not str(record.get("log", "")).endswith("Sysmon/Operational"):
            continue
        event = build_event(record, args.task_id, args.run_id, index)
        if event is None:
            continue
        event.event_id = "evt_" + hashlib.sha256(
            f"{args.task_id}|{record['record_id']}".encode()).hexdigest()[:24]
        event.labels = sorted(set(event.labels + ["real_lab", "controlled_memory_test"]))
        event.metadata.update(classification="real_observation", run_id=args.run_id,
                              raw_reference={"file": raw.name, "record": record["record_id"]})
        events.append(event)
    events.sort(key=lambda e: (e.timestamp, e.event_id))

    knowledge = AttackKnowledge(args.stix) if args.stix else None
    normalized, alerts, graph, trace = analyze(args.task_id, events, knowledge=knowledge)
    args.output.mkdir(parents=True, exist_ok=True)
    for value, name in ((normalized, "normalized_events"), (alerts, "alerts"),
                        ([graph], "attack_graph"), ([trace], "trace_result")):
        (args.output / (name + ".json")).write_text(
            json.dumps([v.model_dump(mode="json") for v in value], ensure_ascii=False, indent=2),
            encoding="utf-8")
    print(json.dumps({
        "task_id": args.task_id,
        "events": len(normalized),
        "alerts": [a.rule_id for a in alerts],
        "mitre": [(a.mitre.technique_id, a.mitre.tactic) if a.mitre else None for a in alerts],
        "stages": [f"{s.tactic}:{s.technique_id or 'unmapped'}" for s in (trace.attack_chain or [])],
    }, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
