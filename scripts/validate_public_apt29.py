"""Evaluate the default host detections against a public enterprise dataset.

Dataset: OTRF Security-Datasets Mordor "APT29 evals day 1" host collection
(Sysmon + Windows event forwarding from a corporate domain). Only Sysmon
process-create, process-access and create-remote-thread records are converted,
because those are the record types the default host rules consume. No labels
from the dataset are fed into the detectors.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common.models import NormalizedEvent  # noqa: E402
from detection.host_rules import detect_host  # noqa: E402
from detection.attack_stix import AttackKnowledge  # noqa: E402

DEFAULT_DATASET = ROOT / "runtime" / "datasets" / "apt29_day1" / (
    "apt29_evals_day1_manual_2020-05-01225525.json")


def _stamp(record):
    value = record.get("@timestamp") or record.get("EventReceivedTime")
    if value is None:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def _hex(value):
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return 0


def _base(value):
    return str(value).rsplit("\\", 1)[-1] if value else None


def convert(record, task, index):
    event_id = record.get("EventID")
    timestamp = _stamp(record)
    if timestamp is None:
        return None
    common = dict(
        event_id=f"evt_pub_{index:06d}",
        task_id=task,
        timestamp=timestamp,
        source_type="host_behavior",
        source="sysmon",
        host_id=None,
        raw_event=record,
        labels=["host_behavior", "sysmon", "public_dataset"],
    )
    base_meta = {"os": "windows", "dataset_host": record.get("host") or record.get("Hostname"),
                 "record_number": record.get("RecordNumber")}
    if event_id == 1:
        image = record.get("Image")
        return NormalizedEvent(
            **common, action="process_create",
            process={"pid": int(record["ProcessId"]) if str(record.get("ProcessId", "")).isdigit() else None,
                     "ppid": int(record["ParentProcessId"]) if str(record.get("ParentProcessId", "")).isdigit() else None,
                     "name": _base(image), "path": image},
            user=record.get("User"),
            metadata={**base_meta, "command_line": record.get("CommandLine"),
                      "parent_image": record.get("ParentImage"), "image": image,
                      "windows_event_id": 1})
    if event_id == 8:
        return NormalizedEvent(
            **common, action="remote_thread_create",
            metadata={**base_meta, "windows_event_id": 8,
                      "source_image": record.get("SourceImage"),
                      "target_image": record.get("TargetImage"),
                      "start_module": record.get("StartModule"),
                      "start_address": record.get("StartAddress")})
    if event_id == 10:
        granted = _hex(record.get("GrantedAccess"))
        return NormalizedEvent(
            **common, action="process_access",
            metadata={**base_meta, "windows_event_id": 10,
                      "source_image": record.get("SourceImage"),
                      "target_image": record.get("TargetImage"),
                      "granted_access": record.get("GrantedAccess"),
                      "granted_access_value": granted,
                      "write_capable": bool(granted & 0x0020)})
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-id", default="task_public_apt29_day1")
    parser.add_argument("--stix", type=Path)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    counters = collections.Counter()
    events = []
    with args.dataset.open(encoding="utf-8", errors="replace") as stream:
        for index, line in enumerate(stream, 1):
            if not line.strip():
                continue
            counters["lines"] += 1
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                counters["unparsed_lines"] += 1
                continue
            if record.get("EventID") not in (1, 8, 10):
                counters["skipped_event_ids"] += 1
                continue
            event = convert(record, args.task_id, index)
            if event is None:
                counters["skipped_missing_time"] += 1
                continue
            counters[f"event_id_{record.get('EventID')}"] += 1
            events.append(event)
            if args.limit and len(events) >= args.limit:
                break

    knowledge = AttackKnowledge(args.stix) if args.stix else None
    alerts = detect_host(events, knowledge)
    by_rule = collections.Counter(a.rule_id for a in alerts)
    by_technique = collections.Counter(a.mitre.technique_id for a in alerts if a.mitre)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "alerts.json").write_text(
        json.dumps([a.model_dump(mode="json") for a in alerts], ensure_ascii=False, indent=2),
        encoding="utf-8")
    report = {
        "dataset": str(args.dataset),
        "records_read": counters["lines"],
        "records_converted": len(events),
        "conversion_counters": dict(counters),
        "alerts_total": len(alerts),
        "alerts_by_rule": dict(by_rule),
        "alerts_by_technique": dict(by_technique),
        "note": "Public dataset labels are not used as detector input; alerts are heuristic candidates.",
    }
    (args.output / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2),
                                             encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
