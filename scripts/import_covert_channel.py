"""Import the covert-channel experiment bundle (DNS, HTTP and ICMP).

Positive windows contain genuine tunnel-shaped traffic generated inside the
isolated lab; the negative window contains ordinary lookups, polling and small
pings. Both are analysed with the unchanged detection rules so the comparison
is like for like.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collectors.network.adapter import load_zeek_logs  # noqa: E402
from correlation.pipeline import analyze  # noqa: E402
from detection.attack_stix import AttackKnowledge  # noqa: E402


def utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--start", required=True)
    parser.add_argument("--end", required=True)
    parser.add_argument("--stix", type=Path)
    parser.add_argument("--window-seconds", type=int, default=1800)
    parser.add_argument("--min-samples", type=int)
    parser.add_argument("--min-span", type=int)
    args = parser.parse_args()

    zeek_dir = args.evidence_dir / "raw" / "zeek"
    events = load_zeek_logs(zeek_dir, args.task_id)
    start, end = utc(args.start), utc(args.end)
    kept = []
    for event in events:
        moment = utc(event.timestamp)
        if start <= moment <= end:
            event.labels = sorted(set(event.labels + ["real_lab", "covert_channel_experiment"]))
            event.metadata.update(classification="real_experiment", run_id=args.run_id,
                                  window=[args.start, args.end])
            kept.append(event)
    kept.sort(key=lambda e: (e.timestamp, e.event_id))

    from detection.network_rules import NetworkConfig
    config = NetworkConfig(window_seconds=args.window_seconds)
    if args.min_samples:
        config = NetworkConfig(window_seconds=args.window_seconds, min_samples=args.min_samples)
    if args.min_span is not None:
        config = NetworkConfig(window_seconds=args.window_seconds, min_samples=config.min_samples,
                               min_span=args.min_span)
    knowledge = AttackKnowledge(args.stix) if args.stix else None
    normalized, alerts, graph, trace = analyze(args.task_id, kept, knowledge=knowledge,
                                               network_config=config)
    args.output.mkdir(parents=True, exist_ok=True)
    for value, name in ((normalized, "normalized_events"), (alerts, "alerts"),
                        ([graph], "attack_graph"), ([trace], "trace_result")):
        (args.output / (name + ".json")).write_text(
            json.dumps([v.model_dump(mode="json") for v in value], ensure_ascii=False, indent=2),
            encoding="utf-8")
    print(json.dumps({
        "task_id": args.task_id,
        "window": [args.start, args.end],
        "events": len(normalized),
        "alerts": [a.rule_id for a in alerts],
        "mitre": [a.mitre.technique_id if a.mitre else None for a in alerts],
        "graph_nodes": len(graph.nodes),
    }, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
