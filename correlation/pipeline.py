"""Offline integration entry point; published backend API is deliberately untouched."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from common.models import NormalizedEvent, Alert
from collectors.network.adapter import load_zeek_logs
from detection.attack_stix import AttackKnowledge
from detection.network_rules import NetworkConfig, detect_network
from detection.sigma_subset import SigmaRule
from .service import correlate, _seconds
from .paths import trace_graph


def analyze(task_id, events, *, alerts=(), knowledge=None, sigma_rules=(), window_seconds=900, network_config=None):
    # Exact repeats are idempotent; conflicting objects sharing an ID are an error.
    unique = {}
    for e in events:
        if e.event_id in unique and unique[e.event_id] != e:
            raise ValueError(f"conflicting event ID: {e.event_id}")
        unique[e.event_id] = e
    events = sorted(unique.values(), key=lambda e: (_seconds(e.timestamp), e.event_id))
    if any(e.task_id != task_id for e in events): raise ValueError("mixed task input")
    detections = list(alerts) + detect_network(events, network_config, knowledge)
    for rule in sigma_rules:
        for e in events:
            detections.extend(rule.match(e, knowledge))
    by_id = {}
    for a in detections:
        if a.alert_id in by_id and by_id[a.alert_id] != a: raise ValueError("conflicting alert ID")
        by_id[a.alert_id] = a
    detections = sorted(by_id.values(), key=lambda a: (_seconds(a.timestamp_start), a.alert_id))
    graph = correlate(task_id, events, detections, window_seconds)
    trace = trace_graph(graph, events, detections, knowledge)
    return events, detections, graph, trace


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--zeek-dir", type=Path)
    parser.add_argument("--events", type=Path, help="JSON array of shared NormalizedEvent objects")
    parser.add_argument("--alerts", type=Path, help="Optional existing Alert JSON array")
    parser.add_argument("--stix", type=Path, required=True, help="Official enterprise-attack STIX bundle")
    parser.add_argument("--sigma-rule", type=Path, action="append", default=[])
    parser.add_argument("--window-seconds", type=int, default=900)
    parser.add_argument("--network-config", type=Path, help="Optional NetworkConfig JSON")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.task_id.startswith("task_"): parser.error("task ID must start with task_")
    if not args.zeek_dir and not args.events: parser.error("provide --zeek-dir and/or --events")
    events = load_zeek_logs(args.zeek_dir, args.task_id) if args.zeek_dir else []
    if args.events:
        events += [NormalizedEvent.model_validate(x) for x in json.loads(args.events.read_text(encoding="utf-8-sig"))]
    alerts = [Alert.model_validate(x) for x in json.loads(args.alerts.read_text(encoding="utf-8-sig"))] if args.alerts else []
    config = NetworkConfig(**json.loads(args.network_config.read_text(encoding="utf-8"))) if args.network_config else None
    result = analyze(args.task_id, events, alerts=alerts, knowledge=AttackKnowledge(args.stix),
        sigma_rules=[SigmaRule(p) for p in args.sigma_rule], window_seconds=args.window_seconds, network_config=config)
    # Validate fresh results against the immutable schemas, not merely existing Mock examples.
    from jsonschema import Draft202012Validator, FormatChecker
    schema_dir = Path(__file__).resolve().parents[1] / "schemas"
    for value, schema in zip(result, ("normalized_event", "alert", "attack_graph", "trace_result")):
        validator = Draft202012Validator(json.loads((schema_dir / (schema + ".schema.json")).read_text(encoding="utf-8")), format_checker=FormatChecker())
        for obj in value if isinstance(value, list) else [value]:
            validator.validate(obj.model_dump(mode="json"))
    args.output.mkdir(parents=True, exist_ok=True)
    for value, name in zip(result, ("normalized_events", "alerts", "attack_graph", "trace_result")):
        data = [x.model_dump(mode="json") for x in value] if isinstance(value, list) else value.model_dump(mode="json")
        (args.output / (name + ".json")).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"events={len(result[0])} alerts={len(result[1])} nodes={len(result[2].nodes)} edges={len(result[2].edges)}")
    print("Deterministic offline analysis complete. LLM agent integration is a separate step.")


if __name__ == "__main__":
    main()
