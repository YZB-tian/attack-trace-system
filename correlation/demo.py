"""Create a small clearly labelled synthetic fixture and run the real pipeline."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from common.models import NormalizedEvent
from collectors.network.adapter import load_zeek_logs
from detection.attack_stix import AttackKnowledge
from .pipeline import analyze


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = args.output / "synthetic_inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    origin = datetime(2026, 9, 8, 10, tzinfo=timezone.utc)
    task = "task_network_demo"
    rows, http = [], []
    host_events = []

    def host_event(eid, sec, action, **kwargs):
        host_events.append(NormalizedEvent(event_id=eid, task_id=task,
            timestamp=(origin + timedelta(seconds=sec)).isoformat(), source="sysmon",
            source_type="host_behavior", host_id="officepc01", user="LAB\\student", action=action,
            process={"pid": 4321, "name": "demo-client", "path": "/lab/demo-client"},
            raw_event={"ProcessGuid": "SYNTHETIC-PROCESS-1", "synthetic": True}, labels=["synthetic"], **kwargs))

    host_event("evt_demo_process", 0, "process_create")
    host_event("evt_demo_read", 1, "file_read", object={"type": "file", "path": "/lab/example.csv"})
    host_event("evt_demo_archive", 2, "file_create", object={"type": "file", "path": "/lab/example.zip"})
    for n in range(10):
        sec = 60 + n * 60
        connection = {"ts": (origin + timedelta(seconds=sec)).timestamp(), "uid": f"SYNTHETIC-C{n}",
            "id.orig_h": "10.10.2.10", "id.resp_h": "10.10.0.20", "id.orig_p": 45000 + n,
            "id.resp_p": 80, "proto": "tcp", "service": "http", "duration": 2,
            "orig_bytes": 70000, "resp_bytes": 100, "orig_pkts": 55, "resp_pkts": 4}
        rows.append(connection)
        http.append({k: v for k, v in connection.items() if k in ("ts", "uid", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p")})
        http[-1].update(ts=connection["ts"] + .2, method="POST", host="lab-c2.example",
            uri="/upload?data=" + "aB3dE5gH7jK9mN2pQ4sT6vW8xY0z" * 12,
            user_agent="course-demo", request_body_len=70000, response_body_len=100)
        host_event(f"evt_demo_net_{n}", sec - .1, "network_connect", src_ip="10.10.2.10", dst_ip="10.10.0.20",
            src_port=45000 + n, dst_port=80, network={"protocol": "tcp"})
    for name, data in (("conn", rows), ("http", http)):
        (inputs / (name + ".log")).write_text("\n".join(json.dumps(x) for x in data) + "\n", encoding="utf-8")
    (inputs / "host_events.json").write_text(json.dumps([e.model_dump(mode="json") for e in host_events], indent=2), encoding="utf-8")
    events = host_events + load_zeek_logs(inputs, task)
    result = analyze(task, events, knowledge=AttackKnowledge(args.stix))
    from jsonschema import Draft202012Validator, FormatChecker
    for value, name, schema in zip(result, ("normalized_events", "alerts", "attack_graph", "trace_result"),
                                  ("normalized_event", "alert", "attack_graph", "trace_result")):
        data = [x.model_dump(mode="json") for x in value] if isinstance(value, list) else value.model_dump(mode="json")
        schema_path = Path(__file__).resolve().parents[1] / "schemas" / (schema + ".schema.json")
        validator = Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")), format_checker=FormatChecker())
        for obj in data if isinstance(data, list) else [data]: validator.validate(obj)
        (args.output / (name + ".json")).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.output / "PROVENANCE.txt").write_text(
        "SYNTHETIC fixture, 33 events. Not a public dataset or real attack capture.\n"
        "The pipeline derives alerts and graph edges; no alerts or attack graph are pre-filled.\n"
        "File access followed by communication is a candidate relationship, not proof that file content was transmitted.\n", encoding="utf-8")
    print(f"SYNTHETIC demo: {len(result[0])} events, {len(result[1])} alerts, {len(result[2].nodes)} nodes, {len(result[2].edges)} edges")
    print(f"Output: {args.output.resolve()}")


if __name__ == "__main__":
    main()
