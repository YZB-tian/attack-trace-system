"""Exercise a backend Git snapshot over localhost HTTP without editing its files.

Use only an explicitly selected, reviewed project ref. Synthetic commands are
submitted as event text, never executed. No external service is contacted.
"""
import argparse
import json
import socket
import subprocess
import threading
import time
import types
import urllib.request
from pathlib import Path
import uvicorn
from common.models import NormalizedEvent, Alert, AttackGraph, TraceResult, TaskStatus
from jsonschema import Draft202012Validator, FormatChecker
from .host_demo import examples

ROOT = Path(__file__).resolve().parents[1]


def verify(ref, output):
    source = subprocess.run(["git", "show", f"{ref}:backend/main.py"], cwd=ROOT,
                            check=True, capture_output=True).stdout.decode("utf-8")
    sha = subprocess.run(["git", "rev-parse", ref], cwd=ROOT, check=True,
                         capture_output=True, text=True).stdout.strip()
    module = types.ModuleType("backend_acceptance_snapshot")
    module.__file__ = str(ROOT / "backend/main.py")
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    if not hasattr(module, "rebuild_task"):
        raise ValueError("Selected backend is still the Mock implementation; use the integrated backend ref.")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(module.app, log_level="error", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url + path, data=data, headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=10) as response:
            result = json.load(response)
        assert result["code"] == 0
        return result["data"]

    report = {"backend_ref": ref, "backend_sha": sha, "transport": "localhost HTTP",
              "synthetic": True, "browser_test": False, "cases": {}}
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("local backend failed to start")
            time.sleep(.05)
        for name, (events, expected) in examples().items():
            task = events[0].task_id
            accepted = request("/api/events", [e.model_dump(mode="json") for e in events])
            assert accepted["accepted"] == len(events)
            alerts = [a for a in request("/api/alerts") if a["task_id"] == task]
            graph = request("/api/attack-graph/" + task)
            trace = request("/api/trace/" + task)
            status = request("/api/tasks/" + task)
            assert [a["rule_id"] for a in alerts] == expected
            assert status["status"] == trace["status"] == "completed"
            if name in {"windows", "linux"}:
                assert len(trace["attack_chain"]) == 1
            node_ids = {n["id"] for n in graph["nodes"]}
            assert all(e["source"] in node_ids and e["target"] in node_ids for e in graph["edges"])
            assert all(set(s["entity_ids"]) <= node_ids for s in trace["attack_chain"])
            directory = output / name
            directory.mkdir(parents=True, exist_ok=True)
            for filename, schema, model, value in [
                ("normalized_events", "normalized_event", NormalizedEvent, [e.model_dump(mode="json") for e in events]),
                ("alerts", "alert", Alert, alerts), ("attack_graph", "attack_graph", AttackGraph, graph),
                ("trace_result", "trace_result", TraceResult, trace), ("task_status", "task_status", TaskStatus, status)]:
                validator = Draft202012Validator(json.loads((ROOT / "schemas" / (schema + ".schema.json")).read_text()),
                                                format_checker=FormatChecker())
                for obj in value if isinstance(value, list) else [value]:
                    model.model_validate(obj)
                    validator.validate(obj)
                (directory / (filename + ".json")).write_text(json.dumps(value, indent=2), encoding="utf-8")
            repeat = request("/api/events", [e.model_dump(mode="json") for e in events])
            assert repeat["accepted"] == 0
            assert request("/api/attack-graph/" + task) == graph
            report["cases"][name] = {"events": len(events), "alerts": len(alerts), "rules": expected,
                "nodes": len(graph["nodes"]), "edges": len(graph["edges"]),
                "stages": len(trace["attack_chain"]), "status": status["status"], "idempotent": True}
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
    (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-ref", required=True)
    parser.add_argument("--output", type=Path, default=Path("correlation/output/backend_host_graph"))
    args = parser.parse_args()
    print(json.dumps(verify(args.backend_ref, args.output), indent=2))


if __name__ == "__main__":
    main()
