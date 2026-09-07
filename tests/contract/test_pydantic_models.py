from pathlib import Path
import json

from common.models import Alert, AttackGraph, NormalizedEvent, TaskStatus, TraceResult

ROOT = Path(__file__).resolve().parents[2]

def load(name):
    return json.loads((ROOT / "testdata" / name).read_text(encoding="utf-8"))

def test_events():
    for item in load("normalized_events.json"):
        NormalizedEvent.model_validate(item)

def test_alerts():
    for item in load("alerts.json"):
        Alert.model_validate(item)

def test_graph():
    AttackGraph.model_validate(load("attack_graph.json"))

def test_trace():
    TraceResult.model_validate(load("trace_result.json"))

def test_task():
    TaskStatus.model_validate(load("task_status.json"))
