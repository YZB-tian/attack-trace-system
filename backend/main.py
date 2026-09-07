from pathlib import Path
import json
from typing import List

from fastapi import FastAPI, HTTPException

from common.models import (
    Alert,
    AttackGraph,
    NormalizedEvent,
    TaskStatus,
    TraceResult,
)

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "testdata"

app = FastAPI(
    title="Attack Trace System API",
    version="0.1.0",
    description="统一接口骨架。当前读取 Mock 数据，便于十人并行开发和联调。",
)

_event_store: List[NormalizedEvent] = []


def load_json(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


@app.get("/api/health")
def health():
    return {"code": 0, "message": "ok", "data": {"status": "healthy"}}


@app.post("/api/events")
def ingest_events(events: List[NormalizedEvent]):
    _event_store.extend(events)
    return {
        "code": 0,
        "message": "ok",
        "data": {"accepted": len(events), "total": len(_event_store)},
    }


@app.get("/api/events")
def get_events():
    data = _event_store or [NormalizedEvent.model_validate(x) for x in load_json("normalized_events.json")]
    return {"code": 0, "message": "ok", "data": [x.model_dump(mode="json") for x in data]}


@app.get("/api/alerts")
def get_alerts():
    data = [Alert.model_validate(x) for x in load_json("alerts.json")]
    return {"code": 0, "message": "ok", "data": [x.model_dump(mode="json") for x in data]}


@app.get("/api/attack-graph/{task_id}")
def get_attack_graph(task_id: str):
    graph = AttackGraph.model_validate(load_json("attack_graph.json"))
    if graph.task_id != task_id:
        raise HTTPException(status_code=404, detail="task not found")
    return {"code": 0, "message": "ok", "data": graph.model_dump(mode="json")}


@app.get("/api/trace/{task_id}")
def get_trace(task_id: str):
    trace = TraceResult.model_validate(load_json("trace_result.json"))
    if trace.task_id != task_id:
        raise HTTPException(status_code=404, detail="task not found")
    return {"code": 0, "message": "ok", "data": trace.model_dump(mode="json")}


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str):
    task = TaskStatus.model_validate(load_json("task_status.json"))
    if task.task_id != task_id:
        raise HTTPException(status_code=404, detail="task not found")
    return {"code": 0, "message": "ok", "data": task.model_dump(mode="json")}
