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
from common.time_utils import now_iso
from correlation.pipeline import analyze


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "testdata"

app = FastAPI(
    title="Attack Trace System API",
    version="0.2.0",
    description="真实集成后端：事件 -> 检测 -> 告警 -> 攻击图 -> 溯源结果。",
)


# ----------------------------
# Runtime stores
# ----------------------------

_event_store: List[NormalizedEvent] = []

_alert_store: dict[str, List[Alert]] = {}
_graph_store: dict[str, AttackGraph] = {}
_trace_store: dict[str, TraceResult] = {}
_task_store: dict[str, dict] = {}


def load_json(name: str):
    return json.loads((DATA / name).read_text(encoding="utf-8"))


def events_for_task(task_id: str) -> List[NormalizedEvent]:
    return [e for e in _event_store if e.task_id == task_id]


def rebuild_task(task_id: str):
    """
    Run the real offline analysis pipeline for one task.
    """

    events = events_for_task(task_id)

    if not events:
        raise ValueError(f"no events for task: {task_id}")

    created_at = _task_store.get(task_id, {}).get(
        "created_at",
        now_iso(),
    )

    _task_store[task_id] = {
        "schema_version": "1.0",
        "task_id": task_id,
        "status": "running",
        "stage": "analysis",
        "progress": 50,
        "message": "Running detection and correlation pipeline.",
        "created_at": created_at,
        "updated_at": now_iso(),
    }

    try:
        analyzed_events, alerts, graph, trace = analyze(
            task_id,
            events,
        )

        _alert_store[task_id] = alerts
        _graph_store[task_id] = graph
        _trace_store[task_id] = trace

        _task_store[task_id] = {
            "schema_version": "1.0",
            "task_id": task_id,
            "status": "completed",
            "stage": "trace_complete",
            "progress": 100,
            "message": "Real analysis pipeline completed.",
            "created_at": created_at,
            "updated_at": now_iso(),
        }

    except Exception as exc:
        _task_store[task_id] = {
            "schema_version": "1.0",
            "task_id": task_id,
            "status": "failed",
            "stage": "analysis_failed",
            "progress": 0,
            "message": str(exc),
            "created_at": created_at,
            "updated_at": now_iso(),
        }

        raise


@app.get("/api/health")
def health():
    return {
        "code": 0,
        "message": "ok",
        "data": {
            "status": "healthy",
        },
    }


@app.post("/api/events")
def ingest_events(events: List[NormalizedEvent]):

    existing = {
        event.event_id: event
        for event in _event_store
    }

    accepted = 0
    touched_tasks = set()

    for event in events:

        # Idempotent repeat
        if event.event_id in existing:

            if existing[event.event_id] != event:
                raise HTTPException(
                    status_code=409,
                    detail=f"conflicting event_id: {event.event_id}",
                )

            continue

        _event_store.append(event)
        existing[event.event_id] = event

        accepted += 1
        touched_tasks.add(event.task_id)

    # Real integration happens here
    for task_id in touched_tasks:
        try:
            rebuild_task(task_id)
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"analysis failed for {task_id}: {exc}",
            )

    return {
        "code": 0,
        "message": "ok",
        "data": {
            "accepted": accepted,
            "total": len(_event_store),
            "tasks_processed": sorted(touched_tasks),
        },
    }


@app.get("/api/events")
def get_events():

    if _event_store:
        data = _event_store
    else:
        data = [
            NormalizedEvent.model_validate(x)
            for x in load_json("normalized_events.json")
        ]

    return {
        "code": 0,
        "message": "ok",
        "data": [
            x.model_dump(mode="json")
            for x in data
        ],
    }


@app.get("/api/alerts")
def get_alerts():

    if _alert_store:

        data = []

        for alerts in _alert_store.values():
            data.extend(alerts)

    else:
        data = [
            Alert.model_validate(x)
            for x in load_json("alerts.json")
        ]

    return {
        "code": 0,
        "message": "ok",
        "data": [
            x.model_dump(mode="json")
            for x in data
        ],
    }


@app.get("/api/attack-graph/{task_id}")
def get_attack_graph(task_id: str):

    if task_id in _graph_store:

        graph = _graph_store[task_id]

    else:

        graph = AttackGraph.model_validate(
            load_json("attack_graph.json")
        )

        if graph.task_id != task_id:
            raise HTTPException(
                status_code=404,
                detail="task not found",
            )

    return {
        "code": 0,
        "message": "ok",
        "data": graph.model_dump(mode="json"),
    }


@app.get("/api/trace/{task_id}")
def get_trace(task_id: str):

    if task_id in _trace_store:

        trace = _trace_store[task_id]

    else:

        trace = TraceResult.model_validate(
            load_json("trace_result.json")
        )

        if trace.task_id != task_id:
            raise HTTPException(
                status_code=404,
                detail="task not found",
            )

    return {
        "code": 0,
        "message": "ok",
        "data": trace.model_dump(mode="json"),
    }


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str):

    if task_id in _task_store:

        task = _task_store[task_id]

        return {
            "code": 0,
            "message": "ok",
            "data": task,
        }

    task = TaskStatus.model_validate(
        load_json("task_status.json")
    )

    if task.task_id != task_id:
        raise HTTPException(
            status_code=404,
            detail="task not found",
        )

    return {
        "code": 0,
        "message": "ok",
        "data": task.model_dump(mode="json"),
    }