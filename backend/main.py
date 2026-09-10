"""Single-process local evidence API. No implicit demonstration data."""
from contextlib import asynccontextmanager
from pathlib import Path
from threading import RLock
import json
import os
import tempfile
from typing import List

from fastapi import FastAPI, HTTPException
from common.models import NormalizedEvent
from common.time_utils import now_iso
from correlation.pipeline import analyze

_event_store: List[NormalizedEvent] = []
_alert_store = {}
_graph_store = {}
_trace_store = {}
_task_store = {}
_lock = RLock()


def _storage_path():
    value = os.environ.get("ATS_EVENTS_FILE")
    return Path(value).resolve() if value else None


def _persist(events):
    path = _storage_path()
    if path is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         suffix=".tmp", delete=False) as stream:
            name = stream.name
            json.dump([e.model_dump(mode="json") for e in events], stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)


@asynccontextmanager
async def lifespan(app):
    path = _storage_path()
    if path and path.exists():
        events = [NormalizedEvent.model_validate(x) for x in json.loads(path.read_text(encoding="utf-8"))]
        with _lock:
            for store in (_event_store, _alert_store, _graph_store, _trace_store, _task_store):
                store.clear()
            _ingest(events, persist=False)
    yield


app = FastAPI(title="Attack Trace System API", version="0.3.0", lifespan=lifespan)


def _ingest(events, *, persist=True):
    existing = {event.event_id: event for event in _event_store}
    touched = set()
    accepted = 0
    for event in events:
        if event.event_id in existing:
            if existing[event.event_id] != event:
                raise HTTPException(409, detail=f"conflicting event_id: {event.event_id}")
            continue
        existing[event.event_id] = event
        touched.add(event.task_id)
        accepted += 1
    staged = list(existing.values())
    results = {}
    try:
        for task_id in sorted(touched):
            results[task_id] = analyze(task_id, [e for e in staged if e.task_id == task_id])
        if accepted and persist:
            _persist(staged)
    except Exception as exc:
        raise HTTPException(500, detail="Analysis or persistence failed; batch was not committed.") from exc
    # Publish only after every task and the durable write have succeeded.
    _event_store[:] = staged
    for task_id, (_, alerts, graph, trace) in results.items():
        _alert_store[task_id] = alerts
        _graph_store[task_id] = graph
        _trace_store[task_id] = trace
        _task_store[task_id] = dict(schema_version="1.0", task_id=task_id, status="completed",
            stage="trace_complete", progress=100, message="Evidence analysis completed; findings are candidates.",
            created_at=_task_store.get(task_id, {}).get("created_at", now_iso()), updated_at=now_iso())
    return {"code": 0, "message": "ok", "data": {
        "accepted": accepted, "total": len(staged), "tasks_processed": sorted(touched)}}


@app.get("/api/health")
def health():
    return {"code": 0, "message": "ok", "data": {"status": "healthy"}}


@app.post("/api/events")
def ingest_events(events: List[NormalizedEvent]):
    with _lock:
        return _ingest(events)


@app.get("/api/events")
def get_events():
    with _lock:
        return {"code": 0, "message": "ok", "data": [e.model_dump(mode="json") for e in _event_store]}


@app.get("/api/alerts")
def get_alerts():
    with _lock:
        return {"code": 0, "message": "ok", "data": [a.model_dump(mode="json") for batch in _alert_store.values() for a in batch]}


def _get(store, task_id):
    with _lock:
        if task_id not in store:
            raise HTTPException(404, detail="task not found")
        value = store[task_id]
        return {"code": 0, "message": "ok", "data": value if isinstance(value, dict) else value.model_dump(mode="json")}


@app.get("/api/attack-graph/{task_id}")
def get_attack_graph(task_id: str):
    return _get(_graph_store, task_id)


@app.get("/api/trace/{task_id}")
def get_trace(task_id: str):
    return _get(_trace_store, task_id)


@app.get("/api/tasks/{task_id}")
def get_task(task_id: str):
    return _get(_task_store, task_id)
