from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import backend.main as backend


client = TestClient(backend.app)


@pytest.fixture(autouse=True)
def clear_runtime_stores():
    """Keep every HTTP E2E test independent."""
    backend._event_store.clear()
    backend._alert_store.clear()
    backend._graph_store.clear()
    backend._trace_store.clear()
    backend._task_store.clear()

    yield

    backend._event_store.clear()
    backend._alert_store.clear()
    backend._graph_store.clear()
    backend._trace_store.clear()
    backend._task_store.clear()


def make_beacon_events(task_id: str):
    base = datetime(
        2026,
        9,
        10,
        20,
        0,
        0,
        tzinfo=timezone(timedelta(hours=8)),
    )

    events = []

    for i in range(10):
        events.append(
            {
                "schema_version": "1.0",
                "event_id": f"evt_e2e_beacon_{i:02d}",
                "task_id": task_id,
                "timestamp": (base + timedelta(minutes=i)).isoformat(),
                "source_type": "network_flow",
                "source": "zeek",
                "host_id": "firewall01",
                "src_ip": "10.10.2.10",
                "src_port": 45000 + i,
                "dst_ip": "10.10.0.20",
                "dst_port": 80,
                "user": None,
                "action": "network_connect",
                "process": None,
                "object": None,
                "network": {
                    "protocol": "tcp",
                    "direction": "outbound",
                    "bytes_in": 120,
                    "bytes_out": 180,
                    "session_id": f"C{i:02d}",
                },
                "raw_event": {
                    "test_case": "backend_http_e2e",
                    "orig_bytes": 180,
                },
                "labels": [
                    "integration_test",
                    "beacon_candidate",
                ],
                "metadata": {},
            }
        )

    return events


def test_real_backend_pipeline_http_e2e():
    task_id = "task_backend_http_e2e_001"
    events = make_beacon_events(task_id)

    # 1. First POST: all events are new.
    response = client.post("/api/events", json=events)
    assert response.status_code == 200

    payload = response.json()
    assert payload["code"] == 0
    assert payload["data"]["accepted"] == 10
    assert payload["data"]["total"] == 10
    assert payload["data"]["tasks_processed"] == [task_id]

    # 2. Replaying the exact same events must be idempotent.
    response = client.post("/api/events", json=events)
    assert response.status_code == 200

    payload = response.json()
    assert payload["data"]["accepted"] == 0
    assert payload["data"]["total"] == 10
    assert payload["data"]["tasks_processed"] == []

    # 3. Events are available through the public API.
    response = client.get("/api/events")
    assert response.status_code == 200

    task_events = [
        event
        for event in response.json()["data"]
        if event["task_id"] == task_id
    ]

    assert len(task_events) == 10

    # 4. Real detection generated NET-BEACON.
    response = client.get("/api/alerts")
    assert response.status_code == 200

    task_alerts = [
        alert
        for alert in response.json()["data"]
        if alert["task_id"] == task_id
    ]

    assert task_alerts
    assert any(alert["rule_id"] == "NET-BEACON" for alert in task_alerts)

    # 5. Correlation produced an AttackGraph.
    response = client.get(f"/api/attack-graph/{task_id}")
    assert response.status_code == 200

    graph = response.json()["data"]

    assert graph["task_id"] == task_id
    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0

    # 6. TraceResult was generated.
    response = client.get(f"/api/trace/{task_id}")
    assert response.status_code == 200

    trace = response.json()["data"]

    assert trace["task_id"] == task_id
    assert trace["trace_id"]
    assert len(trace["evidence_event_ids"]) == 10
    assert len(trace["evidence_alert_ids"]) >= 1

    # 7. Task reached the end of the real analysis pipeline.
    response = client.get(f"/api/tasks/{task_id}")
    assert response.status_code == 200

    task = response.json()["data"]

    assert task["task_id"] == task_id
    assert task["status"] == "completed"
    assert task["stage"] == "trace_complete"
    assert task["progress"] == 100