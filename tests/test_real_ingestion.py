import pytest
from fastapi.testclient import TestClient
import backend.main as backend
from collectors.windows.adapter import normalize_windows_records


@pytest.fixture(autouse=True)
def clean():
    stores = [backend._event_store, backend._alert_store, backend._graph_store,
              backend._trace_store, backend._task_store]
    for store in stores:
        store.clear()
    yield
    for store in stores:
        store.clear()


def event(eid="evt_a"):
    return dict(event_id=eid, task_id="task_real", timestamp="2026-09-10T13:35:00Z",
                source_type="host_log", source="test", action="file_access")


def test_empty_api_never_returns_mock():
    with TestClient(backend.app) as client:
        assert client.get("/api/events").json()["data"] == []
        assert client.get("/api/alerts").json()["data"] == []
        for path in ("tasks", "trace", "attack-graph"):
            assert client.get(f"/api/{path}/task_demo_001").status_code == 404


def test_conflict_does_not_partially_insert():
    with TestClient(backend.app) as client:
        conflict = {**event(), "action": "different"}
        assert client.post("/api/events", json=[event(), conflict]).status_code == 409
        assert backend._event_store == []


def test_analysis_failure_is_retryable(monkeypatch):
    original = backend.analyze
    def fail(*args, **kwargs):
        raise ValueError("test failure")
    with TestClient(backend.app) as client:
        monkeypatch.setattr(backend, "analyze", fail)
        assert client.post("/api/events", json=[event()]).status_code == 500
        assert backend._event_store == []
        monkeypatch.setattr(backend, "analyze", original)
        assert client.post("/api/events", json=[event()]).json()["data"]["accepted"] == 1


def test_persistence_rebuilds_on_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("ATS_EVENTS_FILE", str(tmp_path / "events.json"))
    with TestClient(backend.app) as client:
        assert client.post("/api/events", json=[event()]).status_code == 200
    backend._event_store.clear()
    backend._task_store.clear()
    with TestClient(backend.app) as client:
        assert len(client.get("/api/events").json()["data"]) == 1
        assert client.get("/api/tasks/task_real").json()["data"]["status"] == "completed"


def test_security_export_hex_pid_and_session():
    record = dict(timestamp="2026-09-10T13:35:00Z", event_id=4688,
                  record_id=42, host="officepc01", fields={
                      "NewProcessId": "0x964", "ProcessId": "0x100",
                      "NewProcessName": r"C:\Windows\powershell.exe",
                      "SubjectUserName": "LabAdmin", "SubjectLogonId": "0xa9a97"})
    result = normalize_windows_records([record], "task_real")[0]
    assert result.action == "process_create"
    assert result.process.pid == 2404
    assert result.process.ppid == 256
    assert result.process.name == "powershell.exe"
    assert result.metadata["logon_id"] == "0xa9a97"
    assert result.host_id == "officepc01"


def test_process_session_matches_subject_when_target_is_absent():
    result = normalize_windows_records([{
        "timestamp": "2026-09-10T13:35:00Z", "EventID": 4688,
        "SubjectUserName": "LabAdmin", "SubjectLogonId": "0xa9a97",
        "TargetUserName": "-", "TargetLogonId": "0x0",
        "NewProcessId": "0x10", "NewProcessName": "powershell.exe",
    }], "task_real")[0]
    assert result.user == "LabAdmin"
    assert result.metadata["logon_id"] == "0xa9a97"


def test_windows_ids_are_content_stable_and_source_distinct():
    a = {"timestamp": "2026-09-10T13:35:00Z", "Computer": "officepc01", "EventID": 4634}
    b = {**a, "Computer": "coreserver01"}
    assert normalize_windows_records([a], "task_real")[0].event_id != normalize_windows_records([b], "task_real")[0].event_id
    assert normalize_windows_records([b, a], "task_real")[1].event_id == normalize_windows_records([a], "task_real")[0].event_id


@pytest.mark.parametrize("eid,action", [(2, "file_time_change"), (22, "dns_query"), (4663, "file_access"), (5145, "file_access")])
def test_windows_event_semantics(eid, action):
    result = normalize_windows_records([{"timestamp": "2026-09-10T13:35:00Z", "EventID": eid}], "task_real")[0]
    assert result.action == action
