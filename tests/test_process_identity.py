"""An execve observation must anchor a PID's lifetime the same way as a
process_create record, otherwise collectors that only emit process_exec leave
every event with its own process node."""
from common.models import NormalizedEvent
from correlation.pipeline import analyze

TASK = "task_process_identity"


def event(event_id, timestamp, action, pid, **metadata):
    return NormalizedEvent(
        event_id=event_id, task_id=TASK, timestamp=timestamp,
        source_type="host_behavior", source="bpftrace", host_id="webserver01",
        action=action, process={"pid": pid, "name": "python3"},
        raw_event={"raw": event_id}, labels=[], metadata=metadata,
    )


def _process_nodes(events):
    _, _, graph, _ = analyze(TASK, events)
    return [node for node in graph.nodes if node.type.value == "process"]


def test_process_exec_anchors_the_pid_lifetime():
    events = [
        event("evt_exec", "2026-09-10T18:00:00+00:00", "process_exec", 100, syscall="execve"),
        event("evt_file", "2026-09-10T18:00:10+00:00", "file_access", 100, path="/etc/shadow"),
        event("evt_net", "2026-09-10T18:00:20+00:00", "network_connect", 100),
    ]
    nodes = _process_nodes(events)
    assert len(nodes) == 1
    assert nodes[0].attributes["identity_resolved"] is True
    assert nodes[0].attributes["pid"] == 100


def test_events_without_any_creation_record_stay_unresolved():
    events = [
        event("evt_lonely", "2026-09-10T18:00:00+00:00", "file_access", 999, path="/etc/hosts"),
    ]
    nodes = _process_nodes(events)
    assert len(nodes) == 1
    assert nodes[0].attributes["identity_resolved"] is False


def test_a_new_exec_of_the_same_pid_starts_a_new_lifetime():
    events = [
        event("evt_first", "2026-09-10T18:00:00+00:00", "process_exec", 100, syscall="execve"),
        event("evt_between", "2026-09-10T18:00:05+00:00", "file_access", 100, path="/etc/passwd"),
    ]
    nodes = _process_nodes(events)
    assert len(nodes) == 1
    # A second exec of the same PID is a distinct lifetime, so the earlier and
    # later observations must not be merged into one process instance.
    later = events + [
        event("evt_exec2", "2026-09-10T18:05:30+00:00", "process_exec", 100, syscall="execve"),
    ]
    assert len(_process_nodes(later)) == 2
