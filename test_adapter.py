from datetime import datetime, timezone

import pytest

from collectors.host_behavior.adapter import normalize_host_behavior


def test_normalizes_process_record_and_resolves_asset():
    events = normalize_host_behavior(
        [
            {
                "timestamp": "2026-09-08T10:05:00Z",
                "hostname": "officepc01",
                "source": "sysmon",
                "event_type": "process_start",
                "username": "LAB\\student",
                "process_name": "powershell.exe",
                "process_path": r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "pid": "4321",
                "ppid": 1200,
            }
        ],
        "task_demo_001",
    )

    assert len(events) == 1
    event = events[0]
    assert event.event_id == "evt_task_demo_001_0001"
    assert event.source_type.value == "host_behavior"
    assert event.host_id == "officepc01"
    assert event.timestamp == "2026-09-08T10:05:00+00:00"
    assert event.action == "process_create"
    assert event.process.pid == 4321
    assert event.process.name == "powershell.exe"
    assert event.user == r"LAB\student"


def test_normalizes_file_syscall_and_network_fields():
    events = normalize_host_behavior(
        [
            {
                "event_time": datetime(2026, 9, 8, 10, 6, tzinfo=timezone.utc),
                "host_id": "10.10.2.10",
                "syscall": "openat",
                "file_path": "/etc/shadow",
                "src_ip": "10.10.2.10",
                "dst_ip": "10.10.0.20",
                "dst_port": 443,
                "protocol": "tcp",
            }
        ],
        "task_demo_001",
    )

    event = events[0]
    assert event.host_id == "officepc01"
    assert event.action == "syscall"
    assert event.object.type == "file"
    assert event.object.path == "/etc/shadow"
    assert event.network.protocol == "tcp"
    assert event.dst_port == 443
    assert "syscall" in event.labels


def test_skips_non_mapping_records():
    events = normalize_host_behavior([None, "invalid"], "task_demo_001")

    assert events == []


def test_missing_or_timezone_less_timestamp_is_rejected():
    with pytest.raises(ValueError, match="missing timestamp"):
        normalize_host_behavior([{"host_id": "officepc01"}], "task_demo_001")

    with pytest.raises(ValueError, match="timestamp missing timezone"):
        normalize_host_behavior(
            [{"timestamp": "2026-09-08T10:05:00", "host_id": "officepc01"}],
            "task_demo_001",
        )
