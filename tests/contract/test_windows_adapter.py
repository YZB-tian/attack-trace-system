from collectors.windows.adapter import normalize_windows_records

def test_normalize_windows_records_from_sysmon_like_event_dicts():
    records = [
        {
            "EventID": 1,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "User": "LAB\\student",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentImage": "C:\\Windows\\explorer.exe",
            "CommandLine": "powershell -enc SQBFAFgA",
            "ProcessGuid": "{11111111-2222-3333-4444-555555555555}",
        },
        {
            "EventID": 3,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:02:00+08:00",
            "SourceIp": "10.10.2.10",
            "SourcePort": 49812,
            "DestinationIp": "10.10.0.20",
            "DestinationPort": 443,
            "Protocol": "tcp",
            "Initiated": "true",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        },
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    assert len(events) == 2
    assert events[0].source_type == "host_log"
    assert events[0].task_id == "task_demo_windows_001"
    assert events[0].host_id == "officepc01"
    assert events[0].event_id.startswith("evt_")
    assert events[0].action == "process_create"
    assert events[0].process is not None
    assert events[0].process.name == "powershell.exe"

    assert events[1].action == "network_connect"
    assert events[1].src_ip == "10.10.2.10"
    assert events[1].dst_ip == "10.10.0.20"
    assert events[1].network is not None
    assert events[1].network.protocol == "tcp"
