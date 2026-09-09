from collectors.windows.adapter import normalize_windows_records, reconstruct_sessions


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


def test_normalize_logon_event_extracts_session_fields():
    records = [
        {
            "EventID": 4624,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "TargetUserName": "LAB\\student",
            "LogonId": "0x3E7",
            "LogonType": 10,
            "IpAddress": "10.10.0.10",
            "WorkstationName": "kali-attacker",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    evt = events[0]
    assert evt.action == "logon_success"
    assert evt.user == "LAB\\student"
    assert evt.src_ip == "10.10.0.10"
    assert evt.network is None
    assert evt.metadata["logon_id"] == "0x3E7"
    assert evt.metadata["logon_type"] == 10
    assert evt.metadata["workstation"] == "kali-attacker"
    assert "session" in evt.labels


def test_normalize_logoff_event():
    records = [
        {
            "EventID": 4647,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T11:00:00Z",
            "TargetUserName": "LAB\\student",
            "LogonId": "0x3E7",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    assert events[0].action == "logoff"
    assert events[0].metadata["logon_id"] == "0x3E7"
    assert events[0].src_ip is None


def test_normalize_sysmon_file_create():
    records = [
        {
            "EventID": 11,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Windows\\Temp\\payload.exe",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    evt = events[0]
    assert evt.action == "file_create"
    assert evt.object is not None
    assert evt.object.type == "file"
    assert evt.object.name == "payload.exe"
    assert evt.object.path.endswith("payload.exe")
    assert evt.metadata["target_filename"].endswith("payload.exe")
    assert "file" in evt.labels


def test_normalize_registry_value_set():
    records = [
        {
            "EventID": 13,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\Public\\updater.exe",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    evt = events[0]
    assert evt.action == "registry_value_set"
    assert evt.object is not None
    assert evt.object.type == "registry_key"
    assert evt.metadata["target_object"].startswith("HKLM")
    assert evt.metadata["registry_value"] == "C:\\Users\\Public\\updater.exe"
    assert "registry" in evt.labels


def test_normalize_process_with_hashes_and_commandline():
    records = [
        {
            "EventID": 1,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -enc SQBFAFgA",
            "Hashes": "MD5=deadbeef,SHA256=aaaabbbb,IMPHASH=cccc",
            "ProcessId": 1234,
            "ProcessGuid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    evt = events[0]
    assert evt.process is not None
    assert evt.process.hash_sha256 == "aaaabbbb"
    assert evt.metadata["command_line"] == "powershell -enc SQBFAFgA"
    assert evt.metadata["hashes"]["SHA256"] == "aaaabbbb"
    assert evt.metadata["process_guid"] == "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"


def test_event_id_as_string_is_coerced():
    records = [
        {
            "EventID": "4624",
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "TargetUserName": "LAB\\student",
            "LogonId": "0x3E7",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    assert events[0].action == "logon_success"


def test_empty_values_from_evtx_dump_are_dropped():
    records = [
        {
            "EventID": 3,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "SourceIp": "-",
            "DestinationIp": "10.10.0.20",
            "DestinationPort": "-",
            "Protocol": "tcp",
        }
    ]

    events = normalize_windows_records(records, "task_demo_windows_001")

    evt = events[0]
    assert evt.src_ip is None
    assert evt.dst_ip == "10.10.0.20"
    assert evt.dst_port is None


def test_reconstruct_sessions_groups_by_logon_id():
    records = [
        {
            "EventID": 4624,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "TargetUserName": "LAB\\student",
            "LogonId": "0x3E7",
            "LogonType": 10,
            "IpAddress": "10.10.0.10",
        },
        {
            "EventID": 4647,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T11:00:00Z",
            "TargetUserName": "LAB\\student",
            "LogonId": "0x3E7",
        },
        {
            "EventID": 4624,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T12:00:00Z",
            "TargetUserName": "LAB\\student",
            "LogonId": "0x4B1",
            "LogonType": 2,
            "IpAddress": "10.10.2.10",
        },
    ]

    events = normalize_windows_records(records, "task_sess_001")
    sessions = reconstruct_sessions(events, "task_sess_001")

    assert len(sessions) == 2

    closed = next(s for s in sessions if s["logon_id"] == "0x3E7")
    assert closed["status"] == "closed"
    assert closed["start"] == "2026-09-08T10:00:00+00:00"
    assert closed["end"] == "2026-09-08T11:00:00+00:00"
    assert closed["src_ip"] == "10.10.0.10"
    assert closed["logon_type"] == 10
    assert closed["host_id"] == "officepc01"
    assert closed["user"] == "LAB\\student"
    assert len(closed["event_ids"]) == 2

    opened = next(s for s in sessions if s["logon_id"] == "0x4B1")
    assert opened["status"] == "open"
    assert opened["end"] is None
    assert opened["start"] == "2026-09-08T12:00:00+00:00"
    assert opened["src_ip"] == "10.10.2.10"


def test_reconstruct_sessions_ignores_failed_logons_and_unrelated_events():
    records = [
        {
            "EventID": 4625,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:00:00Z",
            "TargetUserName": "LAB\\attacker",
            "LogonId": "0x0",
            "IpAddress": "10.10.0.10",
        },
        {
            "EventID": 1,
            "Computer": "officepc01",
            "UtcTime": "2026-09-08T10:05:00Z",
            "Image": "C:\\Windows\\System32\\cmd.exe",
        },
    ]

    events = normalize_windows_records(records, "task_sess_002")
    sessions = reconstruct_sessions(events, "task_sess_002")

    assert sessions == []
