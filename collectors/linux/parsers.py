"""Linux 日志行解析与实体/动作提取（仅模块内部使用）。

跨模块输出统一为 common.models.NormalizedEvent；本文件负责把
原始文本行（auth.log/syslog 与 auditd）拆成结构化字段，供 adapter 组装。

覆盖需求点：
- 时间序列对齐：无年份/无时区的 syslog 时间戳、auditd epoch 时间戳
  统一补全为带时区 ISO 8601；
- 日志范式解析：RFC3164（含 <PRI> 前缀）、RFC5424（含 <PRI>VERSION 前缀与
  空格分隔正文）、auditd（含 node=HOST 前缀）三种头部统一解析；
- 关键信息提取：用户/进程(pid/ppid/path)/文件或命令对象/源 IP/源端口。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------- 时间归一

_MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

DEFAULT_TZ_OFFSET_HOURS = 8


def fixed_tz(offset_hours: int = DEFAULT_TZ_OFFSET_HOURS) -> timezone:
    return timezone(timedelta(hours=offset_hours))


# ---------------------------------------------------------------- auth.log / syslog

# 可选的 <PRI>（RFC3164）或 <PRI>VERSION（RFC5424）前缀
_PRI_RE = re.compile(r"^<\d+>(?:\d+\s+)?")

# RFC3164 syslog 行：Mmm dd HH:MM:SS host program[pid]: message
_SYSLOG_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hms>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# RFC5424 / 完整 ISO 时间戳行：2026-09-08T10:00:00+08:00 host ...（后接 prog[pid]: 或 RFC5424 正文）
_ISO_HEAD_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<rest>.*)$"
)

# ISO 头之后的 program[pid]: message 部分（RFC3164 正文）
_PROG_RE = re.compile(
    r"^(?P<program>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

# RFC5424 正文：APP-NAME PROCID MSGID [SD] MSG（空格分隔，无 prog[pid]: 冒号）
_RFC5424_BODY_RE = re.compile(
    r"^(?P<program>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\S+)\s+(?P<message>.*)$"
)

# ---------------------------------------------------------------- auditd

# type=SYSCALL msg=audit(epoch[.ms]:seq): body（可带 node=HOST 前缀，用于远程聚合）
_AUDIT_HEAD_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>\w+)\s+msg=audit\((?P<epoch>\d+)(?:\.(?P<ms>\d+))?:(?P<seq>\d+)\):\s*"
    r"(?P<body>.*)$"
)

# auditd 的 key=value 字段，value 可带单/双引号（含空格）
_AUDIT_KV_RE = re.compile(r"(\w+)=(\"(?:[^\"]*)\"|'(?:[^']*)'|\S+)")

# auditd 中表示「未设置」的哨兵值
_AUDIT_NULL_VALUES = {"?", "(null)", "unknown", ""}


@dataclass
class ParsedRecord:
    timestamp_dt: datetime          # 带时区的 aware datetime（已补年/时区，未应用 host 偏移）
    hostname: Optional[str]
    program: Optional[str]
    pid: Optional[int]
    message: str
    action: str
    user: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[int]
    object_type: Optional[str]
    object_name: Optional[str]
    target_user: Optional[str]
    session_id: Optional[str]
    ppid: Optional[int] = None
    process_path: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    extra_metadata: Dict[str, Any] = field(default_factory=dict)


def _int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return path.rsplit("/", 1)[-1]


def _clean_addr(value: Optional[str]) -> Optional[str]:
    """把 auditd 的未设置哨兵值归一为 None，避免输出 '?'/'(null)' 等非法 IP。"""
    if value is None:
        return None
    v = value.strip()
    return None if v in _AUDIT_NULL_VALUES else v


def _parse_iso(ts: str) -> Optional[datetime]:
    ts = ts.strip()
    if " " in ts:
        ts = ts.replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _parse_syslog(line: str, year: Optional[int], tz: timezone):
    """解析行头部，返回 (hostname, program, pid, message, aware_datetime)。

    兼容三种头部：
    - RFC3164：Mmm dd HH:MM:SS host prog[pid]: msg（可带 <PRI> 前缀）
    - RFC5424：<PRI>VERSION TIMESTAMP HOST APP-NAME PROCID MSGID [SD] MSG
    - 完整 ISO 时间戳头：TIMESTAMP host prog[pid]: msg
    """
    # 先剥离可选的 <PRI>（RFC3164）或 <PRI>VERSION（RFC5424）前缀
    line = _PRI_RE.sub("", line, count=1)

    m = _ISO_HEAD_RE.match(line)
    if m:
        dt = _parse_iso(m.group("ts"))
        if dt is None:
            return None, None, None, None, None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=tz)
        rest = m.group("rest")
        pm = _PROG_RE.match(rest)  # 传统 prog[pid]: message 形式
        if pm:
            return m.group("host"), pm.group("program"), _int(pm.group("pid")), pm.group("message"), dt
        rm = _RFC5424_BODY_RE.match(rest)  # RFC5424 空格分隔形式
        if rm:
            return m.group("host"), rm.group("program"), _int(rm.group("procid")), rm.group("message"), dt
        return m.group("host"), None, None, rest, dt

    m = _SYSLOG_RE.match(line)
    if m:
        mon = _MONTHS.get(m.group("mon").lower())
        if mon is None:
            return None, None, None, None, None
        now = datetime.now(tz)
        y = year if year is not None else now.year
        day = int(m.group("day"))
        hh, mm, ss = map(int, m.group("hms").split(":"))
        dt = datetime(y, mon, day, hh, mm, ss, tzinfo=tz)
        # 无年份时按当前年补齐；若补出的时间明显晚于当前（跨年边界，如 1 月解析 12 月日志），回退一年
        if year is None and dt - now > timedelta(days=1):
            dt = dt.replace(year=y - 1)
        return m.group("host"), m.group("program"), _int(m.group("pid")), m.group("message"), dt

    return None, None, None, None, None


def _info(
    action: str,
    user: Optional[str] = None,
    src_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    object_type: Optional[str] = None,
    object_name: Optional[str] = None,
    target_user: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "action": action,
        "user": user,
        "src_ip": src_ip,
        "src_port": src_port,
        "object_type": object_type,
        "object_name": object_name,
        "target_user": target_user,
    }


def _extract_info(program: Optional[str], message: str) -> Dict[str, Any]:
    prog = (program or "").lower()
    m = message.strip()

    if prog == "sshd":
        r = re.search(
            r"Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+"
            r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)", m,
        )
        if r:
            return _info("login_success", user=r["user"], src_ip=r["ip"], src_port=_int(r["port"]))
        r = re.search(
            r"Failed\s+(?:password|publickey|keyboard-interactive\S*)\s+for\s+"
            r"(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+"
            r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)", m,
        )
        if r:
            return _info("login_failure", user=r["user"], src_ip=r["ip"], src_port=_int(r["port"]))
        r = re.search(r"Received\s+disconnect\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)", m)
        if r:
            return _info("disconnect", src_ip=r["ip"], src_port=_int(r["port"]))
        r = re.search(
            r"Disconnected\s+from\s+(?:authenticating\s+)?user\s+(?P<user>\S+)\s+"
            r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)", m,
        )
        if r:
            return _info("logout", user=r["user"], src_ip=r["ip"], src_port=_int(r["port"]))

    if prog == "sudo":
        r = re.search(r"^(?P<user>\S+)\s*:\s*.*COMMAND=(?P<cmd>.*?)\s*$", m)
        if r:
            tu = re.search(r"\bUSER=(\S+)", m)
            return _info(
                "sudo_exec",
                user=r["user"],
                object_type="command",
                object_name=r["cmd"].strip(),
                target_user=tu.group(1) if tu else None,
            )

    if prog == "su":
        r = re.search(r"\(to\s+(?P<target>\S+)\)\s+(?P<user>\S+)", m)
        if r:
            return _info("user_switch", user=r["user"], target_user=r["target"])

    # 通用 session opened / closed（sshd、sudo、login、pam 等都会落在这里）
    r = re.search(r"session\s+opened\s+for\s+user\s+(?P<user>\S+)", m)
    if r:
        return _info("session_open", user=r["user"])
    r = re.search(r"session\s+closed\s+for\s+user\s+(?P<user>\S+)", m)
    if r:
        return _info("logout", user=r["user"])

    return _info("auth_log")


def _labels_for(action: str) -> List[str]:
    labels = ["auth"]
    if action in ("login_success", "login_failure", "session_open", "logout", "disconnect"):
        labels.append("login")
    elif action in ("sudo_exec", "user_switch"):
        labels.append("privilege_escalation")
    return labels


def parse_authlog_line(
    line: str,
    year: Optional[int] = None,
    tz: Optional[timezone] = None,
) -> Optional[ParsedRecord]:
    """解析单条 auth.log/syslog 行，返回结构化 ParsedRecord；无法解析返回 None。"""
    line = line.strip()
    if not line:
        return None
    tz = tz or fixed_tz()

    hostname, program, pid, message, dt = _parse_syslog(line, year, tz)
    if dt is None:
        return None

    info = _extract_info(program, message)
    session_id = f"{program}-{pid}" if (program and pid is not None) else None

    return ParsedRecord(
        timestamp_dt=dt,
        hostname=hostname,
        program=program,
        pid=pid,
        message=message,
        action=info["action"],
        user=info["user"],
        src_ip=info["src_ip"],
        src_port=info["src_port"],
        object_type=info["object_type"],
        object_name=info["object_name"],
        target_user=info["target_user"],
        session_id=session_id,
        labels=_labels_for(info["action"]),
    )


# ---------------------------------------------------------------- auditd

def is_auditd_line(line: str) -> bool:
    """判断是否 auditd 行（含可选的 node=HOST 远程聚合前缀）。"""
    return bool(_AUDIT_HEAD_RE.match(line))


def _parse_audit_kv(s: str) -> Dict[str, str]:
    """解析 auditd 的 key=value 串（value 可带单/双引号）。"""
    result: Dict[str, str] = {}
    for m in _AUDIT_KV_RE.finditer(s):
        val = m.group(2)
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]
        result[m.group(1)] = val
    return result


def _audit_argv(fields: Dict[str, str]) -> Optional[str]:
    """把 EXECVE 的 a0/a1/... 字段拼接为完整命令行。"""
    argv = []
    i = 0
    while True:
        key = f"a{i}"
        if key not in fields:
            break
        argv.append(fields[key])
        i += 1
    return " ".join(argv) if argv else None


def _audit_info(atype: str, fields: Dict[str, str], nested: Dict[str, str]) -> Dict[str, Any]:
    """按 auditd 事件类型映射到统一 action 与实体。"""
    # 登录 / 认证 / 注销类事件：用户名在嵌套 msg 的 acct，来源 IP 在 addr
    if atype == "USER_LOGIN":
        # op=login 只带数值 uid（id），用户名在 USER_AUTH 的 acct 中
        return _info(
            "session_open",
            user=nested.get("acct") or nested.get("id") or fields.get("auid"),
            src_ip=_clean_addr(nested.get("addr")),
        )
    if atype == "USER_AUTH":
        res = nested.get("res")
        action = "login_success" if res == "success" else "login_failure"
        return _info(action, user=nested.get("acct"), src_ip=_clean_addr(nested.get("addr")))
    if atype in ("USER_LOGOUT", "USER_END"):
        return _info("logout", user=nested.get("acct"), src_ip=_clean_addr(nested.get("addr")))

    # 进程执行：SYSCALL(59=execve) / EXECVE 参数
    if atype == "SYSCALL":
        action = "process_exec" if fields.get("syscall") == "59" else "syscall"
        return _info(action, user=fields.get("auid"),
                     object_type="process", object_name=fields.get("exe"))
    if atype == "EXECVE":
        cmd = _audit_argv(fields)
        return _info("command_args", user=fields.get("auid"),
                     object_type="command" if cmd else None,
                     object_name=cmd)

    # 文件访问
    if atype == "PATH":
        return _info("file_access", object_type="file", object_name=fields.get("name"))

    # 配置变更（如修改审计规则）
    if atype == "CONFIG_CHANGE":
        return _info("config_change", user=fields.get("auid"))

    return _info("audit_event")


def _audit_labels_for(action: str) -> List[str]:
    labels = ["audit"]
    if action in ("login_success", "login_failure", "session_open", "logout"):
        labels.append("login")
    elif action == "process_exec":
        labels.append("process")
    elif action == "file_access":
        labels.append("file")
    elif action == "config_change":
        labels.append("config")
    return labels


def parse_auditd_line(
    line: str,
    tz: Optional[timezone] = None,
    hostname: Optional[str] = None,
) -> Optional[ParsedRecord]:
    """解析单条 auditd 行，返回结构化 ParsedRecord；无法解析返回 None。

    auditd 本地日志行不含主机名，hostname 需由调用方（records 的 host 字段
    或 normalize_linux_records 的 default_host）提供；若行首带 node=HOST
    前缀（远程聚合），则优先用 node 值。
    """
    line = line.strip()
    if not line:
        return None
    tz = tz or fixed_tz()

    m = _AUDIT_HEAD_RE.match(line)
    if not m:
        return None

    atype = m.group("type")
    epoch = int(m.group("epoch"))
    ms = int(m.group("ms")) if m.group("ms") else 0
    seq = m.group("seq")
    body = m.group("body")

    hostname = hostname or m.group("node")
    dt = datetime.fromtimestamp(epoch, tz) + timedelta(milliseconds=ms)

    fields = _parse_audit_kv(body)
    nested = _parse_audit_kv(fields.get("msg", ""))

    info = _audit_info(atype, fields, nested)

    exe = fields.get("exe") or nested.get("exe")
    program = fields.get("comm") or _basename(exe) or _basename(fields.get("a0"))
    pid = _int(fields.get("pid"))
    ppid = _int(fields.get("ppid"))

    extra: Dict[str, Any] = {
        "audit_type": atype,
        "audit_seq": seq,
    }
    if "syscall" in fields:
        extra["syscall"] = fields["syscall"]
    if "success" in fields:
        extra["success"] = fields["success"]
    if "key" in fields and fields["key"] not in ("(null)", ""):
        extra["audit_key"] = fields["key"]
    if "ses" in fields and fields["ses"] not in ("(null)", "4294967295"):
        extra["ses"] = fields["ses"]
    if "terminal" in nested:
        extra["terminal"] = nested["terminal"]

    session_id = extra.get("ses")

    return ParsedRecord(
        timestamp_dt=dt,
        hostname=hostname,
        program=program,
        pid=pid,
        message=line,
        action=info["action"],
        user=info["user"],
        src_ip=info["src_ip"],
        src_port=info["src_port"],
        object_type=info["object_type"],
        object_name=info["object_name"],
        target_user=info["target_user"],
        session_id=session_id,
        ppid=ppid,
        process_path=exe,
        labels=_audit_labels_for(info["action"]),
        extra_metadata=extra,
    )
