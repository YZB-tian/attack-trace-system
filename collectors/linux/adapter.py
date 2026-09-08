"""Linux 日志采集/分析模块入口。

把 auth.log/syslog 与 auditd 原始文本行归一为公共模型 NormalizedEvent。
跨模块输出只能是 NormalizedEvent（见 collectors/linux/README.md）。
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from common.enums import SourceType
from common.id_utils import new_id
from common.models import EventObject, NormalizedEvent, ProcessInfo

from . import parsers
from .hostmap import hostname_to_host_id


def _raw_line(rec: Any) -> Tuple[Optional[str], Optional[str]]:
    """提取原始行与可选的 host 提示，返回 (raw, host_hint)。"""
    if isinstance(rec, str):
        return (rec.strip() or None), None
    if isinstance(rec, dict):
        raw = rec.get("raw")
        host = rec.get("host") or rec.get("hostname")
        if isinstance(raw, str):
            return (raw.strip() or None), (host if isinstance(host, str) else None)
    return None, None


def _to_event(
    parsed: parsers.ParsedRecord,
    timestamp_iso: str,
    raw_line: str,
    task_id: str,
    source: str,
) -> NormalizedEvent:
    host_id = hostname_to_host_id(parsed.hostname)

    process = None
    if parsed.program or parsed.pid is not None or parsed.ppid is not None or parsed.process_path:
        process = ProcessInfo(
            pid=parsed.pid,
            ppid=parsed.ppid,
            name=parsed.program,
            path=parsed.process_path,
        )

    obj = None
    if parsed.object_name:
        obj = EventObject(type=parsed.object_type, name=parsed.object_name)

    metadata: Dict[str, Any] = dict(parsed.extra_metadata)
    if parsed.session_id:
        metadata["session_id"] = parsed.session_id
    if parsed.target_user:
        metadata["target_user"] = parsed.target_user
    if parsed.hostname and parsed.hostname != host_id:
        metadata["raw_hostname"] = parsed.hostname

    return NormalizedEvent(
        event_id=new_id("event"),
        task_id=task_id,
        timestamp=timestamp_iso,
        source_type=SourceType.HOST_LOG,
        source=source,
        host_id=host_id,
        src_ip=parsed.src_ip,
        src_port=parsed.src_port,
        user=parsed.user,
        action=parsed.action,
        process=process,
        object=obj,
        raw_event={"raw": raw_line, "program": parsed.program, "message": parsed.message},
        labels=parsed.labels,
        metadata=metadata,
    )


def normalize_linux_records(
    records: Iterable[Dict[str, Any]],
    task_id: str,
    clock_offset: Optional[Dict[str, int]] = None,
    tz_offset_hours: int = parsers.DEFAULT_TZ_OFFSET_HOURS,
    year: Optional[int] = None,
    default_host: Optional[str] = None,
) -> List[NormalizedEvent]:
    """把 Linux 日志原始记录归一为 list[NormalizedEvent]。

    records 每条可以是：
      - {"raw": "Sep  8 10:00:00 webserver01 sshd[1234]: Accepted ..."}
      - {"raw": "type=SYSCALL msg=audit(...): ...", "host": "webserver01"}
      - 或纯字符串（直接是原始行）
    按行首自动识别来源：以 "type=" 开头走 auditd 解析，否则走 auth.log/syslog 解析。

    clock_offset：可选 {hostname: 偏移秒数}，用于跨主机时钟对齐。
    default_host：auditd 本地行不含主机名时，用该主机名做 host_id 反查。
    """
    clock_offset = clock_offset or {}
    tz = parsers.fixed_tz(tz_offset_hours)
    events: List[NormalizedEvent] = []

    for rec in records:
        line, host_hint = _raw_line(rec)
        if not line:
            continue

        host = host_hint or default_host
        if parsers.is_auditd_line(line):
            parsed = parsers.parse_auditd_line(line, tz=tz, hostname=host)
            source = "auditd"
        else:
            parsed = parsers.parse_authlog_line(line, year=year, tz=tz)
            source = "auth.log"
        if parsed is None:
            continue

        off_host = parsed.hostname or host
        offset = clock_offset.get(off_host, 0) if off_host else 0
        ts_dt = parsed.timestamp_dt + timedelta(seconds=offset) if offset else parsed.timestamp_dt
        events.append(_to_event(parsed, ts_dt.isoformat(), line, task_id, source))

    return events
