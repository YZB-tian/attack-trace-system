from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from common.models import NormalizedEvent

# Security 4624/4625/4634/4647：登录会话类事件。这类事件只把来源 IP 写进 src_ip，
# 不构造 network 对象。
_LOGON_ACTIONS = {"logon_success", "logon_failed", "logoff"}

# EventID -> action。覆盖 Sysmon(1-26) 与 Windows Security 常用事件。
_EVENT_ACTION_MAP = {
    1: "process_create",       # Sysmon：进程创建
    2: "file_time_change",     # Sysmon file creation time change
    3: "network_connect",      # Sysmon：网络连接
    7: "image_load",           # Sysmon：镜像加载（反射加载特征）
    8: "remote_thread",        # Sysmon：远程线程创建（代码注入特征）
    10: "process_access",      # Sysmon：进程访问
    11: "file_create",         # Sysmon：文件创建
    12: "registry_create",     # Sysmon：注册表键/值创建删除
    13: "registry_value_set",  # Sysmon：注册表值设置
    14: "registry_rename",     # Sysmon：注册表键/值重命名
    22: "dns_query",           # Sysmon DNS query
    23: "file_delete",         # Sysmon：文件删除
    26: "file_delete",         # Sysmon：文件删除（检测）
    4624: "logon_success",     # Security：登录成功
    4625: "logon_failed",      # Security：登录失败
    4634: "logoff",            # Security：注销
    4647: "logoff",            # Security：用户启动注销
    4688: "process_create",    # Security：新进程创建
    4689: "process_terminate",  # Security：进程退出（旧版误归为 process_create，已修正）
    4663: "file_access",
    5140: "share_access",
    5145: "file_access",
    5156: "network_connect",   # Security：WFP 连接允许
    5158: "network_connect",   # Security：WFP 连接绑定
}

def _as_iso8601(value: Any) -> str:
    if value is None or value == "":
        raise ValueError("missing timestamp")
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"timestamp missing timezone: {value!r}")
    return dt.isoformat()


def _safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        text = str(value).strip()
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def _clean_text(value: Any) -> Optional[str]:
    """归一化文本字段：evtx_dump 等导出工具常用 "-" 表示空值，统一转为 None。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text or text == "-":
        return None
    return text


def _basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    # Path.name is platform-dependent: on Linux (CI runner) backslashes are not
    # separators, so normalize "\\" to "/" before splitting.
    return str(path).replace("\\", "/").rsplit("/", 1)[-1] or path


def _resolve_asset_host_id(raw_host: Any) -> Optional[str]:
    if raw_host is None:
        return None

    host = str(raw_host).strip()
    if not host:
        return None

    asset_path = Path(__file__).resolve().parents[2] / "config" / "assets.json"
    try:
        asset_data = json.loads(asset_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None

    for asset in asset_data.get("assets", []):
        aliases = {asset.get("host_id"), asset.get("hostname")}
        if any(alias and alias.lower() == host.lower() for alias in aliases):
            return str(asset["host_id"])

    return None


def _parse_sysmon_hashes(value: Any) -> Dict[str, str]:
    """解析 Sysmon 的 Hashes 字段："MD5=..,SHA256=..,IMPHASH=.." -> {"MD5":..,"SHA256":..}。

    也兼容已经是 dict 的导出格式。
    """
    hashes: Dict[str, str] = {}
    if not value:
        return hashes
    if isinstance(value, dict):
        for key, val in value.items():
            text = _clean_text(val)
            if text:
                hashes[str(key).strip().upper()] = text
        return hashes
    for part in str(value).split(","):
        if "=" not in part:
            continue
        key, _, val = part.partition("=")
        key = key.strip().upper()
        val = val.strip()
        if key and val and val != "-":
            hashes[key] = val
    return hashes


def _event_action(record: Dict[str, Any]) -> str:
    action = _EVENT_ACTION_MAP.get(_safe_int(record.get("EventID")))
    if action:
        return action
    # 无 EventID（或未知 EventID）时按字段启发式判断
    if any(key in record for key in ("SourceIp", "DestinationIp", "SourcePort", "DestinationPort")):
        return "network_connect"
    if "TargetFilename" in record:
        return "file_create"
    if "TargetObject" in record:
        return "registry_value_set"
    if any(key in record for key in ("Image", "ParentImage", "CommandLine")):
        return "process_create"
    return "windows_event"


def normalize_windows_records(records: Iterable[Dict[str, Any]], task_id: str) -> List[NormalizedEvent]:
    """将 Windows EVTX/Sysmon 风格事件归一化为共享 NormalizedEvent 格式。

    公共模型放不下的字段（命令行、哈希、目标文件、注册表键、登录会话等）统一放入
    metadata，跨模块传递仍只依赖 NormalizedEvent 本身。
    """
    normalized: List[NormalizedEvent] = []

    for idx, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue

        raw_record = record
        event_id = "evt_" + hashlib.sha256((task_id + json.dumps(record, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()[:24]
        if isinstance(record.get("fields"), dict):
            record = {**record["fields"], **record, "EventID": record["event_id"], "Computer": record.get("host")}
        timestamp = _as_iso8601(record.get("UtcTime") or record.get("TimeCreated") or record.get("timestamp"))
        host_id = _resolve_asset_host_id(record.get("Computer") or record.get("host_id"))
        source = (
            _clean_text(record.get("Provider"))
            or _clean_text(record.get("Source"))
            or _clean_text(record.get("source"))
            or "windows_eventlog"
        )
        user = (
            _clean_text(record.get("User"))
            or _clean_text(record.get("user"))
            or _clean_text(record.get("TargetUserName"))
            or _clean_text(record.get("SubjectUserName"))
        )
        action = _event_action(record)

        # 进程实体（行为主体）
        process_name = _clean_text(record.get("Image")) or _clean_text(record.get("NewProcessName")) or _clean_text(record.get("ProcessName"))
        process_path = (
            _clean_text(record.get("Image"))
            or _clean_text(record.get("NewProcessName"))
            or _clean_text(record.get("ProcessPath"))
            or _clean_text(record.get("ProcessName"))
        )
        parent_image = _clean_text(record.get("ParentImage")) or _clean_text(record.get("ParentProcessName"))
        pid = _safe_int(record.get("ProcessId") or record.get("PID"))
        ppid = _safe_int(record.get("ParentProcessId") or record.get("PPID"))
        if _safe_int(record.get("EventID")) == 4688:
            pid = _safe_int(record.get("NewProcessId"))
            ppid = _safe_int(record.get("ProcessId"))
        hashes = _parse_sysmon_hashes(record.get("Hashes"))
        sha256 = _clean_text(record.get("hash_sha256")) or hashes.get("SHA256")

        process_info = None
        if process_name or process_path or pid is not None or ppid is not None or sha256:
            process_info = {
                "pid": pid,
                "ppid": ppid,
                "name": _basename(process_name) if process_name else None,
                "path": process_path,
                "hash_sha256": sha256,
            }

        # 对象实体：公共模型 object 只有一份，优先级 文件 > 注册表 > 进程
        target_file = _clean_text(record.get("TargetFilename")) or _clean_text(record.get("ObjectName")) or _clean_text(record.get("RelativeTargetName"))
        target_key = _clean_text(record.get("TargetObject"))
        object_info = None
        if target_file:
            object_info = {"type": "file", "name": _basename(target_file), "path": target_file}
        elif target_key:
            object_info = {"type": "registry_key", "name": _basename(target_key), "path": target_key}
        elif process_name or parent_image:
            object_info = {
                "type": "process",
                "name": _basename(process_name) if process_name else None,
                "path": process_path,
            }

        src_ip = (
            _clean_text(record.get("SourceIp"))
            or _clean_text(record.get("src_ip"))
            or _clean_text(record.get("IpAddress"))
        )
        dst_ip = _clean_text(record.get("DestinationIp")) or _clean_text(record.get("dst_ip"))

        # 登录事件只把来源 IP 放进 src_ip，不构造 network 对象
        network_info = None
        if (src_ip or dst_ip or record.get("Protocol")) and action not in _LOGON_ACTIONS:
            network_info = {
                "protocol": record.get("Protocol") or record.get("protocol"),
                "direction": "outbound" if record.get("Initiated") in ("true", "True", True, "1") else None,
                "bytes_in": None,
                "bytes_out": None,
                "session_id": record.get("SessionGuid") or record.get("session_id"),
            }

        # 公共模型放不下的实体字段统一进 metadata（自由 dict）
        metadata: Dict[str, Any] = {
            "event_id_raw": record.get("EventID"),
            "computer": host_id,
            "provider": source,
        }
        command_line = _clean_text(record.get("CommandLine"))
        if command_line:
            metadata["command_line"] = command_line
        if parent_image:
            metadata["parent_image"] = parent_image
        if hashes:
            metadata["hashes"] = hashes
        if target_file:
            metadata["target_filename"] = target_file
        if target_key:
            metadata["target_object"] = target_key
            registry_value = _clean_text(record.get("Details"))
            if registry_value:
                metadata["registry_value"] = registry_value
        process_guid = _clean_text(record.get("ProcessGuid"))
        if process_guid:
            metadata["process_guid"] = process_guid
            parent_guid = _clean_text(record.get("ParentProcessGuid"))
            if parent_guid:
                metadata["parent_process_guid"] = parent_guid
        # 登录会话字段：LogonId 是会话重建的关联键
        logon_id = (_clean_text(record.get("LogonId")) or _clean_text(record.get("logon_id"))
                    or _clean_text(record.get("TargetLogonId")) or _clean_text(record.get("SubjectLogonId")))
        if _safe_int(record.get("EventID")) == 4688 and not _clean_text(record.get("TargetUserName")):
            logon_id = _clean_text(record.get("SubjectLogonId"))
        if logon_id:
            metadata["logon_id"] = logon_id
            logon_type = _safe_int(record.get("LogonType"))
            if logon_type is not None:
                metadata["logon_type"] = logon_type
        workstation = _clean_text(record.get("WorkstationName"))
        if workstation:
            metadata["workstation"] = workstation
        target_sid = _clean_text(record.get("TargetUserSid"))
        if target_sid:
            metadata["target_user_sid"] = target_sid

        labels = ["windows", "eventlog"]
        if process_name:
            labels.append("process")
        if action in _LOGON_ACTIONS:
            labels.append("session")
        elif src_ip or dst_ip:
            labels.append("network")
        if target_file:
            labels.append("file")
        if target_key:
            labels.append("registry")

        norm = NormalizedEvent(
            event_id=event_id,
            task_id=task_id,
            timestamp=timestamp,
            source_type="host_log",
            source=str(source),
            host_id=host_id,
            src_ip=src_ip,
            src_port=_safe_int(record.get("SourcePort") or record.get("src_port") or record.get("IpPort")),
            dst_ip=dst_ip,
            dst_port=_safe_int(record.get("DestinationPort") or record.get("dst_port")),
            user=user,
            action=action,
            process=process_info,
            object=object_info,
            network=network_info,
            raw_event=raw_record,
            labels=labels,
            metadata=metadata,
        )
        normalized.append(norm)

    return normalized


# 无法解析时间的会话排在最后
_MAX_TS = datetime.max.replace(tzinfo=timezone.utc)

_LOGON_START = {"logon_success"}
_LOGON_END = {"logoff"}


def _sort_ts(text: Optional[str]) -> datetime:
    if not text:
        return _MAX_TS
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return _MAX_TS


def reconstruct_sessions(events: List[NormalizedEvent], task_id: str) -> List[Dict[str, Any]]:
    """由 logon_success / logoff 事件重建用户登录会话时间线。

    关联键为 host_id + user + metadata.logon_id（同一主机上 LogonId 唯一）。
    - logon_success 开会话（记录 start、src_ip、logon_type）；
    - logoff 关会话（记录 end，status 置为 closed）；
    - logon_failed 不参与重建（失败登录没有会话）；
    - 只有 logoff 的会话保留为 start=None 的已关闭会话（登录发生在采集窗口之前）。

    注意：返回的是模块内辅助视图（普通 dict），不属于五个公共契约对象；
    跨模块传递的数据仍必须使用 NormalizedEvent。
    """
    sessions: Dict[Tuple[Optional[str], Optional[str], str], Dict[str, Any]] = {}

    for evt in events:
        if evt.action not in _LOGON_START | _LOGON_END:
            continue
        logon_id = evt.metadata.get("logon_id")
        if logon_id is None:
            continue

        key = (evt.host_id, evt.user, str(logon_id))
        sess = sessions.get(key)
        if sess is None:
            sess = {
                "task_id": task_id,
                "host_id": evt.host_id,
                "user": evt.user,
                "logon_id": str(logon_id),
                "logon_type": None,
                "src_ip": None,
                "start": None,
                "end": None,
                "status": "open",
                "event_ids": [],
            }
            sessions[key] = sess

        sess["event_ids"].append(evt.event_id)
        if evt.action in _LOGON_START:
            sess["start"] = evt.timestamp
            sess["src_ip"] = evt.src_ip
            sess["logon_type"] = evt.metadata.get("logon_type")
        elif evt.action in _LOGON_END and sess["end"] is None:
            sess["end"] = evt.timestamp
            sess["status"] = "closed"

    return sorted(sessions.values(), key=lambda s: (_sort_ts(s["start"]), _sort_ts(s["end"])))
