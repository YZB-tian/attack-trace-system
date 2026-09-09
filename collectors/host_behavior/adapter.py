from __future__ import annotations

import json
import ntpath
import posixpath
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from common.models import NormalizedEvent


def _first(record: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None and value != "":
            return value
    return None


def _as_iso8601(value: Any) -> str:
    if value is None or value == "":
        raise ValueError("missing timestamp")
    if isinstance(value, datetime):
        dt = value
    else:
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
        return int(value)
    except (TypeError, ValueError):
        return None


def _basename(value: Any) -> Optional[str]:
    if value is None or value == "":
        return None
    text = str(value)
    return ntpath.basename(text) or posixpath.basename(text) or text


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
        aliases = {asset.get("host_id"), asset.get("hostname"), asset.get("ip")}
        if any(alias and str(alias).lower() == host.lower() for alias in aliases):
            return str(asset["host_id"])
    return None


def _nested(record: Dict[str, Any], name: str) -> Dict[str, Any]:
    value = record.get(name)
    return value if isinstance(value, dict) else {}


def _event_action(record: Dict[str, Any], process: Dict[str, Any], object_info: Dict[str, Any]) -> str:
    explicit = _first(record, "action", "normalized_action")
    if explicit is not None:
        return str(explicit)

    event_name = str(_first(record, "event_type", "event", "type", "category", "name") or "").lower()
    syscall = _first(record, "syscall", "system_call", "systemcall")
    if syscall is not None:
        return "syscall"
    if any(token in event_name for token in ("exit", "terminate", "stop", "kill")) and process:
        return "process_exit"
    if any(token in event_name for token in ("exec", "spawn", "start", "create", "process")) and process:
        return "process_create"
    if object_info:
        return "file_access" if object_info.get("type") == "file" else "object_access"
    if process:
        return "process_event"
    if any(_first(record, key) is not None for key in ("src_ip", "dst_ip", "source_ip", "destination_ip")):
        return "network_connect"
    return "host_behavior"


def normalize_host_behavior(records: Iterable[Dict[str, Any]], task_id: str) -> List[NormalizedEvent]:
    """Normalize process, file, syscall, and host telemetry records."""
    normalized: List[NormalizedEvent] = []

    for idx, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue

        event_id = f"evt_{task_id}_{idx:04d}"
        timestamp = _as_iso8601(
            _first(record, "timestamp", "event_time", "time", "created_at", "UtcTime", "TimeCreated")
        )
        host_id = _resolve_asset_host_id(
            _first(record, "host_id", "hostname", "host", "computer", "Computer")
        )
        source = _first(record, "source", "provider", "collector") or "host_behavior"
        user = _first(record, "user", "username", "user_name", "account")

        raw_process = _nested(record, "process")
        process_name = _first(raw_process, "name", "process_name", "image") or _first(
            record, "process_name", "ProcessName", "image", "Image", "executable"
        )
        process_path = _first(raw_process, "path", "process_path", "image") or _first(
            record, "process_path", "ProcessPath", "image", "Image", "executable"
        )
        pid = _safe_int(
            _first(raw_process, "pid", "process_id", "PID")
            or _first(record, "pid", "process_id", "PID")
        )
        ppid = _safe_int(
            _first(raw_process, "ppid", "parent_pid", "parent_process_id", "PPID")
            or _first(record, "ppid", "parent_pid", "parent_process_id", "PPID")
        )
        process_info = None
        if process_name or process_path or pid is not None or ppid is not None:
            process_info = {
                "pid": pid,
                "ppid": ppid,
                "name": _basename(process_name),
                "path": process_path,
                "hash_sha256": _first(raw_process, "hash_sha256", "sha256")
                or _first(record, "hash_sha256", "sha256"),
            }

        raw_object = _nested(record, "object")
        file_path = _first(raw_object, "path", "file_path") or _first(
            record, "file_path", "path", "target_path", "object_path"
        )
        file_name = _first(raw_object, "name", "file_name") or _first(record, "file_name", "object_name")
        object_type = _first(raw_object, "type") or _first(record, "object_type")
        if file_path or file_name:
            object_info = {
                "type": str(object_type or "file"),
                "name": _basename(file_name or file_path),
                "path": file_path,
            }
        else:
            object_info = None

        src_ip = _first(record, "src_ip", "source_ip", "SourceIp")
        dst_ip = _first(record, "dst_ip", "destination_ip", "DestinationIp")
        protocol = _first(record, "protocol", "Protocol")
        network_info = None
        if src_ip or dst_ip or protocol:
            network_info = {
                "protocol": protocol,
                "direction": _first(record, "direction"),
                "bytes_in": _safe_int(_first(record, "bytes_in")),
                "bytes_out": _safe_int(_first(record, "bytes_out")),
                "session_id": _first(record, "session_id", "SessionGuid"),
            }

        action = _event_action(record, process_info or {}, object_info or {})
        event_type = _first(record, "event_type", "event", "category", "type")
        labels = ["host_behavior"]
        if process_info:
            labels.append("process")
        if object_info:
            labels.append(str(object_info["type"]))
        if _first(record, "syscall", "system_call", "systemcall") is not None:
            labels.append("syscall")
        if network_info:
            labels.append("network")

        normalized.append(
            NormalizedEvent(
                event_id=event_id,
                task_id=task_id,
                timestamp=timestamp,
                source_type="host_behavior",
                source=str(source),
                host_id=host_id,
                src_ip=src_ip,
                src_port=_safe_int(_first(record, "src_port", "source_port", "SourcePort")),
                dst_ip=dst_ip,
                dst_port=_safe_int(_first(record, "dst_port", "destination_port", "DestinationPort")),
                user=str(user) if user is not None else None,
                action=action,
                process=process_info,
                object=object_info,
                network=network_info,
                raw_event=record,
                labels=labels,
                metadata={
                    "event_type": event_type,
                    "syscall": _first(record, "syscall", "system_call", "systemcall"),
                    "computer": host_id,
                },
            )
        )

    return normalized
