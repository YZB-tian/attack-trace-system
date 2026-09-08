from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from common.models import NormalizedEvent


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
        return int(value)
    except (TypeError, ValueError):
        return None


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


def _event_action(record: Dict[str, Any]) -> str:
    event_id = record.get("EventID")
    if event_id in (1, 2, 4688, 4689):
        return "process_create"
    if event_id in (3, 22, 5156, 5158):
        return "network_connect"
    if any(key in record for key in ("SourceIp", "DestinationIp", "SourcePort", "DestinationPort")):
        return "network_connect"
    if any(key in record for key in ("Image", "ParentImage", "CommandLine")):
        return "process_create"
    return "windows_event"


def normalize_windows_records(records: Iterable[Dict[str, Any]], task_id: str) -> List[NormalizedEvent]:
    """Normalize Windows EVTX/Sysmon-like events into the shared NormalizedEvent format."""
    normalized: List[NormalizedEvent] = []

    for idx, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            continue

        event_id = f"evt_{task_id}_{idx:04d}"
        timestamp = _as_iso8601(record.get("UtcTime") or record.get("TimeCreated") or record.get("timestamp"))
        host_id = _resolve_asset_host_id(record.get("Computer") or record.get("host_id"))
        source = record.get("Provider") or record.get("Source") or record.get("source") or "windows_eventlog"
        user = record.get("User") or record.get("user")
        action = _event_action(record)

        process_name = record.get("Image") or record.get("ProcessName")
        process_path = record.get("Image") or record.get("ProcessPath")
        parent_image = record.get("ParentImage") or record.get("ParentProcessName")
        pid = _safe_int(record.get("ProcessId") or record.get("PID"))
        ppid = _safe_int(record.get("ParentProcessId") or record.get("PPID"))

        process_info = None
        if process_name or process_path or pid is not None or ppid is not None:
            process_info = {
                "pid": pid,
                "ppid": ppid,
                "name": _basename(process_name) if process_name else None,
                "path": process_path,
                "hash_sha256": record.get("hash_sha256"),
            }

        object_info = None
        if process_name or parent_image:
            object_info = {
                "type": "process",
                "name": _basename(process_name) if process_name else None,
                "path": process_path,
            }

        network_info = None
        src_ip = record.get("SourceIp") or record.get("src_ip")
        dst_ip = record.get("DestinationIp") or record.get("dst_ip")
        if src_ip or dst_ip or record.get("Protocol"):
            network_info = {
                "protocol": record.get("Protocol") or record.get("protocol"),
                "direction": "outbound" if record.get("Initiated") in ("true", "True", True, "1") else None,
                "bytes_in": None,
                "bytes_out": None,
                "session_id": record.get("SessionGuid") or record.get("session_id"),
            }

        norm = NormalizedEvent(
            event_id=event_id,
            task_id=task_id,
            timestamp=timestamp,
            source_type="host_log",
            source=str(source),
            host_id=host_id,
            src_ip=src_ip,
            src_port=_safe_int(record.get("SourcePort") or record.get("src_port")),
            dst_ip=dst_ip,
            dst_port=_safe_int(record.get("DestinationPort") or record.get("dst_port")),
            user=user,
            action=action,
            process=process_info,
            object=object_info,
            network=network_info,
            raw_event=record,
            labels=["windows", "eventlog"] + (["process"] if process_name else []) + (["network"] if src_ip or dst_ip else []),
            metadata={
                "event_id_raw": record.get("EventID"),
                "computer": host_id,
                "provider": source,
            },
        )
        normalized.append(norm)

    return normalized
