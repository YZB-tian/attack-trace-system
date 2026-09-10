"""Read Zeek output; packet capture and protocol parsing remain Zeek's job."""
from __future__ import annotations
import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List
from common.models import NormalizedEvent

ROOT = Path(__file__).resolve().parents[2]


def _id(prefix, *values):
    encoded = json.dumps(values, sort_keys=True, ensure_ascii=False, default=str).encode()
    return prefix + hashlib.sha256(encoded).hexdigest()[:24]


def _time(value):
    if isinstance(value, (int, float)) or re.fullmatch(r"\d+(\.\d+)?", str(value)):
        result = datetime.fromtimestamp(float(value), timezone.utc)
    else:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp requires timezone")
    return result.astimezone(timezone.utc)


def _number(value, integer=False):
    if value is None or value in ("-", "", "(empty)"):
        return None
    number = float(value)
    if not math.isfinite(number) or number < 0 or (integer and not number.is_integer()):
        raise ValueError(f"invalid nonnegative number: {value!r}")
    return int(number) if integer else number


def _unescape(value):
    return re.sub(r"\\x([0-9a-fA-F]{2})", lambda m: chr(int(m[1], 16)), value)


def read_zeek_log(path: str | Path) -> Iterable[Dict[str, Any]]:
    """JSONL or header-bearing TSV, with explicit file/line errors."""
    path = Path(path)
    resolved = path.resolve()
    reference_file, capture = str(resolved), str(resolved.parent)
    separator, set_separator, unset, empty = "\t", ",", "-", "(empty)"
    fields, types = [], []
    kind = path.name.split(".")[0]
    with path.open(encoding="utf-8-sig") as stream:
        for line_no, line in enumerate(stream, 1):
            line = line.rstrip("\r\n")
            if not line:
                continue
            if line.startswith("#separator "):
                separator = _unescape(line.split(" ", 1)[1])
                # RITA's exported fixtures spell the tab as \\t rather than \\x09.
                if separator == r"\t": separator = "\t"
                continue
            if line.startswith("#"):
                key, _, value = line.partition(separator)
                if key == "#fields": fields = value.split(separator)
                elif key == "#types": types = value.split(separator)
                elif key == "#path": kind = value
                elif key == "#set_separator": set_separator = _unescape(value)
                elif key == "#unset_field": unset = value
                elif key == "#empty_field": empty = value
                continue
            try:
                if line.lstrip().startswith("{"):
                    record = json.loads(line)
                else:
                    values = line.split(separator)
                    # Some Zeek exporters append one empty delimiter to every row.
                    if len(values) == len(fields) + 1 and values[-1] == "":
                        values.pop()
                    if not fields or len(values) != len(fields) or len(types) != len(fields):
                        raise ValueError("TSV requires matching #fields/#types headers and columns")
                    record = {}
                    for key, typ, value in zip(fields, types, values):
                        if value == unset: parsed = None
                        elif value == empty: parsed = [] if typ.startswith(("set[", "vector[")) else ""
                        elif typ == "bool":
                            if value not in ("T", "F"): raise ValueError("invalid Zeek bool")
                            parsed = value == "T"
                        elif typ.startswith(("set[", "vector[")):
                            parsed = [_unescape(v) for v in value.split(set_separator)]
                        elif typ in ("count", "port", "int"): parsed = int(value)
                        elif typ in ("time", "interval", "double"): parsed = float(value)
                        else: parsed = _unescape(value)
                        record[key] = parsed
                record["_log_type"] = kind
                record["_reference"] = {"file": reference_file, "line": line_no}
                record["_capture"] = capture
                yield record
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{path}:{line_no}: {exc}") from exc


def normalize_network_records(records: Iterable[Dict[str, Any]], task_id: str) -> List[NormalizedEvent]:
    assets = json.loads((ROOT / "config/assets.json").read_text(encoding="utf-8"))["assets"]
    by_ip = {a["ip"]: a for a in assets}
    result = []
    for record in records:
        kind = record.get("_log_type") or ("dns" if "query" in record else "http" if "uri" in record else "conn")
        if kind not in {"conn", "dns", "http", "icmp_payload"}:
            raise ValueError(f"unsupported Zeek log: {kind}")
        stamp = _time(record.get("ts", record.get("timestamp")))
        src, dst = record.get("id.orig_h"), record.get("id.resp_h")
        if not src or not dst:
            raise ValueError("Zeek record requires id.orig_h and id.resp_h")
        if kind == "icmp_payload":
            if not isinstance(record.get("is_orig"), bool): raise ValueError("icmp_payload requires is_orig bool")
            if record.get("proto") not in ("icmp", "icmp6"): raise ValueError("icmp_payload requires ICMP protocol")
            required = ("payload_len", "payload_sample_len", "payload_entropy", "payload_sha256", "icmp_type", "icmp_code")
            if any(record.get(k) in (None, "", "-") for k in required):
                raise ValueError("icmp_payload requires complete sample measurements and ICMP type/code")
            if record["is_orig"] is False: src, dst = dst, src
        src, dst = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
        proto = record.get("proto")
        src_asset, dst_asset = by_ip.get(src), by_ip.get(dst)
        owner = src_asset or dst_asset
        src_internal = src_asset and src_asset["zone"] != "external"
        dst_internal = dst_asset and dst_asset["zone"] != "external"
        direction = None
        if src_asset and dst_asset:
            direction = "internal" if src_internal and dst_internal else "outbound" if src_internal else "inbound" if dst_internal else "external"
        elif isinstance(record.get("local_orig"), bool) and isinstance(record.get("local_resp"), bool):
            local_src, local_dst = record["local_orig"], record["local_resp"]
            direction = "internal" if local_src and local_dst else "outbound" if local_src else "inbound" if local_dst else "external"
        duration = _number(record.get("duration"))
        uid = record.get("uid")
        session_id = _id("sess_", task_id, record.get("_capture", "records"), uid) if uid else None
        details = {k: record[k] for k in (
            "uid", "query", "qtype_name", "qtype", "rcode_name", "answers", "host", "uri", "method",
            "user_agent", "request_body_len", "response_body_len", "status_code", "service", "conn_state",
            "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes", "missed_bytes",
            "ats_body_sample_len", "ats_body_entropy", "ats_body_sha256",
            "payload_len", "payload_sample_len", "payload_entropy", "payload_sha256", "is_orig", "echo_id", "echo_seq",
        ) if record.get(k) is not None}
        for name in ("request_body_len", "response_body_len", "orig_pkts", "resp_pkts", "orig_ip_bytes", "resp_ip_bytes",
                     "ats_body_sample_len", "payload_len", "payload_sample_len", "echo_id", "echo_seq"):
            if name in details:
                details[name] = _number(details[name], True)
                if details[name] is None: details.pop(name)
        for name in ("ats_body_entropy", "payload_entropy"):
            if name in details:
                details[name] = _number(details[name])
                if details[name] is not None and details[name] > 8: raise ValueError(f"{name} must be within 0..8")
        for name in ("ats_body_sha256", "payload_sha256"):
            if name in details and not re.fullmatch(r"[0-9a-fA-F]{64}", str(details[name])):
                raise ValueError(f"invalid {name}")
        if kind == "icmp_payload" and ((details.get("payload_sample_len") or 0) > (details.get("payload_len") or 0)):
            raise ValueError("ICMP sample exceeds payload length")
        details.update(log_type=kind, duration=duration,
                       end_time=(stamp + timedelta(seconds=duration)).isoformat() if duration is not None else None)
        if proto in ("icmp", "icmp6"):
            details.update(icmp_type=_number(record.get("icmp_type") if kind == "icmp_payload" else record.get("id.orig_p"), True),
                           icmp_code=_number(record.get("icmp_code") if kind == "icmp_payload" else record.get("id.resp_p"), True))
        sent = _number(record.get("orig_bytes"), True) if kind == "conn" else None
        received = _number(record.get("resp_bytes"), True) if kind == "conn" else None
        if owner is not None and owner is dst_asset and src_asset is None:
            sent, received = received, sent
        result.append(NormalizedEvent(
            event_id=_id("evt_", task_id, record), task_id=task_id, timestamp=stamp.isoformat(),
            source_type="network_flow", source="zeek", host_id=owner["host_id"] if owner else None,
            src_ip=src, dst_ip=dst,
            src_port=None if proto in ("icmp", "icmp6") else _number(record.get("id.orig_p"), True),
            dst_port=None if proto in ("icmp", "icmp6") else _number(record.get("id.resp_p"), True),
            action={"conn": "network_connect", "dns": "dns_query", "http": "http_request", "icmp_payload": "icmp_echo"}[kind],
            network={"protocol": proto, "session_id": session_id, "direction": direction,
                     "bytes_out": sent, "bytes_in": received},
            raw_event={k: v for k, v in record.items() if not k.startswith("_")},
            metadata={"zeek": details, "raw_reference": record.get("_reference"),
                      "bytes_perspective": "host_id" if owner else "originator"},
        ))
    return result


def load_zeek_logs(directory: str | Path, task_id: str) -> List[NormalizedEvent]:
    directory = Path(directory)
    paths = [directory / f"{kind}.log" for kind in ("conn", "dns", "http", "icmp_payload")]
    paths = [p for p in paths if p.is_file()]
    if not paths:
        raise ValueError(f"no conn.log/dns.log/http.log/icmp_payload.log in {directory}")
    events = normalize_network_records((r for p in paths for r in read_zeek_log(p)), task_id)
    sessions = {e.network.session_id: e for e in events if e.action == "network_connect" and e.network.session_id}
    for event in events:
        session = sessions.get(event.network.session_id)
        if session and event is not session:
            event.metadata["session_event_id"] = session.event_id
            event.network.protocol = event.network.protocol or session.network.protocol
            if event.action == "http_request" and event.metadata["zeek"].get("host"):
                hosts = session.metadata["zeek"].setdefault("http_hosts", [])
                host = event.metadata["zeek"]["host"].lower().rstrip(".")
                if host not in hosts: hosts.append(host)
    return sorted(events, key=lambda e: (_time(e.timestamp), e.event_id))


def query_sessions(events: Iterable[NormalizedEvent], *, ip=None, host_id=None, start=None, end=None):
    """Connection events whose observed intervals overlap the query interval."""
    result = []
    assets = json.loads((ROOT / "config/assets.json").read_text(encoding="utf-8"))["assets"]
    host_ip = next((a["ip"] for a in assets if a["host_id"] == host_id), None)
    for e in events:
        if e.source != "zeek" or e.action != "network_connect": continue
        if ip and ip not in (e.src_ip, e.dst_ip): continue
        if host_id and e.host_id != host_id and (not host_ip or host_ip not in (e.src_ip, e.dst_ip)): continue
        last = e.metadata.get("zeek", {}).get("end_time") or e.timestamp
        if start and _time(last) < _time(start): continue
        if end and _time(e.timestamp) > _time(end): continue
        result.append(e)
    return result
