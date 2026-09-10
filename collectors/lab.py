"""Import the course evidence bundle, not an inferred or synthetic attack chain."""
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
import re
from pathlib import Path

from common.models import NormalizedEvent
from collectors.windows.adapter import normalize_windows_records
from collectors.linux import normalize_linux_records

ROOT = Path(__file__).resolve().parents[1]


def _json(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _time(value, offset=None):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        if offset is None:
            raise ValueError("timestamp missing timezone")
        dt = dt.replace(tzinfo=timezone(timedelta(hours=offset)))
    return dt.astimezone(timezone.utc)


def _verify(directory):
    verified = {}
    for entry in _json(directory / "sha256-manifest.json"):
        name = entry["file"]
        if Path(name).name != name or "/" in name or "\\" in name or ":" in name:
            raise ValueError("unsafe manifest path")
        path = (directory / name).resolve()
        if path.parent != directory or name in verified:
            raise ValueError("unsafe or duplicate manifest path")
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry["sha256"] or len(data) != entry["bytes"]:
            raise ValueError(f"integrity hash mismatch: {name}")
        verified[name] = digest
    actual = {p.name for p in directory.iterdir() if p.is_file() and p.name != "sha256-manifest.json"}
    if actual != set(verified):
        raise ValueError("files missing from manifest")
    return verified


def import_bundle(directory):
    directory = Path(directory).resolve()
    hashes = _verify(directory)
    manifest = _json(directory / "manifest.json")
    if manifest.get("classification") != "controlled_emulation":
        raise ValueError("unsupported evidence classification")
    run = manifest["run_id"]
    task = "task_" + run
    start = _time(manifest["started_utc"])
    timeline = _json(directory / "office-timeline.json")
    ends = [_time(x["TimeUtc"]) for x in timeline if x.get("Stage") == "complete"]
    if not ends or max(ends) < start:
        raise ValueError("missing valid experiment end")
    end = max(ends)
    assets = _json(ROOT / "config/assets.json")["assets"]
    by_id = {a["host_id"]: a for a in assets}
    by_ip = {a["ip"]: a["host_id"] for a in assets}
    events = []
    counts = Counter()
    consumed = {"manifest.json", "office-timeline.json"}

    def add(event, name, index):
        dt = _time(event.timestamp)
        if not start <= dt <= end:
            counts["excluded_outside_window"] += 1
            return
        reference = {"file": name, "record": index, "sha256": hashes[name]}
        event.event_id = "evt_" + hashlib.sha256(f"{run}|{name}|{hashes[name]}|{index}".encode()).hexdigest()[:24]
        event.timestamp = dt.isoformat()
        event.labels = sorted(set(event.labels + ["real_lab", "controlled_emulation"]))
        event.metadata.update(classification="controlled_emulation", run_id=run, raw_reference=reference,
                              experiment_membership="time_window_not_causality")
        events.append(event)

    def make(timestamp, source, host, action, raw, **kwargs):
        return NormalizedEvent(event_id="evt_pending", task_id=task, timestamp=timestamp,
            source_type=kwargs.pop("source_type", "host_log"), source=source, host_id=host,
            action=action, raw_event=raw, **kwargs)

    for name, host in (("office-security.json", "officepc01"), ("core-security.json", "coreserver01")):
        if name not in hashes:
            continue
        consumed.add(name)
        for index, record in enumerate(_json(directory / name), 1):
            event = normalize_windows_records([record], task)[0]
            if event.host_id != host:
                raise ValueError(f"asset mismatch in {name}: {record.get('host')}")
            event.metadata["record_id"] = record.get("record_id")
            add(event, name, index)

    name = "firewall-live-raw.json"
    if name in hashes:
        consumed.add(name)
        for index, record in enumerate(_json(directory / name), 1):
            event = make(_time(record["__timestamp__"], 8).isoformat(), "opnsense", "firewall01",
                "firewall_" + record["action"], record, source_type="boundary_log",
                src_ip=record.get("src"), dst_ip=record.get("dst"),
                src_port=int(record["srcport"]) if record.get("srcport") else None,
                dst_port=int(record["dstport"]) if record.get("dstport") else None,
                network={"protocol": record.get("protoname"), "direction": record.get("dir")},
                metadata={"assumed_timezone": "+08:00", "rule_label": record.get("label"), "interface": record.get("interface")})
            add(event, name, index)

    for name, host, port in (("web-events.jsonl", "webserver01", 80),
                             ("c2-events.jsonl", "c2server01", 8080),
                             ("smtp-events.jsonl", "mailserver01", 25)):
        if name not in hashes:
            continue
        consumed.add(name)
        for index, line in enumerate((directory / name).read_text(encoding="utf-8-sig").splitlines(), 1):
            if not line.strip():
                continue
            record = json.loads(line)
            payload_run = (record.get("payload") or {}).get("run_id")
            if payload_run and payload_run != run:
                counts["excluded_other_run"] += 1
                continue
            action = record["event"]
            if action == "login_attempt":
                action = "login_success" if record["success"] else "login_failure"
            event = make(record["timestamp"], "lab_service", host, action, record,
                src_ip=record.get("source_ip"), dst_ip=by_id[host]["ip"], dst_port=port,
                user=record.get("user"), metadata={"service_event": record["event"], "service": name})
            add(event, name, index)

    name = "web-auth.log"
    if name in hashes:
        consumed.add(name)
        for index, line in enumerate((directory / name).read_text(encoding="utf-8-sig").splitlines(), 1):
            parsed = normalize_linux_records([line], task, year=start.year, default_host=by_id["webserver01"]["hostname"])
            if not parsed:
                counts["unparsed_auth_lines"] += 1
            for event in parsed:
                add(event, name, index)

    name = "web-syscalls.strace"
    if name in hashes:
        consumed.add(name)
        pattern = re.compile(r"^(\d+)\s+(\d+\.\d+)\s+(\w+)\((.*)\)\s+=\s+(-?\d+)(.*)$")
        for index, line in enumerate((directory / name).read_text(encoding="utf-8").splitlines(), 1):
            match = pattern.match(line)
            if not match:
                counts["unparsed_strace_lines"] += 1
                continue
            pid, epoch, call, args, result, tail = match.groups()
            success = int(result) >= 0
            quoted = re.search(r'"((?:[^"\\]|\\.)*)"', args)
            path = quoted.group(1) if quoted else None
            action = "process_exec" if call == "execve" and success else "syscall"
            process = {"pid": int(pid)}
            if call == "execve" and success:
                process.update(path=path, name=Path(path).name if path else None)
            event = make(datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(), "strace", "webserver01",
                action, line, source_type="host_behavior", process=process,
                metadata={"syscall": call, "return_value": int(result), "success": success})
            add(event, name, index)

    for name, observer in (("web-network.pcap", "webserver01"), ("office-network.pcap", "switch01")):
        if name not in hashes:
            continue
        from scapy.all import PcapReader, IP, IPv6, TCP, UDP
        consumed.add(name)
        flows = {}
        with PcapReader(str(directory / name)) as capture:
            for index, packet in enumerate(capture, 1):
                dt = datetime.fromtimestamp(float(packet.time), timezone.utc)
                if not start <= dt <= end:
                    counts["excluded_pcap_packets"] += 1
                    continue
                layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                transport = packet.getlayer(TCP) or packet.getlayer(UDP)
                if layer is None or transport is None:
                    counts["unsupported_pcap_packets"] += 1
                    continue
                protocol = "tcp" if TCP in packet else "udp"
                key = (layer.src, int(transport.sport), layer.dst, int(transport.dport), protocol)
                if key not in flows:
                    flows[key] = {"first": index, "last": index, "start": dt.isoformat(), "end": dt.isoformat(), "packets": 0, "bytes": 0}
                flow = flows[key]
                flow.update(last=index, end=dt.isoformat(), packets=flow["packets"] + 1, bytes=flow["bytes"] + len(packet))
        for (src, sport, dst, dport, protocol), flow in flows.items():
            event = make(flow["start"], "pcap_scapy", by_ip.get(src), "network_observed", None,
                source_type="network_flow", src_ip=src, src_port=sport, dst_ip=dst, dst_port=dport,
                network={"protocol": protocol}, metadata={**flow, "observer_host_id": observer,
                    "aggregation": "directional_five_tuple_within_run", "connection_success_proven": False,
                    "byte_semantics": "captured_frame_bytes_including_retransmissions"})
            add(event, name, flow["first"])

    for name in hashes:
        if name not in consumed:
            counts["retained_evidence_files"] += 1
    events.sort(key=lambda e: (e.timestamp, e.event_id))
    report = dict(run_id=run, task_id=task, classification="controlled_emulation",
        start=start.isoformat(), end=end.isoformat(), events=len(events), verified_files=len(hashes),
        excluded_outside_window=counts["excluded_outside_window"], counters=dict(counts),
        sources=dict(Counter(e.source for e in events)),
        host_ids=sorted({e.host_id for e in events if e.host_id}),
        retained_not_normalized=sorted(set(hashes) - consumed),
        limitations=["Time-window membership is not proof of attack causality.",
                     "Office actions were separately orchestrated; no Web-to-Office compromise proven.",
                     "No real privilege escalation, memory injection or live LLM verified."])
    return events, report
