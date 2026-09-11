"""Explainable heuristic detectors. Scores are not calibrated probabilities."""
from __future__ import annotations
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from statistics import mean, median, pstdev
from common.models import Alert
from .protocol_features import assess_http, assess_icmp_aggregate, assess_icmp_payload


@dataclass(frozen=True)
class NetworkConfig:
    window_seconds: int = 1800
    min_samples: int = 8
    min_span: int = 120
    risk_threshold: float = 0.65
    allowed_domains: tuple[str, ...] = ()
    allowed_destinations: tuple[str, ...] = ()
    suppress_ntp_shaped_beacons: bool = True
    detect_short_hex_dns: bool = True
    http_min_encoded_length: int = 64
    http_large_upload_bytes: int = 65536
    icmp_min_packets: int = 100
    icmp_min_average_bytes: int = 256
    icmp_payload_entropy: float = 6.2
    exfil_min_bytes: int = 131072


@lru_cache(maxsize=1)
def _assets_by_ip():
    data = json.loads((Path(__file__).resolve().parents[1] / "config" / "assets.json")
                      .read_text(encoding="utf-8"))
    return {a["ip"]: a for a in data["assets"]}


def seconds(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None: raise ValueError("event timestamp requires timezone")
    return dt.timestamp()


def entropy(text):
    counts = Counter(text)
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in counts.values()) if text else 0.0


def timing(events):
    times = sorted(set(seconds(e.timestamp) for e in events))
    gaps = [b - a for a, b in zip(times, times[1:])]
    if not gaps: return {"span": 0, "regularity": 0, "median_interval": None}
    mid = median(gaps)
    # CV alongside MAD avoids calling a burst plus one large gap perfectly periodic.
    variability = max(median(abs(x - mid) for x in gaps) / mid, pstdev(gaps) / mean(gaps))
    return {"span": times[-1] - times[0], "regularity": max(0, 1 - variability), "median_interval": mid}


def make_alert(events, rule, title, score, features, knowledge=None, technique=None,
               tactic="command-and-control"):
    events = sorted(events, key=lambda e: (seconds(e.timestamp), e.event_id))
    ids = sorted({e.event_id for e in events})
    aid = hashlib.sha256(json.dumps([events[0].task_id, rule, ids]).encode()).hexdigest()[:24]
    mapping = knowledge.mapping(technique, tactic) if knowledge and technique else None
    evidence = dict(features, sample_count=len(ids), score_kind="heuristic_not_probability")
    if technique and mapping is None: evidence["unresolved_technique_id"] = technique
    end = max((e.metadata.get("zeek", {}).get("end_time") or e.timestamp for e in events), key=seconds)
    return Alert(alert_id="alert_" + aid, task_id=events[0].task_id,
        timestamp_start=events[0].timestamp, timestamp_end=end, event_ids=ids,
        host_ids=sorted({e.host_id for e in events if e.host_id}), severity="high" if score >= .8 else "medium",
        rule_id=rule, rule_name=title, description=title + "; requires analyst verification",
        mitre=mapping, confidence=min(.95, score), evidence_summary=json.dumps(evidence, ensure_ascii=False),
        detector="network_heuristic_v1")


def detect_network(events, config=None, knowledge=None):
    cfg = config or NetworkConfig()
    if (cfg.window_seconds <= 0 or cfg.min_samples < 3 or cfg.min_span < 0
            or not 0 <= cfg.risk_threshold <= 1 or cfg.http_min_encoded_length < 16
            or cfg.http_large_upload_bytes <= 0 or cfg.icmp_min_packets < 1
            or cfg.icmp_min_average_bytes < 1 or not 0 <= cfg.icmp_payload_entropy <= 8
            or cfg.exfil_min_bytes <= 0):
        raise ValueError("invalid detector configuration")
    events = list(events)
    payload_counts = Counter((e.task_id, e.network.session_id, e.src_ip, e.dst_ip,
                              e.metadata.get("zeek", {}).get("icmp_type")) for e in events
        if e.source == "zeek" and e.action == "icmp_echo" and e.network and e.network.session_id
        and e.metadata.get("zeek", {}).get("payload_sample_len", 0) >= 64
        and e.metadata.get("zeek", {}).get("payload_entropy") is not None
        and e.metadata.get("zeek", {}).get("payload_sha256"))
    payload_sessions = {(key[0], key[1]) for key, count in payload_counts.items() if count >= cfg.min_samples}
    # Reverse-connection index: a service host opening a high port back to a peer
    # is the follow-through of many remote exploitation primitives.
    reverse_pairs = defaultdict(set)
    for e in events:
        if e.source == "zeek" and e.action == "network_connect" and e.src_ip and e.dst_ip and e.dst_port:
            reverse_pairs[(e.src_ip, e.dst_ip)].add(e.dst_port)
    groups = defaultdict(list)
    for e in events:
        if e.source != "zeek" or not e.network or not e.src_ip or not e.dst_ip: continue
        z = e.metadata.get("zeek", {})
        icmp_type = z.get("icmp_type") if e.network.protocol in ("icmp", "icmp6") else None
        if e.network.protocol in ("icmp", "icmp6"):
            # ICMP errors contain a quoted original packet; do not call it tunnel data.
            expected_types = (128, 129) if e.network.protocol == "icmp6" or ":" in e.src_ip else (0, 8)
            if icmp_type not in expected_types: continue
            if e.action == "network_connect" and (e.task_id, e.network.session_id) in payload_sessions:
                continue  # Prefer direct packet evidence over the same session's totals.
        domain = str(z.get("host") or z.get("query") or "").lower().rstrip(".")
        if e.dst_ip in cfg.allowed_destinations or any(domain == d or domain.endswith("." + d) for d in cfg.allowed_domains): continue
        # DNS grouping uses destination resolver and source; suffix statistics below stay explicit.
        group_domain = domain if e.action == "http_request" else ""
        key = (e.task_id, e.src_ip, e.dst_ip, e.dst_port, e.network.protocol, e.action, group_domain, icmp_type)
        groups[key].append(e)
    alerts = []
    for group in groups.values():
        group = sorted({e.event_id: e for e in group}.values(), key=lambda e: seconds(e.timestamp))
        # Anchored windows, not epoch buckets: traffic is never split at wall-clock boundaries.
        windows = []
        for e in group:
            if not windows or seconds(e.timestamp) - seconds(windows[-1][0].timestamp) > cfg.window_seconds:
                windows.append([])
            windows[-1].append(e)
        for rows in windows:
            z = [e.metadata.get("zeek", {}) for e in rows]
            action, proto = rows[0].action, rows[0].network.protocol
            time = timing(rows)
            sustained = len(rows) >= cfg.min_samples and time["span"] >= cfg.min_span
            rule, title, score, tech, tactic, features = None, "", 0.0, None, None, dict(time)
            if action == "dns_query" and len(rows) >= cfg.min_samples:
                queries = [str(x.get("query", "")).lower().rstrip(".") for x in z]
                labels = [q.split(".")[0] for q in queries]
                long_ratio = mean(len(s) >= 30 for s in labels)
                entropy_ratio = mean(len(s) >= 20 and entropy(s) >= 3.5 for s in labels)
                unique_ratio = len(set(labels)) / len(labels)
                txt_ratio = mean(x.get("qtype_name") == "TXT" or x.get("qtype") == 16 for x in z)
                # Suffixes are a lexical signal, NOT a public-suffix/eTLD+1 implementation.
                suffix_counts = Counter(".".join(q.split(".")[1:]) for q in queries if "." in q)
                concentration = max(suffix_counts.values(), default=0) / len(rows)
                score = .3 * long_ratio + .3 * entropy_ratio + .2 * unique_ratio * concentration + .1 * txt_ratio + .1 * min(1, len(rows) / max(time["span"], 1))
                features.update(long_label_ratio=long_ratio, high_entropy_ratio=entropy_ratio,
                    unique_label_ratio=unique_ratio, suffix_concentration=concentration, txt_ratio=txt_ratio)
                if long_ratio >= .5 and entropy_ratio >= .5:
                    rule, title, tech = "NET-DNS-TUNNEL", "Suspected DNS covert communication", "T1071.004"
                # dnscat-style polling can carry short hex messages: label length alone
                # misses it. Require sustained volume, changing labels, TXT and a
                # concentrated suffix together, without matching any known domain.
                hex_ratio = mean(bool(re.fullmatch(r"[0-9a-f]{16,63}", s)) and entropy(s) >= 2.5 for s in labels)
                short_hex = (cfg.detect_short_hex_dns and sustained and len(rows) >= 100
                             and hex_ratio >= .8 and unique_ratio >= .8
                             and txt_ratio >= .8 and concentration >= .8)
                features.update(hex_label_ratio=hex_ratio, short_hex_txt_pattern=short_hex)
                if short_hex:
                    score = max(score, .35 * hex_ratio + .25 * unique_ratio + .2 * concentration + .1 * txt_ratio)
                    rule, title, tech = "NET-DNS-TUNNEL", "Suspected DNS covert communication", "T1071.004"
            elif action == "http_request" and len(rows) >= cfg.min_samples:
                score, features = assess_http(rows, cfg, time)
                if score > 0:
                    rule, title, tech = "NET-HTTP-COVERT", "Suspected HTTP covert communication", "T1071.001"
            elif action == "network_connect" and proto in ("icmp", "icmp6"):
                score, features = assess_icmp_aggregate(rows, cfg, time, seconds)
                if score > 0:
                    rule, title, tech = "NET-ICMP-TUNNEL", "Suspected ICMP covert communication", "T1095"
            elif action == "icmp_echo" and proto in ("icmp", "icmp6"):
                score, features = assess_icmp_payload(rows, cfg, time)
                if score > 0:
                    rule, title, tech = "NET-ICMP-TUNNEL", "Suspected ICMP covert communication", "T1095"
            elif action == "irc_command":
                # UnrealIRCd-style backdoors are triggered by an IRC client that
                # registers, sends the payload and leaves a shell connecting back.
                # Repeated automated registrations plus the reverse connection are
                # the observable evidence; a single IRC session is not enough.
                nicknames = {str(x.get("value") or x.get("nick") or "") for x in z
                             if x.get("command") == "NICK"}
                nicknames.discard("")
                server, client = rows[0].dst_ip, rows[0].src_ip
                reverse = any(port >= 1024 for port in reverse_pairs.get((server, client), ()))
                features.update(irc_events=len(rows), distinct_nicknames=len(nicknames),
                                reverse_connection_observed=reverse, irc_server=server, irc_client=client)
                if len(rows) >= 4 and len(nicknames) >= 3 and reverse:
                    score = 0.85
                    rule, title, tech, tactic = ("NET-IRC-BACKDOOR-EXPLOIT",
                        "Automated IRC registrations followed by a reverse connection from the IRC service",
                        "T1190", "initial-access")
            if rule and score >= cfg.risk_threshold:
                alerts.append(make_alert(rows, rule, title, score, features, knowledge, tech,
                                         tactic or "command-and-control"))
            if action == "network_connect" and proto in ("tcp", "udp") and sustained and time["regularity"] >= .85:
                # Standard UDP NTP polling is intentionally periodic and fixed-size.
                # This is a narrow shape filter, not an IP allowlist or proof of benignness.
                ntp_shaped = proto == "udp" and all(
                    e.src_port == e.dst_port == 123 and isinstance(e.raw_event, dict)
                    and e.raw_event.get("orig_bytes") == e.raw_event.get("resp_bytes") == 48
                    for e in rows)
                if cfg.suppress_ntp_shaped_beacons and ntp_shaped:
                    continue
                sizes = [e.raw_event.get("orig_bytes") for e in rows if isinstance(e.raw_event, dict) and e.raw_event.get("orig_bytes") is not None]
                stable_size = len(sizes) == len(rows) and mean(sizes) > 0 and pstdev(sizes) / mean(sizes) <= .3
                if stable_size:
                    alerts.append(make_alert(rows, "NET-BEACON", "Periodic communication candidate (may be benign)",
                        .7 + .2 * time["regularity"], dict(time, stable_size=True), knowledge))
    # Exfiltration candidate: an internal host that pushes far more data out to an
    # external destination than it receives back, sustained over several
    # connections. Small credential-sized transfers are deliberately not flagged.
    uploads = defaultdict(list)
    for e in events:
        if e.source != "zeek" or e.action != "network_connect" or not e.network:
            continue
        if not e.src_ip or not e.dst_ip:
            continue
        src_asset, dst_asset = _assets_by_ip().get(e.src_ip), _assets_by_ip().get(e.dst_ip)
        if not src_asset or src_asset.get("zone") == "external":
            continue
        if not dst_asset or dst_asset.get("zone") != "external":
            continue
        uploads[(e.task_id, e.src_ip, e.dst_ip, src_asset.get("zone"))].append(e)
    for (task_id, src_ip, dst_ip, zone), rows in sorted(uploads.items()):
        rows.sort(key=lambda e: seconds(e.timestamp))
        windows = []
        for e in rows:
            if not windows or seconds(e.timestamp) - seconds(windows[-1][0].timestamp) > cfg.window_seconds:
                windows.append([])
            windows[-1].append(e)
        for group in windows:
            out_total = sum((e.network.bytes_out or 0) for e in group)
            in_total = sum((e.network.bytes_in or 0) for e in group)
            if len(group) < 3 or out_total < cfg.exfil_min_bytes:
                continue
            if in_total and out_total < 4 * in_total:
                continue
            features = {"source_ip": src_ip, "destination_ip": dst_ip, "source_zone": zone,
                        "bytes_out": out_total, "bytes_in": in_total, "connections": len(group),
                        "out_in_multiple": round(out_total / in_total, 2) if in_total else None,
                        "threshold_bytes": cfg.exfil_min_bytes,
                        "content_bytes_proven": False}
            alerts.append(make_alert(group, "NET-INTERNAL-SENSITIVE-UPLOAD",
                "Internal host uploaded a large volume to an external destination",
                .75, features, knowledge, "T1041", "exfiltration"))
    return alerts
