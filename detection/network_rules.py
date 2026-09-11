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
    suppress_dhcp_beacons: bool = True
    suppress_unanswered_udp123_retries: bool = True
    suppress_dns_retries: bool = True
    detect_short_hex_dns: bool = True
    http_min_encoded_length: int = 64
    http_large_upload_bytes: int = 65536
    icmp_min_packets: int = 100
    icmp_min_average_bytes: int = 256
    icmp_payload_entropy: float = 6.2
    exfil_min_bytes: int = 131072

    # Recall-oriented connection heuristics. These remain endpoint-grouped so
    # ordinary broad scans do not become one giant alert window.
    failed_retry_min_samples: int = 6
    failed_retry_min_span: int = 20
    failed_retry_ratio: float = 0.80
    failed_retry_no_response_ratio: float = 0.80
    failed_retry_src_port_churn_ratio: float = 0.20
    irc_conn_min_samples: int = 6
    irc_conn_min_span: int = 30
    horizontal_scan_window_seconds: int = 300
    horizontal_scan_min_unique_destinations: int = 20

    # Response-heavy HTTP transfer campaign. This is intentionally campaign-
    # level rather than a single large download: ordinary downloads can be
    # large, while repeated multi-endpoint transfers are more suspicious.
    http_download_window_seconds: int = 60
    http_download_min_flows: int = 4
    http_download_min_unique_destinations: int = 2
    http_download_min_bytes_in: int = 16384
    http_download_min_response_ratio: float = 64.0

    # Retry-to-persistent-connection campaign.
    retry_persistent_window_seconds: int = 86400
    retry_persistent_min_rows: int = 6
    retry_persistent_min_failures: int = 5
    retry_persistent_failure_ratio: float = 0.75
    retry_persistent_no_response_ratio: float = 0.75
    retry_persistent_min_src_port_churn_ratio: float = 0.20
    retry_persistent_min_success_duration: float = 3600.0
    retry_persistent_max_total_bytes: int = 131072

    # Same-endpoint HTTP download + retry campaign.
    http_retry_window_seconds: int = 300
    http_retry_min_downloads: int = 5
    http_retry_min_failures: int = 4
    http_retry_correlated_tcp23_min_duration: float = 3600.0
    http_retry_correlated_tcp23_max_total_bytes: int = 1048576

    # Volumetric UDP one-way traffic.
    volumetric_udp_min_duration: float = 30.0
    volumetric_udp_min_bytes_out: int = 104857600
    volumetric_udp_min_orig_packets: int = 100000

    # Multi-endpoint IRC activity campaign.
    multi_irc_window_seconds: int = 43200
    multi_irc_min_rows: int = 6
    multi_irc_min_irc_rows: int = 4
    multi_irc_min_irc_ratio: float = 0.50
    multi_irc_min_unique_destinations: int = 3


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
            or cfg.exfil_min_bytes <= 0 or cfg.failed_retry_min_samples < 3
            or cfg.failed_retry_min_span < 0 or not 0 <= cfg.failed_retry_ratio <= 1
            or not 0 <= cfg.failed_retry_no_response_ratio <= 1
            or not 0 <= cfg.failed_retry_src_port_churn_ratio <= 1
            or cfg.irc_conn_min_samples < 3 or cfg.irc_conn_min_span < 0
            or cfg.horizontal_scan_window_seconds <= 0
            or cfg.horizontal_scan_min_unique_destinations < 2
            or cfg.http_download_window_seconds <= 0
            or cfg.http_download_min_flows < 2
            or cfg.http_download_min_unique_destinations < 2
            or cfg.http_download_min_bytes_in <= 0
            or cfg.http_download_min_response_ratio <= 1
            or cfg.retry_persistent_window_seconds <= 0
            or cfg.retry_persistent_min_rows < 2
            or cfg.retry_persistent_min_failures < 1
            or cfg.retry_persistent_min_failures > cfg.retry_persistent_min_rows
            or not 0 <= cfg.retry_persistent_failure_ratio <= 1
            or not 0 <= cfg.retry_persistent_no_response_ratio <= 1
            or not 0 <= cfg.retry_persistent_min_src_port_churn_ratio <= 1
            or cfg.retry_persistent_min_success_duration <= 0
            or cfg.retry_persistent_max_total_bytes <= 0
            or cfg.http_retry_window_seconds <= 0
            or cfg.http_retry_min_downloads < 1
            or cfg.http_retry_min_failures < 1
            or cfg.http_retry_correlated_tcp23_min_duration <= 0
            or cfg.http_retry_correlated_tcp23_max_total_bytes <= 0
            or cfg.volumetric_udp_min_duration <= 0
            or cfg.volumetric_udp_min_bytes_out <= 0
            or cfg.volumetric_udp_min_orig_packets <= 0
            or cfg.multi_irc_window_seconds <= 0
            or cfg.multi_irc_min_rows < 2
            or cfg.multi_irc_min_irc_rows < 1
            or cfg.multi_irc_min_irc_rows > cfg.multi_irc_min_rows
            or not 0 <= cfg.multi_irc_min_irc_ratio <= 1
            or cfg.multi_irc_min_unique_destinations < 2):
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
            elif action == "network_connect" and proto in ("tcp", "udp"):
                # A large part of real botnet C2 telemetry is not a clean,
                # successful periodic beacon. Malware often retries the same
                # dead/unreachable endpoint from fresh ephemeral source ports.
                #
                # Keep this rule narrow:
                #   * same task/src/dst/dst-port/protocol/action group
                #   * multiple observations over time
                #   * overwhelmingly failed connection states
                #   * overwhelmingly no response bytes
                #   * source-port churn, which distinguishes repeated attempts
                #     from one duplicated record
                #
                # This is a suspicious retry candidate, not proof of C2, so it
                # intentionally has no ATT&CK technique mapping.
                failure_states = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "SH", "SHR"}
                states = [str(x.get("conn_state") or "").upper() for x in z]
                failure_ratio = mean(state in failure_states for state in states)
                no_response_ratio = mean(
                    e.network.bytes_in in (None, 0)
                    for e in rows
                )
                src_ports = [e.src_port for e in rows if e.src_port is not None]
                src_port_churn_ratio = (
                    len(set(src_ports)) / len(rows) if rows else 0.0
                )
                irc_ratio = mean(
                    "irc" in str(x.get("service") or "").casefold()
                    for x in z
                )
                service_values = [
                    str(x.get("service") or "").strip().casefold()
                    for x in z
                ]

                # Unanswered UDP/123 traffic is commonly ordinary time
                # synchronization retry behavior. Suppress only this narrow
                # protocol shape from the generic failed-connect heuristic;
                # other detections remain available.
                unanswered_udp123_retry = (
                    cfg.suppress_unanswered_udp123_retries
                    and proto == "udp"
                    and rows[0].dst_port == 123
                    and all(s in ("", "-", "ntp") for s in service_values)
                    and all(e.network.bytes_in in (None, 0) for e in rows)
                )

                # UDP/53 resolver retries are common under packet loss or DNS
                # reachability problems. Do not classify the connection retry
                # shape itself as malicious when Zeek identifies the entire
                # endpoint group as DNS. DNS-query/content detectors remain
                # independent and can still raise DNS-specific alerts.
                dns_retry = (
                    cfg.suppress_dns_retries
                    and proto == "udp"
                    and rows[0].dst_port == 53
                    and all(s == "dns" for s in service_values)
                )

                # Two retry profiles:
                # 1) High source-port churn: use the ordinary thresholds.
                # 2) Low source-port churn: allow it only when *all* traffic is
                #    effectively failed/no-response. This preserves Hakai-like
                #    retry loops while excluding mixed successful HTTP traffic.
                high_churn_retry = src_port_churn_ratio >= 0.50
                low_churn_pure_failure = (
                    src_port_churn_ratio >= cfg.failed_retry_src_port_churn_ratio
                    and failure_ratio >= 0.99
                    and no_response_ratio >= 0.99
                )
                source_port_pattern_ok = high_churn_retry or low_churn_pure_failure

                failed_retry = (
                    len(rows) >= cfg.failed_retry_min_samples
                    and time["span"] >= cfg.failed_retry_min_span
                    and failure_ratio >= cfg.failed_retry_ratio
                    and no_response_ratio >= cfg.failed_retry_no_response_ratio
                    and source_port_pattern_ok
                    and not unanswered_udp123_retry
                    and not dns_retry
                )
                generic_irc_candidate = (
                    len(rows) >= cfg.irc_conn_min_samples
                    and time["span"] >= cfg.irc_conn_min_span
                    and irc_ratio >= .80
                )

                # Zeek can classify only part of a botnet's IRC traffic as
                # service=irc. A sustained reconnect campaign to a classic IRC
                # port is therefore evaluated using both protocol metadata and
                # endpoint behavior.
                irc_port_campaign = (
                    proto == "tcp"
                    and rows[0].dst_port in (6667, 6697)
                    and len(rows) >= 20
                    and time["span"] >= 300
                    and irc_ratio >= .20
                    and failure_ratio >= .50
                )
                irc_candidate = generic_irc_candidate or irc_port_campaign

                features.update(
                    connection_states=dict(Counter(states)),
                    failed_state_ratio=round(failure_ratio, 4),
                    no_response_ratio=round(no_response_ratio, 4),
                    source_port_churn_ratio=round(src_port_churn_ratio, 4),
                    irc_service_ratio=round(irc_ratio, 4),
                    endpoint_grouped=True,
                )

                if failed_retry:
                    score = min(
                        .79,
                        .50
                        + .12 * failure_ratio
                        + .08 * no_response_ratio
                        + .06 * src_port_churn_ratio
                        + .05 * min(1.0, len(rows) / 20),
                    )
                    rule = "NET-REPEATED-FAILED-CONNECT"
                    title = "Repeated failed connections to the same endpoint"
                elif irc_candidate:
                    # IRC itself is not proof of compromise. These remain C2
                    # candidates requiring correlation/analyst verification.
                    if irc_port_campaign:
                        score = min(
                            .90,
                            .68
                            + .08 * irc_ratio
                            + .08 * failure_ratio
                            + .06 * min(1.0, len(rows) / 100),
                        )
                        rule = "NET-IRC-RECONNECT-CAMPAIGN"
                        title = "Sustained IRC-port reconnect campaign (C2 candidate)"
                    else:
                        score = min(
                            .85,
                            .64
                            + .10 * irc_ratio
                            + .06 * min(1.0, len(rows) / 20),
                        )
                        rule = "NET-IRC-C2-CANDIDATE"
                        title = "Repeated IRC service connections (C2 candidate)"
                    tech = "T1071"
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
                # DHCP discovery/renewal traffic is intentionally periodic and
                # can look extremely beacon-like. Suppress only the DHCP
                # protocol/broadcast shape from the generic beacon heuristic.
                dhcp_shaped = proto == "udp" and all(
                    str(x.get("service") or "").strip().casefold() == "dhcp"
                    or (
                        e.src_ip == "0.0.0.0"
                        and e.dst_ip == "255.255.255.255"
                        and e.dst_port in (67, 68)
                    )
                    for e, x in zip(rows, z)
                )
                if cfg.suppress_dhcp_beacons and dhcp_shaped:
                    continue

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
    # Retry-to-persistent-connection campaign. This complements the generic
    # failed-connect detector by looking for a transition: repeated failed/no-
    # response attempts to one TCP endpoint followed by a long-lived successful
    # bidirectional session to that same endpoint.
    #
    # This remains an analyst-verification candidate and intentionally has no
    # ATT&CK technique mapping because conn.log alone does not identify the
    # application-layer protocol used by the persistent session.
    retry_persistent_groups = defaultdict(list)
    for e in events:
        if (e.source != "zeek" or e.action != "network_connect" or not e.network
                or e.network.protocol != "tcp" or not e.src_ip or not e.dst_ip
                or e.dst_port is None or e.dst_ip in cfg.allowed_destinations):
            continue
        retry_persistent_groups[
            (e.task_id, e.src_ip, e.dst_ip, e.dst_port)
        ].append(e)

    retry_failure_states = {"S0", "REJ", "RSTO", "RSTR", "RSTOS0", "SH", "SHR"}
    retry_success_states = {"SF", "S1", "S2"}

    for (task_id, src_ip, dst_ip, dst_port), retry_rows in sorted(
            retry_persistent_groups.items()):
        retry_rows = sorted(
            {e.event_id: e for e in retry_rows}.values(),
            key=lambda e: seconds(e.timestamp),
        )
        windows = []
        for e in retry_rows:
            if (not windows or
                    seconds(e.timestamp) - seconds(windows[-1][0].timestamp)
                    > cfg.retry_persistent_window_seconds):
                windows.append([])
            windows[-1].append(e)

        for group in windows:
            if len(group) < cfg.retry_persistent_min_rows:
                continue

            states = [
                str(e.metadata.get("zeek", {}).get("conn_state") or "").upper()
                for e in group
            ]
            failure_count = sum(s in retry_failure_states for s in states)
            failure_ratio = failure_count / len(group)
            no_response_count = sum(
                e.network.bytes_in in (None, 0)
                for e in group
            )
            no_response_ratio = no_response_count / len(group)
            src_ports = [e.src_port for e in group if e.src_port is not None]
            src_port_churn_ratio = (
                len(set(src_ports)) / len(group) if group else 0.0
            )

            persistent_success = []
            for e, state in zip(group, states):
                raw = e.raw_event if isinstance(e.raw_event, dict) else {}
                duration = raw.get("duration")
                service = str(
                    e.metadata.get("zeek", {}).get("service") or ""
                ).strip().casefold()
                total_bytes = (
                    (e.network.bytes_in or 0) + (e.network.bytes_out or 0)
                    if isinstance(e.network.bytes_in, (int, float))
                    and isinstance(e.network.bytes_out, (int, float))
                    else None
                )
                if (
                    state in retry_success_states
                    and isinstance(duration, (int, float))
                    and not isinstance(duration, bool)
                    and duration >= cfg.retry_persistent_min_success_duration
                    and service in ("", "-")
                    and isinstance(e.network.bytes_in, (int, float))
                    and isinstance(e.network.bytes_out, (int, float))
                    and e.network.bytes_in > 0
                    and e.network.bytes_out > 0
                    and isinstance(total_bytes, (int, float))
                    and total_bytes <= cfg.retry_persistent_max_total_bytes
                ):
                    persistent_success.append(e)

            if not (
                failure_count >= cfg.retry_persistent_min_failures
                and failure_ratio >= cfg.retry_persistent_failure_ratio
                and no_response_ratio >= cfg.retry_persistent_no_response_ratio
                and src_port_churn_ratio
                    >= cfg.retry_persistent_min_src_port_churn_ratio
                and persistent_success
            ):
                continue

            max_success_duration = max(
                e.raw_event.get("duration")
                for e in persistent_success
                if isinstance(e.raw_event, dict)
            )
            score = min(
                .95,
                .78
                + .06 * min(1.0, failure_count / 10)
                + .05 * min(
                    1.0,
                    max_success_duration
                    / cfg.retry_persistent_min_success_duration,
                )
                + .03 * min(1.0, src_port_churn_ratio),
            )
            if score < cfg.risk_threshold:
                continue

            features = {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": "tcp",
                "window_seconds": cfg.retry_persistent_window_seconds,
                "flow_count": len(group),
                "failure_count": failure_count,
                "failure_ratio": round(failure_ratio, 4),
                "no_response_ratio": round(no_response_ratio, 4),
                "source_port_churn_ratio": round(src_port_churn_ratio, 4),
                "persistent_success_count": len(persistent_success),
                "max_success_duration": max_success_duration,
                "transition_shape": "repeated_failures_with_persistent_connection",
            }
            alerts.append(make_alert(
                group,
                "NET-RETRY-PERSISTENT-CONNECTION",
                "Repeated failures with a persistent connection to the same endpoint",
                score,
                features,
                knowledge,
            ))

    # Multi-endpoint IRC campaign. Unlike the endpoint-grouped IRC detector,
    # this looks across destination IPs while keeping source host and TCP
    # destination port fixed. This catches rotating IRC/C2 endpoints without
    # treating one ordinary IRC session as sufficient evidence.
    multi_irc_groups = defaultdict(list)
    for e in events:
        if (e.source != "zeek" or e.action != "network_connect" or not e.network
                or e.network.protocol != "tcp" or not e.src_ip or not e.dst_ip
                or e.dst_port is None or e.dst_ip in cfg.allowed_destinations):
            continue
        multi_irc_groups[(e.task_id, e.src_ip, e.dst_port)].append(e)

    for (task_id, src_ip, dst_port), irc_rows in sorted(multi_irc_groups.items()):
        irc_rows = sorted(
            {e.event_id: e for e in irc_rows}.values(),
            key=lambda e: seconds(e.timestamp),
        )
        windows = []
        for e in irc_rows:
            if (not windows or
                    seconds(e.timestamp) - seconds(windows[-1][0].timestamp)
                    > cfg.multi_irc_window_seconds):
                windows.append([])
            windows[-1].append(e)

        for group in windows:
            if len(group) < cfg.multi_irc_min_rows:
                continue

            irc_count = sum(
                "irc" in str(
                    e.metadata.get("zeek", {}).get("service") or ""
                ).casefold()
                for e in group
            )
            irc_ratio = irc_count / len(group)
            unique_dst_ips = len({e.dst_ip for e in group})

            if not (
                irc_count >= cfg.multi_irc_min_irc_rows
                and irc_ratio >= cfg.multi_irc_min_irc_ratio
                and unique_dst_ips >= cfg.multi_irc_min_unique_destinations
            ):
                continue

            score = min(
                .95,
                .82
                + .05 * min(1.0, irc_ratio)
                + .05 * min(1.0, unique_dst_ips / 5),
            )
            if score < cfg.risk_threshold:
                continue

            features = {
                "source_ip": src_ip,
                "destination_port": dst_port,
                "protocol": "tcp",
                "window_seconds": cfg.multi_irc_window_seconds,
                "flow_count": len(group),
                "irc_flow_count": irc_count,
                "irc_service_ratio": round(irc_ratio, 4),
                "unique_destination_ips": unique_dst_ips,
                "destination_ips": sorted({e.dst_ip for e in group}),
                "connection_states": dict(Counter(
                    str(e.metadata.get("zeek", {}).get("conn_state") or "-")
                    for e in group
                )),
                "campaign_shape": "multi_endpoint_irc_same_port",
            }
            alerts.append(make_alert(
                group,
                "NET-MULTI-ENDPOINT-IRC-CAMPAIGN",
                "Multi-endpoint IRC communication campaign (C2 candidate)",
                score,
                features,
                knowledge,
                "T1071",
                "command-and-control",
            ))

    # Horizontal network-service scan candidate. Keep this separate from the
    # endpoint-grouped retry rules above: a horizontal scan is one source
    # touching many destination IPs on the same service port. Only Zeek S0
    # rows are counted and attached as evidence; REJ/RST/SF rows in the same
    # time window are intentionally excluded to avoid pulling ordinary refused
    # or successful service traffic into the alert.
    horizontal_groups = defaultdict(list)
    for e in events:
        if (e.source != "zeek" or e.action != "network_connect" or not e.network
                or e.network.protocol != "tcp" or not e.src_ip or not e.dst_ip
                or e.dst_port is None or e.dst_ip in cfg.allowed_destinations):
            continue
        if str(e.metadata.get("zeek", {}).get("conn_state") or "").upper() != "S0":
            continue
        horizontal_groups[(e.task_id, e.src_ip, e.dst_port, e.network.protocol)].append(e)

    for (task_id, src_ip, dst_port, proto), scan_rows in sorted(horizontal_groups.items()):
        scan_rows = sorted({e.event_id: e for e in scan_rows}.values(),
                           key=lambda e: seconds(e.timestamp))
        windows = []
        for e in scan_rows:
            if (not windows or
                    seconds(e.timestamp) - seconds(windows[-1][0].timestamp)
                    > cfg.horizontal_scan_window_seconds):
                windows.append([])
            windows[-1].append(e)

        for group in windows:
            unique_dst_ips = len({e.dst_ip for e in group})
            if unique_dst_ips < cfg.horizontal_scan_min_unique_destinations:
                continue
            score = min(.95, .78 + .12 * min(1.0, unique_dst_ips / 100))
            if score < cfg.risk_threshold:
                continue
            features = {
                "source_ip": src_ip,
                "destination_port": dst_port,
                "protocol": proto,
                "connection_state": "S0",
                "unique_destination_ips": unique_dst_ips,
                "window_seconds": cfg.horizontal_scan_window_seconds,
                "scan_shape": "horizontal_same_port",
                "evidence_scope": "s0_only",
            }
            alerts.append(make_alert(
                group,
                "NET-HORIZONTAL-SCAN",
                "Horizontal network service scan candidate",
                score,
                features,
                knowledge,
                "T1046",
                "discovery",
            ))

    # Repeated response-heavy HTTP transfer campaign. Keep this separate
    # from endpoint-grouped beacon/retry logic because the signal is explicitly
    # multi-destination: one source receives several large responses from
    # multiple HTTP endpoints in a short period.
    #
    # A single large HTTP response is not sufficient. Requiring a campaign of
    # multiple qualifying flows and multiple destination IPs reduces ordinary
    # download/CDN false positives while retaining repeated tool/payload
    # transfer behavior.
    http_download_groups = defaultdict(list)
    for e in events:
        if (e.source != "zeek" or e.action != "network_connect" or not e.network
                or e.network.protocol != "tcp" or not e.src_ip or not e.dst_ip
                or e.dst_ip in cfg.allowed_destinations
                or e.dst_port not in (80, 8000, 8080, 8888)):
            continue
        z = e.metadata.get("zeek", {})
        if str(z.get("service") or "").strip().casefold() != "http":
            continue
        if str(z.get("conn_state") or "").upper() != "SF":
            continue
        bytes_in = e.network.bytes_in
        bytes_out = e.network.bytes_out
        if not isinstance(bytes_in, (int, float)) or not isinstance(bytes_out, (int, float)):
            continue
        if bytes_in < cfg.http_download_min_bytes_in:
            continue
        response_ratio = bytes_in / max(1, bytes_out)
        if response_ratio < cfg.http_download_min_response_ratio:
            continue
        http_download_groups[(e.task_id, e.src_ip)].append(e)

    for (task_id, src_ip), transfer_rows in sorted(http_download_groups.items()):
        transfer_rows = sorted(
            {e.event_id: e for e in transfer_rows}.values(),
            key=lambda e: seconds(e.timestamp),
        )
        windows = []
        for e in transfer_rows:
            if (not windows or
                    seconds(e.timestamp) - seconds(windows[-1][0].timestamp)
                    > cfg.http_download_window_seconds):
                windows.append([])
            windows[-1].append(e)

        for group in windows:
            unique_dst_ips = len({e.dst_ip for e in group})
            if len(group) < cfg.http_download_min_flows:
                continue
            if unique_dst_ips < cfg.http_download_min_unique_destinations:
                continue

            response_ratios = [
                e.network.bytes_in / max(1, e.network.bytes_out or 0)
                for e in group
            ]
            total_bytes_in = sum((e.network.bytes_in or 0) for e in group)
            total_bytes_out = sum((e.network.bytes_out or 0) for e in group)
            score = min(
                .95,
                .82
                + .05 * min(1.0, len(group) / 8)
                + .04 * min(1.0, unique_dst_ips / 4),
            )
            if score < cfg.risk_threshold:
                continue

            features = {
                "source_ip": src_ip,
                "protocol": "tcp",
                "service": "http",
                "connection_state": "SF",
                "window_seconds": cfg.http_download_window_seconds,
                "flow_count": len(group),
                "unique_destination_ips": unique_dst_ips,
                "destination_ips": sorted({e.dst_ip for e in group}),
                "total_bytes_in": total_bytes_in,
                "total_bytes_out": total_bytes_out,
                "minimum_bytes_in": cfg.http_download_min_bytes_in,
                "minimum_response_ratio": cfg.http_download_min_response_ratio,
                "observed_min_response_ratio": round(min(response_ratios), 3),
                "campaign_shape": "repeated_multi_endpoint_response_heavy_http",
            }
            alerts.append(make_alert(
                group,
                "NET-HTTP-DOWNLOAD-CAMPAIGN",
                "Repeated multi-endpoint HTTP download campaign",
                score,
                features,
                knowledge,
                "T1105",
                "command-and-control",
            ))

    # Same-endpoint HTTP download + failed-connect campaign. This is distinct
    # from NET-HTTP-DOWNLOAD-CAMPAIGN above: a malware server may stay on one
    # destination IP, so require both repeated response-heavy HTTP transfers and
    # repeated failed/no-response connections to that exact endpoint.
    http_retry_groups = defaultdict(list)
    for e in events:
        if (e.source != "zeek" or e.action != "network_connect" or not e.network
                or e.network.protocol != "tcp" or not e.src_ip or not e.dst_ip
                or e.dst_ip in cfg.allowed_destinations
                or e.dst_port not in (80, 8000, 8080, 8888)):
            continue
        http_retry_groups[
            (e.task_id, e.src_ip, e.dst_ip, e.dst_port)
        ].append(e)

    http_retry_failure_states = {
        "S0", "REJ", "RSTO", "RSTR", "RSTOS0", "SH", "SHR"
    }

    for (task_id, src_ip, dst_ip, dst_port), endpoint_rows in sorted(
            http_retry_groups.items()):
        endpoint_rows = sorted(
            {e.event_id: e for e in endpoint_rows}.values(),
            key=lambda e: seconds(e.timestamp),
        )
        windows = []
        for e in endpoint_rows:
            if (not windows or
                    seconds(e.timestamp) - seconds(windows[-1][0].timestamp)
                    > cfg.http_retry_window_seconds):
                windows.append([])
            windows[-1].append(e)

        for group in windows:
            heavy_http = []
            failed_rows = []

            for e in group:
                z = e.metadata.get("zeek", {})
                state = str(z.get("conn_state") or "").upper()
                service = str(z.get("service") or "").strip().casefold()

                if (
                    service == "http"
                    and state == "SF"
                    and isinstance(e.network.bytes_in, (int, float))
                    and isinstance(e.network.bytes_out, (int, float))
                    and e.network.bytes_in >= cfg.http_download_min_bytes_in
                    and e.network.bytes_in / max(1, e.network.bytes_out)
                        >= cfg.http_download_min_response_ratio
                ):
                    heavy_http.append(e)

                if (
                    state in http_retry_failure_states
                    and e.network.bytes_in in (None, 0)
                ):
                    failed_rows.append(e)

            if (
                len(heavy_http) < cfg.http_retry_min_downloads
                or len(failed_rows) < cfg.http_retry_min_failures
            ):
                continue

            campaign_start = min(seconds(e.timestamp) for e in group)
            campaign_end = max(seconds(e.timestamp) for e in group)

            # A long-lived TCP/23 session is weak evidence on its own. Include it
            # only when it occurs during an already-qualified HTTP+retry campaign
            # to the same source/destination pair.
            correlated_tcp23 = []
            for e in events:
                if (
                    e.source != "zeek"
                    or e.action != "network_connect"
                    or not e.network
                    or e.task_id != task_id
                    or e.src_ip != src_ip
                    or e.dst_ip != dst_ip
                    or e.network.protocol != "tcp"
                    or e.dst_port != 23
                ):
                    continue
                if not (
                    campaign_start <= seconds(e.timestamp) <= campaign_end
                ):
                    continue

                z = e.metadata.get("zeek", {})
                state = str(z.get("conn_state") or "").upper()
                raw = e.raw_event if isinstance(e.raw_event, dict) else {}
                duration = raw.get("duration")
                bytes_in = e.network.bytes_in
                bytes_out = e.network.bytes_out
                total_bytes = (
                    bytes_in + bytes_out
                    if isinstance(bytes_in, (int, float))
                    and isinstance(bytes_out, (int, float))
                    else None
                )
                if (
                    state in {"SF", "S1", "S2"}
                    and isinstance(duration, (int, float))
                    and not isinstance(duration, bool)
                    and duration
                        >= cfg.http_retry_correlated_tcp23_min_duration
                    and isinstance(bytes_in, (int, float))
                    and isinstance(bytes_out, (int, float))
                    and bytes_in > 0
                    and bytes_out > 0
                    and isinstance(total_bytes, (int, float))
                    and total_bytes
                        <= cfg.http_retry_correlated_tcp23_max_total_bytes
                ):
                    correlated_tcp23.append(e)

            evidence_rows = list({
                e.event_id: e
                for e in (group + correlated_tcp23)
            }.values())
            response_ratios = [
                e.network.bytes_in / max(1, e.network.bytes_out)
                for e in heavy_http
            ]
            score = min(
                .95,
                .84
                + .04 * min(1.0, len(heavy_http) / 10)
                + .03 * min(1.0, len(failed_rows) / 10)
                + (.02 if correlated_tcp23 else 0),
            )
            if score < cfg.risk_threshold:
                continue

            features = {
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": "tcp",
                "window_seconds": cfg.http_retry_window_seconds,
                "flow_count": len(group),
                "heavy_http_download_count": len(heavy_http),
                "failed_no_response_count": len(failed_rows),
                "minimum_download_bytes_in": cfg.http_download_min_bytes_in,
                "minimum_response_ratio": cfg.http_download_min_response_ratio,
                "observed_min_response_ratio": round(
                    min(response_ratios), 3
                ),
                "correlated_tcp23_count": len(correlated_tcp23),
                "campaign_shape": "same_endpoint_http_download_plus_retries",
            }
            alerts.append(make_alert(
                evidence_rows,
                "NET-HTTP-DOWNLOAD-RETRY-CAMPAIGN",
                "Repeated HTTP downloads with failed retries to one endpoint",
                score,
                features,
                knowledge,
                "T1105",
                "command-and-control",
            ))

    # Extremely high-volume one-way UDP traffic is a strong network-impact
    # anomaly. This deliberately uses large absolute thresholds so ordinary
    # UDP streaming and short bursts are not enough to trigger it.
    for e in events:
        if (e.source != "zeek" or e.action != "network_connect" or not e.network
                or e.network.protocol != "udp" or not e.src_ip or not e.dst_ip
                or e.dst_ip in cfg.allowed_destinations):
            continue
        raw = e.raw_event if isinstance(e.raw_event, dict) else {}
        duration = raw.get("duration")
        orig_pkts = raw.get("orig_pkts")
        bytes_out = e.network.bytes_out
        bytes_in = e.network.bytes_in

        if not (
            isinstance(duration, (int, float))
            and not isinstance(duration, bool)
            and duration >= cfg.volumetric_udp_min_duration
            and isinstance(orig_pkts, (int, float))
            and not isinstance(orig_pkts, bool)
            and orig_pkts >= cfg.volumetric_udp_min_orig_packets
            and isinstance(bytes_out, (int, float))
            and bytes_out >= cfg.volumetric_udp_min_bytes_out
            and bytes_in in (None, 0)
        ):
            continue

        features = {
            "source_ip": e.src_ip,
            "destination_ip": e.dst_ip,
            "destination_port": e.dst_port,
            "protocol": "udp",
            "duration_seconds": duration,
            "bytes_out": bytes_out,
            "bytes_in": bytes_in,
            "orig_packets": orig_pkts,
            "minimum_duration_seconds": cfg.volumetric_udp_min_duration,
            "minimum_bytes_out": cfg.volumetric_udp_min_bytes_out,
            "minimum_orig_packets": cfg.volumetric_udp_min_orig_packets,
            "traffic_shape": "high_volume_one_way_udp",
        }
        alerts.append(make_alert(
            [e],
            "NET-VOLUMETRIC-UDP-OUTBOUND",
            "High-volume one-way UDP traffic candidate",
            .92,
            features,
            knowledge,
            "T1498",
            "impact",
        ))

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
