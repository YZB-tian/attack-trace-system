"""Private HTTP/ICMP evidence analysis; no packet parsing or public model changes."""
from __future__ import annotations
import base64
import binascii
import math
import re
from collections import Counter
from statistics import mean
from urllib.parse import parse_qsl, unquote, urlsplit


def _entropy(value):
    return -sum((n / len(value)) * math.log2(n / len(value)) for n in Counter(value).values()) if value else 0.0


def _encoded(value, minimum):
    if len(value) < minimum or _entropy(value) < 3.0: return False
    if re.fullmatch(r"[a-fA-F0-9]+", value) and len(value) % 2 == 0: return True
    if _entropy(value) < 3.5 or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", value): return False
    try:
        base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        return True
    except (ValueError, binascii.Error):
        return False


def _uri_tokens(uri, minimum):
    # Treat origin-form URLs as paths; malformed absolute URLs are evidence, not crashes.
    try:
        parsed = urlsplit(uri)
        values = [v for _, v in parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=2048)]
        path = unquote(parsed.path)
    except ValueError:
        return [], True
    values += path.split("/")
    return [v for v in values if _encoded(v, minimum)], False


def assess_http(rows, cfg, timing):
    z = [e.metadata.get("zeek", {}) for e in rows]
    sustained = len(rows) >= cfg.min_samples and timing["span"] >= cfg.min_span
    parsed = [_uri_tokens(str(x.get("uri") or ""), cfg.http_min_encoded_length) for x in z]
    signatures = [tuple(tokens) for tokens, _ in parsed if tokens]
    token_ratio = len(signatures) / len(rows)
    churn = len(set(signatures)) / len(signatures) if signatures else 0.0
    long_ratio = mean(len(str(x.get("uri") or "")) >= 256 for x in z)
    upload = [str(x.get("method") or "").upper() in {"POST", "PUT", "PATCH"}
              and (x.get("request_body_len") or 0) >= cfg.http_large_upload_bytes for x in z]
    upload_ratio = mean(upload)
    req_bytes = sum(x.get("request_body_len", 0) or 0 for x in z)
    resp_bytes = sum(x.get("response_body_len", 0) or 0 for x in z)
    out_fraction = req_bytes / max(req_bytes + resp_bytes, 1)
    periodic = timing["regularity"] if sustained else 0.0
    token_pattern = sustained and token_ratio >= .5 and churn >= .5
    token_score = .45 * token_ratio + .25 * long_ratio + .2 * periodic if token_pattern else 0.0
    upload_pattern = sustained and upload_ratio >= .5 and periodic >= .8 and out_fraction >= .8
    upload_score = .65 * upload_ratio + .25 * periodic if upload_pattern else 0.0
    # Optional metrics come from our Zeek script. Missing values never become entropy=0.
    sampled = [x for x in z if x.get("ats_body_sample_len", 0) >= 64
               and x.get("ats_body_entropy") is not None and x.get("ats_body_sha256")]
    body_churn = len({x["ats_body_sha256"] for x in sampled}) / len(sampled) if sampled else 0.0
    entropy_ratio = sum(x["ats_body_entropy"] >= 6 for x in sampled) / len(rows)
    body_pattern = sustained and entropy_ratio >= .8 and body_churn >= .5 and periodic >= .8 and out_fraction >= .8
    body_score = .45 * entropy_ratio + .25 * body_churn + .2 * periodic if body_pattern else 0.0
    score = max(token_score, upload_score, body_score)
    features = dict(timing, encoded_parameter_or_path_ratio=token_ratio, encoded_value_churn=churn,
        long_uri_ratio=long_ratio, large_upload_ratio=upload_ratio, request_body_bytes=req_bytes,
        response_body_bytes=resp_bytes, request_byte_fraction=out_fraction,
        body_sample_count=len(sampled), body_entropy_available=bool(sampled),
        high_entropy_body_ratio=entropy_ratio, body_sample_churn=body_churn,
        malformed_uri_count=sum(bad for _, bad in parsed),
        matched_patterns=[name for name, yes in (("changing_encoded_uri", token_pattern),
            ("periodic_large_upload", upload_pattern), ("periodic_changing_body", body_pattern)) if yes],
        limitation="Patterns may also describe authorized telemetry or backup; HTTPS plaintext is not decrypted.")
    return score, features


def assess_icmp_aggregate(rows, cfg, timing, seconds):
    """Only Echo summaries. Large packets alone are insufficient to prove a tunnel."""
    z = [e.metadata["zeek"] for e in rows]
    packets = sum(x.get("orig_pkts", 0) or 0 for x in z)
    wire_bytes = sum(x.get("orig_ip_bytes", 0) or 0 for x in z)
    begin = min(seconds(e.timestamp) for e in rows)
    finish = max(seconds(e.timestamp) + (x.get("duration") or 0) for e, x in zip(rows, z))
    duration = finish - begin
    average = wire_bytes / packets if packets else 0.0
    rate = packets / max(duration, 1)
    eligible = packets >= cfg.icmp_min_packets and average >= cfg.icmp_min_average_bytes and rate >= 2
    score = .65 + .1 * (duration >= cfg.min_span) if eligible else 0.0
    return score, dict(timing, packets=packets, ip_bytes=wire_bytes, observation_seconds=duration,
        average_ip_packet_bytes=average, packets_per_second=rate,
        evidence_level="flow_statistics", payload_entropy_available=False,
        limitation="Echo volume/size anomaly only; large-packet diagnostics can match. Payload evidence unavailable.")


def assess_icmp_payload(rows, cfg, timing):
    z = [e.metadata["zeek"] for e in rows]
    sampled = [x for x in z if x.get("payload_sample_len", 0) >= 64
               and x.get("payload_entropy") is not None and x.get("payload_sha256")]
    high = sum(x["payload_entropy"] >= cfg.icmp_payload_entropy for x in sampled) / len(rows)
    churn = len({x["payload_sha256"] for x in sampled}) / len(sampled) if sampled else 0.0
    # Normal ping padding may include a changing timestamp; its entropy remains low.
    eligible = len(sampled) >= cfg.min_samples and high >= .8 and churn >= .5
    score = .45 * high + .25 * churn + .15 if eligible else 0.0
    return score, dict(timing, evidence_level="echo_payload_sample", payload_entropy_available=bool(sampled),
        sampled_packets=len(sampled), high_entropy_payload_ratio=high, payload_sample_churn=churn,
        packet_count=len(rows), total_payload_bytes=sum(x.get("payload_len", 0) or 0 for x in z),
        limitation="Entropy covers bounded payload samples; randomized diagnostic pings can match. No confirmed exfiltration.")
