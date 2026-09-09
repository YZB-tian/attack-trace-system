"""Protocol-specific positives, normal controls and integration regressions."""
import base64
import hashlib
import json
import math
from collections import Counter

import pytest
from collectors.network.adapter import load_zeek_logs, normalize_network_records
from correlation.pipeline import analyze
from detection.network_rules import NetworkConfig, detect_network


def row(n=0, **extra):
    return {"ts": 1788825600 + n * 60, "uid": f"C{n}", "id.orig_h": "10.10.2.10",
        "id.resp_h": "10.10.0.20", "id.orig_p": 45000 + n, "id.resp_p": 80,
        "proto": "tcp", "_log_type": "http", "method": "GET", "host": "lab.example",
        "uri": "/index", **extra}


def packet(n, payload=None, **extra):
    payload = payload if payload is not None else hashlib.shake_256(str(n).encode()).digest(512)
    entropy = -sum((count / len(payload)) * math.log2(count / len(payload)) for count in Counter(payload).values())
    record = row(n, _log_type="icmp_payload", proto="icmp", is_orig=True,
        icmp_type=8, icmp_code=0, payload_len=len(payload), payload_sample_len=len(payload),
        payload_entropy=entropy, payload_sha256=hashlib.sha256(payload).hexdigest())
    record.update(extra)
    return record


def detect(rows, cfg=None):
    return detect_network(normalize_network_records(rows, "task_protocol"), cfg)


@pytest.mark.parametrize("location", ["query", "path"])
def test_changing_encoded_http_data_is_detected(location):
    rows = []
    for n in range(10):
        value = base64.urlsafe_b64encode(hashlib.shake_256(str(n).encode()).digest(240)).decode()
        uri = "/api?data=" + value if location == "query" else "/api/" + value
        rows.append(row(n, uri=uri))
    alerts = detect(rows)
    assert len(alerts) == 1 and alerts[0].rule_id == "NET-HTTP-COVERT"
    assert json.loads(alerts[0].evidence_summary)["encoded_value_churn"] == 1


def test_http_fixed_token_single_upload_and_browsing_are_not_covert():
    token = base64.urlsafe_b64encode(hashlib.shake_256(b"fixed-token").digest(240)).decode()
    assert not detect([row(n, uri="/api?token=" + token) for n in range(10)])
    assert not detect([row(n, uri=f"/articles/{n}?page={n}") for n in range(10)])
    assert not detect([row(0, method="POST", request_body_len=5000000, response_body_len=50)])
    assert not detect([row(n, method="CONNECT", uri="proxy.example:443", status_code=200) for n in range(10)])


def test_http_malformed_uri_does_not_abort_other_evidence():
    rows = [row(n, uri="http://[broken", method="POST", request_body_len=70000, response_body_len=50) for n in range(10)]
    alerts = detect(rows)
    assert len(alerts) == 1
    assert json.loads(alerts[0].evidence_summary)["malformed_uri_count"] == 10


def test_http_body_samples_allow_smaller_periodic_uploads():
    rows = [row(n, method="POST", request_body_len=1024, response_body_len=16,
                ats_body_sample_len=1024, ats_body_entropy=7.8,
                ats_body_sha256=hashlib.sha256(str(n).encode()).hexdigest()) for n in range(10)]
    alert = detect(rows)[0]
    features = json.loads(alert.evidence_summary)
    assert features["matched_patterns"] == ["periodic_changing_body"] and features["body_entropy_available"]
    for r in rows: r["ats_body_sha256"] = "a" * 64
    assert not detect(rows)


def test_icmp_payload_positive_and_normal_padding_control():
    alerts = detect([packet(n) for n in range(10)])
    assert len(alerts) == 1 and alerts[0].rule_id == "NET-ICMP-TUNNEL"
    assert json.loads(alerts[0].evidence_summary)["evidence_level"] == "echo_payload_sample"
    # Timestamp/sequence may change; the bulk of diagnostic padding is predictable.
    assert not detect([packet(n, n.to_bytes(8, "little") + b"a" * 504) for n in range(10)])
    assert not detect([packet(0)] * 10)


def test_icmp_error_packets_are_not_tunnel_payloads():
    records = [packet(n) for n in range(10)]
    for r in records: r["icmp_type"] = 3
    assert not detect(records)
    aggregate = row(_log_type="conn", proto="icmp", orig_pkts=1000, orig_ip_bytes=1000000,
                    duration=120, **{"id.orig_p": 3, "id.resp_p": 1})
    assert not detect([aggregate])


def test_ipv6_echo_is_supported_with_zeek_icmp_transport_name():
    records = [packet(n) for n in range(10)]
    for r in records:
        r.update(icmp_type=128, proto="icmp")
        r["id.orig_h"], r["id.resp_h"] = "2001:db8::1", "2001:db8::2"
    assert detect(records)[0].rule_id == "NET-ICMP-TUNNEL"


def test_icmp_aggregate_uses_latest_end_time_not_longest_duration():
    records = [row(n, _log_type="conn", proto="icmp", duration=60,
                   orig_pkts=110, orig_ip_bytes=110000, **{"id.orig_p": 8, "id.resp_p": 0}) for n in (0, 1)]
    # 220 packets / 120 seconds: below the 2 pps fallback gate.
    assert not detect(records)
    records[1]["orig_pkts"] = 200
    alert = detect(records)[0]
    features = json.loads(alert.evidence_summary)
    assert features["observation_seconds"] == 120 and not features["payload_entropy_available"]
    from datetime import datetime
    assert datetime.fromisoformat(alert.timestamp_end).timestamp() == 1788825720


def test_icmp_reply_direction_and_zero_double_accounting(tmp_path):
    original = row(_log_type="conn", proto="icmp", orig_bytes=5000, resp_bytes=5000,
                   **{"id.orig_p": 8, "id.resp_p": 0})
    echo = packet(0)
    echo.update(is_orig=False, icmp_type=0)
    for name, record in (("conn", original), ("icmp_payload", echo)):
        (tmp_path / f"{name}.log").write_text(json.dumps(record), encoding="utf-8")
    events = load_zeek_logs(tmp_path, "task_protocol")
    reply = next(e for e in events if e.action == "icmp_echo")
    connection = next(e for e in events if e.action == "network_connect")
    assert reply.src_ip == original["id.resp_h"] and reply.dst_ip == original["id.orig_h"]
    assert reply.src_port is None and reply.network.bytes_out is None
    assert reply.network.session_id == connection.network.session_id
    assert reply.metadata["session_event_id"] == connection.event_id
    result = analyze("task_protocol", events)
    assert any(edge.attributes.get("kind") == "event_correlation" for edge in result[2].edges)


def test_icmp_payload_prevents_duplicate_flow_alert():
    records = [packet(n) for n in range(10)]
    for r in records: r["uid"] = "same-session"
    records.append(row(_log_type="conn", uid="same-session", proto="icmp", duration=120,
        orig_pkts=1000, orig_ip_bytes=1000000, **{"id.orig_p": 8, "id.resp_p": 0}))
    alerts = detect(records)
    assert len(alerts) == 1
    assert len(alerts[0].event_ids) == 10


@pytest.mark.parametrize("change", [{"payload_entropy": 9}, {"payload_sample_len": 900},
    {"payload_sha256": "wrong"}, {"request_body_len": -1}])
def test_bad_measurements_are_rejected(change):
    with pytest.raises(ValueError): normalize_network_records([packet(0, **change)], "task_protocol")


def test_protocol_configuration_and_allowlist():
    with pytest.raises(ValueError): detect([], NetworkConfig(icmp_payload_entropy=9))
    assert not detect([packet(n) for n in range(10)], NetworkConfig(allowed_destinations=("10.10.0.20",)))
    rows = [row(n, method="POST", request_body_len=70000, response_body_len=50) for n in range(10)]
    assert not detect(rows, NetworkConfig(allowed_domains=("lab.example",)))
