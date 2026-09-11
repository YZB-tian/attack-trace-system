from common.models import NormalizedEvent
from detection.host_rules import detect_host
from detection.network_rules import detect_network


def event(
    event_id,
    timestamp,
    *,
    source_type,
    source,
    host_id,
    action,
    src_ip=None,
    src_port=None,
    dst_ip=None,
    dst_port=None,
    user=None,
    network=None,
    raw_event=None,
):
    return NormalizedEvent.model_validate({
        "schema_version": "1.0",
        "event_id": event_id,
        "task_id": "task_generic_normalized_detection",
        "timestamp": timestamp,
        "source_type": source_type,
        "source": source,
        "host_id": host_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": user,
        "action": action,
        "process": None,
        "object": None,
        "network": network,
        "raw_event": raw_event,
        "labels": [],
        "metadata": {},
    })


def test_auth_failures_then_success_from_generic_host_log():
    rows = [
        event(
            "evt_auth_1", "2026-09-11T12:00:00+00:00",
            source_type="host_log", source="application",
            host_id="webserver01", action="login_failure",
            src_ip="192.0.2.10", dst_ip="192.0.2.20", dst_port=80, user="alice",
        ),
        event(
            "evt_auth_2", "2026-09-11T12:00:05+00:00",
            source_type="host_log", source="application",
            host_id="webserver01", action="login_failure",
            src_ip="192.0.2.10", dst_ip="192.0.2.20", dst_port=80, user="alice",
        ),
        event(
            "evt_auth_3", "2026-09-11T12:00:10+00:00",
            source_type="host_log", source="application",
            host_id="webserver01", action="login_success",
            src_ip="192.0.2.10", dst_ip="192.0.2.20", dst_port=80, user="alice",
        ),
    ]
    alerts = detect_host(rows)
    assert "HOST-AUTH-FAILURE-THEN-SUCCESS" in {a.rule_id for a in alerts}


def test_single_failure_then_success_is_not_enough():
    rows = [
        event(
            "evt_auth_n1", "2026-09-11T12:00:00+00:00",
            source_type="host_log", source="application",
            host_id="webserver01", action="login_failure",
            src_ip="192.0.2.10", user="alice",
        ),
        event(
            "evt_auth_n2", "2026-09-11T12:00:05+00:00",
            source_type="host_log", source="application",
            host_id="webserver01", action="login_success",
            src_ip="192.0.2.10", user="alice",
        ),
    ]
    assert "HOST-AUTH-FAILURE-THEN-SUCCESS" not in {
        a.rule_id for a in detect_host(rows)
    }


def test_cross_source_receiver_beacon_requires_packet_confirmation():
    net = {
        "protocol": "tcp",
        "direction": None,
        "bytes_in": None,
        "bytes_out": None,
        "session_id": None,
    }
    rows = [
        event(
            "evt_beacon_1", "2026-09-11T12:00:00+00:00",
            source_type="host_log", source="receiver_service",
            host_id="c2server01", action="beacon",
            src_ip="192.0.2.30", dst_ip="192.0.2.40", dst_port=8080,
            raw_event={"event": "beacon"},
        ),
        event(
            "evt_beacon_2", "2026-09-11T12:00:02+00:00",
            source_type="host_log", source="receiver_service",
            host_id="c2server01", action="beacon",
            src_ip="192.0.2.30", dst_ip="192.0.2.40", dst_port=8080,
            raw_event={"event": "beacon"},
        ),
        event(
            "evt_flow_1", "2026-09-11T12:00:00.500000+00:00",
            source_type="network_flow", source="pcap_scapy",
            host_id="webserver01", action="network_observed",
            src_ip="192.0.2.30", src_port=50000,
            dst_ip="192.0.2.40", dst_port=8080, network=net,
        ),
        event(
            "evt_flow_2", "2026-09-11T12:00:02.500000+00:00",
            source_type="network_flow", source="pcap_scapy",
            host_id="webserver01", action="network_observed",
            src_ip="192.0.2.30", src_port=50001,
            dst_ip="192.0.2.40", dst_port=8080, network=net,
        ),
    ]
    alerts = detect_network(rows)
    assert "NET-CROSS-SOURCE-BEACON" in {a.rule_id for a in alerts}


def test_receiver_beacon_without_packet_evidence_does_not_alert():
    rows = [
        event(
            "evt_beacon_n1", "2026-09-11T12:00:00+00:00",
            source_type="host_log", source="receiver_service",
            host_id="c2server01", action="beacon",
            src_ip="192.0.2.30", dst_ip="192.0.2.40", dst_port=8080,
        ),
        event(
            "evt_beacon_n2", "2026-09-11T12:00:02+00:00",
            source_type="host_log", source="receiver_service",
            host_id="c2server01", action="beacon",
            src_ip="192.0.2.30", dst_ip="192.0.2.40", dst_port=8080,
        ),
    ]
    assert "NET-CROSS-SOURCE-BEACON" not in {
        a.rule_id for a in detect_network(rows)
    }



def test_same_second_auth_sequence_uses_source_record_order():
    def with_record(event_id, action, record):
        row = event(
            event_id,
            "2026-09-11T12:00:00+00:00",
            source_type="host_log",
            source="application",
            host_id="webserver01",
            action=action,
            src_ip="192.0.2.10",
            dst_ip="192.0.2.20",
            dst_port=80,
            user="alice",
        )
        row.metadata["raw_reference"] = {
            "file": "web-events.jsonl",
            "record": record,
        }
        return row

    rows = [
        with_record("evt_z_success", "login_success", 28),
        with_record("evt_a_failure", "login_failure", 26),
        with_record("evt_b_failure", "login_failure", 27),
    ]

    alerts = detect_host(rows)
    assert "HOST-AUTH-FAILURE-THEN-SUCCESS" in {a.rule_id for a in alerts}


def test_same_second_auth_without_source_order_is_not_assumed():
    rows = [
        event(
            "evt_z_success",
            "2026-09-11T12:00:00+00:00",
            source_type="host_log",
            source="application",
            host_id="webserver01",
            action="login_success",
            src_ip="192.0.2.10",
            user="alice",
        ),
        event(
            "evt_a_failure",
            "2026-09-11T12:00:00+00:00",
            source_type="host_log",
            source="application",
            host_id="webserver01",
            action="login_failure",
            src_ip="192.0.2.10",
            user="alice",
        ),
        event(
            "evt_b_failure",
            "2026-09-11T12:00:00+00:00",
            source_type="host_log",
            source="application",
            host_id="webserver01",
            action="login_failure",
            src_ip="192.0.2.10",
            user="alice",
        ),
    ]

    assert "HOST-AUTH-FAILURE-THEN-SUCCESS" not in {
        a.rule_id for a in detect_host(rows)
    }
