import json

from common.models import Alert, NormalizedEvent
from correlation.paths import trace_graph
from correlation.service import correlate


TASK = "task_alert_sequence_test"


def _event(event_id, timestamp, *, action, source_type, source, host_id,
           src_ip=None, src_port=None, dst_ip=None, dst_port=None, network=None):
    return NormalizedEvent.model_validate({
        "schema_version": "1.0",
        "event_id": event_id,
        "task_id": TASK,
        "timestamp": timestamp,
        "source_type": source_type,
        "source": source,
        "host_id": host_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": "alice" if action == "login_success" else None,
        "action": action,
        "process": None,
        "object": None,
        "network": network,
        "raw_event": {},
        "labels": [],
        "metadata": {},
    })


def _alert(alert_id, event, *, rule_id, rule_name, tactic, technique, confidence):
    return Alert.model_validate({
        "alert_id": alert_id,
        "task_id": TASK,
        "timestamp_start": event.timestamp,
        "timestamp_end": event.timestamp,
        "event_ids": [event.event_id],
        "host_ids": [event.host_id],
        "severity": "high",
        "rule_id": rule_id,
        "rule_name": rule_name,
        "description": "test",
        "mitre": None,
        "confidence": confidence,
        "evidence_summary": json.dumps({
            "unresolved_technique_id": technique,
            "unresolved_tactic": tactic,
        }),
        "detector": "test",
    })


def test_credential_access_then_c2_on_same_host_forms_candidate_path():
    auth = _event(
        "evt_auth_success",
        "2026-09-11T12:00:00+00:00",
        action="login_success",
        source_type="host_log",
        source="application",
        host_id="webserver01",
        src_ip="192.0.2.10",
        dst_ip="192.0.2.20",
        dst_port=80,
    )
    c2 = _event(
        "evt_c2_flow",
        "2026-09-11T12:00:10+00:00",
        action="network_observed",
        source_type="network_flow",
        source="pcap_scapy",
        host_id="webserver01",
        src_ip="192.0.2.20",
        src_port=51000,
        dst_ip="192.0.2.30",
        dst_port=8080,
        network={
            "protocol": "tcp",
            "direction": "outbound",
            "bytes_in": None,
            "bytes_out": None,
            "session_id": None,
        },
    )

    auth_alert = _alert(
        "alert_auth",
        auth,
        rule_id="HOST-AUTH-FAILURE-THEN-SUCCESS",
        rule_name="Authentication failures followed by success",
        tactic="credential-access",
        technique="T1110",
        confidence=.72,
    )
    c2_alert = _alert(
        "alert_c2",
        c2,
        rule_id="NET-CROSS-SOURCE-BEACON",
        rule_name="Cross-source beacon",
        tactic="command-and-control",
        technique="T1071.001",
        confidence=.90,
    )

    graph = correlate(TASK, [auth, c2], [auth_alert, c2_alert])

    sequence_edges = [
        edge for edge in graph.edges
        if edge.attributes.get("kind") == "event_correlation"
        and "same_host_alert_sequence" in edge.attributes.get("reasons", [])
    ]
    assert len(sequence_edges) == 1
    assert set(sequence_edges[0].evidence_alert_ids) == {
        "alert_auth", "alert_c2"
    }

    trace = trace_graph(graph, [auth, c2], [auth_alert, c2_alert], knowledge=None)
    assert [stage.technique_id for stage in trace.attack_chain] == [
        "T1110", "T1071.001"
    ]
    assert [stage.tactic for stage in trace.attack_chain] == [
        "credential-access", "command-and-control"
    ]


def test_same_host_alerts_without_supported_tactic_transition_are_not_forced():
    first = _event(
        "evt_first",
        "2026-09-11T12:00:00+00:00",
        action="login_success",
        source_type="host_log",
        source="application",
        host_id="webserver01",
        src_ip="192.0.2.10",
    )
    second = _event(
        "evt_second",
        "2026-09-11T12:00:05+00:00",
        action="login_success",
        source_type="host_log",
        source="application",
        host_id="webserver01",
        src_ip="192.0.2.11",
    )

    a1 = _alert(
        "alert_one", first,
        rule_id="TEST-ONE", rule_name="one",
        tactic="credential-access", technique="T1110", confidence=.7,
    )
    a2 = _alert(
        "alert_two", second,
        rule_id="TEST-TWO", rule_name="two",
        tactic="credential-access", technique="T1110", confidence=.7,
    )

    graph = correlate(TASK, [first, second], [a1, a2])
    assert not [
        edge for edge in graph.edges
        if "same_host_alert_sequence" in edge.attributes.get("reasons", [])
    ]
