import json
from datetime import datetime, timedelta, timezone

from common.models import Alert, NormalizedEvent
from correlation.paths import trace_graph
from correlation.service import correlate


def _event(
    event_id,
    second,
    *,
    action="syscall",
    source_type="host_behavior",
    source="strace",
    host_id="webserver01",
    src_ip=None,
    src_port=None,
    dst_ip=None,
    dst_port=None,
    network=None,
    process=None,
):
    base = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent.model_validate({
        "schema_version": "1.0",
        "event_id": event_id,
        "task_id": "task_corr_regression",
        "timestamp": (base + timedelta(seconds=second)).isoformat(),
        "source_type": source_type,
        "source": source,
        "host_id": host_id,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "user": None,
        "action": action,
        "process": process,
        "object": None,
        "network": network,
        "raw_event": {},
        "labels": [],
        "metadata": {},
    })


def test_syscall_heavy_trace_does_not_create_quadratic_graph():
    rows = [
        _event(
            f"evt_sys_{i:03d}",
            i / 10,
            process={
                "pid": 4242,
                "ppid": 1,
                "name": "worker",
                "path": "/usr/bin/worker",
            },
        )
        for i in range(200)
    ]
    graph = correlate("task_corr_regression", rows, [])
    correlations = [
        edge for edge in graph.edges
        if edge.attributes.get("kind") == "event_correlation"
    ]
    assert len(correlations) == 0
    assert len(graph.edges) < len(rows) * 3
    assert len(graph.nodes) <= len(rows) * 2 + 1


def test_fallback_attack_mapping_creates_c2_and_trace_stage_without_stix():
    net = _event(
        "evt_network_alert",
        1,
        action="network_observed",
        source_type="network_flow",
        source="pcap_scapy",
        host_id="webserver01",
        src_ip="192.0.2.10",
        src_port=51000,
        dst_ip="192.0.2.20",
        dst_port=8080,
        network={
            "protocol": "tcp",
            "direction": "outbound",
            "bytes_in": None,
            "bytes_out": None,
            "session_id": None,
        },
    )
    alert = Alert.model_validate({
        "alert_id": "alert_cross_source_test",
        "task_id": "task_corr_regression",
        "timestamp_start": net.timestamp,
        "timestamp_end": net.timestamp,
        "event_ids": [net.event_id],
        "host_ids": ["webserver01"],
        "severity": "high",
        "rule_id": "NET-CROSS-SOURCE-BEACON",
        "rule_name": "Cross-source beacon candidate",
        "description": "test",
        "mitre": None,
        "confidence": 0.9,
        "evidence_summary": json.dumps({
            "unresolved_technique_id": "T1071.001",
            "unresolved_tactic": "command-and-control",
        }),
        "detector": "test",
    })

    graph = correlate("task_corr_regression", [net], [alert])
    trace = trace_graph(graph, [net], [alert], knowledge=None)

    assert any(node.type.value == "c2" for node in graph.nodes)
    assert trace.suspected_c2_entity_ids
    assert trace.attack_chain
    assert trace.attack_chain[0].technique_id == "T1071.001"
    assert trace.attack_chain[0].tactic == "command-and-control"

