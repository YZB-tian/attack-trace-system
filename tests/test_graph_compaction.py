from collections import Counter
import pytest
from common.models import MitreMapping, NormalizedEvent
from correlation.host_demo import examples
from correlation.pipeline import analyze
from correlation.paths import trace_graph
from correlation.service import correlate


def uncompressed(monkeypatch, events, alerts):
    with monkeypatch.context() as patch:
        patch.setattr("correlation.compact.compact_graph", lambda graph, _: graph)
        return correlate(events[0].task_id, events, alerts)


def test_ten_beacons_counts_and_complete_evidence(monkeypatch):
    rows = examples()["beacon"][0]
    _, alerts, graph, trace = analyze(rows[0].task_id, rows)
    before = uncompressed(monkeypatch, rows, alerts)
    assert (len(before.nodes), len(before.edges)) == (14, 30)
    assert (len(graph.nodes), len(graph.edges)) == (4, 3)
    assert Counter(n.type.value for n in graph.nodes) == {"host": 1, "ip": 2, "c2": 1}
    ids = {row.event_id for row in rows}
    assert all(set(edge.evidence_event_ids) == ids for edge in graph.edges)
    assert all(edge.evidence_alert_ids == [alerts[0].alert_id] for edge in graph.edges)
    facts = next(edge for edge in graph.edges if edge.relation.value == "network_connect")
    observations = facts.attributes["observations"]
    assert {o["attributes"]["src_port"] for o in observations} == {r.src_port for r in rows}
    assert {o["attributes"]["session_id"] for o in observations} == {r.network.session_id for r in rows}
    assert {o["timestamp"] for o in observations} == {r.timestamp for r in rows}
    assert {o["event_id"] for n in graph.nodes for o in n.attributes.get("event_observations", [])} == ids
    old_trace = trace_graph(before, rows, alerts)
    assert trace.attribution == old_trace.attribution
    assert trace.evidence_event_ids == old_trace.evidence_event_ids
    replay = analyze(rows[0].task_id, reversed(rows))
    assert graph.model_dump(exclude={"generated_at"}) == replay[2].model_dump(exclude={"generated_at"})


def test_compacted_technique_trace_never_references_removed_vertices(monkeypatch):
    rows = examples()["beacon"][0]
    alerts = analyze(rows[0].task_id, rows)[1]
    # Supply a test mapping to exercise the trace path; NET-BEACON itself does
    # not infer a specific ATT&CK technique from periodicity.
    alerts[0].mitre = MitreMapping(tactic="command-and-control", technique_id="T1071",
        subtechnique_id="T1071.001", technique_name="Web Protocols")
    before = uncompressed(monkeypatch, rows, alerts)
    graph = correlate(rows[0].task_id, rows, alerts)
    old, new = [trace_graph(g, rows, alerts) for g in (before, graph)]
    assert old.attribution["candidate_paths"] == new.attribution["candidate_paths"]
    assert [s.evidence_event_ids for s in old.attack_chain] == [s.evidence_event_ids for s in new.attack_chain]
    assert new.attack_chain
    assert all(set(s.entity_ids) <= {n.id for n in graph.nodes} for s in new.attack_chain)
    assert all(e.source in {n.id for n in graph.nodes} and e.target in {n.id for n in graph.nodes} for e in graph.edges)


def test_distinct_services_and_domains_are_not_merged():
    rows = examples()["beacon"][0][:3]
    rows[1].dst_port = 8443
    rows[2].network.protocol = "udp"
    graph = correlate(rows[0].task_id, rows, [])
    assert len([e for e in graph.edges if e.relation.value == "network_connect"]) == 3
    for n, row in enumerate(rows):
        row.action = "http_request"
        row.metadata = {"zeek": {"host": f"service-{n}.example.test"}}
    graph = correlate(rows[0].task_id, rows, [])
    assert len([n for n in graph.nodes if n.type.value == "domain"]) == 3


def test_correlated_events_and_insufficient_network_facts_stay_visible(monkeypatch):
    rows = examples()["beacon"][0][:3]
    rows[1].network.session_id = rows[0].network.session_id
    rows[1].action = "http_request"
    rows[2].network = None
    graph = correlate(rows[0].task_id, rows, [])
    before = uncompressed(monkeypatch, rows, [])
    assert {n.attributes["event_id"] for n in graph.nodes if n.attributes.get("kind") == "event"} == {r.event_id for r in rows}
    assert [e for e in graph.edges if e.attributes.get("kind") == "event_correlation"] == [e for e in before.edges if e.attributes.get("kind") == "event_correlation"]


def test_resolved_process_and_file_chain_preserved(monkeypatch):
    base = dict(task_id="task_chain", source_type="host_behavior", source="sysmon", host_id="officepc01",
                process={"pid": 7, "name": "powershell.exe"}, raw_event={"ProcessGuid": "proc-fixture"})
    rows = [NormalizedEvent(**base, event_id="evt_create", timestamp="2026-09-10T00:00:00+00:00", action="process_create"),
            NormalizedEvent(**base, event_id="evt_read", timestamp="2026-09-10T00:00:01+00:00", action="file_read",
                            object={"type": "file", "path": "C:/fixture.txt"}),
            NormalizedEvent(**base, event_id="evt_connect", timestamp="2026-09-10T00:00:02+00:00", action="network_connect",
                            src_ip="10.10.2.10", dst_ip="198.51.100.20", network={"protocol": "tcp"})]
    graph = correlate("task_chain", rows, [])
    before = uncompressed(monkeypatch, rows, [])
    assert len([n for n in graph.nodes if n.type.value == "process"]) == 1
    assert len([n for n in graph.nodes if n.type.value == "file"]) == 1
    assert [e for e in graph.edges if e.attributes.get("kind") == "event_correlation"] == [e for e in before.edges if e.attributes.get("kind") == "event_correlation"]
    assert any(e.relation.value == "file_access" for e in graph.edges)
