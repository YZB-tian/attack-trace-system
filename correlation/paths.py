"""Build separate chronological candidate chains; never fill absent attack stages."""
from __future__ import annotations
from collections import defaultdict
from common.models import AttackStage, TraceResult
from common.time_utils import now_iso
from .service import _key, _seconds


def trace_graph(graph, events, alerts, knowledge=None):
    events = {e.event_id: e for e in events}
    alerts = {a.alert_id: a for a in alerts}
    enodes = {n.id: n for n in graph.nodes if n.attributes.get("kind") == "event"}
    previous = defaultdict(list)
    for edge in graph.edges:
        if edge.attributes.get("kind") == "event_correlation":
            previous[edge.target].append(edge)
    # Choose the strongest supported predecessor, keeping disconnected chains separate.
    chains = {}
    used_as_parent = set()
    for nid, node in sorted(enodes.items(), key=lambda p: (_seconds(p[1].attributes["timestamp"]), p[1].attributes["event_id"])):
        candidates = [e for e in previous[nid] if e.source in chains]
        best = max(candidates, key=lambda e: (e.confidence, len(chains[e.source]), e.id)) if candidates else None
        chains[nid] = chains[best.source] + [nid] if best else [nid]
        if best: used_as_parent.add(best.source)
    paths = [p for n, p in chains.items() if n not in used_as_parent
             and any(enodes[x].attributes["alert_ids"] for x in p)]
    paths.sort(key=lambda p: (-sum(bool(enodes[x].attributes["alert_ids"]) for x in p), -len(p), p))
    paths = paths[:20]
    main = paths[0] if paths else []
    stages = []
    for nid in main:
        node = enodes[nid]
        eid = node.attributes["event_id"]
        event = events[eid]
        for aid in node.attributes["alert_ids"]:
            a = alerts[aid]
            if not a.mitre: continue
            technique = a.mitre.subtechnique_id or a.mitre.technique_id
            # Aggregate the same alert within a chain while retaining all evidence.
            existing = next((s for s in stages if aid in s.evidence_alert_ids), None)
            if existing:
                existing.evidence_event_ids = sorted(set(existing.evidence_event_ids + [eid]))
                existing.entity_ids = sorted(set(existing.entity_ids + [nid]))
                continue
            stages.append(AttackStage(order=len(stages) + 1, tactic=a.mitre.tactic,
                technique_id=technique, technique_name=a.mitre.technique_name, title=a.rule_name,
                description=f"Observed at {event.timestamp}. {a.description}", entity_ids=[nid],
                evidence_event_ids=[eid], evidence_alert_ids=[aid], confidence=a.confidence))
    observed = {stage.technique_id for stage in stages if stage.technique_id}
    main_events = {enodes[n].attributes["event_id"] for n in main}
    candidates = []
    for edge in graph.edges:
        if (edge.relation.value == "initial_access" and edge.confidence >= .6
                and set(edge.evidence_event_ids) & main_events):
            candidates.append(edge)
    # Earliest among supported candidates, not earliest arbitrary network event.
    candidates.sort(key=lambda e: (_seconds(e.timestamp), -e.confidence))
    path_analysis = {name: [] for name in ("lateral_movement", "privilege_escalation", "data_access", "data_exfiltration")}
    for edge in graph.edges:
        if edge.relation.value in path_analysis:
            path_analysis[edge.relation.value].append({"source": edge.source, "target": edge.target,
                "timestamp": edge.timestamp, "confidence": edge.confidence,
                "evidence_event_ids": edge.evidence_event_ids, "evidence_alert_ids": edge.evidence_alert_ids,
                "status": "alert_supported_candidate"})
    data_paths = []
    for path in paths:
        path_events = [events[enodes[n].attributes["event_id"]] for n in path]
        reads = [e for e in path_events if e.action in ("file_read", "file_access") and e.object and e.object.type == "file"]
        if not reads: continue
        first = min(_seconds(e.timestamp) for e in reads)
        writes = [e for e in path_events if e.action in ("file_create", "file_write") and e.object and e.object.type == "file" and _seconds(e.timestamp) >= first]
        network = [e for e in path_events if e.network and e.dst_ip and _seconds(e.timestamp) >= first]
        if not network: continue
        data_paths.append({"read_event_ids": [e.event_id for e in reads],
            "written_file_event_ids": [e.event_id for e in writes],
            "network_event_ids": [e.event_id for e in network],
            "destinations": sorted({e.dst_ip for e in network}),
            "status": "candidate_data_access_then_communication",
            "content_transfer_proven": False})
    attribution = {
        "method": "deterministic_evidence_correlation", "llm_used": False,
        "candidate_paths": [[enodes[n].attributes["event_id"] for n in p] for p in paths],
        "apt_similarity": knowledge.similarity(observed) if knowledge else [],
        "apt_similarity_scope": "primary_candidate_path_only",
        "path_analysis": path_analysis,
        "data_access_to_network_candidates": data_paths,
        "stix_source": str(knowledge.path) if knowledge else None,
        "limitations": ["Candidate relations do not prove common attacker identity.",
                       "Only the strongest candidate path populates attack_chain; other paths remain separate.",
                       "No live multi-agent LLM analysis is performed by this module.",
                       "TTP similarity is not attribution; unobserved stages are not reconstructed."],
    }
    return TraceResult(trace_id=_key("trace_", graph.graph_id), task_id=graph.task_id, generated_at=now_iso(),
        status="completed", summary=f"Analyzed {len(events)} events and {len(alerts)} alerts; {len(paths)} candidate paths. Evidence-based analysis, not confirmed attribution.",
        initial_access_entity_id=candidates[0].target if candidates else None,
        suspected_c2_entity_ids=[n.id for n in graph.nodes if n.type.value == "c2"], attack_chain=stages,
        attribution=attribution, evidence_event_ids=sorted(events), evidence_alert_ids=sorted(alerts))
