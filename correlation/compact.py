"""Compact redundant network observations without discarding event evidence.

Event vertices participating in temporal correlation remain intact. Isolated
network observations move to entity attributes; trace_graph can read both forms.
"""
from collections import defaultdict
import json
from common.models import GraphEdge


def compact_graph(graph, events):
    from .service import _key, _seconds

    nodes = {n.id: n.model_copy(deep=True) for n in graph.nodes}
    events = {e.event_id: e for e in events}
    protected = {nid for edge in graph.edges
                 if edge.attributes.get("kind") == "event_correlation"
                 for nid in (edge.source, edge.target)}
    outgoing = defaultdict(list)
    network_facts = defaultdict(list)
    for edge in graph.edges:
        outgoing[edge.source].append(edge)
        if edge.relation.value == "network_connect":
            for eid in edge.evidence_event_ids:
                network_facts[eid].append(edge)
    replacements = {}
    for nid, node in list(nodes.items()):
        if node.attributes.get("kind") != "event" or nid in protected:
            continue
        event = events[node.attributes["event_id"]]
        if event.action not in {"network_connect", "http_request", "dns_query", "icmp_echo"}:
            continue
        # Require an actual entity-to-entity fact, not merely an action label.
        facts = network_facts[event.event_id]
        if not facts:
            continue
        anchor = facts[0].source
        entity_ids = sorted({anchor, *(edge.target for edge in facts),
                             *(edge.target for edge in outgoing[nid]
                               if nodes[edge.target].type.value != "technique")})
        nodes[anchor].attributes.setdefault("event_observations", []).append(
            dict(node.attributes, node_id=nid, action=event.action, entity_ids=entity_ids))
        replacements[nid] = anchor
        del nodes[nid]

    groups = {}
    # Preserve every original edge's context (including time, source port, session
    # and confidence) inside observations while grouping equal semantic relations.
    for edge in graph.edges:
        source = replacements.get(edge.source, edge.source)
        target = replacements.get(edge.target, edge.target)
        if source == target and edge.source in replacements and edge.attributes.get("kind") == "observed_on":
            continue  # The entity now owns this observation, so a self-edge adds nothing.
        variable = {"session_id", "src_port"} if edge.relation.value == "network_connect" else set()
        attrs = {k: v for k, v in edge.attributes.items() if k not in variable}
        key = json.dumps([source, target, edge.relation.value, edge.technique_id, attrs], sort_keys=True)
        groups.setdefault(key, []).append((edge, source, target, attrs))
    edges = []
    for group in groups.values():
        original, source, target, attrs = group[0]
        if len(group) == 1 and source == original.source and target == original.target:
            edges.append(original)
            continue
        observations = [dict(timestamp=e.timestamp, confidence=e.confidence,
                             evidence_event_ids=e.evidence_event_ids,
                             evidence_alert_ids=e.evidence_alert_ids, attributes=e.attributes)
                        for e, *_ in group]
        times = sorted((o["timestamp"] for o in observations if o["timestamp"]), key=_seconds)
        event_ids = sorted({eid for e, *_ in group for eid in e.evidence_event_ids})
        alert_ids = sorted({aid for e, *_ in group for aid in e.evidence_alert_ids})
        # Keep only common top-level attributes; varying values are in observations.
        attrs = {k: v for k, v in original.attributes.items()
                 if all(e.attributes.get(k) == v for e, *_ in group)}
        attrs.update(observations=observations, observation_count=len(observations),
                     first_seen=times[0] if times else None, last_seen=times[-1] if times else None)
        edges.append(GraphEdge(id=_key("edge_", graph.task_id, source, target,
                                      original.relation.value, event_ids, attrs),
            source=source, target=target, relation=original.relation,
            technique_id=original.technique_id, timestamp=times[0] if times else None,
            evidence_event_ids=event_ids, evidence_alert_ids=alert_ids,
            confidence=max(e.confidence for e, *_ in group), attributes=attrs))
    return graph.model_copy(update={"nodes": list(nodes.values()), "edges": edges})
