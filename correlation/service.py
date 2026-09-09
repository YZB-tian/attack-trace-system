"""Evidence-preserving entity graph and conservative temporal event correlation."""
from __future__ import annotations
import hashlib
import json
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Iterable
from common.models import NormalizedEvent, Alert, AttackGraph, GraphNode, GraphEdge
from common.time_utils import now_iso


def _key(prefix, *values):
    return prefix + hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()[:24]


def _seconds(value):
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None: raise ValueError("timestamp must contain timezone")
    return stamp.timestamp()


def _correlation_candidates(events, state, window_seconds):
    """Index only entities used by the evidence predicates below; preserve pair order."""
    index = defaultdict(deque)
    stamps = [_seconds(e.timestamp) for e in events]
    logins = {"login", "login_success", "remote_login"}
    for i, event in enumerate(events):
        s = state[event.event_id]
        stored, queried = set(), set()
        for name in ("proc", "file"):
            if s[name]: stored.add((name, s[name])); queried.add((name, s[name]))
        if s["parent"]: queried.add(("proc", s["parent"]))
        if event.network:
            five = (event.src_ip, event.dst_ip, event.src_port, event.dst_port, event.network.protocol)
            stored.add(("five_all", *five))
            if s["proc"]: stored.add(("five_process", *five))
            queried.add(("five_all" if s["proc"] else "five_process", *five))
            stored.add(("endpoints", event.src_ip, event.dst_ip))
            if event.source == "zeek" and event.network.session_id:
                key = ("session", event.network.session_id)
                stored.add(key); queried.add(key)
        if event.action in logins:
            queried.add(("endpoints", event.src_ip, event.dst_ip))
            stored.add(("login_user", event.host_id, event.user))
        if event.action == "process_create" and event.host_id and event.user:
            queried.add(("login_user", event.host_id, event.user))
        candidates = set()
        for key in queried:
            queue = index[key]
            horizon = min(30, window_seconds) if key[0].startswith("five_") else window_seconds
            while queue and stamps[i] - stamps[queue[0]] > horizon: queue.popleft()
            candidates.update(queue)
        yield event, [(events[j], stamps[i] - stamps[j]) for j in sorted(candidates, reverse=True)]
        for key in stored: index[key].append(i)

def build_attack_graph(
    task_id: str,
    events: Iterable[NormalizedEvent],
    alerts: Iterable[Alert],
) -> AttackGraph:
    return correlate(task_id, events, alerts)


def correlate(task_id, events, alerts, window_seconds=900) -> AttackGraph:
    if window_seconds <= 0: raise ValueError("window_seconds must be positive")
    events, alerts = list(events), list(alerts)
    if any(x.task_id != task_id for x in [*events, *alerts]):
        raise ValueError("cross-task data must not be correlated")
    if len({e.event_id for e in events}) != len(events):
        raise ValueError("duplicate event IDs; deduplicate before correlation")
    if len({a.alert_id for a in alerts}) != len(alerts):
        raise ValueError("duplicate alert IDs")
    events.sort(key=lambda e: (_seconds(e.timestamp), e.event_id))
    by_id = {e.event_id: e for e in events}
    by_event = defaultdict(list)
    for a in alerts:
        for eid in a.event_ids:
            if eid not in by_id: raise ValueError(f"dangling evidence {eid} in {a.alert_id}")
            by_event[eid].append(a)
    assets = json.loads((Path(__file__).resolve().parents[1] / "config/assets.json").read_text(encoding="utf-8"))["assets"]
    by_ip = {a["ip"]: a for a in assets}
    nodes, edges = {}, []
    state = {}
    process_births = defaultdict(list)
    process_exits = defaultdict(list)
    for e in events:
        if e.host_id and e.process and e.process.pid is not None and e.action == "process_create":
            process_births[(e.host_id, e.process.pid)].append(e)
        if e.host_id and e.process and e.process.pid is not None and e.action in ("process_exit", "process_terminate"):
            process_exits[(e.host_id, e.process.pid)].append(e)

    def node(node_type, identity, label=None, **attrs):
        nid = identity if node_type == "host" else _key(node_type + "_", task_id, identity)
        if nid not in nodes:
            nodes[nid] = GraphNode(id=nid, type=node_type, label=label or str(identity), attributes=attrs)
        else:
            nodes[nid].attributes.update({k: v for k, v in attrs.items() if v is not None})
        return nid

    def edge(source, target, relation, event, *, confidence=1.0, evidence=None, **attrs):
        if not source or not target: return
        evidence = sorted(set(evidence or [event.event_id]))
        aids = sorted({a.alert_id for eid in evidence for a in by_event[eid]})
        eid = _key("edge_", task_id, source, target, relation, evidence, attrs.get("kind"))
        edges.append(GraphEdge(id=eid, source=source, target=target, relation=relation,
            timestamp=event.timestamp, evidence_event_ids=evidence, evidence_alert_ids=aids,
            confidence=confidence, attributes=attrs))

    def endpoint(ip):
        if not ip: return None
        asset = by_ip.get(ip)
        if asset:
            return node("host", asset["host_id"], asset["hostname"], ip=ip, zone=asset["zone"])
        return node("ip", ip, ip, ip=ip)

    def process_node(e, pid=None, parent=False):
        if not e.host_id or not e.process: return None
        raw = e.raw_event if isinstance(e.raw_event, dict) else {}
        guid = raw.get("ParentProcessGuid" if parent else "ProcessGuid")
        pid = pid if parent else e.process.pid
        if guid:
            identity = (e.host_id, "guid", guid)
        else:
            births = [b for b in process_births.get((e.host_id, pid), []) if _seconds(b.timestamp) <= _seconds(e.timestamp)]
            birth = births[-1] if births else None
            if birth and any(_seconds(birth.timestamp) <= _seconds(x.timestamp) < _seconds(e.timestamp)
                             for x in process_exits.get((e.host_id, pid), [])):
                birth = None
            if birth and _seconds(e.timestamp) - _seconds(birth.timestamp) <= window_seconds:
                birth_raw = birth.raw_event if isinstance(birth.raw_event, dict) else {}
                identity = (e.host_id, "guid", birth_raw["ProcessGuid"]) if birth_raw.get("ProcessGuid") else (e.host_id, "birth", birth.event_id)
            else:
                # PID alone is not an identity: do not merge across ambiguous lifetimes.
                identity = (e.host_id, "unresolved", pid, e.event_id, parent)
        label = f"PID {pid}" if parent else e.process.name or e.process.path or f"PID {pid}"
        return node("process", identity, label, host_id=e.host_id, pid=pid, identity_resolved=identity[1] != "unresolved")

    for e in events:
        host = node("host", e.host_id, e.host_id) if e.host_id else None
        src, dst = endpoint(e.src_ip), endpoint(e.dst_ip)
        user = node("user", (e.host_id or e.event_id, e.user), e.user, host_id=e.host_id) if e.user else None
        proc = process_node(e)
        obj = node("file", (e.host_id or e.event_id, e.object.path or e.object.name), e.object.path or e.object.name,
                   host_id=e.host_id) if e.object and e.object.type == "file" and (e.object.path or e.object.name) else None
        alert_ids = sorted(a.alert_id for a in by_event[e.event_id])
        techniques = sorted({a.mitre.subtechnique_id or a.mitre.technique_id for a in by_event[e.event_id] if a.mitre})
        enode = node("other", ("event", e.event_id), e.action, kind="event", event_id=e.event_id,
                     timestamp=e.timestamp, alert_ids=alert_ids, technique_ids=techniques, host_id=e.host_id)
        edge(enode, host or src, "related_to", e, kind="observed_on")
        if proc:
            edge(host, proc, "related_to", e, kind="process_on_host")
            edge(user, proc, "related_to", e, kind="user_process")
        parent = None
        if e.action == "process_create" and e.process and e.process.ppid is not None:
            parent = process_node(e, e.process.ppid, True)
            edge(parent, proc, "process_spawn", e, kind="observed_parent")
        if obj:
            edge(proc or host, obj, "file_access", e, kind=e.action)
        if e.action in ("login", "login_success", "remote_login"):
            edge(user or src, host or dst, "login", e, src_ip=e.src_ip)
        if e.network and src and dst:
            edge(proc or src, dst, "network_connect", e, kind=e.action,
                 src_ip=e.src_ip, dst_ip=e.dst_ip, protocol=e.network.protocol,
                 session_id=e.network.session_id, src_port=e.src_port, dst_port=e.dst_port)
        domain = e.metadata.get("zeek", {}).get("host") or e.metadata.get("zeek", {}).get("query")
        if domain:
            dn = node("domain", domain.lower().rstrip("."), domain.lower().rstrip("."))
            edge(proc or src, dn, "related_to", e, kind="http_host" if e.action == "http_request" else "dns_query")
        for a in by_event[e.event_id]:
            if a.mitre:
                tech = a.mitre.subtechnique_id or a.mitre.technique_id
                tn = node("technique", tech, a.mitre.technique_name, technique_id=tech, tactic=a.mitre.tactic)
                edge(enode, tn, "related_to", e, confidence=a.confidence, kind="detected_technique")
            tactic = a.mitre.tactic.lower().replace(" ", "-") if a.mitre else ""
            rel = {"initial-access": "initial_access", "lateral-movement": "lateral_movement",
                   "privilege-escalation": "privilege_escalation", "collection": "data_access",
                   "exfiltration": "data_exfiltration"}.get(tactic)
            if rel:
                edge(src or user or enode, dst or proc or host or enode, rel, e,
                     confidence=a.confidence, kind="alert_supported_candidate", alert_id=a.alert_id)
            if a.rule_id == "NET-BEACON" and e.dst_ip:
                c2 = node("c2", (e.dst_ip, e.dst_port, e.network.protocol), e.dst_ip,
                          ip=e.dst_ip, port=e.dst_port, protocol=e.network.protocol, status="candidate")
                attrs = nodes[c2].attributes
                attrs.setdefault("first_seen", e.timestamp)
                attrs["last_seen"] = e.timestamp
                attrs["connected_hosts"] = sorted(set(attrs.get("connected_hosts", []) + ([e.host_id] if e.host_id else [])))
                attrs["domains"] = sorted(set(attrs.get("domains", []) + e.metadata.get("zeek", {}).get("http_hosts", [])))
                attrs["risk_score"] = max(attrs.get("risk_score", 0), a.confidence)
                edge(proc or src, c2, "c2_communication", e, confidence=a.confidence, kind="suspected_beacon")
        state[e.event_id] = dict(node=enode, proc=proc, parent=parent, file=obj, src=src, dst=dst, host=host)

    # Correlate by strong entity evidence inside a bounded time interval.
    for later, candidates in _correlation_candidates(events, state, window_seconds):
        ls = state[later.event_id]
        for earlier, dt in candidates:
            es = state[earlier.event_id]
            reasons, score = [], 0.0
            if es["proc"] and es["proc"] == ls["proc"]:
                reasons.append("same_process_instance"); score += .7
            if es["proc"] and es["proc"] == ls["parent"]:
                reasons.append("parent_child_process"); score += .8
            if es["file"] and es["file"] == ls["file"] and earlier.host_id == later.host_id:
                reasons.append("same_host_file"); score += .6
            if (earlier.network and later.network and earlier.src_ip and earlier.dst_ip
                    and earlier.src_ip == later.src_ip and earlier.dst_ip == later.dst_ip
                    and earlier.src_port is not None and earlier.src_port == later.src_port
                    and earlier.dst_port is not None and earlier.dst_port == later.dst_port
                    and earlier.network.protocol == later.network.protocol and dt <= 30
                    and earlier.source != later.source and (es["proc"] or ls["proc"])):
                reasons.append("cross_source_matching_five_tuple"); score += .8
            if (earlier.network and later.network and earlier.network.session_id
                    and earlier.network.session_id == later.network.session_id
                    and earlier.source == later.source == "zeek"):
                reasons.append("same_zeek_session"); score += .8
            if (earlier.network and later.action in ("login", "login_success", "remote_login")
                    and earlier.src_ip == later.src_ip and earlier.dst_ip == later.dst_ip
                    and earlier.src_ip != earlier.dst_ip and earlier.src_ip):
                reasons.append("connection_and_authentication_endpoints"); score += .8
            # A remote login can connect to a process only with the same target host and user.
            if (earlier.action in ("login", "login_success", "remote_login") and later.action == "process_create"
                    and earlier.host_id and earlier.host_id == later.host_id and earlier.user and earlier.user == later.user):
                reasons.append("authenticated_user_on_target_host"); score += .7
            if not reasons: continue
            score = min(.95, score + .1 * (1 - dt / window_seconds))
            if score >= .65:
                edge(es["node"], ls["node"], "related_to", later, confidence=score,
                     evidence=[earlier.event_id, later.event_id], kind="event_correlation",
                     reasons=reasons, time_delta_seconds=dt, interpretation="candidate_link_not_proof_of_same_attacker")
    unique_edges = {e.id: e for e in edges}
    return AttackGraph(graph_id=_key("graph_", task_id, sorted(by_id), sorted(a.alert_id for a in alerts)),
        task_id=task_id, generated_at=now_iso(), nodes=list(nodes.values()), edges=list(unique_edges.values()))
