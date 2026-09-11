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
    def alert_tactic(alert):
        if alert.mitre:
            return alert.mitre.tactic.lower().replace(" ", "-")
        try:
            evidence = json.loads(alert.evidence_summary or "{}")
        except (TypeError, ValueError, json.JSONDecodeError):
            return ""
        return str(evidence.get("unresolved_tactic") or "").lower().replace(" ", "-")

    assets = json.loads((Path(__file__).resolve().parents[1] / "config/assets.json").read_text(encoding="utf-8"))["assets"]
    by_ip = {a["ip"]: a for a in assets}
    nodes, edges = {}, []
    state = {}
    process_births = defaultdict(list)
    process_exits = defaultdict(list)
    for e in events:
        # An execve observed as process_exec is the same creation boundary as a
        # Sysmon process_create; both anchor a PID's lifetime when no GUID is
        # available, so collectors that only emit process_exec still merge.
        if e.host_id and e.process and e.process.pid is not None and e.action in ("process_create", "process_exec"):
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
            tactic = alert_tactic(a)
            rel = {"initial-access": "initial_access", "lateral-movement": "lateral_movement",
                   "privilege-escalation": "privilege_escalation", "collection": "data_access",
                   "exfiltration": "data_exfiltration"}.get(tactic)
            if rel:
                edge(src or user or enode, dst or proc or host or enode, rel, e,
                     confidence=a.confidence, kind="alert_supported_candidate", alert_id=a.alert_id)
            is_c2_candidate = (
                tactic == "command-and-control"
                or a.rule_id in {"NET-BEACON", "NET-CROSS-SOURCE-BEACON"}
            )
            if is_c2_candidate and e.network and e.dst_ip and e.dst_port is not None:
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
    # trace_graph ultimately chooses the strongest predecessor for each event.
    # Keeping every same-process pair causes O(n^2) growth for syscall-heavy traces,
    # so only the strongest supported predecessor is retained.
    for later, candidates in _correlation_candidates(events, state, window_seconds):
        ls = state[later.event_id]
        ranked = []
        for earlier, dt in candidates:
            es = state[earlier.event_id]

            # Ordinary unalerted syscall records remain evidence on their entity,
            # but are not temporal attack-path vertices.
            if (
                (earlier.action == "syscall" and not by_event[earlier.event_id])
                or (later.action == "syscall" and not by_event[later.event_id])
            ):
                continue

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
            if (earlier.action in ("login", "login_success", "remote_login") and later.action == "process_create"
                    and earlier.host_id and earlier.host_id == later.host_id and earlier.user and earlier.user == later.user):
                reasons.append("authenticated_user_on_target_host"); score += .7

            # Independently alert-supported observations on the same host, close
            # in time, can form a candidate sequence. This is not proof that the
            # same attacker caused both observations.
            if (
                by_event[earlier.event_id]
                and by_event[later.event_id]
                and earlier.host_id
                and earlier.host_id == later.host_id
                and dt <= 120
            ):
                reasons.append("same_host_alert_sequence"); score += .65

            if not reasons:
                continue
            score = min(.95, score + .1 * (1 - dt / window_seconds))
            if score >= .65:
                ranked.append((score, -dt, earlier.event_id, earlier, reasons, dt))

        if ranked:
            score, _, _, earlier, reasons, dt = max(
                ranked, key=lambda row: (row[0], row[1], row[2])
            )
            es = state[earlier.event_id]
            edge(es["node"], ls["node"], "related_to", later, confidence=score,
                 evidence=[earlier.event_id, later.event_id], kind="event_correlation",
                 reasons=reasons, time_delta_seconds=dt,
                 interpretation="candidate_link_not_proof_of_same_attacker")
    # ALERT_SUPPORTED_TACTIC_SEQUENCE_V1
    # Build only a very small number of cross-alert candidate links. This pass
    # does NOT connect arbitrary same-host events. It requires:
    #   1) two different detector alerts,
    #   2) a shared host in their evidence,
    #   3) a supported ATT&CK tactic transition,
    #   4) chronological proximity.
    # The link remains explicitly a candidate, not proof of common attacker
    # identity or causality.
    allowed_alert_transitions = {
        ("credential-access", "command-and-control"),
    }
    alert_host_representatives = defaultdict(list)

    for alert in alerts:
        tactic = alert_tactic(alert)
        if not tactic:
            continue

        per_host = defaultdict(list)
        for event_id in alert.event_ids:
            event = by_id[event_id]
            if event.host_id:
                per_host[event.host_id].append(event)

        for host_id, evidence_rows in per_host.items():
            # Credential-access sequences are represented by their successful
            # authentication endpoint when present. C2/network alerts prefer an
            # actual network observation on the shared host. This avoids choosing
            # a receiver-side service log when a packet observation exists.
            if tactic == "credential-access":
                preferred = [
                    event for event in evidence_rows
                    if event.action in ("login_success", "login", "remote_login")
                ]
                representative = max(
                    preferred or evidence_rows,
                    key=lambda event: (_seconds(event.timestamp), event.event_id),
                )
            else:
                preferred = [
                    event for event in evidence_rows
                    if event.network is not None
                    and event.action in (
                        "network_observed", "network_connect",
                        "http_request", "dns_query", "icmp_echo",
                    )
                ]
                representative = min(
                    preferred or evidence_rows,
                    key=lambda event: (_seconds(event.timestamp), event.event_id),
                )

            alert_host_representatives[host_id].append(
                (alert, tactic, representative)
            )

    for host_id, entries in alert_host_representatives.items():
        entries.sort(
            key=lambda item: (
                _seconds(item[2].timestamp),
                item[0].alert_id,
            )
        )
        for index, (earlier_alert, earlier_tactic, earlier_event) in enumerate(entries):
            for later_alert, later_tactic, later_event in entries[index + 1:]:
                if earlier_alert.alert_id == later_alert.alert_id:
                    continue
                if (earlier_tactic, later_tactic) not in allowed_alert_transitions:
                    continue

                delta = _seconds(later_event.timestamp) - _seconds(earlier_event.timestamp)
                if delta < 0:
                    continue
                if delta > 120:
                    break

                edge(
                    state[earlier_event.event_id]["node"],
                    state[later_event.event_id]["node"],
                    "related_to",
                    later_event,
                    confidence=min(
                        .75,
                        earlier_alert.confidence,
                        later_alert.confidence,
                    ),
                    evidence=[
                        earlier_event.event_id,
                        later_event.event_id,
                    ],
                    kind="event_correlation",
                    reasons=[
                        "same_host_alert_sequence",
                        f"{earlier_tactic}_to_{later_tactic}",
                    ],
                    time_delta_seconds=delta,
                    shared_host_id=host_id,
                    interpretation=(
                        "alert_supported_candidate_sequence_not_proof_of_causality"
                    ),
                )
                # At most one forward candidate per earlier alert on this host.
                break

    unique_edges = {e.id: e for e in edges}
    graph = AttackGraph(graph_id=_key("graph_", task_id, sorted(by_id), sorted(a.alert_id for a in alerts)),
        task_id=task_id, generated_at=now_iso(), nodes=list(nodes.values()), edges=list(unique_edges.values()))
    from .compact import compact_graph
    return compact_graph(graph, events)
