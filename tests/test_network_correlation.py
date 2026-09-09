"""Small, adversarial tests of the implemented pipeline and public contracts."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator, FormatChecker
from common.models import NormalizedEvent, Alert
from collectors.network.adapter import normalize_network_records, read_zeek_log, load_zeek_logs, query_sessions
from detection.network_rules import detect_network, timing
from detection.attack_stix import AttackKnowledge
from detection.sigma_subset import SigmaRule
from correlation.pipeline import analyze
from correlation.service import correlate

ROOT = Path(__file__).resolve().parents[1]


def stamp(offset=0):
    return (datetime(2026, 9, 8, tzinfo=timezone.utc) + timedelta(seconds=offset)).isoformat()


def event(n, action="process_create", **kw):
    return NormalizedEvent(event_id=f"evt_{n}", task_id="task_test", timestamp=stamp(n),
        source_type="host_behavior", source="sysmon", host_id="officepc01", action=action, **kw)


def conn(n=0, **kw):
    return dict({"ts": 1788825600 + n * 60, "uid": f"C{n}", "id.orig_h": "10.10.2.10",
        "id.resp_h": "10.10.0.20", "id.orig_p": 40000 + n, "id.resp_p": 443, "proto": "tcp",
        "duration": 1, "orig_bytes": 100, "resp_bytes": 50, "_log_type": "conn"}, **kw)


def test_zeek_tsv_types_unset_and_icmp(tmp_path):
    p = tmp_path / "conn.log"
    p.write_text("#separator \\x09\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.resp_h\tid.orig_p\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\n"
                 "#types\ttime\tstring\taddr\taddr\tport\tport\tenum\tinterval\tcount\tcount\n"
                 "1788825600\tCicmp\t10.10.2.10\t10.10.0.20\t8\t0\ticmp\t-\t0\t-\n", encoding="utf-8")
    e = normalize_network_records(read_zeek_log(p), "task_test")[0]
    assert e.src_port is None and e.dst_port is None
    assert e.metadata["zeek"]["icmp_type"] == 8
    assert e.network.bytes_out == 0 and e.network.bytes_in is None
    assert e.metadata["zeek"]["end_time"] is None
    assert e.metadata["raw_reference"]["line"] == 5


def test_json_session_uid_join_no_double_bytes(tmp_path):
    (tmp_path / "conn.log").write_text(json.dumps(conn()), encoding="utf-8")
    row = conn(_log_type="http", uri="/", method="GET")
    row.pop("proto")
    (tmp_path / "http.log").write_text(json.dumps(row), encoding="utf-8")
    events = load_zeek_logs(tmp_path, "task_test")
    http = next(e for e in events if e.action == "http_request")
    connection = next(e for e in events if e.action == "network_connect")
    assert http.network.session_id == connection.network.session_id
    assert http.network.protocol == "tcp" and http.network.bytes_out is None
    assert http.metadata["session_event_id"] == connection.event_id
    assert query_sessions(events, host_id="c2server01") == [connection]


def test_rita_tab_spelling_and_trailing_delimiter(tmp_path):
    path = tmp_path / "dns.log"
    header = "#separator \\t\n#fields\tts\tquery\n#types\ttime\tstring\n"
    path.write_text(header + "1\texample.test\t\n", encoding="utf-8")
    record = next(read_zeek_log(path))
    assert record["query"] == "example.test" and record["_reference"]["line"] == 4
    path.write_text(header + "1\texample.test\textra\n", encoding="utf-8")
    with pytest.raises(ValueError, match="columns"): list(read_zeek_log(path))


def test_iot_mixed_label_columns_are_removed_before_detection(tmp_path):
    from correlation.validate_public_data import prepare_iot
    source, clean = tmp_path / "labeled", tmp_path / "conn.log"
    source.write_text("#separator \\x09\n#fields\tts\ttunnel_parents   label   detailed-label\n"
        "#types\ttime\tset[string]   string   string\n1\t(empty)   Malicious   C&C\n", encoding="utf-8")
    assert prepare_iot(source, clean) == {4: "C&C"}
    row = next(read_zeek_log(clean))
    assert row["tunnel_parents"] == [] and not any("label" in k for k in row)


def test_ntp_shape_filter_is_narrow_and_can_be_disabled():
    from detection.network_rules import NetworkConfig
    records = [conn(n, proto="udp", **{"id.orig_p": 123, "id.resp_p": 123,
        "orig_bytes": 48, "resp_bytes": 48}) for n in range(10)]
    events = normalize_network_records(records, "task_test")
    assert not detect_network(events)
    assert detect_network(events, NetworkConfig(suppress_ntp_shaped_beacons=False))
    for row in records: row["orig_bytes"] = 200
    assert detect_network(normalize_network_records(records, "task_test"))


def test_short_hex_dns_requires_sustained_txt_churn():
    import hashlib
    records = [conn(n, _log_type="dns", query=hashlib.sha256(str(n).encode()).hexdigest()[:18] + ".channel.example",
                    qtype_name="TXT") for n in range(100)]
    # Keep the complete set inside one half-hour window, spanning over two minutes.
    for n, row in enumerate(records): row["ts"] = 1788825600 + n * 5
    alerts = detect_network(normalize_network_records(records, "task_test"))
    assert [a.rule_id for a in alerts] == ["NET-DNS-TUNNEL"]
    assert not detect_network(normalize_network_records(records[:10], "task_test"))
    for row in records: row["qtype_name"] = "A"
    assert not detect_network(normalize_network_records(records, "task_test"))


def test_indexed_correlation_matches_exhaustive_evidence_pairs(monkeypatch):
    import correlation.service as service
    events = [event(0, process={"pid": 7}, user="alice"),
              event(1, "file_read", process={"pid": 7}, object={"type": "file", "path": "/report"}),
              event(2, process={"pid": 8, "ppid": 7}),
              event(3, "login_success", user="alice", src_ip="10.10.2.10", dst_ip="10.10.0.20"),
              event(4, process={"pid": 9}, user="alice")]
    events += normalize_network_records([conn(n) for n in range(20)], "task_test")
    # Include a cross-log UID join and a same-host file through a different process.
    events += normalize_network_records([conn(1, _log_type="http", uri="/", method="GET")], "task_test")
    events += [event(5, "file_write", process={"pid": 9}, object={"type": "file", "path": "/report"})]
    indexed = correlate("task_test", events, [])
    def exhaustive(rows, state, window):
        for i, later in enumerate(rows):
            yield later, [(e, service._seconds(later.timestamp) - service._seconds(e.timestamp))
                          for e in reversed(rows[:i]) if service._seconds(later.timestamp) - service._seconds(e.timestamp) <= window]
    monkeypatch.setattr(service, "_correlation_candidates", exhaustive)
    reference = correlate("task_test", events, [])
    assert indexed.nodes == reference.nodes and indexed.edges == reference.edges


@pytest.mark.parametrize("patch", [{"ts": "2026-09-08T00:00:00"}, {"orig_bytes": -1}, {"id.orig_p": 65536}])
def test_invalid_network_input_rejected(patch):
    with pytest.raises(ValueError): normalize_network_records([conn(**patch)], "task_test")


def test_network_detection_positive_and_normal_controls():
    rows = [conn(n) for n in range(10)]
    assert "NET-BEACON" in {a.rule_id for a in detect_network(normalize_network_records(rows, "task_test"))}
    dns = [conn(n, _log_type="dns", query=(f"{n:02d}" + "aB3dE5gH7jK9mN2pQ4sT6vW8xY0z") + ".example.test", qtype_name="TXT") for n in range(10)]
    assert "NET-DNS-TUNNEL" in {a.rule_id for a in detect_network(normalize_network_records(dns, "task_test"))}
    normal = [conn(n, _log_type="dns", query="www.example.test", qtype_name="A") for n in range(10)]
    assert detect_network(normalize_network_records(normal, "task_test")) == []
    http = [conn(n, _log_type="http", uri="/api?data=" + f"{n:04d}" + "Ab3dE5gH7jK9mN2pQ4sT6vW8xY0z" * 12, method="POST") for n in range(10)]
    assert "NET-HTTP-COVERT" in {a.rule_id for a in detect_network(normalize_network_records(http, "task_test"))}
    icmp = [conn(0, proto="icmp", orig_pkts=500, orig_ip_bytes=500000, duration=150, **{"id.orig_p": 8, "id.resp_p": 0})]
    alerts = detect_network(normalize_network_records(icmp, "task_test"))
    assert alerts[0].rule_id == "NET-ICMP-TUNNEL"
    assert json.loads(alerts[0].evidence_summary)["payload_entropy_available"] is False


def test_duplicates_do_not_create_beacon_or_cross_task_counts():
    events = normalize_network_records([conn()], "task_test") * 10
    assert detect_network(events) == []
    mixed = [normalize_network_records([conn(i)], f"task_{i}")[0] for i in range(10)]
    assert detect_network(mixed) == []
    assert timing([event(0), event(1), event(2), event(1000)])["regularity"] < .85


def test_graph_process_file_edges_and_pid_reuse():
    events = [event(0, process={"pid": 7, "name": "a"}),
        event(1, "file_read", process={"pid": 7}, object={"type": "file", "path": "/sensitive"}),
        event(2, process={"pid": 7, "name": "b"}), event(3, "network_connect", process={"pid": 7})]
    graph = correlate("task_test", events, [])
    links = [e.evidence_event_ids for e in graph.edges if e.attributes.get("kind") == "event_correlation"]
    assert ["evt_0", "evt_1"] in links and ["evt_2", "evt_3"] in links
    assert ["evt_1", "evt_2"] not in links
    assert len([n for n in graph.nodes if n.type.value == "process"]) == 2


def test_unrelated_same_host_events_not_forced_into_chain():
    graph = correlate("task_test", [event(0), event(1)], [])
    assert not [e for e in graph.edges if e.attributes.get("kind") == "event_correlation"]


def test_exited_pid_is_not_reused_without_a_new_birth():
    graph = correlate("task_test", [event(0, process={"pid": 7}),
        event(1, "process_exit", process={"pid": 7}), event(2, "file_read", process={"pid": 7})], [])
    assert not [e for e in graph.edges if e.attributes.get("kind") == "event_correlation" and "evt_2" in e.evidence_event_ids]


def test_graph_rejects_cross_task_and_dangling_alerts():
    with pytest.raises(ValueError, match="cross-task"):
        correlate("task_other", [event(0)], [])
    alert = Alert(alert_id="alert_a", task_id="task_test", timestamp_start=stamp(), event_ids=["evt_missing"],
        severity="high", rule_id="test", rule_name="test", description="test", confidence=.8, detector="test")
    with pytest.raises(ValueError, match="dangling"):
        correlate("task_test", [event(0)], [alert])


def test_pipeline_new_outputs_pass_public_schemas():
    events = normalize_network_records([conn(n) for n in range(10)], "task_test")
    result = analyze("task_test", events + events)
    replay = analyze("task_test", reversed(events))
    assert result[:2] == replay[:2]
    assert result[2].model_dump(exclude={"generated_at"}) == replay[2].model_dump(exclude={"generated_at"})
    assert result[3].model_dump(exclude={"generated_at"}) == replay[3].model_dump(exclude={"generated_at"})
    assert len(result[0]) == 10
    node_ids = {n.id for n in result[2].nodes}
    event_ids, alert_ids = {e.event_id for e in result[0]}, {a.alert_id for a in result[1]}
    for edge in result[2].edges:
        assert edge.source in node_ids and edge.target in node_ids
        assert set(edge.evidence_event_ids) <= event_ids
        assert set(edge.evidence_alert_ids) <= alert_ids
    for value, name in zip(result, ("normalized_event", "alert", "attack_graph", "trace_result")):
        validator = Draft202012Validator(json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text()), format_checker=FormatChecker())
        for obj in value if isinstance(value, list) else [value]: validator.validate(obj.model_dump(mode="json"))
    assert result[3].initial_access_entity_id is None
    assert result[3].attribution["llm_used"] is False


def tiny_stix(tmp_path):
    objects = [dict(type="attack-pattern", id="attack-pattern--1", name="DNS", external_references=[dict(source_name="mitre-attack", external_id="T1071.004")],
                    kill_chain_phases=[dict(kill_chain_name="mitre-attack", phase_name="command-and-control")]),
               dict(type="intrusion-set", id="intrusion-set--1", name="Test group", external_references=[dict(source_name="mitre-attack", external_id="G0001")]),
               dict(type="relationship", id="relationship--1", relationship_type="uses", source_ref="intrusion-set--1", target_ref="attack-pattern--1")]
    path = tmp_path / "stix.json"
    path.write_text(json.dumps(dict(type="bundle", objects=objects)))
    return AttackKnowledge(path)


def test_stix_exact_subtechnique_and_empty_similarity(tmp_path):
    k = tiny_stix(tmp_path)
    assert k.mapping("T1071.004").subtechnique_id == "T1071.004"
    assert k.mapping("T0000") is None
    assert k.similarity([]) == []
    assert k.similarity(["T1071.004"])[0]["similarity"] == 1
    assert k.similarity(["T1071"]) == []


def test_sigma_subset_boolean_filters_and_unsupported_syntax(tmp_path):
    p = tmp_path / "rule.yml"
    p.write_text("title: Test\nid: test\nlevel: medium\ntags: [attack.t1071.004]\nlogsource: {product: windows, category: process_creation}\ndetection:\n  selection:\n    Image|endswith: 'powershell.exe'\n  filter:\n    CommandLine|contains: 'approved'\n  condition: selection and not filter\n")
    r = SigmaRule(p)
    e = event(0, metadata={"os": "windows"}, process={"name": "powershell.exe"})
    assert len(r.match(e, tiny_stix(tmp_path))) == 1
    e.raw_event = {"CommandLine": "approved"}
    assert r.match(e, tiny_stix(tmp_path)) == []
    p.write_text(p.read_text().replace("selection and not filter", "selection | count() > 3"))
    with pytest.raises(ValueError): SigmaRule(p)


def test_available_official_sigma_rule():
    # Local integration test: optional reference checkout is not a project dependency.
    path = ROOT.parent / "security-trace-projects/sigma/rules/windows/process_creation/proc_creation_win_certutil_download.yml"
    if not path.exists(): pytest.skip("optional official Sigma checkout is absent")
    rule = SigmaRule(path)
    stix = ROOT.parent / "security-trace-projects/attack-stix-data/enterprise-attack/enterprise-attack.json"
    knowledge = AttackKnowledge(stix) if stix.exists() else None
    selections = rule.detection
    image_suffix = selections["selection_img"][0]["Image|endswith"]
    flag = selections["selection_flags"]["CommandLine|contains"][0]
    marker = selections["selection_http"]["CommandLine|contains"]
    raw = {"Image": "C:\\Windows\\System32" + image_suffix, "CommandLine": flag + marker + "://example.test/fixture"}
    e = event(0, raw_event=raw)
    alerts = rule.match(e, knowledge)
    assert len(alerts) == 2
    assert {a.severity.value for a in alerts} == {"medium"}
    if knowledge:
        assert {a.mitre.technique_id for a in alerts} == {"T1027", "T1105"}
    e.raw_event = {"Image": raw["Image"], "CommandLine": "normal local inventory"}
    assert rule.match(e, knowledge) == []
