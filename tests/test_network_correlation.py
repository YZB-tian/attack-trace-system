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
    assets = {a["host_id"]: a["ip"] for a in json.loads((ROOT / "config/assets.json").read_text(encoding="utf-8"))["assets"]}
    endpoints = {"id.orig_h": assets["officepc01"], "id.resp_h": assets["c2server01"]}
    (tmp_path / "conn.log").write_text(json.dumps(conn(**endpoints)), encoding="utf-8")
    row = conn(_log_type="http", uri="/", method="GET", **endpoints)
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


def test_dhcp_periodic_broadcast_is_not_generic_beacon():
    from detection.network_rules import NetworkConfig

    records = []
    for n in range(10):
        row = conn(
            n,
            proto="udp",
            service="dhcp",
            conn_state="S0",
            orig_bytes=3000,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 128
        row["id.orig_h"] = "0.0.0.0"
        row["id.resp_h"] = "255.255.255.255"
        row["id.orig_p"] = 68
        row["id.resp_p"] = 67
        records.append(row)

    events = normalize_network_records(records, "task_test")
    rules = {a.rule_id for a in detect_network(events)}
    assert "NET-BEACON" not in rules

    rules_unsuppressed = {
        a.rule_id
        for a in detect_network(
            events,
            NetworkConfig(suppress_dhcp_beacons=False),
        )
    }
    assert "NET-BEACON" in rules_unsuppressed


def test_unanswered_udp123_retries_are_not_generic_failed_connects():
    from detection.network_rules import NetworkConfig

    records = []
    for n in range(8):
        row = conn(
            n,
            proto="udp",
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 60
        row["id.orig_p"] = 45000 + n
        row["id.resp_p"] = 123
        row["service"] = "-"
        records.append(row)

    events = normalize_network_records(records, "task_test")
    rules = {a.rule_id for a in detect_network(events)}
    assert "NET-REPEATED-FAILED-CONNECT" not in rules

    rules_unsuppressed = {
        a.rule_id
        for a in detect_network(
            events,
            NetworkConfig(suppress_unanswered_udp123_retries=False),
        )
    }
    assert "NET-REPEATED-FAILED-CONNECT" in rules_unsuppressed


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


def test_repeated_failed_connections_raise_candidate_without_merging_scan_targets():
    # Same endpoint + fresh source ports + S0/no-response => repeated retry candidate.
    rows = [
        conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        for n in range(8)
    ]
    events = normalize_network_records(rows, "task_test")
    rules = {a.rule_id for a in detect_network(events)}
    assert "NET-REPEATED-FAILED-CONNECT" in rules

    # A broad scan touches many destination IPs. Endpoint grouping must prevent
    # those one-off failures from being merged into the retry rule.
    scan_rows = []
    for n in range(8):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["id.resp_h"] = f"10.20.0.{n + 1}"
        scan_rows.append(row)
    scan_rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(scan_rows, "task_test"))
    }
    assert "NET-REPEATED-FAILED-CONNECT" not in scan_rules


def test_repeated_failed_connections_allow_bursty_source_port_reuse():
    # Botnet reconnect loops can reuse one ephemeral source port for several
    # SYN attempts before moving to the next port. Two ports across eight
    # failed attempts gives churn=0.25.
    rows = []
    for n in range(8):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["id.orig_p"] = 43000 if n < 4 else 43004
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-REPEATED-FAILED-CONNECT" in rules



def test_low_churn_mixed_success_and_failure_does_not_raise_retry_alert():
    # Low-churn groups are allowed only for essentially pure failed/no-response
    # retry loops. This models the round-2 iot34 false positive, where some
    # connections succeeded (SF) and returned data.
    rows = []
    for n in range(10):
        is_success = n == 9
        row = conn(
            n,
            conn_state="SF" if is_success else "S0",
            orig_bytes=50 if is_success else 0,
            resp_bytes=120 if is_success else 0,
        )
        # 3 distinct source ports / 10 samples => churn 0.30
        if n < 4:
            row["id.orig_p"] = 43000
        elif n < 7:
            row["id.orig_p"] = 43004
        else:
            row["id.orig_p"] = 43008
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-REPEATED-FAILED-CONNECT" not in rules



def test_conn_log_irc_service_can_raise_c2_candidate_without_irc_command_log():
    rows = [
        conn(
            n,
            service="irc",
            conn_state="SF",
            orig_bytes=120 + n,
            resp_bytes=180 + n,
        )
        for n in range(8)
    ]
    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-IRC-C2-CANDIDATE" in rules


def test_partial_irc_service_on_classic_port_can_raise_reconnect_campaign():
    rows = []
    for n in range(20):
        row = conn(
            n,
            service="irc" if n < 5 else "-",
            conn_state="S0" if n < 12 else "S3",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1700000000.0 + n * 30
        row["id.resp_p"] = 6667
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-IRC-RECONNECT-CAMPAIGN" in rules


def test_partial_irc_pattern_on_non_irc_port_does_not_raise_irc_campaign():
    rows = []
    for n in range(20):
        row = conn(
            n,
            service="irc" if n < 5 else "-",
            conn_state="S0" if n < 12 else "S3",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1700000000.0 + n * 30
        row["id.resp_p"] = 443
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-IRC-RECONNECT-CAMPAIGN" not in rules




def test_horizontal_scan_s0_only_across_many_destination_ips():
    rows = []
    for n in range(20):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 10
        row["id.resp_h"] = f"10.20.0.{n + 1}"
        row["id.resp_p"] = 22
        rows.append(row)

    alerts = detect_network(normalize_network_records(rows, "task_test"))
    scan = next(a for a in alerts if a.rule_id == "NET-HORIZONTAL-SCAN")
    evidence = json.loads(scan.evidence_summary)

    assert len(scan.event_ids) == 20
    assert evidence["unique_destination_ips"] == 20
    assert evidence["connection_state"] == "S0"
    assert evidence["evidence_scope"] == "s0_only"


def test_horizontal_scan_rejected_connections_are_not_scan_evidence():
    rows = []
    for n in range(20):
        row = conn(
            n,
            conn_state="REJ",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 10
        row["id.resp_h"] = f"10.30.0.{n + 1}"
        row["id.resp_p"] = 22
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-HORIZONTAL-SCAN" not in rules


def test_horizontal_scan_alert_attaches_only_s0_rows_from_mixed_window():
    rows = []
    for n in range(20):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 10
        row["id.resp_h"] = f"10.40.0.{n + 1}"
        row["id.resp_p"] = 22
        rows.append(row)

    for n in range(20, 25):
        row = conn(
            n,
            conn_state="REJ",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 5
        row["id.resp_h"] = f"10.50.0.{n + 1}"
        row["id.resp_p"] = 22
        rows.append(row)

    events = normalize_network_records(rows, "task_test")
    by_id = {e.event_id: e for e in events}
    scan = next(a for a in detect_network(events) if a.rule_id == "NET-HORIZONTAL-SCAN")

    assert len(scan.event_ids) == 20
    assert {
        by_id[eid].metadata["zeek"]["conn_state"]
        for eid in scan.event_ids
    } == {"S0"}



def test_http_download_campaign_requires_repeated_multi_destination_transfers():
    rows = []
    for n in range(4):
        row = conn(
            n,
            service="http",
            conn_state="SF",
            orig_bytes=100,
            resp_bytes=65536,
        )
        row["ts"] = 1788825600 + n * 10
        row["id.resp_h"] = "203.0.113.10" if n % 2 == 0 else "203.0.113.11"
        row["id.resp_p"] = 80
        rows.append(row)

    alerts = detect_network(normalize_network_records(rows, "task_test"))
    download = next(a for a in alerts if a.rule_id == "NET-HTTP-DOWNLOAD-CAMPAIGN")
    evidence = json.loads(download.evidence_summary)

    assert len(download.event_ids) == 4
    assert evidence["flow_count"] == 4
    assert evidence["unique_destination_ips"] == 2
    assert evidence["minimum_bytes_in"] == 16384
    assert evidence["minimum_response_ratio"] == 64.0
    assert evidence["campaign_shape"] == "repeated_multi_endpoint_response_heavy_http"


def test_http_download_campaign_does_not_flag_single_destination_download_burst():
    rows = []
    for n in range(6):
        row = conn(
            n,
            service="http",
            conn_state="SF",
            orig_bytes=100,
            resp_bytes=131072,
        )
        row["ts"] = 1788825600 + n * 8
        row["id.resp_h"] = "203.0.113.20"
        row["id.resp_p"] = 80
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-HTTP-DOWNLOAD-CAMPAIGN" not in rules


def test_http_download_campaign_does_not_flag_small_http_responses():
    rows = []
    for n in range(4):
        row = conn(
            n,
            service="http",
            conn_state="SF",
            orig_bytes=100,
            resp_bytes=4096,
        )
        row["ts"] = 1788825600 + n * 10
        row["id.resp_h"] = "203.0.113.30" if n % 2 == 0 else "203.0.113.31"
        row["id.resp_p"] = 80
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-HTTP-DOWNLOAD-CAMPAIGN" not in rules



def test_retry_persistent_connection_detects_failures_then_long_success():
    rows = []
    for n in range(5):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 20
        row["id.orig_p"] = 41000 + n
        row["id.resp_p"] = 443
        rows.append(row)

    success = conn(
        99,
        conn_state="SF",
        duration=7200,
        orig_bytes=4096,
        resp_bytes=4096,
    )
    success["ts"] = 1788825700
    success["id.orig_p"] = 42000
    success["id.resp_p"] = 443
    rows.append(success)

    alerts = detect_network(normalize_network_records(rows, "task_test"))
    alert = next(
        a for a in alerts
        if a.rule_id == "NET-RETRY-PERSISTENT-CONNECTION"
    )
    evidence = json.loads(alert.evidence_summary)

    assert len(alert.event_ids) == 6
    assert evidence["failure_count"] == 5
    assert evidence["persistent_success_count"] == 1
    assert evidence["max_success_duration"] == 7200
    assert evidence["transition_shape"] == (
        "repeated_failures_with_persistent_connection"
    )


def test_retry_persistent_connection_requires_long_success():
    rows = []
    for n in range(5):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 20
        row["id.orig_p"] = 43000 + n
        rows.append(row)

    success = conn(
        100,
        conn_state="SF",
        duration=60,
        orig_bytes=4096,
        resp_bytes=4096,
    )
    success["ts"] = 1788825700
    success["id.orig_p"] = 44000
    rows.append(success)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-RETRY-PERSISTENT-CONNECTION" not in rules


def test_multi_endpoint_irc_campaign_detects_rotating_endpoints():
    rows = []
    destinations = [
        "203.0.113.10",
        "203.0.113.11",
        "203.0.113.12",
        "203.0.113.13",
    ]
    for n in range(6):
        row = conn(
            n,
            service="irc" if n < 4 else "-",
            conn_state="S1" if n < 4 else "S0",
            orig_bytes=200 if n < 4 else 0,
            resp_bytes=400 if n < 4 else 0,
        )
        row["ts"] = 1788825600 + n * 300
        row["id.resp_h"] = destinations[n % len(destinations)]
        row["id.resp_p"] = 2407
        rows.append(row)

    alerts = detect_network(normalize_network_records(rows, "task_test"))
    alert = next(
        a for a in alerts
        if a.rule_id == "NET-MULTI-ENDPOINT-IRC-CAMPAIGN"
    )
    evidence = json.loads(alert.evidence_summary)

    assert len(alert.event_ids) == 6
    assert evidence["irc_flow_count"] == 4
    assert evidence["unique_destination_ips"] == 4
    assert evidence["campaign_shape"] == "multi_endpoint_irc_same_port"


def test_multi_endpoint_irc_campaign_requires_multiple_destinations():
    rows = []
    for n in range(6):
        row = conn(
            n,
            service="irc",
            conn_state="S1",
            orig_bytes=200,
            resp_bytes=400,
        )
        row["ts"] = 1788825600 + n * 300
        row["id.resp_h"] = "203.0.113.20"
        row["id.resp_p"] = 2407
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-MULTI-ENDPOINT-IRC-CAMPAIGN" not in rules



def test_dns_retries_are_not_generic_failed_connects():
    from detection.network_rules import NetworkConfig

    rows = []
    for n in range(8):
        row = conn(
            n,
            proto="udp",
            service="dns",
            conn_state="S0" if n != 7 else "SF",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 5
        row["id.orig_p"] = 53000 + n
        row["id.resp_p"] = 53
        rows.append(row)

    events = normalize_network_records(rows, "task_test")
    rules = {a.rule_id for a in detect_network(events)}
    assert "NET-REPEATED-FAILED-CONNECT" not in rules

    rules_unsuppressed = {
        a.rule_id
        for a in detect_network(
            events,
            NetworkConfig(suppress_dns_retries=False),
        )
    }
    assert "NET-REPEATED-FAILED-CONNECT" in rules_unsuppressed


def test_retry_persistent_connection_accepts_long_horizon_s2_session():
    rows = []
    for n in range(5):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 3600
        row["id.orig_p"] = 45000 + n
        row["service"] = "-"
        rows.append(row)

    success = conn(
        100,
        service="-",
        conn_state="S2",
        duration=8 * 3600,
        orig_bytes=14000,
        resp_bytes=14000,
    )
    success["ts"] = 1788825600 + 17 * 3600
    success["id.orig_p"] = 46000
    rows.append(success)

    alerts = detect_network(normalize_network_records(rows, "task_test"))
    alert = next(
        a for a in alerts
        if a.rule_id == "NET-RETRY-PERSISTENT-CONNECTION"
    )
    evidence = json.loads(alert.evidence_summary)

    assert len(alert.event_ids) == 6
    assert evidence["persistent_success_count"] == 1
    assert evidence["max_success_duration"] == 8 * 3600
    assert evidence["transition_shape"] == (
        "repeated_failures_with_persistent_connection"
    )


def test_retry_persistent_connection_rejects_high_volume_long_session():
    rows = []
    for n in range(5):
        row = conn(
            n,
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825600 + n * 3600
        row["id.orig_p"] = 47000 + n
        row["service"] = "-"
        rows.append(row)

    success = conn(
        101,
        service="-",
        conn_state="S1",
        duration=8 * 3600,
        orig_bytes=200000,
        resp_bytes=200000,
    )
    success["ts"] = 1788825600 + 17 * 3600
    success["id.orig_p"] = 48000
    rows.append(success)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-RETRY-PERSISTENT-CONNECTION" not in rules


def test_http_download_retry_campaign_can_correlate_persistent_tcp23():
    rows = []
    dst = "203.0.113.50"

    # Five large response-heavy HTTP downloads.
    for n in range(5):
        row = conn(
            n,
            service="http",
            conn_state="SF",
            orig_bytes=150,
            resp_bytes=150000,
        )
        row["ts"] = 1788825600 + n * 20
        row["id.orig_p"] = 50000 + n
        row["id.resp_h"] = dst
        row["id.resp_p"] = 80
        rows.append(row)

    # Four failed/no-response attempts to the same HTTP endpoint.
    for n in range(4):
        row = conn(
            20 + n,
            service="-",
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825610 + n * 20
        row["id.orig_p"] = 51000 + n
        row["id.resp_h"] = dst
        row["id.resp_p"] = 80
        rows.append(row)

    # Same source/destination pair, concurrent persistent TCP/23 session.
    telnet = conn(
        99,
        service="-",
        conn_state="S1",
        duration=7200,
        orig_bytes=639,
        resp_bytes=627,
    )
    telnet["ts"] = 1788825650
    telnet["id.orig_p"] = 52000
    telnet["id.resp_h"] = dst
    telnet["id.resp_p"] = 23
    rows.append(telnet)

    alerts = detect_network(normalize_network_records(rows, "task_test"))
    alert = next(
        a for a in alerts
        if a.rule_id == "NET-HTTP-DOWNLOAD-RETRY-CAMPAIGN"
    )
    evidence = json.loads(alert.evidence_summary)

    assert len(alert.event_ids) == 10
    assert evidence["heavy_http_download_count"] == 5
    assert evidence["failed_no_response_count"] == 4
    assert evidence["correlated_tcp23_count"] == 1
    assert evidence["campaign_shape"] == (
        "same_endpoint_http_download_plus_retries"
    )


def test_http_download_retry_campaign_requires_five_heavy_downloads():
    rows = []
    dst = "203.0.113.60"

    # IoT34-like shape: many failures, but only four heavy HTTP responses.
    for n in range(4):
        row = conn(
            n,
            service="http",
            conn_state="SF",
            orig_bytes=150,
            resp_bytes=120000,
        )
        row["ts"] = 1788825600 + n * 30
        row["id.resp_h"] = dst
        row["id.resp_p"] = 80
        rows.append(row)

    for n in range(13):
        row = conn(
            30 + n,
            service="-",
            conn_state="S0",
            orig_bytes=0,
            resp_bytes=0,
        )
        row["ts"] = 1788825605 + n * 20
        row["id.orig_p"] = 54000 + n
        row["id.resp_h"] = dst
        row["id.resp_p"] = 80
        rows.append(row)

    rules = {
        a.rule_id
        for a in detect_network(normalize_network_records(rows, "task_test"))
    }
    assert "NET-HTTP-DOWNLOAD-RETRY-CAMPAIGN" not in rules


def test_volumetric_udp_outbound_detects_one_way_high_volume_flow():
    row = conn(
        1,
        proto="udp",
        conn_state="S0",
        duration=300,
        orig_bytes=200 * 1024 * 1024,
        resp_bytes=0,
        orig_pkts=200000,
        resp_pkts=0,
    )
    row["id.resp_p"] = 80

    alerts = detect_network(normalize_network_records([row], "task_test"))
    alert = next(
        a for a in alerts
        if a.rule_id == "NET-VOLUMETRIC-UDP-OUTBOUND"
    )
    evidence = json.loads(alert.evidence_summary)

    assert evidence["traffic_shape"] == "high_volume_one_way_udp"
    assert evidence["bytes_out"] == 200 * 1024 * 1024
    assert evidence["orig_packets"] == 200000


def test_volumetric_udp_outbound_ignores_ordinary_udp_flow():
    row = conn(
        1,
        proto="udp",
        conn_state="S0",
        duration=300,
        orig_bytes=10 * 1024 * 1024,
        resp_bytes=0,
        orig_pkts=10000,
        resp_pkts=0,
    )

    rules = {
        a.rule_id
        for a in detect_network(
            normalize_network_records([row], "task_test")
        )
    }
    assert "NET-VOLUMETRIC-UDP-OUTBOUND" not in rules


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
