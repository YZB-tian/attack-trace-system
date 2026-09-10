import json
from pathlib import Path
import pytest
from common.models import NormalizedEvent
from common.enums import SourceType
from correlation.host_demo import examples
from correlation.pipeline import analyze
from detection.host_rules import detect_host
from detection.service import detect
from collectors.windows.adapter import normalize_windows_records
from collectors.linux.adapter import normalize_linux_records
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("case", ["windows", "linux", "windows_normal", "linux_normal", "beacon"])
def test_default_pipeline_cases_and_schemas(case):
    events, expected = examples()[case]
    result = analyze(events[0].task_id, events)
    assert [a.rule_id for a in result[1]] == expected
    assert [a.rule_id for a in detect(iter(events))] == expected
    if case in {"windows", "linux"}:
        assert len(result[3].attack_chain) == 1
        assert result[3].attack_chain[0].evidence_alert_ids == [result[1][0].alert_id]
        assert result[3].attack_chain[0].evidence_event_ids == [events[0].event_id]
    nodes = {n.id for n in result[2].nodes}
    assert all(set(s.entity_ids) <= nodes for s in result[3].attack_chain)
    assert result[3].attribution["llm_used"] is False
    for value, name in zip(result, ("normalized_event", "alert", "attack_graph", "trace_result")):
        validator = Draft202012Validator(json.loads((ROOT / "schemas" / f"{name}.schema.json").read_text()),
                                        format_checker=FormatChecker())
        for obj in value if isinstance(value, list) else [value]:
            validator.validate(obj.model_dump(mode="json"))


def test_real_collectors_produce_supported_default_host_inputs():
    command = examples()["windows"][0][0].metadata["command_line"]
    windows = normalize_windows_records([{"EventID": 1, "Computer": "officepc01",
        "UtcTime": "2026-09-10T10:00:00+08:00", "Image": r"C:\Windows\powershell.exe",
        "ProcessId": 1200, "CommandLine": command}], "task_adapter_windows")
    linux = normalize_linux_records([{"host": "webserver01", "raw":
        'type=EXECVE msg=audit(1789000000.100:500): argc=3 a0="/sbin/auditctl" a1="-e" a2="0"'}], "task_adapter_linux")
    for rows, expected in [(windows, "HOST-WIN-POWERSHELL-ENCODED"), (linux, "HOST-LINUX-AUDIT-DISABLE")]:
        assert len(rows) == 1
        result = analyze(rows[0].task_id, rows)
        assert [a.rule_id for a in result[1]] == [expected]
        assert result[3].attack_chain


@pytest.mark.parametrize("command", ["powershell.exe", "powershell.exe -enc", "powershell.exe -enc !!!",
    'powershell.exe -Command "Write-Output -enc AAAA"', "powershell.exe -File demo.ps1 -enc AAAA",
    "notpowershell.exe -enc AAAA", 'echo powershell.exe -enc AAAA', 'powershell.exe "unclosed'])
def test_windows_negative_controls(command):
    row = examples()["windows"][0][0]
    row.metadata["command_line"] = command
    assert not detect_host([row])


@pytest.mark.parametrize("command", ["/sbin/auditctl -s", "/sbin/auditctl -e 1", "/sbin/auditctl -e 2",
    "echo auditctl -e 0", "/sbin/auditctl -l", "/sbin/auditctl -Dextra", "/sbin/AUDITCTL -e 0"])
def test_linux_negative_controls(command):
    row = examples()["linux"][0][0]
    row.object.name = command
    assert not detect_host([row])


def test_idempotence_host_source_gating_and_missing_data():
    row = examples()["windows"][0][0]
    assert len(detect_host([row, row])) == 1
    assert len(analyze(row.task_id, [row, row])[1]) == 1
    row.source_type = SourceType.NETWORK_FLOW
    assert not detect_host([row])
    row = examples()["windows"][0][0]
    row.metadata.clear()
    assert not detect_host([row])


def test_distinct_tasks_never_merge_host_alerts():
    row = examples()["linux"][0][0]
    other = row.model_copy(update={"task_id": "task_other"})
    alerts = detect_host([row, other])
    assert len({a.alert_id for a in alerts}) == 2
    with pytest.raises(ValueError, match="conflicting event ID"):
        analyze(row.task_id, [row, other])
    other.event_id = "evt_other_task"
    with pytest.raises(ValueError, match="mixed task"):
        analyze(row.task_id, [row, other])


def test_linux_process_exec_with_metadata_command_and_explicit_knowledge():
    row = examples()["linux"][0][0]
    row.action = "process_exec"
    row.metadata["command_line"] = "/sbin/auditctl -D"
    assert detect_host([row])[0].mitre.subtechnique_id == "T1685.004"
    class EmptyKnowledge:
        def mapping(self, *_): return None
    alert = detect_host([row], EmptyKnowledge())[0]
    assert alert.mitre is None  # Never override explicitly supplied knowledge with the bundled extract.
    assert json.loads(alert.evidence_summary)["unresolved_technique_id"] == "T1685.004"
