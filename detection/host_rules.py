"""Two deliberately narrow, default-on host detections over public events.

No programs are executed. These rules detect suspicious command intent, not
successful compromise; optional Sigma rules remain available separately.
"""
from __future__ import annotations
import base64
import binascii
import json
import re
import shlex
from functools import lru_cache
from pathlib import Path
from common.models import MitreMapping
from .network_rules import make_alert

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=1)
def _assets():
    return {a["host_id"]: a.get("os") for a in
            json.loads((ROOT / "config/assets.json").read_text(encoding="utf-8"))["assets"]}


def _os(event):
    product = event.metadata.get("os") or _assets().get(event.host_id)
    if isinstance(product, str):
        return product.casefold()
    source = event.source.casefold()
    if source in {"auditd", "auth.log", "syslog", "linux"}:
        return "linux"
    if source in {"sysmon", "windows", "microsoft-windows-sysmon", "security"}:
        return "windows"
    return None


def _command(event):
    if isinstance(event.metadata.get("command_line"), str):
        return event.metadata["command_line"], "metadata.command_line"
    raw = event.raw_event if isinstance(event.raw_event, dict) else {}
    for key in ("CommandLine", "command_line", "cmdline"):
        if isinstance(raw.get(key), str):
            return raw[key], "raw_event." + key
    if event.action == "command_args" and event.object and event.object.type == "command":
        return event.object.name or "", "object.name"
    return "", None


def _basename(value):
    return re.split(r"[/\\]", value.strip('"'))[-1]


@lru_cache(maxsize=1)
def _reviewed_mappings():
    return json.loads((Path(__file__).with_name("host_techniques.json")).read_text(encoding="utf-8"))


def detect_host(events, knowledge=None):
    unique = {}
    for event in events:
        key = (event.task_id, event.event_id)
        if key in unique and unique[key] != event:
            raise ValueError(f"conflicting event ID: {event.event_id}")
        unique[key] = event
    alerts = []
    for event in unique.values():
        if event.source_type.value not in {"host_log", "host_behavior"}:
            continue
        if event.action not in {"process_create", "process_exec", "command_args"}:
            continue
        product = _os(event)
        if product not in {"windows", "linux"}:
            continue
        command, field = _command(event)
        if not command:
            continue
        try:
            args = shlex.split(command, posix=product != "windows")
        except ValueError:
            continue
        if not args:
            continue
        executable = _basename(args[0])
        image = _basename(event.process.path or event.process.name or "") if event.process else ""
        # Avoid matching command strings merely mentioned in echo/logger arguments.
        if image and (image.casefold() if product == "windows" else image) != (
                executable.casefold() if product == "windows" else executable):
            continue
        rule = None
        if product == "windows" and executable.casefold() in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}:
            for i, arg in enumerate(args[1:], 1):
                # Everything after -Command/-File belongs to a script, not to
                # PowerShell's own startup options.
                if arg.casefold() in {"-command", "-c", "-file", "-f"}:
                    break
                if arg.casefold() not in {"-enc", "-encodedcommand"} or i + 1 >= len(args):
                    continue
                encoded = args[i + 1].strip('"\'')
                try:
                    decoded = base64.b64decode(encoded, validate=True)
                    valid = bool(decoded) and len(decoded) % 2 == 0
                    if valid:
                        decoded.decode("utf-16-le")
                except (ValueError, binascii.Error, UnicodeDecodeError):
                    valid = False
                if valid:
                    rule = ("HOST-WIN-POWERSHELL-ENCODED", "PowerShell encoded command execution candidate",
                            "T1059.001", "execution", "encoded_command_argument")
                    break
        elif product == "linux" and executable == "auditctl":
            if args[1:] in (["-e", "0"], ["-e0"], ["-D"]):
                rule = ("HOST-LINUX-AUDIT-DISABLE", "Linux audit disabling or rule removal candidate",
                        "T1685.004", "defense-impairment", "auditctl_disable_or_delete_rules")
        if not rule:
            continue
        rid, title, technique, tactic, reason = rule
        features = {"os": product, "command_field": field, "executable": executable,
                    "matched_condition": reason, "action": event.action,
                    "execution_success_proven": False}
        alert = make_alert([event], rid, title, .8, features, knowledge, technique)
        alert.detector = "host_heuristic_v1"
        alert.description = title + ". Review original event and authorized administration context; success is not proven."
        # A tiny reviewed STIX extract makes the two default rules useful without
        # an external download. Explicitly supplied knowledge remains authoritative.
        alert.mitre = knowledge.mapping(technique, tactic) if knowledge else MitreMapping.model_validate(
            _reviewed_mappings()["mappings"][technique])
        evidence = json.loads(alert.evidence_summary)
        if alert.mitre:
            evidence.pop("unresolved_technique_id", None)
        if not knowledge:
            evidence["mapping_source"] = "bundled_reviewed_stix_extract"
            evidence["stix_bundle_sha256"] = _reviewed_mappings()["bundle_sha256"]
        alert.evidence_summary = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        alerts.append(alert)
    return sorted(alerts, key=lambda a: (a.timestamp_start, a.alert_id))
