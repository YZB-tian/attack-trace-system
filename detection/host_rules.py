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
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from common.models import MitreMapping
from .network_rules import make_alert, seconds

ROOT = Path(__file__).resolve().parents[1]

# Credential and privilege material; ordinary log reading and backups also open
# these paths, so the resulting alert stays a candidate for human review.
# SSH clients probe many key paths on every connection, so generic key
# filenames are deliberately excluded.
SENSITIVE_EXACT_PATHS = frozenset({
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
    "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ed25519_key",
    "/etc/ssh/ssh_host_ecdsa_key", "/root/.ssh/authorized_keys",
})
SENSITIVE_STEM_PATTERNS = (".aws/credentials", ".pgpass")

# Signed Windows binaries that are frequently abused to proxy execution.
# Only clearly remote/scripted argument shapes are treated as suspicious.
WINDOWS_LOLBIN_SIGNATURES = {
    "rundll32.exe": ("javascript:", "http://", "https://", "\\\\unc\\"),
    "regsvr32.exe": ("scrobj.dll", "/i:http", "/i:https", "http://", "https://"),
    "mshta.exe": ("http://", "https://", ".hta"),
    "certutil.exe": ("-urlcache", "-decode", "-encode"),
}

# Processes that legitimately hold handles to LSASS memory in a default Windows
# install or a security agent. Everything else reading LSASS is a candidate.
LSASS_READER_ALLOWLIST = frozenset({
    "lsass.exe", "csrss.exe", "services.exe", "svchost.exe", "wininit.exe",
    "wmiprvse.exe", "msmpeng.exe", "nissrv.exe", "securityhealthservice.exe",
    "taskmgr.exe", "sysmon.exe", "sysmon64.exe", "searchindexer.exe",
})

# Accounts the laboratory uses for administration and evidence collection. Their
# logins and sudo calls must not turn into attacker candidates, and every alert
# that applies the exclusion says so in its evidence. Any other account,
# including other administrators, is still reported.
OPERATOR_ACCOUNTS = frozenset({"labforensics", "labadmin"})

# csrss.exe creates the first thread of every new process and dwm.exe does the
# same for its children. Both are documented Windows behaviour and were the
# dominant source of CreateRemoteThread candidates on the public dataset.
REMOTE_THREAD_SOURCE_ALLOWLIST = frozenset({"csrss.exe", "dwm.exe"})


def _is_sensitive_path(path: str) -> bool:
    if path in SENSITIVE_EXACT_PATHS:
        return True
    return any(stem in path for stem in SENSITIVE_STEM_PATTERNS)


def _unbacked_thread(event) -> bool:
    """True when a remote thread starts outside every loaded module.

    Sysmon writes ``-`` for an empty field. A start address with no backing
    module is the usual shape of injected or reflectively loaded code, so it is
    reported separately from a thread that starts inside a known image.
    """
    module = str(event.metadata.get("start_module") or "").strip()
    return module in {"", "-"}


_ASSET_CACHE: Optional[tuple[tuple[int, int], list]] = None


def _asset_rows() -> list:
    """Asset table, re-read when ``config/assets.json`` changes on disk."""
    global _ASSET_CACHE
    path = ROOT / "config" / "assets.json"
    stat = path.stat()
    stamp = (stat.st_mtime_ns, stat.st_size)
    if _ASSET_CACHE is None or _ASSET_CACHE[0] != stamp:
        _ASSET_CACHE = (stamp, json.loads(path.read_text(encoding="utf-8"))["assets"])
    return _ASSET_CACHE[1]


def _assets():
    return {a["host_id"]: a.get("os") for a in _asset_rows()}


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


def _assets_by_ip():
    return {a["ip"]: a for a in _asset_rows()}


def _access_alerts(events, knowledge):
    """Lateral-movement and privilege-escalation candidates from Linux auth logs.

    A remote login on a lab host whose source is another lab host (not the
    external attacker segment) is a lateral-movement candidate. A sudo command
    that names root as the target user while the caller is not root is a
    privilege-escalation candidate. Both are heuristics and stay below the
    initial-access confidence bar so they cannot be mistaken for certainties.
    """
    logins = defaultdict(list)
    sudo = defaultdict(list)
    sensitive = defaultdict(list)
    injections = defaultdict(list)
    write_access = defaultdict(list)
    lsass_access = defaultdict(list)
    for event in events:
        if event.source_type.value not in {"host_log", "host_behavior"}:
            continue
        product = _os(event)
        if product == "windows":
            if event.action in {"remote_thread_create", "process_access"}:
                key = (event.host_id, event.metadata.get("source_image"),
                       event.metadata.get("target_image"))
                if event.action == "remote_thread_create":
                    source = str(event.metadata.get("source_image") or "").rsplit("\\", 1)[-1].casefold()
                    if source not in REMOTE_THREAD_SOURCE_ALLOWLIST:
                        injections[key].append(event)
                elif event.metadata.get("write_capable"):
                    write_access[key].append(event)
                target = str(event.metadata.get("target_image") or "").casefold().replace("/", "\\")
                granted = event.metadata.get("granted_access_value")
                reader = str(event.metadata.get("source_image") or "").rsplit("\\", 1)[-1].casefold()
                if (event.action == "process_access" and isinstance(granted, int)
                        and granted & (0x0010 | 0x0020 | 0x0008)
                        and target.endswith("\\lsass.exe")
                        and reader not in LSASS_READER_ALLOWLIST):
                    lsass_access[key].append(event)
            continue
        if product != "linux":
            continue
        if event.action == "login_success" and event.src_ip and event.host_id:
            source = _assets_by_ip().get(event.src_ip)
            operator = str(event.user or "").casefold() in OPERATOR_ACCOUNTS
            if (source and not operator and source.get("zone") != "external"
                    and source["host_id"] != event.host_id):
                logins[(event.host_id, event.src_ip)].append(event)
        elif event.action == "sudo_exec" and event.host_id:
            target = str(event.metadata.get("target_user") or "").casefold()
            caller = str(event.user or "").casefold()
            if (target in {"root", "0"} and caller not in {"root", "0", ""}
                    and caller not in OPERATOR_ACCOUNTS):
                sudo[event.host_id].append(event)
        elif (event.action in {"file_access", "file_read", "file_open"} and event.object
              and event.object.type == "file"):
            path = str(event.object.path or "")
            if _is_sensitive_path(path):
                sensitive[(event.host_id, path)].append(event)
    alerts = []
    for (host_id, src_ip), rows in sorted(logins.items()):
        features = {"host_id": host_id, "source_ip": src_ip, "login_events": len(rows),
                    "reason": "remote_login_from_another_lab_host", "success_proven": True,
                    "excluded_operator_accounts": sorted(OPERATOR_ACCOUNTS)}
        alert = make_alert(rows, "HOST-LINUX-INTERNAL-SSH-LOGIN",
                           "Remote login from another internal host (lateral movement candidate)",
                           0.6, features, knowledge, "T1021.004", "lateral-movement")
        alert.detector = "host_heuristic_v1"
        alert.description = alert.description + " Source host is an internal asset, not the external attacker segment."
        alerts.append(alert)
    for host_id, rows in sorted(sudo.items()):
        users = sorted({str(e.user) for e in rows})
        features = {"host_id": host_id, "callers": users, "sudo_events": len(rows),
                    "reason": "sudo_command_targets_root", "execution_success_proven": False,
                    "excluded_operator_accounts": sorted(OPERATOR_ACCOUNTS)}
        alert = make_alert(rows, "HOST-LINUX-SUDO-TO-ROOT",
                           "Sudo command targeting root from a non-root account",
                           0.6, features, knowledge, "T1548.003", "privilege-escalation")
        alert.detector = "host_heuristic_v1"
        alert.description = alert.description + " Authorized administration also looks like this; review the caller and command."
        alerts.append(alert)
    for (host_id, path), rows in sorted(sensitive.items()):
        processes = sorted({str(e.process.name) for e in rows if e.process and e.process.name})
        features = {"host_id": host_id, "path": path, "access_events": len(rows),
                    "processes": processes, "reason": "credential_or_privilege_file_accessed",
                    "read_success_proven": False}
        alert = make_alert(rows, "HOST-LINUX-SENSITIVE-FILE-ACCESS",
                           "Sensitive credential file accessed on a monitored host",
                           0.6, features, knowledge, "T1005", "collection")
        alert.detector = "host_heuristic_v1"
        alert.description = alert.description + " Backups and configuration management also read these files."
        alerts.append(alert)
    for (host_id, source_image, target_image), rows in sorted(injections.items(), key=str):
        evidence = sorted(rows + write_access.get((host_id, source_image, target_image), []),
                          key=lambda e: (e.timestamp, e.event_id))
        unbacked = [e for e in rows if _unbacked_thread(e)]
        features = {"host_id": host_id, "source_image": source_image, "target_image": target_image,
                    "remote_thread_events": len(rows),
                    "write_capable_access_events": len(write_access.get((host_id, source_image, target_image), [])),
                    "unbacked_thread_events": len(unbacked),
                    "reflective_or_injected_code_indicator": bool(unbacked),
                    "reason": "create_remote_thread_into_another_process",
                    "code_execution_proven": False}
        alert = make_alert(evidence, "HOST-WIN-PROCESS-INJECTION",
                           "Remote thread created inside another process (memory injection candidate)",
                           0.9 if unbacked else 0.85, features, knowledge, "T1055", "defense-evasion")
        alert.detector = "host_heuristic_v1"
        alert.description = alert.description + (" The thread start address is outside every loaded module, which is consistent with injected or reflectively loaded code."
                                                  if unbacked else
                                                  " Debuggers, EDR products and accessibility tools also create remote threads.")
        alerts.append(alert)
    for (host_id, source_image, target_image), rows in sorted(lsass_access.items(), key=str):
        features = {"host_id": host_id, "source_image": source_image, "target_image": target_image,
                    "access_events": len(rows),
                    "reason": "lsass_process_memory_write_access",
                    "dump_created_proven": False}
        alert = make_alert(rows, "HOST-WIN-LSASS-MEMORY-ACCESS",
                           "Process requested write access to LSASS memory (credential dumping candidate)",
                           0.8, features, knowledge, "T1003.001", "credential-access")
        alert.detector = "host_heuristic_v1"
        alert.description = alert.description + " Backup, EDR and password-filter components also request LSASS access."
        alerts.append(alert)
    return alerts


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
        elif product == "windows" and executable.casefold() in WINDOWS_LOLBIN_SIGNATURES:
            lowered = command.casefold()
            if any(token in lowered for token in WINDOWS_LOLBIN_SIGNATURES[executable.casefold()]):
                rule = ("HOST-WIN-LOLBIN-EXECUTION",
                        "System binary used to launch a remote or scripted payload",
                        "T1218", "defense-evasion", "lolbin_remote_or_scripted_argument")
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
        alert = make_alert([event], rid, title, .8, features, knowledge, technique, tactic)
        alert.detector = "host_heuristic_v1"
        alert.description = title + ". Review original event and authorized administration context; success is not proven."
        # A tiny reviewed STIX extract makes the two default rules useful without
        # an external download. Explicitly supplied knowledge remains authoritative.
        bundled = None if knowledge else _reviewed_mappings()["mappings"].get(technique)
        alert.mitre = knowledge.mapping(technique, tactic) if knowledge else (
            MitreMapping.model_validate(bundled) if bundled else None)
        evidence = json.loads(alert.evidence_summary)
        if alert.mitre:
            evidence.pop("unresolved_technique_id", None)
        if not knowledge and bundled:
            evidence["mapping_source"] = "bundled_reviewed_stix_extract"
            evidence["stix_bundle_sha256"] = _reviewed_mappings()["bundle_sha256"]
        elif not knowledge:
            # Techniques outside the bundled extract stay unmapped until an
            # official STIX bundle is supplied; no name is invented.
            evidence["unresolved_technique_id"] = technique
            evidence["mapping_source"] = "unmapped_without_stix_bundle"
        alert.evidence_summary = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        alerts.append(alert)

    # GENERIC_NORMALIZED_AUTH_SEQUENCE_V1
    # Detect a short burst of failed logins followed by a success using only the
    # public NormalizedEvent contract. This is intentionally source-agnostic.
    auth_groups = defaultdict(list)
    for event in unique.values():
        if event.source_type.value != "host_log":
            continue
        if event.action not in {"login_failure", "login_success"}:
            continue
        if not event.host_id or not event.src_ip:
            continue
        auth_groups[
            (event.task_id, event.host_id, event.src_ip, str(event.user or ""))
        ].append(event)

    for (task_id, host_id, src_ip, user), rows in sorted(auth_groups.items()):
        def _raw_order(event):
            ref = event.metadata.get("raw_reference", {}) if isinstance(event.metadata, dict) else {}
            if not isinstance(ref, dict):
                return None, None
            record = ref.get("record")
            try:
                record = int(record)
            except (TypeError, ValueError):
                record = None
            return str(ref.get("file") or ""), record

        for success in rows:
            if success.action != "login_success":
                continue
            success_time = seconds(success.timestamp)
            success_file, success_record = _raw_order(success)
            failures = []
            for row in rows:
                if row.action != "login_failure":
                    continue
                delta = success_time - seconds(row.timestamp)
                if not 0 <= delta <= 120:
                    continue

                # Some application logs have only second-level timestamps. When
                # failure and success share the same timestamp, use the original
                # source-record order if the collector preserved it. Never use
                # event_id hash order as a chronology signal.
                if delta == 0:
                    failure_file, failure_record = _raw_order(row)
                    if not (
                        failure_file
                        and failure_file == success_file
                        and failure_record is not None
                        and success_record is not None
                        and failure_record < success_record
                    ):
                        continue
                failures.append(row)
            if len(failures) < 2:
                continue

            evidence = failures[-5:] + [success]
            features = {
                "host_id": host_id,
                "source_ip": src_ip,
                "user": user or None,
                "failed_logins_before_success": len(failures),
                "window_seconds": round(success_time - seconds(failures[0].timestamp), 3),
                "success_observed": True,
                "reason": "multiple_authentication_failures_followed_by_success",
            }
            alert = make_alert(
                evidence,
                "HOST-AUTH-FAILURE-THEN-SUCCESS",
                "Multiple authentication failures followed by a successful login",
                .72,
                features,
                knowledge,
                "T1110",
                "credential-access",
            )
            alert.detector = "host_heuristic_v1"
            alert.description = (
                "Multiple authentication failures were followed by a successful "
                "login from the same source. This is a suspicious authentication "
                "sequence, not proof of compromise; user mistakes can look similar."
            )
            alerts.append(alert)
            break

    alerts.extend(_access_alerts(unique.values(), knowledge))
    dedup = {}
    for alert in alerts:
        dedup[alert.alert_id] = alert
    return sorted(dedup.values(), key=lambda a: (a.timestamp_start, a.alert_id))
