"""Reproducible offline evaluation; dataset answers never enter the detector."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from collectors.network.adapter import load_zeek_logs, read_zeek_log
from detection.attack_stix import AttackKnowledge
from detection.network_rules import NetworkConfig, detect_network
from .pipeline import analyze

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "1317d70ce00319782c0983c7d9033b9290e58e95"
IOT_URL = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"


def file_info(path, source):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): digest.update(block)
    return {"path": str(path.resolve()), "source": source, "bytes": path.stat().st_size,
            "sha256": digest.hexdigest()}


def prepare_iot(source, output):
    """Remove labels, preserving source line numbers; support both official layouts."""
    labels, fields, mixed = {}, [], False
    output.parent.mkdir(parents=True, exist_ok=True)
    with source.open(encoding="utf-8-sig") as src, output.open("w", encoding="utf-8", newline="\n") as dst:
        for line_no, line in enumerate(src, 1):
            line = line.rstrip("\r\n")
            if line.startswith(("#fields\t", "#types\t")):
                values = line.split("\t")
                if line.startswith("#fields\t"):
                    mixed = values[-1] == "tunnel_parents   label   detailed-label"
                if mixed: values = values[:-1] + re.split(r" {3}", values[-1])
                if line.startswith("#fields\t"):
                    fields = values[1:]
                    if fields[-2:] not in (["label", "det_label"], ["label", "detailed-label"]):
                        raise ValueError(f"unsupported IoT labels at {source}:{line_no}")
                dst.write("\t".join(values[:-2]) + "\n")
            elif line and not line.startswith("#"):
                values = line.split("\t")
                if mixed: values = values[:-1] + re.split(r" {3}", values[-1])
                if len(values) != len(fields): raise ValueError(f"IoT column mismatch: {source}:{line_no}")
                label, detail = values[-2:]
                if label not in {"Benign", "Malicious"}: raise ValueError(f"unknown IoT label: {label}")
                labels[line_no] = detail if label == "Malicious" else "Benign"
                dst.write("\t".join(values[:-2]) + "\n")
            else: dst.write(line + "\n")
    if not labels: raise ValueError("empty labeled dataset")
    return labels


def metrics(events, alerts, labels):
    flagged = {eid for a in alerts for eid in a.event_ids}
    covered = Counter(labels[e.event_id] for e in events if e.event_id in flagged)
    total = Counter(labels.values())
    positive = {k for k in total if k.startswith("C&C")}
    tp = sum(covered[k] for k in positive)
    positives = sum(total[k] for k in positive)
    fp, negatives = covered["Benign"], total["Benign"]
    return {"alerts_by_rule": dict(Counter(a.rule_id for a in alerts)),
            "label_counts": dict(total), "flagged_flows_by_label": dict(covered),
            "c_and_c_vs_benign": {"tp": tp, "fn": positives - tp, "fp": fp, "tn": negatives - fp,
                "recall": tp / positives if positives else None,
                "precision": tp / (tp + fp) if tp + fp else None,
                "benign_flow_false_positive_rate": fp / negatives if negatives else None,
                "excluded_other_attack_flows": sum(v for k, v in total.items() if k not in positive | {"Benign"})},
            "interpretation": "Flow evidence coverage, not window-level accuracy. General C&C labels are not beacon ground truth."}


def validate_and_write(result, destination):
    destination.mkdir(parents=True, exist_ok=True)
    counts = {}
    for value, schema, filename in zip(result, ("normalized_event", "alert", "attack_graph", "trace_result"),
                                       ("normalized_events", "alerts", "attack_graph", "trace_result")):
        validator = Draft202012Validator(json.loads((ROOT / "schemas" / (schema + ".schema.json")).read_text(encoding="utf-8")),
                                          format_checker=FormatChecker())
        objects = value if isinstance(value, list) else [value]
        for obj in objects: validator.validate(obj.model_dump(mode="json"))
        counts[schema] = len(objects)
        data = [obj.model_dump(mode="json") for obj in objects] if isinstance(value, list) else value.model_dump(mode="json")
        (destination / (filename + ".json")).write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    # Verify references as well as schema shape.
    ids = {e.event_id for e in result[0]}; aids = {a.alert_id for a in result[1]}; nodes = {n.id for n in result[2].nodes}
    for edge in result[2].edges:
        assert edge.source in nodes and edge.target in nodes
        assert set(edge.evidence_event_ids) <= ids and set(edge.evidence_alert_ids) <= aids
    return {"schema_validated_objects": counts, "nodes": len(nodes), "edges": len(result[2].edges),
            "initial_access": result[3].initial_access_entity_id, "attack_stages": len(result[3].attack_chain)}


def run(base, stix):
    knowledge = AttackKnowledge(stix)
    before = NetworkConfig(suppress_ntp_shaped_beacons=False, detect_short_hex_dns=False)
    report = {"dataset_files": [], "stix": file_info(stix, "official local enterprise ATT&CK STIX bundle"),
              "baseline_config": asdict(before), "final_config": asdict(NetworkConfig()), "scenarios": {},
              "label_leakage": False, "rita_original_parser": "failed on line 9 in all three logs before separator/trailing-tab fix"}
    for name, capture in (("iot34", "CTU-IoT-Malware-Capture-34-1"), ("iot8", "CTU-IoT-Malware-Capture-8-1")):
        print(f"Starting {name}: full capture parse, detection, graph and schema checks", flush=True)
        start = time.perf_counter()
        source = base / name / "conn.log.labeled"
        report["dataset_files"].append(file_info(source, IOT_URL + capture + "/bro/conn.log.labeled"))
        labeled_lines = prepare_iot(source, base / name / "clean" / "conn.log")
        events = load_zeek_logs(base / name / "clean", "task_public_" + name)
        labels = {e.event_id: labeled_lines[e.metadata["raw_reference"]["line"]] for e in events}
        assert len(events) == len(labeled_lines)
        assert all(not e.labels and not any("label" in k for k in e.raw_event) for e in events)
        baseline = metrics(events, detect_network(events, before, knowledge), labels)
        result = analyze("task_public_" + name, events, knowledge=knowledge)
        entry = {"scope": "entire capture", "events": len(events), "baseline": baseline,
                 "final": metrics(events, result[1], labels), **validate_and_write(result, base / name / "result"),
                 "elapsed_seconds": round(time.perf_counter() - start, 3)}
        report["scenarios"][name] = entry
        print(name, json.dumps(entry, ensure_ascii=False), flush=True)
    # The first-hour selection is fixed before inspection of detector outcomes. Parse
    # every original row, normalize/detect/correlate only this same timestamp interval.
    rita = base / "rita"; clean = rita / "first_hour"; clean.mkdir(exist_ok=True)
    anchor = next(read_zeek_log(rita / "conn.log"))["ts"]
    inventory = {}
    for kind in ("conn", "dns", "http"):
        print(f"Parsing complete RITA {kind}.log; selecting fixed first hour", flush=True)
        source = rita / (kind + ".log")
        report["dataset_files"].append(file_info(rita / (kind + ".log.gz"),
            f"https://github.com/activecm/rita/blob/{COMMIT}/test_data/dnscat2-ja3-strobe-agent/{kind}.log.gz"))
        total = selected = 0
        with (clean / (kind + ".log")).open("w", encoding="utf-8") as dst:
            for record in read_zeek_log(source):
                total += 1
                if anchor <= record["ts"] < anchor + 3600:
                    selected += 1
                    # Original file/line retained separately from the derived input.
                    record["validation_original_reference"] = record["_reference"]
                    dst.write(json.dumps({k: v for k, v in record.items() if not k.startswith("_")}) + "\n")
        inventory[kind] = {"parsed_rows": total, "selected_rows": selected}
    events = load_zeek_logs(clean, "task_public_rita")
    print(f"Analyzing RITA first hour: {len(events)} events", flush=True)
    baseline = detect_network(events, before, knowledge)
    result = analyze("task_public_rita", events, knowledge=knowledge)
    coverage = {}
    byid = {e.event_id: e for e in events}
    for rule in sorted({a.rule_id for a in result[1]}):
        ids = {eid for a in result[1] if a.rule_id == rule for eid in a.event_ids}
        coverage[rule] = {"evidence_events": len(ids), "last_three_query_labels": dict(Counter(
            ".".join((byid[eid].metadata["zeek"].get("query") or "").split(".")[-3:]) for eid in ids))}
    report["scenarios"]["rita"] = {"scope": "first 3600 seconds from first conn record", "anchor_epoch": anchor,
        "inventory": inventory, "events": len(events), "baseline_alerts_by_rule": dict(Counter(a.rule_id for a in baseline)),
        "final_alerts_by_rule": dict(Counter(a.rule_id for a in result[1])), "coverage": coverage,
        "labels": "No independent per-flow truth; fixture smoke test only, no precision/recall claimed.",
        **validate_and_write(result, rita / "result")}
    (base / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print("rita", json.dumps(report["scenarios"]["rita"], ensure_ascii=False), flush=True)
    print("Report:", base / "report.json", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "correlation/output/public_validation")
    parser.add_argument("--stix", type=Path, required=True)
    args = parser.parse_args()
    run(args.data_dir, args.stix)
