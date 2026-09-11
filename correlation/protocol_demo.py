"""Small explicitly synthetic HTTP/ICMP handoff examples; not real capture validation."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import math
from collections import Counter
from pathlib import Path

from collectors.network.adapter import load_zeek_logs
from detection.attack_stix import AttackKnowledge
from .pipeline import analyze
from .validate_public_data import validate_and_write


def examples():
    cases = {}
    for name, kind, expected in (("http_uri", "http", "NET-HTTP-COVERT"),
            ("http_body", "http", "NET-HTTP-COVERT"), ("http_fixed_token", "http", None),
            ("icmp_payload", "icmp_payload", "NET-ICMP-TUNNEL"), ("icmp_ping", "icmp_payload", None)):
        records = []
        for n in range(10):
            body = hashlib.shake_256(f"{name}-{n}".encode()).digest(512)
            record = {"ts": 1788825600 + n * 60, "uid": f"SYNTHETIC-{name}-{n}",
                "id.orig_h": "10.10.2.10", "id.resp_h": "10.10.0.20", "id.orig_p": 45000 + n,
                "id.resp_p": 80, "proto": "tcp", "synthetic": True}
            if kind == "http":
                token = base64.urlsafe_b64encode(body[:240]).decode()
                if name == "http_fixed_token": token = base64.urlsafe_b64encode(hashlib.shake_256(b"constant").digest(240)).decode()
                record.update(method="GET", host="synthetic.example", uri="/api?data=" + token,
                              request_body_len=0, response_body_len=32)
                if name == "http_body":
                    record.update(method="POST", uri="/api", request_body_len=512, ats_body_sample_len=512,
                        ats_body_entropy=-sum((k / len(body)) * math.log2(k / len(body)) for k in Counter(body).values()),
                        ats_body_sha256=hashlib.sha256(body).hexdigest())
            else:
                if name == "icmp_ping": body = n.to_bytes(8, "little") + b"a" * 504
                record.update(proto="icmp", is_orig=True, icmp_type=8, icmp_code=0,
                    echo_id=123, echo_seq=n, payload_len=len(body), payload_sample_len=len(body),
                    payload_entropy=-sum((k / len(body)) * math.log2(k / len(body)) for k in Counter(body).values()),
                    payload_sha256=hashlib.sha256(body).hexdigest())
                record["id.orig_p"], record["id.resp_p"] = 8, 0
            records.append(record)
        cases[name] = (kind, records, expected)
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("correlation/output/protocol_demo"))
    args = parser.parse_args()
    knowledge = AttackKnowledge(args.stix)
    report = {"synthetic": True, "real_capture_validation": False, "cases": {}}
    for name, (kind, records, expected) in examples().items():
        directory = args.output / name / "input"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{kind}.log").write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
        task = "task_protocol_" + name
        result = analyze(task, load_zeek_logs(directory, task), knowledge=knowledge)
        actual = sorted({a.rule_id for a in result[1]})
        expected_rules = [expected] if expected else []
        checks = validate_and_write(result, args.output / name / "result")
        if actual != expected_rules: raise AssertionError(f"{name}: expected {expected_rules}, got {actual}")
        report["cases"][name] = {"events": len(result[0]), "alert_rules": actual,
            "alert_count": len(result[1]), "expected_rules": expected_rules, **checks}
    (args.output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.output / "PROVENANCE.txt").write_text("50 SYNTHETIC events. Not a capture or public dataset.\n"
        "Payload metrics are computed from synthetic bytes, not from Zeek execution.\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
