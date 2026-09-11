"""Run the deterministic attribution pipeline over an analysed task.

Input: the outputs of a previous analysis (normalized events, alerts, graph).
Output: the attacker-attribution TraceResult produced by the agents module,
including tool fingerprints, C2 infrastructure correlation and APT TTP
similarity. Deterministic only; no model call is made here.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.service import analyze_trace  # noqa: E402
from common.models import Alert, AttackGraph, NormalizedEvent  # noqa: E402


def load(path: Path, model, many=True):
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    items = data if isinstance(data, list) and many else [data]
    return [model.model_validate(x) for x in items]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--analysis-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    events = load(args.analysis_dir / "normalized_events.json", NormalizedEvent)
    alerts = load(args.analysis_dir / "alerts.json", Alert)
    graph = AttackGraph.model_validate(json.loads(
        (args.analysis_dir / "attack_graph.json").read_text(encoding="utf-8-sig")))
    result = analyze_trace(graph, alerts, events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2),
                           encoding="utf-8")
    attribution = result.attribution
    print(json.dumps({
        "output": str(args.output),
        "summary": result.summary,
        "initial_access_entity_id": result.initial_access_entity_id,
        "c2_entities": result.suspected_c2_entity_ids,
        "attribution_keys": sorted(attribution.keys()) if isinstance(attribution, dict)
                            else sorted(attribution.__fields__.keys()),
    }, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
