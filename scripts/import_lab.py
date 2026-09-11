"""Verify and normalize local lab evidence. Never modifies the source bundle."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from collectors.lab import import_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("runtime/lab"))
    args = parser.parse_args()
    source, output = args.evidence_dir.resolve(), args.output.resolve()
    if output == source or source in output.parents:
        parser.error("output must be outside the immutable evidence directory")
    events, report = import_bundle(source)
    output.mkdir(parents=True, exist_ok=True)
    (output / "normalized_events.json").write_text(json.dumps([e.model_dump(mode="json") for e in events], ensure_ascii=False), encoding="utf-8")
    (output / "import-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
