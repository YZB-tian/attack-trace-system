from pathlib import Path
import json
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]

PAIRS = [
    ("schemas/normalized_event.schema.json", "testdata/normalized_events.json", True),
    ("schemas/alert.schema.json", "testdata/alerts.json", True),
    ("schemas/attack_graph.schema.json", "testdata/attack_graph.json", False),
    ("schemas/trace_result.schema.json", "testdata/trace_result.json", False),
    ("schemas/task_status.schema.json", "testdata/task_status.json", False),
]

def main():
    failed = False
    for schema_rel, data_rel, is_list in PAIRS:
        schema = json.loads((ROOT / schema_rel).read_text(encoding="utf-8"))
        data = json.loads((ROOT / data_rel).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        items = data if is_list else [data]
        for i, item in enumerate(items):
            errors = sorted(validator.iter_errors(item), key=lambda e: list(e.path))
            if errors:
                failed = True
                print(f"[FAIL] {data_rel} item={i}")
                for err in errors:
                    print("  -", "/".join(map(str, err.path)), err.message)
            else:
                print(f"[OK] {data_rel} item={i}")

    if failed:
        raise SystemExit(1)
    print("\nAll contract examples are valid.")

if __name__ == "__main__":
    main()
