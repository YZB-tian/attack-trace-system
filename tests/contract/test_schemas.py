from pathlib import Path
import json
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]

CASES = [
    ("normalized_event.schema.json", "normalized_events.json", True),
    ("alert.schema.json", "alerts.json", True),
    ("attack_graph.schema.json", "attack_graph.json", False),
    ("trace_result.schema.json", "trace_result.json", False),
    ("task_status.schema.json", "task_status.json", False),
]

def test_mock_data_against_json_schemas():
    for schema_name, data_name, is_list in CASES:
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        data = json.loads((ROOT / "testdata" / data_name).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        items = data if is_list else [data]
        for item in items:
            errors = list(validator.iter_errors(item))
            assert not errors, f"{data_name}: {[e.message for e in errors]}"
