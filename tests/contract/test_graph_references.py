from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[2]

def load(name):
    return json.loads((ROOT / "testdata" / name).read_text(encoding="utf-8"))

def test_graph_edges_reference_existing_nodes():
    graph = load("attack_graph.json")
    node_ids = {n["id"] for n in graph["nodes"]}
    for edge in graph["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids

def test_graph_evidence_references_mock_data():
    graph = load("attack_graph.json")
    event_ids = {e["event_id"] for e in load("normalized_events.json")}
    alert_ids = {a["alert_id"] for a in load("alerts.json")}
    for edge in graph["edges"]:
        assert set(edge["evidence_event_ids"]).issubset(event_ids)
        assert set(edge["evidence_alert_ids"]).issubset(alert_ids)
