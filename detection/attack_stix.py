"""Small read-only index over an official ATT&CK STIX bundle, with no copied KB."""
from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path
from common.models import MitreMapping


def external_id(obj):
    return next((r["external_id"] for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack" and "external_id" in r), None)


class AttackKnowledge:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        bundle = json.loads(self.path.read_text(encoding="utf-8"))
        if bundle.get("type") != "bundle":
            raise ValueError("expected an official STIX bundle")
        # Multiple versions can exist; retain the most recent active version per STIX ID.
        latest = {}
        for obj in bundle["objects"]:
            if obj.get("modified", "") >= latest.get(obj["id"], {}).get("modified", ""):
                latest[obj["id"]] = obj
        self.objects = {k: o for k, o in latest.items() if not o.get("revoked") and not o.get("x_mitre_deprecated")}
        self.techniques = {external_id(o): o for o in self.objects.values()
                           if o["type"] == "attack-pattern" and external_id(o)}
        self.groups = {o["id"]: o for o in self.objects.values() if o["type"] == "intrusion-set"}
        self.links = defaultdict(set)
        for obj in self.objects.values():
            if obj["type"] == "relationship" and obj["source_ref"] in self.objects and obj["target_ref"] in self.objects:
                self.links[(obj["source_ref"], obj["relationship_type"])].add(obj["target_ref"])

    def lookup(self, technique_id):
        obj = self.techniques.get(technique_id)
        if not obj: return None
        related = [o for o in self.objects.values() if obj["id"] in self.links.get((o["id"], "uses"), set())]
        return {
            "technique_id": technique_id, "name": obj["name"], "description": obj.get("description", ""),
            "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"],
            "parent_ids": sorted(external_id(self.objects[p]) for p in self.links.get((obj["id"], "subtechnique-of"), set())
                                 if external_id(self.objects[p])),
            "groups": sorted(external_id(o) for o in related if o["type"] == "intrusion-set" and external_id(o)),
            "software": sorted(external_id(o) for o in related if o["type"] in ("tool", "malware") and external_id(o)),
        }

    def mapping(self, technique_id, preferred_tactic=None):
        info = self.lookup(technique_id)
        if not info or not info["tactics"]: return None
        tactic = preferred_tactic if preferred_tactic in info["tactics"] else info["tactics"][0]
        return MitreMapping(tactic=tactic, technique_id=technique_id.split(".")[0],
                            subtechnique_id=technique_id if "." in technique_id else None,
                            technique_name=info["name"])

    def group_techniques(self, group_id):
        return {external_id(self.objects[t]) for t in self.links.get((group_id, "uses"), set())
                if self.objects[t]["type"] == "attack-pattern" and external_id(self.objects[t])}

    def similarity(self, technique_ids, limit=5):
        observed = set(technique_ids) & self.techniques.keys()
        if not observed: return []
        results = []
        for stix_id, group in self.groups.items():
            known = self.group_techniques(stix_id)
            overlap = observed & known
            if overlap:
                results.append({"group_id": external_id(group), "group_name": group["name"],
                    "similarity": len(overlap) / len(observed | known), "metric": "jaccard_exact_technique_ids",
                    "matched_techniques": sorted(overlap), "observed_count": len(observed),
                    "group_technique_count": len(known),
                    "interpretation": "TTP similarity only; not confirmed attribution"})
        return sorted(results, key=lambda x: (-x["similarity"], x["group_id"] or ""))[:limit]
