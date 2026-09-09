"""Explicit opt-in Sigma subset, not a full Sigma engine. Unsupported rules fail."""
from __future__ import annotations
import fnmatch
import json
import re
from pathlib import Path
from common.enums import Severity
from .network_rules import make_alert


class SigmaRule:
    def __init__(self, path):
        import yaml  # Optional dependency, only needed for selected YAML rules.
        self.path = Path(path)
        self.rule = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self.detection = self.rule["detection"]
        self.condition = self.detection["condition"]
        self.selectors = {k: v for k, v in self.detection.items() if k != "condition"}
        source = self.rule.get("logsource", {})
        if source.get("category") not in (None, "process_creation", "file_event", "network_connection") or source.get("service"):
            raise ValueError(f"{self.path}: unsupported Sigma logsource: {source}")
        assets = json.loads((Path(__file__).resolve().parents[1] / "config/assets.json").read_text(encoding="utf-8"))["assets"]
        self.asset_os = {a["host_id"]: a.get("os") for a in assets}
        self._validate_selectors(self.selectors.values())
        self._condition({k: False for k in self.selectors})

    def _validate_selectors(self, selectors):
        for selector in selectors:
            if isinstance(selector, list):
                self._validate_selectors(selector)
                continue
            if not isinstance(selector, dict):
                raise ValueError(f"{self.path}: keyword selectors are unsupported")
            for field, value in selector.items():
                choices = value if isinstance(value, list) else [value]
                if any(isinstance(v, (dict, list)) for v in choices):
                    raise ValueError(f"{self.path}: unsupported nested selector value")
                mods = field.split("|")[1:]
                if set(mods) - {"contains", "startswith", "endswith", "all"}:
                    raise ValueError(f"{self.path}: unsupported modifier in {field}")
                if len(set(mods) & {"contains", "startswith", "endswith"}) > 1:
                    raise ValueError(f"{self.path}: incompatible modifiers")

    def _condition(self, values):
        if not isinstance(self.condition, str): raise ValueError("only one Sigma condition is supported")
        tokens = re.findall(r"\(|\)|[^\s()]+", self.condition)
        pos = 0

        def atom():
            nonlocal pos
            if pos >= len(tokens): raise ValueError("incomplete Sigma condition")
            token = tokens[pos]; pos += 1
            if token == "not": return not atom()
            if token == "(":
                value = expression()
                if pos >= len(tokens) or tokens[pos] != ")": raise ValueError("unclosed Sigma condition")
                pos += 1
                return value
            if token in ("1", "all"):
                if pos + 1 >= len(tokens) or tokens[pos] != "of": raise ValueError("unsupported Sigma quantifier")
                pattern = tokens[pos + 1]; pos += 2
                keys = list(values) if pattern == "them" else [k for k in values if fnmatch.fnmatchcase(k, pattern)]
                if not keys: raise ValueError(f"Sigma condition matches no selectors: {pattern}")
                return (any if token == "1" else all)(values[k] for k in keys)
            if token not in values: raise ValueError(f"unsupported Sigma condition token: {token}")
            return values[token]

        def conjunction():
            nonlocal pos
            value = atom()
            while pos < len(tokens) and tokens[pos] == "and":
                pos += 1
                right = atom()
                value = value and right
            return value

        def expression():
            nonlocal pos
            value = conjunction()
            while pos < len(tokens) and tokens[pos] == "or":
                pos += 1
                right = conjunction()
                value = value or right
            return value

        value = expression()
        if pos != len(tokens): raise ValueError(f"unsupported Sigma syntax: {tokens[pos:]}")
        return value

    def _selector(self, selector, record):
        if isinstance(selector, list): return any(self._selector(s, record) for s in selector)
        for field, expected in selector.items():
            key, *mods = field.split("|")
            actual = record.get(key)
            choices = expected if isinstance(expected, list) else [expected]

            def match(choice):
                if choice is None: return actual is None
                if actual is None: return False
                text, pattern = str(actual).casefold(), str(choice).casefold()
                if "contains" in mods: pattern = "*" + pattern + "*"
                if "startswith" in mods: pattern += "*"
                if "endswith" in mods: pattern = "*" + pattern
                return fnmatch.fnmatchcase(text, pattern)

            if not (all if "all" in mods else any)(match(x) for x in choices): return False
        return True

    def match(self, event, knowledge):
        source = self.rule.get("logsource", {})
        raw = dict(event.raw_event) if isinstance(event.raw_event, dict) else {}
        product = event.metadata.get("os") or self.asset_os.get(event.host_id)
        if not product:
            identity = (event.source + " " + str(raw.get("Provider", ""))).lower()
            if "linux" in identity: product = "linux"
            elif "windows" in identity or "windows" in event.labels: product = "windows"
        if source.get("product") and source["product"] != product: return []
        if source.get("category") not in (None, "process_creation", "file_event", "network_connection"):
            raise ValueError(f"unsupported Sigma logsource: {source}")
        category_action = {"process_creation": {"process_create"}, "file_event": {"file_create", "file_write"},
                           "network_connection": {"network_connect"}}
        if source.get("category") and event.action not in category_action[source["category"]]: return []
        if source.get("service"):
            raise ValueError("service-specific Sigma rules require a source adapter")
        if event.process:
            raw.setdefault("Image", event.process.path or event.process.name)
            raw.setdefault("ProcessId", event.process.pid)
        if not self._condition({k: self._selector(v, raw) for k, v in self.selectors.items()}): return []
        techniques = sorted({tag[7:].upper() for tag in self.rule.get("tags", [])
                             if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", tag)})
        result = []
        for tech in techniques or [None]:
            aid = "SIGMA-" + self.rule["id"] + ("-" + tech if tech else "")
            alert = make_alert([event], aid, self.rule["title"], .7,
                {"sigma_rule_id": self.rule["id"], "rule_file": str(self.path), "condition": self.condition}, knowledge, tech)
            alert.detector = "sigma_subset_v1"
            level = self.rule.get("level", "medium")
            alert.severity = Severity({"informational": "info"}.get(level, level))
            if knowledge and tech:
                info = knowledge.lookup(tech)
                tags = {t[7:] for t in self.rule.get("tags", []) if t.startswith("attack.")}
                preferred = next((t for t in info["tactics"] if t in tags), None) if info else None
                alert.mitre = knowledge.mapping(tech, preferred)
            result.append(alert)
        return result
