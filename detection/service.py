from typing import Iterable, List
from common.models import NormalizedEvent, Alert

def detect(events: Iterable[NormalizedEvent]) -> List[Alert]:
    """Preserve the published entry point; optional knowledge configured by environment."""
    import os
    from .attack_stix import AttackKnowledge
    from .network_rules import detect_network
    path = os.environ.get("ATTACK_STIX_PATH")
    return detect_network(list(events), knowledge=AttackKnowledge(path) if path else None)
