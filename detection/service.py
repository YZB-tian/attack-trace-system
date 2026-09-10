from typing import Iterable, List
from common.models import NormalizedEvent, Alert

def detect(events: Iterable[NormalizedEvent]) -> List[Alert]:
    """Preserve the published entry point; optional knowledge configured by environment."""
    import os
    from .attack_stix import AttackKnowledge
    from .network_rules import detect_network
    from .host_rules import detect_host
    path = os.environ.get("ATTACK_STIX_PATH")
    knowledge = AttackKnowledge(path) if path else None
    events = list(events)
    return detect_network(events, knowledge=knowledge) + detect_host(events, knowledge)
