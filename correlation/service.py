from typing import Iterable
from common.models import NormalizedEvent, Alert, AttackGraph

def build_attack_graph(
    task_id: str,
    events: Iterable[NormalizedEvent],
    alerts: Iterable[Alert],
) -> AttackGraph:
    raise NotImplementedError("TODO: correlation module implements this function")
