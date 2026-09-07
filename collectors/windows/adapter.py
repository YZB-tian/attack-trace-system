from typing import Iterable, Dict, Any, List
from common.models import NormalizedEvent

def normalize_windows_records(records: Iterable[Dict[str, Any]], task_id: str) -> List[NormalizedEvent]:
    """
    TODO: 组员实现真实 Windows 日志解析。
    必须返回 list[NormalizedEvent]，禁止返回自定义跨模块结构。
    """
    return []
