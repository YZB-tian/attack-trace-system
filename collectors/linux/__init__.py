"""Linux 日志采集/分析模块。

跨模块输出统一为 common.models.NormalizedEvent。
"""
from .adapter import normalize_linux_records

__all__ = ["normalize_linux_records"]
