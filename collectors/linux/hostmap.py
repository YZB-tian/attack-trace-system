"""hostname -> host_id 映射，统一从 config/assets.json 读取。

规则（AGENTS.md）：靶场主机 ID 只能从 config/assets.json 读取，
本模块不在代码里自行写死 IP/主机名映射。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

# config/assets.json 位于仓库根目录：collectors/linux -> 上三级
_ASSETS_PATH = Path(__file__).resolve().parents[2] / "config" / "assets.json"


def _load_assets() -> Dict[str, Any]:
    """Read the asset table, re-reading it when the file changes.

    A plain cache would keep serving stale hosts after ``config/assets.json`` is
    edited, so the cache key is the file's mtime and size.
    """
    global _cache
    try:
        stat = _ASSETS_PATH.stat()
    except FileNotFoundError:
        _cache = None
        raise
    stamp = (stat.st_mtime_ns, stat.st_size)
    if _cache is None or _cache[0] != stamp:
        with open(_ASSETS_PATH, encoding="utf-8") as fh:
            _cache = (stamp, json.load(fh))
    return _cache[1]


_cache: Optional[tuple[tuple[int, int], Dict[str, Any]]] = None


def hostname_to_host_id(hostname: Optional[str]) -> Optional[str]:
    """按 hostname 反查 assets.json 中的 host_id；未命中返回 None。"""
    if not hostname:
        return None
    for asset in _load_assets().get("assets", []):
        if hostname.lower() in {str(asset.get("hostname", "")).lower(), str(asset.get("host_id", "")).lower()}:
            return asset.get("host_id")
    return None
