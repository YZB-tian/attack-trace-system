"""hostname -> host_id 映射，统一从 config/assets.json 读取。

规则（AGENTS.md）：靶场主机 ID 只能从 config/assets.json 读取，
本模块不在代码里自行写死 IP/主机名映射。
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

# config/assets.json 位于仓库根目录：collectors/linux -> 上三级
_ASSETS_PATH = Path(__file__).resolve().parents[2] / "config" / "assets.json"


@lru_cache(maxsize=1)
def _load_assets() -> Dict[str, Any]:
    with open(_ASSETS_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def hostname_to_host_id(hostname: Optional[str]) -> Optional[str]:
    """按 hostname 反查 assets.json 中的 host_id；未命中返回 None。"""
    if not hostname:
        return None
    for asset in _load_assets().get("assets", []):
        if hostname.lower() in {str(asset.get("hostname", "")).lower(), str(asset.get("host_id", "")).lower()}:
            return asset.get("host_id")
    return None
