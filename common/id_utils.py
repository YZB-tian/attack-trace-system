from uuid import uuid4

PREFIXES = {
    "task": "task",
    "event": "evt",
    "alert": "alert",
    "graph": "graph",
    "trace": "trace",
    "edge": "edge",
}

def new_id(kind: str) -> str:
    if kind not in PREFIXES:
        raise ValueError(f"unsupported id kind: {kind}")
    return f"{PREFIXES[kind]}_{uuid4().hex[:12]}"
