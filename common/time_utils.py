from datetime import datetime, timezone

def now_iso() -> str:
    """Return timezone-aware ISO 8601 UTC time."""
    return datetime.now(timezone.utc).isoformat()
