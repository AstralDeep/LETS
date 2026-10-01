from __future__ import annotations

from datetime import datetime, timezone

VALID_DEADLINE_MOCK = {
    "deadline_at": datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc).isoformat()
}
