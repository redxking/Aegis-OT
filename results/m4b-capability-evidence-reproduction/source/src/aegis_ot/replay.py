"""Thread-safe nonce replay protection."""

from __future__ import annotations

from datetime import datetime, timedelta
from threading import Lock


class ReplayLedger:
    def __init__(self, retention: timedelta = timedelta(hours=1)) -> None:
        self._retention = retention
        self._seen: dict[str, datetime] = {}
        self._lock = Lock()

    def reserve(self, nonce: str, now: datetime) -> bool:
        with self._lock:
            cutoff = now - self._retention
            self._seen = {
                value: seen_at for value, seen_at in self._seen.items() if seen_at >= cutoff
            }
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True

    def contains(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._seen
