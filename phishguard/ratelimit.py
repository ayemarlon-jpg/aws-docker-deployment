"""Limits on AI analysis, so a public deployment can't run up an unbounded Claude bill.

Rule-based checks are free and never limited. When a limit is hit, the request still
gets a verdict, just without the AI part (llm_status = "limited: ...").

State is in memory per process: good enough for a single small container. Limits are
approximate across multiple uvicorn workers (each worker counts separately).
"""

from __future__ import annotations

import threading
import time
from collections import deque


class AIUsageLimiter:
    def __init__(self, per_ip_per_hour: int, per_day: int) -> None:
        self.per_ip_per_hour = per_ip_per_hour
        self.per_day = per_day
        self._lock = threading.Lock()
        self._by_ip: dict[str, deque[float]] = {}
        self._day: deque[float] = deque()

    def allow(self, client_id: str | None, now: float | None = None) -> str | None:
        """Record one AI call. Return None if allowed, or the reason it was refused."""
        now = time.time() if now is None else now
        with self._lock:
            while self._day and now - self._day[0] > 86400:
                self._day.popleft()
            if self.per_day > 0 and len(self._day) >= self.per_day:
                return "limited: daily AI quota reached"

            key = client_id or "unknown"
            hits = self._by_ip.setdefault(key, deque())
            while hits and now - hits[0] > 3600:
                hits.popleft()
            if self.per_ip_per_hour > 0 and len(hits) >= self.per_ip_per_hour:
                return "limited: hourly AI checks used up, try again later"

            hits.append(now)
            self._day.append(now)
            if len(self._by_ip) > 10000:  # drop idle clients so memory stays bounded
                for k in [k for k, v in self._by_ip.items() if not v or now - v[-1] > 3600]:
                    del self._by_ip[k]
            return None
