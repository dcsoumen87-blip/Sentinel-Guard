"""Security event risk assessment for Sentinel Guard."""

from collections import defaultdict, deque
from time import monotonic


class RiskEngine:
    """Track repeated security events and calculate risk levels."""

    def __init__(self, window_seconds: int = 10):
        self.window_seconds = max(1, window_seconds)
        self._events = defaultdict(deque)

    def record_event(
        self,
        guild_id: int,
        actor_id: int,
        action: str,
    ) -> dict:
        """Record an event and return its risk assessment."""

        now = monotonic()
        key = (guild_id, actor_id, action)
        events = self._events[key]

        while events and now - events[0] > self.window_seconds:
            events.popleft()

        events.append(now)
        count = len(events)

        if count >= 6:
            level = "critical"
        elif count >= 4:
            level = "high"
        elif count >= 2:
            level = "medium"
        else:
            level = "low"

        return {
            "guild_id": guild_id,
            "actor_id": actor_id,
            "action": action,
            "event_count": count,
            "risk_level": level,
            "window_seconds": self.window_seconds,
        }

    def clear_actor(self, guild_id: int, actor_id: int) -> None:
        """Clear tracked events for an actor in one server."""

        keys = [
            key
            for key in self._events
            if key[0] == guild_id and key[1] == actor_id
        ]

        for key in keys:
            del self._events[key]
