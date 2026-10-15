"""Deterministic, explainable risk scoring for defensive event triage.

This engine only scores evidence; it never bans or kicks users automatically.
"""
from dataclasses import dataclass, field
from time import monotonic
from collections import defaultdict, deque

@dataclass
class RiskResult:
    score: int
    level: str
    reasons: list[str] = field(default_factory=list)

class RiskEngine:
    def __init__(self, window_seconds: int = 30):
        self.window_seconds = max(5, min(int(window_seconds), 300))
        self.events = defaultdict(deque)

    def score(self, guild_id: int, actor_id: int, event: str, *, trusted: bool = False,
              account_age_days: int | None = None, burst_weight: int = 1) -> RiskResult:
        if trusted:
            return RiskResult(0, "TRUSTED", ["trusted exemption"])
        now = monotonic()
        key = (int(guild_id), int(actor_id), str(event))
        q = self.events[key]
        q.append((now, max(1, min(int(burst_weight), 10))))
        while q and now - q[0][0] > self.window_seconds:
            q.popleft()
        score = min(60, sum(weight * 10 for _, weight in q))
        reasons = [f"{event} burst: {len(q)} event(s) in {self.window_seconds}s"]
        if account_age_days is not None and account_age_days < 7:
            score += 20
            reasons.append("account younger than 7 days (signal only)")
        score = min(score, 100)
        level = "LOW" if score < 20 else "GUARDED" if score < 40 else "HIGH" if score < 70 else "CRITICAL"
        return RiskResult(score, level, reasons)
