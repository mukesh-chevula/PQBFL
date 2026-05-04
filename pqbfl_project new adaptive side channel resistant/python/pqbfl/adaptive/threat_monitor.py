"""
Threat Monitor for Adaptive Ratcheting in PQBFL.

Tracks real-time security signals and computes a composite threat level
that drives the adaptive ratcheting policy.  Each event has a type and
severity (0.0–1.0).  The threat level is the weighted average of recent
events within a configurable sliding time window — older events decay
automatically so the system recovers after transient anomalies.

Tracked signal categories:
  - sig_verification_failed   — potential MITM or impersonation
  - hash_mismatch             — pubkey/model hash tampering attempt
  - reputation_drop           — blockchain-reported client misbehaviour
  - timing_anomaly            — suspicious round-trip time deviation
  - stale_ratchet             — too many rounds without asymmetric ratchet

This module is fully deterministic (no randomness) and side-channel
safe — it does not branch on secret material.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ThreatEventType(str, Enum):
    """Categories of security-relevant events."""

    SIG_VERIFICATION_FAILED = "sig_verification_failed"
    HASH_MISMATCH = "hash_mismatch"
    REPUTATION_DROP = "reputation_drop"
    TIMING_ANOMALY = "timing_anomaly"
    STALE_RATCHET = "stale_ratchet"


# Default severity weights per event type (how much each type
# influences the overall threat level).
_DEFAULT_WEIGHTS: dict[ThreatEventType, float] = {
    ThreatEventType.SIG_VERIFICATION_FAILED: 1.0,   # most critical
    ThreatEventType.HASH_MISMATCH: 0.9,
    ThreatEventType.REPUTATION_DROP: 0.6,
    ThreatEventType.TIMING_ANOMALY: 0.4,
    ThreatEventType.STALE_RATCHET: 0.3,
}


@dataclass(frozen=True)
class ThreatEvent:
    """A single recorded security event."""

    event_type: ThreatEventType
    severity: float          # 0.0–1.0 (caller-supplied intensity)
    timestamp: float         # time.time() epoch
    round_num: int = -1      # FL round when the event occurred
    detail: str = ""         # human-readable description


@dataclass
class ThreatMonitor:
    """Collects security signals and computes a composite threat level.

    Parameters
    ----------
    window_seconds : float
        Sliding time window — only events within this many seconds of
        *now* contribute to the threat level.  Default 300 s (5 min).
    decay_half_life : float
        Half-life in seconds for exponential decay.  An event at exactly
        ``decay_half_life`` seconds ago contributes 50 % of its original
        weight.  Default 120 s (2 min).
    weights : dict
        Per-event-type multiplier.  If ``None``, uses ``_DEFAULT_WEIGHTS``.
    """

    window_seconds: float = 300.0
    decay_half_life: float = 120.0
    weights: dict[ThreatEventType, float] = field(default_factory=lambda: dict(_DEFAULT_WEIGHTS))
    _events: list[ThreatEvent] = field(default_factory=list, repr=False)

    # ── recording ────────────────────────────────────────────────

    def record_event(
        self,
        event_type: ThreatEventType | str,
        severity: float = 0.5,
        *,
        round_num: int = -1,
        detail: str = "",
        timestamp: Optional[float] = None,
    ) -> ThreatEvent:
        """Record a new security event.

        Parameters
        ----------
        event_type : ThreatEventType or str
            Category of the event.
        severity : float
            Intensity (0.0 = benign, 1.0 = maximum threat).
        round_num : int
            FL round during which the event occurred.
        detail : str
            Optional human-readable note.
        timestamp : float or None
            Override the event timestamp (defaults to ``time.time()``).

        Returns
        -------
        ThreatEvent
            The recorded event instance.
        """
        if isinstance(event_type, str):
            event_type = ThreatEventType(event_type)
        severity = max(0.0, min(1.0, severity))
        ts = timestamp if timestamp is not None else time.time()
        ev = ThreatEvent(
            event_type=event_type,
            severity=severity,
            timestamp=ts,
            round_num=round_num,
            detail=detail,
        )
        self._events.append(ev)
        return ev

    # ── query ────────────────────────────────────────────────────

    def get_threat_level(self, *, now: Optional[float] = None) -> float:
        """Compute the current composite threat level in [0.0, 1.0].

        The level is the weighted, decay-adjusted average of recent events.
        If no events have been recorded (or all have decayed), returns 0.0.
        """
        now = now if now is not None else time.time()
        cutoff = now - self.window_seconds

        total_weight = 0.0
        total_score = 0.0

        for ev in self._events:
            if ev.timestamp < cutoff:
                continue
            age = now - ev.timestamp
            # Exponential decay: weight = 2^(-age / half_life)
            decay = 2.0 ** (-age / self.decay_half_life) if self.decay_half_life > 0 else 1.0
            type_weight = self.weights.get(ev.event_type, 0.5)
            w = decay * type_weight
            total_weight += w
            total_score += w * ev.severity

        if total_weight <= 0:
            return 0.0

        raw = total_score / total_weight
        return max(0.0, min(1.0, raw))

    def get_recent_events(
        self,
        *,
        limit: int = 50,
        now: Optional[float] = None,
    ) -> list[ThreatEvent]:
        """Return the most recent events within the sliding window."""
        now = now if now is not None else time.time()
        cutoff = now - self.window_seconds
        recent = [ev for ev in self._events if ev.timestamp >= cutoff]
        return recent[-limit:]

    def get_event_log(self) -> list[dict]:
        """Return all events as serialisable dicts (for UI / JSON)."""
        return [
            {
                "event_type": ev.event_type.value,
                "severity": round(ev.severity, 3),
                "timestamp": ev.timestamp,
                "round": ev.round_num,
                "detail": ev.detail,
            }
            for ev in self._events
        ]

    def get_event_count(self) -> int:
        """Total number of events ever recorded."""
        return len(self._events)

    def reset(self) -> None:
        """Clear all recorded events."""
        self._events.clear()
