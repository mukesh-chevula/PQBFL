"""
adaptive/threat_engine.py
ThreatEngine for Kappala et al. (2026) — Dynamic Quantum-Resistant Selective Encryption.

This is the CORE CONTRIBUTION of the paper: a lightweight threat-scoring engine
that runs on resource-constrained agricultural sensor nodes and derives a
normalized threat level θ ∈ [0, 1] from local and network observations.

Design (§III of the paper):
  θ(t) = Σ_i  w_i · e^{-λ(t - t_i)}

Where:
  • Each security event e_i has weight w_i and timestamp t_i
  • λ is an exponential decay constant (forgetting factor)
  • The sum is bounded to [0, 1] via tanh normalization

Event types modelled:
  1. REPLAY_ATTEMPT      w=0.40  — replayed/duplicate packet ID detected
  2. CHANNEL_ANOMALY     w=0.30  — RF channel statistics deviate from baseline
  3. TIMING_JITTER       w=0.20  — packet arrival jitter exceeds threshold
  4. AUTH_FAILURE        w=0.25  — gateway authentication failure
  5. PHYSICAL_TAMPER     w=0.80  — accelerometer / tamper-switch triggered
  6. POWER_SPIKE         w=0.15  — supply voltage anomaly (side-channel hint)

Relation to JOURNAL-3 (Adaptive PQBFL):
  JOURNAL-3's ThreatMonitor uses the same exponential-decay weighting but
  reads events from BLOCKCHAIN telemetry (hash mismatches, sig failures)
  rather than local sensor observations — and drives ratchet-window L_j
  rather than per-packet encryption-mode selection.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Tuple


class EventType(Enum):
    REPLAY_ATTEMPT  = auto()
    CHANNEL_ANOMALY = auto()
    TIMING_JITTER   = auto()
    AUTH_FAILURE    = auto()
    PHYSICAL_TAMPER = auto()
    POWER_SPIKE     = auto()
    CUSTOM          = auto()


# Base weights per event type (from Kappala et al. Table II)
EVENT_WEIGHTS: dict[EventType, float] = {
    EventType.REPLAY_ATTEMPT:  0.40,
    EventType.CHANNEL_ANOMALY: 0.30,
    EventType.TIMING_JITTER:   0.20,
    EventType.AUTH_FAILURE:    0.25,
    EventType.PHYSICAL_TAMPER: 0.80,
    EventType.POWER_SPIKE:     0.15,
    EventType.CUSTOM:          0.10,
}

DECAY_LAMBDA: float = 0.15   # forgetting factor λ (per second)
MAX_EVENT_HISTORY: int = 64  # ring buffer size


@dataclass
class ThreatEvent:
    event_type: EventType
    timestamp:  float          # time.time()
    weight:     float = 0.0
    sensor_id:  int   = -1
    detail:     str   = ""

    def __post_init__(self):
        if self.weight == 0.0:
            self.weight = EVENT_WEIGHTS.get(self.event_type, 0.10)


class ThreatEngine:
    """
    Lightweight threat-score engine for a single sensor node.

    Computes θ(t) = tanh( Σ_i w_i · e^{-λ(t - t_i)} )

    This normalises the raw weighted sum into [0, 1] so that
    the SelectiveEncryptionPolicy can use simple threshold comparisons.
    """

    def __init__(
        self,
        decay_lambda: float = DECAY_LAMBDA,
        max_history:  int   = MAX_EVENT_HISTORY,
    ):
        self._lambda    = decay_lambda
        self._history:  List[ThreatEvent] = []
        self._max_hist  = max_history
        self._last_theta: float = 0.0

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def record_event(
        self,
        event_type: EventType,
        weight:     float | None = None,
        sensor_id:  int   = -1,
        detail:     str   = "",
        timestamp:  float | None = None,
    ) -> float:
        """
        Ingest a security event and return the updated θ immediately.
        """
        ts = timestamp if timestamp is not None else time.time()
        w  = weight if weight is not None else EVENT_WEIGHTS.get(event_type, 0.10)
        ev = ThreatEvent(event_type=event_type, timestamp=ts,
                         weight=w, sensor_id=sensor_id, detail=detail)

        self._history.append(ev)
        if len(self._history) > self._max_hist:
            self._history.pop(0)

        return self.theta()

    # ------------------------------------------------------------------
    # Score computation
    # ------------------------------------------------------------------

    def theta(self, now: float | None = None) -> float:
        """
        Compute current normalized threat score θ ∈ [0, 1].

        θ(t) = tanh( Σ_i  w_i · exp(-λ · (t - t_i)) )
        """
        if not self._history:
            self._last_theta = 0.0
            return 0.0

        t = now if now is not None else time.time()
        raw = sum(
            ev.weight * math.exp(-self._lambda * max(0.0, t - ev.timestamp))
            for ev in self._history
        )
        self._last_theta = math.tanh(raw)
        return self._last_theta

    def decay_all(self, seconds: float) -> float:
        """Simulate time passage — useful in discrete-step simulations."""
        for ev in self._history:
            ev.timestamp -= seconds          # shift timestamps back
        return self.theta()

    def reset(self) -> None:
        self._history.clear()
        self._last_theta = 0.0

    @property
    def last_theta(self) -> float:
        return self._last_theta

    @property
    def event_count(self) -> int:
        return len(self._history)

    def snapshot(self) -> dict:
        return {
            "theta":        round(self._last_theta, 6),
            "event_count":  len(self._history),
            "decay_lambda": self._lambda,
            "events": [
                {
                    "type":      ev.event_type.name,
                    "weight":    ev.weight,
                    "sensor_id": ev.sensor_id,
                }
                for ev in self._history[-8:]   # last 8 events
            ],
        }
