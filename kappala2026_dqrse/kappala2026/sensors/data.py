"""
sensors/data.py
Synthetic agricultural sensor data generator for Kappala et al. (2026).

Simulates readings from a precision-agriculture field:
  - Soil sensors: pH, moisture, temperature, NPK levels
  - Weather: temperature, humidity, wind, rain
  - Actuator status: irrigation valves, dosing pumps
  - GPS positions: sensor / tractor locations

Each reading is tagged with a DataTier based on its type:
  CRITICAL  → actuator commands, GPS, dosing instructions
  SENSITIVE → soil pH, moisture, NPK, field maps
  NORMAL    → ambient weather, light, wind (low sensitivity)
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List

import numpy as np

from kappala2026.adaptive.policy import DataTier


class SensorType(Enum):
    SOIL_PH        = auto()   # SENSITIVE
    SOIL_MOISTURE  = auto()   # SENSITIVE
    SOIL_TEMP      = auto()   # SENSITIVE
    SOIL_NPK       = auto()   # SENSITIVE
    AIR_TEMP       = auto()   # NORMAL
    AIR_HUMIDITY   = auto()   # NORMAL
    WIND_SPEED     = auto()   # NORMAL
    RAINFALL       = auto()   # NORMAL
    IRRIGATION_CMD = auto()   # CRITICAL — actuator command
    DOSING_CMD     = auto()   # CRITICAL — chemical dosing
    GPS_POSITION   = auto()   # CRITICAL — asset location
    VALVE_STATUS   = auto()   # CRITICAL — physical actuator state


TIER_MAP: dict[SensorType, DataTier] = {
    SensorType.SOIL_PH:        DataTier.SENSITIVE,
    SensorType.SOIL_MOISTURE:  DataTier.SENSITIVE,
    SensorType.SOIL_TEMP:      DataTier.SENSITIVE,
    SensorType.SOIL_NPK:       DataTier.SENSITIVE,
    SensorType.AIR_TEMP:       DataTier.NORMAL,
    SensorType.AIR_HUMIDITY:   DataTier.NORMAL,
    SensorType.WIND_SPEED:     DataTier.NORMAL,
    SensorType.RAINFALL:       DataTier.NORMAL,
    SensorType.IRRIGATION_CMD: DataTier.CRITICAL,
    SensorType.DOSING_CMD:     DataTier.CRITICAL,
    SensorType.GPS_POSITION:   DataTier.CRITICAL,
    SensorType.VALVE_STATUS:   DataTier.CRITICAL,
}


@dataclass
class SensorReading:
    sensor_id:   int
    packet_id:   int
    sensor_type: SensorType
    tier:        DataTier
    value:       float
    payload:     bytes        # serialised payload (variable length)
    timestamp:   float

    @property
    def payload_size(self) -> int:
        return len(self.payload)


def generate_reading(
    sensor_id:  int,
    packet_id:  int,
    sensor_type: SensorType | None = None,
    rng: np.random.Generator | None = None,
) -> SensorReading:
    """Generate one realistic synthetic sensor reading."""
    import time
    if rng is None:
        rng = np.random.default_rng()
    if sensor_type is None:
        sensor_type = rng.choice(list(SensorType))

    tier = TIER_MAP[sensor_type]

    # Realistic value ranges per sensor type
    value_ranges = {
        SensorType.SOIL_PH:        (5.5, 7.5),
        SensorType.SOIL_MOISTURE:  (10.0, 80.0),
        SensorType.SOIL_TEMP:      (5.0, 35.0),
        SensorType.SOIL_NPK:       (0.0, 500.0),
        SensorType.AIR_TEMP:       (10.0, 45.0),
        SensorType.AIR_HUMIDITY:   (20.0, 95.0),
        SensorType.WIND_SPEED:     (0.0, 30.0),
        SensorType.RAINFALL:       (0.0, 50.0),
        SensorType.IRRIGATION_CMD: (0.0, 1.0),   # binary
        SensorType.DOSING_CMD:     (0.0, 100.0), # ml/m²
        SensorType.GPS_POSITION:   (17.0, 18.0), # lat approx Hyderabad
        SensorType.VALVE_STATUS:   (0.0, 1.0),   # binary
    }
    lo, hi = value_ranges[sensor_type]
    value = float(rng.uniform(lo, hi))

    # Payload: type byte + 4-byte sensor_id + 4-byte packet_id + 8-byte float64 value
    # + optional 16-byte metadata (tier, timestamp, CRC stub)
    payload_sizes = {
        DataTier.CRITICAL:  48,   # larger: includes command checksum
        DataTier.SENSITIVE: 32,
        DataTier.NORMAL:    16,
    }
    payload = bytes(rng.integers(0, 256, payload_sizes[tier], dtype=np.uint8))

    return SensorReading(
        sensor_id=sensor_id,
        packet_id=packet_id,
        sensor_type=sensor_type,
        tier=tier,
        value=value,
        payload=payload,
        timestamp=time.time(),
    )


def generate_packet_stream(
    n_sensors:   int = 5,
    n_packets:   int = 200,
    tier_mix:    dict | None = None,
    seed:        int = 42,
) -> List[SensorReading]:
    """
    Generate a stream of sensor readings across all nodes.

    Args:
        n_sensors: Number of field sensor nodes.
        n_packets: Total packets to generate.
        tier_mix:  Fraction of CRITICAL / SENSITIVE / NORMAL packets.
                   Default: 20% / 35% / 45% (realistic field deployment).
        seed:      RNG seed.
    """
    if tier_mix is None:
        tier_mix = {
            DataTier.CRITICAL:  0.20,
            DataTier.SENSITIVE: 0.35,
            DataTier.NORMAL:    0.45,
        }

    rng = np.random.default_rng(seed)
    tiers   = list(tier_mix.keys())
    weights = [tier_mix[t] for t in tiers]
    weights = [w / sum(weights) for w in weights]

    # Map tier → sensor types belonging to that tier
    tier_to_types = {t: [st for st, ti in TIER_MAP.items() if ti == t] for t in DataTier}

    readings: List[SensorReading] = []
    for pkt_id in range(n_packets):
        sensor_id = int(rng.integers(0, n_sensors))
        chosen_tier = rng.choice(tiers, p=weights)
        sensor_type = rng.choice(tier_to_types[chosen_tier])
        readings.append(generate_reading(sensor_id, pkt_id, sensor_type, rng))

    return readings
