"""WAN partition / latency emulator (paper Section 15).

A simple virtual-clock model: tests advance a shared clock and flip
connectivity, rather than sleeping in real time, so a simulated
24-hour partition runs in milliseconds.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PartitionEmulator:
    _now: float = 0.0
    _connected: bool = True
    _latency_seconds: float = 0.05

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> float:
        self._now += seconds
        return self._now

    def partition(self) -> None:
        self._connected = False

    def heal(self, latency_seconds: Optional[float] = None) -> None:
        self._connected = True
        if latency_seconds is not None:
            self._latency_seconds = latency_seconds

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def round_trip_latency(self) -> float:
        return self._latency_seconds
