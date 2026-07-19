"""Sealed monotonic counter: a software simulator of a TPM/vTPM-style
monotonic counter (paper Section 8/10/11), hash-chained so that any
rollback of the counter's persisted value is *detectable* at
reconciliation time, even though it is not *preventable* by software
alone -- this is the honest limit stated in the paper's Section 20
(Limitations) and Section 10 (Formal Security Model).

Real deployments would back this with a TPM2 NV monotonic counter or
an equivalent hardware root of trust. Here the "seal" is a running
BLAKE2b hash chain over every increment amount; ``verify_integrity``
recomputes the chain and the value independently from the recorded
increment history, so a rollback that only resets ``value`` (as a
naive attacker or a snapshot/VM rollback would do, without also being
able to fabricate a consistent prior chain) is caught.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import List


class CounterRollbackDetected(Exception):
    pass


@dataclass
class SealedMonotonicCounter:
    seed: str
    value: float = 0.0
    _chain: List[str] = field(default_factory=list)
    _increments: List[float] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        if not self._chain:
            self._chain.append(self._genesis_hash())

    def _genesis_hash(self) -> str:
        return hashlib.blake2b(f"genesis:{self.seed}".encode("utf-8")).hexdigest()

    def increment(self, amount: float = 1) -> float:
        if amount < 0:
            raise ValueError("monotonic counter cannot decrement")
        self.value += amount
        self._increments.append(amount)
        prev = self._chain[-1]
        nxt = hashlib.blake2b(f"{prev}:{amount}".encode("utf-8")).hexdigest()
        self._chain.append(nxt)
        return self.value

    def chain_head(self) -> str:
        return self._chain[-1]

    def verify_integrity(self) -> bool:
        """Recompute both the hash chain and the summed value from the
        recorded increment history and compare against the live state.
        Returns False if a rollback (or any other tamper of ``value``
        that bypassed ``increment``) is detected."""
        recomputed_head = self._genesis_hash()
        for amount in self._increments:
            recomputed_head = hashlib.blake2b(f"{recomputed_head}:{amount}".encode("utf-8")).hexdigest()
        recomputed_value = sum(self._increments)
        return recomputed_head == self._chain[-1] and recomputed_value == self.value

    def snapshot(self):
        return self.value, self.chain_head()

    def simulate_rollback(self, claimed_value: float) -> None:
        """Simulates an attacker, a cloned VM, or a storage-snapshot
        restore resetting the counter's persisted value without being
        able to reproduce the hash chain a real hardware counter would
        have produced. Used by experiments/scenarios.py to test that
        ``verify_integrity`` (and therefore reconciliation) detects it."""
        self.value = claimed_value
        # Deliberately leave `_chain` / `_increments` untouched: this
        # desync between the raw value and the recorded history is
        # exactly what verify_integrity() and Reconciler detect.
