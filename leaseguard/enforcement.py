"""Enforcement Point (PEP) (paper Section 7/9/10/11).

Verifies an IssuedLease, then locally adjudicates every subsequent
operation against a sealed, per-dimension consumption ledger. Once any
budget dimension is exhausted the PEP drops to safe-degradation
(read-only); destructive operations beyond the destructive-op ceiling
require an explicit emergency procedure (dual control + absence of an
emergency-deny witness), never a remote approval, since remote is by
definition unavailable in the scenario this model targets.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .lease import IssuedLease
from .operation import Operation
from .counter import SealedMonotonicCounter, CounterRollbackDetected


class BudgetExhaustedError(Exception):
    pass


class SafeDegradationError(Exception):
    pass


DIMENSIONS = ("actions", "data_bytes", "objects", "financial_impact_usd", "destructive_ops")


@dataclass
class AuthDecision:
    allowed: bool
    reason: str
    degraded: bool = False
    emergency: bool = False


@dataclass
class ConsumptionLedger:
    """Sealed, per-dimension monotonic counters, one hash chain each."""

    pep_id: str
    counters: Dict[str, SealedMonotonicCounter] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for dim in DIMENSIONS:
            self.counters.setdefault(dim, SealedMonotonicCounter(seed=f"{self.pep_id}:{dim}"))

    def totals(self) -> Dict[str, float]:
        return {dim: c.value for dim, c in self.counters.items()}

    def chain_heads(self) -> Dict[str, str]:
        return {dim: c.chain_head() for dim, c in self.counters.items()}

    def consume(self, deltas: Dict[str, float]) -> None:
        for dim, amount in deltas.items():
            if amount:
                self.counters[dim].increment(amount)


@dataclass
class EnforcementPoint:
    pep_id: str
    issued_lease: IssuedLease
    ledger: ConsumptionLedger = field(init=False)
    degraded: bool = False
    log: List[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.ledger = ConsumptionLedger(pep_id=self.pep_id)

    def _budget(self) -> dict:
        return self.issued_lease.lease.budget.as_dict()

    def _op_deltas(self, op: Operation) -> Dict[str, float]:
        # Read operations are unmetered against every budget dimension.
        # This is deliberate, not an oversight: the spec requires that
        # once a budget is exhausted the PEP "reduce the subject to
        # read-only access" -- that fallback has to remain available
        # unconditionally, so reads cannot themselves be what exhausts
        # the budget that guards them. `max_actions` therefore bounds
        # *state-changing* operations, not every request.
        if op.is_read:
            return {dim: 0 for dim in DIMENSIONS}
        return {
            "actions": 1,
            "data_bytes": op.data_bytes,
            "objects": op.objects,
            "financial_impact_usd": op.financial_impact_usd,
            "destructive_ops": 1 if op.destructive else 0,
        }

    def _would_exceed(self, deltas: Dict[str, float]) -> Optional[str]:
        budget = self._budget()
        totals = self.ledger.totals()
        limit_key = {
            "actions": "max_actions",
            "data_bytes": "max_data_bytes",
            "objects": "max_objects",
            "financial_impact_usd": "max_financial_impact_usd",
            "destructive_ops": "max_destructive_ops",
        }
        for dim, delta in deltas.items():
            prospective = totals[dim] + delta
            if prospective > budget[limit_key[dim]]:
                return dim
        return None

    def authorize(
        self,
        op: Operation,
        now: float,
        emergency_witness_absent: bool = False,
        dual_control_confirmed: bool = False,
    ) -> AuthDecision:
        if not self.issued_lease.verify():
            return AuthDecision(False, "signature verification failed")
        if not self.issued_lease.is_time_valid(now):
            return AuthDecision(False, "lease outside validity window")
        if op.op_class not in self.issued_lease.lease.op_classes:
            return AuthDecision(False, f"op class '{op.op_class}' not permitted by lease")

        # Reads are unmetered against every dimension (see _op_deltas), so
        # they bypass the budget check entirely rather than being run
        # through _would_exceed: a dimension that is already exhausted or
        # permanently over-ceiling (e.g. destructive_ops after an
        # emergency-procedure use) must not re-trip on an operation that
        # contributes zero to it. This is what keeps read-only access
        # unconditionally available, both under general safe-degradation
        # and after the destructive-op ceiling has been used.
        if op.is_read:
            self._record(op, {}, allowed=True, reason="read allowed" + (" under safe-degradation" if self.degraded else ""))
            return AuthDecision(True, "read allowed", degraded=self.degraded)

        if self.degraded:
            return AuthDecision(False, "budget exhausted: non-read denied under safe-degradation", degraded=True)

        deltas = self._op_deltas(op)
        exceeded_dim = self._would_exceed(deltas)

        if exceeded_dim == "destructive_ops":
            if emergency_witness_absent and dual_control_confirmed:
                self.ledger.consume(deltas)
                self._record(op, deltas, allowed=True, reason="emergency destructive procedure", emergency=True)
                return AuthDecision(True, "emergency destructive procedure invoked", emergency=True)
            return AuthDecision(False, "destructive-op ceiling reached and emergency procedure not satisfied")

        if exceeded_dim is not None:
            self.degraded = True
            self._record(op, {}, allowed=False, reason=f"budget dimension '{exceeded_dim}' exhausted")
            return AuthDecision(False, f"budget dimension '{exceeded_dim}' exhausted; entering safe-degradation", degraded=True)

        self.ledger.consume(deltas)
        self._record(op, deltas, allowed=True, reason="within budget")
        return AuthDecision(True, "within budget")

    def _record(self, op: Operation, deltas: Dict[str, float], allowed: bool, reason: str, emergency: bool = False) -> None:
        self.log.append({
            "op_class": op.op_class,
            "deltas": deltas,
            "allowed": allowed,
            "reason": reason,
            "emergency": emergency,
            "chain_heads": self.ledger.chain_heads(),
        })

    def reconciliation_bundle(self) -> dict:
        return {
            "pep_id": self.pep_id,
            "sub": self.issued_lease.lease.sub,
            "aud": self.issued_lease.lease.aud,
            "epoch": self.issued_lease.lease.epoch,
            "totals": self.ledger.totals(),
            "chain_heads": self.ledger.chain_heads(),
            "log_length": len(self.log),
        }
