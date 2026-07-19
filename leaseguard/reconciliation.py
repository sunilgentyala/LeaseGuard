"""Reconciliation protocol (paper Section 9 step 4, Section 11).

Run when a PEP (or several forked replicas of the same lease/audience
pair) reconnects to the Authorization Authority. Detects local-state
rollback via SealedMonotonicCounter.verify_integrity(), and resolves
forked enforcement state conservatively: if two PEPs independently
consumed budget under the same lease (e.g. two isolated array
controllers mistakenly issued the same lease, or a cloned VM), the
reconciled total is the *sum* of their consumption, which is the
safety-preserving (not availability-preserving) choice.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .authority import AuthorizationAuthority
from .enforcement import EnforcementPoint, DIMENSIONS


@dataclass
class ReconciliationReport:
    sub: str
    aud: str
    rollback_detected: bool
    forked: bool
    reconciled_totals: Dict[str, float]
    budget_violated: bool
    next_epoch: int
    notes: List[str] = field(default_factory=list)


class Reconciler:
    def __init__(self, authority: AuthorizationAuthority) -> None:
        self.authority = authority

    def reconcile(self, peps: List[EnforcementPoint]) -> ReconciliationReport:
        if not peps:
            raise ValueError("no enforcement points to reconcile")

        subs = {p.issued_lease.lease.sub for p in peps}
        auds = {p.issued_lease.lease.aud for p in peps}
        if len(subs) != 1 or len(auds) != 1:
            raise ValueError("reconcile() expects PEPs sharing one (sub, aud) pair")

        notes: List[str] = []
        rollback_detected = False
        for p in peps:
            for dim in DIMENSIONS:
                if not p.ledger.counters[dim].verify_integrity():
                    rollback_detected = True
                    notes.append(f"{p.pep_id}: rollback detected on dimension '{dim}'")

        forked = len(peps) > 1

        reconciled_totals: Dict[str, float] = {dim: 0.0 for dim in DIMENSIONS}
        for p in peps:
            totals = p.ledger.totals()
            for dim in DIMENSIONS:
                # Conservative reconciliation: sum consumption across all
                # replicas that held the same lease, never take a max()
                # or last-writer-wins, since that could under-count
                # cumulative impact.
                reconciled_totals[dim] += totals[dim]

        budget = peps[0].issued_lease.lease.budget.as_dict()
        limit_key = {
            "actions": "max_actions",
            "data_bytes": "max_data_bytes",
            "objects": "max_objects",
            "financial_impact_usd": "max_financial_impact_usd",
            "destructive_ops": "max_destructive_ops",
        }
        budget_violated = any(
            reconciled_totals[dim] > budget[limit_key[dim]] for dim in DIMENSIONS
        )
        if forked:
            notes.append(f"{len(peps)} enforcement-point replicas held the same lease/audience pair")
        if budget_violated:
            notes.append("conservative reconciled total exceeds the authorized budget -- flag for manual review")

        next_epoch = self.authority.advance_epoch()

        return ReconciliationReport(
            sub=subs.pop(),
            aud=auds.pop(),
            rollback_detected=rollback_detected,
            forked=forked,
            reconciled_totals=reconciled_totals,
            budget_violated=budget_violated,
            next_epoch=next_epoch,
            notes=notes,
        )
