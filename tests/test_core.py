"""Correctness tests for the lease/enforcement/reconciliation core.
These are the closest thing this prototype has to the paper's Section
10 formal-model claims: each test exercises one security property from
Section 11 directly against the implementation.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from leaseguard import (
    AuthorizationAuthority,
    ImpactBudget,
    EnforcementPoint,
    Operation,
    Reconciler,
)
from leaseguard.counter import SealedMonotonicCounter


def make_pop_key_pem() -> str:
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def issue_test_lease(aa: AuthorizationAuthority, budget: ImpactBudget, op_classes=("read", "snapshot.create", "snapshot.delete")):
    return aa.issue(
        sub="workload:test",
        aud="storage-array:test",
        budget=budget,
        op_classes=op_classes,
        pop_public_key_pem=make_pop_key_pem(),
        device_measurement="sha384:test-quote",
        duration_seconds=86400.0,
        now=0.0,
    )


def test_lease_signature_verifies():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(10, 10_000, 10, 100.0, 1)
    issued = issue_test_lease(aa, budget)
    assert issued.verify()


def test_tampered_lease_fails_verification():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(10, 10_000, 10, 100.0, 1)
    issued = issue_test_lease(aa, budget)
    tampered = issued.lease.__class__(**{**issued.lease.__dict__, "epoch": issued.lease.epoch + 1})
    from leaseguard.lease import IssuedLease
    tampered_issued = IssuedLease(lease=tampered, signature=issued.signature, aa_public_key_pem=issued.aa_public_key_pem)
    assert not tampered_issued.verify()


def test_budget_exhaustion_triggers_safe_degradation():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(max_actions=3, max_data_bytes=10_000, max_objects=10, max_financial_impact_usd=100.0, max_destructive_ops=5)
    issued = issue_test_lease(aa, budget, op_classes=("read", "snapshot.create"))
    pep = EnforcementPoint(pep_id="pep1", issued_lease=issued)

    mutate = Operation("snapshot.create", data_bytes=1, financial_impact_usd=0.0)
    for i in range(3):
        d = pep.authorize(mutate, now=float(i))
        assert d.allowed

    d = pep.authorize(mutate, now=9.0)
    assert not d.allowed and d.degraded, "4th mutating op must exhaust max_actions and enter safe-degradation"

    d = pep.authorize(Operation("read"), now=10.0)
    assert d.allowed, "reads must remain available under safe-degradation"
    assert d.degraded


def test_non_read_denied_after_exhaustion_but_reads_continue():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(max_actions=100, max_data_bytes=1, max_objects=100, max_financial_impact_usd=100.0, max_destructive_ops=5)
    issued = issue_test_lease(aa, budget, op_classes=("read", "snapshot.create"))
    pep = EnforcementPoint(pep_id="pep1", issued_lease=issued)

    snap = Operation("snapshot.create", data_bytes=1 << 30, financial_impact_usd=0.1)
    d1 = pep.authorize(snap, now=0.0)
    assert not d1.allowed, "single snapshot already exceeds a 1-byte data budget"
    assert pep.degraded

    d2 = pep.authorize(Operation("read"), now=1.0)
    assert d2.allowed


def test_destructive_ceiling_requires_emergency_procedure():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(max_actions=100, max_data_bytes=10_000, max_objects=100, max_financial_impact_usd=100.0, max_destructive_ops=1)
    issued = issue_test_lease(aa, budget, op_classes=("snapshot.delete",))
    pep = EnforcementPoint(pep_id="pep1", issued_lease=issued)

    destructive = Operation("snapshot.delete", destructive=True)
    d1 = pep.authorize(destructive, now=0.0)
    assert d1.allowed

    d2 = pep.authorize(destructive, now=1.0)
    assert not d2.allowed, "second destructive op exceeds ceiling and no emergency procedure was invoked"

    d3 = pep.authorize(destructive, now=2.0, emergency_witness_absent=True, dual_control_confirmed=True)
    assert d3.allowed and d3.emergency


def test_cumulative_impact_never_exceeds_budget_across_long_partition():
    """This is the closest executable check to the paper's Section 10
    impact-bounded safety property: run far more operations than the
    budget allows and confirm every dimension's consumed total stays
    at or below the authorized ceiling."""
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(max_actions=50, max_data_bytes=50_000, max_objects=50, max_financial_impact_usd=25.0, max_destructive_ops=2)
    issued = issue_test_lease(aa, budget, op_classes=("read", "snapshot.create", "snapshot.delete"))
    pep = EnforcementPoint(pep_id="pep1", issued_lease=issued)

    op = Operation("snapshot.create", data_bytes=1000, financial_impact_usd=1.0)
    for i in range(10_000):
        pep.authorize(op, now=float(i))

    totals = pep.ledger.totals()
    b = budget.as_dict()
    assert totals["actions"] <= b["max_actions"]
    assert totals["data_bytes"] <= b["max_data_bytes"]
    assert totals["financial_impact_usd"] <= b["max_financial_impact_usd"]


def test_counter_rollback_is_detected():
    c = SealedMonotonicCounter(seed="test")
    c.increment(5)
    c.increment(3)
    assert c.verify_integrity()
    c.simulate_rollback(2)
    assert not c.verify_integrity()


def test_forked_enforcement_points_reconcile_conservatively():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(max_actions=100, max_data_bytes=10_000, max_objects=100, max_financial_impact_usd=100.0, max_destructive_ops=5)
    issued = issue_test_lease(aa, budget, op_classes=("read", "snapshot.create"))

    pep_a = EnforcementPoint(pep_id="pep-a", issued_lease=issued)
    pep_b = EnforcementPoint(pep_id="pep-b", issued_lease=issued)

    op = Operation("snapshot.create", data_bytes=4000, financial_impact_usd=30.0)
    pep_a.authorize(op, now=0.0)
    pep_a.authorize(op, now=1.0)
    pep_b.authorize(op, now=0.0)
    pep_b.authorize(op, now=1.0)

    reconciler = Reconciler(aa)
    report = reconciler.reconcile([pep_a, pep_b])

    assert report.forked
    assert report.reconciled_totals["financial_impact_usd"] == pytest.approx(120.0)
    assert report.budget_violated, "each PEP stayed within budget individually, but the sum across the fork exceeds it"


def test_reconciliation_detects_rollback_across_replicas():
    aa = AuthorizationAuthority(name="aa1")
    budget = ImpactBudget(max_actions=100, max_data_bytes=10_000, max_objects=100, max_financial_impact_usd=100.0, max_destructive_ops=5)
    issued = issue_test_lease(aa, budget, op_classes=("snapshot.create",))
    pep = EnforcementPoint(pep_id="pep1", issued_lease=issued)
    pep.authorize(Operation("snapshot.create", data_bytes=100, financial_impact_usd=1.0), now=0.0)
    pep.ledger.counters["actions"].simulate_rollback(0.0)

    reconciler = Reconciler(aa)
    report = reconciler.reconcile([pep])
    assert report.rollback_detected
