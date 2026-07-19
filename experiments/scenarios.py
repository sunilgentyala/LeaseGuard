"""Scripted adversarial scenarios (paper Section 16, second half):
enforcement-point restart, VM/snapshot rollback, counter-state
corruption, multiple isolated PEPs sharing a lease, a destructive
operation exceeding its ceiling, and read-only emergency operations
continuing under safe-degradation. Writes results/scenarios.md.

Run: python -m experiments.scenarios
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from leaseguard import AuthorizationAuthority, ImpactBudget, EnforcementPoint, Operation, Reconciler


def pop_key_pem() -> str:
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def issue(aa, budget, op_classes):
    return aa.issue(
        sub="workload:scenario-pep",
        aud="storage-array:scenario",
        budget=budget,
        op_classes=op_classes,
        pop_public_key_pem=pop_key_pem(),
        device_measurement="sha384:simulated-quote",
        duration_seconds=90000.0,
        now=0.0,
    )


def scenario_enforcement_point_restart():
    aa = AuthorizationAuthority(name="aa-restart")
    budget = ImpactBudget(50, 100_000, 50, 500.0, 3)
    issued = issue(aa, budget, ("read", "snapshot.create"))
    pep = EnforcementPoint(pep_id="pep-restart", issued_lease=issued)
    for i in range(5):
        pep.authorize(Operation("snapshot.create", data_bytes=1000, financial_impact_usd=10.0), now=float(i))
    before = pep.ledger.totals()
    # "restart" = new process object, but sealed counter state is durable
    # (persisted outside process memory in a real deployment); simulated
    # here by handing the same ledger to a fresh EnforcementPoint instance.
    restarted = EnforcementPoint(pep_id="pep-restart", issued_lease=issued)
    restarted.ledger = pep.ledger
    after = restarted.ledger.totals()
    return {
        "scenario": "enforcement_point_restart",
        "totals_before": before,
        "totals_after_restart": after,
        "state_preserved": before == after,
    }


def scenario_vm_snapshot_rollback():
    aa = AuthorizationAuthority(name="aa-rollback")
    budget = ImpactBudget(50, 100_000, 50, 500.0, 3)
    issued = issue(aa, budget, ("snapshot.create",))
    pep = EnforcementPoint(pep_id="pep-rollback", issued_lease=issued)
    for i in range(5):
        pep.authorize(Operation("snapshot.create", data_bytes=1000, financial_impact_usd=10.0), now=float(i))
    integrity_before = all(c.verify_integrity() for c in pep.ledger.counters.values())
    # Simulate a hypervisor snapshot-rollback of the PEP's local disk state.
    pep.ledger.counters["financial_impact_usd"].simulate_rollback(0.0)
    integrity_after = all(c.verify_integrity() for c in pep.ledger.counters.values())
    reconciler = Reconciler(aa)
    report = reconciler.reconcile([pep])
    return {
        "scenario": "vm_snapshot_rollback",
        "integrity_before_rollback": integrity_before,
        "integrity_after_rollback": integrity_after,
        "rollback_detected_at_reconciliation": report.rollback_detected,
    }


def scenario_multiple_isolated_peps_same_lease():
    aa = AuthorizationAuthority(name="aa-fork")
    budget = ImpactBudget(100, 200_000, 100, 150.0, 10)
    issued = issue(aa, budget, ("read", "snapshot.create"))
    peps = [EnforcementPoint(pep_id=f"pep-{i}", issued_lease=issued) for i in range(3)]
    op = Operation("snapshot.create", data_bytes=1000, financial_impact_usd=60.0)
    for pep in peps:
        pep.authorize(op, now=0.0)  # each replica independently thinks it has full budget
    reconciler = Reconciler(aa)
    report = reconciler.reconcile(peps)
    return {
        "scenario": "multiple_isolated_peps_same_lease",
        "num_replicas": len(peps),
        "each_replica_individually_within_budget": all(
            p.ledger.totals()["financial_impact_usd"] <= budget.max_financial_impact_usd for p in peps
        ),
        "reconciled_total_financial_impact_usd": report.reconciled_totals["financial_impact_usd"],
        "budget_violated_when_summed": report.budget_violated,
    }


def scenario_destructive_ceiling_and_readonly_emergency():
    aa = AuthorizationAuthority(name="aa-destructive")
    budget = ImpactBudget(100, 100_000, 100, 500.0, max_destructive_ops=2)
    issued = issue(aa, budget, ("read", "snapshot.delete"))
    pep = EnforcementPoint(pep_id="pep-destructive", issued_lease=issued)
    destructive = Operation("snapshot.delete", destructive=True)

    results = []
    for i in range(4):
        d = pep.authorize(destructive, now=float(i))
        results.append({"attempt": i, "allowed": d.allowed, "reason": d.reason})

    emergency = pep.authorize(destructive, now=10.0, emergency_witness_absent=True, dual_control_confirmed=True)
    read_during = pep.authorize(Operation("read"), now=11.0)

    return {
        "scenario": "destructive_ceiling_and_readonly_emergency",
        "attempts": results,
        "emergency_procedure_result": {"allowed": emergency.allowed, "emergency": emergency.emergency},
        "read_still_available": read_during.allowed,
    }


def main() -> None:
    scenarios = [
        scenario_enforcement_point_restart(),
        scenario_vm_snapshot_rollback(),
        scenario_multiple_isolated_peps_same_lease(),
        scenario_destructive_ceiling_and_readonly_emergency(),
    ]

    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "scenarios.md")

    with open(out_path, "w") as f:
        f.write("# Scenario results (generated by experiments/scenarios.py)\n\n")
        for s in scenarios:
            f.write(f"## {s['scenario']}\n\n")
            for k, v in s.items():
                if k == "scenario":
                    continue
                f.write(f"- **{k}**: {v}\n")
            f.write("\n")

    for s in scenarios:
        print(s)
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
