"""Experiment harness (paper Section 16-19). Runs the same scripted
workload against all 7 baseline schemes plus LeaseGuard across 4
partition durations (1 min, 10 min, 1 hour, 24 hours), with a
credential-revocation event injected 30 seconds into every partition
long enough to contain one. Writes results/results.csv.

Run: python -m experiments.run_experiments
"""
from __future__ import annotations

import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from leaseguard import AuthorizationAuthority, ImpactBudget, EnforcementPoint
from leaseguard.baselines import ALL_BASELINES
from experiments.workload import generate_workload

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

DURATIONS = {
    "1_minute": 60.0,
    "10_minutes": 600.0,
    "1_hour": 3600.0,
    "24_hours": 86400.0,
}

REVOCATION_OFFSET = 30.0

LEASEGUARD_BUDGET = ImpactBudget(
    max_actions=5000,
    max_data_bytes=3_000_000_000_000,  # 3 TB
    max_objects=6000,
    max_financial_impact_usd=400.0,
    max_destructive_ops=5,
)


def impact_weight(op) -> float:
    return op.financial_impact_usd + (1000.0 if op.destructive else 0.0)


def run_baseline(baseline, schedule, revoked_at):
    total = len(schedule)
    allowed = 0
    post_revocation_allowed = 0
    post_revocation_impact = 0.0
    for sched in schedule:
        revoked = revoked_at is not None and sched.t >= revoked_at
        decision = baseline.decide(elapsed_since_issue=sched.t, connected=False, revoked=revoked)
        if decision.allowed:
            allowed += 1
            if revoked:
                post_revocation_allowed += 1
                post_revocation_impact += impact_weight(sched.op)
    return total, allowed, post_revocation_allowed, post_revocation_impact


def run_leaseguard(schedule, revoked_at):
    aa = AuthorizationAuthority(name="leaseguard-experiment")
    priv = ec.generate_private_key(ec.SECP256R1())
    pop_pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    issued = aa.issue(
        sub="workload:experiment-pep",
        aud="storage-array:experiment",
        budget=LEASEGUARD_BUDGET,
        op_classes=tuple(sorted({s.op.op_class for s in schedule})),
        pop_public_key_pem=pop_pub_pem,
        device_measurement="sha384:simulated-quote",
        duration_seconds=max(s.t for s in schedule) + 3600,
        now=0.0,
    )
    pep = EnforcementPoint(pep_id="pep-experiment", issued_lease=issued)

    total = len(schedule)
    allowed = 0
    post_revocation_allowed = 0
    post_revocation_impact = 0.0
    exhausted_dim = None
    for sched in schedule:
        # AA revoking the subject has NO effect on an already-disconnected
        # PEP -- this is the property under test, not a bug: revocation
        # cannot propagate across a partition, so the model bounds damage
        # via the budget instead of relying on revocation delivery.
        revoked = revoked_at is not None and sched.t >= revoked_at
        decision = pep.authorize(sched.op, now=sched.t)
        if decision.allowed:
            allowed += 1
            if revoked:
                post_revocation_allowed += 1
                post_revocation_impact += impact_weight(sched.op)
        if decision.degraded and exhausted_dim is None and not decision.allowed:
            exhausted_dim = decision.reason
    return total, allowed, post_revocation_allowed, post_revocation_impact, exhausted_dim, pep.degraded


def main() -> None:
    results_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "results.csv")

    rows = []
    for label, duration in DURATIONS.items():
        schedule = generate_workload(duration, interval_seconds=5.0)
        revoked_at = REVOCATION_OFFSET if duration > REVOCATION_OFFSET else None

        for baseline_cls in ALL_BASELINES:
            baseline = baseline_cls()
            total, allowed, pr_allowed, pr_impact = run_baseline(baseline, schedule, revoked_at)
            rows.append({
                "partition_duration": label,
                "partition_seconds": duration,
                "scheme": baseline.name,
                "ops_attempted": total,
                "ops_allowed": allowed,
                "availability_pct": round(100.0 * allowed / total, 2),
                "post_revocation_ops_allowed": pr_allowed,
                "post_revocation_impact_score": round(pr_impact, 2),
                "degraded_or_exhausted": "",
            })

        total, allowed, pr_allowed, pr_impact, exhausted_dim, degraded = run_leaseguard(schedule, revoked_at)
        rows.append({
            "partition_duration": label,
            "partition_seconds": duration,
            "scheme": "leaseguard",
            "ops_attempted": total,
            "ops_allowed": allowed,
            "availability_pct": round(100.0 * allowed / total, 2),
            "post_revocation_ops_allowed": pr_allowed,
            "post_revocation_impact_score": round(pr_impact, 2),
            "degraded_or_exhausted": exhausted_dim or ("" if not degraded else "degraded"),
        })

    fieldnames = [
        "partition_duration", "partition_seconds", "scheme", "ops_attempted",
        "ops_allowed", "availability_pct", "post_revocation_ops_allowed",
        "post_revocation_impact_score", "degraded_or_exhausted",
    ]
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {out_path}")


if __name__ == "__main__":
    main()
