"""Scripted workload generator (paper Section 16). Produces a fixed
cadence of operations drawn from OP_CATALOG for a given duration, used
identically across every baseline and LeaseGuard so comparisons are
apples-to-apples.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from leaseguard.operation import Operation, OP_CATALOG

# A representative mixed workload: mostly reads, periodic snapshots and
# provisioning, rare destructive operations -- typical of a storage /
# backup appliance or DR-site controller under normal operation.
WORKLOAD_MIX = (
    ("read", 10),
    ("snapshot.create", 2),
    ("volume.provision", 1),
    ("k8s.scale", 1),
    ("backup.restore", 1),
    ("snapshot.delete", 1),
    ("volume.delete", 1),
)


@dataclass
class ScheduledOp:
    t: float
    op: Operation


def generate_workload(duration_seconds: float, interval_seconds: float = 5.0) -> List[ScheduledOp]:
    """One operation every `interval_seconds`, cycling through
    WORKLOAD_MIX in proportion to its weights, for `duration_seconds`."""
    cycle: List[str] = []
    for op_class, weight in WORKLOAD_MIX:
        cycle.extend([op_class] * weight)

    schedule: List[ScheduledOp] = []
    t = 0.0
    i = 0
    while t <= duration_seconds:
        op_class = cycle[i % len(cycle)]
        schedule.append(ScheduledOp(t=t, op=OP_CATALOG[op_class]))
        i += 1
        t += interval_seconds
    return schedule
