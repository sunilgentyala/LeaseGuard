"""Typed infrastructure operation classes used by the simulated
storage / Kubernetes / hypervisor / edge adapters (paper Section 15).
Each operation carries a policy-authored cost estimate along each
impact-budget dimension; the estimate is what the model bounds, not
independently-verified real-world damage (paper Section 20).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Operation:
    op_class: str  # e.g. "read", "snapshot.create", "volume.provision", "volume.delete"
    data_bytes: int = 0
    objects: int = 1
    financial_impact_usd: float = 0.0
    destructive: bool = False

    @property
    def is_read(self) -> bool:
        return self.op_class == "read"


# Reference cost table for the simulated infrastructure adapters
# (storage array, Kubernetes, hypervisor, edge/backup).
OP_CATALOG = {
    "read": Operation("read", data_bytes=0, objects=1, financial_impact_usd=0.0, destructive=False),
    "snapshot.create": Operation("snapshot.create", data_bytes=1 << 30, objects=1, financial_impact_usd=0.10, destructive=False),
    "snapshot.delete": Operation("snapshot.delete", data_bytes=0, objects=1, financial_impact_usd=0.0, destructive=True),
    "volume.provision": Operation("volume.provision", data_bytes=0, objects=1, financial_impact_usd=5.00, destructive=False),
    "volume.delete": Operation("volume.delete", data_bytes=0, objects=1, financial_impact_usd=0.0, destructive=True),
    "backup.restore": Operation("backup.restore", data_bytes=10 << 30, objects=1, financial_impact_usd=2.50, destructive=False),
    "k8s.scale": Operation("k8s.scale", data_bytes=0, objects=1, financial_impact_usd=1.00, destructive=False),
    "vm.snapshot_rollback": Operation("vm.snapshot_rollback", data_bytes=0, objects=1, financial_impact_usd=0.0, destructive=True),
}
