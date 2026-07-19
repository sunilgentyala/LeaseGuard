"""Authorization Authority (AA): policy engine + issuer + epoch/revocation
registry (paper Section 7/9). The policy check is a deliberately simple
OPA/Cedar-style stub -- a boolean allow/deny plus a policy_hash -- since
the research contribution is the lease/budget/reconciliation model, not
a new policy language.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .lease import Lease, ImpactBudget, IssuedLease


PolicyFn = Callable[[str, str, tuple], bool]


def default_policy(sub: str, aud: str, op_classes: tuple) -> bool:
    """Always-allow stub policy; replace with a real OPA/Cedar call."""
    return True


@dataclass
class AuthorizationAuthority:
    name: str
    policy_fn: PolicyFn = default_policy
    epoch: int = 0
    revoked_subjects: Dict[str, int] = field(default_factory=dict)  # sub -> epoch revoked at
    _private_key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    _next_seq: int = 0

    @property
    def public_key_pem(self) -> str:
        return self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def policy_hash(self) -> str:
        return "sha256:" + hashlib.sha256(f"policy-v1:{self.name}".encode("utf-8")).hexdigest()[:16]

    def advance_epoch(self) -> int:
        self.epoch += 1
        return self.epoch

    def revoke(self, sub: str) -> None:
        self.revoked_subjects[sub] = self.epoch

    def is_revoked_as_of(self, sub: str, epoch: int) -> bool:
        revoked_at = self.revoked_subjects.get(sub)
        return revoked_at is not None and revoked_at <= epoch

    def issue(
        self,
        sub: str,
        aud: str,
        budget: ImpactBudget,
        op_classes: tuple,
        pop_public_key_pem: str,
        device_measurement: str,
        duration_seconds: float = 86400.0,
        offline_delegation: str = "none",
        now: Optional[float] = None,
    ) -> Optional[IssuedLease]:
        if not self.policy_fn(sub, aud, op_classes):
            return None
        if self.is_revoked_as_of(sub, self.epoch):
            return None
        now = now if now is not None else time.time()
        seq_start = self._next_seq
        self._next_seq += budget.max_actions
        lease = Lease(
            sub=sub,
            aud=aud,
            policy_hash=self.policy_hash(),
            epoch=self.epoch,
            lease_start=now,
            lease_end=now + duration_seconds,
            reconciliation_deadline=now + duration_seconds,
            budget=budget,
            op_classes=tuple(op_classes),
            seq_range=(seq_start, seq_start + budget.max_actions),
            device_measurement=device_measurement,
            pop_public_key_pem=pop_public_key_pem,
            offline_delegation=offline_delegation,
        )
        signature = self._private_key.sign(lease.canonical_bytes(), ec.ECDSA(hashes.SHA256()))
        return IssuedLease(lease=lease, signature=signature, aa_public_key_pem=self.public_key_pem)
