"""Lease schema and signing.

A Lease is the claims object described in the paper's lease schema
(Section 8). It is signed by the Authorization Authority using ECDSA
P-256 (a stand-in for a COSE_Sign1 / JOSE JWS envelope) and becomes an
IssuedLease: an immutable, replayable credential. Consumption against
the lease's ImpactBudget is tracked separately, PEP-side, by
enforcement.EnforcementPoint + counter.SealedMonotonicCounter -- never
mutated on the Lease object itself.
"""
from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


@dataclass(frozen=True)
class ImpactBudget:
    """Multi-dimensional cumulative-impact ceiling (paper Section 8)."""

    max_actions: int
    max_data_bytes: int
    max_objects: int
    max_financial_impact_usd: float
    max_destructive_ops: int

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Lease:
    """Unsigned claims set. Call AuthorizationAuthority.issue() to sign it."""

    sub: str
    aud: str
    policy_hash: str
    epoch: int
    lease_start: float
    lease_end: float
    reconciliation_deadline: float
    budget: ImpactBudget
    op_classes: tuple
    seq_range: tuple  # (start, end) inclusive
    device_measurement: str
    pop_public_key_pem: str
    offline_delegation: str = "none"
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(16))

    def canonical_bytes(self) -> bytes:
        payload = {
            "sub": self.sub,
            "aud": self.aud,
            "policy_hash": self.policy_hash,
            "epoch": self.epoch,
            "lease_start": self.lease_start,
            "lease_end": self.lease_end,
            "reconciliation_deadline": self.reconciliation_deadline,
            "budget": self.budget.as_dict(),
            "op_classes": list(self.op_classes),
            "seq_range": list(self.seq_range),
            "device_measurement": self.device_measurement,
            "pop_public_key_pem": self.pop_public_key_pem,
            "offline_delegation": self.offline_delegation,
            "nonce": self.nonce,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class IssuedLease:
    """A Lease plus the Authority's signature over it (COSE_Sign1 analogue)."""

    lease: Lease
    signature: bytes
    aa_public_key_pem: str

    def verify(self) -> bool:
        try:
            pub = serialization.load_pem_public_key(self.aa_public_key_pem.encode("utf-8"))
            pub.verify(self.signature, self.lease.canonical_bytes(), ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    def is_time_valid(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        return self.lease.lease_start <= now <= self.lease.lease_end

    def to_wire(self) -> str:
        """Base64url envelope, analogous to a compact JWS/CWT string."""
        body = {
            "claims": json.loads(self.lease.canonical_bytes()),
            "sig": base64.urlsafe_b64encode(self.signature).decode("ascii"),
            "aa_pub": self.aa_public_key_pem,
        }
        return base64.urlsafe_b64encode(json.dumps(body).encode("utf-8")).decode("ascii")
