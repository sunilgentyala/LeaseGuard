"""LeaseGuard: cryptographic impact-bounded authorization leases for
disconnected hybrid-infrastructure control planes.

This package is a research prototype / simulator. It implements the
lease schema, signing, local sealed-counter enforcement, a WAN
partition emulator, and baseline credential schemes for comparison.
It does not integrate with real Kubernetes/VMware/Keycloak deployments;
infrastructure adapters are simulated typed operation classes.
"""

from .lease import Lease, ImpactBudget, IssuedLease
from .authority import AuthorizationAuthority
from .enforcement import EnforcementPoint, SafeDegradationError, BudgetExhaustedError, AuthDecision
from .counter import SealedMonotonicCounter, CounterRollbackDetected
from .partition import PartitionEmulator
from .operation import Operation, OP_CATALOG
from .reconciliation import Reconciler, ReconciliationReport

__all__ = [
    "Lease",
    "ImpactBudget",
    "IssuedLease",
    "AuthorizationAuthority",
    "EnforcementPoint",
    "AuthDecision",
    "SafeDegradationError",
    "BudgetExhaustedError",
    "SealedMonotonicCounter",
    "CounterRollbackDetected",
    "PartitionEmulator",
    "Operation",
    "OP_CATALOG",
    "Reconciler",
    "ReconciliationReport",
]
