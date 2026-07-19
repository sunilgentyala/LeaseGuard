"""Reference implementations of the seven comparison baselines from the
paper's experimental section (Section 17). These are deliberately
simple -- they model the *authorization-decision shape* of each real
scheme (what information it can use, and what it cannot use while
disconnected), not full protocol implementations. LeaseGuard itself is
NOT a baseline; it is exercised directly via EnforcementPoint in the
experiment harness, since it needs the full Lease/budget machinery.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class BaselineDecision:
    allowed: bool
    reason: str


class BearerToken:
    """1. Long-lived bearer token: never expires, never checks revocation."""

    name = "bearer_token"

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        return BaselineDecision(True, "bearer token accepted unconditionally")


class ShortLivedJWT:
    """2. Short-lived JWT: must be refreshed periodically; refresh requires
    connectivity. Once its expiry passes while disconnected, it can no
    longer be renewed and further requests are denied."""

    name = "short_lived_jwt"

    def __init__(self, exp_seconds: float = 300.0) -> None:
        self.exp_seconds = exp_seconds
        self.last_refresh = 0.0

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        if connected:
            self.last_refresh = elapsed_since_issue  # transparent auto-refresh while connected
            if revoked:
                return BaselineDecision(False, "refresh denied: subject revoked at authority")
            return BaselineDecision(True, "refreshed JWT accepted")
        if elapsed_since_issue - self.last_refresh <= self.exp_seconds:
            return BaselineDecision(True, "unexpired JWT accepted while disconnected")
        return BaselineDecision(False, "JWT expired and cannot be refreshed while disconnected")


class OnlineIntrospection:
    """3. Every request requires a live introspection call to the authority."""

    name = "online_introspection"

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        if not connected:
            return BaselineDecision(False, "introspection endpoint unreachable")
        if revoked:
            return BaselineDecision(False, "introspection reports revoked")
        return BaselineDecision(True, "introspection reports valid")


class SelfContainedPoPToken:
    """4. Self-contained proof-of-possession token (DPoP-style): sender
    constrained, but otherwise behaves like a long-window bearer token
    with respect to revocation-while-offline."""

    name = "self_contained_pop_token"

    def __init__(self, exp_seconds: float = 86400.0) -> None:
        self.exp_seconds = exp_seconds

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        if elapsed_since_issue <= self.exp_seconds:
            return BaselineDecision(True, "PoP token accepted (no revocation check possible offline)")
        return BaselineDecision(False, "PoP token expired")


class TimeOnlyLease:
    """5. Ordinary authorization lease bounded only by a time window --
    no cumulative-impact accounting of any kind."""

    name = "time_only_lease"

    def __init__(self, duration_seconds: float = 86400.0) -> None:
        self.duration_seconds = duration_seconds

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        if elapsed_since_issue <= self.duration_seconds:
            return BaselineDecision(True, "within time-only lease window")
        return BaselineDecision(False, "time-only lease window elapsed")


class EpochRevocableToken:
    """6. Valid only within the current policy epoch; cannot renew into
    the next epoch without reconnecting."""

    name = "epoch_revocable_token"

    def __init__(self, epoch_length_seconds: float = 3600.0) -> None:
        self.epoch_length_seconds = epoch_length_seconds

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        if elapsed_since_issue <= self.epoch_length_seconds:
            return BaselineDecision(True, "within current epoch")
        if connected:
            return BaselineDecision(not revoked, "epoch renewed on reconnect" if not revoked else "epoch renewal denied: revoked")
        return BaselineDecision(False, "epoch boundary passed while disconnected; cannot renew")


class HeartbeatDependentCredential:
    """7. Requires a periodic heartbeat from the authority; if the grace
    window since the last successful heartbeat elapses, access is denied."""

    name = "heartbeat_dependent_credential"

    def __init__(self, grace_seconds: float = 60.0) -> None:
        self.grace_seconds = grace_seconds
        self.last_heartbeat = 0.0

    def decide(self, elapsed_since_issue: float, connected: bool, revoked: bool) -> BaselineDecision:
        if connected:
            self.last_heartbeat = elapsed_since_issue
            if revoked:
                return BaselineDecision(False, "heartbeat reports revoked")
            return BaselineDecision(True, "heartbeat fresh")
        if elapsed_since_issue - self.last_heartbeat <= self.grace_seconds:
            return BaselineDecision(True, "within heartbeat grace window")
        return BaselineDecision(False, "heartbeat grace window exceeded")


ALL_BASELINES = [
    BearerToken,
    ShortLivedJWT,
    OnlineIntrospection,
    SelfContainedPoPToken,
    TimeOnlyLease,
    EpochRevocableToken,
    HeartbeatDependentCredential,
]
