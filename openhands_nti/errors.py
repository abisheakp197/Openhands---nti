"""Exception hierarchy for openhands-nti.

Every failure path in the guardrail is fail-closed: if anything about the
action cannot be proven authorized, :class:`NTIBlocked` is raised and the
tool never runs.
"""

from __future__ import annotations


class NTIError(Exception):
    """Base class for all openhands-nti errors."""


class CanonicalizationError(NTIError):
    """An action payload cannot be encoded to the engine's canonical form."""


class IdentityError(NTIError):
    """The agent's DID or verification method could not be resolved or bound."""


class DelegationError(NTIError):
    """The Merkle delegation chain is missing, malformed, or does not authorize."""


class NTIBlocked(NTIError):
    """The action was denied. Raised before the tool executes (fail-closed)."""

    def __init__(self, message: str, *, reason: str = "denied", receipt: dict | None = None):
        super().__init__(message)
        self.reason = reason
        self.receipt = receipt
