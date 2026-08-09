"""Stable exception hierarchy shared by library and transport adapters."""

from __future__ import annotations


class LETSError(Exception):
    """Base class for expected LETS failures."""

    code = "lets_error"


class ValidationError(LETSError, ValueError):
    code = "validation_error"


class NotFoundError(LETSError, LookupError):
    code = "not_found"


class ConflictError(LETSError):
    code = "conflict"


class PolicyError(LETSError, PermissionError):
    code = "policy_denied"


class ExpiredError(PolicyError):
    code = "expired"


class ReplayError(PolicyError):
    code = "replay_detected"


class SignatureError(PolicyError):
    code = "invalid_signature"


class InvariantError(LETSError, AssertionError):
    code = "invariant_violation"


class StorageError(LETSError):
    code = "storage_error"


class ClockUncertainError(PolicyError):
    code = "clock_uncertain"
