"""Stable exception hierarchy shared by library and transport adapters."""

from __future__ import annotations

from typing import ClassVar


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


class AuthorityAnchorTransportError(StorageError):
    """A bounded parent/helper transport failure, never an anchor semantic failure.

    ``ProcessFileAuthorityAnchor`` is the only production source of this error.
    The structured fields let core storage distinguish a retryable helper
    transport interruption from a durable-anchor rejection without inspecting
    exception text.
    """

    code = "authority_anchor_transport_error"
    REASONS = frozenset(
        {
            "deadline",
            "helper_eof",
            "helper_pipe",
            "helper_start",
            "helper_start_deadline",
            "helper_start_in_progress",
            "process_lock_deadline",
        }
    )
    OPERATIONS = frozenset({"compare-and-set", "confirm", "initialize", "read"})
    _SAFE_MESSAGES: ClassVar[dict[str, str]] = {
        "deadline": "authority anchor reconciliation exceeded its deadline",
        "helper_eof": "authority anchor helper terminated unexpectedly",
        "helper_pipe": "authority anchor helper pipe failed",
        "helper_start": "authority anchor helper could not be started",
        "helper_start_deadline": "authority anchor helper start exceeded its deadline",
        "helper_start_in_progress": "authority anchor helper start is already in progress",
        "process_lock_deadline": "authority anchor process lock exceeded its deadline",
    }

    def __init__(
        self,
        message: str,
        *,
        reason: str,
        operation: str,
        request_flushed: bool,
        mutation_uncertain: bool,
        helper_pid: int | None,
        helper_exit_code: int | None,
    ) -> None:
        del message
        if not self.valid_metadata_values(
            reason=reason,
            operation=operation,
            request_flushed=request_flushed,
            mutation_uncertain=mutation_uncertain,
            helper_pid=helper_pid,
            helper_exit_code=helper_exit_code,
        ):
            raise ValidationError("authority anchor transport metadata is invalid")
        super().__init__(self._SAFE_MESSAGES[reason])
        self.reason = reason
        self.operation = operation
        self.request_flushed = request_flushed
        self.mutation_uncertain = mutation_uncertain
        self.helper_pid = helper_pid
        self.helper_exit_code = helper_exit_code

    @classmethod
    def valid_metadata_values(
        cls,
        *,
        reason: object,
        operation: object,
        request_flushed: object,
        mutation_uncertain: object,
        helper_pid: object,
        helper_exit_code: object,
    ) -> bool:
        if (
            not isinstance(reason, str)
            or reason not in cls.REASONS
            or not isinstance(operation, str)
            or operation not in cls.OPERATIONS
            or type(request_flushed) is not bool
            or type(mutation_uncertain) is not bool
            or (operation == "read" and mutation_uncertain is True)
            or (
                reason in {"helper_start", "helper_start_deadline", "helper_start_in_progress"}
                and (request_flushed is True or mutation_uncertain is True)
            )
        ):
            return False
        if helper_pid is not None and (
            type(helper_pid) is not int or not 1 <= helper_pid <= (1 << 31) - 1
        ):
            return False
        return helper_exit_code is None or (
            type(helper_exit_code) is int and -(1 << 31) <= helper_exit_code <= (1 << 31) - 1
        )

    @classmethod
    def is_well_formed(cls, value: object) -> bool:
        if type(value) is not cls:
            return False
        try:
            return cls.valid_metadata_values(
                reason=value.reason,
                operation=value.operation,
                request_flushed=value.request_flushed,
                mutation_uncertain=value.mutation_uncertain,
                helper_pid=value.helper_pid,
                helper_exit_code=value.helper_exit_code,
            )
        except AttributeError:
            return False


class DrainingError(StorageError):
    code = "warden_draining"


class CapacityError(StorageError):
    code = "storage_capacity_exhausted"


class ClockUncertainError(PolicyError):
    code = "clock_uncertain"
