"""Local conservation checks for a durable LETS warden.

The global envelope invariant is assembled from these local identities.  A
warden keeps cumulative accepted-in and prepared-out totals so transfer
records can be compacted without losing the accounting proof.
"""

from __future__ import annotations

from dataclasses import dataclass

from lets.errors import InvariantError, ValidationError
from lets.vector import ResourceVector, add


@dataclass(frozen=True, slots=True)
class ConservationSnapshot:
    """The durable terms in one warden's conservation equation.

    ``initial_share + transferred_in`` must equal
    ``free_pool + residual + consumed + transferred_out``.  Before a prepared
    transfer is accepted, its amount therefore appears globally as
    ``transferred_out - transferred_in`` (the in-flight term).  Once accepted,
    the peer's cumulative inbound total cancels it exactly.
    """

    initial_share: ResourceVector
    transferred_in: ResourceVector
    transferred_out: ResourceVector
    free_pool: ResourceVector
    residual: ResourceVector
    consumed: ResourceVector

    def __post_init__(self) -> None:
        dimensions = len(self.initial_share)
        if dimensions == 0:
            raise ValidationError("conservation vectors must not be empty")
        for name in (
            "transferred_in",
            "transferred_out",
            "free_pool",
            "residual",
            "consumed",
        ):
            value = getattr(self, name)
            if len(value) != dimensions:
                raise ValidationError(f"{name} has {len(value)} dimensions; expected {dimensions}")

    @property
    def available_total(self) -> ResourceVector:
        """Rights ever made locally available, including accepted transfers."""

        return add(self.initial_share, self.transferred_in)

    @property
    def accounted_total(self) -> ResourceVector:
        """Rights currently represented by a durable local ledger category."""

        return add(
            add(self.free_pool, self.residual),
            add(self.consumed, self.transferred_out),
        )

    @property
    def healthy(self) -> bool:
        return self.available_total == self.accounted_total

    def assert_healthy(self) -> None:
        if not self.healthy:
            raise InvariantError(
                "local conservation violated: "
                f"available={self.available_total}, accounted={self.accounted_total}"
            )


def assert_nested_expiry(*, child_expires_at_ns: int, parent_expires_at_ns: int) -> None:
    """Reject a lease interval that extends past its immediate parent."""

    if child_expires_at_ns > parent_expires_at_ns:
        raise InvariantError(
            f"nested expiry violated: child={child_expires_at_ns} > parent={parent_expires_at_ns}"
        )
