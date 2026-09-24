"""Local conservation-equation checks a warden uses to prove its ledger is consistent,
plus assert_nested_expiry for lease nesting. service.py assembles
ConservationSnapshot's identities into the global envelope invariant.
"""

from __future__ import annotations

from dataclasses import dataclass

from lets.errors import InvariantError, ValidationError
from lets.vector import ResourceVector, add


@dataclass(frozen=True, slots=True)
class ConservationSnapshot:
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
        return add(self.initial_share, self.transferred_in)

    @property
    def accounted_total(self) -> ResourceVector:
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
    if child_expires_at_ns > parent_expires_at_ns:
        raise InvariantError(
            f"nested expiry violated: child={child_expires_at_ns} > parent={parent_expires_at_ns}"
        )
