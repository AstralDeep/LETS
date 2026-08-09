"""Injectable time sources and explicit uncertainty policy inputs."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol

from lets.errors import ValidationError
from lets.vector import MAX_RESOURCE


class Clock(Protocol):
    def now_ns(self) -> int: ...

    def uncertainty_ns(self) -> int: ...


@dataclass(frozen=True, slots=True)
class SystemClock:
    """Wall clock with a caller-declared synchronization uncertainty."""

    declared_uncertainty_ns: int = 0

    def __post_init__(self) -> None:
        if (
            isinstance(self.declared_uncertainty_ns, bool)
            or not isinstance(self.declared_uncertainty_ns, int)
            or self.declared_uncertainty_ns < 0
            or self.declared_uncertainty_ns > MAX_RESOURCE
        ):
            raise ValidationError("clock uncertainty must be a non-negative signed 64-bit integer")

    def now_ns(self) -> int:
        return time.time_ns()

    def uncertainty_ns(self) -> int:
        return self.declared_uncertainty_ns


@dataclass(slots=True)
class ManualClock:
    """Deterministic clock useful for simulation and host integrations."""

    current_ns: int = 0
    declared_uncertainty_ns: int = 0

    def __post_init__(self) -> None:
        for name, value in (
            ("manual clock time", self.current_ns),
            ("manual clock uncertainty", self.declared_uncertainty_ns),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > MAX_RESOURCE
            ):
                raise ValidationError(f"{name} must be a non-negative signed 64-bit integer")

    def now_ns(self) -> int:
        return self.current_ns

    def uncertainty_ns(self) -> int:
        return self.declared_uncertainty_ns

    def advance(self, nanoseconds: int) -> int:
        if isinstance(nanoseconds, bool) or not isinstance(nanoseconds, int) or nanoseconds < 0:
            raise ValidationError("manual clock advance must be a non-negative integer")
        if self.current_ns > MAX_RESOURCE - nanoseconds:
            raise ValidationError("manual clock advance exceeds signed 64-bit time")
        self.current_ns += nanoseconds
        return self.current_ns
