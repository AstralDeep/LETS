"""Checked resource-vector arithmetic used by every conservation boundary."""

from __future__ import annotations

import struct
from collections.abc import Iterable, Sequence
from typing import TypeAlias

from lets.errors import ValidationError

ResourceVector: TypeAlias = tuple[int, ...]
MAX_RESOURCE = (1 << 63) - 1


def vector(
    value: Sequence[int] | Iterable[int], *, dimensions: int | None = None
) -> ResourceVector:
    result = tuple(value)
    if dimensions is not None and len(result) != dimensions:
        raise ValidationError(
            f"resource-vector dimension mismatch: expected {dimensions}, got {len(result)}"
        )
    if not result:
        raise ValidationError("resource vectors must contain at least one dimension")
    for item in result:
        if isinstance(item, bool) or not isinstance(item, int):
            raise ValidationError("resource-vector values must be integers")
        if item < 0:
            raise ValidationError("resource-vector values must be non-negative")
        if item > MAX_RESOURCE:
            raise ValidationError(f"resource-vector values must not exceed {MAX_RESOURCE}")
    return result


def same_dimensions(left: ResourceVector, right: ResourceVector) -> None:
    if len(left) != len(right):
        raise ValidationError(f"resource-vector dimension mismatch: {len(left)} != {len(right)}")


def add(left: ResourceVector, right: ResourceVector) -> ResourceVector:
    same_dimensions(left, right)
    output = tuple(a + b for a, b in zip(left, right, strict=True))
    if any(item > MAX_RESOURCE for item in output):
        raise ValidationError("resource-vector addition overflow")
    return output


def subtract(left: ResourceVector, right: ResourceVector) -> ResourceVector:
    same_dimensions(left, right)
    if any(b > a for a, b in zip(left, right, strict=True)):
        raise ValidationError(f"insufficient escrow rights: {left} - {right}")
    return tuple(a - b for a, b in zip(left, right, strict=True))


def less_than_or_equal(left: ResourceVector, right: ResourceVector) -> bool:
    same_dimensions(left, right)
    return all(a <= b for a, b in zip(left, right, strict=True))


def zero(dimensions: int) -> ResourceVector:
    if dimensions <= 0:
        raise ValidationError("resource-vector dimensions must be positive")
    return (0,) * dimensions


def total(vectors: Iterable[ResourceVector], dimensions: int) -> ResourceVector:
    result = zero(dimensions)
    for item in vectors:
        result = add(result, item)
    return result


def pack(value: ResourceVector) -> bytes:
    """Encode a vector as a compact, endian-stable SQLite BLOB."""

    checked = vector(value)
    if len(checked) > 0xFFFF:
        raise ValidationError("resource vector has too many dimensions")
    return struct.pack(f">H{len(checked)}Q", len(checked), *checked)


def unpack(value: bytes, *, dimensions: int | None = None) -> ResourceVector:
    if len(value) < 2:
        raise ValidationError("truncated resource-vector encoding")
    count = struct.unpack_from(">H", value)[0]
    expected = 2 + 8 * count
    if len(value) != expected:
        raise ValidationError("invalid resource-vector encoding length")
    result = tuple(struct.unpack_from(f">{count}Q", value, 2))
    return vector(result, dimensions=dimensions)
