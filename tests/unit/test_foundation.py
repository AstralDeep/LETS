from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

import pytest

from lets.canonical import b64url_decode, b64url_encode, canonical_digest, canonical_json
from lets.clock import ManualClock, SystemClock
from lets.errors import ValidationError
from lets.vector import MAX_RESOURCE, add, pack, subtract, unpack, vector


class ExampleState(StrEnum):
    READY = "ready"


@dataclass(frozen=True)
class ExampleRecord:
    state: ExampleState
    rights: tuple[int, ...]


def test_canonical_json_is_stable_and_normalizes_protocol_values() -> None:
    left = {"z": 1, "record": ExampleRecord(ExampleState.READY, (2, 3)), "caps": ["a", "b"]}
    right = {"caps": ["a", "b"], "record": {"rights": [2, 3], "state": "ready"}, "z": 1}

    assert canonical_json(left) == canonical_json(right)
    assert canonical_digest(left) == canonical_digest(right)


def test_canonical_json_rejects_unordered_sets() -> None:
    with pytest.raises(TypeError, match="unordered sets"):
        canonical_json({"caps": {"a", "b"}})


def test_canonical_json_rejects_nan_and_unknown_objects() -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": math.nan})
    with pytest.raises(TypeError):
        canonical_json(object())


def test_base64url_round_trip_has_no_padding() -> None:
    encoded = b64url_encode(b"\x00\xffsigned payload")
    assert "=" not in encoded
    assert b64url_decode(encoded) == b"\x00\xffsigned payload"


@pytest.mark.parametrize(
    "candidate",
    [(), (-1,), (True,), (1.0,), (MAX_RESOURCE + 1,)],
)
def test_vector_rejects_invalid_values(candidate: tuple[object, ...]) -> None:
    with pytest.raises(ValidationError):
        vector(candidate)  # type: ignore[arg-type]


def test_vector_checked_arithmetic_and_binary_round_trip() -> None:
    left = vector((5, 9, 0))
    right = vector((2, 4, 0))

    assert add(left, right) == (7, 13, 0)
    assert subtract(left, right) == (3, 5, 0)
    assert unpack(pack(left), dimensions=3) == left

    with pytest.raises(ValidationError, match="insufficient"):
        subtract(right, left)
    with pytest.raises(ValidationError, match="overflow"):
        add((MAX_RESOURCE,), (1,))


@pytest.mark.parametrize("encoded", [b"", b"\x00", b"\x00\x01", b"\x00\x01\x00"])
def test_vector_unpack_rejects_truncated_data(encoded: bytes) -> None:
    with pytest.raises(ValidationError):
        unpack(encoded)


def test_clock_inputs_are_monotonic_and_validated() -> None:
    clock = ManualClock(current_ns=10)
    assert clock.advance(5) == 15
    with pytest.raises(ValidationError):
        clock.advance(-1)
    with pytest.raises(ValidationError):
        SystemClock(declared_uncertainty_ns=-1)
