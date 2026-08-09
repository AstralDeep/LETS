from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from lets.errors import ValidationError
from lets.vector import MAX_RESOURCE, add, pack, subtract, unpack, vector


@st.composite
def _compatible_vectors(
    draw: st.DrawFn,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    dimensions = draw(st.integers(min_value=1, max_value=8))
    left = tuple(
        draw(
            st.lists(
                st.integers(min_value=0, max_value=1_000_000),
                min_size=dimensions,
                max_size=dimensions,
            )
        )
    )
    right = tuple(
        draw(
            st.lists(
                st.integers(min_value=0, max_value=1_000_000),
                min_size=dimensions,
                max_size=dimensions,
            )
        )
    )
    return left, right


@given(_compatible_vectors())
def test_checked_add_subtract_round_trip(
    operands: tuple[tuple[int, ...], tuple[int, ...]],
) -> None:
    left, right = operands
    total = add(vector(left), vector(right))
    assert subtract(total, vector(right)) == vector(left)
    assert subtract(total, vector(left)) == vector(right)


@given(
    st.lists(
        st.integers(min_value=0, max_value=MAX_RESOURCE),
        min_size=1,
        max_size=32,
    )
)
def test_vector_binary_encoding_is_canonical_and_round_trips(values: list[int]) -> None:
    checked = vector(values)
    encoded = pack(checked)
    assert unpack(encoded) == checked
    assert pack(unpack(encoded)) == encoded


@given(st.binary(max_size=80))
def test_arbitrary_binary_vector_input_never_decodes_to_a_noncanonical_value(
    encoded: bytes,
) -> None:
    try:
        decoded = unpack(encoded)
    except ValidationError:
        return
    assert pack(decoded) == encoded


def test_overflow_underflow_negative_bool_and_dimension_mismatch_fail_closed() -> None:
    with pytest.raises(ValidationError, match="overflow"):
        add((MAX_RESOURCE,), (1,))
    with pytest.raises(ValidationError, match="insufficient"):
        subtract((0,), (1,))
    for malformed in ((-1,), (True,), (1.0,)):
        with pytest.raises(ValidationError):
            vector(malformed)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="dimension mismatch"):
        add((1,), (1, 2))
