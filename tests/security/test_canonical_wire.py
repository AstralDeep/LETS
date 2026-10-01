"""Tests canonical.py's LETS-CJ/1 wire format and deterministic datetime normalization.
Published conformance vectors bind encoding, digests, Unicode, and integer constraints.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from struct import pack
from zoneinfo import ZoneInfo

import pytest

from lets.canonical import (
    b64url_decode,
    b64url_encode,
    canonical_digest,
    canonical_json,
    strict_json_loads,
)
from lets.errors import ValidationError
from lets.models import Receipt, TransferVoucher
from lets.vector import MAX_RESOURCE


@dataclass
class _DateTimePayload:
    timestamp: datetime


class _MissingOffsetTimezone(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        return None

    def dst(self, dt: datetime | None) -> None:
        return None

    def tzname(self, dt: datetime | None) -> None:
        return None


def _new_york_2026_timezone() -> ZoneInfo:
    transitions = (
        int(datetime(2026, 3, 8, 7, tzinfo=UTC).timestamp()),
        int(datetime(2026, 11, 1, 6, tzinfo=UTC).timestamp()),
    )
    tzif = (
        b"TZif\x00"
        + b"\x00" * 15
        + pack(">6I", 0, 0, 0, 2, 2, 8)
        + pack(">2i", *transitions)
        + bytes((1, 0))
        + pack(">iBB", -18000, 0, 0)
        + pack(">iBB", -14400, 1, 4)
        + b"EST\x00EDT\x00"
    )
    return ZoneInfo.from_file(BytesIO(tzif), key="America/New_York")


@pytest.mark.parametrize("zone", [None, _MissingOffsetTimezone()])
def test_lets_cj_rejects_timezone_naive_datetime(zone: tzinfo | None) -> None:
    naive_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=zone)
    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json(naive_dt)

    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json({"timestamp": naive_dt})

    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json([naive_dt])

    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json(_DateTimePayload(timestamp=naive_dt))

    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_digest({"nested": [{"event": _DateTimePayload(timestamp=naive_dt)}]})


def test_lets_cj_accepts_and_normalizes_timezone_aware_datetime() -> None:
    utc_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    offset_dt = datetime(2026, 1, 1, 20, 0, 0, tzinfo=timezone(timedelta(hours=8)))
    negative_offset_dt = datetime(2026, 1, 1, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))

    expected = b'{"timestamp":"2026-01-01T12:00:00.000000Z"}'
    assert canonical_json({"timestamp": utc_dt}) == expected
    assert canonical_json({"timestamp": offset_dt}) == expected
    assert canonical_json({"timestamp": negative_offset_dt}) == expected
    assert canonical_json(_DateTimePayload(timestamp=utc_dt)) == expected
    assert canonical_json(_DateTimePayload(timestamp=offset_dt)) == expected


@pytest.mark.parametrize(
    ("wall_clock", "expected"),
    [
        ((2026, 3, 8, 1, 59, 59, 999999, 0), "2026-03-08T06:59:59.999999Z"),
        ((2026, 3, 8, 3, 0, 0, 0, 0), "2026-03-08T07:00:00.000000Z"),
        ((2026, 11, 1, 1, 30, 0, 0, 0), "2026-11-01T05:30:00.000000Z"),
        ((2026, 11, 1, 1, 30, 0, 0, 1), "2026-11-01T06:30:00.000000Z"),
    ],
)
def test_lets_cj_normalizes_dst_transition_and_fold(
    wall_clock: tuple[int, int, int, int, int, int, int, int], expected: str
) -> None:
    local_dt = datetime(*wall_clock[:7], tzinfo=_new_york_2026_timezone(), fold=wall_clock[7])
    assert canonical_json(local_dt) == f'"{expected}"'.encode()
    assert canonical_json({"events": [{"timestamp": local_dt}]}) == (
        f'{{"events":[{{"timestamp":"{expected}"}}]}}'.encode()
    )
    assert canonical_digest(local_dt) == canonical_digest(local_dt.astimezone(UTC))


@pytest.mark.parametrize("value", [0.0, -0.0, 1.5, math.inf, -math.inf, math.nan])
def test_lets_cj_rejects_every_floating_point_value(value: float) -> None:
    with pytest.raises(ValueError, match="fixed-point"):
        canonical_json({"value": value})


@pytest.mark.parametrize("value", [-(1 << 63) - 1, 1 << 63])
def test_lets_cj_rejects_integers_outside_signed_64_bit(value: int) -> None:
    with pytest.raises(ValueError, match="signed 64-bit"):
        canonical_json({"value": value})


def test_lets_cj_has_fixed_unicode_control_and_int64_vectors() -> None:
    assert (
        canonical_json(
            {
                "\U0001f600": "astral",
                "\ue000": "private",
                "control": "\x00\n\t",
                "max": (1 << 63) - 1,
                "min": -(1 << 63),
            }
        )
        == (
            '{"control":"\\u0000\\n\\t","max":9223372036854775807,'
            '"min":-9223372036854775808,"\ue000":"private","\U0001f600":"astral"}'
        ).encode()
    )
    assert canonical_json({"é": 1}) != canonical_json({"e\u0301": 1})


def test_lets_cj_rejects_non_string_object_keys_instead_of_aliasing_them() -> None:
    with pytest.raises(TypeError, match="keys must be strings"):
        canonical_json({1: "integer", "1": "text"})


def test_lets_cj_datetime_timezone_handling() -> None:
    naive = datetime(2026, 1, 1, 12, 0, 0)
    with pytest.raises(ValueError, match="timezone-naive"):
        canonical_json({"nested": [{"deep": [naive]}]})

    @dataclass
    class EventRecord:
        timestamp: datetime
        name: str

    with pytest.raises(ValueError, match="timezone-naive"):
        canonical_json({"event": EventRecord(naive, "unanchored")})

    utc_dt = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
    est_dt = datetime(2026, 1, 1, 7, 0, 0, tzinfo=timezone(timedelta(hours=-5)))
    tokyo_dt = datetime(2026, 1, 1, 21, 0, 0, tzinfo=timezone(timedelta(hours=9)))

    expected = b'{"when":"2026-01-01T12:00:00.000000Z"}'
    assert canonical_json({"when": utc_dt}) == expected
    assert canonical_json({"when": est_dt}) == expected
    assert canonical_json({"when": tokyo_dt}) == expected

    aware_record = EventRecord(utc_dt, "anchored")
    assert canonical_json({"event": aware_record}) == (
        b'{"event":{"name":"anchored","timestamp":"2026-01-01T12:00:00.000000Z"}}'
    )

    micro_dt = datetime(2026, 6, 15, 10, 20, 30, 123456, tzinfo=UTC)
    assert canonical_json({"t": micro_dt}) == b'{"t":"2026-06-15T10:20:30.123456Z"}'


def test_base64url_decoder_rejects_alternate_spellings() -> None:
    encoded = b64url_encode(b"signed bytes")
    assert b64url_decode(encoded) == b"signed bytes"
    for malformed in (encoded + "=", encoded + "!", "é", "A"):
        with pytest.raises(ValueError):
            b64url_decode(malformed)


def test_signed_record_parsers_report_missing_and_unknown_fields_as_validation_errors() -> None:
    with pytest.raises(ValidationError, match="missing transfer voucher fields"):
        TransferVoucher.from_dict({"type": TransferVoucher.WIRE_TYPE})
    with pytest.raises(ValidationError, match="unknown receipt fields"):
        Receipt.from_dict({"type": Receipt.WIRE_TYPE, "unexpected": True})


def test_wire_integer_overflow_is_rejected_before_sqlite_binding() -> None:
    data = {
        "type": TransferVoucher.WIRE_TYPE,
        "tenant_id": "tenant",
        "envelope_id": "envelope",
        "config_epoch": 1,
        "transfer_id": "transfer",
        "source_warden": "source",
        "target_warden": "target",
        "policy_id": "policy",
        "policy_version": "v1",
        "policy_digest": "sha256:" + "0" * 64,
        "sequence": MAX_RESOURCE + 1,
        "amount": [1],
        "issued_at_ns": 1,
        "key_id": "key",
        "signature": "signature",
    }
    with pytest.raises(ValidationError, match="signed 64-bit"):
        TransferVoucher.from_dict(data)


@pytest.mark.parametrize(
    "document",
    [
        b'{"signed":1,"signed":2}',
        b'{"nested":{"key":1,"key":2}}',
        b'{"value":1.5}',
        b'{"value":NaN}',
        b'{"value":9223372036854775808}',
        b'{"value":"\\ud800"}',
    ],
)
def test_strict_wire_parser_rejects_ambiguous_or_nonportable_json(document: bytes) -> None:
    with pytest.raises(ValueError):
        strict_json_loads(document)


def test_published_cross_language_canonicalization_vectors() -> None:
    path = Path(__file__).parents[2] / "protocol" / "canonicalization-vectors.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))
    assert vectors["version"] == "LETS-CJ/1"
    for vector in vectors["valid"]:
        encoded = canonical_json(vector["input"])
        assert encoded.decode("utf-8") == vector["canonical"]
        assert sha256(encoded).hexdigest() == vector["sha256"]
    for document in vectors["invalid_json"]:
        with pytest.raises(ValueError):
            strict_json_loads(document)
    for vector in vectors["base64url"]:
        raw = bytes.fromhex(vector["bytes_hex"])
        assert b64url_encode(raw) == vector["encoded"]
        assert b64url_decode(vector["encoded"]) == raw
    for encoded in vectors["invalid_base64url"]:
        with pytest.raises(ValueError):
            b64url_decode(encoded)


@dataclass(frozen=True)
class NestedRecord:
    occurred_at: datetime


def test_aware_equivalent_instants_have_identical_canonical_bytes() -> None:
    utc_value = datetime(2025, 3, 30, 1, 30, tzinfo=UTC)
    offset_value = datetime(
        2025,
        3,
        30,
        3,
        30,
        tzinfo=timezone(timedelta(hours=2)),
    )

    assert canonical_json(utc_value) == canonical_json(offset_value)


def test_timezone_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json(datetime(2025, 1, 1, 12, 0))


def test_nested_dataclass_timezone_naive_datetime_is_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        canonical_json(NestedRecord(datetime(2025, 1, 1, 12, 0)))


def test_aware_datetime_offsets_normalize_across_date_boundaries() -> None:
    utc_value = datetime(2025, 3, 29, 23, 30, tzinfo=UTC)
    offset_value = datetime(
        2025,
        3,
        30,
        1,
        30,
        tzinfo=timezone(timedelta(hours=2)),
    )

    expected = b'{"occurred_at":"2025-03-29T23:30:00.000000Z"}'
    assert canonical_json({"occurred_at": utc_value}) == expected
    assert canonical_json(NestedRecord(offset_value)) == expected
