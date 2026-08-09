from __future__ import annotations

import json
import math
from hashlib import sha256
from pathlib import Path

import pytest

from lets.canonical import b64url_decode, b64url_encode, canonical_json, strict_json_loads
from lets.errors import ValidationError
from lets.models import Receipt, TransferVoucher
from lets.vector import MAX_RESOURCE


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
    # LETS-CJ/1 does not normalize Unicode: signed identifiers remain byte-distinct.
    assert canonical_json({"é": 1}) != canonical_json({"e\u0301": 1})


def test_lets_cj_rejects_non_string_object_keys_instead_of_aliasing_them() -> None:
    with pytest.raises(TypeError, match="keys must be strings"):
        canonical_json({1: "integer", "1": "text"})


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
