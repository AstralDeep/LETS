"""Deterministic serialization helpers for hashes and signatures."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from typing import Any


def _normalize(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _normalize(asdict(value))
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, bytes):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return {key: _normalize(item) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        raise TypeError(
            "canonical JSON does not accept unordered sets; encode an explicitly sorted array"
        )
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize(item) for item in value]
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, int):
        if not -(1 << 63) <= value <= (1 << 63) - 1:
            raise ValueError("canonical JSON integers must fit in signed 64-bit range")
        return value
    if isinstance(value, float):
        raise ValueError("canonical JSON numbers must be integers; encode fixed-point values")
    raise TypeError(f"cannot canonically serialize {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON for protocol objects.

    LETS signed payloads use integers, strings, booleans, and arrays. Keeping
    that subset avoids cross-runtime floating-point canonicalization traps.
    """

    try:
        return json.dumps(
            _normalize(value),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("canonical JSON strings must be valid Unicode scalar values") from exc


def canonical_digest(value: Any) -> str:
    return f"sha256:{sha256(canonical_json(value)).hexdigest()}"


def strict_json_loads(value: str | bytes | bytearray) -> Any:
    """Parse the LETS-CJ/1 input subset without lossy or ambiguous extensions."""

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key: {key!r}")
            result[key] = item
        return result

    def reject_constant(constant: str) -> Any:
        raise ValueError(f"non-finite JSON number is forbidden: {constant}")

    def reject_float(number: str) -> Any:
        raise ValueError(f"floating-point JSON number is forbidden: {number}")

    parsed = json.loads(
        value,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
        parse_float=reject_float,
    )
    # Reuse the encoder's integer range and Unicode checks before returning a
    # value that may later enter a digest or signature decision.
    canonical_json(parsed)
    return parsed


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    """Decode the unique, unpadded base64url representation emitted by LETS.

    Python's convenience decoder silently ignores non-alphabet characters.
    Signed protocol fields must instead have one canonical spelling so a
    signature string cannot be changed without being rejected at the wire
    boundary.
    """

    if not isinstance(value, str) or "=" in value:
        raise ValueError("base64url value must be unpadded text")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("base64url value must contain ASCII characters") from exc
    padding = b"=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("malformed base64url value") from exc
    if b64url_encode(decoded) != value:
        raise ValueError("base64url value is not canonical")
    return decoded
