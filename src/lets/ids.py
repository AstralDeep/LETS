"""Identifier generation and validation at protocol trust boundaries."""

from __future__ import annotations

import re
from uuid import uuid4

from lets.errors import ValidationError

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_WARDEN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,511}$")


def new_id(kind: str) -> str:
    """Return a collision-resistant, log-friendly opaque identifier."""

    require_identifier(kind, field="identifier kind", maximum=32)
    return f"{kind}_{uuid4().hex}"


def require_identifier(value: str, *, field: str = "identifier", maximum: int = 512) -> str:
    """Validate an untrusted protocol identifier without normalizing it.

    Normalizing identifiers can alias distinct signed payloads.  LETS instead
    rejects surrounding whitespace, control characters, and oversized values.
    """

    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value) > maximum:
        raise ValidationError(f"{field} exceeds {maximum} characters")
    if value != value.strip():
        raise ValidationError(f"{field} must not contain surrounding whitespace")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValidationError(f"{field} must not contain control characters")
    return value


def require_digest(value: str, *, field: str = "digest") -> str:
    """Validate the canonical SHA-256 wire representation used by LETS."""

    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must match sha256:<64 lowercase hex characters>")
    return value


def require_warden_id(value: str, *, field: str = "warden_id") -> str:
    """Require a stable ASCII URI-segment and HTTP-header-safe node identifier."""

    if not isinstance(value, str) or _WARDEN_ID_RE.fullmatch(value) is None:
        raise ValidationError(
            f"{field} must be 1..128 ASCII URI-unreserved characters, start with "
            "an alphanumeric character, and contain no percent escapes"
        )
    return value


def require_key_id(value: str, *, field: str = "key_id") -> str:
    """Require an ASCII HTTP-header-safe cryptographic key identifier."""

    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise ValidationError(f"{field} must be an ASCII transport-safe key identifier")
    return value
