"""Vendor-neutral production runtime provider.

This profile keeps secret-key operations outside the LETS process.  It invokes
one operator-installed helper without a shell, verifies short-lived Ed25519 JWT
access tokens, and binds the node to independently mounted authority-anchor and
audit-archive files.  Deployments can replace it with a cloud KMS, PKCS#11,
SPIFFE, or OIDC provider through the same runtime-provider protocol.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from lets.audit import SQLiteAuditSink
from lets.auth import AuthenticationError
from lets.authority import ProcessFileAuthorityAnchor
from lets.canonical import b64url_decode, strict_json_loads
from lets.errors import SignatureError, ValidationError
from lets.ids import require_identifier, require_key_id
from lets.models import IdentityContext
from lets.runtime import RuntimeBindings, RuntimeProviderContext

_REQUIRED_OPTIONS = frozenset(
    {
        "signer_command_json",
        "signer_key_id",
        "signer_public_key",
        "identity_keys_file",
        "identity_issuer",
        "identity_audience",
        "authority_anchor_path",
        "audit_archive_path",
    }
)
_OPTIONAL_OPTIONS = frozenset(
    {
        "signer_timeout_s",
        "identity_clock_skew_s",
        "identity_max_lifetime_s",
        "authority_timeout_s",
    }
)
_MAX_JWT_BYTES = 16_384
_MAX_KEY_FILE_BYTES = 1_048_576
_MAX_SCOPES = 128


def _bounded_seconds(
    value: str | None,
    field: str,
    *,
    default: float,
    minimum: float,
    maximum: float,
) -> float:
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be a number") from exc
    if not minimum <= parsed <= maximum:
        raise ValidationError(f"{field} must be between {minimum:g} and {maximum:g} seconds")
    return parsed


def _absolute_file(value: str, field: str, *, must_exist: bool = True) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValidationError(f"{field} must be an absolute path")
    resolved = path.resolve()
    if must_exist and (not resolved.exists() or not resolved.is_file()):
        raise ValidationError(f"{field} must name an existing regular file")
    return resolved


def _read_bounded(path: Path, field: str) -> bytes:
    try:
        size = path.stat().st_size
        if size <= 0 or size > _MAX_KEY_FILE_BYTES:
            raise ValidationError(f"{field} size is outside the supported range")
        return path.read_bytes()
    except OSError as exc:
        raise ValidationError(f"{field} could not be read") from exc


def _require_immutable_executable_path(path: Path, field: str) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ValidationError(f"{field} metadata could not be read") from exc
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValidationError(f"{field} must not be group- or world-writable")


def _one_header(request: object, name: str) -> str | None:
    headers = getattr(request, "headers", None)
    if not isinstance(headers, Mapping):
        raise AuthenticationError("the authentication request has no HTTP headers")
    getlist = getattr(headers, "getlist", None)
    if callable(getlist):
        values = tuple(getlist(name))
    else:
        values = tuple(value for key, value in headers.items() if str(key).casefold() == name)
    if len(values) > 1:
        raise AuthenticationError(f"duplicate {name} headers are forbidden")
    if not values:
        return None
    value = values[0]
    if not isinstance(value, str):
        raise AuthenticationError(f"the {name} header must be text")
    return value


class CommandEd25519Signer:
    """Ed25519 signer backed by an operator-controlled helper process.

    The helper receives the exact bytes to sign on standard input and must emit
    one unpadded base64url 64-byte signature.  No shell is involved.  A helper
    can therefore bridge LETS to PKCS#11, a cloud KMS, or an HSM sidecar without
    exposing private material to this process.
    """

    def __init__(
        self,
        *,
        warden_id: str,
        key_id: str,
        public_key: bytes,
        command: Sequence[str],
        timeout_s: float,
    ) -> None:
        self.warden_id = warden_id
        self.key_id = require_key_id(key_id, field="generic signer key_id")
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValidationError("generic signer public key must contain 32 bytes")
        self._public_key = public_key
        if (
            not command
            or len(command) > 16
            or any(
                not isinstance(item, str) or not item or len(item) > 2048 or "\x00" in item
                for item in command
            )
        ):
            raise ValidationError("signer command must contain 1..16 bounded string arguments")
        executable = _absolute_file(command[0], "signer command executable")
        _require_immutable_executable_path(executable, "signer command executable")
        for argument in command[1:]:
            candidate = Path(argument)
            if candidate.is_absolute() and candidate.exists() and candidate.is_file():
                _require_immutable_executable_path(candidate, "signer command file argument")
        self._command = (str(executable), *command[1:])
        self._timeout_s = timeout_s

    @property
    def public_key_bytes(self) -> bytes:
        return self._public_key

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes) or not payload or len(payload) > _MAX_JWT_BYTES * 8:
            raise SignatureError("signer payload size is outside the supported range")
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            result = subprocess.run(
                self._command,
                input=payload,
                capture_output=True,
                check=False,
                timeout=self._timeout_s,
                creationflags=creation_flags,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SignatureError("external signer did not complete within its contract") from exc
        if result.returncode != 0:
            raise SignatureError("external signer rejected the signing request")
        if len(result.stdout) > 256 or len(result.stderr) > 4096:
            raise SignatureError("external signer returned an oversized response")
        try:
            encoded = result.stdout.strip().decode("ascii")
            signature = b64url_decode(encoded)
        except (UnicodeError, ValueError) as exc:
            raise SignatureError("external signer returned malformed base64url") from exc
        if len(signature) != 64:
            raise SignatureError("external signer returned a non-Ed25519 signature")
        try:
            VerifyKey(self._public_key).verify(payload, signature)
        except BadSignatureError as exc:
            raise SignatureError(
                "external signer signature does not match the configured key"
            ) from exc
        return signature


class Ed25519JWTAuthenticator:
    """Strict short-lived EdDSA JWT authenticator for human/service identities."""

    def __init__(
        self,
        *,
        key_file: Path,
        issuer: str,
        audience: str,
        tenant_id: str,
        clock_skew_s: int,
        max_lifetime_s: int,
    ) -> None:
        self._issuer = require_identifier(issuer, field="identity issuer")
        self._audience = require_identifier(audience, field="identity audience")
        self._tenant_id = require_identifier(tenant_id, field="identity tenant")
        self._clock_skew_s = clock_skew_s
        self._max_lifetime_s = max_lifetime_s
        raw = _read_bounded(key_file, "identity key file")
        try:
            decoded = strict_json_loads(raw)
        except (UnicodeError, ValueError) as exc:
            raise ValidationError("identity key file is not strict JSON") from exc
        if not isinstance(decoded, Mapping) or set(decoded) != {"keys"}:
            raise ValidationError("identity key file must contain exactly a keys array")
        entries = decoded.get("keys")
        if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)) or not entries:
            raise ValidationError("identity key file keys must be a non-empty array")
        if len(entries) > 64:
            raise ValidationError("identity key file contains too many keys")
        keys: dict[str, VerifyKey] = {}
        material: set[bytes] = set()
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {"kid", "public_key"}:
                raise ValidationError("identity key entries require exactly kid and public_key")
            raw_kid = entry.get("kid")
            if not isinstance(raw_kid, str):
                raise ValidationError("identity JWT kid must be text")
            kid = require_key_id(raw_kid, field="identity JWT kid")
            encoded = entry.get("public_key")
            if not isinstance(encoded, str):
                raise ValidationError("identity JWT public_key must be base64url text")
            try:
                public_key = b64url_decode(encoded)
            except ValueError as exc:
                raise ValidationError("identity JWT public_key is malformed") from exc
            if len(public_key) != 32:
                raise ValidationError("identity JWT public_key must contain 32 bytes")
            if kid in keys or public_key in material:
                raise ValidationError("identity JWT keys must have unique IDs and material")
            keys[kid] = VerifyKey(public_key)
            material.add(public_key)
        self._keys = keys

    @staticmethod
    def _integer_claim(payload: Mapping[str, Any], field: str) -> int:
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise AuthenticationError(f"JWT {field} must be a non-negative integer")
        return value

    def authenticate(self, request: object) -> IdentityContext:
        authorization = _one_header(request, "authorization")
        if authorization is None:
            raise AuthenticationError("a short-lived EdDSA bearer token is required")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.casefold() != "bearer" or not token or " " in token:
            raise AuthenticationError("the Authorization header is malformed")
        try:
            encoded = token.encode("ascii", "strict")
        except UnicodeEncodeError as exc:
            raise AuthenticationError(
                "the bearer JWT must use ASCII compact serialization"
            ) from exc
        if len(encoded) > _MAX_JWT_BYTES or token.count(".") != 2:
            raise AuthenticationError("the bearer JWT is malformed or oversized")
        encoded_header, encoded_payload, encoded_signature = token.split(".")
        try:
            header = strict_json_loads(b64url_decode(encoded_header))
            payload = strict_json_loads(b64url_decode(encoded_payload))
            signature = b64url_decode(encoded_signature)
        except (UnicodeError, ValueError) as exc:
            raise AuthenticationError(
                "the bearer JWT is not strict canonical base64url JSON"
            ) from exc
        if not isinstance(header, Mapping) or set(header) != {"alg", "kid", "typ"}:
            raise AuthenticationError("the bearer JWT header is not accepted")
        if header.get("alg") != "EdDSA" or header.get("typ") not in {"JWT", "at+jwt"}:
            raise AuthenticationError("the bearer JWT algorithm or type is not accepted")
        kid = header.get("kid")
        if not isinstance(kid, str) or kid not in self._keys:
            raise AuthenticationError("the bearer JWT key is not trusted")
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        try:
            self._keys[kid].verify(signing_input, signature)
        except (BadSignatureError, TypeError, ValueError) as exc:
            raise AuthenticationError("the bearer JWT signature is invalid") from exc
        if not isinstance(payload, Mapping) or len(payload) > 64:
            raise AuthenticationError("the bearer JWT claims are malformed")
        issuer = payload.get("iss")
        subject = payload.get("sub")
        tenant = payload.get("tenant_id")
        token_id = payload.get("jti")
        if issuer != self._issuer or tenant != self._tenant_id:
            raise AuthenticationError("the bearer JWT issuer or tenant is not accepted")
        if not all(isinstance(item, str) for item in (subject, token_id)):
            raise AuthenticationError("the bearer JWT identity claims are malformed")
        try:
            require_identifier(cast(str, token_id), field="identity token jti")
        except ValidationError as exc:
            raise AuthenticationError("the bearer JWT token identifier is invalid") from exc
        audience = payload.get("aud")
        if isinstance(audience, str):
            audiences = (audience,)
        elif isinstance(audience, Sequence) and not isinstance(audience, (str, bytes)):
            audiences = tuple(audience)
        else:
            raise AuthenticationError("the bearer JWT audience claim is malformed")
        if (
            self._audience not in audiences
            or len(audiences) > 16
            or any(not isinstance(item, str) for item in audiences)
        ):
            raise AuthenticationError("the bearer JWT audience is not accepted")
        issued_at = self._integer_claim(payload, "iat")
        not_before = self._integer_claim(payload, "nbf")
        expires_at = self._integer_claim(payload, "exp")
        now = int(time.time())
        if issued_at > now + self._clock_skew_s or not_before > now + self._clock_skew_s:
            raise AuthenticationError("the bearer JWT is not yet valid")
        if expires_at <= now - self._clock_skew_s:
            raise AuthenticationError("the bearer JWT has expired")
        if not issued_at <= not_before <= expires_at:
            raise AuthenticationError("the bearer JWT validity interval is inconsistent")
        if expires_at - issued_at > self._max_lifetime_s:
            raise AuthenticationError("the bearer JWT lifetime exceeds policy")
        scope_claim = payload.get("scope")
        if not isinstance(scope_claim, str) or not scope_claim or "  " in scope_claim:
            raise AuthenticationError("the bearer JWT scope claim is malformed")
        scopes = frozenset(scope_claim.split(" "))
        if not scopes or len(scopes) > _MAX_SCOPES or "" in scopes:
            raise AuthenticationError("the bearer JWT scope claim is outside policy")
        try:
            return IdentityContext(
                subject_id=cast(str, subject),
                tenant_id=cast(str, tenant),
                scopes=scopes,
                authentication_method="jwt-eddsa",
            )
        except ValidationError as exc:
            raise AuthenticationError("the bearer JWT identity is invalid") from exc


def _command(value: str) -> tuple[str, ...]:
    try:
        decoded = strict_json_loads(value)
    except (UnicodeError, ValueError) as exc:
        raise ValidationError("signer_command_json must be strict JSON") from exc
    if not isinstance(decoded, Sequence) or isinstance(decoded, (str, bytes)):
        raise ValidationError("signer_command_json must encode an argument array")
    return tuple(decoded)


def open_runtime(context: RuntimeProviderContext) -> RuntimeBindings:
    """Create the generic production bindings selected by the runtime loader."""

    options = context.options
    missing = _REQUIRED_OPTIONS - options.keys()
    unknown = options.keys() - _REQUIRED_OPTIONS - _OPTIONAL_OPTIONS
    if missing or unknown:
        detail = f"missing={sorted(missing)}, unknown={sorted(unknown)}"
        raise ValidationError(f"generic provider option mismatch: {detail}")
    try:
        public_key = b64url_decode(options["signer_public_key"])
    except ValueError as exc:
        raise ValidationError("signer_public_key must be canonical base64url") from exc
    signer_timeout = _bounded_seconds(
        options.get("signer_timeout_s"),
        "signer_timeout_s",
        default=5.0,
        minimum=0.05,
        maximum=30.0,
    )
    authority_timeout = _bounded_seconds(
        options.get("authority_timeout_s"),
        "authority_timeout_s",
        default=5.0,
        minimum=0.05,
        maximum=30.0,
    )
    skew = int(
        _bounded_seconds(
            options.get("identity_clock_skew_s"),
            "identity_clock_skew_s",
            default=5,
            minimum=0,
            maximum=60,
        )
    )
    lifetime = int(
        _bounded_seconds(
            options.get("identity_max_lifetime_s"),
            "identity_max_lifetime_s",
            default=900,
            minimum=30,
            maximum=3600,
        )
    )
    signer = CommandEd25519Signer(
        warden_id=context.warden_id,
        key_id=options["signer_key_id"],
        public_key=public_key,
        command=_command(options["signer_command_json"]),
        timeout_s=signer_timeout,
    )
    authenticator = Ed25519JWTAuthenticator(
        key_file=_absolute_file(options["identity_keys_file"], "identity_keys_file"),
        issuer=options["identity_issuer"],
        audience=options["identity_audience"],
        tenant_id=context.tenant_id,
        clock_skew_s=skew,
        max_lifetime_s=lifetime,
    )
    anchor_path = _absolute_file(
        options["authority_anchor_path"],
        "authority_anchor_path",
        must_exist=False,
    )
    if not anchor_path.parent.is_dir():
        raise ValidationError("authority_anchor_path parent directory must already exist")
    audit_path = _absolute_file(options["audit_archive_path"], "audit_archive_path")
    protected_directories = {
        context.config_path.parent.resolve(),
        context.database_path.parent.resolve(),
    }
    if any(
        anchor_path.is_relative_to(directory) or audit_path.is_relative_to(directory)
        for directory in protected_directories
    ):
        raise ValidationError("authority anchor and audit archive must be outside node state")
    if anchor_path.parent == audit_path.parent:
        raise ValidationError("authority anchor and audit archive require separate mount roots")
    anchor = ProcessFileAuthorityAnchor(anchor_path, timeout_s=authority_timeout)
    return RuntimeBindings(
        warden_id=context.warden_id,
        tenant_id=context.tenant_id,
        signer=signer,
        authenticator=authenticator,
        production_capable=True,
        authority_anchor=anchor,
        audit_sink=SQLiteAuditSink(audit_path),
        cleanup=anchor.close,
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Provision the generic provider's independent audit archive explicitly."""

    parser = argparse.ArgumentParser(prog="lets-provider")
    subparsers = parser.add_subparsers(dest="command", required=True)
    audit = subparsers.add_parser("audit-init", help="initialize an independent audit archive")
    audit.add_argument("--path", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command != "audit-init":  # pragma: no cover - argparse owns this boundary
        parser.error("unsupported provider command")
    path = Path(arguments.path)
    if not path.is_absolute():
        parser.error("--path must be absolute")
    path.parent.mkdir(parents=True, exist_ok=True)
    sink = SQLiteAuditSink.initialize(path)
    print(json.dumps({"audit_archive": str(sink.path), "status": "initialized"}, sort_keys=True))
    return 0


__all__ = [
    "CommandEd25519Signer",
    "Ed25519JWTAuthenticator",
    "main",
    "open_runtime",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
