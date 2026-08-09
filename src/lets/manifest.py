"""Validated and signed bootstrap manifests for a LETS warden cluster."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self
from urllib.parse import urlsplit

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from lets.canonical import b64url_decode, canonical_digest, canonical_json, strict_json_loads
from lets.errors import SignatureError, ValidationError
from lets.ids import require_identifier, require_key_id, require_warden_id
from lets.policy import PolicySpec, ResourceDimension
from lets.vector import MAX_RESOURCE, ResourceVector, add, vector, zero

API_VERSION = "lets.manifest/v1"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_WARDENS = 1024
MAX_WARDEN_KEYS = 32
MAX_MANIFEST_POLICIES = 256
MAX_MANIFEST_SIGNATURES = 64
_RFC3339 = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,9})?(?P<offset>Z|[+-]\d{2}:\d{2})$"
)
_EXTENSION_NAME = re.compile(r"^[a-z][a-z0-9.-]+/[a-zA-Z0-9._-]+$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _strict(data: Mapping[str, Any], allowed: set[str], label: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise ValidationError(f"unknown {label} fields: {sorted(unknown)}")


def _validate_extensions(extensions: Mapping[str, Any], label: str) -> None:
    if not isinstance(extensions, Mapping):
        raise ValidationError(f"{label} extensions must be an object")
    for name in extensions:
        if not isinstance(name, str) or _EXTENSION_NAME.fullmatch(name) is None:
            raise ValidationError(
                f"{label} extension names must use the reverse-DNS/name namespace form"
            )
    try:
        canonical_json(dict(extensions))
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{label} extensions must use LETS-CJ/1 values") from exc


def _timestamp(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp")
    if _RFC3339.fullmatch(value) is None:
        raise ValidationError(
            f"{field} must be RFC 3339 with at most nine fractional-second digits"
        )
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValidationError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValidationError(f"{field} must include a UTC offset")
    return value


def _timestamp_ns(value: str, field: str) -> int:
    """Convert a validated RFC 3339 timestamp to exact Unix nanoseconds."""

    checked = _timestamp(value, field)
    matched = _RFC3339.fullmatch(checked)
    if matched is None:  # Defensive: _timestamp validates the same expression.
        raise ValidationError(f"{field} must be an RFC 3339 timestamp")
    offset = "+00:00" if matched.group("offset") == "Z" else matched.group("offset")
    parsed = datetime.fromisoformat(f"{matched.group('date')}{offset}").astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = parsed - epoch
    fraction = matched.group("fraction")
    fractional_ns = 0 if fraction is None else int(fraction[1:].ljust(9, "0"))
    result = delta.days * 86_400_000_000_000 + delta.seconds * 1_000_000_000 + fractional_ns
    if result < 0 or result > (1 << 63) - 1:
        raise ValidationError(f"{field} must fit in a non-negative signed 64-bit timestamp")
    return result


def validate_endpoint_origin(
    value: object,
    field: str,
    *,
    allow_insecure_http: bool,
) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a URI")
    if any(
        character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
        for character in value
    ):
        raise ValidationError(f"{field} must not contain whitespace or control characters")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise ValidationError(f"{field} is not a valid URI origin") from exc
    accepted_schemes = {"https", "http"} if allow_insecure_http else {"https"}
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValidationError(f"{field} contains an invalid TCP port") from exc
    raw_port = re.search(r":(?P<port>[0-9]*)$", parsed.netloc)
    if raw_port is not None:
        port_text = raw_port.group("port")
        if not port_text or (len(port_text) > 1 and port_text.startswith("0")):
            raise ValidationError(f"{field} contains a non-canonical TCP port")
    if port == 0:
        raise ValidationError(f"{field} TCP port must be in the range 1..65535")
    if (
        parsed.scheme not in accepted_schemes
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        qualifier = "HTTP(S)" if allow_insecure_http else "HTTPS"
        raise ValidationError(
            f"{field} must be an absolute {qualifier} origin without credentials, path, query, "
            "or fragment"
        )
    if not value.startswith(f"{parsed.scheme}://"):
        raise ValidationError(f"{field} URI scheme must use lowercase canonical spelling")
    host = parsed.hostname
    if host is None or not host.isascii():
        raise ValidationError(f"{field} host must be ASCII; use an explicit IDNA A-label")
    if parsed.netloc.startswith("[") and re.fullmatch(r"[0-9A-Fa-f:]+", host) is None:
        raise ValidationError(
            f"{field} IPv6 literals must use hexadecimal address syntax without a scope ID"
        )
    canonical_host: str
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            all(label.isdigit() for label in labels)
            or len(host) > 253
            or any(_DNS_LABEL.fullmatch(label) is None for label in labels)
        ):
            raise ValidationError(f"{field} host is not a valid ASCII DNS name") from None
        canonical_host = host.lower()
    else:
        canonical_host = address.compressed
        if address.version == 6:
            canonical_host = f"[{canonical_host}]"
    default_port = 443 if parsed.scheme == "https" else 80
    port_suffix = "" if port is None or port == default_port else f":{port}"
    return f"{parsed.scheme}://{canonical_host}{port_suffix}"


@dataclass(frozen=True, slots=True)
class ManifestPublicKey:
    key_id: str
    public_key: bytes
    not_before: str | None = None
    not_after: str | None = None

    def __post_init__(self) -> None:
        require_key_id(self.key_id, field="manifest key_id")
        if not isinstance(self.public_key, bytes) or len(self.public_key) != 32:
            raise ValidationError("manifest Ed25519 public keys must contain 32 bytes")
        try:
            VerifyKey(self.public_key)
        except (ValueError, TypeError) as exc:
            raise ValidationError("manifest contains an invalid Ed25519 public key") from exc
        start = (
            None if self.not_before is None else _timestamp_ns(self.not_before, "key not_before")
        )
        end = None if self.not_after is None else _timestamp_ns(self.not_after, "key not_after")
        if start is not None and end is not None and end <= start:
            raise ValidationError("manifest key validity interval is empty")

    def to_dict(self) -> dict[str, Any]:
        from lets.canonical import b64url_encode

        result: dict[str, Any] = {
            "key_id": self.key_id,
            "algorithm": "Ed25519",
            "public_key": b64url_encode(self.public_key),
        }
        if self.not_before is not None:
            result["not_before"] = self.not_before
        if self.not_after is not None:
            result["not_after"] = self.not_after
        return result

    @property
    def not_before_ns(self) -> int | None:
        return None if self.not_before is None else _timestamp_ns(self.not_before, "key not_before")

    @property
    def not_after_ns(self) -> int | None:
        return None if self.not_after is None else _timestamp_ns(self.not_after, "key not_after")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _strict(
            data,
            {"key_id", "algorithm", "public_key", "not_before", "not_after"},
            "public key",
        )
        if data.get("algorithm") != "Ed25519":
            raise ValidationError("only Ed25519 manifest keys are supported")
        encoded = data.get("public_key")
        if not isinstance(encoded, str):
            raise ValidationError("manifest public_key must be base64url text")
        try:
            public_key = b64url_decode(encoded)
        except Exception as exc:
            raise ValidationError("manifest public_key is malformed") from exc
        return cls(
            key_id=data["key_id"],
            public_key=public_key,
            not_before=data.get("not_before"),
            not_after=data.get("not_after"),
        )


@dataclass(frozen=True, slots=True)
class WardenManifest:
    warden_id: str
    peer_endpoint: str
    client_endpoint: str
    initial_share: ResourceVector
    keys: tuple[ManifestPublicKey, ...]
    extensions: Mapping[str, Any]

    def __post_init__(self) -> None:
        require_warden_id(self.warden_id)
        object.__setattr__(
            self,
            "peer_endpoint",
            validate_endpoint_origin(
                self.peer_endpoint,
                "peer_endpoint",
                allow_insecure_http=True,
            ),
        )
        object.__setattr__(
            self,
            "client_endpoint",
            validate_endpoint_origin(
                self.client_endpoint,
                "client_endpoint",
                allow_insecure_http=True,
            ),
        )
        _validate_extensions(self.extensions, "warden")
        if not self.keys or len(self.keys) > MAX_WARDEN_KEYS:
            raise ValidationError(f"each manifest warden requires 1..{MAX_WARDEN_KEYS} public keys")
        key_ids = [item.key_id for item in self.keys]
        if len(key_ids) != len(set(key_ids)):
            raise ValidationError(f"warden {self.warden_id!r} has duplicate key ids")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "warden_id": self.warden_id,
            "peer_endpoint": self.peer_endpoint,
            "client_endpoint": self.client_endpoint,
            "initial_share": list(self.initial_share),
            "keys": [item.to_dict() for item in self.keys],
        }
        if self.extensions:
            result["extensions"] = dict(self.extensions)
        return result

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        dimensions: int,
        allow_insecure_http: bool,
    ) -> Self:
        _strict(
            data,
            {
                "warden_id",
                "peer_endpoint",
                "client_endpoint",
                "initial_share",
                "keys",
                "extensions",
            },
            "warden",
        )
        raw_keys = data.get("keys")
        if not isinstance(raw_keys, Sequence) or isinstance(raw_keys, (str, bytes)):
            raise ValidationError("warden keys must be an array")
        raw_extensions = data.get("extensions", {})
        if not isinstance(raw_extensions, Mapping):
            raise ValidationError("warden extensions must be an object")
        raw_share = data.get("initial_share")
        if not isinstance(raw_share, Sequence) or isinstance(raw_share, (str, bytes)):
            raise ValidationError("warden initial_share must be an integer array")
        return cls(
            warden_id=data["warden_id"],
            peer_endpoint=validate_endpoint_origin(
                data.get("peer_endpoint"),
                "peer_endpoint",
                allow_insecure_http=allow_insecure_http,
            ),
            client_endpoint=validate_endpoint_origin(
                data.get("client_endpoint"),
                "client_endpoint",
                allow_insecure_http=allow_insecure_http,
            ),
            initial_share=vector(raw_share, dimensions=dimensions),
            keys=tuple(ManifestPublicKey.from_dict(item) for item in raw_keys),
            extensions=dict(raw_extensions),
        )


@dataclass(frozen=True, slots=True)
class ManifestSignature:
    key_id: str
    signature: bytes

    def __post_init__(self) -> None:
        require_identifier(self.key_id, field="manifest signer key_id")
        if not isinstance(self.signature, bytes) or len(self.signature) != 64:
            raise ValidationError("manifest Ed25519 signatures must contain 64 bytes")

    def to_dict(self) -> dict[str, str]:
        from lets.canonical import b64url_encode

        return {
            "key_id": self.key_id,
            "algorithm": "Ed25519",
            "signature": b64url_encode(self.signature),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Self:
        _strict(data, {"key_id", "algorithm", "signature"}, "manifest signature")
        if data.get("algorithm") != "Ed25519":
            raise ValidationError("only Ed25519 manifest signatures are supported")
        encoded = data.get("signature")
        if not isinstance(encoded, str):
            raise ValidationError("manifest signature must be base64url text")
        try:
            signature = b64url_decode(encoded)
        except Exception as exc:
            raise ValidationError("manifest signature is malformed") from exc
        return cls(key_id=data["key_id"], signature=signature)


@dataclass(frozen=True, slots=True)
class ClusterManifest:
    tenant_id: str
    envelope_id: str
    config_epoch: int
    created_at: str
    resources: tuple[ResourceDimension, ...]
    initial_budget: ResourceVector
    wardens: tuple[WardenManifest, ...]
    policies: tuple[PolicySpec, ...]
    extensions: Mapping[str, Any]
    signatures: tuple[ManifestSignature, ...] = ()

    def __post_init__(self) -> None:
        require_identifier(self.tenant_id, field="manifest tenant_id")
        require_identifier(self.envelope_id, field="manifest envelope_id")
        _validate_extensions(self.extensions, "manifest")
        if (
            isinstance(self.config_epoch, bool)
            or not isinstance(self.config_epoch, int)
            or self.config_epoch <= 0
            or self.config_epoch > MAX_RESOURCE
        ):
            raise ValidationError("manifest config_epoch must be a positive integer")
        _timestamp(self.created_at, "manifest created_at")
        if not self.resources or len(self.resources) > 256:
            raise ValidationError("manifest requires 1..256 resource dimensions")
        dimension_ids = [item.id for item in self.resources]
        if len(dimension_ids) != len(set(dimension_ids)):
            raise ValidationError("manifest resource dimension ids must be unique")
        object.__setattr__(
            self,
            "initial_budget",
            vector(self.initial_budget, dimensions=len(self.resources)),
        )
        if not self.wardens or len(self.wardens) > MAX_MANIFEST_WARDENS:
            raise ValidationError(f"manifest requires 1..{MAX_MANIFEST_WARDENS} wardens")
        warden_ids = [item.warden_id for item in self.wardens]
        if len(warden_ids) != len(set(warden_ids)):
            raise ValidationError("manifest warden ids must be unique")
        peer_endpoints = [item.peer_endpoint for item in self.wardens]
        if len(peer_endpoints) != len(set(peer_endpoints)):
            raise ValidationError("manifest peer endpoint origins must be unique across wardens")
        key_ids = [key.key_id for item in self.wardens for key in item.keys]
        if len(key_ids) != len(set(key_ids)):
            raise ValidationError("manifest key ids must be globally unique")
        key_material = [key.public_key for item in self.wardens for key in item.keys]
        if len(key_material) != len(set(key_material)):
            raise ValidationError(
                "manifest Ed25519 public-key material must be globally unique across wardens"
            )
        allocated = zero(len(self.resources))
        for item in self.wardens:
            share = vector(item.initial_share, dimensions=len(self.resources))
            allocated = add(allocated, share)
        if allocated != self.initial_budget:
            raise ValidationError(
                "the component-wise sum of warden shares must equal initial_budget"
            )
        if not self.policies or len(self.policies) > MAX_MANIFEST_POLICIES:
            raise ValidationError(f"manifest requires 1..{MAX_MANIFEST_POLICIES} policies")
        versions = [item.policy_version for item in self.policies]
        if len(versions) != len(set(versions)):
            raise ValidationError("manifest policy versions must be unique")
        first = self.policies[0]
        for policy in self.policies:
            if policy.dimensions != self.resources:
                raise ValidationError("policy resources do not match manifest resources")
            for field in (
                "receipt_ttl_ns",
                "max_clock_uncertainty_ns",
                "transfer_gap_window",
            ):
                if getattr(policy, field) != getattr(first, field):
                    raise ValidationError(f"all manifest policies must agree on immutable {field}")
        signer_ids = [item.key_id for item in self.signatures]
        if len(self.signatures) > MAX_MANIFEST_SIGNATURES:
            raise ValidationError(
                f"manifest signatures exceed the v1 limit of {MAX_MANIFEST_SIGNATURES}"
            )
        if len(signer_ids) != len(set(signer_ids)):
            raise ValidationError("manifest contains duplicate signer key ids")

    @property
    def digest(self) -> str:
        return canonical_digest(self.unsigned_dict())

    def unsigned_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "api_version": API_VERSION,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "created_at": self.created_at,
            "resources": [item.to_dict() for item in self.resources],
            "initial_budget": list(self.initial_budget),
            "wardens": [item.to_dict() for item in self.wardens],
            "policies": [item.to_dict() for item in self.policies],
        }
        if self.extensions:
            result["extensions"] = dict(self.extensions)
        return result

    def to_dict(self) -> dict[str, Any]:
        result = self.unsigned_dict()
        if self.signatures:
            result["signatures"] = [item.to_dict() for item in self.signatures]
        return result

    def verify_signatures(
        self,
        trusted_operator_keys: Mapping[str, bytes],
        *,
        threshold: int = 1,
    ) -> frozenset[str]:
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold <= 0:
            raise ValidationError("manifest signature threshold must be positive")
        material_owners: dict[bytes, str] = {}
        for key_id, public_bytes in trusted_operator_keys.items():
            require_identifier(key_id, field="trusted operator key_id")
            if not isinstance(public_bytes, bytes) or len(public_bytes) != 32:
                raise ValidationError(f"trusted operator key {key_id!r} is malformed")
            existing_owner = material_owners.get(public_bytes)
            if existing_owner is not None and existing_owner != key_id:
                raise ValidationError(
                    "trusted operator key aliases must not reuse Ed25519 public-key material"
                )
            material_owners[public_bytes] = key_id
        warden_material = {key.public_key for warden in self.wardens for key in warden.keys}
        if warden_material.intersection(material_owners):
            raise ValidationError(
                "operator and online warden roles must use disjoint Ed25519 public-key material"
            )
        payload = canonical_json(self.unsigned_dict())
        accepted: set[str] = set()
        accepted_material: set[bytes] = set()
        for signed in self.signatures:
            signature_public_bytes = trusted_operator_keys.get(signed.key_id)
            if signature_public_bytes is None:
                continue
            try:
                VerifyKey(signature_public_bytes).verify(payload, signed.signature)
            except (BadSignatureError, ValueError, TypeError):
                continue
            accepted.add(signed.key_id)
            accepted_material.add(signature_public_bytes)
        if len(accepted_material) < threshold:
            raise SignatureError(
                f"manifest has {len(accepted_material)} distinct trusted signatures; "
                f"{threshold} required"
            )
        return frozenset(accepted)

    def warden(self, warden_id: str) -> WardenManifest:
        matches = [item for item in self.wardens if item.warden_id == warden_id]
        if len(matches) != 1:
            raise ValidationError(f"warden {warden_id!r} is not declared in this manifest")
        return matches[0]

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        allow_insecure_http: bool = False,
    ) -> Self:
        _strict(
            data,
            {
                "api_version",
                "tenant_id",
                "envelope_id",
                "config_epoch",
                "created_at",
                "resources",
                "initial_budget",
                "wardens",
                "policies",
                "extensions",
                "signatures",
            },
            "cluster manifest",
        )
        if data.get("api_version") != API_VERSION:
            raise ValidationError("unsupported LETS manifest api_version")
        raw_resources = data.get("resources")
        if not isinstance(raw_resources, Sequence) or isinstance(raw_resources, (str, bytes)):
            raise ValidationError("manifest resources must be an array")
        resources = tuple(ResourceDimension.from_dict(dict(item)) for item in raw_resources)
        raw_wardens = data.get("wardens")
        if not isinstance(raw_wardens, Sequence) or isinstance(raw_wardens, (str, bytes)):
            raise ValidationError("manifest wardens must be an array")
        raw_policies = data.get("policies")
        if not isinstance(raw_policies, Sequence) or isinstance(raw_policies, (str, bytes)):
            raise ValidationError("manifest policies must be an array")
        raw_signatures = data.get("signatures", ())
        if not isinstance(raw_signatures, Sequence) or isinstance(raw_signatures, (str, bytes)):
            raise ValidationError("manifest signatures must be an array")
        raw_extensions = data.get("extensions", {})
        if not isinstance(raw_extensions, Mapping):
            raise ValidationError("manifest extensions must be an object")
        raw_budget = data.get("initial_budget")
        if not isinstance(raw_budget, Sequence) or isinstance(raw_budget, (str, bytes)):
            raise ValidationError("manifest initial_budget must be an integer array")
        return cls(
            tenant_id=data["tenant_id"],
            envelope_id=data["envelope_id"],
            config_epoch=data["config_epoch"],
            created_at=data["created_at"],
            resources=resources,
            initial_budget=vector(raw_budget, dimensions=len(resources)),
            wardens=tuple(
                WardenManifest.from_dict(
                    item,
                    dimensions=len(resources),
                    allow_insecure_http=allow_insecure_http,
                )
                for item in raw_wardens
            ),
            policies=tuple(PolicySpec.from_dict(dict(item)) for item in raw_policies),
            extensions=dict(raw_extensions),
            signatures=tuple(ManifestSignature.from_dict(item) for item in raw_signatures),
        )

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        allow_insecure_http: bool = False,
    ) -> Self:
        try:
            with Path(path).open("rb") as stream:
                raw = stream.read(MAX_MANIFEST_BYTES + 1)
            if len(raw) > MAX_MANIFEST_BYTES:
                raise ValueError(f"manifest exceeds the v1 byte limit of {MAX_MANIFEST_BYTES}")
            data = strict_json_loads(raw)
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValidationError(f"could not load LETS manifest {path!s}") from exc
        if not isinstance(data, Mapping):
            raise ValidationError("LETS manifest root must be an object")
        return cls.from_dict(data, allow_insecure_http=allow_insecure_http)
