"""Operator-selected runtime identity and signing providers.

The LETS core remains vendor neutral.  Deployments integrate managed Ed25519
keys and transport identity systems through one explicitly selected Python
entry point instead of importing provider-specific code into the warden.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from threading import Lock
from types import MappingProxyType
from typing import Protocol, TypeAlias, runtime_checkable

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from lets.audit import AuditSink
from lets.auth import IdentityAuthenticator, TenantBoundAuthenticator
from lets.authority import AuthorityAnchor
from lets.canonical import b64url_encode, canonical_json
from lets.errors import SignatureError, ValidationError
from lets.ids import require_digest, require_key_id, require_warden_id
from lets.vector import MAX_RESOURCE

RUNTIME_PROVIDER_GROUP = "lets.runtime_providers"
BUILTIN_RUNTIME_PROVIDER = "builtin"
MAX_RUNTIME_OPTIONS = 32
MAX_RUNTIME_OPTION_NAME = 64
MAX_RUNTIME_OPTION_VALUE = 4096
MAX_RUNTIME_OPTIONS_SIZE = 16_384

_PROVIDER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_OPTION_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


@runtime_checkable
class RuntimeSigner(Protocol):
    """Ed25519 signer surface required by the warden and peer protocols."""

    warden_id: str
    key_id: str

    @property
    def public_key_bytes(self) -> bytes: ...

    def sign(self, payload: bytes) -> bytes: ...


def validate_runtime_provider_name(value: str) -> str:
    """Validate an installed entry-point name without interpreting import paths."""

    if not isinstance(value, str) or _PROVIDER_NAME.fullmatch(value) is None:
        raise ValidationError(
            "runtime provider name must be 1..128 ASCII letters, digits, '.', '_', or '-'"
        )
    return value


def validate_runtime_options(
    values: Mapping[str, str] | Iterable[tuple[str, str]],
) -> Mapping[str, str]:
    """Return an immutable, bounded option map and reject duplicate names."""

    items = values.items() if isinstance(values, Mapping) else values
    checked: dict[str, str] = {}
    total_size = 0
    try:
        iterator = iter(items)
    except TypeError as exc:
        raise ValidationError("runtime provider options must be key/value pairs") from exc
    for item in iterator:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValidationError("runtime provider options must be key/value pairs")
        name, value = item
        if not isinstance(name, str) or _OPTION_NAME.fullmatch(name) is None:
            raise ValidationError(
                f"runtime option names must be 1..{MAX_RUNTIME_OPTION_NAME} safe ASCII characters"
            )
        if name in checked:
            raise ValidationError(f"duplicate runtime provider option {name!r}")
        if (
            not isinstance(value, str)
            or not value
            or len(value) > MAX_RUNTIME_OPTION_VALUE
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise ValidationError(
                "runtime option values must be non-empty bounded strings without control characters"
            )
        checked[name] = value
        total_size += len(name) + len(value)
        if len(checked) > MAX_RUNTIME_OPTIONS:
            raise ValidationError(f"runtime providers accept at most {MAX_RUNTIME_OPTIONS} options")
        if total_size > MAX_RUNTIME_OPTIONS_SIZE:
            raise ValidationError("runtime provider options exceed the aggregate size limit")
    try:
        canonical_json(checked)
    except (TypeError, ValueError) as exc:
        raise ValidationError("runtime provider options are outside the LETS-CJ/1 subset") from exc
    return MappingProxyType(checked)


@dataclass(frozen=True, slots=True)
class RuntimeProviderContext:
    """Validated local identity and non-secret configuration supplied to a provider."""

    config_path: Path
    warden_id: str
    tenant_id: str
    envelope_id: str
    config_epoch: int
    manifest_digest: str | None
    options: Mapping[str, str]
    production: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.config_path, Path):
            raise ValidationError("runtime provider config_path must be a pathlib Path")
        object.__setattr__(self, "config_path", self.config_path.resolve())
        require_warden_id(self.warden_id, field="runtime warden_id")
        for field_name in ("tenant_id", "envelope_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value or len(value) > 512:
                raise ValidationError(f"runtime {field_name} must be a non-empty bounded string")
            if value != value.strip() or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            ):
                raise ValidationError(f"runtime {field_name} contains unsafe characters")
        if (
            isinstance(self.config_epoch, bool)
            or not isinstance(self.config_epoch, int)
            or self.config_epoch <= 0
            or self.config_epoch > MAX_RESOURCE
        ):
            raise ValidationError("runtime config_epoch must be a positive signed 64-bit integer")
        if self.manifest_digest is not None:
            require_digest(self.manifest_digest, field="runtime manifest_digest")
        if type(self.production) is not bool:
            raise ValidationError("runtime production flag must be a boolean")
        object.__setattr__(self, "options", validate_runtime_options(self.options))


@dataclass(frozen=True, slots=True)
class RuntimeBindings:
    """Resources returned by a runtime-provider entry point.

    ``cleanup`` is synchronous and is invoked exactly once after the command, or
    immediately if admission of the returned resources fails.
    """

    warden_id: str
    tenant_id: str
    signer: object
    authenticator: object
    production_capable: bool
    authority_anchor: AuthorityAnchor | None = None
    audit_sink: AuditSink | None = None
    cleanup: Callable[[], object] | None = None


RuntimeProviderFactory: TypeAlias = Callable[[RuntimeProviderContext], RuntimeBindings]


class RuntimeSession:
    """Validated runtime bindings with idempotent lifecycle cleanup."""

    def __init__(
        self,
        *,
        provider_name: str,
        signer: RuntimeSigner,
        authenticator: IdentityAuthenticator,
        production_capable: bool,
        authority_anchor: AuthorityAnchor | None,
        audit_sink: AuditSink | None,
        cleanup: Callable[[], object] | None,
    ) -> None:
        self.provider_name = provider_name
        self.signer = signer
        self.authenticator = authenticator
        self.production_capable = production_capable
        self.authority_anchor = authority_anchor
        self.audit_sink = audit_sink
        self._cleanup = cleanup
        self._closed = False
        self._close_lock = Lock()

    def __enter__(self) -> RuntimeSession:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        if self._cleanup is not None:
            try:
                result = self._cleanup()
            except Exception as exc:
                raise ValidationError("runtime provider cleanup failed") from exc
            if result is not None:
                raise ValidationError("runtime provider cleanup must return None")


def _run_failed_admission_cleanup(bindings: RuntimeBindings) -> None:
    cleanup = bindings.cleanup
    if cleanup is None:
        return
    result = cleanup()
    if result is not None:
        raise ValidationError("runtime provider cleanup must return None")


def _admit_bindings(
    provider_name: str,
    context: RuntimeProviderContext,
    bindings: object,
) -> RuntimeSession:
    if not isinstance(bindings, RuntimeBindings):
        raise ValidationError("runtime provider must return RuntimeBindings")
    if bindings.cleanup is not None and not callable(bindings.cleanup):
        raise ValidationError("runtime provider cleanup must be callable")
    try:
        if not isinstance(bindings.warden_id, str):
            raise ValidationError("runtime provider warden identity must be a string")
        if not isinstance(bindings.tenant_id, str):
            raise ValidationError("runtime provider tenant identity must be a string")
        if bindings.warden_id != context.warden_id:
            raise ValidationError("runtime provider declared the wrong warden identity")
        if bindings.tenant_id != context.tenant_id:
            raise ValidationError("runtime provider declared the wrong tenant identity")
        if type(bindings.production_capable) is not bool:
            raise ValidationError("runtime provider production_capable must be a boolean")
        if not isinstance(bindings.signer, RuntimeSigner):
            raise ValidationError("runtime provider returned an invalid signer type")
        signer = bindings.signer
        signer_warden_id = require_warden_id(
            signer.warden_id,
            field="runtime signer warden_id",
        )
        if signer_warden_id != context.warden_id:
            raise ValidationError("runtime signer warden identity does not match configuration")
        require_key_id(signer.key_id, field="runtime signer key_id")
        if not callable(getattr(signer, "sign", None)):
            raise ValidationError("runtime signer sign operation must be callable")
        public_key = signer.public_key_bytes
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise SignatureError("runtime signer must expose a 32-byte Ed25519 public key")
        challenge = canonical_json(
            {
                "type": "lets.runtime-provider-proof/v1",
                "provider": provider_name,
                "warden_id": context.warden_id,
                "tenant_id": context.tenant_id,
                "nonce": b64url_encode(secrets.token_bytes(32)),
            }
        )
        signature = signer.sign(challenge)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise SignatureError("runtime signer returned a malformed Ed25519 signature")
        try:
            VerifyKey(public_key).verify(challenge, signature)
        except (BadSignatureError, TypeError, ValueError) as exc:
            raise SignatureError("runtime signer proof does not match its public key") from exc
        if not isinstance(bindings.authenticator, IdentityAuthenticator):
            raise ValidationError("runtime provider returned an invalid authenticator type")
        if not callable(getattr(bindings.authenticator, "authenticate", None)):
            raise ValidationError("runtime authenticator operation must be callable")
        if context.production and bindings.production_capable is not True:
            raise ValidationError(
                "the selected runtime provider did not declare production capability"
            )
        anchor = bindings.authority_anchor
        if anchor is not None and not callable(getattr(anchor, "reconcile", None)):
            raise ValidationError("runtime provider returned an invalid authority anchor type")
        if context.production and anchor is None:
            raise ValidationError(
                "the selected runtime provider did not supply an independent authority anchor"
            )
        audit_sink = bindings.audit_sink
        if audit_sink is not None and not callable(getattr(audit_sink, "publish", None)):
            raise ValidationError("runtime provider returned an invalid audit sink type")
        if context.production and audit_sink is None:
            raise ValidationError(
                "the selected runtime provider did not supply an independent audit sink"
            )
        authenticator = TenantBoundAuthenticator(
            bindings.authenticator,
            context.tenant_id,
        )
        return RuntimeSession(
            provider_name=provider_name,
            signer=signer,
            authenticator=authenticator,
            production_capable=bindings.production_capable,
            authority_anchor=anchor,
            audit_sink=audit_sink,
            cleanup=bindings.cleanup,
        )
    except Exception as admission_error:
        try:
            _run_failed_admission_cleanup(bindings)
        except Exception as cleanup_error:
            raise ValidationError(
                "runtime provider cleanup failed after its bindings were rejected"
            ) from cleanup_error
        if isinstance(admission_error, (SignatureError, ValidationError)):
            raise
        raise ValidationError(
            "runtime provider bindings could not be admitted"
        ) from admission_error


def open_runtime_provider(
    provider_name: str,
    context: RuntimeProviderContext,
    *,
    builtin_factory: RuntimeProviderFactory | None = None,
) -> RuntimeSession:
    """Load exactly one selected provider and admit its returned resources.

    There is deliberately no module-path or dynamic-import fallback.  External
    implementations must be installed into ``lets.runtime_providers`` and the
    operator must select the entry-point name.
    """

    checked_name = validate_runtime_provider_name(provider_name)
    if not isinstance(context, RuntimeProviderContext):
        raise ValidationError("runtime provider context has an invalid type")
    if checked_name == BUILTIN_RUNTIME_PROVIDER:
        if context.production:
            raise ValidationError("the built-in runtime provider is forbidden in production")
        if builtin_factory is None:
            raise ValidationError("the built-in runtime provider is not available")
        factory: object = builtin_factory
    else:
        try:
            candidates = tuple(metadata.entry_points(group=RUNTIME_PROVIDER_GROUP))
        except Exception as exc:
            raise ValidationError("installed runtime providers could not be enumerated") from exc
        matches = tuple(
            candidate
            for candidate in candidates
            if candidate.group == RUNTIME_PROVIDER_GROUP and candidate.name == checked_name
        )
        if not matches:
            raise ValidationError(f"runtime provider {checked_name!r} is not installed")
        if len(matches) != 1:
            raise ValidationError(
                f"runtime provider {checked_name!r} has duplicate installed entry points"
            )
        try:
            factory = matches[0].load()
        except Exception as exc:
            raise ValidationError(f"runtime provider {checked_name!r} could not be loaded") from exc
    if not callable(factory):
        raise ValidationError("runtime provider entry point must be callable")
    try:
        bindings = factory(context)
    except Exception as exc:
        raise ValidationError(f"runtime provider {checked_name!r} failed to initialize") from exc
    return _admit_bindings(checked_name, context, bindings)
