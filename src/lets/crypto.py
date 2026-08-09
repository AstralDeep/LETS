"""Ed25519 signing identities and peer trust registry."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import Any, Self

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from lets.canonical import b64url_decode, b64url_encode, canonical_json
from lets.clock import Clock, SystemClock
from lets.errors import ConflictError, SignatureError, ValidationError
from lets.ids import require_key_id, require_warden_id
from lets.vector import MAX_RESOURCE


class Ed25519Signer:
    """Stable warden signing identity backed by a 32-byte private seed."""

    def __init__(self, warden_id: str, private_key: SigningKey) -> None:
        self.warden_id = require_warden_id(warden_id)
        self._private_key = private_key
        fingerprint = sha256(self.public_key_bytes).hexdigest()[:32]
        self.key_id = f"{self.warden_id}/ed25519-{fingerprint}"

    @classmethod
    def generate(cls, warden_id: str) -> Self:
        return cls(warden_id, SigningKey.generate())

    @classmethod
    def from_seed(cls, warden_id: str, seed: bytes) -> Self:
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ValidationError("Ed25519 seed must contain exactly 32 bytes")
        return cls(warden_id, SigningKey(seed))

    @classmethod
    def load_seed_file(cls, warden_id: str, path: str | os.PathLike[str]) -> Self:
        try:
            seed = Path(path).read_bytes()
        except OSError as exc:
            raise ValidationError(f"could not read signing seed file {path!s}") from exc
        return cls.from_seed(warden_id, seed)

    @property
    def seed_bytes(self) -> bytes:
        return bytes(self._private_key.encode())

    @property
    def public_key_bytes(self) -> bytes:
        return bytes(self._private_key.verify_key.encode())

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes):
            raise TypeError("signed payload must be bytes")
        return bytes(self._private_key.sign(payload).signature)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self._private_key.verify_key.verify(payload, signature)
            return True
        except (BadSignatureError, ValueError, TypeError):
            return False

    def sign_mapping(self, payload: Mapping[str, Any]) -> str:
        return b64url_encode(self.sign(canonical_json(payload)))

    def verify_mapping(self, payload: Mapping[str, Any], signature: str) -> None:
        try:
            valid = self.verify(canonical_json(payload), b64url_decode(signature))
        except Exception as exc:
            raise SignatureError("malformed Ed25519 signature") from exc
        if not valid:
            raise SignatureError("invalid Ed25519 signature")

    def save_seed_file(
        self,
        path: str | os.PathLike[str],
        *,
        overwrite: bool = False,
    ) -> None:
        """Atomically write a raw seed for development/bootstrap use.

        Production deployments should inject a hardware or external key provider.
        """

        destination = Path(path).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not overwrite:
            raise ConflictError(f"signing seed file already exists: {destination}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(self.seed_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            with suppress(OSError):
                os.chmod(temporary_name, 0o600)
            if overwrite:
                os.replace(temporary_name, destination)
            else:
                try:
                    os.link(temporary_name, destination)
                except FileExistsError as exc:
                    raise ConflictError(f"signing seed file already exists: {destination}") from exc
                os.unlink(temporary_name)
        except Exception:
            with suppress(FileNotFoundError):
                os.unlink(temporary_name)
            raise


class PublicKeyRegistry:
    """Explicit `(warden_id, key_id)` trust map with conflict detection."""

    def __init__(self, *, clock: Clock | None = None) -> None:
        self._clock = SystemClock() if clock is None else clock
        self._keys: dict[
            tuple[str, str],
            tuple[bytes, VerifyKey, int | None, int | None],
        ] = {}
        self._identity_by_material: dict[bytes, tuple[str, str]] = {}

    def register(
        self,
        warden_id: str,
        key_id: str,
        public_key: bytes,
        *,
        not_before_ns: int | None = None,
        not_after_ns: int | None = None,
    ) -> None:
        checked_warden = require_warden_id(warden_id)
        checked_key = require_key_id(key_id)
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValidationError("Ed25519 public key must contain exactly 32 bytes")
        for name, value in (("not_before_ns", not_before_ns), ("not_after_ns", not_after_ns)):
            if value is not None and (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > MAX_RESOURCE
            ):
                raise ValidationError(f"{name} must be a non-negative signed 64-bit integer")
        if not_before_ns is not None and not_after_ns is not None and not_after_ns <= not_before_ns:
            raise ValidationError("trusted key validity interval is empty")
        identity = (checked_warden, checked_key)
        material_identity = self._identity_by_material.get(public_key)
        if material_identity is not None and material_identity != identity:
            raise ConflictError(
                "Ed25519 public-key material is already bound to trusted identity "
                f"{material_identity!r}"
            )
        existing = self._keys.get(identity)
        if existing is not None:
            if existing[0] != public_key or existing[2:] != (not_before_ns, not_after_ns):
                raise ConflictError(
                    f"trusted key {identity!r} is already bound to other material or validity"
                )
            return
        self._keys[identity] = (
            public_key,
            VerifyKey(public_key),
            not_before_ns,
            not_after_ns,
        )
        self._identity_by_material[public_key] = identity

    def register_signer(self, signer: Ed25519Signer) -> None:
        self.register(signer.warden_id, signer.key_id, signer.public_key_bytes)

    def verify(
        self,
        warden_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> bool:
        entry = self._keys.get((warden_id, key_id))
        if entry is None:
            return False
        if not self._entry_is_current(entry):
            return False
        try:
            entry[1].verify(payload, signature)
            return True
        except (BadSignatureError, ValueError, TypeError):
            return False

    def key_validity(self, warden_id: str, key_id: str) -> tuple[int | None, int | None]:
        """Return the configured half-open validity interval for one trusted key."""

        entry = self._keys.get((warden_id, key_id))
        if entry is None:
            raise SignatureError(f"untrusted key {(warden_id, key_id)!r}")
        return entry[2], entry[3]

    def require_current(self, warden_id: str, key_id: str) -> None:
        """Fail unless the full declared clock interval is inside the key interval."""

        entry = self._keys.get((warden_id, key_id))
        if entry is None:
            raise SignatureError(f"untrusted key {(warden_id, key_id)!r}")
        if not self._entry_is_current(entry):
            raise SignatureError(
                f"trusted key {(warden_id, key_id)!r} is outside its validity interval"
            )

    def require_current_warden(self, warden_id: str) -> None:
        """Fail unless a warden has at least one currently valid verification key."""

        checked = require_warden_id(warden_id)
        if not any(
            identity[0] == checked and self._entry_is_current(entry)
            for identity, entry in self._keys.items()
        ):
            raise SignatureError(f"warden {checked!r} has no currently valid trusted key")

    def _entry_is_current(
        self,
        entry: tuple[bytes, VerifyKey, int | None, int | None],
    ) -> bool:
        now_ns = self._clock.now_ns()
        uncertainty_ns = self._clock.uncertainty_ns()
        if (
            isinstance(now_ns, bool)
            or not isinstance(now_ns, int)
            or now_ns < 0
            or now_ns > MAX_RESOURCE
            or isinstance(uncertainty_ns, bool)
            or not isinstance(uncertainty_ns, int)
            or uncertainty_ns < 0
            or uncertainty_ns > MAX_RESOURCE
            or now_ns > MAX_RESOURCE - uncertainty_ns
        ):
            return False
        not_before_ns, not_after_ns = entry[2], entry[3]
        if not_before_ns is not None and now_ns - uncertainty_ns < not_before_ns:
            return False
        return not (not_after_ns is not None and now_ns + uncertainty_ns >= not_after_ns)

    def public_key(self, warden_id: str, key_id: str) -> bytes:
        entry = self._keys.get((warden_id, key_id))
        if entry is None:
            raise SignatureError(f"untrusted key {(warden_id, key_id)!r}")
        return entry[0]

    def trust_digest(self) -> bytes:
        """Canonical digest of every admitted key, identity, and validity bound.

        Protected executors bind this value into their external replay anchor so
        a restored verifier cannot substitute key bytes or silently widen trust
        while retaining the same warden identifiers.
        """

        keys = [
            {
                "warden_id": warden_id,
                "key_id": key_id,
                "public_key": b64url_encode(entry[0]),
                "not_before_ns": entry[2],
                "not_after_ns": entry[3],
            }
            for (warden_id, key_id), entry in sorted(self._keys.items())
        ]
        return sha256(
            canonical_json(
                {
                    "type": "lets.executor-trust-registry/v1",
                    "keys": keys,
                }
            )
        ).digest()
