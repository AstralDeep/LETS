"""External monotonic authority anchors for stale-state fencing.

The LETS database is internally crash safe, but a byte-for-byte older backup is
also internally valid.  An authority anchor lives outside that backup domain and
records the latest committed audit/state head.  A warden checks the anchor before
and after every transaction, so an older restored database cannot silently revive
previously consumed capacity.

The file implementation is suitable when the file is placed on independently
protected durable storage.  Higher-assurance deployments can implement the same
protocol with a hardware monotonic counter or conditional remote record.
"""

from __future__ import annotations

import os
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Self, cast

from lets.canonical import b64url_decode, b64url_encode, canonical_json, strict_json_loads
from lets.errors import StorageError, ValidationError
from lets.ids import require_identifier, require_warden_id
from lets.vector import MAX_RESOURCE

ANCHOR_FORMAT = "LETS-AUTHORITY-ANCHOR/1"
_ZERO_HASH = bytes(32)


def _integer(value: object, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < minimum or value > MAX_RESOURCE:
        raise ValidationError(f"{field} is outside the supported signed 64-bit range")
    return value


def _digest(value: object, field: str) -> bytes:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be canonical base64url")
    try:
        decoded = b64url_decode(value)
    except ValueError as exc:
        raise ValidationError(f"{field} must be canonical base64url") from exc
    if len(decoded) != 32:
        raise ValidationError(f"{field} must contain exactly 32 bytes")
    return decoded


@dataclass(frozen=True, slots=True)
class AuthorityCheckpoint:
    """A monotonic, identity-bound summary of committed authority state."""

    warden_id: str
    tenant_id: str
    envelope_id: str
    config_epoch: int
    schema_version: int
    signing_key_id: str
    signing_public_key_sha256: bytes
    database_instance_id: bytes
    audit_sequence: int
    audit_hash: bytes
    state_revision: int
    state_digest: bytes

    def __post_init__(self) -> None:
        require_warden_id(self.warden_id, field="authority checkpoint warden_id")
        require_identifier(self.tenant_id, field="authority checkpoint tenant_id")
        require_identifier(self.envelope_id, field="authority checkpoint envelope_id")
        require_identifier(self.signing_key_id, field="authority checkpoint signing_key_id")
        _integer(self.config_epoch, "authority checkpoint config_epoch", minimum=1)
        _integer(self.schema_version, "authority checkpoint schema_version", minimum=1)
        _integer(self.audit_sequence, "authority checkpoint audit_sequence", minimum=-1)
        _integer(self.state_revision, "authority checkpoint state_revision")
        if not isinstance(self.audit_hash, bytes) or len(self.audit_hash) != 32:
            raise ValidationError("authority checkpoint audit_hash must contain 32 bytes")
        if not isinstance(self.state_digest, bytes) or len(self.state_digest) != 32:
            raise ValidationError("authority checkpoint state_digest must contain 32 bytes")
        if (
            not isinstance(self.signing_public_key_sha256, bytes)
            or len(self.signing_public_key_sha256) != 32
        ):
            raise ValidationError(
                "authority checkpoint signing_public_key_sha256 must contain 32 bytes"
            )
        if not isinstance(self.database_instance_id, bytes) or len(self.database_instance_id) != 32:
            raise ValidationError("authority checkpoint database_instance_id must contain 32 bytes")
        if self.audit_sequence == -1 and self.audit_hash != _ZERO_HASH:
            raise ValidationError("an empty audit log must use the zero audit hash")

    @property
    def stable_identity(self) -> tuple[str, str, str, int, str, bytes, bytes]:
        return (
            self.warden_id,
            self.tenant_id,
            self.envelope_id,
            self.config_epoch,
            self.signing_key_id,
            self.signing_public_key_sha256,
            self.database_instance_id,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "format": ANCHOR_FORMAT,
            "warden_id": self.warden_id,
            "tenant_id": self.tenant_id,
            "envelope_id": self.envelope_id,
            "config_epoch": self.config_epoch,
            "schema_version": self.schema_version,
            "signing_key_id": self.signing_key_id,
            "signing_public_key_sha256": b64url_encode(self.signing_public_key_sha256),
            "database_instance_id": b64url_encode(self.database_instance_id),
            "audit_sequence": self.audit_sequence,
            "audit_hash": b64url_encode(self.audit_hash),
            "state_revision": self.state_revision,
            "state_digest": b64url_encode(self.state_digest),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> Self:
        expected = {
            "format",
            "warden_id",
            "tenant_id",
            "envelope_id",
            "config_epoch",
            "schema_version",
            "signing_key_id",
            "signing_public_key_sha256",
            "database_instance_id",
            "audit_sequence",
            "audit_hash",
            "state_revision",
            "state_digest",
        }
        if set(value) != expected:
            raise ValidationError("authority anchor fields do not match LETS-AUTHORITY-ANCHOR/1")
        if value.get("format") != ANCHOR_FORMAT:
            raise ValidationError("unsupported authority anchor format")
        warden_id = value.get("warden_id")
        tenant_id = value.get("tenant_id")
        envelope_id = value.get("envelope_id")
        signing_key_id = value.get("signing_key_id")
        if not all(
            isinstance(item, str) for item in (warden_id, tenant_id, envelope_id, signing_key_id)
        ):
            raise ValidationError("authority anchor identity fields must be strings")
        return cls(
            warden_id=cast(str, warden_id),
            tenant_id=cast(str, tenant_id),
            envelope_id=cast(str, envelope_id),
            config_epoch=_integer(
                value.get("config_epoch"), "authority anchor config_epoch", minimum=1
            ),
            schema_version=_integer(
                value.get("schema_version"), "authority anchor schema_version", minimum=1
            ),
            signing_key_id=cast(str, signing_key_id),
            signing_public_key_sha256=_digest(
                value.get("signing_public_key_sha256"),
                "authority anchor signing_public_key_sha256",
            ),
            database_instance_id=_digest(
                value.get("database_instance_id"), "authority anchor database_instance_id"
            ),
            audit_sequence=_integer(
                value.get("audit_sequence"), "authority anchor audit_sequence", minimum=-1
            ),
            audit_hash=_digest(value.get("audit_hash"), "authority anchor audit_hash"),
            state_revision=_integer(value.get("state_revision"), "authority anchor state_revision"),
            state_digest=_digest(value.get("state_digest"), "authority anchor state_digest"),
        )


class AuthorityAnchor(Protocol):
    """Linearizable CAS state outside the database rollback domain.

    Implementations MUST serialize contenders, compare the durable head inside
    that serialization boundary, and advance it atomically.  A check followed by
    an unconditional write is not a conforming implementation.  Reconciliation
    is synchronous and MUST either complete or raise within the deployment's
    configured authority-anchor timeout; an unbounded remote call is invalid.
    """

    def reconcile(
        self,
        checkpoint: AuthorityCheckpoint,
        *,
        audit_hash_at: Callable[[int], bytes | None],
        initialize: bool = False,
        allow_schema_upgrade: bool = False,
    ) -> None: ...


class FileAuthorityAnchor:
    """Atomic, cross-process serialized authority anchor stored in one file.

    The containing directory must be in an independent, non-rollback failure
    domain.  Copying this file into the same snapshot as the warden database
    defeats stale-restore detection.
    """

    def __init__(self, path: str | os.PathLike[str], *, timeout_s: float = 5.0) -> None:
        self._path = Path(path).resolve()
        if self._path == self._path.parent:
            raise ValidationError("authority anchor path must name a file")
        if (
            isinstance(timeout_s, bool)
            or not isinstance(timeout_s, (int, float))
            or timeout_s <= 0
            or timeout_s > 60
        ):
            raise ValidationError("authority anchor timeout_s must be in (0, 60]")
        self._timeout_s = float(timeout_s)
        self._lock_path = self._path.with_name(f".{self._path.name}.lock")

    @property
    def path(self) -> Path:
        return self._path

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._lock_path, "a+b") as stream:
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            deadline = time.monotonic() + self._timeout_s
            if os.name == "nt":
                import msvcrt

                while True:
                    try:
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if time.monotonic() >= deadline:
                            raise StorageError("timed out acquiring authority anchor lock") from exc
                        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                try:
                    yield
                finally:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import importlib

                fcntl = importlib.import_module("fcntl")
                while True:
                    try:
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError as exc:
                        if time.monotonic() >= deadline:
                            raise StorageError("timed out acquiring authority anchor lock") from exc
                        time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))
                try:
                    yield
                finally:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        if os.name != "nt":
            with suppress(OSError):
                os.chmod(self._lock_path, 0o600)

    def _read(self) -> AuthorityCheckpoint:
        try:
            raw = self._path.read_bytes()
            decoded = strict_json_loads(raw)
        except FileNotFoundError as exc:
            raise StorageError(f"authority anchor does not exist: {self._path}") from exc
        except (OSError, UnicodeError, ValueError) as exc:
            raise StorageError(f"authority anchor is unreadable: {self._path}") from exc
        if not isinstance(decoded, Mapping):
            raise StorageError("authority anchor root must be an object")
        try:
            return AuthorityCheckpoint.from_dict(decoded)
        except ValidationError as exc:
            raise StorageError("authority anchor is malformed") from exc

    def _write(self, checkpoint: AuthorityCheckpoint, *, exclusive: bool) -> None:
        payload = canonical_json(checkpoint.to_dict()) + b"\n"
        descriptor = -1
        temporary = ""
        try:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{self._path.name}.", suffix=".tmp", dir=self._path.parent
            )
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            if exclusive:
                try:
                    os.link(temporary, self._path)
                except FileExistsError as exc:
                    raise StorageError(f"authority anchor already exists: {self._path}") from exc
                os.unlink(temporary)
                temporary = ""
            else:
                os.replace(temporary, self._path)
                temporary = ""
            if os.name != "nt":
                directory_fd = os.open(self._path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        except OSError as exc:
            raise StorageError(f"could not persist authority anchor: {self._path}") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                with suppress(FileNotFoundError):
                    os.unlink(temporary)

    @staticmethod
    def _require_identity(anchored: AuthorityCheckpoint, current: AuthorityCheckpoint) -> None:
        if anchored.stable_identity != current.stable_identity:
            raise StorageError("authority anchor identity does not match this warden database")

    def reconcile(
        self,
        checkpoint: AuthorityCheckpoint,
        *,
        audit_hash_at: Callable[[int], bytes | None],
        initialize: bool = False,
        allow_schema_upgrade: bool = False,
    ) -> None:
        with self._locked():
            if not self._path.exists():
                if not initialize:
                    raise StorageError(
                        "authority anchor is missing; refusing to open rollback-sensitive state"
                    )
                self._write(checkpoint, exclusive=True)
                return

            anchored = self._read()
            self._require_identity(anchored, checkpoint)
            schema_upgrade = checkpoint.schema_version != anchored.schema_version
            if checkpoint.schema_version < anchored.schema_version:
                raise StorageError("warden schema is older than its authority anchor")
            if schema_upgrade and not allow_schema_upgrade:
                raise StorageError(
                    "authority anchor schema transition requires explicit migration admission"
                )
            if checkpoint.audit_sequence < anchored.audit_sequence:
                raise StorageError("warden database is older than its monotonic authority anchor")
            if checkpoint.audit_sequence == anchored.audit_sequence:
                if checkpoint.audit_hash != anchored.audit_hash:
                    raise StorageError(
                        "warden database audit head diverges from its authority anchor"
                    )
                if (
                    checkpoint.state_revision != anchored.state_revision
                    or checkpoint.state_digest != anchored.state_digest
                ):
                    raise StorageError(
                        "warden database authority state diverges at the anchored audit head"
                    )
                if schema_upgrade:
                    self._write(checkpoint, exclusive=False)
                return

            historical = (
                _ZERO_HASH
                if anchored.audit_sequence == -1
                else audit_hash_at(anchored.audit_sequence)
            )
            if historical != anchored.audit_hash:
                raise StorageError("warden database does not extend the anchored audit history")
            if checkpoint.state_revision < anchored.state_revision:
                raise StorageError(
                    "warden database state revision moved behind its authority anchor"
                )
            self._write(checkpoint, exclusive=False)


__all__ = [
    "ANCHOR_FORMAT",
    "AuthorityAnchor",
    "AuthorityCheckpoint",
    "FileAuthorityAnchor",
]
