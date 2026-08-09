"""Transport authentication for LETS client and peer HTTP APIs.

The core service deliberately receives :class:`~lets.models.IdentityContext`
objects rather than credentials.  This module is the trust-boundary adapter
that creates those identities and authenticates messages exchanged by stable
wardens.
"""

from __future__ import annotations

import asyncio
import hmac
import inspect
import os
import secrets
import sqlite3
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from contextlib import closing, suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Protocol, Self, runtime_checkable

from lets.canonical import b64url_decode, b64url_encode, canonical_json
from lets.errors import (
    ClockUncertainError,
    PolicyError,
    ReplayError,
    SignatureError,
    StorageError,
    ValidationError,
)
from lets.ids import require_identifier, require_key_id, require_warden_id
from lets.models import IdentityContext
from lets.vector import MAX_RESOURCE

AUTHORIZATION_HEADER = "authorization"
PEER_WARDEN_HEADER = "x-lets-warden-id"
PEER_KEY_HEADER = "x-lets-key-id"
PEER_TIMESTAMP_HEADER = "x-lets-timestamp"
PEER_NONCE_HEADER = "x-lets-nonce"
PEER_CONTENT_DIGEST_HEADER = "x-lets-content-sha256"
PEER_SIGNATURE_HEADER = "x-lets-signature"

_LEGACY_REPLAY_GC_BATCH = 128


class AuthenticationError(PolicyError):
    """A client did not present an accepted transport identity."""

    code = "authentication_required"


@runtime_checkable
class HTTPAuthRequest(Protocol):
    """Small request surface understood by transport authenticators."""

    headers: Mapping[str, str]


@runtime_checkable
class IdentityAuthenticator(Protocol):
    """Resolve a client identity without consulting the JSON request body."""

    def authenticate(self, request: object) -> IdentityContext | Awaitable[IdentityContext]: ...


class StaticBearerAuthenticator:
    """Constant-time bearer authenticator for bootstrap and test deployments.

    Only SHA-256 token digests are retained.  This is intentionally a small
    bootstrap mechanism, not an OAuth token issuer; production deployments can
    inject an mTLS, SPIFFE, OIDC, or gateway-backed ``IdentityAuthenticator``.
    """

    def __init__(
        self,
        credentials: Mapping[str, IdentityContext] | Iterable[tuple[str, IdentityContext]],
    ) -> None:
        items = credentials.items() if isinstance(credentials, Mapping) else credentials
        entries: list[tuple[bytes, IdentityContext]] = []
        seen: set[bytes] = set()
        for token, identity in items:
            if not isinstance(token, str) or not token:
                raise ValidationError("bootstrap bearer tokens must be non-empty strings")
            if not isinstance(identity, IdentityContext):
                raise ValidationError("bootstrap credentials require IdentityContext values")
            digest = sha256(token.encode("utf-8")).digest()
            if digest in seen:
                raise ValidationError("duplicate bootstrap bearer token")
            seen.add(digest)
            entries.append((digest, identity))
        self._set_entries(entries)

    def _set_entries(self, entries: Iterable[tuple[bytes, IdentityContext]]) -> None:
        checked = tuple(entries)
        if not checked:
            raise ValidationError("at least one bootstrap bearer token is required")
        # A tuple prevents accidental mutation and, unlike a token-keyed dict,
        # forces every credential digest through compare_digest.
        self._entries = checked

    @classmethod
    def single(cls, token: str, identity: IdentityContext) -> StaticBearerAuthenticator:
        return cls(((token, identity),))

    @classmethod
    def from_sha256_digests(
        cls,
        credentials: Iterable[tuple[str, IdentityContext]],
    ) -> StaticBearerAuthenticator:
        """Load already-digested bootstrap credentials from node configuration."""

        entries: list[tuple[bytes, IdentityContext]] = []
        seen: set[bytes] = set()
        for encoded_digest, identity in credentials:
            if not isinstance(encoded_digest, str) or len(encoded_digest) != 64:
                raise ValidationError("bootstrap token SHA-256 digest must be 64 hex characters")
            try:
                digest = bytes.fromhex(encoded_digest)
            except ValueError as exc:
                raise ValidationError("bootstrap token SHA-256 digest is malformed") from exc
            if digest in seen:
                raise ValidationError("duplicate bootstrap bearer token digest")
            if not isinstance(identity, IdentityContext):
                raise ValidationError("bootstrap credentials require IdentityContext values")
            seen.add(digest)
            entries.append((digest, identity))
        instance = cls.__new__(cls)
        instance._set_entries(entries)
        return instance

    def authenticate(self, request: object) -> IdentityContext:
        headers = getattr(request, "headers", None)
        if not isinstance(headers, Mapping):
            raise AuthenticationError("the authentication request has no HTTP headers")
        authorization = _single_header(request, AUTHORIZATION_HEADER)
        if authorization is None:
            # Starlette Headers is case-insensitive; plain mappings used by an
            # embedding might not be, so accept the conventional spelling too.
            authorization = headers.get("Authorization")
        if not isinstance(authorization, str):
            raise AuthenticationError("a bearer credential is required")
        scheme, separator, token = authorization.partition(" ")
        if separator != " " or scheme.casefold() != "bearer" or not token or " " in token:
            raise AuthenticationError("the Authorization header is malformed")

        candidate = sha256(token.encode("utf-8")).digest()
        matched: IdentityContext | None = None
        for digest, identity in self._entries:
            if hmac.compare_digest(candidate, digest):
                matched = identity
        if matched is None:
            raise AuthenticationError("the bearer credential was not accepted")
        return matched


class TenantBoundAuthenticator:
    """Validate identities returned by an external authenticator.

    Runtime providers are selected by the operator, but their request results
    still cross an authorization boundary.  This wrapper prevents malformed or
    cross-tenant results from reaching the application service.
    """

    def __init__(self, authenticator: IdentityAuthenticator, tenant_id: str) -> None:
        if not isinstance(authenticator, IdentityAuthenticator):
            raise TypeError("authenticator must implement IdentityAuthenticator")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValidationError("bound authenticator tenant_id must be non-empty")
        self._authenticator = authenticator
        self._tenant_id = tenant_id

    async def authenticate(self, request: object) -> IdentityContext:
        result = self._authenticator.authenticate(request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, IdentityContext):
            raise AuthenticationError("the identity provider returned no valid identity")
        if result.tenant_id != self._tenant_id:
            raise AuthenticationError("the identity provider returned a cross-tenant identity")
        return result


@dataclass(frozen=True, slots=True)
class PeerIdentity:
    """Authenticated identity of the warden that signed an HTTP message."""

    warden_id: str
    key_id: str

    def __post_init__(self) -> None:
        require_warden_id(self.warden_id, field="peer warden_id")
        require_key_id(self.key_id, field="peer key_id")


class PeerSigner(Protocol):
    warden_id: str
    key_id: str

    def sign(self, payload: bytes) -> bytes: ...


class PeerTrustRegistry(Protocol):
    def verify(
        self,
        warden_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> bool: ...


@runtime_checkable
class ReplayStore(Protocol):
    """Atomic durable nonce claim used after a peer signature is verified."""

    def claim(
        self,
        *,
        warden_id: str,
        key_id: str,
        nonce: str,
        timestamp_s: int,
        expires_at_s: int,
        now_s: int,
        clock_tolerance_s: int = 0,
    ) -> bool: ...


class CoreReplayAuthority(Protocol):
    """Core service boundary that burns transport nonces under the authority anchor."""

    def claim_peer_request(
        self,
        *,
        warden_id: str,
        key_id: str,
        nonce: str,
        timestamp_s: int,
        expires_at_s: int,
        now_s: int,
        clock_tolerance_s: int = 0,
    ) -> bool: ...


class CorePeerReplayStore:
    """ReplayStore adapter for the externally anchored core authority service."""

    def __init__(self, authority: CoreReplayAuthority) -> None:
        if not callable(getattr(authority, "claim_peer_request", None)):
            raise TypeError("core replay authority must implement claim_peer_request")
        self._authority = authority

    def claim(
        self,
        *,
        warden_id: str,
        key_id: str,
        nonce: str,
        timestamp_s: int,
        expires_at_s: int,
        now_s: int,
        clock_tolerance_s: int = 0,
    ) -> bool:
        return self._authority.claim_peer_request(
            warden_id=warden_id,
            key_id=key_id,
            nonce=nonce,
            timestamp_s=timestamp_s,
            expires_at_s=expires_at_s,
            now_s=now_s,
            clock_tolerance_s=clock_tolerance_s,
        )


@dataclass(frozen=True, slots=True)
class LegacyPeerReplaySnapshot:
    """Bounded logical snapshot imported once from the schema-1 replay database."""

    clock_floor_s: int | None
    active_claim_count: int
    digest: bytes


class SQLitePeerReplayStore:
    """Process-safe and crash-durable replay store backed by SQLite."""

    APPLICATION_ID = 0x4C455450
    SCHEMA_VERSION = 1

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5000,
        read_only: bool = False,
        immutable: bool = False,
        _create: bool = False,
    ) -> None:
        if str(path) == ":memory:":
            raise ValidationError("peer replay protection must use a durable SQLite file")
        self._path = str(Path(path).resolve())
        if busy_timeout_ms <= 0:
            raise ValidationError("busy_timeout_ms must be positive")
        self._busy_timeout_ms = busy_timeout_ms
        if type(read_only) is not bool:
            raise ValidationError("peer replay read_only must be a boolean")
        if _create and read_only:
            raise ValidationError("peer replay initialization cannot be read-only")
        if type(immutable) is not bool or (immutable and not read_only):
            raise ValidationError("peer replay immutable mode requires read_only=True")
        self._read_only = read_only
        self._immutable = immutable
        self._connect_path = self._path
        self._connect_uri = False
        reserved = False
        if _create:
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            try:
                descriptor = os.open(self._path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError as exc:
                raise StorageError("peer replay database already exists") from exc
            else:
                os.close(descriptor)
                reserved = True
        else:
            mode = "ro" if read_only else "rw"
            immutable_query = "&immutable=1" if immutable else ""
            self._connect_path = f"{Path(self._path).as_uri()}?mode={mode}{immutable_query}"
            self._connect_uri = True
        try:
            if _create:
                self._initialize()
            else:
                self._verify_existing()
            if self.integrity_check() != ("ok",):
                raise StorageError("peer replay database failed its integrity check")
        except BaseException:
            if reserved:
                with suppress(OSError):
                    os.unlink(self._path)
            raise

    @classmethod
    def initialize(cls, path: str | Path, *, busy_timeout_ms: int = 5000) -> Self:
        """Create replay authority state exactly once."""

        return cls(path, busy_timeout_ms=busy_timeout_ms, _create=True)

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS peer_http_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    clock_floor_s INTEGER CHECK (
                        clock_floor_s IS NULL OR clock_floor_s >= 0
                    )
                ) STRICT
                """
            )
            connection.execute(
                """
                INSERT OR IGNORE INTO peer_http_metadata(singleton, clock_floor_s)
                VALUES (1, NULL)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS peer_http_replay (
                    warden_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    timestamp_s INTEGER NOT NULL,
                    expires_at_s INTEGER NOT NULL,
                    PRIMARY KEY (warden_id, key_id, nonce)
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS peer_http_replay_expiry
                ON peer_http_replay(expires_at_s)
                """
            )
            connection.execute(f"PRAGMA application_id={self.APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version={self.SCHEMA_VERSION}")

    def _verify_existing(self) -> None:
        with closing(self._connect()) as connection:
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")
            }
            required = {"peer_http_metadata", "peer_http_replay"}
            if not required.issubset(tables):
                raise StorageError("peer replay database is empty or has an incomplete schema")
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id != self.APPLICATION_ID or schema_version != self.SCHEMA_VERSION:
                raise StorageError("peer replay database identity or schema version is invalid")
            metadata_info = tuple(connection.execute("PRAGMA table_info(peer_http_metadata)"))
            replay_info = tuple(connection.execute("PRAGMA table_info(peer_http_replay)"))
            metadata_columns = {str(row[1]) for row in metadata_info}
            replay_columns = {str(row[1]) for row in replay_info}
            if metadata_columns != {"singleton", "clock_floor_s"} or replay_columns != {
                "warden_id",
                "key_id",
                "nonce",
                "timestamp_s",
                "expires_at_s",
            }:
                raise StorageError("peer replay database schema is not supported")
            replay_primary_key = tuple(
                name
                for _, name in sorted(
                    (int(row[5]), str(row[1])) for row in replay_info if int(row[5]) > 0
                )
            )
            expiry_index = tuple(
                str(row[2])
                for row in connection.execute("PRAGMA index_info(peer_http_replay_expiry)")
            )
            if replay_primary_key != ("warden_id", "key_id", "nonce") or expiry_index != (
                "expires_at_s",
            ):
                raise StorageError("peer replay uniqueness or expiry index is missing")
            if (
                connection.execute(
                    "SELECT 1 FROM peer_http_metadata WHERE singleton = 1"
                ).fetchone()
                is None
            ):
                raise StorageError("peer replay database metadata is missing")
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            if not self._immutable and journal_mode.casefold() != "wal":
                raise StorageError("peer replay database must already use WAL journal mode")
            if self._immutable and journal_mode.casefold() not in {"delete", "wal"}:
                raise StorageError("frozen peer replay snapshot has an invalid journal mode")

    @property
    def path(self) -> str:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self._connect_path,
                timeout=self._busy_timeout_ms / 1000,
                isolation_level=None,
                uri=self._connect_uri,
            )
            connection.execute(f"PRAGMA busy_timeout={self._busy_timeout_ms}")
            if not self._read_only:
                connection.execute("PRAGMA synchronous=FULL")
            return connection
        except sqlite3.Error as exc:
            raise StorageError("could not open the durable peer replay database") from exc

    def integrity_check(self) -> tuple[str, ...]:
        try:
            with closing(self._connect()) as connection:
                return tuple(str(row[0]) for row in connection.execute("PRAGMA integrity_check"))
        except sqlite3.Error as exc:
            raise StorageError("could not verify the peer replay database integrity") from exc

    def active_claim_count(self, *, now_s: int) -> int:
        """Count still-valid schema-1 claims without materializing them."""

        if not self._read_only:
            raise ValidationError("legacy peer replay inspection requires a read-only store")
        if (
            isinstance(now_s, bool)
            or not isinstance(now_s, int)
            or now_s < 0
            or now_s > MAX_RESOURCE
        ):
            raise ValidationError("legacy peer replay inspection time is invalid")
        try:
            with closing(self._connect()) as connection:
                floor_row = connection.execute(
                    "SELECT clock_floor_s FROM peer_http_metadata WHERE singleton=1"
                ).fetchone()
                if floor_row is None:
                    raise StorageError("legacy peer replay clock metadata is missing")
                floor = None if floor_row[0] is None else int(floor_row[0])
                if floor is not None and now_s < floor:
                    raise ClockUncertainError(
                        "migration clock moved behind the legacy peer replay floor"
                    )
                count = connection.execute(
                    "SELECT COUNT(*) FROM peer_http_replay WHERE expires_at_s >= ?",
                    (now_s,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("could not inspect legacy peer replay claims") from exc
        return 0 if count is None else int(count[0])

    def snapshot(self, *, now_s: int, expected_digest: bytes) -> LegacyPeerReplaySnapshot:
        """Read frozen legacy metadata after binding the exact backup artifact.

        Migration deliberately refuses live legacy claims.  Operators stop the
        schema-1 node and wait out the peer signature validity window first, so
        the one-time import is O(1) in memory and WAL rather than an unbounded
        authority transaction.
        """

        if not self._read_only:
            raise ValidationError("legacy peer replay snapshots require a read-only store")
        if not isinstance(expected_digest, bytes) or len(expected_digest) != 32:
            raise ValidationError("legacy peer replay artifact digest must contain 32 bytes")
        if (
            isinstance(now_s, bool)
            or not isinstance(now_s, int)
            or now_s < 0
            or now_s > MAX_RESOURCE
        ):
            raise ValidationError("legacy peer replay snapshot time is invalid")
        before = self._artifact_digest()
        if before != expected_digest:
            raise ValidationError("legacy peer replay artifact digest changed before import")
        try:
            with closing(self._connect()) as connection:
                floor_row = connection.execute(
                    "SELECT clock_floor_s FROM peer_http_metadata WHERE singleton=1"
                ).fetchone()
                if floor_row is None:
                    raise StorageError("legacy peer replay clock metadata is missing")
                floor = None if floor_row[0] is None else int(floor_row[0])
                if floor is not None and now_s < floor:
                    raise ClockUncertainError(
                        "migration clock moved behind the legacy peer replay floor"
                    )
                count_row = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM peer_http_replay
                    WHERE expires_at_s >= ?
                    """,
                    (now_s,),
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError("could not snapshot the legacy peer replay database") from exc
        after = self._artifact_digest()
        if after != expected_digest:
            raise ValidationError("legacy peer replay artifact digest changed during import")
        active_claim_count = 0 if count_row is None else int(count_row[0])
        return LegacyPeerReplaySnapshot(floor, active_claim_count, expected_digest)

    def _artifact_digest(self) -> bytes:
        digest = sha256()
        try:
            with Path(self._path).open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
        except OSError as exc:
            raise StorageError("could not hash the legacy peer replay artifact") from exc
        return digest.digest()

    def claim(
        self,
        *,
        warden_id: str,
        key_id: str,
        nonce: str,
        timestamp_s: int,
        expires_at_s: int,
        now_s: int,
        clock_tolerance_s: int = 0,
    ) -> bool:
        require_warden_id(warden_id, field="peer warden_id")
        require_key_id(key_id, field="peer key_id")
        require_identifier(nonce, field="peer nonce")
        for name, value in (
            ("timestamp_s", timestamp_s),
            ("expires_at_s", expires_at_s),
            ("now_s", now_s),
            ("clock_tolerance_s", clock_tolerance_s),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > MAX_RESOURCE
            ):
                raise ValidationError(f"peer replay {name} must be a non-negative integer")
        if timestamp_s > MAX_RESOURCE - clock_tolerance_s:
            raise ValidationError("peer replay timestamp window exceeds signed 64-bit time")
        if expires_at_s < max(timestamp_s, now_s):
            raise ValidationError("peer replay expiry precedes its acceptance window")
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    floor_row = connection.execute(
                        "SELECT clock_floor_s FROM peer_http_metadata WHERE singleton = 1"
                    ).fetchone()
                    if floor_row is None:
                        raise StorageError("peer replay clock metadata is missing")
                    floor = floor_row[0]
                    if floor is not None and now_s < int(floor):
                        raise ClockUncertainError(
                            "peer HTTP clock moved behind its durable replay floor"
                        )
                    if floor is not None and timestamp_s + clock_tolerance_s < int(floor):
                        connection.rollback()
                        return False
                    if floor is None or now_s > int(floor):
                        connection.execute(
                            "UPDATE peer_http_metadata SET clock_floor_s = ? WHERE singleton = 1",
                            (now_s,),
                        )
                    connection.execute(
                        """
                        DELETE FROM peer_http_replay
                        WHERE (warden_id, key_id, nonce) IN (
                            SELECT warden_id, key_id, nonce
                            FROM peer_http_replay
                            WHERE expires_at_s < ?
                            ORDER BY expires_at_s, warden_id, key_id, nonce
                            LIMIT ?
                        )
                        """,
                        (now_s, _LEGACY_REPLAY_GC_BATCH),
                    )
                    connection.execute(
                        """
                        INSERT INTO peer_http_replay(
                            warden_id, key_id, nonce, timestamp_s, expires_at_s
                        ) VALUES (?, ?, ?, ?, ?)
                        """,
                        (warden_id, key_id, nonce, timestamp_s, expires_at_s),
                    )
                except sqlite3.IntegrityError:
                    connection.rollback()
                    return False
                except Exception:
                    connection.rollback()
                    raise
                connection.commit()
        except sqlite3.Error as exc:
            raise StorageError("could not claim a durable peer replay nonce") from exc
        return True

    def prune(self, *, now_s: int | None = None) -> int:
        cutoff = int(time.time()) if now_s is None else now_s
        if (
            isinstance(cutoff, bool)
            or not isinstance(cutoff, int)
            or cutoff < 0
            or cutoff > MAX_RESOURCE
        ):
            raise ValidationError(
                "peer replay prune time must be a non-negative signed 64-bit integer"
            )
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                floor_row = connection.execute(
                    "SELECT clock_floor_s FROM peer_http_metadata WHERE singleton = 1"
                ).fetchone()
                if floor_row is None:
                    raise StorageError("peer replay clock metadata is missing")
                floor = floor_row[0]
                if floor is not None and cutoff < int(floor):
                    raise ClockUncertainError(
                        "peer HTTP clock moved behind its durable replay floor"
                    )
                if floor is None or cutoff > int(floor):
                    connection.execute(
                        "UPDATE peer_http_metadata SET clock_floor_s = ? WHERE singleton = 1",
                        (cutoff,),
                    )
                cursor = connection.execute(
                    """
                    DELETE FROM peer_http_replay
                    WHERE (warden_id, key_id, nonce) IN (
                        SELECT warden_id, key_id, nonce
                        FROM peer_http_replay
                        WHERE expires_at_s < ?
                        ORDER BY expires_at_s, warden_id, key_id, nonce
                        LIMIT ?
                    )
                    """,
                    (cutoff, _LEGACY_REPLAY_GC_BATCH),
                )
                connection.commit()
                return cursor.rowcount
        except sqlite3.Error as exc:
            raise StorageError("could not prune the durable peer replay database") from exc


def peer_body_digest(body: bytes) -> str:
    if not isinstance(body, bytes):
        raise TypeError("peer HTTP body must be bytes")
    return f"sha256:{sha256(body).hexdigest()}"


def canonical_peer_message(
    *,
    method: str,
    path: str,
    content_digest: str,
    timestamp_s: int,
    nonce: str,
    warden_id: str,
    key_id: str,
) -> bytes:
    """Canonical, versioned signature input for one peer HTTP request."""

    if not method or not method.isascii():
        raise ValidationError("peer HTTP method is invalid")
    if not path.startswith("/") or "#" in path:
        raise ValidationError("peer HTTP target must be an absolute path without a fragment")
    if not content_digest.startswith("sha256:") or len(content_digest) != 71:
        raise ValidationError("peer content digest is malformed")
    if (
        isinstance(timestamp_s, bool)
        or not isinstance(timestamp_s, int)
        or timestamp_s < 0
        or timestamp_s > MAX_RESOURCE
    ):
        raise ValidationError("peer timestamp must be an integer")
    require_identifier(nonce, field="peer nonce")
    return canonical_json(
        {
            "type": "lets.peer-http-signature/v1",
            "method": method.upper(),
            "path": path,
            "content_digest": content_digest,
            "timestamp_s": timestamp_s,
            "nonce": nonce,
            "warden_id": require_warden_id(warden_id, field="peer warden_id"),
            "key_id": require_key_id(key_id, field="peer key_id"),
        }
    )


def sign_peer_headers(
    signer: PeerSigner,
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp_s: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Return all headers needed to authenticate one exact peer request."""

    actual_timestamp = int(time.time()) if timestamp_s is None else timestamp_s
    actual_nonce = secrets.token_urlsafe(24) if nonce is None else nonce
    digest = peer_body_digest(body)
    message = canonical_peer_message(
        method=method,
        path=path,
        content_digest=digest,
        timestamp_s=actual_timestamp,
        nonce=actual_nonce,
        warden_id=signer.warden_id,
        key_id=signer.key_id,
    )
    signature = signer.sign(message)
    if not isinstance(signature, bytes) or not signature:
        raise SignatureError("peer signer returned an invalid signature")
    return {
        PEER_WARDEN_HEADER: signer.warden_id,
        PEER_KEY_HEADER: signer.key_id,
        PEER_TIMESTAMP_HEADER: str(actual_timestamp),
        PEER_NONCE_HEADER: actual_nonce,
        PEER_CONTENT_DIGEST_HEADER: digest,
        PEER_SIGNATURE_HEADER: b64url_encode(signature),
    }


class PeerMessageAuthenticator:
    """Verify an Ed25519-authenticated HTTP body and durably reject replays."""

    def __init__(
        self,
        trust_registry: PeerTrustRegistry,
        replay_store: ReplayStore,
        *,
        max_skew_s: int = 30,
        now: Callable[[], float] = time.time,
    ) -> None:
        if (
            isinstance(max_skew_s, bool)
            or not isinstance(max_skew_s, int)
            or max_skew_s <= 0
            or max_skew_s > MAX_RESOURCE
        ):
            raise ValidationError("max_skew_s must be a positive integer")
        if not isinstance(replay_store, ReplayStore):
            raise TypeError("replay_store must implement the durable ReplayStore protocol")
        self._trust_registry = trust_registry
        self._replay_store = replay_store
        self._max_skew_s = max_skew_s
        self._now = now

    async def authenticate(self, request: object) -> PeerIdentity:
        headers = getattr(request, "headers", None)
        body_reader = getattr(request, "body", None)
        method = getattr(request, "method", None)
        if (
            not isinstance(headers, Mapping)
            or not callable(body_reader)
            or not isinstance(method, str)
        ):
            raise TypeError("peer authentication requires an ASGI-compatible request")
        warden_id = _required_single_header(request, PEER_WARDEN_HEADER)
        key_id = _required_single_header(request, PEER_KEY_HEADER)
        timestamp_text = _required_single_header(request, PEER_TIMESTAMP_HEADER)
        nonce = _required_single_header(request, PEER_NONCE_HEADER)
        claimed_digest = _required_single_header(request, PEER_CONTENT_DIGEST_HEADER)
        signature_text = _required_single_header(request, PEER_SIGNATURE_HEADER)
        try:
            if not timestamp_text or not timestamp_text.isascii() or not timestamp_text.isdecimal():
                raise ValueError
            timestamp_s = int(timestamp_text)
        except ValueError as exc:
            raise AuthenticationError("peer timestamp is malformed") from exc
        now_s = int(self._now())
        if abs(now_s - timestamp_s) > self._max_skew_s:
            raise AuthenticationError("peer timestamp is outside the accepted clock-skew window")
        if len(nonce) < 16 or len(nonce) > 256:
            raise AuthenticationError("peer nonce has an invalid length")

        body = await body_reader()
        if not isinstance(body, bytes):
            raise AuthenticationError("peer request body could not be authenticated")
        actual_digest = peer_body_digest(body)
        if not hmac.compare_digest(actual_digest, claimed_digest):
            raise SignatureError("peer request body digest does not match its signed headers")
        path = asgi_request_target(request)
        message = canonical_peer_message(
            method=method,
            path=path,
            content_digest=claimed_digest,
            timestamp_s=timestamp_s,
            nonce=nonce,
            warden_id=warden_id,
            key_id=key_id,
        )
        try:
            signature = b64url_decode(signature_text)
            valid = self._trust_registry.verify(warden_id, key_id, message, signature)
        except Exception as exc:
            raise SignatureError("peer request signature could not be verified") from exc
        if valid is not True:
            raise SignatureError("peer request signature is invalid or untrusted")
        # The production replay boundary performs an anchored SQLite commit.  Keep
        # that bounded blocking operation off the ASGI event loop so liveness and
        # unrelated request parsing continue while the single authority writer is
        # serialized in its worker thread.
        claimed = await asyncio.to_thread(
            self._replay_store.claim,
            warden_id=warden_id,
            key_id=key_id,
            nonce=nonce,
            timestamp_s=timestamp_s,
            expires_at_s=max(now_s, timestamp_s) + self._max_skew_s,
            now_s=now_s,
            clock_tolerance_s=self._max_skew_s,
        )
        if not claimed:
            raise ReplayError("peer request nonce was already accepted")
        return PeerIdentity(warden_id=warden_id, key_id=key_id)


def asgi_request_target(request: object) -> str:
    """Return the raw path and query used in peer signature verification."""

    scope = getattr(request, "scope", None)
    if not isinstance(scope, Mapping):
        raise AuthenticationError("peer request has no ASGI scope")
    raw_path = scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        path = scope.get("path")
        if not isinstance(path, str):
            raise AuthenticationError("peer request path is unavailable")
        raw_path = path.encode("utf-8")
    query = scope.get("query_string", b"")
    if not isinstance(query, bytes):
        raise AuthenticationError("peer request query is malformed")
    try:
        target = raw_path.decode("ascii")
        if query:
            target = f"{target}?{query.decode('ascii')}"
    except UnicodeDecodeError as exc:
        raise AuthenticationError("peer request target must be ASCII encoded") from exc
    return target


def _single_header(request: object, name: str) -> str | None:
    """Return one header value and reject ambiguous duplicate ASGI fields."""

    scope = getattr(request, "scope", None)
    if isinstance(scope, Mapping):
        raw_headers = scope.get("headers")
        if isinstance(raw_headers, Sequence) and not isinstance(
            raw_headers, (str, bytes, bytearray)
        ):
            encoded_name = name.encode("ascii").lower()
            matches = [
                value
                for key, value in raw_headers
                if isinstance(key, bytes)
                and isinstance(value, bytes)
                and key.lower() == encoded_name
            ]
            if len(matches) > 1:
                raise AuthenticationError(f"duplicate authentication header: {name}")
            if matches:
                try:
                    return matches[0].decode("latin-1")
                except UnicodeDecodeError as exc:
                    raise AuthenticationError(
                        f"authentication header is malformed: {name}"
                    ) from exc
    headers = getattr(request, "headers", None)
    if not isinstance(headers, Mapping):
        return None
    value = headers.get(name)
    return value if isinstance(value, str) else None


def _required_single_header(request: object, name: str) -> str:
    value = _single_header(request, name)
    if value is None:
        raise AuthenticationError(f"required peer authentication header is missing: {name}")
    return value
