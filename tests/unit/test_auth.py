from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pytest

from lets.auth import (
    AuthenticationError,
    SQLitePeerReplayStore,
    StaticBearerAuthenticator,
)
from lets.errors import ClockUncertainError, StorageError, ValidationError
from lets.models import IdentityContext


@dataclass
class Request:
    headers: dict[str, str]


def _identity() -> IdentityContext:
    return IdentityContext(
        subject_id="operator",
        tenant_id="tenant-a",
        scopes=frozenset({"lets.admin"}),
        authentication_method="test",
    )


def test_static_bearer_keeps_only_digest_and_authenticates() -> None:
    token = "correct-horse-battery-staple"
    authenticator = StaticBearerAuthenticator.single(token, _identity())

    assert authenticator.authenticate(Request({"authorization": f"Bearer {token}"})) == _identity()
    assert token.encode() not in repr(authenticator.__dict__).encode()
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(Request({"authorization": "Bearer incorrect-token"}))
    with pytest.raises(AuthenticationError):
        authenticator.authenticate(Request({}))


def test_static_bearer_can_load_persisted_sha256_digest() -> None:
    digest = "41" * 32
    authenticator = StaticBearerAuthenticator.from_sha256_digests(((digest, _identity()),))

    assert authenticator._entries[0][0] == bytes.fromhex(digest)
    with pytest.raises(ValidationError):
        StaticBearerAuthenticator.from_sha256_digests((("not-a-digest", _identity()),))


def test_sqlite_peer_replay_claim_is_durable_and_atomic(tmp_path: Path) -> None:
    path = tmp_path / "peer-replay.sqlite3"
    first = SQLitePeerReplayStore.initialize(path)
    now = int(time.time())

    assert first.claim(
        warden_id="warden-a",
        key_id="warden-a/key-1",
        nonce="nonce-with-enough-entropy",
        timestamp_s=now,
        expires_at_s=now + 60,
        now_s=now,
    )
    reopened = SQLitePeerReplayStore(path)
    assert not reopened.claim(
        warden_id="warden-a",
        key_id="warden-a/key-1",
        nonce="nonce-with-enough-entropy",
        timestamp_s=now + 1,
        expires_at_s=now + 61,
        now_s=now + 1,
    )


def test_sqlite_peer_replay_rejects_memory_database() -> None:
    with pytest.raises(ValidationError, match="durable"):
        SQLitePeerReplayStore(":memory:")


def test_peer_replay_open_does_not_recreate_missing_state(tmp_path: Path) -> None:
    path = tmp_path / "missing-peer-replay.sqlite3"
    with pytest.raises(StorageError, match="could not open"):
        SQLitePeerReplayStore(path)
    assert not path.exists()

    empty = tmp_path / "empty-peer-replay.sqlite3"
    empty.write_bytes(b"")
    with pytest.raises(StorageError, match="empty or has an incomplete schema"):
        SQLitePeerReplayStore(empty)
    assert empty.read_bytes() == b""


def test_peer_replay_rejects_versioned_schema_without_nonce_primary_key(tmp_path: Path) -> None:
    path = tmp_path / "weakened-peer-replay.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA application_id={SQLitePeerReplayStore.APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={SQLitePeerReplayStore.SCHEMA_VERSION}")
        connection.executescript(
            """
            CREATE TABLE peer_http_metadata(
                singleton INTEGER PRIMARY KEY,
                clock_floor_s INTEGER
            ) STRICT;
            INSERT INTO peer_http_metadata VALUES (1, NULL);
            CREATE TABLE peer_http_replay(
                warden_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                nonce TEXT NOT NULL,
                timestamp_s INTEGER NOT NULL,
                expires_at_s INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX peer_http_replay_expiry ON peer_http_replay(expires_at_s);
            """
        )
    with pytest.raises(StorageError, match="uniqueness"):
        SQLitePeerReplayStore(path)


def test_sqlite_peer_replay_prunes_in_same_claim_transaction(tmp_path: Path) -> None:
    path = tmp_path / "bounded-replay.sqlite3"
    replay = SQLitePeerReplayStore.initialize(path)
    start = int(time.time())

    for offset in range(200):
        assert replay.claim(
            warden_id="warden-a",
            key_id="warden-a/key-1",
            nonce=f"nonce-{offset}",
            timestamp_s=start + offset,
            expires_at_s=start + offset + 2,
            now_s=start + offset,
        )

    with closing(sqlite3.connect(path)) as connection:
        retained = int(connection.execute("SELECT COUNT(*) FROM peer_http_replay").fetchone()[0])
    assert retained <= 3


def test_peer_replay_clock_floor_survives_restart_and_blocks_revived_nonce(
    tmp_path: Path,
) -> None:
    path = tmp_path / "rollback-replay.sqlite3"
    replay = SQLitePeerReplayStore.initialize(path)
    assert replay.claim(
        warden_id="warden-a",
        key_id="warden-a/key-1",
        nonce="nonce-before-clock-jump",
        timestamp_s=100,
        expires_at_s=130,
        now_s=100,
        clock_tolerance_s=30,
    )
    assert replay.prune(now_s=200) == 1

    restarted = SQLitePeerReplayStore(path)
    with pytest.raises(ClockUncertainError, match="durable replay floor"):
        restarted.claim(
            warden_id="warden-a",
            key_id="warden-a/key-1",
            nonce="nonce-before-clock-jump",
            timestamp_s=100,
            expires_at_s=130,
            now_s=100,
            clock_tolerance_s=30,
        )
