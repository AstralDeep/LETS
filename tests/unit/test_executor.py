from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ClockUncertainError, PolicyError, ReplayError, SignatureError, StorageError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import Receipt

POLICY_DIGEST = "sha256:" + "1" * 64
MACHINE_DIGEST = "sha256:" + "2" * 64


def _signed_receipt(
    signer: Ed25519Signer,
    *,
    receipt_id: str = "receipt-1",
    nonce: str = "nonce-1",
    sequence: int = 1,
    audience: str = "executor-a",
    issued_at_ns: int = 90,
    expires_at_ns: int = 200,
) -> Receipt:
    receipt = Receipt(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        receipt_id=receipt_id,
        request_id=f"request-{receipt_id}",
        warden_id=signer.warden_id,
        key_id=signer.key_id,
        policy_id="policy-a",
        policy_version="v1",
        policy_digest=POLICY_DIGEST,
        machine_digest=MACHINE_DIGEST,
        lease_id="lease-a",
        lineage_id="lineage-a",
        subject_id="subject-a",
        executor_audience=audience,
        transition="run",
        source_state="ready",
        target_state="running",
        cost=(1, 2),
        resulting_sequence=sequence,
        evidence_digest=None,
        nonce=nonce,
        issued_at_ns=issued_at_ns,
        expires_at_ns=expires_at_ns,
    )
    signature = b64url_encode(signer.sign(canonical_json(receipt.unsigned_payload())))
    return replace(receipt, signature=signature)


def _verifier(
    path: Path,
    signer: Ed25519Signer,
    *,
    now_ns: int = 100,
    uncertainty_ns: int = 0,
    initialize: bool = True,
) -> ReceiptVerifier:
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    policy = ExecutorPolicy(
        audience="executor-a",
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        allowed_policy_digests=frozenset({POLICY_DIGEST}),
        allowed_machine_digests=frozenset({MACHINE_DIGEST}),
        trusted_wardens=frozenset({signer.warden_id}),
        max_clock_uncertainty_ns=5,
    )
    clock = ManualClock(now_ns, uncertainty_ns)
    factory = SQLiteReceiptReplayStore.initialize if initialize else SQLiteReceiptReplayStore
    return ReceiptVerifier(registry, factory(path), policy, clock=clock)


def test_valid_receipt_is_claimed_exactly_once_across_restart(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden-a")
    path = tmp_path / "executor.sqlite3"
    receipt = _signed_receipt(signer)

    _verifier(path, signer).verify_and_claim(receipt)

    restarted = _verifier(path, signer, initialize=False)
    assert SQLiteReceiptReplayStore(path).integrity_check() == ("ok",)
    with pytest.raises(ReplayError):
        restarted.verify_and_claim(receipt)


def test_domain_nonce_is_unique_across_trusted_wardens(tmp_path: Path) -> None:
    first = Ed25519Signer.generate("warden-a")
    second = Ed25519Signer.generate("warden-b")
    registry = PublicKeyRegistry()
    registry.register_signer(first)
    registry.register_signer(second)
    verifier = ReceiptVerifier(
        registry,
        SQLiteReceiptReplayStore.initialize(tmp_path / "executor.sqlite3"),
        ExecutorPolicy(
            audience="executor-a",
            tenant_id="tenant-a",
            envelope_id="envelope-a",
            config_epoch=1,
            allowed_policy_digests=frozenset({POLICY_DIGEST}),
            allowed_machine_digests=frozenset({MACHINE_DIGEST}),
            trusted_wardens=frozenset({first.warden_id, second.warden_id}),
        ),
        clock=ManualClock(100),
    )
    verifier.verify_and_claim(
        _signed_receipt(first, receipt_id="receipt-a", nonce="shared-effect-nonce")
    )
    with pytest.raises(ReplayError, match="nonce"):
        verifier.verify_and_claim(
            _signed_receipt(second, receipt_id="receipt-b", nonce="shared-effect-nonce")
        )


def test_sequence_watermark_rejects_an_older_fresh_receipt(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden-a")
    verifier = _verifier(tmp_path / "executor.sqlite3", signer)
    verifier.verify_and_claim(
        _signed_receipt(signer, receipt_id="receipt-2", nonce="nonce-2", sequence=2)
    )

    with pytest.raises(ReplayError, match="watermark"):
        verifier.verify_and_claim(
            _signed_receipt(signer, receipt_id="receipt-1", nonce="nonce-1", sequence=1)
        )


@pytest.mark.parametrize(
    ("receipt", "error"),
    [
        ({"audience": "executor-b"}, PolicyError),
        ({"issued_at_ns": 101}, PolicyError),
        ({"expires_at_ns": 100}, PolicyError),
    ],
)
def test_executor_rejects_wrong_audience_or_invalid_time(
    tmp_path: Path,
    receipt: dict[str, object],
    error: type[Exception],
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    candidate = _signed_receipt(signer, **receipt)  # type: ignore[arg-type]
    with pytest.raises(error):
        _verifier(tmp_path / "executor.sqlite3", signer).verify(candidate)


def test_executor_rejects_signature_tampering_and_untrusted_keys(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden-a")
    receipt = _signed_receipt(signer)
    verifier = _verifier(tmp_path / "executor.sqlite3", signer)

    with pytest.raises(SignatureError):
        verifier.verify(replace(receipt, signature=b64url_encode(b"x" * 64)))

    other = Ed25519Signer.generate("warden-b")
    registry = PublicKeyRegistry()
    registry.register_signer(other)
    policy = replace(verifier.policy, trusted_wardens=frozenset())
    untrusted = ReceiptVerifier(
        registry,
        SQLiteReceiptReplayStore.initialize(tmp_path / "untrusted.sqlite3"),
        policy,
        clock=ManualClock(100),
    )
    with pytest.raises(SignatureError):
        untrusted.verify(receipt)


def test_executor_fails_closed_on_excessive_clock_uncertainty(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden-a")
    receipt = _signed_receipt(signer)

    with pytest.raises(ClockUncertainError):
        _verifier(
            tmp_path / "executor.sqlite3",
            signer,
            uncertainty_ns=6,
        ).verify(receipt)


def test_replay_store_requires_durable_filesystem_storage() -> None:
    with pytest.raises(ValueError, match="filesystem-backed"):
        SQLiteReceiptReplayStore(":memory:")


def test_executor_replay_open_does_not_reset_missing_state(tmp_path: Path) -> None:
    path = tmp_path / "missing-executor-replay.sqlite3"
    with pytest.raises(StorageError, match="could not open"):
        SQLiteReceiptReplayStore(path)
    assert not path.exists()

    empty = tmp_path / "empty-executor-replay.sqlite3"
    empty.write_bytes(b"")
    with pytest.raises(StorageError, match="empty or has an incomplete schema"):
        SQLiteReceiptReplayStore(empty)
    assert empty.read_bytes() == b""


def test_executor_replay_rejects_versioned_schema_without_nonce_uniqueness(
    tmp_path: Path,
) -> None:
    path = tmp_path / "weakened-executor-replay.sqlite3"
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute(f"PRAGMA application_id={SQLiteReceiptReplayStore.APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={SQLiteReceiptReplayStore.SCHEMA_VERSION}")
        connection.executescript(
            """
            CREATE TABLE metadata(
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                clock_floor_ns INTEGER
            ) STRICT;
            INSERT INTO metadata VALUES (1, 4, NULL);
            CREATE TABLE receipt_claims(
                receipt_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                envelope_id TEXT NOT NULL,
                warden_id TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                audience TEXT NOT NULL,
                resulting_sequence INTEGER NOT NULL,
                nonce TEXT NOT NULL,
                claimed_at_ns INTEGER NOT NULL,
                expires_at_ns INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX ix_receipt_claims_expiry ON receipt_claims(expires_at_ns);
            CREATE TABLE lease_watermarks(
                warden_id TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                audience TEXT NOT NULL,
                last_sequence INTEGER NOT NULL,
                updated_at_ns INTEGER NOT NULL,
                expires_at_ns INTEGER NOT NULL,
                PRIMARY KEY(warden_id, lease_id, audience)
            ) STRICT, WITHOUT ROWID;
            """
        )
    with pytest.raises(StorageError, match="uniqueness"):
        SQLiteReceiptReplayStore(path)
