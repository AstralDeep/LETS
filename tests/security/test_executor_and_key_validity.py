from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import pytest

from lets.canonical import b64url_encode, canonical_json
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ClockUncertainError, PolicyError, ReplayError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.manifest import ManifestPublicKey
from lets.models import Receipt

POLICY_DIGEST = "sha256:" + "1" * 64
MACHINE_DIGEST = "sha256:" + "2" * 64


def _receipt(
    signer: Ed25519Signer,
    *,
    receipt_id: str,
    lease_id: str = "lease-a",
    nonce: str,
    sequence: int,
    issued_at_ns: int = 90,
    expires_at_ns: int = 200,
) -> Receipt:
    unsigned = Receipt(
        tenant_id="tenant",
        envelope_id="envelope",
        config_epoch=1,
        receipt_id=receipt_id,
        request_id=f"request-{receipt_id}",
        warden_id=signer.warden_id,
        key_id=signer.key_id,
        policy_id="policy",
        policy_version="v1",
        policy_digest=POLICY_DIGEST,
        machine_digest=MACHINE_DIGEST,
        lease_id=lease_id,
        lineage_id="lineage",
        subject_id="agent",
        executor_audience="executor",
        transition="act",
        source_state="ready",
        target_state="ready",
        cost=(1,),
        resulting_sequence=sequence,
        evidence_digest=None,
        nonce=nonce,
        issued_at_ns=issued_at_ns,
        expires_at_ns=expires_at_ns,
    )
    return replace(
        unsigned,
        signature=b64url_encode(signer.sign(canonical_json(unsigned.unsigned_payload()))),
    )


def _verifier(
    path: Path,
    signer: Ed25519Signer,
    clock: ManualClock,
    *,
    initialize: bool = True,
) -> ReceiptVerifier:
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    factory = SQLiteReceiptReplayStore.initialize if initialize else SQLiteReceiptReplayStore
    return ReceiptVerifier(
        registry,
        factory(path),
        ExecutorPolicy(
            audience="executor",
            tenant_id="tenant",
            envelope_id="envelope",
            config_epoch=1,
            allowed_policy_digests=frozenset({POLICY_DIGEST}),
            allowed_machine_digests=frozenset({MACHINE_DIGEST}),
            trusted_wardens=frozenset({signer.warden_id}),
        ),
        clock=clock,
    )


def test_concurrent_executor_claim_has_one_winner(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden")
    clock = ManualClock(100)
    verifier = _verifier(tmp_path / "executor.sqlite3", signer, clock)
    receipt = _receipt(signer, receipt_id="receipt", nonce="nonce", sequence=1)

    def claim(_: int) -> bool:
        try:
            verifier.verify_and_claim(receipt)
        except ReplayError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(claim, range(32)))
    assert sum(results) == 1


def test_expired_watermarks_are_bounded_and_late_receipts_still_fail_closed(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate("warden")
    clock = ManualClock(100)
    path = tmp_path / "executor.sqlite3"
    verifier = _verifier(path, signer, clock)
    first = _receipt(
        signer,
        receipt_id="receipt-a",
        lease_id="lease-a",
        nonce="nonce-a",
        sequence=2,
        expires_at_ns=150,
    )
    verifier.verify_and_claim(first)

    clock.current_ns = 150
    with pytest.raises(PolicyError, match="expired"):
        verifier.verify_and_claim(first)
    second = _receipt(
        signer,
        receipt_id="receipt-b",
        lease_id="lease-b",
        nonce="nonce-b",
        sequence=1,
        issued_at_ns=149,
        expires_at_ns=250,
    )
    verifier.verify_and_claim(second)
    with closing(sqlite3.connect(path)) as connection:
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM lease_watermarks WHERE lease_id = 'lease-a'"
            ).fetchone()[0]
            == 0
        )
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM receipt_claims WHERE receipt_id = 'receipt-a'"
            ).fetchone()[0]
            == 0
        )

    restarted = _verifier(path, signer, clock, initialize=False)
    with pytest.raises(PolicyError, match="expired"):
        restarted.verify_and_claim(first)
    with pytest.raises(ReplayError):
        restarted.verify_and_claim(second)


def test_peer_key_validity_is_enforced_with_clock_uncertainty() -> None:
    signer = Ed25519Signer.generate("warden")
    clock = ManualClock(100)
    registry = PublicKeyRegistry(clock=clock)
    registry.register(
        signer.warden_id,
        signer.key_id,
        signer.public_key_bytes,
        not_before_ns=90,
        not_after_ns=110,
    )
    payload = b"signed payload"
    signature = signer.sign(payload)
    assert registry.verify(signer.warden_id, signer.key_id, payload, signature)

    clock.current_ns = 90
    clock.declared_uncertainty_ns = 1
    assert not registry.verify(signer.warden_id, signer.key_id, payload, signature)
    clock.current_ns = 109
    assert not registry.verify(signer.warden_id, signer.key_id, payload, signature)
    clock.declared_uncertainty_ns = 0
    assert registry.verify(signer.warden_id, signer.key_id, payload, signature)
    clock.current_ns = 110
    assert not registry.verify(signer.warden_id, signer.key_id, payload, signature)


def test_manifest_key_validity_converts_offsets_to_exact_unix_nanoseconds() -> None:
    signer = Ed25519Signer.generate("warden")
    key = ManifestPublicKey(
        signer.key_id,
        signer.public_key_bytes,
        not_before="1970-01-01T00:00:01.000001Z",
        not_after="1970-01-01T01:00:02.000001+01:00",
    )
    assert key.not_before_ns == 1_000_001_000
    assert key.not_after_ns == 2_000_001_000
    nanosecond_key = ManifestPublicKey(
        signer.key_id,
        signer.public_key_bytes,
        not_before="1970-01-01T00:00:01.000000001Z",
    )
    assert nanosecond_key.not_before_ns == 1_000_000_001


def test_executor_replay_floor_survives_restart_and_rejects_clock_rollback(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate("warden")
    path = tmp_path / "executor.sqlite3"
    forward = ManualClock(150)
    verifier = _verifier(path, signer, forward)
    verifier.verify_and_claim(
        _receipt(
            signer,
            receipt_id="future-floor",
            lease_id="lease-future",
            nonce="nonce-future",
            sequence=1,
            issued_at_ns=140,
            expires_at_ns=300,
        )
    )

    rolled_back = ManualClock(100)
    restarted = _verifier(path, signer, rolled_back, initialize=False)
    with pytest.raises(ClockUncertainError, match="durable floor"):
        restarted.verify_and_claim(
            _receipt(
                signer,
                receipt_id="rollback-receipt",
                lease_id="lease-rollback",
                nonce="nonce-rollback",
                sequence=1,
                issued_at_ns=90,
                expires_at_ns=250,
            )
        )
