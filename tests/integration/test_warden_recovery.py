from __future__ import annotations

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ConflictError
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

_TEST_SIGNING_SEED = bytes(range(32))


def _policy() -> PolicySpec:
    return PolicySpec(
        "policy",
        "v1",
        (ResourceDimension("work", "count"),),
        MachineSpec(
            "machine",
            "ready",
            (TransitionSpec("work", "ready", "ready", (1,), "work.execute"),),
        ),
        10_000,
        100,
        0,
        8,
    )


def _open(
    path: Path, *, initialize: bool = True
) -> tuple[SQLiteStorage, WardenService, ManualClock]:
    clock = ManualClock(1_000_000)
    signer = Ed25519Signer.from_seed("warden-a", _TEST_SIGNING_SEED)
    factory = SQLiteStorage.initialize if initialize else SQLiteStorage
    store = factory(
        path,
        "warden-a",
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        transfer_gap_window=8,
    )
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(_policy())
    return store, service, clock


def _agent() -> IdentityContext:
    return IdentityContext("agent", "tenant", frozenset({"lets.lease.issue"}))


def test_reopen_preserves_receipt_idempotency_and_audit(tmp_path: Path) -> None:
    path = tmp_path / "warden.db"
    store, service, _ = _open(path)
    grant = service.issue_root(
        request_id="issue",
        identity=_agent(),
        tenant_id="tenant",
        envelope_id="envelope",
        subject_id="agent",
        allocation=(10,),
        capabilities={"work.execute"},
        policy_digest=_policy().digest,
        ttl_ns=1_000,
    )
    receipt = service.authorize(
        request_id="authorize",
        identity=_agent(),
        lease_id=grant.lease_id,
        transition="work",
        audience="executor",
        nonce="recovery-nonce-01",
        expected_sequence=0,
    )
    store.close()

    reopened, recovered, _ = _open(path, initialize=False)
    try:
        duplicate = recovered.authorize(
            request_id="authorize",
            identity=_agent(),
            lease_id=grant.lease_id,
            transition="work",
            audience="executor",
            nonce="recovery-nonce-01",
            expected_sequence=0,
        )
        assert duplicate == receipt
        assert recovered.snapshot(identity=_agent(), lease_id=grant.lease_id).residual == (9,)
        assert recovered.verify_audit(
            identity=IdentityContext("operator", "tenant", frozenset({"lets.admin"}))
        )
        assert reopened.pragma_integrity_check() == ("ok",)
        assert reopened.pragma_foreign_key_check() == []
    finally:
        reopened.close()


def test_concurrent_same_request_creates_one_root(tmp_path: Path) -> None:
    store, service, _ = _open(tmp_path / "warden.db")
    try:

        def issue() -> str:
            return service.issue_root(
                request_id="one-request",
                identity=_agent(),
                tenant_id="tenant",
                envelope_id="envelope",
                subject_id="agent",
                allocation=(10,),
                capabilities={"work.execute"},
                policy_digest=_policy().digest,
                ttl_ns=1_000,
            ).lease_id

        with ThreadPoolExecutor(max_workers=8) as executor:
            lease_ids = list(executor.map(lambda _: issue(), range(32)))
        assert len(set(lease_ids)) == 1
        with store.read() as transaction:
            assert transaction.connection.execute("SELECT COUNT(*) FROM leases").fetchone()[0] == 1
            free_blob = transaction.connection.execute(
                "SELECT free_pool FROM warden_state"
            ).fetchone()[0]
            assert transaction.unpack_vector(free_blob) == (90,)
    finally:
        store.close()


def test_concurrent_expected_sequence_allows_one_debit(tmp_path: Path) -> None:
    store, service, _ = _open(tmp_path / "warden.db")
    try:
        grant = service.issue_root(
            request_id="issue",
            identity=_agent(),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="agent",
            allocation=(20,),
            capabilities={"work.execute"},
            policy_digest=_policy().digest,
            ttl_ns=1_000,
        )

        def authorize(index: int) -> bool:
            try:
                service.authorize(
                    request_id=f"authorize-{index}",
                    identity=_agent(),
                    lease_id=grant.lease_id,
                    transition="work",
                    audience="executor",
                    nonce=f"concurrent-nonce-{index:04d}",
                    expected_sequence=0,
                )
            except ConflictError:
                return False
            return True

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(authorize, range(32)))
        assert sum(results) == 1
        snapshot = service.snapshot(identity=_agent(), lease_id=grant.lease_id)
        assert snapshot.sequence == 1
        assert snapshot.residual == (19,)
        with store.read() as transaction:
            count = transaction.connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            assert count == 1
    finally:
        store.close()


@pytest.mark.skipif(os.name != "nt", reason="this crash harness targets the Windows runtime")
def test_abrupt_process_exit_recovers_committed_authorization(tmp_path: Path) -> None:
    path = tmp_path / "crash.db"
    script = r"""
import os
import sys
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

path = sys.argv[1]
signer = Ed25519Signer.from_seed("warden-a", bytes(range(32)))
store = SQLiteStorage.initialize(
    path,
    "warden-a",
    (100,),
    signing_key_id=signer.key_id,
    signing_public_key=signer.public_key_bytes,
    tenant_id="tenant",
    envelope_id="envelope",
    receipt_ttl_ns=100,
    transfer_gap_window=8,
)
registry = PublicKeyRegistry()
registry.register_signer(signer)
service = WardenService(
    store,
    signer=signer,
    clock=ManualClock(1_000_000),
    trust_registry=registry,
)
policy = PolicySpec(
    "policy",
    "v1",
    (ResourceDimension("work", "count"),),
    MachineSpec(
        "machine",
        "ready",
        (TransitionSpec("work", "ready", "ready", (1,), "work.execute"),),
    ),
    10_000,
    100,
    0,
    8,
)
service.register_policy(policy)
identity = IdentityContext("agent", "tenant", frozenset({"lets.lease.issue"}))
grant = service.issue_root(
    request_id="issue",
    identity=identity,
    tenant_id="tenant",
    envelope_id="envelope",
    subject_id="agent",
    allocation=(10,),
    capabilities={"work.execute"},
    policy_digest=policy.digest,
    ttl_ns=1_000,
)
service.authorize(
    request_id="authorize",
    identity=identity,
    lease_id=grant.lease_id,
    transition="work",
    audience="executor",
    nonce="abrupt-exit-nonce",
    expected_sequence=0,
)
os._exit(73)
"""
    process = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert process.returncode == 73, process.stderr

    store, service, _ = _open(path, initialize=False)
    try:
        with store.read() as transaction:
            lease_id = transaction.connection.execute("SELECT lease_id FROM leases").fetchone()[0]
        duplicate = service.authorize(
            request_id="authorize",
            identity=_agent(),
            lease_id=lease_id,
            transition="work",
            audience="executor",
            nonce="abrupt-exit-nonce",
            expected_sequence=0,
        )
        assert duplicate.resulting_sequence == 1
        assert service.snapshot(identity=_agent(), lease_id=lease_id).residual == (9,)
        assert store.pragma_integrity_check() == ("ok",)
    finally:
        store.close()
