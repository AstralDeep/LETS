from __future__ import annotations

import json
import time
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

import lets.cli as cli_module
import lets.runtime as runtime_module
from lets.audit import AuditExporter, SQLiteAuditSink
from lets.auth import SQLitePeerReplayStore
from lets.authority import FileAuthorityAnchor
from lets.canonical import b64url_encode, canonical_json
from lets.cli import (
    _operator_service,
    _parser,
    _recovery_backup,
    _recovery_restore,
    _recovery_verify,
)
from lets.crypto import Ed25519Signer
from lets.errors import InvariantError, StorageError
from lets.manifest import (
    ClusterManifest,
    ManifestPublicKey,
    ManifestSignature,
    WardenManifest,
)
from lets.models import IdentityContext, RuntimeMode
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.recovery import (
    create_recovery_bundle,
    install_verified_artifact,
    verify_recovery_bundle,
)
from lets.runtime import RUNTIME_PROVIDER_GROUP, RuntimeBindings
from lets.service import WardenService
from lets.storage import SQLiteStorage


class Authenticator:
    def __init__(self, identity: IdentityContext) -> None:
        self._identity = identity

    def authenticate(self, _request: object) -> IdentityContext:
        return self._identity


@dataclass
class FakeEntryPoint:
    name: str
    factory: object
    group: str = RUNTIME_PROVIDER_GROUP

    def load(self) -> object:
        return self.factory


def test_stale_recovery_bundle_is_fenced_before_live_files_are_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "node"
    authority = tmp_path / "independent-authority"
    audit = tmp_path / "independent-audit"
    state.mkdir()
    authority.mkdir()
    audit.mkdir()
    signer = Ed25519Signer.generate("warden-a")
    operator_signer = Ed25519Signer.generate("operator-a")
    resources = (ResourceDimension("actions", "count"),)
    policy = PolicySpec(
        policy_id="runtime",
        policy_version="v1",
        dimensions=resources,
        machine=MachineSpec(
            machine_id="agent",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    name="run",
                    source="ready",
                    target="ready",
                    cost=(1,),
                    capability="agent.run",
                ),
            ),
        ),
        max_lease_ttl_ns=1_000_000,
        receipt_ttl_ns=1_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )
    unsigned_manifest = ClusterManifest(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        created_at="2026-08-09T05:00:00Z",
        resources=resources,
        initial_budget=(10,),
        wardens=(
            WardenManifest(
                "warden-a",
                "https://warden-a.example:8741",
                "https://warden-a.example:8741",
                (10,),
                (ManifestPublicKey(signer.key_id, signer.public_key_bytes),),
                {},
            ),
        ),
        policies=(policy,),
        extensions={},
    )
    manifest = replace(
        unsigned_manifest,
        signatures=(
            ManifestSignature(
                operator_signer.key_id,
                operator_signer.sign(canonical_json(unsigned_manifest.unsigned_dict())),
            ),
        ),
    )
    manifest_path = state / "cluster-manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
    anchor_path = authority / "head.json"
    archive_path = audit / "archive.sqlite3"
    SQLiteAuditSink.initialize(archive_path)
    operator = IdentityContext(
        subject_id="operator",
        tenant_id="tenant-a",
        scopes=frozenset({"lets.admin", "lets.audit.read", "lets.audit.verify"}),
        authentication_method="test-runtime-provider",
    )

    def provider(_context: object) -> RuntimeBindings:
        return RuntimeBindings(
            warden_id="warden-a",
            tenant_id="tenant-a",
            signer=signer,
            authenticator=Authenticator(operator),
            production_capable=True,
            authority_anchor=FileAuthorityAnchor(anchor_path),
            audit_sink=SQLiteAuditSink(archive_path),
        )

    monkeypatch.setattr(
        runtime_module.metadata,
        "entry_points",
        lambda *, group: (
            (FakeEntryPoint("managed", provider),) if group == RUNTIME_PROVIDER_GROUP else ()
        ),
    )

    core = state / "warden.sqlite3"
    store = SQLiteStorage.initialize(
        core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
        dimension_metadata=[{"name": "actions", "unit": "count", "description": ""}],
        receipt_ttl_ns=1_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
        authority_anchor=FileAuthorityAnchor(anchor_path),
        config={"manifest_digest": manifest.digest},
        min_free_disk_bytes=1,
        max_database_bytes=100_000_000,
        reserve_pages=1,
    )
    with store.write() as transaction:
        transaction.connection.execute(
            """
            INSERT INTO idempotency(
                tenant_id, envelope_id, scope, request_id, fingerprint,
                response, status_code, created_at_ns, expires_at_ns
            ) VALUES ('tenant-a', 'envelope-a', 'recovery-test', 'large-record',
                      x'01', zeroblob(?), 200, 0, NULL)
            """,
            (17 * 1024 * 1024,),
        )
    store.close()
    replay = state / "peer-replay.sqlite3"
    SQLitePeerReplayStore.initialize(replay)
    config_path = state / "config.json"
    config = {
        "version": 1,
        "warden_id": "warden-a",
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
        "config_epoch": 1,
        "budget": [10],
        "local_share": [10],
        "receipt_ttl_ns": 1_000_000,
        "max_clock_uncertainty_ns": 0,
        "transfer_gap_window": 64,
        "min_free_disk_bytes": 1,
        "max_database_bytes": 100_000_000,
        "reserve_pages": 1,
        "database": core.name,
        "replay_database": replay.name,
        "dimension_metadata": [{"name": "actions", "unit": "count", "description": ""}],
        "manifest": str(manifest_path.resolve()),
        "manifest_digest": manifest.digest,
        "manifest_policy_digests": [policy.digest],
        "operator_trust": {
            "threshold": 1,
            "accepted_signatures": [operator_signer.key_id],
            "keys": [
                {
                    "key_id": operator_signer.key_id,
                    "public_key": b64url_encode(operator_signer.public_key_bytes),
                }
            ],
        },
        "allow_insecure_manifest": False,
        "endpoints": {
            "client_endpoint": "https://warden-a.example:8741",
            "peer_endpoint": "https://warden-a.example:8741",
        },
        "runtime": {"provider": "managed", "options": {}},
        "bootstrap_identities": [],
        "trusted_peers": [],
        "peer_endpoints": {},
    }
    config_path.write_text(json.dumps(config, sort_keys=True) + "\n", encoding="utf-8")

    live = SQLiteStorage(
        core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
        authority_anchor=FileAuthorityAnchor(anchor_path),
        config={"manifest_digest": manifest.digest},
        min_free_disk_bytes=1,
        max_database_bytes=100_000_000,
        reserve_pages=1,
    )
    service, identity = _operator_service(config, signer, live)
    service.set_runtime_mode(
        request_id="drain-for-backup",
        identity=identity,
        mode=RuntimeMode.DRAINING,
        reason="consistent disaster-recovery snapshot",
    )
    assert AuditExporter(live, SQLiteAuditSink(archive_path)).run_once() == 1
    live.close()

    backup_domain = tmp_path / "backup-domain"
    backup_domain.mkdir()
    bundle_path = backup_domain / "recovery-bundle"
    backup_arguments = _parser().parse_args(
        ["recovery", "backup", "--output", str(bundle_path), "--production"]
    )
    assert _recovery_backup(config_path, backup_arguments) == 0
    assert not (bundle_path / anchor_path.name).exists()
    assert (bundle_path / "warden.sqlite3").stat().st_size > 16 * 1024 * 1024

    anchor_before_invalid_candidate = anchor_path.read_bytes()
    verify_arguments = _parser().parse_args(
        ["recovery", "verify", "--bundle", str(bundle_path), "--production"]
    )
    original_temporary_directory = cli_module.tempfile.TemporaryDirectory
    scratch_directories: list[Path] = []

    def tracked_temporary_directory(*args: object, **kwargs: object) -> object:
        scratch_directories.append(Path(str(kwargs["dir"])).resolve())
        return original_temporary_directory(*args, **kwargs)

    with monkeypatch.context() as explicit_scratch:
        explicit_scratch.setattr(
            cli_module.tempfile,
            "TemporaryDirectory",
            tracked_temporary_directory,
        )
        assert _recovery_verify(config_path, verify_arguments) == 0
    assert scratch_directories == [backup_domain.resolve()]

    def reject_invalid_audit(_service: WardenService, *, identity: IdentityContext) -> bool:
        raise InvariantError(f"injected invalid audit for {identity.subject_id}")

    with monkeypatch.context() as invalid_candidate:
        invalid_candidate.setattr(
            WardenService,
            "verify_audit",
            reject_invalid_audit,
        )
        with pytest.raises(InvariantError, match="injected invalid audit"):
            _recovery_verify(config_path, verify_arguments)
    assert anchor_path.read_bytes() == anchor_before_invalid_candidate

    # A self-consistent, signed candidate ahead of the live anchor must be
    # rejected before it can publish its additional audit tail into the live
    # independent archive.  Its local outbox is acknowledged against a separate
    # archive so every other recovery preflight check passes.
    verified = verify_recovery_bundle(bundle_path)
    ahead_core = tmp_path / "ahead.sqlite3"
    install_verified_artifact(verified.artifacts["core_database"], ahead_core)
    ahead = SQLiteStorage(
        ahead_core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
        config={"manifest_digest": manifest.digest},
        min_free_disk_bytes=1,
        max_database_bytes=100_000_000,
        reserve_pages=1,
    )
    ahead_service, ahead_identity = _operator_service(config, signer, ahead)
    ahead_service.set_runtime_mode(
        request_id="ahead-activate",
        identity=ahead_identity,
        mode=RuntimeMode.ACTIVE,
        reason="construct a valid ahead recovery candidate",
    )
    ahead_service.set_runtime_mode(
        request_id="ahead-drain",
        identity=ahead_identity,
        mode=RuntimeMode.DRAINING,
        reason="make the ahead candidate recovery-safe",
    )
    isolated_archive = tmp_path / "ahead-audit.sqlite3"
    SQLiteAuditSink.initialize(isolated_archive)
    assert AuditExporter(ahead, SQLiteAuditSink(isolated_archive)).run_once() >= 2
    ahead_checkpoint = ahead.authority_checkpoint().to_dict()
    ahead.close()
    ahead_bundle_path = backup_domain / "ahead-bundle"
    create_recovery_bundle(
        destination=ahead_bundle_path,
        config_path=config_path,
        core_database=ahead_core,
        replay_database=None,
        signed_manifest=manifest_path,
        source_schema_version=2,
        identity=verified.identity,
        authority_checkpoint=ahead_checkpoint,
    )
    ahead_restore_arguments = _parser().parse_args(
        [
            "recovery",
            "restore",
            "--bundle",
            str(ahead_bundle_path),
            "--confirm-warden-id",
            "warden-a",
        ]
    )
    archive_count = SQLiteAuditSink(archive_path).count()
    with pytest.raises(StorageError, match="does not exactly match the current authority anchor"):
        _recovery_restore(config_path, ahead_restore_arguments)
    assert SQLiteAuditSink(archive_path).count() == archive_count

    exact_restore_arguments = _parser().parse_args(
        [
            "recovery",
            "restore",
            "--bundle",
            str(bundle_path),
            "--confirm-warden-id",
            "warden-a",
        ]
    )
    wal = Path(f"{core}-wal")
    shm = Path(f"{core}-shm")
    wal.write_bytes(b"interrupted-wal-preservation")
    shm.write_bytes(b"interrupted-shm-preservation")
    original_preserve_sidecar = cli_module.preserve_and_remove_artifact
    sidecar_crashed = False

    def crash_after_sidecar_publication(source: Path, destination: Path) -> None:
        nonlocal sidecar_crashed
        if not sidecar_crashed:
            sidecar_crashed = True
            install_verified_artifact(source, destination)
            raise StorageError("injected crash after sidecar quarantine publication")
        original_preserve_sidecar(source, destination)

    with monkeypatch.context() as interrupted_sidecar:
        interrupted_sidecar.setattr(
            cli_module,
            "preserve_and_remove_artifact",
            crash_after_sidecar_publication,
        )
        with pytest.raises(StorageError, match="after sidecar quarantine publication"):
            _recovery_restore(config_path, exact_restore_arguments)
    prepared_journal = json.loads((state / "recovery-restore.json").read_text(encoding="utf-8"))
    assert prepared_journal["phase"] == "PREPARED"
    prepared_quarantine = Path(prepared_journal["quarantine"])
    assert wal.is_file()
    assert (prepared_quarantine / wal.name).read_bytes() == wal.read_bytes()

    original_preflight = cli_module._recovery_preflight

    def fail_post_publication_admission(
        *,
        store: SQLiteStorage,
        service: WardenService,
        identity: IdentityContext,
        require_anchor: bool,
    ) -> dict[str, object]:
        if Path(store.path).resolve() == core.resolve():
            raise StorageError("injected crash after anchored core publication")
        return original_preflight(
            store=store,
            service=service,
            identity=identity,
            require_anchor=require_anchor,
        )

    with monkeypatch.context() as interrupted_restore:
        interrupted_restore.setattr(
            cli_module, "_recovery_preflight", fail_post_publication_admission
        )
        with pytest.raises(StorageError, match="after anchored core publication"):
            _recovery_restore(config_path, exact_restore_arguments)
    interrupted_journal = json.loads((state / "recovery-restore.json").read_text(encoding="utf-8"))
    assert interrupted_journal["phase"] == "CORE_INSTALLED"
    interrupted_quarantine = Path(interrupted_journal["quarantine"])
    assert Path(interrupted_journal["workspace"]) == backup_domain.resolve()
    assert interrupted_quarantine.parent == backup_domain.resolve()
    assert (interrupted_quarantine / core.name).is_file()
    fenced_backup = _parser().parse_args(
        ["recovery", "backup", "--output", str(tmp_path / "must-not-back-up")]
    )
    with pytest.raises(StorageError, match="restore is incomplete"):
        _recovery_backup(config_path, fenced_backup)

    # Repeating the exact command resumes at anchored core admission.
    assert _recovery_restore(config_path, exact_restore_arguments) == 0
    assert _recovery_restore(config_path, exact_restore_arguments) == 0
    restore_journal = json.loads((state / "recovery-restore.json").read_text(encoding="utf-8"))
    assert restore_journal["phase"] == "COMPLETE"
    assert not interrupted_quarantine.exists()

    advanced = SQLiteStorage(
        core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
        authority_anchor=FileAuthorityAnchor(anchor_path),
        config={"manifest_digest": manifest.digest},
        min_free_disk_bytes=1,
        max_database_bytes=100_000_000,
        reserve_pages=1,
    )
    replay_service = WardenService(advanced, signer=signer)
    replay_now = int(time.time())
    assert replay_service.claim_peer_request(
        warden_id="warden-b",
        key_id="warden-b-key",
        nonce="recovery-replay-nonce-000001",
        timestamp_s=replay_now,
        expires_at_s=replay_now + 30,
        now_s=replay_now,
        clock_tolerance_s=30,
    )
    assert replay_service.peer_replay_status()["revision"] == 1
    current_checkpoint = advanced.authority_checkpoint()
    advanced.close()
    current_bytes = core.read_bytes()

    with pytest.raises(StorageError, match="does not exactly match the current authority anchor"):
        _recovery_restore(config_path, exact_restore_arguments)
    assert core.read_bytes() == current_bytes

    admitted = SQLiteStorage(
        core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
        authority_anchor=FileAuthorityAnchor(anchor_path),
        config={"manifest_digest": manifest.digest},
        min_free_disk_bytes=1,
        max_database_bytes=100_000_000,
        reserve_pages=1,
    )
    try:
        assert admitted.authority_checkpoint() == current_checkpoint
    finally:
        admitted.close()
