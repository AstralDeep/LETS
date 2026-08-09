from __future__ import annotations

import json
import sqlite3
import stat
from contextlib import closing
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import pytest

import lets.cli as cli_module
import lets.recovery as recovery_module
from lets.audit import AuditArchiveHead, AuditExportRecord
from lets.auth import SQLitePeerReplayStore
from lets.authority import AuthorityAnchor, AuthorityCheckpoint, FileAuthorityAnchor
from lets.canonical import b64url_encode, canonical_json
from lets.cli import (
    _initialize,
    _migrate,
    _parser,
    _serve,
    _validate_production_admission,
    _validate_production_state_admission,
)
from lets.crypto import Ed25519Signer
from lets.errors import StorageError, ValidationError
from lets.manifest import (
    ClusterManifest,
    ManifestPublicKey,
    ManifestSignature,
    WardenManifest,
)
from lets.models import IdentityContext, RuntimeMode, RuntimeStatus
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.recovery import (
    create_recovery_bundle,
    install_verified_artifact,
    node_process_lock,
    preserve_and_remove_artifact,
    read_sqlite_header,
    require_filesystem_headroom,
    verify_recovery_bundle,
)
from lets.runtime import RUNTIME_PROVIDER_GROUP, RuntimeBindings
from lets.service import WardenService
from lets.storage import SQLiteStorage


@dataclass
class FakeEntryPoint:
    name: str
    factory: object
    group: str = RUNTIME_PROVIDER_GROUP

    def load(self) -> object:
        return self.factory


class Authenticator:
    def authenticate(self, _request: object) -> IdentityContext:
        return IdentityContext(
            subject_id="operator",
            tenant_id="tenant-a",
            scopes=frozenset({"lets.admin", "lets.audit.read", "lets.audit.verify"}),
            authentication_method="test-provider",
        )


class AuditSink:
    def publish(self, _record: AuditExportRecord) -> None:
        return None

    def head(
        self,
        *,
        warden_id: str,
        tenant_id: str,
        envelope_id: str,
        config_epoch: int,
        database_instance_id: bytes,
    ) -> AuditArchiveHead | None:
        del warden_id, tenant_id, envelope_id, config_epoch, database_instance_id
        return None


def test_recovery_headroom_accepts_exact_boundary_and_rejects_one_byte_short(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    usage_type = type(recovery_module.shutil.disk_usage(tmp_path))
    monkeypatch.setattr(
        recovery_module.shutil,
        "disk_usage",
        lambda _path: usage_type(1_000, 900, 100),
    )
    assert (
        require_filesystem_headroom(
            tmp_path,
            required_bytes=100,
            operation="boundary test",
        )
        == 100
    )
    with pytest.raises(StorageError, match="required=101, available=100"):
        require_filesystem_headroom(
            tmp_path,
            required_bytes=101,
            operation="boundary test",
        )


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_sidecar_quarantine_resume_closes_both_crash_windows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    suffix: str,
) -> None:
    state = tmp_path / "state"
    quarantine = tmp_path / "backup"
    state.mkdir()
    quarantine.mkdir()
    sidecar = Path(f"{state / 'warden.sqlite3'}{suffix}")
    preserved = quarantine / sidecar.name
    payload = (suffix.encode("ascii") + b"-durable-sidecar") * 64
    sidecar.write_bytes(payload)

    # Crash after quarantine publication but before source unlink: both files
    # are present. Exact equality permits the resumable unlink; drift fences.
    install_verified_artifact(sidecar, preserved)
    preserve_and_remove_artifact(sidecar, preserved)
    assert not sidecar.exists()
    assert preserved.read_bytes() == payload
    sidecar.write_bytes(b"conflicting-live-sidecar")
    with pytest.raises(ValidationError, match="sidecars differ"):
        preserve_and_remove_artifact(sidecar, preserved)
    sidecar.unlink()

    # Crash after unlink but before its directory fsync: retry sees the durable
    # quarantine copy and absent source and converges without changing bytes.
    second_sidecar = Path(f"{state / 'second.sqlite3'}{suffix}")
    second_preserved = quarantine / second_sidecar.name
    second_sidecar.write_bytes(payload)
    original_fsync = recovery_module._fsync_directory

    def fail_source_directory_fsync(path: Path) -> None:
        if path.resolve() == state.resolve():
            raise StorageError("injected crash before sidecar unlink fsync")
        original_fsync(path)

    monkeypatch.setattr(
        recovery_module,
        "_fsync_directory",
        fail_source_directory_fsync,
    )
    with pytest.raises(StorageError, match="before sidecar unlink fsync"):
        preserve_and_remove_artifact(second_sidecar, second_preserved)
    assert not second_sidecar.exists()
    assert second_preserved.read_bytes() == payload
    monkeypatch.setattr(recovery_module, "_fsync_directory", original_fsync)
    preserve_and_remove_artifact(second_sidecar, second_preserved)


def test_offline_production_commands_require_signed_manifest_and_capacity() -> None:
    with pytest.raises(ValidationError, match="operator-signed cluster manifest"):
        _validate_production_state_admission({"allow_insecure_manifest": False})

    _validate_production_state_admission(
        {
            "manifest": "cluster.json",
            "manifest_digest": "sha256:" + "1" * 64,
            "operator_trust": {"threshold": 1},
            "allow_insecure_manifest": False,
            "bootstrap_identities": [],
            "min_free_disk_bytes": 1,
            "max_database_bytes": 1_000_000,
            "reserve_pages": 1,
        }
    )


def test_external_provider_failure_precedes_every_local_init_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(_context: object) -> object:
        raise RuntimeError("managed signer unavailable")

    monkeypatch.setattr(
        "lets.runtime.metadata.entry_points",
        lambda *, group: (
            (FakeEntryPoint("managed", fail),) if group == RUNTIME_PROVIDER_GROUP else ()
        ),
    )
    config = tmp_path / "node" / "config.json"
    arguments = _parser().parse_args(
        [
            "--config",
            str(config),
            "init",
            "--warden-id",
            "warden-a",
            "--tenant-id",
            "tenant-a",
            "--envelope-id",
            "envelope-a",
            "--budget",
            "10",
            "--runtime-provider",
            "managed",
        ]
    )
    with pytest.raises(ValidationError, match="failed to initialize"):
        _initialize(config, arguments)
    assert not config.parent.exists()


def test_production_init_uses_provider_signer_without_local_seed_or_bootstrap_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    operator = Ed25519Signer.generate("operator-a")
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
        receipt_ttl_ns=10_000,
        max_clock_uncertainty_ns=100,
        transfer_gap_window=64,
    )
    unsigned = ClusterManifest(
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
        unsigned,
        signatures=(
            ManifestSignature(
                operator.key_id,
                operator.sign(canonical_json(unsigned.unsigned_dict())),
            ),
        ),
    )
    manifest_path = tmp_path / "cluster.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
    anchor = FileAuthorityAnchor(tmp_path / "authority" / "head.json")
    (tmp_path / "authority").mkdir()

    def provider(_context: object) -> RuntimeBindings:
        return RuntimeBindings(
            warden_id="warden-a",
            tenant_id="tenant-a",
            signer=signer,
            authenticator=Authenticator(),
            production_capable=True,
            authority_anchor=anchor,
            audit_sink=AuditSink(),
        )

    monkeypatch.setattr(
        "lets.runtime.metadata.entry_points",
        lambda *, group: (
            (FakeEntryPoint("managed", provider),) if group == RUNTIME_PROVIDER_GROUP else ()
        ),
    )
    config_path = tmp_path / "node" / "config.json"
    arguments = _parser().parse_args(
        [
            "--config",
            str(config_path),
            "init",
            "--warden-id",
            "warden-a",
            "--manifest",
            str(manifest_path),
            "--operator-key",
            f"{operator.key_id}={b64url_encode(operator.public_key_bytes)}",
            "--production",
            "--runtime-provider",
            "managed",
            "--min-free-disk-bytes",
            "1",
            "--max-database-bytes",
            "100000000",
            "--reserve-pages",
            "1",
        ]
    )
    assert _initialize(config_path, arguments) == 0
    output = capsys.readouterr().out
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["runtime"] == {"provider": "managed", "options": {}}
    assert config["bootstrap_identities"] == []
    assert "replay_database" not in config
    assert "signing_key" not in config
    assert "bootstrap_token" not in output
    assert not (config_path.parent / "warden.ed25519").exists()
    assert not (config_path.parent / "peer-replay.sqlite3").exists()


def test_server_holds_same_process_lock_as_recovery_for_its_full_lifetime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / "config.json"
    config.write_text("{}", encoding="utf-8")
    arguments = _parser().parse_args(["serve"])

    def observed(config_path: Path, _arguments: object) -> int:
        with (
            pytest.raises(StorageError, match="another LETS process"),
            node_process_lock(config_path.resolve().parent / ".node.lock"),
        ):
            pytest.fail("recovery acquired the live server lock")
        return 0

    monkeypatch.setattr(cli_module, "_serve_unlocked", observed)
    assert _serve(config, arguments) == 0


def test_node_lock_does_not_relabel_protected_operation_errors(tmp_path: Path) -> None:
    with (
        pytest.raises(PermissionError, match="protected operation failed"),
        node_process_lock(tmp_path / ".node.lock"),
    ):
        raise PermissionError("protected operation failed")


def test_production_serve_requires_inbound_and_peer_mtls_and_bounded_limits() -> None:
    config: dict[str, object] = {
        "manifest": "cluster.json",
        "manifest_digest": "sha256:" + "1" * 64,
        "operator_trust": {"threshold": 1},
        "allow_insecure_manifest": False,
        "bootstrap_identities": [],
        "min_free_disk_bytes": 1,
        "max_database_bytes": 1_000_000,
        "reserve_pages": 1,
        "peer_endpoints": {"warden-b": "https://warden-b.example"},
    }
    incomplete = _parser().parse_args(
        [
            "serve",
            "--production",
            "--tls-cert",
            "server.pem",
            "--tls-key",
            "server.key",
            "--runtime-provider",
            "managed",
        ]
    )
    with pytest.raises(ValidationError, match="client-ca"):
        _validate_production_admission(config, incomplete, provider_name="managed")

    complete = _parser().parse_args(
        [
            "serve",
            "--production",
            "--tls-cert",
            "server.pem",
            "--tls-key",
            "server.key",
            "--client-ca",
            "client-ca.pem",
            "--peer-ca",
            "peer-ca.pem",
            "--peer-cert",
            "peer.pem",
            "--peer-key",
            "peer.key",
            "--runtime-provider",
            "managed",
            "--limit-concurrency",
            "256",
            "--timeout-keep-alive",
            "4",
            "--timeout-graceful-shutdown",
            "20",
        ]
    )
    _validate_production_admission(config, complete, provider_name="managed")
    assert complete.limit_concurrency == 256
    assert complete.timeout_keep_alive == 4
    assert complete.timeout_graceful_shutdown == 20


def test_recovery_bundle_rejects_tampering_and_unlisted_files(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden-a")
    core = tmp_path / "warden.sqlite3"
    store = SQLiteStorage.initialize(
        core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
    )
    checkpoint = store.authority_checkpoint().to_dict()
    store.close()
    replay = tmp_path / "peer-replay.sqlite3"
    SQLitePeerReplayStore.initialize(replay)
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"version": 1}) + "\n", encoding="utf-8")

    bundle = create_recovery_bundle(
        destination=tmp_path / "bundle",
        config_path=config,
        core_database=core,
        replay_database=None,
        signed_manifest=None,
        source_schema_version=2,
        identity={"warden_id": signer.warden_id},
        authority_checkpoint=checkpoint,
    )
    verified = verify_recovery_bundle(bundle.root)
    assert verified.source_schema_version == 2
    protected = [bundle.root / "warden.sqlite3"]
    for artifact in protected:
        artifact.chmod(stat.S_IREAD)
    assert verify_recovery_bundle(bundle.root).source_schema_version == 2
    assert verify_recovery_bundle(bundle.root).source_schema_version == 2
    assert {entry.name for entry in bundle.root.iterdir()} == {
        "bundle.json",
        "config.json",
        "warden.sqlite3",
    }

    # A source changed after manifest verification must never be published.
    core_artifact = bundle.root / "warden.sqlite3"
    original_core = core_artifact.read_bytes()
    core_artifact.chmod(stat.S_IREAD | stat.S_IWRITE)
    core_artifact.write_bytes(original_core + b"mutated-after-verification")
    raced_target = tmp_path / "raced-install.sqlite3"
    with pytest.raises(StorageError, match="post-copy digest"):
        install_verified_artifact(
            core_artifact,
            raced_target,
            expected=verified.digests["core_database"],
        )
    assert not raced_target.exists()
    core_artifact.write_bytes(original_core)
    core_artifact.chmod(stat.S_IREAD)

    # Schema-2 bundles reject mixed legacy replay authority artifacts. Replay
    # protection is part of the anchored core database after cutover.
    install_verified_artifact(replay, bundle.root / "peer-replay.sqlite3")
    with pytest.raises(ValidationError, match="unlisted"):
        verify_recovery_bundle(bundle.root)
    (bundle.root / "peer-replay.sqlite3").unlink()

    (bundle.root / "unlisted").write_text("surprise", encoding="utf-8")
    with pytest.raises(ValidationError, match="unlisted"):
        verify_recovery_bundle(bundle.root)
    (bundle.root / "unlisted").unlink()
    (bundle.root / "config.json").write_bytes(b"tampered")
    with pytest.raises(ValidationError, match="exact digest"):
        verify_recovery_bundle(bundle.root)
    for artifact in protected:
        artifact.chmod(stat.S_IREAD | stat.S_IWRITE)


def test_schema_migration_resume_converges_after_post_commit_anchor_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    core = tmp_path / "warden.sqlite3"
    current = SQLiteStorage.initialize(
        core,
        signer.warden_id,
        (10,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        initial_local_share=(10,),
    )
    current.close()
    with closing(sqlite3.connect(core)) as connection, connection:
        connection.execute("DROP TRIGGER runtime_control_generation_monotonic")
        connection.execute("DROP TRIGGER runtime_control_no_delete")
        connection.execute("DROP TABLE runtime_control")
        connection.execute("DROP TRIGGER peer_http_replay_immutable_update")
        connection.execute("DROP TRIGGER peer_http_authority_monotonic")
        connection.execute("DROP TRIGGER peer_http_authority_no_delete")
        connection.execute("DROP TABLE peer_http_replay")
        connection.execute("DROP TABLE peer_http_authority")
        connection.execute("DROP TRIGGER database_instance_immutable")
        connection.execute("DROP TRIGGER database_instance_no_delete")
        connection.execute("DROP TABLE database_instance")
        connection.execute("UPDATE database_metadata SET schema_version = 1 WHERE singleton = 1")
        connection.execute("PRAGMA user_version = 1")
    replay = tmp_path / "peer-replay.sqlite3"
    legacy_replay = SQLitePeerReplayStore.initialize(replay)
    migration_now_s = int(cli_module.time.time())
    assert legacy_replay.claim(
        warden_id="warden-b",
        key_id="warden-b-key",
        nonce="legacy-peer-nonce-0000001",
        timestamp_s=migration_now_s,
        expires_at_s=migration_now_s + 30,
        now_s=migration_now_s,
        clock_tolerance_s=30,
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "version": 1,
                "warden_id": "warden-a",
                "tenant_id": "tenant-a",
                "envelope_id": "envelope-a",
                "config_epoch": 1,
                "budget": [10],
                "local_share": [10],
                "receipt_ttl_ns": 1_000_000_000,
                "max_clock_uncertainty_ns": 0,
                "transfer_gap_window": 64,
                "database": core.name,
                "replay_database": replay.name,
                "runtime": {"provider": "managed", "options": {}},
                "bootstrap_identities": [],
                "trusted_peers": [],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    anchor_path = tmp_path / "external" / "authority.json"
    anchor_path.parent.mkdir()
    selected_anchor: list[AuthorityAnchor] = [FileAuthorityAnchor(anchor_path)]

    def provider(_context: object) -> RuntimeBindings:
        return RuntimeBindings(
            warden_id="warden-a",
            tenant_id="tenant-a",
            signer=signer,
            authenticator=Authenticator(),
            production_capable=True,
            authority_anchor=selected_anchor[0],
            audit_sink=AuditSink(),
        )

    monkeypatch.setattr(
        "lets.runtime.metadata.entry_points",
        lambda *, group: (
            (FakeEntryPoint("managed", provider),) if group == RUNTIME_PROVIDER_GROUP else ()
        ),
    )
    backup = tmp_path / "pre-migration"
    first = _parser().parse_args(["migrate", "--backup", str(backup)])
    with pytest.raises(ValidationError, match="still has live claims"):
        _migrate(config_path, first)
    assert read_sqlite_header(core)[1] == 1
    assert not backup.exists()

    # The current peer envelope is valid for at most twice the 30-second skew
    # window. This exact fixture expires at +30 seconds.
    monkeypatch.setattr(cli_module.time, "time", lambda: float(migration_now_s + 31))
    original_set_runtime_mode = WardenService.set_runtime_mode
    injected = False

    def fail_before_drain(self: WardenService, **options: Any) -> RuntimeStatus:
        nonlocal injected
        if not injected and options.get("reason") == (
            "schema migration completed; operator activation required"
        ):
            injected = True
            raise StorageError("injected crash after schema commit before drain")
        return original_set_runtime_mode(self, **options)

    monkeypatch.setattr(WardenService, "set_runtime_mode", fail_before_drain)
    with pytest.raises(StorageError, match="after schema commit before drain"):
        _migrate(config_path, first)
    monkeypatch.setattr(WardenService, "set_runtime_mode", original_set_runtime_mode)
    assert read_sqlite_header(core)[1] == 2
    assert backup.is_dir()
    journal = json.loads((tmp_path / "migration-v1-v2.json").read_text(encoding="utf-8"))
    assert journal["phase"] == "BACKUP_VERIFIED"
    assert SQLitePeerReplayStore(replay).integrity_check() == ("ok",)

    resume = _parser().parse_args(["migrate", "--backup", str(backup), "--resume"])

    class FailAnchorBootstrapOnce:
        def __init__(self, delegate: FileAuthorityAnchor) -> None:
            self.delegate = delegate
            self.failed = False

        def reconcile(self, checkpoint: AuthorityCheckpoint, **options: Any) -> None:
            if not self.failed:
                self.failed = True
                raise StorageError("injected crash after replay import before anchor")
            self.delegate.reconcile(checkpoint, **options)

        def read_current(self) -> AuthorityCheckpoint:
            return self.delegate.read_current()

    # Once the schema-1 peer envelope validity window has elapsed, migration
    # binds the exact frozen legacy artifact and floor without an unbounded
    # nonce import. A crash after that core COMMIT but before anchor bootstrap
    # leaves a resumable DATABASE_MIGRATED journal.
    selected_anchor[0] = FailAnchorBootstrapOnce(FileAuthorityAnchor(anchor_path))
    with pytest.raises(StorageError, match="after replay import before anchor"):
        _migrate(config_path, resume)
    assert (
        json.loads((tmp_path / "migration-v1-v2.json").read_text(encoding="utf-8"))["phase"]
        == "DATABASE_MIGRATED"
    )

    selected_anchor[0] = FileAuthorityAnchor(anchor_path)
    assert _migrate(config_path, resume) == 0
    assert anchor_path.is_file()
    assert (
        json.loads((tmp_path / "migration-v1-v2.json").read_text(encoding="utf-8"))["phase"]
        == "COMPLETE"
    )

    # Repeating a completed resume is an idempotent anchor reconciliation and
    # never reinitializes authority or activates the node.
    anchor_before = anchor_path.read_bytes()
    assert _migrate(config_path, resume) == 0
    assert anchor_path.read_bytes() == anchor_before
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
    )
    try:
        with admitted.read() as transaction:
            mode = transaction.connection.execute(
                "SELECT mode FROM runtime_control WHERE singleton=1"
            ).fetchone()[0]
        assert mode == RuntimeMode.DRAINING.value
        replay_status = WardenService(admitted, signer=signer).peer_replay_status()
        assert replay_status["revision"] == 1
        assert replay_status["active_claims"] == 0
        assert replay_status["legacy_snapshot_digest"] is not None
    finally:
        admitted.close()
