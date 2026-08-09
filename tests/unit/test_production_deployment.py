from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
from contextlib import closing
from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest

from deploy.production import check_build_context, healthcheck, stage_config, validate

REPOSITORY = Path(__file__).resolve().parents[2]
PRODUCTION = REPOSITORY / "deploy" / "production"
PINNED_ACTION = re.compile(r"^\s*-?\s*uses:\s*[^\s@]+@[0-9a-f]{40}(?:\s+#.*)?$")


@pytest.fixture(autouse=True)
def _model_independent_production_filesystems(monkeypatch: pytest.MonkeyPatch) -> None:
    original = validate._storage_device
    original_mount = validate._storage_mount
    modeled_devices = {
        "state": 10_001,
        "authority": 10_002,
        "audit": 10_003,
        "backup": 10_004,
    }

    def storage_device(path: Path) -> int:
        return modeled_devices.get(path.name, original(path))

    def storage_mount(path: Path) -> validate.StorageMount:
        device = modeled_devices.get(path.name)
        if device is None:
            return original_mount(path)
        mount_point = PurePosixPath(path.as_posix())
        return validate.StorageMount(
            mount_id=device,
            device=f"0:{device}",
            root=PurePosixPath("/"),
            mount_point=mount_point,
            filesystem_type="ext4",
            source=f"/dev/lets-{path.name}",
            has_descendant_mount=False,
        )

    monkeypatch.setattr(validate, "_storage_device", storage_device)
    monkeypatch.setattr(validate, "_storage_device_numbers", lambda device: (0, device))
    monkeypatch.setattr(validate, "_storage_mount", storage_mount)


def test_runtime_image_is_pinned_nonroot_and_root_owned() -> None:
    dockerfile = (REPOSITORY / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    internal_stages: set[str] = set()
    external_lines: list[str] = []
    for line in from_lines:
        fields = line.split()
        if fields[1] not in internal_stages:
            external_lines.append(line)
        if len(fields) >= 4 and fields[-2].casefold() == "as":
            internal_stages.add(fields[-1])

    assert from_lines
    assert all(re.search(r"@sha256:[0-9a-f]{64}(?:\s+AS\s+\w+)?$", line) for line in external_lines)
    assert "COPY --from=builder --chown=0:0 /app/.venv /app/.venv" in dockerfile
    assert "COPY --chown=0:0" in dockerfile
    assert "chmod -R a-w /app" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "python:3.14-alpine@sha256:" in dockerfile
    assert "apk add --no-cache openssl=3.5.7-r0" in dockerfile
    assert "/usr/local/lib/python3.14/site-packages/pip" in dockerfile
    assert "/sbin/nologin" in dockerfile
    assert "org.opencontainers.image.revision" in dockerfile
    assert "ARG SOURCE_DATE_EPOCH=0" in dockerfile
    assert "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" in dockerfile
    assert "lets_agent-*.dist-info/uv_cache.json" in dockerfile
    assert "find /app/.venv -exec touch -h -d" in dockerfile
    assert "find /app -exec touch -h -d" in dockerfile
    assert re.search(r"^\s*(?:COPY|ADD)\s+[.]\s", dockerfile, re.MULTILINE) is None
    runtime_stage = dockerfile.split(" AS runtime", 1)[1].split("FROM runtime", 1)[0]
    assert "bootstrap_cluster.py" not in runtime_stage
    assert "start_warden.py" not in runtime_stage


def test_opt_in_production_acceptance_requires_real_mtls_and_external_provider() -> None:
    compose = (PRODUCTION / "acceptance-compose.yaml").read_text(encoding="utf-8")
    scenario = (PRODUCTION / "acceptance" / "scenario.py").read_text(encoding="utf-8")
    runner = (PRODUCTION / "run_acceptance.py").read_text(encoding="utf-8")

    assert compose.count("--production") == 1
    for argument in ("--tls-cert", "--tls-key", "--client-ca", "--peer-ca", "--peer-cert"):
        assert argument in compose
    assert compose.count("/var/lib/lets-authority") >= 6
    assert compose.count("/var/lib/lets-audit") >= 6
    assert compose.count("subpath: config.json") == 3
    assert "/var/lib/lets-executor" in compose
    assert "/var/lib/lets-executor-authority" in compose
    assert compose.count("LETS_PRODUCTION_ACCEPTANCE_IMAGE") == 3
    assert '"read_only_config": True' in runner
    assert '"audit_archive": archive' in runner
    assert "apk add --no-cache openssl >/dev/null" not in compose
    assert "network_mode: none" in compose.split("  materials:", 1)[1].split("  init-a:", 1)[0]
    assert "cap_add: [CHOWN, FOWNER]" in compose
    assert "--backlog" in compose
    assert "max-size: 10m" in compose
    assert "nofile:" in compose
    assert compose.count("mem_limit: 1g") == 1
    assert compose.count("memswap_limit: 1g") == 1
    assert "generic-production" in scenario
    assert "_sqlite_wal_reset_safe" in scenario
    assert "ProcessFileExecutorAuthorityAnchor" in scenario
    assert "SQLiteReceiptReplayStore.initialize" in scenario
    assert "duplicate_receipt_rejected_after_reopen" in scenario
    assert "stale_database_restore_rejected" in scenario
    assert "expired JWT" in scenario
    assert "untrusted client certificate" in scenario
    assert "SIGKILL" in runner
    assert '"a_to_b"' in runner and '"b_to_a"' in runner
    assert '"tree_digest": source_tree_digest' in runner
    assert '"runtime_image_digest": candidate_image' in runner
    assert "configured_images != {candidate_image}" in runner
    assert 'executor = _scenario("executor")' in runner
    assert '"executor": executor' in runner
    assert 'host.get("Memory") != 1024 * 1024 * 1024' in runner
    assert 'host.get("MemorySwap") != 1024 * 1024 * 1024' in runner


def test_build_context_policy_rejects_secret_like_tracked_paths() -> None:
    assert check_build_context.is_sensitive_path("operator/.env")
    assert check_build_context.is_sensitive_path("nested/secrets/identity.json")
    assert check_build_context.is_sensitive_path("tls/server.key")
    assert check_build_context.is_sensitive_path("id_ed25519")
    assert check_build_context.is_sensitive_path("gcp/service-account-prod.json")
    assert not check_build_context.is_sensitive_path("deploy/production/.env.example")
    assert check_build_context.find_violations(REPOSITORY) == ()


def test_dependabot_tracks_python_actions_and_pinned_container_bases() -> None:
    configuration = (REPOSITORY / ".github/dependabot.yml").read_text(encoding="utf-8")

    for ecosystem in ("uv", "github-actions", "docker"):
        assert f"package-ecosystem: {ecosystem}" in configuration
    assert configuration.count("interval: weekly") == 3


def test_production_compose_is_fail_closed_and_hardened() -> None:
    compose = (PRODUCTION / "compose.yaml").read_text(encoding="utf-8")
    example_environment = (PRODUCTION / ".env.example").read_text(encoding="utf-8")

    assert "${LETS_IMAGE:?" in compose
    assert "${LETS_RUNTIME_PROVIDER:?" in compose
    assert "${LETS_CONFIG_FILE:?" in compose
    assert "--production" in compose
    assert "--runtime-provider" in compose
    assert "--limit-concurrency" in compose
    assert "${LETS_LIMIT_CONCURRENCY:-64}" in compose
    assert "--backlog" in compose
    assert "${LETS_BACKLOG:-128}" in compose
    assert "--request-body-timeout" in compose
    assert "${LETS_REQUEST_BODY_TIMEOUT_SECONDS:-30}" in compose
    assert "LETS_REQUEST_BODY_TIMEOUT_SECONDS=30" in example_environment
    assert "--timeout-graceful-shutdown" in compose
    assert "stop_grace_period: 75s" in compose
    assert "${LETS_HEALTH_START_PERIOD_SECONDS:-600}s" in compose
    assert 'mem_limit: "${LETS_MEMORY_LIMIT:-1g}"' in compose
    assert 'memswap_limit: "${LETS_MEMORY_LIMIT:-1g}"' in compose
    assert "allow-insecure" not in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert 'user: "10001:10001"' in compose
    assert "/var/lib/lets-authority" in compose
    assert "/var/lib/lets-audit" in compose
    assert "/var/lib/lets-backup" not in compose
    assert "/etc/lets/trust" in compose
    assert "create_host_path: false" in compose
    assert compose.count("propagation: rprivate") == compose.count("create_host_path: false")
    assert "LETS_BOOTSTRAP_TOKEN" not in compose
    assert "lets-acceptance-token" not in compose
    assert "http://" not in compose
    assert compose.count('file: "${LETS_') == 6
    for audit_setting in (
        "LETS_AUDIT_STORAGE_BOUNDARY",
        "LETS_AUDIT_CAPACITY_BYTES",
        "LETS_AUDIT_EXPECTED_DAILY_BYTES",
        "LETS_AUDIT_FORECAST_DAYS",
        "LETS_AUDIT_MIN_FREE_BYTES",
    ):
        assert f"{audit_setting}=" in example_environment
    for domain_setting in (
        "LETS_STATE_ROLLBACK_DOMAIN",
        "LETS_AUTHORITY_STORAGE_BOUNDARY",
        "LETS_AUTHORITY_ROLLBACK_DOMAIN",
        "LETS_AUDIT_ROLLBACK_DOMAIN",
        "LETS_BACKUP_STORAGE_BOUNDARY",
        "LETS_BACKUP_ROLLBACK_DOMAIN",
    ):
        assert f"{domain_setting}=" in example_environment


def test_provisioning_compose_does_not_expose_the_runtime_config_or_network() -> None:
    compose = (PRODUCTION / "provision-compose.yaml").read_text(encoding="utf-8")

    assert "network_mode: none" in compose
    assert "LETS_CONFIG_FILE" not in compose
    assert "/var/lib/lets/config.json" not in compose
    assert 'user: "10001:10001"' in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert compose.count("propagation: rprivate") == compose.count("create_host_path: false")


def test_maintenance_compose_is_networkless_and_owns_backup_access() -> None:
    compose = (PRODUCTION / "maintenance-compose.yaml").read_text(encoding="utf-8")

    assert "network_mode: none" in compose
    assert "/var/lib/lets-backup" in compose
    assert "/var/lib/lets/config.json" in compose
    assert 'user: "10001:10001"' in compose
    assert "read_only: true" in compose
    assert "cap_drop: [ALL]" in compose
    assert "no-new-privileges:true" in compose
    assert compose.count("propagation: rprivate") == compose.count("create_host_path: false")
    assert 'restart: "no"' in compose
    assert "ports:" not in compose


def _production_environment(tmp_path: Path) -> dict[str, str]:
    directories = {}
    for name in ("state", "authority", "audit", "backup", "trust"):
        path = tmp_path / name
        path.mkdir()
        directories[name] = str(path.resolve())
    trust = Path(directories["trust"])
    (trust / "manifest.json").write_text("{}\n", encoding="utf-8")
    (trust / "identity-keys.json").write_text("{}\n", encoding="utf-8")
    with (
        closing(sqlite3.connect(Path(directories["state"]) / "warden.sqlite3")) as connection,
        connection,
    ):
        connection.execute("CREATE TABLE production_validation_probe(value INTEGER)")
    files = {}
    for name in ("tls-cert", "tls-key", "client-ca", "peer-ca", "peer-cert", "peer-key"):
        path = tmp_path / f"{name}.pem"
        path.write_text("test-only-placeholder\n", encoding="utf-8")
        path.chmod(0o600)
        files[name] = str(path.resolve())
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "allow_insecure_manifest": False,
                "bootstrap_identities": [],
                "database": "/var/lib/lets/warden.sqlite3",
                "manifest": "/etc/lets/trust/manifest.json",
                "manifest_digest": "sha256:" + "a" * 64,
                "operator_trust": {},
                "max_database_bytes": 16_777_216,
                "min_free_disk_bytes": 1_048_576,
                "reserve_pages": 64,
                "runtime": {"provider": "example-provider", "options": {}},
                "version": 1,
                "warden_id": "warden-a",
                "tenant_id": "tenant-a",
                "envelope_id": "envelope-a",
            }
        ),
        encoding="utf-8",
    )
    config.chmod(0o444)
    return {
        "LETS_IMAGE": f"ghcr.io/example/lets@sha256:{'a' * 64}",
        "LETS_RUNTIME_PROVIDER": "example-provider",
        "LETS_SERVER_NAME": "warden-a.example.test",
        "LETS_STATE_DIR": directories["state"],
        "LETS_AUTHORITY_DIR": directories["authority"],
        "LETS_AUDIT_DIR": directories["audit"],
        "LETS_BACKUP_DIR": directories["backup"],
        "LETS_TRUST_DIR": directories["trust"],
        "LETS_CONFIG_FILE": str(config.resolve()),
        "LETS_STATE_STORAGE_BOUNDARY": "enforced-quota",
        "LETS_STATE_ROLLBACK_DOMAIN": "zfs://state-pool/warden-a",
        "LETS_STATE_CAPACITY_BYTES": "41943040",
        "LETS_AUTHORITY_STORAGE_BOUNDARY": "fenced-filesystem",
        "LETS_AUTHORITY_ROLLBACK_DOMAIN": "zfs://authority-pool/warden-a",
        "LETS_AUDIT_STORAGE_BOUNDARY": "dedicated-filesystem",
        "LETS_AUDIT_ROLLBACK_DOMAIN": "zfs://audit-pool/warden-a",
        "LETS_AUDIT_CAPACITY_BYTES": "16777216",
        "LETS_AUDIT_EXPECTED_DAILY_BYTES": "1024",
        "LETS_AUDIT_FORECAST_DAYS": "30",
        "LETS_AUDIT_MIN_FREE_BYTES": "1048576",
        "LETS_BACKUP_STORAGE_BOUNDARY": "dedicated-filesystem",
        "LETS_BACKUP_ROLLBACK_DOMAIN": "zfs://backup-pool/warden-a",
        "LETS_TLS_CERT_FILE": files["tls-cert"],
        "LETS_TLS_KEY_FILE": files["tls-key"],
        "LETS_CLIENT_CA_FILE": files["client-ca"],
        "LETS_PEER_CA_FILE": files["peer-ca"],
        "LETS_PEER_CERT_FILE": files["peer-cert"],
        "LETS_PEER_KEY_FILE": files["peer-key"],
    }


def _generic_options() -> dict[str, str]:
    return {
        "audit_archive_path": "/var/lib/lets-audit/audit.sqlite3",
        "authority_anchor_path": "/var/lib/lets-authority/warden.anchor.json",
        "identity_audience": "lets-api",
        "identity_issuer": "https://identity.example",
        "identity_keys_file": "/etc/lets/trust/identity-keys.json",
        "signer_command_json": '["/usr/local/bin/lets-hsm-sign"]',
        "signer_key_id": "warden-key",
        "signer_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    }


def _rewrite_config(environment: dict[str, str], document: dict[str, object]) -> None:
    config = Path(environment["LETS_CONFIG_FILE"])
    config.chmod(0o600)
    config.write_text(json.dumps(document), encoding="utf-8")
    config.chmod(0o444)


def test_production_environment_validation(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    assert validate.validate_environment(environment) == ()

    environment["LETS_IMAGE"] = "ghcr.io/example/lets:latest"
    environment["LETS_AUTHORITY_DIR"] = environment["LETS_STATE_DIR"]
    environment["LETS_TIMEOUT_GRACEFUL_SHUTDOWN"] = "45"
    environment["LETS_HEALTH_START_PERIOD_SECONDS"] = "30"
    environment["LETS_STATE_STORAGE_BOUNDARY"] = "shared-directory"
    environment["LETS_STATE_CAPACITY_BYTES"] = "1"
    environment["LETS_SERVER_NAME"] = "https://unsafe.example"
    environment["LETS_BIND_ADDRESS"] = "all-interfaces"
    environment["LETS_CPUS"] = "0"
    environment["LETS_MEMORY_LIMIT"] = "0"
    environment["LETS_BACKLOG"] = "0"
    environment["LETS_REQUEST_BODY_TIMEOUT_SECONDS"] = "0"
    errors = validate.validate_environment(environment)
    assert any("immutable" in error for error in errors)
    assert any("distinct non-nested paths" in error for error in errors)
    assert any("GRACEFUL_SHUTDOWN" in error for error in errors)
    assert any("HEALTH_START_PERIOD" in error for error in errors)
    assert any("LETS_STATE_STORAGE_BOUNDARY" in error for error in errors)
    assert any("worst-case WAL" in error for error in errors)
    assert any("LETS_SERVER_NAME" in error for error in errors)
    assert any("LETS_BIND_ADDRESS" in error for error in errors)
    assert any("LETS_CPUS" in error for error in errors)
    assert any("LETS_MEMORY_LIMIT" in error for error in errors)
    assert any("LETS_BACKLOG" in error for error in errors)
    assert any("LETS_REQUEST_BODY_TIMEOUT_SECONDS" in error for error in errors)


def test_production_environment_rejects_shared_or_undeclared_rollback_domains(
    tmp_path: Path,
) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_AUTHORITY_ROLLBACK_DOMAIN"] = environment["LETS_STATE_ROLLBACK_DOMAIN"]
    environment["LETS_BACKUP_STORAGE_BOUNDARY"] = "shared-directory"
    environment.pop("LETS_AUDIT_ROLLBACK_DOMAIN")

    errors = validate.validate_environment(environment)

    assert any("independent rollback domains" in error for error in errors)
    assert any("LETS_BACKUP_STORAGE_BOUNDARY" in error for error in errors)
    assert any("LETS_AUDIT_ROLLBACK_DOMAIN" in error for error in errors)


def test_production_environment_rejects_one_filesystem_for_all_domains(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _production_environment(tmp_path)
    monkeypatch.setattr(validate, "_storage_device", lambda _path: 42)

    errors = validate.validate_environment(environment)

    assert sum("distinct mounted filesystems" in error for error in errors) == 3


def test_mountinfo_parser_tracks_exact_and_nested_mounts() -> None:
    observations = validate._parse_mountinfo(
        "41 1 8:1 / /srv/lets\\040state rw - ext4 /dev/state rw\n"
        "42 41 8:2 / /srv/lets\\040state/nested rw - ext4 /dev/nested rw\n"
    )

    assert observations[0].mount_point == PurePosixPath("/srv/lets state")
    assert observations[0].has_descendant_mount is True
    assert observations[1].has_descendant_mount is False


def test_production_environment_rejects_fallback_or_remote_mounts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _production_environment(tmp_path)
    modeled_mount = validate._storage_mount

    def unsafe_mount(path: Path) -> validate.StorageMount:
        observation = modeled_mount(path)
        if path.name == "authority":
            return replace(
                observation,
                mount_point=PurePosixPath(path.parent.as_posix()),
                has_descendant_mount=True,
            )
        if path.name == "audit":
            return replace(observation, filesystem_type="nfs4")
        return observation

    monkeypatch.setattr(validate, "_storage_mount", unsafe_mount)

    errors = validate.validate_environment(environment)

    assert any("LETS_AUTHORITY_DIR must be the exact mountpoint" in error for error in errors)
    assert any(
        "LETS_AUTHORITY_DIR must not contain nested mountpoints" in error for error in errors
    )
    assert any("LETS_AUDIT_DIR uses unsupported production filesystem" in error for error in errors)


@pytest.mark.parametrize("value", ['"/safe/path"', "/safe/path # comment", "$UNSAFE/path"])
def test_environment_file_parser_rejects_ambiguous_compose_syntax(
    tmp_path: Path,
    value: str,
) -> None:
    environment = tmp_path / "production.env"
    environment.write_text(f"LETS_STATE_DIR={value}\n", encoding="utf-8")

    with pytest.raises(ValueError):
        validate.load_environment(environment)


def test_production_environment_rejects_impossible_page_reserve(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    document = json.loads(Path(environment["LETS_CONFIG_FILE"]).read_text(encoding="utf-8"))
    document["reserve_pages"] = 4097
    _rewrite_config(environment, document)

    errors = validate.validate_environment(environment)

    assert any("reserve_pages exceeds" in error for error in errors)


def test_production_environment_accounts_for_existing_wal_growth(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    database = Path(environment["LETS_STATE_DIR"]) / "warden.sqlite3"
    page_size = 4096
    with database.with_name(f"{database.name}-wal").open("wb") as stream:
        stream.truncate(32 + 5_000 * (page_size + 24))

    errors = validate.validate_environment(environment)

    assert any("LETS_STATE_CAPACITY_BYTES is below" in error for error in errors)


def test_production_environment_requires_audit_lifecycle_capacity(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_AUDIT_CAPACITY_BYTES"] = "1"

    errors = validate.validate_environment(environment)

    assert any("lifecycle forecast" in error for error in errors)


def test_generic_provider_rejects_interpreter_or_mutable_signer_code(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_RUNTIME_PROVIDER"] = "generic-production"
    document = json.loads(Path(environment["LETS_CONFIG_FILE"]).read_text(encoding="utf-8"))
    options = _generic_options()
    options["signer_command_json"] = '["/bin/sh","/var/lib/lets/evil.sh"]'
    document["runtime"] = {"provider": "generic-production", "options": options}
    _rewrite_config(environment, document)

    errors = validate.validate_environment(environment)

    assert any("dedicated helper" in error for error in errors)
    assert any("writable or ephemeral mounts" in error for error in errors)


def test_production_environment_rejects_linked_security_input(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    original = Path(environment["LETS_TLS_KEY_FILE"])
    linked = tmp_path / "linked-server-key.pem"
    try:
        os.link(original, linked)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")
    environment["LETS_TLS_KEY_FILE"] = str(linked.resolve())

    errors = validate.validate_environment(environment)

    assert any("must not be hard linked" in error for error in errors)


def test_production_environment_requires_mapped_immutable_trust_files(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    manifest = Path(environment["LETS_TRUST_DIR"]) / "manifest.json"
    manifest.unlink()

    errors = validate.validate_environment(environment)

    assert any("manifest.json" in error or "manifest" in error for error in errors)


def test_production_environment_rejects_symlinked_security_path(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    target = tmp_path / "operator-owned-key.pem"
    target.write_text("test-only-placeholder\n", encoding="utf-8")
    target.chmod(0o600)
    linked = tmp_path / "symlinked-server-key.pem"
    try:
        linked.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic links are unavailable: {exc}")
    environment["LETS_TLS_KEY_FILE"] = str(linked.absolute())

    errors = validate.validate_environment(environment)

    assert any("symbolic links or reparse points" in error for error in errors)


def test_runtime_image_validation_executes_the_loaded_sqlite_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        observed.extend(command)
        return subprocess.CompletedProcess(command, 0, "3.53.2\n", "")

    monkeypatch.setattr("deploy.production.validate.subprocess.run", run)
    image = f"ghcr.io/example/lets@sha256:{'a' * 64}"

    assert validate.validate_runtime_image(image) == "3.53.2"
    assert observed[0:2] == ["docker", "run"]
    assert image in observed
    assert "--network" in observed and "none" in observed
    assert "--read-only" in observed
    assert "--pids-limit" in observed and "64" in observed
    assert "--memory" in observed and "256m" in observed
    assert "--cpus" in observed and "1.0" in observed
    assert "_require_production_sqlite" in observed[-1]

    observed.clear()
    assert (
        validate.validate_runtime_image(
            image,
            provider="generic-production",
            signer_executable="/usr/local/bin/lets-hsm-sign",
        )
        == "3.53.2"
    )
    assert observed[-2:] == ["generic-production", "/usr/local/bin/lets-hsm-sign"]
    assert "runtime provider is missing" in observed[-3]


def test_runtime_image_validation_fences_a_timed_out_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[1] == "run":
            raise subprocess.TimeoutExpired(command, 180)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("deploy.production.validate.subprocess.run", run)
    image = f"ghcr.io/example/lets@sha256:{'a' * 64}"

    with pytest.raises(ValueError, match="timed out and was fenced"):
        validate.validate_runtime_image(image)

    assert commands[1][:3] == ["docker", "rm", "--force"]
    assert commands[1][3] in commands[0]


def test_production_environment_rejects_inputs_inside_writable_domains(
    tmp_path: Path,
) -> None:
    environment = _production_environment(tmp_path)
    unsafe_key = Path(environment["LETS_STATE_DIR"]) / "runtime-writable-key.pem"
    unsafe_key.write_text("unsafe\n", encoding="utf-8")
    unsafe_key.chmod(0o600)
    environment["LETS_TLS_KEY_FILE"] = str(unsafe_key.resolve())

    errors = validate.validate_environment(environment)

    assert any(
        "LETS_TLS_KEY_FILE must be outside runtime-writable LETS_STATE_DIR" in error
        for error in errors
    )


def test_generic_provider_paths_are_bound_to_separate_production_mounts(tmp_path: Path) -> None:
    environment = _production_environment(tmp_path)
    environment["LETS_RUNTIME_PROVIDER"] = "generic-production"
    config = Path(environment["LETS_CONFIG_FILE"])
    document = json.loads(config.read_text(encoding="utf-8"))
    document["runtime"] = {"provider": "generic-production", "options": _generic_options()}
    config.chmod(0o600)
    config.write_text(json.dumps(document), encoding="utf-8")
    config.chmod(0o444)
    assert validate.validate_environment(environment) == ()

    document["runtime"]["options"].update(
        {
            "authority_anchor_path": "/var/lib/lets/anchor.json",
            "audit_archive_path": "/var/lib/lets/audit.sqlite3",
            "identity_keys_file": "/etc/lets/trust/../mutable/identity-keys.json",
            "signer_command_json": '["/run/operator-controlled/sign"]',
        }
    )
    config.chmod(0o600)
    config.write_text(json.dumps(document), encoding="utf-8")
    config.chmod(0o444)

    errors = validate.validate_environment(environment)

    for field in (
        "authority_anchor_path",
        "audit_archive_path",
        "identity_keys_file",
        "signer executable",
    ):
        assert any(field in error for error in errors)


def test_production_compose_renders_when_docker_compose_is_available(tmp_path: Path) -> None:
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("Docker CLI is not installed")
    version = subprocess.run(
        [docker, "compose", "version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if version.returncode != 0:
        pytest.skip("Docker Compose plugin is not available")

    environment = os.environ.copy()
    environment.update(_production_environment(tmp_path))
    rendered = subprocess.run(
        [
            docker,
            "compose",
            "-f",
            str(PRODUCTION / "compose.yaml"),
            "config",
            "--format",
            "json",
        ],
        cwd=REPOSITORY,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    document = json.loads(rendered.stdout)
    warden = document["services"]["warden"]
    assert warden["image"] == environment["LETS_IMAGE"]
    assert warden["user"] == "10001:10001"
    assert warden["read_only"] is True
    assert warden["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in warden["security_opt"]
    assert warden["healthcheck"]["start_period"] == "10m0s"
    assert "--production" in warden["command"]
    assert "--allow-insecure-http" not in warden["command"]
    assert len(warden["secrets"]) == 6
    targets = {mount["target"] for mount in warden["volumes"]}
    assert targets == {
        "/var/lib/lets",
        "/var/lib/lets/config.json",
        "/var/lib/lets-authority",
        "/var/lib/lets-audit",
        "/etc/lets/trust",
    }

    for compose_name, service_name, expected_targets in (
        (
            "maintenance-compose.yaml",
            "maintenance",
            {
                "/var/lib/lets",
                "/var/lib/lets/config.json",
                "/var/lib/lets-authority",
                "/var/lib/lets-audit",
                "/var/lib/lets-backup",
                "/etc/lets/trust",
            },
        ),
        (
            "provision-compose.yaml",
            "provision",
            {
                "/var/lib/lets",
                "/var/lib/lets-authority",
                "/var/lib/lets-audit",
                "/etc/lets/trust",
            },
        ),
    ):
        rendered = subprocess.run(
            [
                docker,
                "compose",
                "-f",
                str(PRODUCTION / compose_name),
                "config",
                "--format",
                "json",
            ],
            cwd=REPOSITORY,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        service = json.loads(rendered.stdout)["services"][service_name]
        assert service["network_mode"] == "none"
        assert service["user"] == "10001:10001"
        assert service["read_only"] is True
        assert service["cap_drop"] == ["ALL"]
        assert {mount["target"] for mount in service["volumes"]} == expected_targets


def test_stage_config_moves_runtime_configuration_outside_writable_state(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    protected = tmp_path / "protected"
    state.mkdir()
    protected.mkdir()
    (state / "warden.sqlite3").write_bytes(b"test-database")
    (state / "peer-replay.sqlite3").write_bytes(b"test-replay-database")
    source = state / "config.json"
    source.write_text(
        json.dumps(
            {
                "allow_insecure_manifest": False,
                "bootstrap_identities": [],
                "database": "warden.sqlite3",
                "manifest": "/etc/lets/trust/manifest.json",
                "manifest_digest": "sha256:" + "a" * 64,
                "operator_trust": {},
                "replay_database": "peer-replay.sqlite3",
                "runtime": {
                    "provider": "generic-production",
                    "options": _generic_options(),
                },
                "version": 1,
                "warden_id": "warden-a",
                "tenant_id": "tenant-a",
                "envelope_id": "envelope-a",
            }
        ),
        encoding="utf-8",
    )
    destination = protected / "config.json"

    staged = stage_config.stage_config(source.resolve(), destination.resolve())

    document = json.loads(staged.read_text(encoding="utf-8"))
    assert document["database"] == "/var/lib/lets/warden.sqlite3"
    assert document["replay_database"] == "/var/lib/lets/peer-replay.sqlite3"
    if os.name != "nt":
        assert staged.stat().st_mode & 0o222 == 0
    with pytest.raises(ValueError, match="already exists"):
        stage_config.stage_config(source.resolve(), destination.resolve())


def test_healthcheck_requires_exact_ready_document() -> None:
    assert healthcheck.build_request("warden.example").startswith(b"GET /health/ready HTTP/1.1")
    assert b"Host: [2001:db8::1]\r\n" in healthcheck.build_request("2001:db8::1")
    assert healthcheck.is_ready_response(
        b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ready"}'
    )
    assert not healthcheck.is_ready_response(
        b'HTTP/1.1 503 Service Unavailable\r\n\r\n{"status":"ready"}'
    )
    assert not healthcheck.is_ready_response(b'HTTP/1.1 200 OK\r\n\r\n{"status":"live"}')


@pytest.mark.parametrize("workflow", ["security.yml", "release.yml"])
def test_supply_chain_workflow_uses_only_pinned_actions(workflow: str) -> None:
    text = (REPOSITORY / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    uses = [line for line in text.splitlines() if "uses:" in line]

    assert uses
    assert all(PINNED_ACTION.fullmatch(line) for line in uses)
    assert "runs-on: ubuntu-latest" not in text
    assert "continue-on-error" not in text


def test_security_workflow_has_fatal_scans_sboms_and_package_smoke() -> None:
    workflow = (REPOSITORY / ".github/workflows/security.yml").read_text(encoding="utf-8")

    for required in (
        "bandit==1.9.4",
        "pip-audit==2.10.1",
        "cyclonedx-bom==7.3.1",
        "twine==7.0.0",
        "syft-version: v1.50.0",
        "version: v0.73.0",
        "exit-code: 1",
        "--read-only",
        "--cap-drop ALL",
        "rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667",
        "moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec",
        "_require_production_sqlite",
    ):
        assert required in workflow
    assert workflow.count("--constraint requirements-audit.txt") == 2


def test_release_workflow_verifies_and_keyless_signs_before_release() -> None:
    workflow = (REPOSITORY / ".github/workflows/release.yml").read_text(encoding="utf-8")

    assert "if: github.event.deleted == false" in workflow
    assert "Require a GitHub-verified annotated tag" in workflow
    assert "Require a verified commit and successful push gates" in workflow
    assert "actions: read" in workflow
    assert "for required, expected_path in required_workflows.items()" in workflow
    assert 'run.get("head_sha") == os.environ["GITHUB_SHA"]' in workflow
    assert 'latest.get("conclusion") != "success"' in workflow
    assert "release commit is not GitHub-verified" in workflow
    assert "Perform two clean reproducible builds" in workflow
    assert "Record deterministic image metadata" in workflow
    assert 'epoch="$(git show -s --format=%ct "$GITHUB_SHA")"' in workflow
    assert "SOURCE_DATE_EPOCH: ${{ steps.build-metadata.outputs.epoch }}" in workflow
    assert "SOURCE_DATE_EPOCH=${{ steps.build-metadata.outputs.epoch }}" in workflow
    assert "digest: ${{ steps.candidate.outputs.digest }}" in workflow
    assert "Resume an already promoted candidate without rebuilding" in workflow
    assert "existing immutable release tags resolve to different digests" in workflow
    assert 'manifest.get("digest") != expected_digest' in workflow
    assert '"org.opencontainers.image.revision": os.environ["GITHUB_SHA"]' in workflow
    assert "actions/attest" not in workflow
    assert "gh attestation verify" not in workflow
    assert "attestations: write" not in workflow
    assert workflow.count("id-token: write") == 3
    assert workflow.count("cosign-release: v3.1.3") == 3
    assert workflow.count("--type slsaprovenance1") == 3
    assert workflow.count('--certificate-identity "$workflow_identity"') >= 6
    assert (
        workflow.count("--certificate-oidc-issuer https://token.actions.githubusercontent.com") >= 6
    )
    assert workflow.count('--certificate-github-workflow-sha "$GITHUB_SHA"') >= 6
    assert workflow.count('"_type": "https://in-toto.io/Statement/v0.1"') == 3
    assert '"predicateType": "https://slsa.dev/provenance/v1"' in workflow
    assert (
        '"buildType": "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1"'
        in workflow
    )
    assert '"candidate": f"{os.environ[\'IMAGE_NAME\']}@' in workflow
    assert '"gitCommit": os.environ["GITHUB_SHA"]' in workflow
    assert '"created": os.environ["EXPECTED_CREATED"]' in workflow
    assert '"version": os.environ["EXPECTED_VERSION"]' in workflow
    assert "resumed image lacks the exact signed candidate provenance" in workflow
    assert "new image lacks the exact signed candidate provenance" in workflow
    assert workflow.count("if: steps.resume.outputs.build_required == 'true'") == 2
    assert 'digest="${RESUMED_DIGEST:-$BUILT_DIGEST}"' in workflow
    assert "lets-deployment-$version.tar.gz" in workflow
    assert "deploy/production/maintenance-compose.yaml" in workflow
    assert "git archive --format=tar" in workflow
    assert "gzip -n" in workflow
    assert 'archive_contents="$(mktemp)"' in workflow
    assert '> "$archive_contents"' in workflow
    assert "grep -q '/deploy/production/compose.yaml$' \"$archive_contents\"" in workflow
    assert "| grep -q '/deploy/production/compose.yaml$'" not in workflow
    assert "sha256sum --check RELEASE_SHA256SUMS" in workflow
    assert "uv pip sync --python .release-smoke/bin/python requirements-release.txt" in workflow
    assert 'uv pip install --python .release-smoke/bin/python --no-deps "$wheel"' in workflow
    assert "uv pip check --python .release-smoke/bin/python" in workflow
    assert "--requirement requirements-release.txt" in workflow
    assert 'sysconfig.get_paths()["purelib"]' not in workflow
    assert '--path "$site_packages"' not in workflow
    assert workflow.index("uv pip sync --python") < workflow.index("uv pip install --python")
    assert workflow.index("uv pip install --python") < workflow.index("uv pip check --python")
    assert workflow.index("uv pip check --python") < workflow.index("pip-audit --strict")
    assert workflow.index("pip-audit --strict") < workflow.index("cyclonedx-py environment")
    assert "sqlite-runtime-versions.txt" in workflow
    assert workflow.count("_require_production_sqlite") >= 1
    assert "outputs: type=registry,rewrite-timestamp=true" in workflow
    assert "provenance: false" in workflow
    assert "sbom: false" in workflow
    assert "Keyless-attest and verify exact candidate build provenance" in workflow
    assert "cosign attest --yes" in workflow
    assert "--predicate candidate-provenance.json" in workflow
    assert "cosign sign --yes" in workflow
    assert "cosign verify \\" in workflow
    assert "Run the mTLS production-profile acceptance" in workflow
    assert "release-production-acceptance-${{ needs.verify.outputs.version }}" in workflow
    assert "Run the one-hour production-profile soak against the exact candidate" in workflow
    assert "release-production-soak-${{ needs.verify.outputs.version }}" in workflow
    assert "--duration-seconds 3600" in workflow
    assert 'source.get("git_commit") != os.environ["GITHUB_SHA"]' in workflow
    assert 'source.get("dirty") is not False' in workflow
    assert 'workload_evaluation.get("passed") is not True' in workflow
    assert 'get("health_cadence") is not True' in workflow
    assert 'int(workload_metrics.get("actual_cycles", 0)) < 300' in workflow
    assert "len(pair_counts) != 6" in workflow
    assert 'get("durably_pending_observed") is not True' in workflow
    assert 'get("all_wardens_sigkilled") is not True' in workflow
    assert '"cgroup_memory_max_bytes": 1024 * 1024 * 1024' in workflow
    assert '"cgroup_swap_max_bytes": 0' in workflow
    assert '"max_cgroup_memory_peak_bytes": 768 * 1024 * 1024' in workflow
    assert '"max_rss_bytes": 256 * 1024 * 1024' in workflow
    assert '"max_rss_growth_bytes": 128 * 1024 * 1024' in workflow
    assert 'checkpoint.get("evaluation_passed") is not True' in workflow
    assert 'sample.get("reason") != "pre_sigkill"' in workflow
    assert "if: ${{ always() && (failure() || cancelled()) }}" in workflow
    assert (
        "diagnostic-production-soak-${{ needs.verify.outputs.version }}-"
        "${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    )
    assert workflow.count("release-production-soak-${{ needs.verify.outputs.version }}") == 1
    assert 'get("identity", {}).get("passed") is not True' in workflow
    assert 'cleanup.get("remaining_containers") != 0' in workflow
    assert (
        "tonistiigi/binfmt@sha256:400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
        in workflow
    )
    assert (
        "moby/buildkit:buildx-stable-1@sha256:2f5adac4ecd194d9f8c10b7b5d7bceb5186853db1b26e5abd3a657af0b7e26ec"
        in workflow
    )
    assert "needs: [verify, package, image-candidate]" in workflow
    assert (
        "needs: [verify, package, image-candidate, production-acceptance, production-soak]"
        in workflow
    )
    assert "needs: [verify, package, production-acceptance, production-soak, image]" in workflow
    assert "candidate-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "LETS_PRODUCTION_ACCEPTANCE_IMAGE" in workflow
    assert 'evidence.get("runtime_image_digest")' in workflow
    assert workflow.count("flavor: latest=false") == 2
    assert "type=semver,pattern={{major}}.{{minor}}" not in workflow
    assert "type=raw,value=latest" not in workflow
    assert "release tag must resolve to the current main commit" in workflow
    assert "lets.__version__ does not match package version" in workflow
    assert '"ci": ".github/workflows/ci.yml"' in workflow
    assert '"security": ".github/workflows/security.yml"' in workflow
    assert 'key=lambda run: (run.get("id", 0), run.get("run_attempt", 0))' in workflow
    assert "refusing to move existing release image tag" in workflow
    assert (
        workflow.count(
            "image-ref: ${{ env.IMAGE_NAME }}@${{ needs.image-candidate.outputs.digest }}"
        )
        == 2
    )
    assert "already resolves to the verified candidate digest" in workflow
    assert "release tag did not resolve to the verified candidate" in workflow
    assert "could not prove that release image tag is absent" in workflow
    assert workflow.count("--format '{{.Manifest.Digest}}'") == 3
    assert "merge-multiple: true" not in workflow
    assert 'f"release-package-{version}"' in workflow
    assert 'f"release-production-acceptance-{version}"' in workflow
    assert 'f"release-production-soak-{version}"' in workflow
    assert 'f"release-image-{version}"' in workflow
    assert "release asset name collision" in workflow
    assert "release asset is empty" in workflow
    assert "if len(artifacts) != 15:" in workflow
    assert 'signature_name = f"{checksum_name}.sigstore.json"' in workflow
    assert "path.name not in {checksum_name, signature_name}" in workflow
    assert 'test "$(find release-assets -maxdepth 1 -type f | wc -l)" -eq 17' in workflow
    assert "anchore/sbom-action/download-syft@e22c389904149dbc22b58101806040fa8d37a610" in workflow
    assert "syft-version: v1.50.0" in workflow
    assert "--from registry" in workflow
    assert '--platform "$platform"' in workflow
    assert workflow.index("Verify both candidate architectures are present") < workflow.index(
        "Require patched SQLite in both exact published architectures"
    )
    sqlite_step = workflow.split(
        "- name: Require patched SQLite in both exact published architectures", maxsplit=1
    )[1].split("- name: Scan the exact published amd64 candidate", maxsplit=1)[0]
    assert "steps.manifest.outputs.amd64_digest" in sqlite_step
    assert "steps.manifest.outputs.arm64_digest" in sqlite_step
    assert '"$IMAGE_NAME@$child_digest"' in sqlite_step
    assert "needs.image-candidate.outputs.digest" not in sqlite_step
    assert '"schema": "lets.container-sbom-index/v1"' in workflow
    assert 'metadata.get("manifestDigest") != child_digest' in workflow
    assert 'image_ref not in (metadata.get("repoDigests") or [])' in workflow
    assert "Keyless-attest and verify each SPDX SBOM against its child manifest" in workflow
    assert "AMD64_DIGEST: ${{ steps.manifest.outputs.amd64_digest }}" in workflow
    assert "ARM64_DIGEST: ${{ steps.manifest.outputs.arm64_digest }}" in workflow
    assert workflow.count("--type spdxjson") == 2
    assert '"predicateType": "https://spdx.dev/Document"' in workflow
    assert "child manifest lacks its exact signed SPDX SBOM" in workflow
    assert "lets-container.spdx.json" not in workflow
    assert "Keyless-sign and verify the complete release checksum manifest" in workflow
    assert "cosign sign-blob --yes" in workflow
    assert '--bundle "$bundle"' in workflow
    assert "cosign verify-blob" in workflow
    assert workflow.count('"RELEASE_SHA256SUMS.sigstore.json"') >= 2
    assert "existing GitHub release has duplicate Sigstore bundles" in workflow
    assert "existing GitHub release has an invalid draft state" in workflow
    assert 'is_draft = state.get("draft")' in workflow
    assert 'is_draft = state.get("isDraft")' not in workflow
    assert '"reuse" if is_draft is False and matching else "retain"' in workflow
    assert "reused the existing release's verified Sigstore bundle" in workflow
    assert "retained the freshly signed bundle for a draft or bundle-free release" in workflow
    assert "could not prove that an existing release bundle is absent" in workflow
    assert 'mv "$remote_bundle" "$bundle"' in workflow
    assert "final release asset allowlist mismatch" in workflow
    assert workflow.index("cosign sign-blob --yes") < workflow.index('release_state="$(mktemp)"')
    assert workflow.index('test -s "$remote_bundle"') < workflow.index(
        'mv "$remote_bundle" "$bundle"'
    )
    assert workflow.index('--bundle "$remote_bundle"') < workflow.index(
        'mv "$remote_bundle" "$bundle"'
    )
    assert "Publish or safely resume the immutable GitHub release" in workflow
    assert "Extract exact compatibility, migration, and rollback release notes" in workflow
    assert '"### Compatibility, migration, and rollback"' in workflow
    assert "--notes-file release-notes.md" in workflow
    assert "published GitHub release has the wrong lifecycle notes" in workflow
    assert "--generate-notes" not in workflow
    assert '"repos/$GITHUB_REPOSITORY/immutable-releases"' not in workflow
    assert "release tag moved before publication" in workflow
    assert "GitHub release did not become immutable within its deadline" in workflow
    assert "mutable release was returned to draft" in workflow
    assert 'gh release verify "$GITHUB_REF_NAME"' in workflow
    assert workflow.count("X-GitHub-Api-Version: 2026-03-10") >= 1
    assert 'gh release create "$GITHUB_REF_NAME"' in workflow
    assert "--draft" in workflow
    assert 'gh release upload "$GITHUB_REF_NAME" release-assets/*' in workflow
    assert "--clobber" in workflow
    assert 'gh release edit "$GITHUB_REF_NAME"' in workflow
    assert "--draft=false" in workflow
    assert "GitHub release asset digest mismatch" in workflow
    assert "published GitHub release already has the exact verified asset set" in workflow
    assert "could not prove that the GitHub release is absent" in workflow
    for required_asset in (
        'f"lets-deployment-{version}.tar.gz"',
        'f"lets_agent-{version}-py3-none-any.whl"',
        'f"lets_agent-{version}.tar.gz"',
        '"RELEASE_SHA256SUMS"',
        '"RELEASE_SHA256SUMS.sigstore.json"',
        '"production-profile-acceptance.json"',
        '"production-profile-soak.json"',
        '"image-digest.txt"',
        '"image-manifest.json"',
        '"lets-container-amd64.spdx.json"',
        '"lets-container-arm64.spdx.json"',
        '"lets-container-sbom-index.json"',
        '"sqlite-runtime-versions.txt"',
        '"trivy-amd64.txt"',
        '"trivy-arm64.txt"',
    ):
        assert required_asset in workflow
    assert "Promote the verified digest to immutable release tags" in workflow
    assert workflow.index("Publish the multi-architecture release candidate") < workflow.index(
        "Keyless-attest and verify exact candidate build provenance"
    )
    assert workflow.index(
        "Resume an already promoted candidate without rebuilding"
    ) < workflow.index("Publish the multi-architecture release candidate")
    assert workflow.index(
        "Keyless-attest and verify exact candidate build provenance"
    ) < workflow.index("Run the mTLS production-profile acceptance against the exact candidate")
    assert workflow.index(
        "Run the mTLS production-profile acceptance against the exact candidate"
    ) < workflow.index("Scan the exact published amd64 candidate with Trivy")
    assert workflow.index("Verify both candidate architectures are present") < workflow.index(
        "Generate and validate one SPDX SBOM per published architecture"
    )
    assert workflow.index(
        "Generate and validate one SPDX SBOM per published architecture"
    ) < workflow.index("Keyless-attest and verify each SPDX SBOM against its child manifest")
    assert workflow.index(
        "Keyless-attest and verify each SPDX SBOM against its child manifest"
    ) < workflow.index("Promote the verified digest to immutable release tags")
    assert workflow.index("Keyless-sign and verify the exact image digest") < workflow.index(
        "Promote the verified digest to immutable release tags"
    )
    assert workflow.index("Promote the verified digest to immutable release tags") < workflow.index(
        "Publish or safely resume the immutable GitHub release"
    )
    assert workflow.index(
        "Keyless-sign and verify the complete release checksum manifest"
    ) < workflow.index("Publish or safely resume the immutable GitHub release")
