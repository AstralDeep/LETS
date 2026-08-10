"""Command-line bootstrap and server entry point for a LETS warden node."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import secrets
import sqlite3
import ssl
import sys
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing, suppress
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path
from typing import Any, NoReturn, cast

from lets.auth import CorePeerReplayStore, SQLitePeerReplayStore, StaticBearerAuthenticator
from lets.authority import AuthorityAnchor
from lets.canonical import b64url_decode, b64url_encode, canonical_json, strict_json_loads
from lets.clock import Clock, SystemClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import LETSError, SignatureError, StorageError, ValidationError
from lets.ids import require_warden_id
from lets.manifest import validate_endpoint_origin
from lets.models import IdentityContext, RuntimeMode, RuntimeStatus
from lets.recovery import (
    RECOVERY_METADATA_HEADROOM_BYTES,
    ArtifactDigest,
    VerifiedBundle,
    create_recovery_bundle,
    create_recovery_quarantine,
    install_verified_artifact,
    node_process_lock,
    preserve_and_remove_artifact,
    read_sqlite_header,
    remove_recovery_quarantine,
    require_filesystem_headroom,
    sqlite_diagnostics,
    verify_recovery_bundle,
)
from lets.runtime import (
    BUILTIN_RUNTIME_PROVIDER,
    RuntimeBindings,
    RuntimeProviderContext,
    RuntimeSession,
    RuntimeSigner,
    open_runtime_provider,
    validate_runtime_options,
    validate_runtime_provider_name,
)
from lets.service import WardenService
from lets.storage import SQLiteStorage
from lets.storage.schema import APPLICATION_ID, SCHEMA_VERSION
from lets.timeouts import (
    DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS,
    MAX_PEER_REQUEST_TIMEOUT_SECONDS,
    MIN_PRODUCTION_PEER_REQUEST_TIMEOUT_SECONDS,
)
from lets.vector import MAX_RESOURCE

CONFIG_VERSION = 1
DEFAULT_CONFIG = Path(".lets/config.json")
GENERIC_PRODUCTION_RUNTIME_PROVIDER = "generic-production"
_GENERIC_PROVIDER_AUTHORITY_CALLS_PER_PEER_REQUEST = Decimal(4)
_GENERIC_PROVIDER_SIGNER_CALLS_PER_PEER_REQUEST = Decimal(4)
_GENERIC_PROVIDER_SQLITE_ALLOWANCE_SECONDS = Decimal(5)
_GENERIC_PROVIDER_SCHEDULING_TLS_MARGIN_SECONDS = Decimal(5)
_GENERIC_PROVIDER_SQLITE_WRITES_PER_PEER_REQUEST = Decimal(2)


def _sqlite_wal_reset_safe(version: tuple[int, ...]) -> bool:
    """Return whether SQLite includes the upstream 2026 WAL-reset fix.

    SQLite fixed the issue in 3.51.3 and published maintained-branch
    backports as 3.50.7 and 3.44.6.  Intermediate release branches without a
    published fixed build remain unsafe for concurrent WAL-mode production.
    """

    normalized = tuple(version[:3]) + (0,) * max(0, 3 - len(version))
    current = cast(tuple[int, int, int], normalized[:3])
    if (3, 51, 3) <= current < (3, 52, 0):
        return True
    # SQLite withdrew the 3.52 line because of an unrelated expression-index
    # compatibility defect.  The corrected successor line starts at 3.53.0.
    if current >= (3, 53, 0):
        return True
    if (3, 50, 7) <= current < (3, 51, 0):
        return True
    return (3, 44, 6) <= current < (3, 45, 0)


def _require_production_sqlite() -> None:
    version = tuple(sqlite3.sqlite_version_info)
    if not _sqlite_wal_reset_safe(version):
        rendered = ".".join(str(item) for item in version)
        raise ValidationError(
            "production WAL mode requires SQLite 3.53+, the 3.51.3 patch line, "
            "the 3.50.7+ backport, or the 3.44.6+ backport; SQLite 3.52 is "
            f"withdrawn; loaded {rendered}"
        )


def _add_runtime_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--runtime-provider",
        metavar="NAME",
        help="installed lets.runtime_providers entry point (default: configured provider)",
    )
    command.add_argument(
        "--runtime-option",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="bounded provider option; repeatable and never interpreted by LETS",
    )


def _strict_json(data: str | bytes) -> object:
    try:
        return strict_json_loads(data)
    except (UnicodeError, ValueError) as exc:
        raise ValidationError(f"JSON is outside LETS-CJ/1: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lets",
        description="Operate a standalone distributed LETS warden node",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(os.environ.get("LETS_CONFIG", DEFAULT_CONFIG)),
        help="project-local node configuration (default: .lets/config.json)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init", help="initialize a project-local node")
    initialize.add_argument("--warden-id", required=True)
    initialize.add_argument("--tenant-id", default="default")
    initialize.add_argument("--envelope-id", default="default")
    initialize.add_argument("--config-epoch", type=int, default=1)
    initialize.add_argument("--budget", help="comma-separated non-negative resource vector")
    initialize.add_argument(
        "--local-share", help="comma-separated local share (defaults to the full budget)"
    )
    initialize.add_argument("--receipt-ttl-ns", type=int, default=1_000_000_000)
    initialize.add_argument("--max-clock-uncertainty-ns", type=int, default=50_000_000)
    initialize.add_argument("--transfer-gap-window", type=int, default=64)
    initialize.add_argument(
        "--min-free-disk-bytes",
        type=int,
        default=0,
        help="development disk-free reserve; production requires an explicit positive value",
    )
    initialize.add_argument(
        "--max-database-bytes",
        type=int,
        help=(
            "logical main-database ceiling; production also reserves one worst-case "
            "WAL transaction above the filesystem floor"
        ),
    )
    initialize.add_argument(
        "--reserve-pages",
        type=int,
        default=64,
        help="minimum SQLite page headroom retained for authority writes",
    )
    initialize.add_argument("--bootstrap-subject")
    initialize.add_argument(
        "--manifest",
        type=Path,
        help="signed cluster manifest used instead of individual envelope arguments",
    )
    initialize.add_argument(
        "--operator-key",
        action="append",
        default=[],
        metavar="KEY_ID=BASE64URL",
        help="trusted manifest operator key (repeatable)",
    )
    initialize.add_argument("--operator-threshold", type=int, default=1)
    initialize.add_argument(
        "--allow-insecure-manifest",
        action="store_true",
        help="allow HTTP endpoints in a development cluster manifest",
    )
    initialize.add_argument(
        "--signing-seed-file",
        type=Path,
        help="existing raw 32-byte Ed25519 seed (required with --manifest)",
    )
    initialize.add_argument(
        "--bootstrap-token",
        help="bootstrap bearer token; generated and printed once when omitted",
    )
    initialize.add_argument(
        "--production",
        action="store_true",
        help="provision with an external production runtime provider and no local secrets",
    )
    _add_runtime_arguments(initialize)

    serve = commands.add_parser("serve", help="serve the configured warden API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8741)
    serve.add_argument("--tls-cert", type=Path)
    serve.add_argument("--tls-key", type=Path)
    serve.add_argument("--client-ca", type=Path)
    serve.add_argument(
        "--peer-ca",
        type=Path,
        help="CA bundle used to verify outbound peer TLS certificates",
    )
    serve.add_argument(
        "--peer-cert",
        type=Path,
        help="client certificate presented to peer wardens",
    )
    serve.add_argument(
        "--peer-key",
        type=Path,
        help="private key for --peer-cert",
    )
    serve.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="explicitly permit cleartext on a non-loopback interface (development only)",
    )
    serve.add_argument(
        "--allow-insecure-peer-http",
        action="store_true",
        help="explicitly permit cleartext outbound peer endpoints (development only)",
    )
    serve.add_argument(
        "--production",
        action="store_true",
        help="require manifest, TLS, and an external production-capable runtime provider",
    )
    serve.add_argument(
        "--limit-concurrency",
        type=int,
        default=64,
        help="maximum concurrent requests before bounded overload rejection",
    )
    serve.add_argument(
        "--backlog",
        type=int,
        default=128,
        help="maximum kernel accept backlog for the listening socket",
    )
    serve.add_argument(
        "--request-body-timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="total deadline in seconds for receiving a request body before authentication",
    )
    serve.add_argument(
        "--peer-request-timeout-seconds",
        type=int,
        default=DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS,
        metavar="SECONDS",
        help="total deadline in seconds for one durable outbound peer request",
    )
    serve.add_argument(
        "--timeout-keep-alive",
        type=int,
        default=5,
        help="bounded HTTP keep-alive timeout in seconds",
    )
    serve.add_argument(
        "--timeout-graceful-shutdown",
        type=int,
        default=30,
        help="bounded graceful shutdown timeout in seconds",
    )
    serve.add_argument("--log-level", default="info")
    _add_runtime_arguments(serve)

    key = commands.add_parser("key", help="print this node's public signing key")
    _add_runtime_arguments(key)
    info = commands.add_parser("info", help="inspect local node identity and database health")
    info.add_argument(
        "--production",
        action="store_true",
        help="apply production provider, anchor, manifest, and capacity admission",
    )
    info.add_argument(
        "--allow-insecure-peer-http",
        action="store_true",
        help="allow configured HTTP peer endpoints in development diagnostics",
    )
    _add_runtime_arguments(info)
    backup = commands.add_parser("backup", help="create a verified consistent SQLite backup")
    backup.add_argument("--output", type=Path, required=True)
    _add_runtime_arguments(backup)

    status = commands.add_parser("status", help="show durable ACTIVE/DRAINING state")
    _add_runtime_arguments(status)
    drain = commands.add_parser("drain", help="reject new authority-increasing work")
    drain.add_argument("--reason", required=True)
    _add_runtime_arguments(drain)
    activate = commands.add_parser("activate", help="return a drained warden to ACTIVE")
    activate.add_argument("--reason", required=True)
    _add_runtime_arguments(activate)

    recovery = commands.add_parser("recovery", help="create, verify, or restore recovery bundles")
    recovery_commands = recovery.add_subparsers(dest="recovery_command", required=True)
    recovery_backup = recovery_commands.add_parser(
        "backup", help="create a quiescent authority-safe recovery bundle"
    )
    recovery_backup.add_argument("--output", type=Path, required=True)
    recovery_backup.add_argument("--production", action="store_true")
    _add_runtime_arguments(recovery_backup)
    recovery_verify = recovery_commands.add_parser(
        "verify", help="verify a bundle against the current authority anchor without mutation"
    )
    recovery_verify.add_argument("--bundle", type=Path, required=True)
    recovery_verify.add_argument("--production", action="store_true")
    _add_runtime_arguments(recovery_verify)
    recovery_restore = recovery_commands.add_parser(
        "restore", help="restore a verified bundle under the independent authority anchor"
    )
    recovery_restore.add_argument("--bundle", type=Path, required=True)
    recovery_restore.add_argument("--confirm-warden-id", required=True)
    _add_runtime_arguments(recovery_restore)

    migrate = commands.add_parser(
        "migrate", help="perform an explicit stop-the-world schema migration"
    )
    migrate.add_argument("--backup", type=Path, required=True)
    migrate.add_argument("--dry-run", action="store_true")
    migrate.add_argument(
        "--resume",
        action="store_true",
        help="resume a journaled migration after a verified interrupted phase",
    )
    migrate.add_argument("--production", action="store_true")
    _add_runtime_arguments(migrate)
    return parser


def _vector(text: str, *, field: str) -> list[int]:
    try:
        values = [int(item.strip()) for item in text.split(",")]
    except ValueError as exc:
        raise ValidationError(f"{field} must be a comma-separated integer vector") from exc
    if not values or any(value < 0 for value in values):
        raise ValidationError(f"{field} must contain non-negative integers")
    return values


def _atomic_json(path: Path, value: Mapping[str, object]) -> None:
    destination = path.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise ValidationError(f"configuration already exists: {destination}")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        with suppress(OSError):
            os.chmod(temporary, 0o600)
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise ValidationError(
                f"configuration appeared during initialization: {destination}"
            ) from exc
        os.unlink(temporary)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _load_config(path: Path) -> tuple[Path, dict[str, Any]]:
    resolved = path.resolve()
    try:
        decoded = _strict_json(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"could not read LETS configuration {resolved}") from exc
    if not isinstance(decoded, dict):
        raise ValidationError("LETS configuration must be a JSON object")
    if decoded.get("version") != CONFIG_VERSION:
        raise ValidationError(f"unsupported LETS configuration version: {decoded.get('version')!r}")
    return resolved, cast(dict[str, Any], decoded)


def _required_text(config: Mapping[str, Any], name: str) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"configuration field {name!r} must be a non-empty string")
    return value


def _local_path(config_path: Path, config: Mapping[str, Any], name: str) -> Path:
    raw = Path(_required_text(config, name))
    if raw.is_absolute():
        raise ValidationError(f"configuration path {name!r} must be project-local")
    base = config_path.parent.resolve()
    resolved = (base / raw).resolve()
    if not resolved.is_relative_to(base):
        raise ValidationError(f"configuration path {name!r} escapes its project directory")
    return resolved


def _database_path(config_path: Path, config: Mapping[str, Any]) -> Path:
    """Resolve the authority database path admitted by the runtime configuration.

    Development nodes keep every artifact project-local.  Production provisioning
    deliberately stages an immutable configuration whose database path is an
    absolute path inside the separately mounted state domain.  Admit that form only
    when the configuration explicitly selects an external runtime provider; the
    built-in seed/static-bearer runtime retains the project-local boundary.
    """

    raw = Path(_required_text(config, "database"))
    if not raw.is_absolute():
        return _local_path(config_path, config, "database")
    runtime = config.get("runtime")
    provider = runtime.get("provider") if isinstance(runtime, Mapping) else None
    if not isinstance(provider, str) or provider == BUILTIN_RUNTIME_PROVIDER:
        raise ValidationError(
            "an absolute configuration database path requires an external runtime provider"
        )
    return raw.resolve()


def _config_vector(config: Mapping[str, Any], name: str) -> list[int]:
    value = config.get(name)
    if (
        not isinstance(value, list)
        or not value
        or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value)
    ):
        raise ValidationError(f"configuration field {name!r} is not a resource vector")
    return cast(list[int], value)


def _operator_keys(values: Sequence[str]) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    material_owners: dict[bytes, str] = {}
    for value in values:
        key_id, separator, encoded = value.partition("=")
        if separator != "=" or not key_id or not encoded:
            raise ValidationError("--operator-key must use KEY_ID=BASE64URL syntax")
        try:
            public_key = b64url_decode(encoded)
        except Exception as exc:
            raise ValidationError(f"operator key {key_id!r} is malformed") from exc
        if len(public_key) != 32:
            raise ValidationError(f"operator key {key_id!r} must contain 32 bytes")
        existing = keys.get(key_id)
        if existing is not None and existing != public_key:
            raise ValidationError(f"operator key {key_id!r} was supplied with conflicting data")
        existing_owner = material_owners.get(public_key)
        if existing_owner is not None and existing_owner != key_id:
            raise ValidationError("operator key aliases must not reuse Ed25519 public-key material")
        keys[key_id] = public_key
        material_owners[public_key] = key_id
    return keys


def _finish_initialization(
    *,
    resolved: Path,
    arguments: argparse.Namespace,
    signer: RuntimeSigner,
    authority_anchor: AuthorityAnchor | None,
    provider_name: str,
    provider_options: Mapping[str, str],
    budget: list[int],
    local_share: list[int],
    dimension_metadata: list[dict[str, Any]] | None,
    policies: Sequence[object],
    manifest_digest: str | None,
    manifest_registry: PublicKeyRegistry | None,
    manifest_clock: SystemClock | None,
    accepted_operator_keys: frozenset[str],
    operator_keys: Mapping[str, bytes],
    trusted_peers: list[dict[str, str]],
    node_endpoints: dict[str, str] | None,
    peer_endpoints: dict[str, str],
) -> int:
    """Create local artifacts only after the selected provider has been admitted."""

    if len(local_share) != len(budget):
        raise ValidationError("local_share must have the same dimensions as budget")
    if any(local > total for local, total in zip(local_share, budget, strict=True)):
        raise ValidationError("local_share cannot exceed budget")

    builtin = provider_name == BUILTIN_RUNTIME_PROVIDER
    token: str | None = None
    if builtin:
        token = arguments.bootstrap_token or secrets.token_urlsafe(32)
        if len(token) < 24:
            raise ValidationError("bootstrap token must contain at least 24 characters")
    elif arguments.bootstrap_token is not None or arguments.bootstrap_subject is not None:
        raise ValidationError(
            "external runtime providers reject static --bootstrap-token/--bootstrap-subject"
        )

    directory = resolved.parent
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "warden.ed25519"
    database_path = directory / "warden.sqlite3"
    candidates = [database_path]
    if builtin:
        candidates.append(key_path)
    partial_artifacts = [candidate for candidate in candidates if candidate.exists()]
    if partial_artifacts:
        rendered = ", ".join(str(candidate) for candidate in partial_artifacts)
        raise ValidationError(
            "partial LETS initialization artifacts already exist and will not be overwritten: "
            f"{rendered}. Inspect, recover, or move those exact files before retrying init."
        )
    if builtin:
        cast(Ed25519Signer, signer).save_seed_file(key_path)

    store = SQLiteStorage.initialize(
        database_path,
        arguments.warden_id,
        budget,
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=arguments.tenant_id,
        envelope_id=arguments.envelope_id,
        config_epoch=arguments.config_epoch,
        dimension_metadata=dimension_metadata,
        initial_local_share=local_share,
        receipt_ttl_ns=arguments.receipt_ttl_ns,
        max_clock_uncertainty_ns=arguments.max_clock_uncertainty_ns,
        transfer_gap_window=arguments.transfer_gap_window,
        config={} if manifest_digest is None else {"manifest_digest": manifest_digest},
        authority_anchor=authority_anchor,
        min_free_disk_bytes=arguments.min_free_disk_bytes,
        max_database_bytes=arguments.max_database_bytes,
        reserve_pages=arguments.reserve_pages,
    )
    policy_digests: list[str] = []
    try:
        if policies:
            if manifest_registry is None or manifest_clock is None:
                raise RuntimeError("manifest policy registration has no admitted trust registry")
            service = WardenService(
                store,
                signer=signer,
                clock=manifest_clock,
                trust_registry=manifest_registry,
                signing_key_validity=manifest_registry.key_validity(
                    signer.warden_id,
                    signer.key_id,
                ),
            )
            policy_digests = [service.register_policy(policy) for policy in policies]
    finally:
        store.close()
    bootstrap_identities: list[dict[str, object]] = []
    if token is not None:
        subject = arguments.bootstrap_subject or arguments.warden_id
        bootstrap_identities.append(
            {
                "token_sha256": sha256(token.encode("utf-8")).hexdigest(),
                "subject_id": subject,
                "tenant_id": arguments.tenant_id,
                "scopes": [
                    "lets.admin",
                    "lets.audit.read",
                    "lets.audit.verify",
                    "lets.branch.revoke",
                    "lets.lease.manage",
                    "lets.metrics.read",
                    "lets.transfer",
                ],
            }
        )
    config: dict[str, object] = {
        "version": CONFIG_VERSION,
        "warden_id": arguments.warden_id,
        "tenant_id": arguments.tenant_id,
        "envelope_id": arguments.envelope_id,
        "config_epoch": arguments.config_epoch,
        "budget": budget,
        "local_share": local_share,
        "receipt_ttl_ns": arguments.receipt_ttl_ns,
        "max_clock_uncertainty_ns": arguments.max_clock_uncertainty_ns,
        "transfer_gap_window": arguments.transfer_gap_window,
        "min_free_disk_bytes": arguments.min_free_disk_bytes,
        "max_database_bytes": arguments.max_database_bytes,
        "reserve_pages": arguments.reserve_pages,
        "database": database_path.name,
        "runtime": {"provider": provider_name, "options": dict(provider_options)},
        "bootstrap_identities": bootstrap_identities,
        "trusted_peers": trusted_peers,
    }
    if builtin:
        config["signing_key"] = key_path.name
    if dimension_metadata is not None:
        config["dimension_metadata"] = dimension_metadata
    if manifest_digest is not None:
        config["manifest_digest"] = manifest_digest
        config["manifest"] = str(arguments.manifest.resolve())
        config["manifest_policy_digests"] = policy_digests
        config["operator_trust"] = {
            "threshold": arguments.operator_threshold,
            "accepted_signatures": sorted(accepted_operator_keys),
            "keys": [
                {"key_id": key_id, "public_key": b64url_encode(public_key)}
                for key_id, public_key in sorted(operator_keys.items())
            ],
        }
        config["allow_insecure_manifest"] = bool(arguments.allow_insecure_manifest)
    if node_endpoints is not None:
        config["endpoints"] = node_endpoints
    if peer_endpoints:
        config["peer_endpoints"] = peer_endpoints
    _atomic_json(resolved, config)

    document: dict[str, object] = {
        "config": str(resolved),
        "warden_id": arguments.warden_id,
        "key_id": signer.key_id,
        "runtime_provider": provider_name,
    }
    if token is not None:
        document.update(
            {
                "bootstrap_token": token,
                "warning": (
                    "Store the bootstrap token securely; only its SHA-256 digest was saved."
                ),
            }
        )
    else:
        document["bootstrap_identity"] = "external-runtime-provider"
    print(json.dumps(document, indent=2))
    return 0


def _initialize(config_path: Path, arguments: argparse.Namespace) -> int:
    resolved = config_path.resolve()
    if resolved.exists():
        raise ValidationError(f"configuration already exists: {resolved}")
    provider_name = validate_runtime_provider_name(
        arguments.runtime_provider or BUILTIN_RUNTIME_PROVIDER
    )
    provider_options = validate_runtime_options(_runtime_option_pairs(arguments.runtime_option))
    if arguments.production:
        if provider_name == BUILTIN_RUNTIME_PROVIDER:
            raise ValidationError("--production init requires an external runtime provider")
        if arguments.manifest is None:
            raise ValidationError("--production init requires an operator-signed manifest")
        if arguments.allow_insecure_manifest:
            raise ValidationError("--production init rejects insecure manifest endpoints")
        if arguments.signing_seed_file is not None:
            raise ValidationError("--production init rejects local signing seed files")
    for field, minimum in (
        ("min_free_disk_bytes", 0),
        ("reserve_pages", 1),
    ):
        value = getattr(arguments, field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < minimum
            or value > MAX_RESOURCE
        ):
            raise ValidationError(
                f"--{field.replace('_', '-')} must be an integer in [{minimum}, {MAX_RESOURCE}]"
            )
    if arguments.max_database_bytes is not None and (
        isinstance(arguments.max_database_bytes, bool)
        or not isinstance(arguments.max_database_bytes, int)
        or arguments.max_database_bytes <= 0
        or arguments.max_database_bytes > MAX_RESOURCE
    ):
        raise ValidationError(f"--max-database-bytes must be an integer in [1, {MAX_RESOURCE}]")
    if arguments.production and (
        arguments.min_free_disk_bytes <= 0
        or arguments.max_database_bytes is None
        or arguments.reserve_pages <= 0
    ):
        raise ValidationError(
            "--production init requires positive disk reserve, database limit, and page reserve"
        )
    manifest = None
    accepted_operator_keys: frozenset[str] = frozenset()
    operator_keys: dict[str, bytes] = {}
    trusted_peers: list[dict[str, str]] = []
    policies: Sequence[object] = ()
    dimension_metadata: list[dict[str, Any]] | None = None
    manifest_digest: str | None = None
    manifest_registry: PublicKeyRegistry | None = None
    manifest_clock: SystemClock | None = None
    node_endpoints: dict[str, str] | None = None
    peer_endpoints: dict[str, str] = {}
    if arguments.manifest is not None:
        from lets.manifest import ClusterManifest

        try:
            manifest_document = _strict_json(arguments.manifest.read_bytes())
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError(f"could not load LETS manifest {arguments.manifest}") from exc
        if not isinstance(manifest_document, Mapping):
            raise ValidationError("LETS manifest root must be an object")
        manifest = ClusterManifest.from_dict(
            manifest_document,
            allow_insecure_http=arguments.allow_insecure_manifest,
        )
        operator_keys = _operator_keys(arguments.operator_key)
        accepted_operator_keys = manifest.verify_signatures(
            operator_keys,
            threshold=arguments.operator_threshold,
        )
        local = manifest.warden(arguments.warden_id)
        budget = list(manifest.initial_budget)
        local_share = list(local.initial_share)
        arguments.tenant_id = manifest.tenant_id
        arguments.envelope_id = manifest.envelope_id
        arguments.config_epoch = manifest.config_epoch
        first_policy = manifest.policies[0]
        arguments.receipt_ttl_ns = first_policy.receipt_ttl_ns
        arguments.max_clock_uncertainty_ns = first_policy.max_clock_uncertainty_ns
        arguments.transfer_gap_window = first_policy.transfer_gap_window
        manifest_clock = SystemClock(declared_uncertainty_ns=first_policy.max_clock_uncertainty_ns)
        manifest_registry = PublicKeyRegistry(clock=manifest_clock)
        for warden in manifest.wardens:
            for key in warden.keys:
                manifest_registry.register(
                    warden.warden_id,
                    key.key_id,
                    key.public_key,
                    not_before_ns=key.not_before_ns,
                    not_after_ns=key.not_after_ns,
                )
        dimension_metadata = [
            {
                "name": resource.id,
                "unit": resource.unit,
                "description": resource.description,
            }
            for resource in manifest.resources
        ]
        policies = manifest.policies
        manifest_digest = manifest.digest
        node_endpoints = {
            "client_endpoint": local.client_endpoint,
            "peer_endpoint": local.peer_endpoint,
        }
        for warden in manifest.wardens:
            if warden.warden_id == arguments.warden_id:
                continue
            peer_endpoints[warden.warden_id] = warden.peer_endpoint
            for key in warden.keys:
                peer_key = {
                    "warden_id": warden.warden_id,
                    "key_id": key.key_id,
                    "public_key": b64url_encode(key.public_key),
                }
                if key.not_before is not None:
                    peer_key["not_before"] = key.not_before
                if key.not_after is not None:
                    peer_key["not_after"] = key.not_after
                trusted_peers.append(peer_key)
    else:
        if arguments.operator_key:
            raise ValidationError("--operator-key requires --manifest")
        if arguments.budget is None:
            raise ValidationError("--budget is required unless --manifest is supplied")
        budget = _vector(arguments.budget, field="budget")
        local_share = (
            budget
            if arguments.local_share is None
            else _vector(arguments.local_share, field="local_share")
        )

    def finish(signer: RuntimeSigner, authority_anchor: AuthorityAnchor | None) -> int:
        if manifest is not None:
            if not any(
                key.key_id == signer.key_id and key.public_key == signer.public_key_bytes
                for key in manifest.warden(arguments.warden_id).keys
            ):
                raise ValidationError("runtime signer does not match a manifest warden key")
            if manifest_registry is None:
                raise RuntimeError("manifest trust registry was not constructed")
            try:
                manifest_registry.require_current(signer.warden_id, signer.key_id)
                for warden in manifest.wardens:
                    if warden.warden_id != signer.warden_id:
                        manifest_registry.require_current_warden(warden.warden_id)
            except SignatureError as exc:
                raise ValidationError(
                    "manifest initialization requires current local and peer signing keys"
                ) from exc
        return _finish_initialization(
            resolved=resolved,
            arguments=arguments,
            signer=signer,
            authority_anchor=authority_anchor,
            provider_name=provider_name,
            provider_options=provider_options,
            budget=budget,
            local_share=local_share,
            dimension_metadata=dimension_metadata,
            policies=policies,
            manifest_digest=manifest_digest,
            manifest_registry=manifest_registry,
            manifest_clock=manifest_clock,
            accepted_operator_keys=accepted_operator_keys,
            operator_keys=operator_keys,
            trusted_peers=trusted_peers,
            node_endpoints=node_endpoints,
            peer_endpoints=peer_endpoints,
        )

    if provider_name == BUILTIN_RUNTIME_PROVIDER:
        if provider_options:
            raise ValidationError("the built-in runtime provider does not accept options")
        if arguments.manifest is not None and arguments.signing_seed_file is None:
            raise ValidationError("--signing-seed-file is required with --manifest")
        signer = (
            Ed25519Signer.generate(arguments.warden_id)
            if arguments.signing_seed_file is None
            else Ed25519Signer.load_seed_file(arguments.warden_id, arguments.signing_seed_file)
        )
        return finish(signer, None)

    context = RuntimeProviderContext(
        config_path=resolved,
        database_path=resolved.parent / "warden.sqlite3",
        warden_id=arguments.warden_id,
        tenant_id=arguments.tenant_id,
        envelope_id=arguments.envelope_id,
        config_epoch=arguments.config_epoch,
        manifest_digest=manifest_digest,
        options=provider_options,
        production=arguments.production,
    )
    # Provider admission occurs before directory creation or any local artifact.
    with open_runtime_provider(provider_name, context) as runtime:
        return finish(runtime.signer, runtime.authority_anchor)


def _signer(config_path: Path, config: Mapping[str, Any]) -> Ed25519Signer:
    return Ed25519Signer.load_seed_file(
        _required_text(config, "warden_id"),
        _local_path(config_path, config, "signing_key"),
    )


def _storage(
    config_path: Path,
    config: Mapping[str, Any],
    *,
    signer: RuntimeSigner,
    database_override: Path | None = None,
    authority_anchor: AuthorityAnchor | None = None,
) -> SQLiteStorage:
    manifest_digest = config.get("manifest_digest")
    storage_extensions = (
        None
        if manifest_digest is None
        else {"manifest_digest": _required_text(config, "manifest_digest")}
    )
    return SQLiteStorage(
        (_database_path(config_path, config) if database_override is None else database_override),
        _required_text(config, "warden_id"),
        _config_vector(config, "budget"),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=_required_text(config, "tenant_id"),
        envelope_id=_required_text(config, "envelope_id"),
        config_epoch=int(config.get("config_epoch", 1)),
        dimension_metadata=config.get("dimension_metadata"),
        initial_local_share=_config_vector(config, "local_share"),
        receipt_ttl_ns=int(config.get("receipt_ttl_ns", 1_000_000_000)),
        max_clock_uncertainty_ns=int(config.get("max_clock_uncertainty_ns", 50_000_000)),
        transfer_gap_window=int(config.get("transfer_gap_window", 64)),
        config=storage_extensions,
        authority_anchor=authority_anchor,
        min_free_disk_bytes=config.get("min_free_disk_bytes", 0),
        max_database_bytes=config.get("max_database_bytes"),
        reserve_pages=config.get("reserve_pages", 64),
    )


def _client_authenticator(config: Mapping[str, Any]) -> StaticBearerAuthenticator:
    raw_identities = config.get("bootstrap_identities")
    if not isinstance(raw_identities, Sequence) or isinstance(raw_identities, (str, bytes)):
        raise ValidationError("bootstrap_identities must be an array")
    credentials: list[tuple[str, IdentityContext]] = []
    for raw in raw_identities:
        if not isinstance(raw, Mapping):
            raise ValidationError("each bootstrap identity must be an object")
        digest = raw.get("token_sha256")
        subject = raw.get("subject_id")
        tenant = raw.get("tenant_id")
        scopes = raw.get("scopes")
        if (
            not isinstance(digest, str)
            or not isinstance(subject, str)
            or not isinstance(tenant, str)
        ):
            raise ValidationError("bootstrap identity fields are malformed")
        if not isinstance(scopes, Sequence) or isinstance(scopes, (str, bytes)):
            raise ValidationError("bootstrap identity scopes must be an array")
        credentials.append(
            (
                digest,
                IdentityContext(
                    subject_id=subject,
                    tenant_id=tenant,
                    scopes=frozenset(cast(Sequence[str], scopes)),
                    authentication_method="static-bearer-sha256",
                ),
            )
        )
    return StaticBearerAuthenticator.from_sha256_digests(credentials)


def _runtime_option_pairs(values: Sequence[str]) -> tuple[tuple[str, str], ...]:
    pairs: list[tuple[str, str]] = []
    for raw in values:
        if not isinstance(raw, str):
            raise ValidationError("--runtime-option must use NAME=VALUE syntax")
        name, separator, value = raw.partition("=")
        if separator != "=" or not name or not value:
            raise ValidationError("--runtime-option must use NAME=VALUE syntax")
        pairs.append((name, value))
    return tuple(pairs)


def _runtime_configuration(
    config: Mapping[str, Any],
    arguments: argparse.Namespace | None = None,
) -> tuple[str, Mapping[str, str]]:
    raw_runtime = config.get("runtime")
    configured = raw_runtime is not None
    if raw_runtime is None:
        configured_provider = BUILTIN_RUNTIME_PROVIDER
        configured_options: Mapping[str, str] = {}
    else:
        if not isinstance(raw_runtime, Mapping):
            raise ValidationError("runtime configuration must be an object")
        unknown = set(raw_runtime) - {"provider", "options"}
        if unknown:
            raise ValidationError(f"unknown runtime configuration fields: {sorted(unknown)}")
        raw_provider = raw_runtime.get("provider")
        raw_options = raw_runtime.get("options", {})
        if not isinstance(raw_provider, str):
            raise ValidationError("runtime provider must be a string")
        if not isinstance(raw_options, Mapping):
            raise ValidationError("runtime provider options must be an object")
        if any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in raw_options.items()
        ):
            raise ValidationError("runtime provider options must map strings to strings")
        configured_provider = validate_runtime_provider_name(raw_provider)
        configured_options = cast(Mapping[str, str], raw_options)

    provider_override = None if arguments is None else arguments.runtime_provider
    raw_overrides = () if arguments is None else arguments.runtime_option
    if not isinstance(raw_overrides, Sequence) or isinstance(raw_overrides, (str, bytes)):
        raise ValidationError("runtime option overrides must be an array")
    override_pairs = _runtime_option_pairs(cast(Sequence[str], raw_overrides))
    if provider_override is None:
        selected_provider = configured_provider
        option_pairs = (*configured_options.items(), *override_pairs)
    else:
        selected_provider = validate_runtime_provider_name(provider_override)
        # Options belong to a provider.  A deliberate provider override does not
        # inherit options configured for a different implementation.
        option_pairs = (
            (*configured_options.items(), *override_pairs)
            if not configured or selected_provider == configured_provider
            else override_pairs
        )
    return selected_provider, validate_runtime_options(option_pairs)


def _open_runtime(
    config_path: Path,
    config: Mapping[str, Any],
    arguments: argparse.Namespace | None = None,
    *,
    production: bool = False,
) -> RuntimeSession:
    provider_name, options = _runtime_configuration(config, arguments)
    manifest_digest = config.get("manifest_digest")
    if manifest_digest is not None and not isinstance(manifest_digest, str):
        raise ValidationError("manifest_digest must be a string")
    context = RuntimeProviderContext(
        config_path=config_path,
        database_path=_database_path(config_path, config),
        warden_id=_required_text(config, "warden_id"),
        tenant_id=_required_text(config, "tenant_id"),
        envelope_id=_required_text(config, "envelope_id"),
        config_epoch=config.get("config_epoch", 1),
        manifest_digest=manifest_digest,
        options=options,
        production=production,
    )

    def builtin_factory(runtime_context: RuntimeProviderContext) -> RuntimeBindings:
        if runtime_context.options:
            raise ValidationError("the built-in runtime provider does not accept options")
        return RuntimeBindings(
            warden_id=runtime_context.warden_id,
            tenant_id=runtime_context.tenant_id,
            signer=_signer(config_path, config),
            authenticator=_client_authenticator(config),
            production_capable=False,
            authority_anchor=None,
            audit_sink=None,
        )

    return open_runtime_provider(
        provider_name,
        context,
        builtin_factory=builtin_factory,
    )


def _configured_peer_endpoints(
    config: Mapping[str, Any],
    *,
    allow_insecure_http: bool,
) -> dict[str, str]:
    raw = config.get("peer_endpoints", {})
    if not isinstance(raw, Mapping):
        raise ValidationError("peer_endpoints must map warden IDs to endpoint URIs")
    checked: dict[str, str] = {}
    for raw_warden, raw_endpoint in raw.items():
        if not isinstance(raw_warden, str):
            raise ValidationError("peer endpoint warden IDs must be strings")
        warden_id = require_warden_id(raw_warden, field="peer endpoint warden_id")
        endpoint = validate_endpoint_origin(
            raw_endpoint,
            f"peer endpoint for {warden_id}",
            allow_insecure_http=allow_insecure_http,
        )
        checked[warden_id] = endpoint
    return checked


def _validate_peer_trust(
    peer_endpoints: Mapping[str, str],
    registry: PublicKeyRegistry,
    *,
    local_warden_id: str,
) -> None:
    """Reject outbound authority routes that cannot yield a verifiable acknowledgement."""

    if local_warden_id in peer_endpoints:
        raise ValidationError("peer_endpoints must not contain the local warden")
    for warden_id in sorted(peer_endpoints):
        try:
            registry.require_current_warden(warden_id)
        except SignatureError as exc:
            raise ValidationError(
                f"peer endpoint {warden_id!r} has no currently valid trusted verification key"
            ) from exc


def _trust_registry(
    config: Mapping[str, Any],
    signer: RuntimeSigner,
    *,
    clock: Clock | None = None,
) -> PublicKeyRegistry:
    from lets.manifest import ManifestPublicKey

    registry = PublicKeyRegistry(clock=clock)
    registry.register(signer.warden_id, signer.key_id, signer.public_key_bytes)
    raw_peers = config.get("trusted_peers", [])
    if not isinstance(raw_peers, Sequence) or isinstance(raw_peers, (str, bytes)):
        raise ValidationError("trusted_peers must be an array")
    for peer in raw_peers:
        if not isinstance(peer, Mapping):
            raise ValidationError("each trusted peer must be an object")
        warden_id = peer.get("warden_id")
        key_id = peer.get("key_id")
        public_key = peer.get("public_key")
        not_before = peer.get("not_before")
        not_after = peer.get("not_after")
        if not all(isinstance(item, str) for item in (warden_id, key_id, public_key)):
            raise ValidationError("trusted peer fields are malformed")
        if not_before is not None and not isinstance(not_before, str):
            raise ValidationError("trusted peer not_before must be an RFC 3339 string")
        if not_after is not None and not isinstance(not_after, str):
            raise ValidationError("trusted peer not_after must be an RFC 3339 string")
        parsed = ManifestPublicKey(
            key_id=cast(str, key_id),
            public_key=b64url_decode(cast(str, public_key)),
            not_before=not_before,
            not_after=not_after,
        )
        registry.register(
            cast(str, warden_id),
            parsed.key_id,
            parsed.public_key,
            not_before_ns=parsed.not_before_ns,
            not_after_ns=parsed.not_after_ns,
        )
    return registry


def _manifest_trust_registry(
    config: Mapping[str, Any],
    signer: RuntimeSigner,
    *,
    clock: Clock,
) -> PublicKeyRegistry:
    """Rebuild peer trust from the operator-signed manifest on every serve."""

    from lets.manifest import ClusterManifest

    if "manifest_digest" not in config:
        return _trust_registry(config, signer, clock=clock)
    insecure = config.get("allow_insecure_manifest", False)
    if not isinstance(insecure, bool):
        raise ValidationError("allow_insecure_manifest must be a boolean")
    manifest_path = Path(_required_text(config, "manifest"))
    manifest = ClusterManifest.load(manifest_path, allow_insecure_http=insecure)
    expected_digest = _required_text(config, "manifest_digest")
    if manifest.digest != expected_digest:
        raise ValidationError(
            "signed manifest digest does not match the configured database anchor"
        )

    raw_trust = config.get("operator_trust")
    if not isinstance(raw_trust, Mapping):
        raise ValidationError("manifest-backed serving requires operator_trust")
    threshold = raw_trust.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
        raise ValidationError("operator trust threshold must be a positive integer")
    raw_keys = raw_trust.get("keys")
    if not isinstance(raw_keys, Sequence) or isinstance(raw_keys, (str, bytes)):
        raise ValidationError("operator trust keys must be an array")
    operator_keys: dict[str, bytes] = {}
    operator_material_owners: dict[bytes, str] = {}
    for raw_key in raw_keys:
        if not isinstance(raw_key, Mapping):
            raise ValidationError("operator trust key entries must be objects")
        key_id = raw_key.get("key_id")
        public_key = raw_key.get("public_key")
        if not isinstance(key_id, str) or not isinstance(public_key, str):
            raise ValidationError("operator trust key fields are malformed")
        decoded = b64url_decode(public_key)
        if len(decoded) != 32:
            raise ValidationError("operator Ed25519 public keys must contain exactly 32 bytes")
        existing = operator_keys.get(key_id)
        if existing is not None and existing != decoded:
            raise ValidationError("operator key_id is bound to conflicting public keys")
        existing_owner = operator_material_owners.get(decoded)
        if existing_owner is not None and existing_owner != key_id:
            raise ValidationError(
                "operator trust aliases must not reuse Ed25519 public-key material"
            )
        operator_keys[key_id] = decoded
        operator_material_owners[decoded] = key_id
    accepted = manifest.verify_signatures(operator_keys, threshold=threshold)
    configured_accepted = raw_trust.get("accepted_signatures")
    if (
        not isinstance(configured_accepted, Sequence)
        or isinstance(configured_accepted, (str, bytes))
        or any(not isinstance(item, str) for item in configured_accepted)
        or frozenset(configured_accepted) != accepted
    ):
        raise ValidationError("operator signature acceptance set drifted from the signed manifest")

    local = manifest.warden(signer.warden_id)
    if not any(
        key.key_id == signer.key_id and key.public_key == signer.public_key_bytes
        for key in local.keys
    ):
        raise ValidationError("local signing key is not authorized by the signed manifest")
    first_policy = manifest.policies[0]
    expected_dimensions = [
        {
            "name": resource.id,
            "unit": resource.unit,
            "description": resource.description,
        }
        for resource in manifest.resources
    ]
    comparisons: dict[str, tuple[object, object]] = {
        "tenant_id": (config.get("tenant_id"), manifest.tenant_id),
        "envelope_id": (config.get("envelope_id"), manifest.envelope_id),
        "config_epoch": (config.get("config_epoch"), manifest.config_epoch),
        "budget": (config.get("budget"), list(manifest.initial_budget)),
        "local_share": (config.get("local_share"), list(local.initial_share)),
        "receipt_ttl_ns": (config.get("receipt_ttl_ns"), first_policy.receipt_ttl_ns),
        "max_clock_uncertainty_ns": (
            config.get("max_clock_uncertainty_ns"),
            first_policy.max_clock_uncertainty_ns,
        ),
        "transfer_gap_window": (
            config.get("transfer_gap_window"),
            first_policy.transfer_gap_window,
        ),
        "dimension_metadata": (config.get("dimension_metadata"), expected_dimensions),
        "manifest_policy_digests": (
            config.get("manifest_policy_digests"),
            [policy.digest for policy in manifest.policies],
        ),
    }
    drift = [field for field, values in comparisons.items() if values[0] != values[1]]
    if drift:
        raise ValidationError(
            "signed manifest does not match local configuration fields: " + ", ".join(drift)
        )

    expected_peers = {
        (
            warden.warden_id,
            key.key_id,
            key.public_key,
            key.not_before,
            key.not_after,
        )
        for warden in manifest.wardens
        if warden.warden_id != signer.warden_id
        for key in warden.keys
    }
    raw_peers = config.get("trusted_peers")
    if not isinstance(raw_peers, Sequence) or isinstance(raw_peers, (str, bytes)):
        raise ValidationError("trusted_peers must be an array")
    configured_peers: set[tuple[str, str, bytes, str | None, str | None]] = set()
    for raw_peer in raw_peers:
        if not isinstance(raw_peer, Mapping):
            raise ValidationError("trusted peer entries must be objects")
        warden_id = raw_peer.get("warden_id")
        key_id = raw_peer.get("key_id")
        public_key = raw_peer.get("public_key")
        not_before = raw_peer.get("not_before")
        not_after = raw_peer.get("not_after")
        if not all(isinstance(value, str) for value in (warden_id, key_id, public_key)):
            raise ValidationError("trusted peer fields are malformed")
        if not_before is not None and not isinstance(not_before, str):
            raise ValidationError("trusted peer not_before must be an RFC 3339 string")
        if not_after is not None and not isinstance(not_after, str):
            raise ValidationError("trusted peer not_after must be an RFC 3339 string")
        configured_peers.add(
            (
                cast(str, warden_id),
                cast(str, key_id),
                b64url_decode(cast(str, public_key)),
                not_before,
                not_after,
            )
        )
    if configured_peers != expected_peers:
        raise ValidationError("configured peer trust does not exactly match the signed manifest")
    expected_endpoints = {
        warden.warden_id: warden.peer_endpoint
        for warden in manifest.wardens
        if warden.warden_id != signer.warden_id
    }
    configured_endpoints = config.get("peer_endpoints")
    if not isinstance(configured_endpoints, Mapping) or configured_endpoints != expected_endpoints:
        raise ValidationError("configured peer endpoints do not exactly match the signed manifest")

    registry = PublicKeyRegistry(clock=clock)
    for warden in manifest.wardens:
        for key in warden.keys:
            registry.register(
                warden.warden_id,
                key.key_id,
                key.public_key,
                not_before_ns=key.not_before_ns,
                not_after_ns=key.not_after_ns,
            )
    registry.require_current(signer.warden_id, signer.key_id)
    return registry


def _key(config_path: Path, arguments: argparse.Namespace | None = None) -> int:
    resolved, config = _load_config(config_path)
    with _open_runtime(resolved, config, arguments) as runtime:
        signer = runtime.signer
        document = {
            "warden_id": signer.warden_id,
            "key_id": signer.key_id,
            "algorithm": "Ed25519",
            "public_key": b64url_encode(signer.public_key_bytes),
            "runtime_provider": runtime.provider_name,
        }
    print(json.dumps(document, indent=2))
    return 0


def _operator_identity(config: Mapping[str, Any], signer: RuntimeSigner) -> IdentityContext:
    return IdentityContext(
        subject_id=f"{signer.warden_id}-local-operator",
        tenant_id=_required_text(config, "tenant_id"),
        scopes=frozenset({"lets.admin", "lets.audit.read", "lets.audit.verify"}),
        authentication_method="local-runtime-provider",
    )


def _operator_service(
    config: Mapping[str, Any],
    signer: RuntimeSigner,
    store: SQLiteStorage,
    *,
    allow_insecure_peer_http: bool = False,
) -> tuple[WardenService, IdentityContext]:
    clock = SystemClock(
        declared_uncertainty_ns=int(config.get("max_clock_uncertainty_ns", 50_000_000))
    )
    registry = _manifest_trust_registry(config, signer, clock=clock)
    configured_insecure = config.get("allow_insecure_manifest", False)
    if not isinstance(configured_insecure, bool):
        raise ValidationError("allow_insecure_manifest must be a boolean")
    endpoints = _configured_peer_endpoints(
        config,
        allow_insecure_http=allow_insecure_peer_http or configured_insecure,
    )
    _validate_peer_trust(endpoints, registry, local_warden_id=signer.warden_id)
    service = WardenService(
        store,
        signer=signer,
        clock=clock,
        trust_registry=registry,
        signing_key_validity=registry.key_validity(signer.warden_id, signer.key_id),
        allowed_peer_wardens=frozenset(endpoints),
    )
    return service, _operator_identity(config, signer)


def _runtime_control(
    config_path: Path,
    arguments: argparse.Namespace,
    mode: RuntimeMode | None,
) -> int:
    resolved, config = _load_config(config_path)
    _require_no_incomplete_restore(resolved)
    with _open_runtime(resolved, config, arguments) as runtime:
        store = _storage(
            resolved,
            config,
            signer=runtime.signer,
            authority_anchor=runtime.authority_anchor,
        )
        try:
            service, identity = _operator_service(config, runtime.signer, store)
            if mode is None:
                status = service.runtime_status(identity=identity)
            else:
                status = service.set_runtime_mode(
                    request_id=f"cli-{secrets.token_hex(16)}",
                    identity=identity,
                    mode=mode,
                    reason=arguments.reason,
                )
        finally:
            store.close()
    print(json.dumps(status.to_dict(), indent=2))
    return 0


def _sqlite_counts(store: SQLiteStorage) -> tuple[int, int]:
    with store.read() as transaction:
        pending_peer = int(
            transaction.connection.execute(
                """
                SELECT COUNT(*) FROM peer_delivery_state
                WHERE delivered_at_ns IS NULL AND superseded_at_ns IS NULL
                """
            ).fetchone()[0]
        )
        pending_audit = int(
            transaction.connection.execute(
                "SELECT COUNT(*) FROM audit_outbox WHERE published_at_ns IS NULL"
            ).fetchone()[0]
        )
    return pending_peer, pending_audit


def _admit_audit_exporter(store: SQLiteStorage, sink: object) -> dict[str, object]:
    from lets.audit import AuditExporter, AuditSink

    if not callable(getattr(sink, "publish", None)) or not callable(getattr(sink, "head", None)):
        raise ValidationError("runtime audit sink does not implement the production protocol")
    exporter = AuditExporter(
        store,
        cast(AuditSink, sink),
        poll_interval_s=0.05,
        publish_timeout_s=1.0,
        max_stall_s=1.0,
    )
    exporter.start()
    try:
        deadline = time.monotonic() + 1.25
        status = exporter.status()
        while (
            (status.get("pending") != 0 or status.get("archive_reconciled") is not True)
            and status.get("last_error") is None
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
            status = exporter.status()
        if status.get("healthy") is not True:
            raise ValidationError(f"audit exporter unhealthy: {status}")
        return status
    finally:
        exporter.stop(timeout_s=2.0)


def _recovery_preflight(
    *,
    store: SQLiteStorage,
    service: WardenService,
    identity: IdentityContext,
    require_anchor: bool,
) -> dict[str, object]:
    status = service.runtime_status(identity=identity)
    if status.mode is not RuntimeMode.DRAINING:
        raise ValidationError("recovery backup requires durable DRAINING mode")
    pending_peer, pending_audit = _sqlite_counts(store)
    if pending_peer:
        raise ValidationError(f"recovery backup has {pending_peer} pending peer deliveries")
    if pending_audit:
        raise ValidationError(f"recovery backup has {pending_audit} unpublished audit records")
    integrity = store.pragma_integrity_check()
    foreign_keys = store.pragma_foreign_key_check()
    if integrity != ("ok",) or foreign_keys:
        raise ValidationError("core database failed recovery preflight integrity checks")
    if not store.verify_conservation(reconcile=True):
        raise ValidationError("core database failed conservation verification")
    if not service.verify_audit(identity=identity):
        raise ValidationError("core database failed audit-chain verification")
    capacity = store.capacity_snapshot()
    if not capacity.healthy:
        raise ValidationError("core database capacity reserve is unhealthy")
    replay_status = service.peer_replay_status()
    anchor_verified = False
    if store.authority_anchor_enabled:
        anchor_verified = store.verify_authority_anchor()
    elif require_anchor:
        raise ValidationError("production recovery requires an independent authority anchor")
    return {
        "runtime": status.to_dict(),
        "pending_peer_deliveries": pending_peer,
        "pending_audit_records": pending_audit,
        "database_integrity": list(integrity),
        "foreign_key_violations": len(foreign_keys),
        "conservation": True,
        "audit_chain": True,
        "peer_replay": replay_status,
        "capacity": capacity.to_dict(),
        "authority_anchor": anchor_verified,
    }


def _bundle_identity(config: Mapping[str, Any], signer: RuntimeSigner) -> dict[str, object]:
    return {
        "warden_id": _required_text(config, "warden_id"),
        "tenant_id": _required_text(config, "tenant_id"),
        "envelope_id": _required_text(config, "envelope_id"),
        "config_epoch": int(config.get("config_epoch", 1)),
        "signing_key_id": signer.key_id,
        "signing_public_key_sha256": sha256(signer.public_key_bytes).hexdigest(),
        "manifest_digest": config.get("manifest_digest"),
    }


def _signed_manifest_path(config: Mapping[str, Any]) -> Path | None:
    if "manifest_digest" not in config:
        return None
    return Path(_required_text(config, "manifest")).resolve()


def _recovery_workspace(
    path: Path,
    *,
    state_directory: Path,
    production: bool,
) -> Path:
    """Admit an explicit backup-domain workspace without creating it."""

    requested = Path(os.path.abspath(path))
    requested_junction = getattr(requested, "is_junction", lambda: False)
    workspace = requested.resolve()
    if requested.is_symlink() or requested_junction() or requested != workspace:
        raise ValidationError("recovery workspace must not cross a symbolic-link boundary")
    state = state_directory.resolve()
    require_filesystem_headroom(
        workspace,
        required_bytes=0,
        operation="recovery workspace admission",
    )
    if production and (
        workspace == state or workspace.is_relative_to(state) or state.is_relative_to(workspace)
    ):
        raise ValidationError(
            "production recovery workspace must be outside the node state directory; "
            "place the bundle on an independent backup volume"
        )
    return workspace


def _recovery_backup(config_path: Path, arguments: argparse.Namespace) -> int:
    resolved, config = _load_config(config_path)
    _require_no_incomplete_restore(resolved)
    if arguments.production:
        _validate_production_state_admission(config)
    lock_path = resolved.parent / ".node.lock"
    with node_process_lock(lock_path):  # noqa: SIM117 - lock must precede provider startup
        with _open_runtime(
            resolved,
            config,
            arguments,
            production=arguments.production,
        ) as runtime:
            store = _storage(
                resolved,
                config,
                signer=runtime.signer,
                authority_anchor=runtime.authority_anchor,
            )
            try:
                service, identity = _operator_service(config, runtime.signer, store)
                if runtime.audit_sink is not None:
                    audit_export = _admit_audit_exporter(store, runtime.audit_sink)
                elif arguments.production:
                    raise ValidationError("production recovery requires an independent audit sink")
                else:
                    audit_export = {"healthy": True, "status": "not-required"}
                checks = _recovery_preflight(
                    store=store,
                    service=service,
                    identity=identity,
                    require_anchor=arguments.production,
                )
                store.checkpoint(truncate=True)
                checkpoint = store.authority_checkpoint().to_dict()
                core_path = _database_path(resolved, config)
                signed_manifest = _signed_manifest_path(config)
                if arguments.production:
                    workspace = _recovery_workspace(
                        arguments.output.resolve().parent,
                        state_directory=core_path.parent,
                        production=True,
                    )
                    bundle_bytes = core_path.stat().st_size + resolved.stat().st_size
                    if signed_manifest is not None:
                        bundle_bytes += signed_manifest.stat().st_size
                    backup_headroom_bytes = bundle_bytes + RECOVERY_METADATA_HEADROOM_BYTES
                    checks["backup_headroom_bytes"] = backup_headroom_bytes
                    require_filesystem_headroom(
                        workspace,
                        required_bytes=backup_headroom_bytes,
                        operation="recovery bundle publication",
                    )
                bundle = create_recovery_bundle(
                    destination=arguments.output,
                    config_path=resolved,
                    core_database=core_path,
                    replay_database=None,
                    signed_manifest=signed_manifest,
                    source_schema_version=store.schema_version,
                    identity=_bundle_identity(config, runtime.signer),
                    authority_checkpoint=checkpoint,
                )
                checks["audit_exporter"] = audit_export
            finally:
                store.close()
    print(
        json.dumps(
            {
                "bundle": str(bundle.root),
                "format": "LETS-RECOVERY-BUNDLE/1",
                "schema_version": bundle.source_schema_version,
                "checks": checks,
                "authority_anchor_included": False,
            },
            indent=2,
        )
    )
    return 0


def _require_bundle_trust_inputs(
    bundle_config: Path,
    bundle_manifest: Path | None,
    *,
    live_config: Path,
    config: Mapping[str, Any],
) -> None:
    if bundle_config.read_bytes() != live_config.read_bytes():
        raise ValidationError("bundled configuration is not byte-identical to trusted live config")
    expected_manifest = _signed_manifest_path(config)
    if expected_manifest is None:
        if bundle_manifest is not None:
            raise ValidationError("bundle unexpectedly contains a signed manifest")
        return
    if bundle_manifest is None:
        raise ValidationError("bundle omits the configured signed manifest")
    if bundle_manifest.read_bytes() != expected_manifest.read_bytes():
        raise ValidationError("bundled manifest is not byte-identical to the trusted manifest")


def _verify_current_bundle(
    *,
    resolved: Path,
    config: Mapping[str, Any],
    arguments: argparse.Namespace,
    production: bool,
    repair_audit_archive: bool = False,
) -> tuple[VerifiedBundle, dict[str, object]]:
    if production:
        _validate_production_state_admission(config)
    bundle = verify_recovery_bundle(arguments.bundle)
    _require_bundle_trust_inputs(
        bundle.artifacts["config"],
        bundle.artifacts.get("signed_manifest"),
        live_config=resolved,
        config=config,
    )
    expected_identity = {
        "warden_id": _required_text(config, "warden_id"),
        "tenant_id": _required_text(config, "tenant_id"),
        "envelope_id": _required_text(config, "envelope_id"),
        "config_epoch": int(config.get("config_epoch", 1)),
        "manifest_digest": config.get("manifest_digest"),
    }
    for field, expected in expected_identity.items():
        if bundle.identity.get(field) != expected:
            raise ValidationError(f"recovery bundle identity field {field!r} does not match config")
    if bundle.source_schema_version != SCHEMA_VERSION:
        return bundle, {"legacy_schema": bundle.source_schema_version, "hashes": True}

    core = _database_path(resolved, config)
    workspace = _recovery_workspace(
        bundle.root.parent,
        state_directory=core.parent,
        production=production,
    )
    require_filesystem_headroom(
        workspace,
        required_bytes=(bundle.digests["core_database"].bytes + RECOVERY_METADATA_HEADROOM_BYTES),
        operation="recovery candidate verification",
    )

    with _open_runtime(resolved, config, arguments, production=production) as runtime:
        if bundle.identity.get("signing_key_id") != runtime.signer.key_id:
            raise ValidationError("recovery bundle signer key does not match runtime provider")
        if (
            bundle.identity.get("signing_public_key_sha256")
            != sha256(runtime.signer.public_key_bytes).hexdigest()
        ):
            raise ValidationError("recovery bundle signer public key does not match provider")
        with tempfile.TemporaryDirectory(
            prefix=".lets-bundle-admission-", dir=workspace
        ) as directory:
            candidate_core = Path(directory) / "warden.sqlite3"
            install_verified_artifact(
                bundle.artifacts["core_database"],
                candidate_core,
                expected=bundle.digests["core_database"],
            )
            store = _storage(
                resolved,
                config,
                signer=runtime.signer,
                database_override=candidate_core,
                # Never expose an unverified candidate to a mutating anchor CAS.
                # Full integrity, conservation, audit, and checkpoint validation
                # must complete before any external authority comparison.
                authority_anchor=None,
            )
            try:
                service, identity = _operator_service(config, runtime.signer, store)
                checks = _recovery_preflight(
                    store=store,
                    service=service,
                    identity=identity,
                    require_anchor=False,
                )
                candidate_checkpoint = store.authority_checkpoint()
                if bundle.authority_checkpoint != candidate_checkpoint.to_dict():
                    raise ValidationError(
                        "bundled authority checkpoint summary does not match bundled database"
                    )
                if production and runtime.authority_anchor is None:
                    raise ValidationError(
                        "production recovery requires an independent authority anchor"
                    )
                if runtime.authority_anchor is not None:
                    anchored_checkpoint = runtime.authority_anchor.read_current()
                    if anchored_checkpoint != candidate_checkpoint:
                        raise StorageError(
                            "recovery bundle does not exactly match the current authority anchor"
                        )
                # Archive publication is deliberately last.  A cryptographically
                # valid but stale/ahead/forked candidate must not be able to write
                # into the independent audit archive before the live anchor has
                # admitted its exact checkpoint.  Plain `recovery verify` remains
                # entirely non-mutating; backup and restore are the only repair
                # paths.
                if runtime.audit_sink is None:
                    if production:
                        raise ValidationError(
                            "production recovery requires an independent audit sink"
                        )
                    checks["audit_exporter"] = {
                        "healthy": True,
                        "status": "not-required",
                    }
                elif repair_audit_archive:
                    checks["audit_exporter"] = _admit_audit_exporter(store, runtime.audit_sink)
                else:
                    checks["audit_exporter"] = {
                        "healthy": True,
                        "status": "provider-bound-non-mutating-verification",
                    }
            finally:
                store.close()
    return bundle, checks


def _recovery_verify(config_path: Path, arguments: argparse.Namespace) -> int:
    resolved, config = _load_config(config_path)
    bundle, checks = _verify_current_bundle(
        resolved=resolved,
        config=config,
        arguments=arguments,
        production=arguments.production,
    )
    print(
        json.dumps(
            {
                "bundle": str(bundle.root),
                "verified": True,
                "schema_version": bundle.source_schema_version,
                "checks": checks,
                "authority_anchor_included": False,
            },
            indent=2,
        )
    )
    return 0


def _preserve_and_remove_sidecars(database: Path, quarantine: Path) -> None:
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{database}{suffix}")
        sidecar_junction = getattr(sidecar, "is_junction", lambda: False)
        if sidecar.is_symlink() or sidecar_junction():
            raise ValidationError(f"refusing non-regular SQLite sidecar during restore: {sidecar}")
        if not sidecar.exists():
            continue
        if not sidecar.is_file():
            raise ValidationError(f"refusing non-regular SQLite sidecar during restore: {sidecar}")
        preserved = quarantine / sidecar.name
        preserve_and_remove_artifact(sidecar, preserved)


def _restore_headroom_preflight(
    *,
    core: Path,
    replacement_bytes: int,
    workspace: Path,
) -> dict[str, int | bool]:
    """Admit peak copy-on-restore bytes before journal or quarantine mutation."""

    preserved_bytes = 0
    for candidate in (core, Path(f"{core}-wal"), Path(f"{core}-shm")):
        if not candidate.exists():
            continue
        candidate_junction = getattr(candidate, "is_junction", lambda: False)
        if candidate.is_symlink() or candidate_junction() or not candidate.is_file():
            raise ValidationError(f"refusing unsafe live recovery artifact: {candidate}")
        preserved_bytes += candidate.stat().st_size
    state_required = replacement_bytes + RECOVERY_METADATA_HEADROOM_BYTES
    workspace_required = preserved_bytes + RECOVERY_METADATA_HEADROOM_BYTES
    try:
        shared_filesystem = os.stat(core.parent).st_dev == os.stat(workspace).st_dev
    except OSError as exc:
        raise StorageError("could not compare recovery workspace and state filesystems") from exc
    if shared_filesystem:
        require_filesystem_headroom(
            workspace,
            required_bytes=state_required + workspace_required,
            operation="same-filesystem restore staging and quarantine",
        )
    else:
        require_filesystem_headroom(
            core.parent,
            required_bytes=state_required,
            operation="atomic restore staging",
        )
        require_filesystem_headroom(
            workspace,
            required_bytes=workspace_required,
            operation="pre-restore quarantine",
        )
    return {
        "replacement_bytes": replacement_bytes,
        "preserved_bytes": preserved_bytes,
        "state_required_bytes": state_required,
        "workspace_required_bytes": workspace_required,
        "shared_filesystem": shared_filesystem,
    }


def _restore_journal_path(config_path: Path) -> Path:
    return config_path.parent / "recovery-restore.json"


def _write_restore_journal(
    path: Path,
    *,
    warden_id: str,
    bundle: Path,
    bundle_manifest_sha256: str,
    quarantine: Path,
    workspace: Path,
    phase: str,
) -> None:
    if phase not in {"PREPARED", "CORE_INSTALLED", "COMPLETE"}:
        raise ValidationError("invalid restore journal phase")
    document = {
        "format": "LETS-RESTORE-JOURNAL/1",
        "warden_id": warden_id,
        "bundle": str(bundle.resolve()),
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "quarantine": str(quarantine.resolve()),
        "workspace": str(workspace.resolve()),
        "phase": phase,
        "updated_at_ns": time.time_ns(),
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(document) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        install_verified_artifact(temporary, path)
    finally:
        with suppress(OSError):
            temporary.unlink()


def _load_restore_journal(path: Path) -> Mapping[str, Any]:
    try:
        decoded = _strict_json(path.read_bytes())
    except OSError as exc:
        raise StorageError("could not read restore journal") from exc
    if not isinstance(decoded, Mapping):
        raise ValidationError("restore journal root must be an object")
    expected = {
        "format",
        "warden_id",
        "bundle",
        "bundle_manifest_sha256",
        "quarantine",
        "workspace",
        "phase",
        "updated_at_ns",
    }
    if (
        set(decoded) != expected
        or decoded.get("format") != "LETS-RESTORE-JOURNAL/1"
        or decoded.get("phase") not in {"PREPARED", "CORE_INSTALLED", "COMPLETE"}
    ):
        raise ValidationError("restore journal fields or format are invalid")
    for field in (
        "warden_id",
        "bundle",
        "bundle_manifest_sha256",
        "quarantine",
        "workspace",
    ):
        if not isinstance(decoded.get(field), str) or not decoded[field]:
            raise ValidationError(f"restore journal field {field!r} is invalid")
    return cast(Mapping[str, Any], decoded)


def _require_no_incomplete_restore(config_path: Path) -> None:
    journal = _restore_journal_path(config_path)
    if not journal.exists():
        return
    state = _load_restore_journal(journal)
    if state["phase"] != "COMPLETE":
        raise StorageError(
            f"restore is incomplete at phase {state['phase']}; resume the exact restore command"
        )


def _recovery_restore(config_path: Path, arguments: argparse.Namespace) -> int:
    resolved, config = _load_config(config_path)
    warden_id = _required_text(config, "warden_id")
    if arguments.confirm_warden_id != warden_id:
        raise ValidationError("--confirm-warden-id does not match the configured warden")
    lock_path = resolved.parent / ".node.lock"
    with node_process_lock(lock_path):
        # Restore always requires the production-capable provider and its live,
        # independent anchor, even if the original bundle came from development.
        bundle, checks = _verify_current_bundle(
            resolved=resolved,
            config=config,
            arguments=arguments,
            production=True,
            repair_audit_archive=True,
        )
        if bundle.source_schema_version != SCHEMA_VERSION:
            raise ValidationError("restore requires a bundle at the current schema version")
        core = _database_path(resolved, config)
        workspace = _recovery_workspace(
            bundle.root.parent,
            state_directory=core.parent,
            production=True,
        )
        journal_path = _restore_journal_path(resolved)
        manifest_hash = _bundle_manifest_hash(bundle.root)
        state: Mapping[str, Any] | None = (
            _load_restore_journal(journal_path) if journal_path.exists() else None
        )
        if state is not None and (
            state["warden_id"] != warden_id
            or state["bundle"] != str(bundle.root)
            or state["bundle_manifest_sha256"] != manifest_hash
        ):
            if state["phase"] != "COMPLETE":
                raise ValidationError(
                    "incomplete restore journal binds a different bundle or warden"
                )
            old_workspace = _recovery_workspace(
                Path(str(state["workspace"])),
                state_directory=core.parent,
                production=True,
            )
            remove_recovery_quarantine(
                Path(str(state["quarantine"])),
                workspace=old_workspace,
                expected_names=frozenset({core.name, f"{core.name}-wal", f"{core.name}-shm"}),
            )
            state = None
        if state is None:
            checks["restore_headroom"] = _restore_headroom_preflight(
                core=core,
                replacement_bytes=bundle.digests["core_database"].bytes,
                workspace=workspace,
            )
            quarantine = create_recovery_quarantine(
                workspace / f"pre-restore-{warden_id}-{time.time_ns()}",
                workspace=workspace,
            )
            phase = "PREPARED"
            _write_restore_journal(
                journal_path,
                warden_id=warden_id,
                bundle=bundle.root,
                bundle_manifest_sha256=manifest_hash,
                quarantine=quarantine,
                workspace=workspace,
                phase=phase,
            )
        else:
            journal_workspace = Path(str(state["workspace"])).resolve()
            if journal_workspace != workspace:
                raise ValidationError("restore journal binds a different recovery workspace")
            quarantine = Path(str(state["quarantine"])).resolve()
            if quarantine.parent != workspace or (
                state["phase"] != "COMPLETE"
                and (
                    not quarantine.is_dir()
                    or quarantine.is_symlink()
                    or getattr(quarantine, "is_junction", lambda: False)()
                )
            ):
                raise ValidationError("restore quarantine is outside its recovery workspace")
            phase = str(state["phase"])

        if phase == "PREPARED":
            preserved = quarantine / core.name
            if core.exists() and not preserved.exists():
                if core.is_symlink() or not core.is_file():
                    raise ValidationError(f"refusing non-regular restore target: {core}")
                install_verified_artifact(core, preserved)
            _preserve_and_remove_sidecars(core, quarantine)
            install_verified_artifact(
                bundle.artifacts["core_database"],
                core,
                expected=bundle.digests["core_database"],
            )
            phase = "CORE_INSTALLED"
            _write_restore_journal(
                journal_path,
                warden_id=warden_id,
                bundle=bundle.root,
                bundle_manifest_sha256=manifest_hash,
                quarantine=quarantine,
                workspace=workspace,
                phase=phase,
            )
        if phase == "CORE_INSTALLED":
            # A second provider/anchor admission occurs only after the core file is
            # durable. Peer replay authority lives in this same anchored database.
            # Failure leaves the journal incomplete, so serve remains fenced.
            with _open_runtime(resolved, config, arguments, production=True) as runtime:
                restored = _storage(
                    resolved,
                    config,
                    signer=runtime.signer,
                    authority_anchor=runtime.authority_anchor,
                )
                try:
                    service, identity = _operator_service(config, runtime.signer, restored)
                    _recovery_preflight(
                        store=restored,
                        service=service,
                        identity=identity,
                        require_anchor=True,
                    )
                finally:
                    restored.close()
            phase = "COMPLETE"
            _write_restore_journal(
                journal_path,
                warden_id=warden_id,
                bundle=bundle.root,
                bundle_manifest_sha256=manifest_hash,
                quarantine=quarantine,
                workspace=workspace,
                phase=phase,
            )
        if phase == "COMPLETE":
            remove_recovery_quarantine(
                quarantine,
                workspace=workspace,
                expected_names=frozenset({core.name, f"{core.name}-wal", f"{core.name}-shm"}),
            )
    print(
        json.dumps(
            {
                "restored": str(bundle.root),
                "warden_id": warden_id,
                "pre_restore_quarantine": str(quarantine),
                "pre_restore_quarantine_retained": quarantine.exists(),
                "checks": checks,
                "authority_anchor_restored": False,
                "runtime_mode": "DRAINING",
            },
            indent=2,
        )
    )
    return 0


def _migrate_storage(
    path: Path,
    config: Mapping[str, Any],
    signer: RuntimeSigner,
    *,
    authority_anchor: AuthorityAnchor | None = None,
) -> SQLiteStorage:
    manifest_digest = config.get("manifest_digest")
    extensions = (
        None
        if manifest_digest is None
        else {"manifest_digest": _required_text(config, "manifest_digest")}
    )
    return SQLiteStorage.migrate(
        path,
        _required_text(config, "warden_id"),
        _config_vector(config, "budget"),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=_required_text(config, "tenant_id"),
        envelope_id=_required_text(config, "envelope_id"),
        config_epoch=int(config.get("config_epoch", 1)),
        dimension_metadata=config.get("dimension_metadata"),
        initial_local_share=_config_vector(config, "local_share"),
        receipt_ttl_ns=int(config.get("receipt_ttl_ns", 1_000_000_000)),
        max_clock_uncertainty_ns=int(config.get("max_clock_uncertainty_ns", 50_000_000)),
        transfer_gap_window=int(config.get("transfer_gap_window", 64)),
        config=extensions,
        authority_anchor=authority_anchor,
        min_free_disk_bytes=config.get("min_free_disk_bytes", 0),
        max_database_bytes=config.get("max_database_bytes"),
        reserve_pages=config.get("reserve_pages", 64),
    )


def _legacy_preflight(core: Path, replay: Path) -> dict[str, object]:
    core_diagnostics = sqlite_diagnostics(
        core,
        expected_application_id=APPLICATION_ID,
        expected_schema_version=1,
        foreign_keys=True,
    )
    replay_diagnostics = sqlite_diagnostics(
        replay,
        expected_application_id=SQLitePeerReplayStore.APPLICATION_ID,
        expected_schema_version=SQLitePeerReplayStore.SCHEMA_VERSION,
        foreign_keys=False,
    )
    legacy_replay = SQLitePeerReplayStore(replay, read_only=True)
    active_replay_claims = legacy_replay.active_claim_count(now_s=int(time.time()))
    if active_replay_claims:
        raise ValidationError(
            "legacy peer replay still has live claims; keep the schema-1 node stopped, "
            "wait at least the peer signature validity window, then retry migration"
        )
    try:
        with closing(sqlite3.connect(f"{core.resolve().as_uri()}?mode=ro", uri=True)) as connection:
            pending_peer = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM peer_delivery_state
                    WHERE delivered_at_ns IS NULL AND superseded_at_ns IS NULL
                    """
                ).fetchone()[0]
            )
            pending_audit = int(
                connection.execute(
                    "SELECT COUNT(*) FROM audit_outbox WHERE published_at_ns IS NULL"
                ).fetchone()[0]
            )
    except sqlite3.Error as exc:
        raise StorageError("could not inspect legacy migration queues") from exc
    if pending_peer or pending_audit:
        raise ValidationError(
            "migration requires empty delivery/export queues: "
            f"peer={pending_peer}, audit={pending_audit}"
        )
    return {
        "core": core_diagnostics,
        "replay": replay_diagnostics,
        "pending_peer_deliveries": pending_peer,
        "pending_audit_records": pending_audit,
        "active_peer_replay_claims": active_replay_claims,
    }


def _verify_migration_copy(
    source: Path,
    config: Mapping[str, Any],
    signer: RuntimeSigner,
    *,
    scratch_directory: Path,
    expected_digest: ArtifactDigest | None = None,
) -> dict[str, object]:
    required_bytes = (
        source.stat().st_size if expected_digest is None else expected_digest.bytes
    ) + RECOVERY_METADATA_HEADROOM_BYTES
    require_filesystem_headroom(
        scratch_directory,
        required_bytes=required_bytes,
        operation="migration compatibility verification",
    )
    with tempfile.TemporaryDirectory(
        prefix=".lets-migration-verifier-", dir=scratch_directory
    ) as directory:
        candidate = Path(directory) / "warden.sqlite3"
        install_verified_artifact(source, candidate, expected=expected_digest)
        store = _migrate_storage(candidate, config, signer)
        try:
            service, identity = _operator_service(config, signer, store)
            if store.pragma_integrity_check() != ("ok",) or store.pragma_foreign_key_check():
                raise ValidationError("migrated verification copy failed database diagnostics")
            store.verify_conservation(reconcile=True)
            service.verify_audit(identity=identity)
            return {
                "schema_version": store.schema_version,
                "database_integrity": ["ok"],
                "foreign_key_violations": 0,
                "conservation": True,
                "audit_chain": True,
            }
        finally:
            store.close()


def _anchor_audit_lookup(database: Path) -> Callable[[int], bytes | None]:
    def lookup(sequence: int) -> bytes | None:
        try:
            with closing(
                sqlite3.connect(f"{database.resolve().as_uri()}?mode=ro", uri=True)
            ) as connection:
                row = connection.execute(
                    "SELECT event_hash FROM audit_log WHERE sequence = ?", (sequence,)
                ).fetchone()
        except sqlite3.Error as exc:
            raise StorageError(
                "could not read audit history while bootstrapping authority"
            ) from exc
        return None if row is None else bytes(row[0])

    return lookup


def _migration_journal_path(config_path: Path) -> Path:
    return config_path.parent / "migration-v1-v2.json"


def _bundle_manifest_hash(bundle_root: Path) -> str:
    try:
        payload = (bundle_root / "bundle.json").read_bytes()
    except OSError as exc:
        raise StorageError("could not read migration bundle manifest") from exc
    return sha256(payload).hexdigest()


def _write_migration_journal(
    path: Path,
    *,
    warden_id: str,
    backup: Path,
    bundle_manifest_sha256: str,
    phase: str,
) -> None:
    if phase not in {"BACKUP_VERIFIED", "DATABASE_MIGRATED", "ANCHOR_ADMITTED", "COMPLETE"}:
        raise ValidationError("invalid migration journal phase")
    document = {
        "format": "LETS-MIGRATION-JOURNAL/1",
        "warden_id": warden_id,
        "source_schema_version": 1,
        "target_schema_version": SCHEMA_VERSION,
        "backup": str(backup.resolve()),
        "bundle_manifest_sha256": bundle_manifest_sha256,
        "phase": phase,
        "updated_at_ns": time.time_ns(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(document) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        install_verified_artifact(temporary, path)
    finally:
        with suppress(OSError):
            temporary.unlink()


def _load_migration_journal(
    path: Path,
    *,
    warden_id: str,
    backup: Path,
    bundle_manifest_sha256: str,
) -> Mapping[str, Any]:
    try:
        decoded = _strict_json(path.read_bytes())
    except OSError as exc:
        raise ValidationError("migration resume requires its durable journal") from exc
    if not isinstance(decoded, Mapping):
        raise ValidationError("migration journal root must be an object")
    expected = {
        "format",
        "warden_id",
        "source_schema_version",
        "target_schema_version",
        "backup",
        "bundle_manifest_sha256",
        "phase",
        "updated_at_ns",
    }
    if set(decoded) != expected or decoded.get("format") != "LETS-MIGRATION-JOURNAL/1":
        raise ValidationError("migration journal fields or format are invalid")
    if (
        decoded.get("warden_id") != warden_id
        or decoded.get("source_schema_version") != 1
        or decoded.get("target_schema_version") != SCHEMA_VERSION
        or decoded.get("backup") != str(backup.resolve())
        or decoded.get("bundle_manifest_sha256") != bundle_manifest_sha256
        or decoded.get("phase")
        not in {"BACKUP_VERIFIED", "DATABASE_MIGRATED", "ANCHOR_ADMITTED", "COMPLETE"}
    ):
        raise ValidationError("migration journal does not bind this exact migration backup")
    return cast(Mapping[str, Any], decoded)


def _verify_migration_bundle(
    backup: Path,
    *,
    resolved: Path,
    config: Mapping[str, Any],
    signer: RuntimeSigner,
) -> VerifiedBundle:
    bundle = verify_recovery_bundle(backup)
    if bundle.source_schema_version != 1:
        raise ValidationError("migration backup must preserve the schema-1 source")
    _require_bundle_trust_inputs(
        bundle.artifacts["config"],
        bundle.artifacts.get("signed_manifest"),
        live_config=resolved,
        config=config,
    )
    expected = _bundle_identity(config, signer)
    for field, value in expected.items():
        if bundle.identity.get(field) != value:
            raise ValidationError(f"migration backup identity field {field!r} drifted")
    if bundle.authority_checkpoint is not None:
        raise ValidationError("schema-1 migration backup must not contain an authority anchor")
    _verify_migration_copy(
        bundle.artifacts["core_database"],
        config,
        signer,
        scratch_directory=bundle.root.parent,
        expected_digest=bundle.digests["core_database"],
    )
    return bundle


def _pre_anchor_authority_fingerprint(
    database: Path, *, immutable: bool = False
) -> tuple[object, ...]:
    """Bind the schema-1 authority fields that MIGRATION_2 must not change."""

    try:
        with closing(
            sqlite3.connect(
                f"{database.resolve().as_uri()}?mode=ro" + ("&immutable=1" if immutable else ""),
                uri=True,
            )
        ) as connection:
            state = connection.execute(
                """
                SELECT free_pool, lease_residual, consumed, transferred_in, transferred_out,
                       clock_floor_ns, revision
                FROM warden_state
                """
            ).fetchone()
            audit = connection.execute(
                "SELECT sequence, event_hash FROM audit_log ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
    except sqlite3.Error as exc:
        raise StorageError("could not fingerprint migration authority state") from exc
    if state is None:
        raise StorageError("migration authority state is missing")
    state_values = tuple(bytes(value) if isinstance(value, bytes) else value for value in state)
    audit_values: tuple[object, object] = (
        (-1, bytes(32)) if audit is None else (int(audit[0]), bytes(audit[1]))
    )
    return (*state_values, *audit_values)


def _resume_migrated_database(
    *,
    resolved: Path,
    config: Mapping[str, Any],
    core: Path,
    runtime: RuntimeSession,
    journal: Path,
    backup: Path,
    manifest_hash: str,
    journal_phase: str,
) -> tuple[RuntimeStatus, dict[str, object]]:
    store = _storage(resolved, config, signer=runtime.signer)
    try:
        service, identity = _operator_service(config, runtime.signer, store)
        status = service.runtime_status(identity=identity)
        pristine_expansion = (
            journal_phase == "BACKUP_VERIFIED"
            and status.mode is RuntimeMode.ACTIVE
            and status.generation == 0
            and status.reason == "schema initialization"
            and status.changed_at_ns == 0
            and status.changed_by == "lets-migration"
        )
        if pristine_expansion:
            source_bundle = verify_recovery_bundle(backup)
            if _pre_anchor_authority_fingerprint(core) != _pre_anchor_authority_fingerprint(
                source_bundle.artifacts["core_database"], immutable=True
            ):
                raise ValidationError(
                    "pristine expansion authority state differs from the verified schema-1 backup"
                )
            # MIGRATION_2 installed its exact expand-only genesis but the process
            # died before the separately audited drain.  No production serve can
            # pass the still-missing anchor.  Complete the drain idempotently now.
            status = service.set_runtime_mode(
                request_id=f"migration-resume-{secrets.token_hex(16)}",
                identity=identity,
                mode=RuntimeMode.DRAINING,
                reason="schema migration completed; operator activation required",
            )
        elif (
            status.mode is not RuntimeMode.DRAINING
            or status.reason != "schema migration completed; operator activation required"
        ):
            raise ValidationError(
                "resumable database is neither pristine schema expansion nor migration DRAINING"
            )
        migration_now_s = int(time.time())
        migration_bundle = verify_recovery_bundle(backup)
        legacy_replay_path = migration_bundle.artifacts.get("replay_database")
        if legacy_replay_path is None:
            raise ValidationError("schema-1 migration backup omits peer replay authority")
        legacy_replay = SQLitePeerReplayStore(legacy_replay_path, read_only=True, immutable=True)
        legacy_snapshot = legacy_replay.snapshot(
            now_s=migration_now_s,
            expected_digest=bytes.fromhex(migration_bundle.digests["replay_database"].sha256),
        )
        imported_legacy_replay = service.import_legacy_peer_replay(
            clock_floor_s=legacy_snapshot.clock_floor_s,
            snapshot_digest=legacy_snapshot.digest,
            active_claim_count=legacy_snapshot.active_claim_count,
            now_s=migration_now_s,
        )
        pending_peer, pending_audit = _sqlite_counts(store)
        if pending_peer:
            raise ValidationError("resumable migration has pending peer deliveries")
        if store.pragma_integrity_check() != ("ok",) or store.pragma_foreign_key_check():
            raise ValidationError("resumable migrated database failed integrity diagnostics")
        store.verify_conservation(reconcile=True)
        service.verify_audit(identity=identity)
        if legacy_replay.integrity_check() != ("ok",):
            raise ValidationError("resumable migration replay database failed integrity")
        checkpoint = store.authority_checkpoint()
        checks = {
            "runtime": status.to_dict(),
            "pending_peer_deliveries": pending_peer,
            "pending_audit_records": pending_audit,
            "database_integrity": ["ok"],
            "conservation": True,
            "audit_chain": True,
            "legacy_replay_integrity": ["ok"],
            "legacy_replay_snapshot_sha256": legacy_snapshot.digest.hex(),
            "legacy_replay_active_claims": legacy_snapshot.active_claim_count,
            "legacy_replay_imported": imported_legacy_replay,
            "peer_replay": service.peer_replay_status(),
        }
    finally:
        store.close()
    _write_migration_journal(
        journal,
        warden_id=runtime.signer.warden_id,
        backup=backup,
        bundle_manifest_sha256=manifest_hash,
        phase="DATABASE_MIGRATED",
    )
    if runtime.authority_anchor is not None:
        runtime.authority_anchor.reconcile(
            checkpoint,
            audit_hash_at=_anchor_audit_lookup(core),
            initialize=True,
            allow_schema_upgrade=True,
        )
        _write_migration_journal(
            journal,
            warden_id=runtime.signer.warden_id,
            backup=backup,
            bundle_manifest_sha256=manifest_hash,
            phase="ANCHOR_ADMITTED",
        )
        admitted = _storage(
            resolved,
            config,
            signer=runtime.signer,
            authority_anchor=runtime.authority_anchor,
        )
        try:
            admitted.verify_authority_anchor()
            admitted.verify_conservation(reconcile=True)
        finally:
            admitted.close()
    elif runtime.production_capable:
        raise ValidationError("production migration requires an independent authority anchor")
    _write_migration_journal(
        journal,
        warden_id=runtime.signer.warden_id,
        backup=backup,
        bundle_manifest_sha256=manifest_hash,
        phase="COMPLETE",
    )
    return status, checks


def _migrate(config_path: Path, arguments: argparse.Namespace) -> int:
    resolved, config = _load_config(config_path)
    _require_no_incomplete_restore(resolved)
    if arguments.production:
        _validate_production_state_admission(config)
    core = _database_path(resolved, config)
    backup_path = arguments.backup.resolve()
    scratch_candidate = backup_path.parent if backup_path.parent.is_dir() else resolved.parent
    scratch_directory = _recovery_workspace(
        scratch_candidate,
        state_directory=core.parent,
        production=arguments.production,
    )
    journal = _migration_journal_path(resolved)
    lock_path = resolved.parent / ".node.lock"
    with node_process_lock(lock_path):
        application_id, source_version = read_sqlite_header(core)
        if application_id != APPLICATION_ID:
            raise ValidationError("migration source is not a LETS authority database")
        if source_version not in (1, SCHEMA_VERSION):
            raise ValidationError(
                f"migrate supports schema 1 -> {SCHEMA_VERSION}; source is {source_version}"
            )
        with _open_runtime(
            resolved,
            config,
            arguments,
            production=arguments.production,
        ) as runtime:
            if source_version == SCHEMA_VERSION:
                if not arguments.resume:
                    raise ValidationError("schema-2 migration recovery requires explicit --resume")
                bundle = _verify_migration_bundle(
                    backup_path,
                    resolved=resolved,
                    config=config,
                    signer=runtime.signer,
                )
                manifest_hash = _bundle_manifest_hash(bundle.root)
                journal_state = _load_migration_journal(
                    journal,
                    warden_id=runtime.signer.warden_id,
                    backup=backup_path,
                    bundle_manifest_sha256=manifest_hash,
                )
                status, resume_checks = _resume_migrated_database(
                    resolved=resolved,
                    config=config,
                    core=core,
                    runtime=runtime,
                    journal=journal,
                    backup=backup_path,
                    manifest_hash=manifest_hash,
                    journal_phase=str(journal_state["phase"]),
                )
                print(
                    json.dumps(
                        {
                            "resumed": True,
                            "target_schema_version": SCHEMA_VERSION,
                            "backup": str(bundle.root),
                            "backup_verified": True,
                            "authority_anchor_restored": False,
                            "runtime": status.to_dict(),
                            "checks": resume_checks,
                        },
                        indent=2,
                    )
                )
                return 0

            replay = _local_path(resolved, config, "replay_database")
            checks = _legacy_preflight(core, replay)
            compatibility = _verify_migration_copy(
                core,
                config,
                runtime.signer,
                scratch_directory=scratch_directory,
            )
            if arguments.dry_run:
                if arguments.resume:
                    raise ValidationError("--dry-run and --resume are mutually exclusive")
                print(
                    json.dumps(
                        {
                            "dry_run": True,
                            "source_schema_version": source_version,
                            "target_schema_version": SCHEMA_VERSION,
                            "backup": str(arguments.backup.resolve()),
                            "backup_created": False,
                            "stop_the_world": True,
                            "checks": checks,
                            "migration_compatibility": compatibility,
                        },
                        indent=2,
                    )
                )
                return 0

            if backup_path.exists():
                if not arguments.resume:
                    raise ValidationError(
                        "migration backup exists; use --resume to verify and continue it"
                    )
                bundle = _verify_migration_bundle(
                    backup_path,
                    resolved=resolved,
                    config=config,
                    signer=runtime.signer,
                )
            else:
                bundle = create_recovery_bundle(
                    destination=backup_path,
                    config_path=resolved,
                    core_database=core,
                    replay_database=replay,
                    signed_manifest=_signed_manifest_path(config),
                    source_schema_version=source_version,
                    identity=_bundle_identity(config, runtime.signer),
                    authority_checkpoint=None,
                )
                # Mandatory post-publication verification precedes the first source write.
                bundle = _verify_migration_bundle(
                    bundle.root,
                    resolved=resolved,
                    config=config,
                    signer=runtime.signer,
                )
            manifest_hash = _bundle_manifest_hash(bundle.root)
            _write_migration_journal(
                journal,
                warden_id=runtime.signer.warden_id,
                backup=backup_path,
                bundle_manifest_sha256=manifest_hash,
                phase="BACKUP_VERIFIED",
            )

            # Schema 1 predates external anchors.  Migrate and drain while the node
            # process lock excludes serving, then explicitly bootstrap the provider
            # anchor at the complete schema-2/drained head.
            migrated = _migrate_storage(core, config, runtime.signer)
            try:
                service, identity = _operator_service(config, runtime.signer, migrated)
                status = service.set_runtime_mode(
                    request_id=f"migration-{secrets.token_hex(16)}",
                    identity=identity,
                    mode=RuntimeMode.DRAINING,
                    reason="schema migration completed; operator activation required",
                )
                migrated.checkpoint(truncate=True)
            finally:
                migrated.close()
            status, resume_checks = _resume_migrated_database(
                resolved=resolved,
                config=config,
                core=core,
                runtime=runtime,
                journal=journal,
                backup=backup_path,
                manifest_hash=manifest_hash,
                journal_phase="DATABASE_MIGRATED",
            )

    print(
        json.dumps(
            {
                "migrated": str(core),
                "source_schema_version": source_version,
                "target_schema_version": SCHEMA_VERSION,
                "backup": str(bundle.root),
                "backup_verified": True,
                "stop_the_world": True,
                "rolling_upgrade_supported": False,
                "runtime": status.to_dict(),
                "checks": checks,
                "post_migration_checks": resume_checks,
                "migration_compatibility": compatibility,
            },
            indent=2,
        )
    )
    return 0


def _info(config_path: Path, arguments: argparse.Namespace | None = None) -> int:
    resolved, config = _load_config(config_path)
    production = bool(arguments is not None and getattr(arguments, "production", False))
    allow_insecure_peer_http = bool(
        arguments is not None and getattr(arguments, "allow_insecure_peer_http", False)
    )
    checks: dict[str, dict[str, object]] = {}

    def passed(name: str, detail: object) -> None:
        checks[name] = {"ok": True, "detail": detail}

    def failed(name: str, error: Exception | str) -> None:
        checks[name] = {
            "ok": False,
            "error": str(error),
            "error_type": type(error).__name__ if isinstance(error, Exception) else "admission",
        }

    try:
        _require_no_incomplete_restore(resolved)
        passed("restore_journal", "clear")
    except Exception as exc:
        failed("restore_journal", exc)
        blocked_document = {
            "config": str(resolved),
            "manifest_digest": config.get("manifest_digest"),
            "checks": checks,
            "ready": False,
        }
        print(json.dumps(blocked_document, indent=2))
        return 1

    database_path = _database_path(resolved, config)
    try:
        application_id, schema_version = read_sqlite_header(database_path)
        if application_id != APPLICATION_ID or schema_version != SCHEMA_VERSION:
            raise ValidationError(
                f"database identity/schema is {application_id:#x}/{schema_version}, "
                f"expected {APPLICATION_ID:#x}/{SCHEMA_VERSION}"
            )
        passed(
            "schema_identity",
            {"application_id": application_id, "schema_version": schema_version},
        )
    except Exception as exc:
        failed("schema_identity", exc)

    document: dict[str, object] = {
        "config": str(resolved),
        "database": str(database_path),
        "manifest_digest": config.get("manifest_digest"),
        "checks": checks,
    }
    try:
        runtime_context = _open_runtime(
            resolved,
            config,
            arguments,
            production=production,
        )
    except Exception as exc:
        failed("runtime_provider", exc)
        document["ready"] = False
        print(json.dumps(document, indent=2))
        return 1

    with runtime_context as runtime:
        provider_healthy = not production or (
            runtime.production_capable
            and runtime.authority_anchor is not None
            and runtime.audit_sink is not None
        )
        provider_detail = {
            "name": runtime.provider_name,
            "production_capable": runtime.production_capable,
            "authority_anchor": runtime.authority_anchor is not None,
            "audit_sink": runtime.audit_sink is not None,
        }
        if provider_healthy:
            passed("runtime_provider", provider_detail)
        else:
            failed("runtime_provider", "provider lacks required production bindings")
        signer = runtime.signer
        document.update(
            {
                "warden_id": signer.warden_id,
                "key_id": signer.key_id,
                "runtime_provider": runtime.provider_name,
            }
        )

        if production:
            try:
                if config.get("allow_insecure_manifest") is not False:
                    raise ValidationError("production manifest permits insecure HTTP")
                if any(
                    field not in config
                    for field in ("manifest", "manifest_digest", "operator_trust")
                ):
                    raise ValidationError("production manifest trust inputs are incomplete")
                if config.get("bootstrap_identities") not in (None, []):
                    raise ValidationError("production config contains static bootstrap identities")
                for field in ("min_free_disk_bytes", "max_database_bytes", "reserve_pages"):
                    value = config.get(field)
                    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                        raise ValidationError(
                            f"production capacity field {field!r} is not positive"
                        )
                passed("production_configuration", True)
            except Exception as exc:
                failed("production_configuration", exc)
        else:
            passed("production_configuration", "not-requested")

        try:
            store = _storage(
                resolved,
                config,
                signer=signer,
                authority_anchor=runtime.authority_anchor,
            )
        except Exception as exc:
            failed("database_open", exc)
            document["ready"] = False
            print(json.dumps(document, indent=2))
            return 1
        try:
            passed(
                "database_open",
                {
                    "tenant_id": store.metadata.tenant_id,
                    "envelope_id": store.metadata.envelope_id,
                    "config_epoch": store.metadata.config_epoch,
                },
            )
            document.update(
                {
                    "tenant_id": store.metadata.tenant_id,
                    "envelope_id": store.metadata.envelope_id,
                    "config_epoch": store.metadata.config_epoch,
                    "schema_version": store.schema_version,
                }
            )
            try:
                integrity = store.pragma_integrity_check()
                foreign_keys = store.pragma_foreign_key_check()
                if integrity != ("ok",) or foreign_keys:
                    raise ValidationError(
                        f"integrity={integrity!r}, foreign_key_violations={len(foreign_keys)}"
                    )
                passed(
                    "core_integrity",
                    {"integrity": list(integrity), "foreign_key_violations": 0},
                )
                document["database_integrity"] = list(integrity)
                document["foreign_key_violations"] = 0
            except Exception as exc:
                failed("core_integrity", exc)

            try:
                capacity = store.capacity_snapshot()
                if not capacity.healthy:
                    raise ValidationError("configured storage capacity reserve is exhausted")
                passed("capacity", capacity.to_dict())
                document["storage_capacity"] = capacity.to_dict()
            except Exception as exc:
                failed("capacity", exc)

            try:
                store.verify_conservation(reconcile=True)
                passed("conservation", True)
            except Exception as exc:
                failed("conservation", exc)

            service: WardenService | None = None
            identity: IdentityContext | None = None
            try:
                service, identity = _operator_service(
                    config,
                    signer,
                    store,
                    allow_insecure_peer_http=allow_insecure_peer_http,
                )
                passed("manifest_peer_trust", True)
            except Exception as exc:
                failed("manifest_peer_trust", exc)
            if service is not None and identity is not None:
                try:
                    passed("peer_replay", service.peer_replay_status())
                except Exception as exc:
                    failed("peer_replay", exc)
                try:
                    status = service.runtime_status(identity=identity)
                    if not service.ready():
                        raise ValidationError(
                            f"service is not ready (runtime mode {status.mode.value})"
                        )
                    passed("clock_key_runtime", status.to_dict())
                except Exception as exc:
                    failed("clock_key_runtime", exc)
                try:
                    service.verify_audit(identity=identity)
                    passed("audit_chain", True)
                except Exception as exc:
                    failed("audit_chain", exc)
            else:
                failed("peer_replay", "core service admission failed")

            try:
                if runtime.authority_anchor is None:
                    if production:
                        raise ValidationError("production runtime has no independent anchor")
                    passed("authority_anchor", "not-required")
                else:
                    store.verify_authority_anchor()
                    passed("authority_anchor", store.authority_checkpoint().to_dict())
            except Exception as exc:
                failed("authority_anchor", exc)

            try:
                if runtime.audit_sink is None:
                    if production:
                        raise ValidationError("production runtime has no independent audit sink")
                    passed("audit_exporter", "not-required")
                else:
                    passed(
                        "audit_exporter",
                        _admit_audit_exporter(store, runtime.audit_sink),
                    )
            except Exception as exc:
                failed("audit_exporter", exc)
        finally:
            store.close()

    document["ready"] = all(bool(check.get("ok")) for check in checks.values())
    print(json.dumps(document, indent=2))
    return 0 if document["ready"] else 1


def _backup(
    config_path: Path,
    output: Path,
    arguments: argparse.Namespace | None = None,
) -> int:
    resolved, config = _load_config(config_path)
    _require_no_incomplete_restore(resolved)
    destination = output.resolve()
    if destination.exists():
        raise ValidationError(f"backup destination already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary = ""
    with _open_runtime(resolved, config, arguments) as runtime:
        store = _storage(
            resolved,
            config,
            signer=runtime.signer,
            authority_anchor=runtime.authority_anchor,
        )
        try:
            store.checkpoint()
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
            )
            os.close(descriptor)
            descriptor = -1
            source = sqlite3.connect(store.path)
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
                target.commit()
            finally:
                target.close()
                source.close()
            verifier = _storage(
                resolved,
                config,
                signer=runtime.signer,
                database_override=Path(temporary),
                authority_anchor=runtime.authority_anchor,
            )
            try:
                integrity = verifier.pragma_integrity_check()
                if integrity != ("ok",):
                    raise ValidationError(f"backup integrity check failed: {integrity!r}")
            finally:
                verifier.close()
            with open(temporary, "r+b") as stream:
                os.fsync(stream.fileno())
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise ValidationError(
                    f"backup destination appeared during backup: {destination}"
                ) from exc
            os.unlink(temporary)
            temporary = ""
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary:
                with suppress(FileNotFoundError):
                    os.unlink(temporary)
            store.close()
    print(
        json.dumps(
            {
                "backup": str(destination),
                "bytes": destination.stat().st_size,
                "scope": "database-only",
                "warning": (
                    "Back up config and runtime-provider recovery material separately "
                    "as protected secrets."
                ),
            },
            indent=2,
        )
    )
    return 0


def _metrics_provider(
    service: WardenService,
    store: SQLiteStorage,
    identity: IdentityContext,
    *,
    peer_status: Callable[[], Mapping[str, object]] | None = None,
    audit_status: Callable[[], Mapping[str, object]] | None = None,
) -> dict[str, object]:
    invariant = service.invariant_snapshot(identity=identity)
    capacity = store.capacity_snapshot()
    service_ready = service.ready()
    with store.read() as transaction:
        connection = transaction.connection
        lease_rows = connection.execute(
            "SELECT status, COUNT(*) AS count FROM leases GROUP BY status ORDER BY status"
        ).fetchall()
        receipt_count = int(connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0])
        outgoing = connection.execute(
            """
            SELECT COUNT(*), COALESCE(MAX(acked_through), 0),
                   COALESCE(MAX(compacted_through), 0)
            FROM outgoing_transfer_streams
            """
        ).fetchone()
        incoming = connection.execute(
            """
            SELECT COUNT(*), COALESCE(MAX(contiguous_through), 0),
                   COALESCE(MAX(compacted_through), 0)
            FROM inbound_transfer_streams
            """
        ).fetchone()
        gap_count = int(
            connection.execute("SELECT COUNT(*) FROM inbound_transfer_gaps").fetchone()[0]
        )
        in_flight = int(
            connection.execute(
                "SELECT COUNT(*) FROM outgoing_transfers WHERE status = 'PREPARED'"
            ).fetchone()[0]
        )
        outbox = connection.execute(
            """
            SELECT COUNT(*), MIN(created_at_ns) FROM audit_outbox
            WHERE published_at_ns IS NULL
            """
        ).fetchone()
    unpublished = int(outbox[0])
    oldest = outbox[1]
    checked_at_ns = time.time_ns()
    result: dict[str, object] = {
        "checked_at_ns": checked_at_ns,
        "ready": service_ready,
        "service_ready": service_ready,
        "invariant_healthy": invariant.healthy,
        "resources": {
            "initial_share": list(invariant.initial_share),
            "transferred_in": list(invariant.transferred_in),
            "transferred_out": list(invariant.transferred_out),
            "free_pool": list(invariant.free_pool),
            "lease_residual": list(invariant.lease_residual),
            "consumed": list(invariant.consumed),
        },
        "leases": {
            "total": sum(int(row[1]) for row in lease_rows),
            "by_status": {str(row[0]): int(row[1]) for row in lease_rows},
        },
        "receipts": {"total": receipt_count},
        "authority_anchor": store.authority_anchor_status(),
        "storage_capacity": capacity.to_dict(),
        "transfers": {
            "outgoing_streams": int(outgoing[0]),
            "outgoing_acked_high_water": int(outgoing[1]),
            "outgoing_compacted_high_water": int(outgoing[2]),
            "incoming_streams": int(incoming[0]),
            "incoming_contiguous_high_water": int(incoming[1]),
            "incoming_compacted_high_water": int(incoming[2]),
            "inbound_gap_count": gap_count,
            "in_flight_count": in_flight,
        },
        "audit_outbox": {
            "unpublished_count": unpublished,
            "oldest_unpublished_age_ns": (
                0 if oldest is None else max(0, checked_at_ns - int(oldest))
            ),
        },
    }
    if peer_status is not None:
        result["peer_dispatcher"] = dict(peer_status())
    if audit_status is not None:
        status = dict(audit_status())
        result["audit_exporter"] = status
        result["ready"] = bool(result["ready"]) and status.get("healthy") is True
    return result


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_production_state_admission(config: Mapping[str, Any]) -> None:
    """Require durable production trust and capacity inputs for offline commands."""

    if config.get("allow_insecure_manifest") is not False:
        raise ValidationError("production requires a manifest admitted without insecure HTTP")
    for field in ("manifest", "manifest_digest", "operator_trust"):
        if field not in config:
            raise ValidationError("production requires an operator-signed cluster manifest")
    bootstrap = config.get("bootstrap_identities")
    if bootstrap not in (None, []):
        raise ValidationError("production rejects static bootstrap credentials")
    for field in ("min_free_disk_bytes", "max_database_bytes", "reserve_pages"):
        value = config.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > MAX_RESOURCE
        ):
            raise ValidationError(
                f"production requires an explicit positive {field} capacity setting"
            )


def _validate_production_admission(
    config: Mapping[str, Any],
    arguments: argparse.Namespace,
    *,
    provider_name: str,
    provider_options: Mapping[str, str] | None = None,
) -> None:
    """Reject development trust and transport choices before opening resources."""

    if provider_name == BUILTIN_RUNTIME_PROVIDER:
        raise ValidationError(
            "--production rejects the built-in file signer and static bearer authenticator"
        )
    if arguments.tls_cert is None or arguments.tls_key is None:
        raise ValidationError("--production requires --tls-cert and --tls-key")
    if arguments.client_ca is None:
        raise ValidationError("--production requires --client-ca for inbound mTLS")
    if arguments.allow_insecure_http or arguments.allow_insecure_peer_http:
        raise ValidationError("--production rejects insecure client or peer HTTP opt-ins")
    if not (
        MIN_PRODUCTION_PEER_REQUEST_TIMEOUT_SECONDS
        <= arguments.peer_request_timeout_seconds
        <= MAX_PEER_REQUEST_TIMEOUT_SECONDS
    ):
        raise ValidationError(
            "--production requires --peer-request-timeout-seconds between "
            f"{MIN_PRODUCTION_PEER_REQUEST_TIMEOUT_SECONDS} and "
            f"{MAX_PEER_REQUEST_TIMEOUT_SECONDS}"
        )
    _validate_production_state_admission(config)
    raw_peers = config.get("peer_endpoints", {})
    if not isinstance(raw_peers, Mapping):
        raise ValidationError("peer_endpoints must be an object")
    if raw_peers and (
        arguments.peer_ca is None or arguments.peer_cert is None or arguments.peer_key is None
    ):
        raise ValidationError(
            "--production peer endpoints require --peer-ca, --peer-cert, and --peer-key"
        )
    if raw_peers and provider_name == GENERIC_PRODUCTION_RUNTIME_PROVIDER:
        options = {} if provider_options is None else provider_options

        def provider_timeout(name: str) -> Decimal:
            raw = options.get(name)
            if raw is None:
                return Decimal(5)
            if not isinstance(raw, str):
                raise ValidationError(f"{name} must be a number")
            try:
                parsed = Decimal(raw)
            except (InvalidOperation, TypeError, ValueError) as exc:
                raise ValidationError(f"{name} must be a number") from exc
            if not parsed.is_finite() or not Decimal("0.05") <= parsed <= Decimal(30):
                raise ValidationError(f"{name} must be between 0.05 and 30 seconds")
            return parsed

        authority_timeout = provider_timeout("authority_timeout_s")
        signer_timeout = provider_timeout("signer_timeout_s")
        required_timeout = (
            _GENERIC_PROVIDER_AUTHORITY_CALLS_PER_PEER_REQUEST * authority_timeout
            + _GENERIC_PROVIDER_SIGNER_CALLS_PER_PEER_REQUEST * signer_timeout
            + _GENERIC_PROVIDER_SQLITE_WRITES_PER_PEER_REQUEST
            * _GENERIC_PROVIDER_SQLITE_ALLOWANCE_SECONDS
            + _GENERIC_PROVIDER_SCHEDULING_TLS_MARGIN_SECONDS
        )
        if Decimal(arguments.peer_request_timeout_seconds) < required_timeout:
            raise ValidationError(
                "--peer-request-timeout-seconds is below the generic-production provider "
                f"safety bound ({required_timeout:g} seconds)"
            )


def _serve_unlocked(config_path: Path, arguments: argparse.Namespace) -> int:
    if (arguments.tls_cert is None) != (arguments.tls_key is None):
        raise ValidationError("--tls-cert and --tls-key must be supplied together")
    if arguments.client_ca is not None and arguments.tls_cert is None:
        raise ValidationError("--client-ca requires --tls-cert and --tls-key")
    if (arguments.peer_cert is None) != (arguments.peer_key is None):
        raise ValidationError("--peer-cert and --peer-key must be supplied together")
    if (
        not _is_loopback(arguments.host)
        and arguments.tls_cert is None
        and not arguments.allow_insecure_http
    ):
        raise ValidationError(
            "non-loopback serving requires TLS or the explicit --allow-insecure-http flag"
        )
    for name in ("limit_concurrency", "timeout_keep_alive", "timeout_graceful_shutdown"):
        value = getattr(arguments, name)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3600:
            raise ValidationError(
                f"--{name.replace('_', '-')} must be an integer between 1 and 3600"
            )
    if (
        isinstance(arguments.request_body_timeout, bool)
        or not isinstance(arguments.request_body_timeout, int)
        or not 1 <= arguments.request_body_timeout <= 300
    ):
        raise ValidationError("--request-body-timeout must be an integer between 1 and 300")
    if (
        isinstance(arguments.peer_request_timeout_seconds, bool)
        or not isinstance(arguments.peer_request_timeout_seconds, int)
        or not 1 <= arguments.peer_request_timeout_seconds <= MAX_PEER_REQUEST_TIMEOUT_SECONDS
    ):
        raise ValidationError(
            "--peer-request-timeout-seconds must be an integer between 1 and "
            f"{MAX_PEER_REQUEST_TIMEOUT_SECONDS}"
        )
    if (
        isinstance(arguments.backlog, bool)
        or not isinstance(arguments.backlog, int)
        or not 1 <= arguments.backlog <= 65_535
    ):
        raise ValidationError("--backlog must be an integer between 1 and 65535")

    resolved, config = _load_config(config_path)
    _require_no_incomplete_restore(resolved)
    provider_name, provider_options = _runtime_configuration(config, arguments)
    if arguments.production:
        _validate_production_admission(
            config,
            arguments,
            provider_name=provider_name,
            provider_options=provider_options,
        )
        _require_production_sqlite()
    try:
        import uvicorn
    except ImportError as exc:
        raise ValidationError("install the project-local 'server' extra to use lets serve") from exc

    from lets.api import create_app
    from lets.audit import AuditExporter
    from lets.auth import PeerMessageAuthenticator
    from lets.peer import PeerDispatcher

    configured_insecure = config.get("allow_insecure_manifest", False)
    if not isinstance(configured_insecure, bool):
        raise ValidationError("allow_insecure_manifest must be a boolean")
    peer_endpoints = _configured_peer_endpoints(
        config,
        allow_insecure_http=arguments.allow_insecure_peer_http or configured_insecure,
    )
    ssl_certfile = None if arguments.tls_cert is None else str(arguments.tls_cert.resolve())
    ssl_keyfile = None if arguments.tls_key is None else str(arguments.tls_key.resolve())
    ssl_ca_certs = None if arguments.client_ca is None else str(arguments.client_ca.resolve())
    ssl_cert_reqs = ssl.CERT_REQUIRED if arguments.client_ca is not None else ssl.CERT_NONE

    with _open_runtime(
        resolved,
        config,
        arguments,
        production=arguments.production,
    ) as runtime:
        signer = runtime.signer
        clock = SystemClock(
            declared_uncertainty_ns=int(config.get("max_clock_uncertainty_ns", 50_000_000))
        )
        registry = _manifest_trust_registry(config, signer, clock=clock)
        _validate_peer_trust(
            peer_endpoints,
            registry,
            local_warden_id=signer.warden_id,
        )
        store = _storage(
            resolved,
            config,
            signer=signer,
            authority_anchor=runtime.authority_anchor,
        )
        try:
            # Deep scans are a one-time admission gate. Request-path readiness remains bounded.
            integrity = store.pragma_integrity_check()
            foreign_keys = store.pragma_foreign_key_check()
            if integrity != ("ok",) or foreign_keys:
                raise StorageError(
                    "startup database diagnostics failed: "
                    f"integrity={integrity!r}, foreign_key_violations={len(foreign_keys)}"
                )
            service = WardenService(
                store,
                signer=signer,
                clock=clock,
                trust_registry=registry,
                signing_key_validity=registry.key_validity(signer.warden_id, signer.key_id),
                allowed_peer_wardens=frozenset(peer_endpoints),
            )
            peer_verify: bool | str = (
                True if arguments.peer_ca is None else str(arguments.peer_ca.resolve())
            )
            peer_cert: str | tuple[str, str] | None = (
                None
                if arguments.peer_cert is None
                else (
                    str(arguments.peer_cert.resolve()),
                    str(arguments.peer_key.resolve()),
                )
            )
            dispatcher = PeerDispatcher(
                service,
                store,
                cast(Ed25519Signer, signer),
                peer_endpoints,
                verify=peer_verify,
                cert=peer_cert,
                request_timeout_s=float(arguments.peer_request_timeout_seconds),
            )
            audit_exporter = (
                None if runtime.audit_sink is None else AuditExporter(store, runtime.audit_sink)
            )
            peer_authenticator = PeerMessageAuthenticator(registry, CorePeerReplayStore(service))
            metrics_identity = IdentityContext(
                subject_id=signer.warden_id,
                tenant_id=_required_text(config, "tenant_id"),
                scopes=frozenset({"lets.admin", "lets.metrics.read"}),
                authentication_method="local-metrics",
            )

            def ready() -> bool:
                try:
                    if not service.ready():
                        return False
                    if audit_exporter is None:
                        return True
                    audit_state = audit_exporter.status()
                    return audit_state.get("healthy") is True
                except (LETSError, sqlite3.Error):
                    return False

            def metrics_snapshot() -> dict[str, object]:
                return _metrics_provider(
                    service,
                    store,
                    metrics_identity,
                    peer_status=dispatcher.status,
                    audit_status=(None if audit_exporter is None else audit_exporter.status),
                )

            def fence_authority(restart_id: str, expected_lifetime_id: str) -> dict[str, object]:
                return store.fence_authority_admission(
                    restart_id=restart_id,
                    expected_lifetime_id=expected_lifetime_id,
                )

            def authority_status() -> dict[str, object]:
                return store.authority_anchor_status()

            app = create_app(
                service,
                authenticator=runtime.authenticator,
                signer=signer,
                peer_authenticator=peer_authenticator,
                peer_tenant_id=_required_text(config, "tenant_id"),
                readiness_check=ready,
                metrics_provider=metrics_snapshot,
                authority_fence_provider=fence_authority,
                authority_status_provider=authority_status,
                node_metadata={
                    "tenant_id": _required_text(config, "tenant_id"),
                    "envelope_id": _required_text(config, "envelope_id"),
                    "config_epoch": int(config.get("config_epoch", 1)),
                    "manifest_digest": config.get("manifest_digest"),
                    "runtime_provider": runtime.provider_name,
                    "sqlite_version": sqlite3.sqlite_version,
                },
                request_body_timeout_s=float(arguments.request_body_timeout),
            )
            dispatcher.start()
            try:
                if audit_exporter is not None:
                    audit_exporter.start()
                uvicorn.run(
                    app,
                    host=arguments.host,
                    port=arguments.port,
                    log_level=arguments.log_level,
                    ssl_certfile=ssl_certfile,
                    ssl_keyfile=ssl_keyfile,
                    ssl_ca_certs=ssl_ca_certs,
                    ssl_cert_reqs=ssl_cert_reqs,
                    limit_concurrency=arguments.limit_concurrency,
                    backlog=arguments.backlog,
                    timeout_keep_alive=arguments.timeout_keep_alive,
                    timeout_graceful_shutdown=arguments.timeout_graceful_shutdown,
                )
            finally:
                try:
                    if audit_exporter is not None:
                        audit_exporter.stop()
                finally:
                    dispatcher.stop()
        finally:
            store.close()
    return 0


def _serve(config_path: Path, arguments: argparse.Namespace) -> int:
    """Hold the node process lock for the complete server lifetime."""

    # Preserve deterministic argument errors without creating a lock directory
    # for a missing configuration path.
    if (arguments.tls_cert is None) != (arguments.tls_key is None):
        raise ValidationError("--tls-cert and --tls-key must be supplied together")
    if arguments.client_ca is not None and arguments.tls_cert is None:
        raise ValidationError("--client-ca requires --tls-cert and --tls-key")
    if (arguments.peer_cert is None) != (arguments.peer_key is None):
        raise ValidationError("--peer-cert and --peer-key must be supplied together")
    if (
        not _is_loopback(arguments.host)
        and arguments.tls_cert is None
        and not arguments.allow_insecure_http
    ):
        raise ValidationError(
            "non-loopback serving requires TLS or the explicit --allow-insecure-http flag"
        )
    resolved = config_path.resolve()
    if not resolved.exists():
        return _serve_unlocked(config_path, arguments)
    with node_process_lock(resolved.parent / ".node.lock"):
        return _serve_unlocked(config_path, arguments)


def _fail(error: Exception) -> NoReturn:
    print(f"lets: {error}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "init":
            return _initialize(arguments.config, arguments)
        if arguments.command == "serve":
            return _serve(arguments.config, arguments)
        if arguments.command == "key":
            return _key(arguments.config, arguments)
        if arguments.command == "info":
            return _info(arguments.config, arguments)
        if arguments.command == "backup":
            return _backup(arguments.config, arguments.output, arguments)
        if arguments.command == "status":
            return _runtime_control(arguments.config, arguments, None)
        if arguments.command == "drain":
            return _runtime_control(arguments.config, arguments, RuntimeMode.DRAINING)
        if arguments.command == "activate":
            return _runtime_control(arguments.config, arguments, RuntimeMode.ACTIVE)
        if arguments.command == "recovery":
            if arguments.recovery_command == "backup":
                return _recovery_backup(arguments.config, arguments)
            if arguments.recovery_command == "verify":
                return _recovery_verify(arguments.config, arguments)
            if arguments.recovery_command == "restore":
                return _recovery_restore(arguments.config, arguments)
        if arguments.command == "migrate":
            return _migrate(arguments.config, arguments)
        parser.error(f"unknown command: {arguments.command}")
    except (LETSError, OSError, ValueError) as error:
        _fail(error)
    return 2


if __name__ == "__main__":  # pragma: no cover - installed script is the normal entry point
    raise SystemExit(main())
