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
from contextlib import suppress
from hashlib import sha256
from pathlib import Path
from typing import Any, NoReturn, cast

from lets.auth import SQLitePeerReplayStore, StaticBearerAuthenticator
from lets.authority import AuthorityAnchor
from lets.canonical import b64url_decode, b64url_encode, strict_json_loads
from lets.clock import Clock, SystemClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import LETSError, SignatureError, StorageError, ValidationError
from lets.ids import require_warden_id
from lets.manifest import validate_endpoint_origin
from lets.models import IdentityContext
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
from lets.vector import MAX_RESOURCE

CONFIG_VERSION = 1
DEFAULT_CONFIG = Path(".lets/config.json")


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
        help="maximum database plus WAL/SHM bytes; production requires a positive value",
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
    serve.add_argument("--log-level", default="info")
    _add_runtime_arguments(serve)

    key = commands.add_parser("key", help="print this node's public signing key")
    _add_runtime_arguments(key)
    info = commands.add_parser("info", help="inspect local node identity and database health")
    _add_runtime_arguments(info)
    backup = commands.add_parser("backup", help="create a verified consistent SQLite backup")
    backup.add_argument("--output", type=Path, required=True)
    _add_runtime_arguments(backup)
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


def _initialize(config_path: Path, arguments: argparse.Namespace) -> int:
    resolved = config_path.resolve()
    if resolved.exists():
        raise ValidationError(f"configuration already exists: {resolved}")
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
        if arguments.signing_seed_file is None:
            raise ValidationError("--signing-seed-file is required with --manifest")
        signer = Ed25519Signer.load_seed_file(
            arguments.warden_id,
            arguments.signing_seed_file,
        )
        if not any(
            key.key_id == signer.key_id and key.public_key == signer.public_key_bytes
            for key in local.keys
        ):
            raise ValidationError("local signing seed does not match a manifest warden key")
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
        try:
            manifest_registry.require_current(signer.warden_id, signer.key_id)
            for warden in manifest.wardens:
                if warden.warden_id != signer.warden_id:
                    manifest_registry.require_current_warden(warden.warden_id)
        except SignatureError as exc:
            raise ValidationError(
                "manifest initialization requires current local and peer signing keys"
            ) from exc
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
        signer = (
            Ed25519Signer.generate(arguments.warden_id)
            if arguments.signing_seed_file is None
            else Ed25519Signer.load_seed_file(
                arguments.warden_id,
                arguments.signing_seed_file,
            )
        )
    if len(local_share) != len(budget):
        raise ValidationError("local_share must have the same dimensions as budget")
    if any(local > total for local, total in zip(local_share, budget, strict=True)):
        raise ValidationError("local_share cannot exceed budget")

    token = arguments.bootstrap_token or secrets.token_urlsafe(32)
    if len(token) < 24:
        raise ValidationError("bootstrap token must contain at least 24 characters")
    subject = arguments.bootstrap_subject or arguments.warden_id
    directory = resolved.parent
    directory.mkdir(parents=True, exist_ok=True)
    key_path = directory / "warden.ed25519"
    database_path = directory / "warden.sqlite3"
    replay_path = directory / "peer-replay.sqlite3"
    partial_artifacts = [
        candidate for candidate in (key_path, database_path, replay_path) if candidate.exists()
    ]
    if partial_artifacts:
        rendered = ", ".join(str(candidate) for candidate in partial_artifacts)
        raise ValidationError(
            "partial LETS initialization artifacts already exist and will not be overwritten: "
            f"{rendered}. Inspect, recover, or move those exact files before retrying init."
        )
    signer.save_seed_file(key_path)
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
        min_free_disk_bytes=arguments.min_free_disk_bytes,
        max_database_bytes=arguments.max_database_bytes,
        reserve_pages=arguments.reserve_pages,
    )
    policy_digests: list[str] = []
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
    store.close()
    SQLitePeerReplayStore.initialize(replay_path)
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
        "signing_key": key_path.name,
        "replay_database": replay_path.name,
        "runtime": {"provider": BUILTIN_RUNTIME_PROVIDER, "options": {}},
        "bootstrap_identities": [
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
        ],
        "trusted_peers": trusted_peers,
    }
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
    print(
        json.dumps(
            {
                "config": str(resolved),
                "warden_id": arguments.warden_id,
                "key_id": signer.key_id,
                "bootstrap_token": token,
                "warning": "Store the bootstrap token securely; only its SHA-256 digest was saved.",
            },
            indent=2,
        )
    )
    return 0


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
        (
            _local_path(config_path, config, "database")
            if database_override is None
            else database_override
        ),
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


def _info(config_path: Path, arguments: argparse.Namespace | None = None) -> int:
    resolved, config = _load_config(config_path)
    with _open_runtime(resolved, config, arguments) as runtime:
        signer = runtime.signer
        store = _storage(
            resolved,
            config,
            signer=signer,
            authority_anchor=runtime.authority_anchor,
        )
        try:
            integrity = store.pragma_integrity_check()
            foreign_keys = store.pragma_foreign_key_check()
            capacity = store.capacity_snapshot()
            document = {
                "config": str(resolved),
                "warden_id": signer.warden_id,
                "key_id": signer.key_id,
                "tenant_id": store.metadata.tenant_id,
                "envelope_id": store.metadata.envelope_id,
                "config_epoch": store.metadata.config_epoch,
                "schema_version": store.schema_version,
                "database": store.path,
                "database_integrity": list(integrity),
                "foreign_key_violations": len(foreign_keys),
                "storage_capacity": capacity.to_dict(),
                "runtime_provider": runtime.provider_name,
                "ready": integrity == ("ok",) and not foreign_keys and capacity.healthy,
            }
            if "manifest_digest" in config:
                document["manifest_digest"] = config["manifest_digest"]
        finally:
            store.close()
    print(json.dumps(document, indent=2))
    return 0 if document["ready"] else 1


def _backup(
    config_path: Path,
    output: Path,
    arguments: argparse.Namespace | None = None,
) -> int:
    resolved, config = _load_config(config_path)
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
        "ready": service.ready(),
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
        result["ready"] = (
            bool(result["ready"])
            and status.get("running") is True
            and status.get("last_error") is None
        )
    return result


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_production_admission(
    config: Mapping[str, Any],
    arguments: argparse.Namespace,
    *,
    provider_name: str,
) -> None:
    """Reject development trust and transport choices before opening resources."""

    if provider_name == BUILTIN_RUNTIME_PROVIDER:
        raise ValidationError(
            "--production rejects the built-in file signer and static bearer authenticator"
        )
    if arguments.tls_cert is None or arguments.tls_key is None:
        raise ValidationError("--production requires --tls-cert and --tls-key")
    if arguments.allow_insecure_http or arguments.allow_insecure_peer_http:
        raise ValidationError("--production rejects insecure client or peer HTTP opt-ins")
    if config.get("allow_insecure_manifest") is not False:
        raise ValidationError("--production requires a manifest admitted without insecure HTTP")
    for field in ("manifest", "manifest_digest", "operator_trust"):
        if field not in config:
            raise ValidationError("--production requires an operator-signed cluster manifest")
    bootstrap = config.get("bootstrap_identities")
    if bootstrap not in (None, []):
        raise ValidationError("--production rejects static bootstrap credentials")
    for field in ("min_free_disk_bytes", "max_database_bytes", "reserve_pages"):
        value = config.get(field)
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value <= 0
            or value > MAX_RESOURCE
        ):
            raise ValidationError(
                f"--production requires an explicit positive {field} capacity setting"
            )


def _serve(config_path: Path, arguments: argparse.Namespace) -> int:
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

    resolved, config = _load_config(config_path)
    provider_name, _ = _runtime_configuration(config, arguments)
    if arguments.production:
        _validate_production_admission(
            config,
            arguments,
            provider_name=provider_name,
        )
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
            replay = SQLitePeerReplayStore(_local_path(resolved, config, "replay_database"))
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
            )
            audit_exporter = (
                None if runtime.audit_sink is None else AuditExporter(store, runtime.audit_sink)
            )
            peer_authenticator = PeerMessageAuthenticator(registry, replay)
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
                    return audit_state["running"] is True and audit_state["last_error"] is None
                except (LETSError, sqlite3.Error):
                    return False

            app = create_app(
                service,
                authenticator=runtime.authenticator,
                signer=signer,
                peer_authenticator=peer_authenticator,
                peer_tenant_id=_required_text(config, "tenant_id"),
                readiness_check=ready,
                metrics_provider=lambda: _metrics_provider(
                    service,
                    store,
                    metrics_identity,
                    peer_status=dispatcher.status,
                    audit_status=(None if audit_exporter is None else audit_exporter.status),
                ),
                node_metadata={
                    "tenant_id": _required_text(config, "tenant_id"),
                    "envelope_id": _required_text(config, "envelope_id"),
                    "config_epoch": int(config.get("config_epoch", 1)),
                    "manifest_digest": config.get("manifest_digest"),
                    "runtime_provider": runtime.provider_name,
                },
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
        parser.error(f"unknown command: {arguments.command}")
    except (LETSError, OSError, ValueError) as error:
        _fail(error)
    return 2


if __name__ == "__main__":  # pragma: no cover - installed script is the normal entry point
    raise SystemExit(main())
