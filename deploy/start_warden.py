"""Verify signed cluster configuration, register policies, and exec one warden."""

from __future__ import annotations

import argparse
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from lets.canonical import b64url_decode, strict_json_loads
from lets.clock import SystemClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.manifest import ClusterManifest
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _json_object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return cast(dict[str, Any], value)


def _text(config: Mapping[str, Any], field: str) -> str:
    value = config.get(field)
    if not isinstance(value, str) or not value:
        raise RuntimeError(f"node configuration field {field!r} is invalid")
    return value


def _local_path(config_path: Path, config: Mapping[str, Any], field: str) -> Path:
    base = config_path.parent.resolve()
    candidate = Path(_text(config, field))
    if candidate.is_absolute():
        raise RuntimeError(f"node configuration path {field!r} must be relative")
    resolved = (base / candidate).resolve()
    if not resolved.is_relative_to(base):
        raise RuntimeError(f"node configuration path {field!r} escapes its state directory")
    return resolved


def _vector(config: Mapping[str, Any], field: str) -> tuple[int, ...]:
    value = config.get(field)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise RuntimeError(f"node configuration field {field!r} is not a vector")
    if any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value):
        raise RuntimeError(f"node configuration field {field!r} is not non-negative")
    return tuple(cast(Sequence[int], value))


def _verify_manifest(
    config_path: Path,
    config: Mapping[str, Any],
    manifest_path: Path,
    operator_path: Path,
) -> tuple[ClusterManifest, Ed25519Signer, PublicKeyRegistry]:
    manifest = ClusterManifest.load(manifest_path, allow_insecure_http=True)
    operator = _json_object(operator_path)
    key_id = _text(operator, "key_id")
    public_key = b64url_decode(_text(operator, "public_key"))
    threshold = operator.get("threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, int):
        raise RuntimeError("operator trust threshold must be an integer")
    manifest.verify_signatures({key_id: public_key}, threshold=threshold)

    warden_id = _text(config, "warden_id")
    local = manifest.warden(warden_id)
    signer = Ed25519Signer.load_seed_file(
        warden_id,
        _local_path(config_path, config, "signing_key"),
    )
    if not any(
        key.key_id == signer.key_id and key.public_key == signer.public_key_bytes
        for key in local.keys
    ):
        raise RuntimeError("local private signing key is not authorized by the manifest")
    comparisons: dict[str, tuple[object, object]] = {
        "tenant_id": (config.get("tenant_id"), manifest.tenant_id),
        "envelope_id": (config.get("envelope_id"), manifest.envelope_id),
        "config_epoch": (config.get("config_epoch"), manifest.config_epoch),
        "budget": (_vector(config, "budget"), manifest.initial_budget),
        "local_share": (_vector(config, "local_share"), local.initial_share),
        "manifest_digest": (config.get("manifest_digest"), manifest.digest),
    }
    mismatches = {field: values for field, values in comparisons.items() if values[0] != values[1]}
    if mismatches:
        raise RuntimeError(f"signed manifest does not match local state: {mismatches}")

    clock = SystemClock(declared_uncertainty_ns=int(config["max_clock_uncertainty_ns"]))
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
    expected_peers = {
        (warden.warden_id, key.key_id, b64url_decode(key.to_dict()["public_key"]))
        for warden in manifest.wardens
        if warden.warden_id != warden_id
        for key in warden.keys
    }
    raw_peers = config.get("trusted_peers")
    if not isinstance(raw_peers, Sequence) or isinstance(raw_peers, (str, bytes)):
        raise RuntimeError("trusted_peers must be an array")
    configured_peers: set[tuple[str, str, bytes]] = set()
    for peer in raw_peers:
        if not isinstance(peer, Mapping):
            raise RuntimeError("trusted peer entries must be objects")
        peer_warden = _text(peer, "warden_id")
        peer_key = _text(peer, "key_id")
        peer_public = b64url_decode(_text(peer, "public_key"))
        configured_peers.add((peer_warden, peer_key, peer_public))
    if configured_peers != expected_peers:
        raise RuntimeError("configured peer trust does not exactly match the signed manifest")
    return manifest, signer, registry


def _register_manifest_policies(
    config_path: Path,
    config: Mapping[str, Any],
    manifest: ClusterManifest,
    signer: Ed25519Signer,
    registry: PublicKeyRegistry,
) -> None:
    store = SQLiteStorage(
        _local_path(config_path, config, "database"),
        signer.warden_id,
        _vector(config, "budget"),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=_text(config, "tenant_id"),
        envelope_id=_text(config, "envelope_id"),
        config_epoch=int(config["config_epoch"]),
        dimension_metadata=config.get("dimension_metadata"),
        initial_local_share=_vector(config, "local_share"),
        receipt_ttl_ns=int(config["receipt_ttl_ns"]),
        max_clock_uncertainty_ns=int(config["max_clock_uncertainty_ns"]),
        transfer_gap_window=int(config["transfer_gap_window"]),
        config={"manifest_digest": manifest.digest},
    )
    try:
        clock = SystemClock(declared_uncertainty_ns=int(config["max_clock_uncertainty_ns"]))
        service = WardenService(
            store,
            signer=signer,
            clock=clock,
            trust_registry=registry,
            signing_key_validity=registry.key_validity(signer.warden_id, signer.key_id),
        )
        registered = tuple(service.register_policy(policy) for policy in manifest.policies)
        expected = tuple(policy.digest for policy in manifest.policies)
        if registered != expected:
            raise RuntimeError("registered policy digests do not match the signed manifest")
    finally:
        store.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    arguments = parser.parse_args()
    config_path = arguments.config.resolve()
    config = _json_object(config_path)
    manifest_path = Path(os.environ.get("LETS_MANIFEST", "/cluster/manifest.json"))
    operator_path = Path(os.environ.get("LETS_OPERATOR_TRUST", "/cluster/operator.json"))
    manifest, signer, registry = _verify_manifest(
        config_path,
        config,
        manifest_path,
        operator_path,
    )
    _register_manifest_policies(config_path, config, manifest, signer, registry)
    os.execvp(
        "lets",
        [
            "lets",
            "--config",
            str(config_path),
            "serve",
            "--host",
            "0.0.0.0",
            "--port",
            "8080",
            "--allow-insecure-http",
            "--log-level",
            "warning",
        ],
    )
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
