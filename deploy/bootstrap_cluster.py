"""One-shot, idempotent bootstrap for the three-node acceptance cluster."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

from lets.canonical import b64url_encode, canonical_json, strict_json_loads
from lets.crypto import Ed25519Signer
from lets.manifest import (
    API_VERSION,
    ClusterManifest,
    ManifestPublicKey,
    ManifestSignature,
    WardenManifest,
)
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec

TENANT_ID = "acceptance-tenant"
ENVELOPE_ID = "acceptance-envelope"
CONFIG_EPOCH = 1
INITIAL_BUDGET = (300,)
RECEIPT_TTL_NS = 60_000_000_000
MAX_CLOCK_UNCERTAINTY_NS = 1_000_000_000
TRANSFER_GAP_WINDOW = 8
NODES = (
    ("warden-a", (150,), "http://toxiproxy:8667", "http://warden-a:8080"),
    ("warden-b", (100,), "http://toxiproxy:8666", "http://warden-b:8080"),
    ("warden-c", (50,), "http://warden-c:8080", "http://warden-c:8080"),
)


def acceptance_policy() -> PolicySpec:
    """Return the immutable policy loaded by every acceptance warden."""

    dimension = ResourceDimension(
        "operations",
        "count",
        "Finite authorization operations available to this cluster.",
    )
    return PolicySpec(
        policy_id="acceptance-policy",
        policy_version="v1",
        dimensions=(dimension,),
        machine=MachineSpec(
            machine_id="acceptance-worker",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    name="act",
                    source="ready",
                    target="ready",
                    cost=(1,),
                    capability="worker.act",
                ),
            ),
        ),
        max_lease_ttl_ns=600_000_000_000,
        receipt_ttl_ns=RECEIPT_TTL_NS,
        max_clock_uncertainty_ns=MAX_CLOCK_UNCERTAINTY_NS,
        transfer_gap_window=TRANSFER_GAP_WINDOW,
    )


def _load_json(path: Path) -> dict[str, Any]:
    decoded = strict_json_loads(path.read_bytes())
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{path} does not contain a JSON object")
    return decoded


def _atomic_json(path: Path, value: object, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _atomic_bytes(path: Path, value: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _initialize_node(
    warden_id: str,
    share: tuple[int, ...],
    token: str,
    *,
    manifest: ClusterManifest,
    operator: Ed25519Signer,
    seed_path: Path,
) -> tuple[Path, dict[str, Any], Ed25519Signer]:
    state = Path("/nodes") / warden_id
    config_path = state / "config.json"
    if not config_path.exists():
        command = [
            "lets",
            "--config",
            str(config_path),
            "init",
            "--warden-id",
            warden_id,
            "--manifest",
            "/cluster/manifest.json",
            "--operator-key",
            f"{operator.key_id}={b64url_encode(operator.public_key_bytes)}",
            "--operator-threshold",
            "1",
            "--allow-insecure-manifest",
            "--signing-seed-file",
            str(seed_path),
            "--bootstrap-subject",
            warden_id,
            "--bootstrap-token",
            token,
        ]
        subprocess.run(command, check=True, capture_output=True, text=True)
    config = _load_json(config_path)
    expected = {
        "warden_id": warden_id,
        "tenant_id": TENANT_ID,
        "envelope_id": ENVELOPE_ID,
        "config_epoch": CONFIG_EPOCH,
        "budget": list(INITIAL_BUDGET),
        "local_share": list(share),
        "receipt_ttl_ns": RECEIPT_TTL_NS,
        "max_clock_uncertainty_ns": MAX_CLOCK_UNCERTAINTY_NS,
        "transfer_gap_window": TRANSFER_GAP_WINDOW,
        "manifest_digest": manifest.digest,
        "manifest_policy_digests": [policy.digest for policy in manifest.policies],
    }
    mismatches = {
        name: (config.get(name), value)
        for name, value in expected.items()
        if config.get(name) != value
    }
    if mismatches:
        raise RuntimeError(f"refusing mismatched persisted node configuration: {mismatches}")
    identities = config.get("bootstrap_identities")
    if not isinstance(identities, list) or len(identities) != 1:
        raise RuntimeError(f"{warden_id} bootstrap identity is missing or ambiguous")
    if identities[0].get("token_sha256") != sha256(token.encode()).hexdigest():
        raise RuntimeError(f"persisted token digest for {warden_id} does not match the secret")
    signer = Ed25519Signer.load_seed_file(warden_id, state / "warden.ed25519")
    return config_path, config, signer


def _operator_signer() -> Ed25519Signer:
    seed_path = Path("/operator/operator.ed25519")
    if not seed_path.exists():
        _atomic_bytes(seed_path, secrets.token_bytes(32), mode=0o600)
    return Ed25519Signer.load_seed_file("cluster-operator", seed_path)


def _warden_signers() -> dict[str, tuple[Path, Ed25519Signer]]:
    result: dict[str, tuple[Path, Ed25519Signer]] = {}
    for warden_id, _share, _peer_endpoint, _client_endpoint in NODES:
        seed_path = Path("/operator") / "warden-seeds" / f"{warden_id}.ed25519"
        if not seed_path.exists():
            _atomic_bytes(seed_path, secrets.token_bytes(32), mode=0o600)
        result[warden_id] = (
            seed_path,
            Ed25519Signer.load_seed_file(warden_id, seed_path),
        )
    return result


def _signed_manifest(
    operator: Ed25519Signer,
    signers: dict[str, tuple[Path, Ed25519Signer]],
) -> ClusterManifest:
    policy = acceptance_policy()
    created_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    existing_manifest = Path("/cluster/manifest.json")
    if existing_manifest.exists():
        prior = _load_json(existing_manifest)
        prior_created_at = prior.get("created_at")
        if isinstance(prior_created_at, str):
            created_at = prior_created_at
    unsigned = ClusterManifest(
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        config_epoch=CONFIG_EPOCH,
        created_at=created_at,
        resources=policy.dimensions,
        initial_budget=INITIAL_BUDGET,
        wardens=tuple(
            WardenManifest(
                warden_id=warden_id,
                peer_endpoint=peer_endpoint,
                client_endpoint=client_endpoint,
                initial_share=share,
                keys=(
                    ManifestPublicKey(
                        key_id=signers[warden_id][1].key_id,
                        public_key=signers[warden_id][1].public_key_bytes,
                    ),
                ),
                extensions={},
            )
            for warden_id, share, peer_endpoint, client_endpoint in NODES
        ),
        policies=(policy,),
        extensions={
            "org.astraldeep.lets/purpose": "LETS real multi-process acceptance cluster",
            "org.astraldeep.lets/transport_security": (
                "Ed25519 message signatures over isolated Docker network"
            ),
        },
    )
    signature = ManifestSignature(
        key_id=operator.key_id,
        signature=operator.sign(canonical_json(unsigned.unsigned_dict())),
    )
    return ClusterManifest(
        tenant_id=unsigned.tenant_id,
        envelope_id=unsigned.envelope_id,
        config_epoch=unsigned.config_epoch,
        created_at=unsigned.created_at,
        resources=unsigned.resources,
        initial_budget=unsigned.initial_budget,
        wardens=unsigned.wardens,
        policies=unsigned.policies,
        extensions=unsigned.extensions,
        signatures=(signature,),
    )


def _chown_tree(path: Path, uid: int, gid: int) -> None:
    candidate = os.__dict__.get("chown")
    if not callable(candidate):
        raise RuntimeError("cluster bootstrap requires POSIX ownership support")
    chown = cast(Callable[..., None], candidate)
    for child in path.rglob("*"):
        chown(child, uid, gid, follow_symlinks=False)
    chown(path, uid, gid, follow_symlinks=False)


def main() -> int:
    token = os.environ.get("LETS_BOOTSTRAP_TOKEN", "")
    if len(token) < 24:
        raise RuntimeError("LETS_BOOTSTRAP_TOKEN must contain at least 24 characters")

    operator = _operator_signer()
    seed_signers = _warden_signers()
    manifest = _signed_manifest(operator, seed_signers)
    policy = acceptance_policy()
    _atomic_json(Path("/cluster/manifest.json"), manifest.to_dict())
    _atomic_json(
        Path("/cluster/operator.json"),
        {
            "api_version": API_VERSION,
            "key_id": operator.key_id,
            "algorithm": "Ed25519",
            "public_key": b64url_encode(operator.public_key_bytes),
            "threshold": 1,
        },
    )
    initialized = [
        (
            *node,
            *_initialize_node(
                node[0],
                node[1],
                token,
                manifest=manifest,
                operator=operator,
                seed_path=seed_signers[node[0]][0],
            ),
        )
        for node in NODES
    ]
    signers = {entry[0]: entry[6] for entry in initialized}
    for (
        warden_id,
        _share,
        _peer_endpoint,
        _client_endpoint,
        _config_path,
        config,
        signer,
    ) in initialized:
        if signer.public_key_bytes != seed_signers[warden_id][1].public_key_bytes:
            raise RuntimeError(f"initialized key for {warden_id} changed during bootstrap")
        trusted = config.get("trusted_peers")
        if not isinstance(trusted, list) or len(trusted) != len(NODES) - 1:
            raise RuntimeError(f"manifest peer trust for {warden_id} is incomplete")
    _atomic_json(
        Path("/cluster/bootstrap-report.json"),
        {
            "manifest_digest": manifest.digest,
            "policy_digest": policy.digest,
            "initial_budget": list(INITIAL_BUDGET),
            "shares": {warden_id: list(share) for warden_id, share, _, _ in NODES},
            "warden_keys": {warden_id: signer.key_id for warden_id, signer in signers.items()},
        },
    )
    for warden_id, _share, _peer_endpoint, _client_endpoint in NODES:
        _chown_tree(Path("/nodes") / warden_id, 10001, 10001)
    print(
        json.dumps(
            {
                "status": "bootstrapped",
                "manifest_digest": manifest.digest,
                "policy_digest": policy.digest,
                "wardens": list(signers),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
