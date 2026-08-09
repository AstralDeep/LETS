"""Create ephemeral PKI, trust, JWT, and external-signer acceptance material."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from nacl.signing import SigningKey

from lets.canonical import b64url_encode, canonical_json
from lets.crypto import Ed25519Signer
from lets.manifest import (
    ClusterManifest,
    ManifestPublicKey,
    ManifestSignature,
    WardenManifest,
)
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec

TENANT_ID = "production-acceptance-tenant"
ENVELOPE_ID = "production-acceptance-envelope"
IDENTITY_ISSUER = "https://identity.production-acceptance"
IDENTITY_AUDIENCE = "lets-production-acceptance"
INITIAL_BUDGET = (300,)
NODES = (
    ("warden-a", (100,), "https://toxiproxy:8667", "https://warden-a:8443"),
    ("warden-b", (100,), "https://toxiproxy:8666", "https://warden-b:8443"),
    ("warden-c", (100,), "https://warden-c:8443", "https://warden-c:8443"),
)
ROOT = Path("/materials")
TRUST = ROOT / "trust"
CLIENT = ROOT / "client"
SOURCE_HELPER = Path("/app/deploy/production/acceptance/signer_helper.py")


def acceptance_policy() -> PolicySpec:
    dimension = ResourceDimension(
        "operations",
        "count",
        "Finite authorization operations available to the production-profile cluster.",
    )
    return PolicySpec(
        policy_id="production-acceptance-policy",
        policy_version="v1",
        dimensions=(dimension,),
        machine=MachineSpec(
            machine_id="production-acceptance-worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), "worker.act"),),
        ),
        max_lease_ttl_ns=600_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=1_000_000_000,
        transfer_gap_window=8,
    )


def _json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _run(*arguments: str) -> None:
    result = subprocess.run(arguments, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"command failed: {arguments[0]}: {result.stderr.strip()}")


def _require_empty(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if any(path.iterdir()):
        raise RuntimeError(f"refusing to overwrite non-empty acceptance material: {path}")


def _certificate(
    work: Path,
    *,
    name: str,
    common_name: str,
    ca_certificate: Path,
    ca_key: Path,
    serial: int,
    usage: str,
    san: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    key = work / f"{name}.key"
    request = work / f"{name}.csr"
    certificate = work / f"{name}.pem"
    extensions = work / f"{name}.ext"
    extension_lines = ["basicConstraints=critical,CA:FALSE", "keyUsage=critical,digitalSignature"]
    if usage == "serverAuth":
        extension_lines[1] += ",keyEncipherment"
    extension_lines.append(f"extendedKeyUsage={usage}")
    if san:
        extension_lines.append("subjectAltName=" + ",".join(san))
    extensions.write_text("\n".join(extension_lines) + "\n", encoding="ascii")
    _run(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(request),
        "-subj",
        f"/CN={common_name}",
    )
    _run(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(request),
        "-CA",
        str(ca_certificate),
        "-CAkey",
        str(ca_key),
        "-set_serial",
        str(serial),
        "-days",
        "2",
        "-sha256",
        "-extfile",
        str(extensions),
        "-out",
        str(certificate),
    )
    return certificate, key


def _ca(work: Path, name: str) -> tuple[Path, Path]:
    key = work / f"{name}.key"
    certificate = work / f"{name}.pem"
    _run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        str(key),
        "-out",
        str(certificate),
        "-days",
        "2",
        "-sha256",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-subj",
        f"/CN=LETS {name}",
    )
    return certificate, key


def _copy(source: Path, destination: Path, mode: int) -> None:
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def _protect_tree(path: Path, *, owner: int = 10001) -> None:
    candidate = os.__dict__.get("chown")
    if not callable(candidate):
        raise RuntimeError("acceptance materialization requires POSIX ownership support")
    chown = cast(Callable[..., None], candidate)
    for child in path.iterdir():
        chown(child, owner, owner, follow_symlinks=False)
    chown(path, owner, owner, follow_symlinks=False)
    path.chmod(0o500)


def _own_writable_directory(path: Path, *, owner: int = 10001) -> None:
    candidate = os.__dict__.get("chown")
    if not callable(candidate):
        raise RuntimeError("acceptance materialization requires POSIX ownership support")
    chown = cast(Callable[..., None], candidate)
    chown(path, owner, owner, follow_symlinks=False)
    path.chmod(0o700)


def _manifest(signers: dict[str, Ed25519Signer], operator: Ed25519Signer) -> ClusterManifest:
    policy = acceptance_policy()
    unsigned = ClusterManifest(
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        config_epoch=1,
        created_at=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        resources=policy.dimensions,
        initial_budget=INITIAL_BUDGET,
        wardens=tuple(
            WardenManifest(
                warden_id=warden_id,
                initial_share=share,
                peer_endpoint=peer_endpoint,
                client_endpoint=client_endpoint,
                keys=(
                    ManifestPublicKey(
                        key_id=signers[warden_id].key_id,
                        public_key=signers[warden_id].public_key_bytes,
                    ),
                ),
                extensions={},
            )
            for warden_id, share, peer_endpoint, client_endpoint in NODES
        ),
        policies=(policy,),
        extensions={
            "org.astraldeep.lets/purpose": "production-profile acceptance",
            "org.astraldeep.lets/transport": "TLS with required mutual authentication",
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


def main() -> int:
    _require_empty(TRUST)
    _require_empty(CLIENT)
    _require_empty(ROOT / "scenario")
    _own_writable_directory(ROOT / "scenario")
    for executor_domain in ("state", "authority"):
        directory = ROOT / "executor" / executor_domain
        _require_empty(directory)
        _own_writable_directory(directory)
    for warden_id, *_ in NODES:
        _require_empty(ROOT / "pki" / warden_id)
        _require_empty(ROOT / "signers" / warden_id)
        for domain in ("state", "config", "authority", "audit"):
            directory = ROOT / domain / warden_id
            _require_empty(directory)
            _own_writable_directory(directory)

    operator = Ed25519Signer.generate("production-acceptance-operator")
    signers: dict[str, Ed25519Signer] = {}
    for warden_id, *_ in NODES:
        signer = Ed25519Signer.generate(warden_id)
        signers[warden_id] = signer
        directory = ROOT / "signers" / warden_id
        (directory / "warden.seed").write_bytes(signer.seed_bytes)
        (directory / "warden.seed").chmod(0o400)
        _json(
            directory / "signer.json",
            {
                "key_id": signer.key_id,
                "public_key": b64url_encode(signer.public_key_bytes),
            },
        )
        (directory / "signer.json").chmod(0o400)
        _copy(SOURCE_HELPER, directory / "signer_helper.py", 0o500)
        _protect_tree(directory)

    manifest = _manifest(signers, operator)
    _json(TRUST / "manifest.json", manifest.to_dict())
    _json(
        TRUST / "operator.json",
        {"key_id": operator.key_id, "public_key": b64url_encode(operator.public_key_bytes)},
    )

    identity_key = SigningKey.generate()
    identity_kid = f"identity-{bytes(identity_key.verify_key).hex()[:24]}"
    _json(
        TRUST / "identity-keys.json",
        {
            "keys": [
                {
                    "kid": identity_kid,
                    "public_key": b64url_encode(bytes(identity_key.verify_key)),
                }
            ]
        },
    )
    (CLIENT / "identity.seed").write_bytes(bytes(identity_key))
    (CLIENT / "identity.seed").chmod(0o400)
    _json(
        CLIENT / "identity.json",
        {"audience": IDENTITY_AUDIENCE, "issuer": IDENTITY_ISSUER, "kid": identity_kid},
    )
    (CLIENT / "identity.json").chmod(0o400)

    with tempfile.TemporaryDirectory(prefix="lets-production-pki-") as raw_work:
        work = Path(raw_work)
        server_ca, server_ca_key = _ca(work, "server-ca")
        client_ca, client_ca_key = _ca(work, "client-ca")
        wrong_ca, wrong_ca_key = _ca(work, "untrusted-client-ca")
        for serial, (warden_id, *_rest) in enumerate(NODES, 10):
            directory = ROOT / "pki" / warden_id
            server_certificate, server_key = _certificate(
                work,
                name=f"{warden_id}-server",
                common_name=warden_id,
                ca_certificate=server_ca,
                ca_key=server_ca_key,
                serial=serial,
                usage="serverAuth",
                san=(f"DNS:{warden_id}", "DNS:localhost", "DNS:toxiproxy", "IP:127.0.0.1"),
            )
            peer_certificate, peer_key = _certificate(
                work,
                name=f"{warden_id}-peer",
                common_name=f"peer-{warden_id}",
                ca_certificate=client_ca,
                ca_key=client_ca_key,
                serial=serial + 100,
                usage="clientAuth",
            )
            for source, name, mode in (
                (server_certificate, "server-cert.pem", 0o444),
                (server_key, "server-key.pem", 0o400),
                (peer_certificate, "peer-cert.pem", 0o444),
                (peer_key, "peer-key.pem", 0o400),
                (server_ca, "server-ca.pem", 0o444),
                (client_ca, "client-ca.pem", 0o444),
            ):
                _copy(source, directory / name, mode)
            _protect_tree(directory)

        client_certificate, client_key = _certificate(
            work,
            name="acceptance-client",
            common_name="production-acceptance-client",
            ca_certificate=client_ca,
            ca_key=client_ca_key,
            serial=500,
            usage="clientAuth",
        )
        wrong_certificate, wrong_key = _certificate(
            work,
            name="wrong-client",
            common_name="untrusted-production-client",
            ca_certificate=wrong_ca,
            ca_key=wrong_ca_key,
            serial=501,
            usage="clientAuth",
        )
        for source, name, mode in (
            (client_certificate, "client-cert.pem", 0o444),
            (client_key, "client-key.pem", 0o400),
            (wrong_certificate, "wrong-client-cert.pem", 0o444),
            (wrong_key, "wrong-client-key.pem", 0o400),
            (server_ca, "server-ca.pem", 0o444),
        ):
            _copy(source, CLIENT / name, mode)

    for item in TRUST.iterdir():
        item.chmod(0o444)
    TRUST.chmod(0o555)
    _protect_tree(CLIENT)
    print(
        json.dumps(
            {
                "manifest_digest": manifest.digest,
                "provider": "generic-production",
                "status": "materialized",
                "wardens": [item[0] for item in NODES],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
