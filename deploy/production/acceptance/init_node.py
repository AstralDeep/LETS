"""Initialize one production-profile node through the public provider CLI."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

from nacl.signing import VerifyKey

from lets.canonical import b64url_decode, canonical_json, strict_json_loads

WARDEN_ID = os.environ["LETS_ACCEPTANCE_WARDEN_ID"]
CONFIG = Path("/var/lib/lets/config.json")
STAGED_CONFIG = Path("/var/lib/lets-config/config.json")
MANIFEST = Path("/etc/lets/trust/manifest.json")
OPERATOR = Path("/etc/lets/trust/operator.json")
SIGNER_METADATA = Path("/run/lets-signer/signer.json")


def _object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not an object")
    return cast(dict[str, Any], value)


def main() -> int:
    if any(Path("/var/lib/lets").iterdir()):
        raise RuntimeError("refusing to initialize a non-empty node state volume")
    operator = _object(OPERATOR)
    signer = _object(SIGNER_METADATA)
    subprocess.run(
        [
            "lets-provider",
            "audit-init",
            "--path",
            "/var/lib/lets-audit/audit.sqlite3",
        ],
        check=True,
    )
    signer_command = json.dumps(
        helper_command := [
            "/run/lets-signer/signer_helper.py",
            "--seed",
            "/run/lets-signer/warden.seed",
            "--audit-log",
            "/var/lib/lets-audit/signer-helper.jsonl",
        ],
        separators=(",", ":"),
    )
    challenge = b"LETS production acceptance external signer preflight"
    proof = subprocess.run(
        helper_command,
        input=challenge,
        check=False,
        capture_output=True,
        timeout=10,
    )
    if proof.returncode != 0:
        raise RuntimeError(
            "external signer preflight failed: " + proof.stderr.decode("utf-8", errors="replace")
        )
    VerifyKey(b64url_decode(cast(str, signer["public_key"]))).verify(
        challenge,
        b64url_decode(proof.stdout.strip().decode("ascii")),
    )
    command = [
        "lets",
        "--config",
        str(CONFIG),
        "init",
        "--production",
        "--warden-id",
        WARDEN_ID,
        "--manifest",
        str(MANIFEST),
        "--operator-key",
        f"{operator['key_id']}={operator['public_key']}",
        "--operator-threshold",
        "1",
        "--min-free-disk-bytes",
        "1048576",
        "--max-database-bytes",
        "104857600",
        "--reserve-pages",
        "64",
        "--runtime-provider",
        "generic-production",
        "--runtime-option",
        f"signer_command_json={signer_command}",
        "--runtime-option",
        f"signer_key_id={signer['key_id']}",
        "--runtime-option",
        f"signer_public_key={signer['public_key']}",
        "--runtime-option",
        "identity_keys_file=/etc/lets/trust/identity-keys.json",
        "--runtime-option",
        "identity_issuer=https://identity.production-acceptance",
        "--runtime-option",
        "identity_audience=lets-production-acceptance",
        "--runtime-option",
        "authority_anchor_path=/var/lib/lets-authority/anchor.json",
        "--runtime-option",
        "audit_archive_path=/var/lib/lets-audit/audit.sqlite3",
    ]
    subprocess.run(command, check=True)
    if STAGED_CONFIG.exists():
        raise RuntimeError("refusing to overwrite an existing staged config")
    staged = _object(CONFIG)
    if staged.get("database") != "warden.sqlite3":
        raise RuntimeError("generated config did not use the canonical state database")
    staged["database"] = "/var/lib/lets/warden.sqlite3"
    if "replay_database" in staged:
        if staged["replay_database"] != "peer-replay.sqlite3":
            raise RuntimeError("generated config used a non-canonical replay database")
        staged["replay_database"] = "/var/lib/lets/peer-replay.sqlite3"
    with STAGED_CONFIG.open("xb") as stream:
        stream.write(canonical_json(staged) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    STAGED_CONFIG.chmod(0o444)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
