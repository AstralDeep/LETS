"""Provision the production node: state volumes, audit archive, `lets init --production`.

Driven from Python rather than PowerShell because `signer_command_json` is a
JSON array passed as a single `NAME=VALUE` token. Quoting that correctly through
two shells is a losing game; handing subprocess an argv list sidesteps it.

`--production` init is strict, and every requirement below is enforced by the
runtime rather than chosen here:

  * an operator-signed manifest, admitted without any insecure-HTTP opt-in
  * an external runtime provider -- the built-in file signer is rejected outright
  * no local signing seed file and no bootstrap token; identity comes only from
    short-lived JWTs
  * explicit positive disk, database, and page-reserve capacity settings
  * an authority anchor and an audit archive that live outside the node's own
    state directory, and not in the same parent as each other, because they
    model independently mounted volumes
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lets.canonical import b64url_encode  # noqa: E402

from prod import params  # noqa: E402

# Capacity admission. Any of these at zero makes `--production` refuse to start;
# the values themselves are ordinary local-rig sizing.
MIN_FREE_DISK_BYTES = 64 * 1024 * 1024
MAX_DATABASE_BYTES = 1024 * 1024 * 1024
RESERVE_PAGES = 64


def runtime_options() -> dict[str, str]:
    warden_public = bytes(SigningKey(params.WARDEN_SEED.read_bytes()).verify_key)
    return {
        # argv for the external signer: interpreter, script, seed. The provider
        # requires an absolute existing file for the executable and spawns it
        # without a shell.
        "signer_command_json": json.dumps(
            [
                str(params.VENV_PYTHON),
                str(params.SIGNER_SCRIPT),
                str(params.WARDEN_SEED),
            ]
        ),
        "signer_key_id": params.warden_key_id(warden_public),
        "signer_public_key": b64url_encode(warden_public),
        "identity_keys_file": str(params.IDENTITY_KEYS_FILE),
        "identity_issuer": params.IDENTITY_ISSUER,
        "identity_audience": params.IDENTITY_AUDIENCE,
        "authority_anchor_path": str(params.ANCHOR_PATH),
        "audit_archive_path": str(params.AUDIT_PATH),
    }


def ensure_state() -> None:
    params.ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    params.AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # The anchor file is created by `lets init`; the audit archive is not, and
    # opening a missing one fails closed.
    if not params.AUDIT_PATH.exists():
        provider = params.PROJECT_ROOT / ".venv-prod" / "Scripts" / "lets-provider.exe"
        result = subprocess.run(
            [str(provider), "audit-init", "--path", str(params.AUDIT_PATH)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"audit-init failed:\n{result.stdout}\n{result.stderr}")
        print(f"audit archive initialized: {params.AUDIT_PATH}")


def normalize_peer_endpoints() -> None:
    """Write an explicit empty ``peer_endpoints`` map into the node config.

    This works around a genuine defect in lets-agent 1.0.10 that makes a
    single-warden manifest cluster unable to start.

    ``lets init`` only writes the key when the map is non-empty (cli.py:629),
    and a lone warden has no peers, so the key is absent. But the serve-time
    manifest check reads it with ``config.get("peer_endpoints")`` and no default
    (cli.py:1275), then requires the result to be a Mapping -- so ``None`` fails
    with "configured peer endpoints do not exactly match the signed manifest",
    even though the manifest expects exactly the empty set it just computed.

    Every other reader already defaults it to ``{}`` (cli.py:1044, cli.py:3163),
    so writing the empty object explicitly is semantically identical to what the
    rest of the runtime assumes, not a loosening of any check. ``peer_endpoints``
    is not one of the ten config fields diffed against the manifest, and an empty
    map is falsy, so production peer-TLS admission is unaffected.
    """

    config = json.loads(params.NODE_CONFIG.read_text(encoding="utf-8"))
    if config.get("peer_endpoints") is None:
        config["peer_endpoints"] = {}
        params.NODE_CONFIG.write_text(
            json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print("wrote explicit empty peer_endpoints (single-warden cluster)")


def main() -> int:
    if params.NODE_CONFIG.exists():
        print(f"node already initialized at {params.NODE_CONFIG}")
        print("run scripts\\reset-prod.ps1 to start over")
        return 0

    for required in (params.MANIFEST_FILE, params.IDENTITY_KEYS_FILE, params.WARDEN_SEED):
        if not required.exists():
            raise SystemExit(f"missing prerequisite: {required}")

    ensure_state()
    params.NODE_CONFIG.parent.mkdir(parents=True, exist_ok=True)

    operator_public = bytes(SigningKey(params.OPERATOR_SEED.read_bytes()).verify_key)
    lets = params.PROJECT_ROOT / ".venv-prod" / "Scripts" / "lets.exe"

    argv = [
        str(lets),
        "--config",
        str(params.NODE_CONFIG),
        "init",
        "--warden-id",
        params.WARDEN_ID,
        "--production",
        "--manifest",
        str(params.MANIFEST_FILE),
        "--operator-key",
        f"{params.OPERATOR_KEY_ID}={b64url_encode(operator_public)}",
        "--operator-threshold",
        "1",
        "--runtime-provider",
        "generic-production",
        "--min-free-disk-bytes",
        str(MIN_FREE_DISK_BYTES),
        "--max-database-bytes",
        str(MAX_DATABASE_BYTES),
        "--reserve-pages",
        str(RESERVE_PAGES),
    ]
    for name, value in runtime_options().items():
        argv += ["--runtime-option", f"{name}={value}"]

    result = subprocess.run(argv, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"lets init --production failed with exit {result.returncode}")

    normalize_peer_endpoints()

    print(result.stdout.strip())
    print()
    print(f"production node initialized at {params.NODE_CONFIG}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
