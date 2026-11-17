"""Generate the three Ed25519 keypairs the production node needs.

Three separate keys, because LETS enforces role separation:

  warden-signer  the node's signing identity. Only signer.py ever reads it; the
                 warden process itself never sees the private half.
  operator       signs the cluster manifest. The manifest refuses to verify if
                 operator and warden key material overlap, so this cannot be
                 folded into the warden key.
  issuer         mints the short-lived JWTs the dashboard authenticates with.

Idempotent: an existing seed is reused, never regenerated, because rotating the
warden seed would invalidate the manifest and rotating the issuer seed would
invalidate identity-keys.json.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lets.canonical import b64url_encode  # noqa: E402

from prod import params  # noqa: E402


def load_or_create_seed(path: Path) -> bytes:
    if path.exists():
        seed = path.read_bytes()
        if len(seed) != 32:
            raise SystemExit(f"{path} is not a 32-byte Ed25519 seed ({len(seed)} bytes)")
        return seed
    path.parent.mkdir(parents=True, exist_ok=True)
    seed = secrets.token_bytes(32)
    path.write_bytes(seed)
    return seed


def public_key(seed: bytes) -> bytes:
    return bytes(SigningKey(seed).verify_key)


def main() -> int:
    warden_public = public_key(load_or_create_seed(params.WARDEN_SEED))
    operator_public = public_key(load_or_create_seed(params.OPERATOR_SEED))
    issuer_public = public_key(load_or_create_seed(params.ISSUER_SEED))

    if len({warden_public, operator_public, issuer_public}) != 3:
        raise SystemExit("the three seeds must produce distinct public keys")

    # The provider's authenticator accepts this file only with exactly the keys
    # `kid` and `public_key` per entry -- it is deliberately not a JWKS, and any
    # extra member (kty, crv, alg, use) is rejected.
    params.IDENTITY_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    params.IDENTITY_KEYS_FILE.write_text(
        json.dumps(
            {"keys": [{"kid": params.ISSUER_KID, "public_key": b64url_encode(issuer_public)}]},
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "warden_id": params.WARDEN_ID,
                "warden_key_id": params.warden_key_id(warden_public),
                "warden_public_key": b64url_encode(warden_public),
                "operator_key_id": params.OPERATOR_KEY_ID,
                "operator_public_key": b64url_encode(operator_public),
                "issuer_kid": params.ISSUER_KID,
                "issuer_public_key": b64url_encode(issuer_public),
                "identity_keys_file": str(params.IDENTITY_KEYS_FILE),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
