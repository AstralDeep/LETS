"""Author and operator-sign the cluster manifest.

The manifest is the root of trust for the whole node: it declares the genesis
envelope, the resource dimensions, the policy, and which Ed25519 keys are
allowed to be this warden. `lets serve` re-loads and re-verifies it on *every*
boot and diffs it against ten fields of the node config, refusing to start on
any drift.

Two things make this a program rather than a hand-written JSON file.

First, the signed bytes are a *reconstruction*, not the bytes on disk.
`unsigned_dict()` canonicalizes endpoints, drops empty descriptions, and
recomputes and re-injects `policy_digest` and `machine_digest`. Signing a
hand-edited file's literal bytes produces a signature that verifies against
nothing. The only correct order is: build -> unsigned_dict -> sign -> attach.

Second, the manifest's policy must match the running demo's policy exactly --
including the `description` strings on every resource dimension, which are
compared by value. So the policy is imported from demo/policy.py rather than
retyped, and cannot drift from what the dashboard actually uses.

Idempotent: an existing manifest is left alone, because its digest is anchored
in the node database and regenerating it (with a new `created_at`) would lock
the node out of its own state.
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

from nacl.signing import SigningKey

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lets.canonical import b64url_encode, canonical_json  # noqa: E402
from lets.manifest import (  # noqa: E402
    ClusterManifest,
    ManifestPublicKey,
    WardenManifest,
)

from demo.policy import DIMENSIONS, POLICY  # noqa: E402
from prod import params  # noqa: E402


def build() -> ClusterManifest:
    warden_seed = params.WARDEN_SEED.read_bytes()
    warden_public = bytes(SigningKey(warden_seed).verify_key)

    return ClusterManifest(
        tenant_id=params.TENANT_ID,
        envelope_id=params.ENVELOPE_ID,
        config_epoch=params.CONFIG_EPOCH,
        created_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        resources=tuple(DIMENSIONS),
        initial_budget=tuple(params.BUDGET),
        wardens=(
            WardenManifest(
                warden_id=params.WARDEN_ID,
                peer_endpoint=params.PEER_ENDPOINT,
                client_endpoint=params.CLIENT_ENDPOINT,
                # Single warden, so its share is the whole envelope. The
                # manifest requires the component-wise sum of every warden's
                # share to equal initial_budget exactly.
                initial_share=tuple(params.BUDGET),
                keys=(
                    ManifestPublicKey(
                        key_id=params.warden_key_id(warden_public),
                        public_key=warden_public,
                    ),
                ),
                extensions={},
            ),
        ),
        policies=(POLICY,),
        extensions={},
    )


def main() -> int:
    if params.MANIFEST_FILE.exists():
        existing = json.loads(params.MANIFEST_FILE.read_text(encoding="utf-8"))
        loaded = ClusterManifest.from_dict(existing)
        print(f"manifest already exists, keeping it: {params.MANIFEST_FILE}")
        print(f"  digest: {loaded.digest}")
        return 0

    manifest = build()

    operator = SigningKey(params.OPERATOR_SEED.read_bytes())
    operator_public = bytes(operator.verify_key)

    # Sign the canonical reconstruction, never the file bytes.
    signature = operator.sign(canonical_json(manifest.unsigned_dict())).signature

    document = manifest.unsigned_dict()
    document["signatures"] = [
        {
            "key_id": params.OPERATOR_KEY_ID,
            "algorithm": "Ed25519",
            "signature": b64url_encode(signature),
        }
    ]

    params.MANIFEST_FILE.parent.mkdir(parents=True, exist_ok=True)
    params.MANIFEST_FILE.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    # Read it back the way the warden will and prove the signature verifies,
    # rather than trusting that what was just written is loadable.
    reloaded = ClusterManifest.from_dict(
        json.loads(params.MANIFEST_FILE.read_text(encoding="utf-8"))
    )
    accepted = reloaded.verify_signatures({params.OPERATOR_KEY_ID: operator_public}, threshold=1)

    print(f"manifest written: {params.MANIFEST_FILE}")
    print(f"  digest          : {reloaded.digest}")
    print(f"  accepted signers: {sorted(accepted)}")
    print(f"  warden key_id   : {reloaded.wardens[0].keys[0].key_id}")
    print(f"  operator key    : {params.OPERATOR_KEY_ID}={b64url_encode(operator_public)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
