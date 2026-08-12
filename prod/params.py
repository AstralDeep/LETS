"""Shared constants for the production node.

Every production artifact -- the seeds, the cluster manifest, the provider
options, and the demo app's JWTs -- has to agree on these values exactly. The
warden re-verifies the manifest against its own config on *every* boot and
refuses to start on any drift, so a single source of truth is not a nicety.

The dev node in ``.lets/a`` is untouched by anything here.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# --- identity -----------------------------------------------------------------
WARDEN_ID = "warden-prod"
TENANT_ID = "example"
ENVELOPE_ID = "agents"
CONFIG_EPOCH = 1

# Genesis envelope, matching the dev node so the same demo actions and the same
# verify_core_four.py arithmetic apply. Index 0 is `actions`, index 1 is
# `tokens`, per DIMENSIONS in demo/policy.py.
BUDGET = [10_000, 1_000_000]

# --- endpoints ----------------------------------------------------------------
# `--production` init rejects --allow-insecure-manifest, so these must be https.
WARDEN_HOST = "127.0.0.1"
WARDEN_PORT = 8443
PEER_PORT = 8444
CLIENT_ENDPOINT = f"https://{WARDEN_HOST}:{WARDEN_PORT}"
PEER_ENDPOINT = f"https://{WARDEN_HOST}:{PEER_PORT}"
BASE_URL = CLIENT_ENDPOINT

DASHBOARD_PORT = 8801

# --- key ids ------------------------------------------------------------------
OPERATOR_KEY_ID = "ops-1"
ISSUER_KID = "demo-issuer-1"

# --- JWT identity -------------------------------------------------------------
IDENTITY_ISSUER = "lets-demo-issuer"
IDENTITY_AUDIENCE = "lets-warden-prod"
IDENTITY_SUBJECT = "demo-dashboard"

# The same scope set the dev node's bootstrap identity carries, so behaviour is
# identical across the two nodes and any difference is transport/identity only.
IDENTITY_SCOPES = (
    "lets.admin",
    "lets.audit.read",
    "lets.audit.verify",
    "lets.branch.revoke",
    "lets.lease.manage",
    "lets.metrics.read",
    "lets.transfer",
)

# --- paths --------------------------------------------------------------------
SECRETS_DIR = PROJECT_ROOT / "secrets"
PKI_DIR = PROJECT_ROOT / "pki"
PROD_DIR = PROJECT_ROOT / "prod"
STATE_DIR = PROJECT_ROOT / "state"

WARDEN_SEED = SECRETS_DIR / "warden-signer.seed"
OPERATOR_SEED = SECRETS_DIR / "operator.seed"
ISSUER_SEED = SECRETS_DIR / "issuer.seed"

IDENTITY_KEYS_FILE = PROD_DIR / "identity-keys.json"
MANIFEST_FILE = PROD_DIR / "cluster-manifest.json"
SIGNER_SCRIPT = PROD_DIR / "signer.py"

NODE_CONFIG = PROJECT_ROOT / ".lets" / "prod" / "config.json"
VENV_PYTHON = PROJECT_ROOT / ".venv-prod" / "Scripts" / "python.exe"

# The provider refuses an anchor or archive inside the node state directory, and
# refuses the two sharing a parent -- they model independently mounted volumes.
ANCHOR_PATH = STATE_DIR / "anchor" / "authority.json"
AUDIT_PATH = STATE_DIR / "audit" / "audit.sqlite3"

CA_CERT = PKI_DIR / "ca.crt"
WARDEN_CERT = PKI_DIR / "warden.crt"
WARDEN_KEY = PKI_DIR / "warden.key"
CLIENT_CERT = PKI_DIR / "demo-client.crt"
CLIENT_KEY = PKI_DIR / "demo-client.key"


def warden_key_id(public_key: bytes) -> str:
    """Reproduce the key id lets derives internally for an Ed25519 signer.

    ``Ed25519Signer.__init__`` builds this from the public key, and ``lets init``
    refuses a manifest whose warden key entry does not match the runtime signer
    on *both* key id and key material. Deriving it the same way here is what
    lets the manifest be authored before the node exists.
    """

    from hashlib import sha256

    return f"{WARDEN_ID}/ed25519-{sha256(public_key).hexdigest()[:32]}"
