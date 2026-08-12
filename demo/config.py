"""Connection settings for the warden node this demo governs itself against.

Two profiles, selected by the ``LETS_DEMO_PROFILE`` environment variable:

``dev`` (the default)
    The original setup: loopback cleartext HTTP and a static bearer token.
    ``.lets-demo.json`` is written by ``scripts/bootstrap.ps1`` because
    ``lets init`` prints the bootstrap token exactly once and only stores its
    SHA-256 digest.

``production``
    The node in ``.lets/prod``, running under ``lets serve --production``:
    mutual TLS, an operator-signed cluster manifest, an external signer, and
    short-lived EdDSA JWTs instead of a bearer token. There is no stored
    credential at all -- the dashboard mints its own tokens from the issuer seed.

The dev path is unchanged, so ``scripts\\run.ps1`` behaves exactly as before.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEMO_CONFIG = PROJECT_ROOT / ".lets-demo.json"

# The audience a receipt is bound to. A real deployment names the service that
# performs the protected effect; a receipt is only valid at that one executor.
EXECUTOR_AUDIENCE = "demo-tool-gateway"


@dataclass(frozen=True, slots=True)
class Identity:
    """Everything needed to mint a JWT the production warden will accept."""

    seed_path: Path
    kid: str
    issuer: str
    audience: str
    subject: str
    tenant_id: str
    scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Settings:
    base_url: str
    token: str | None = None
    ca_cert: Path | None = None
    client_cert: Path | None = None
    client_key: Path | None = None
    identity: Identity | None = None

    @property
    def is_production(self) -> bool:
        return self.identity is not None

    @property
    def profile(self) -> str:
        return "prod" if self.is_production else "dev"

    def registry_path(self, kind: str = "fleet") -> Path:
        """Where this profile remembers the leases it opened.

        Per profile, because lease IDs are node-local: a dev registry adopted by
        the production dashboard would name leases that warden has never heard
        of, and the host would be unable to close them.
        """

        # The dev profile keeps its original filenames, so leases opened before
        # the production node existed are still adopted rather than orphaned.
        if not self.is_production:
            return PROJECT_ROOT / f".lets-demo-{kind}.json"
        return PROJECT_ROOT / f".lets-demo-{kind}-prod.json"

    @classmethod
    def load(cls) -> "Settings":
        if os.environ.get("LETS_DEMO_PROFILE", "dev").lower() == "production":
            return cls.load_production()
        return cls.load_dev()

    @classmethod
    def load_dev(cls) -> "Settings":
        base_url = os.environ.get("LETS_DEMO_URL")
        token = os.environ.get("LETS_DEMO_TOKEN")
        if base_url and token:
            return cls(base_url=base_url, token=token)

        if not DEMO_CONFIG.exists():
            raise SystemExit(
                f"{DEMO_CONFIG} not found. Run scripts\\bootstrap.ps1 first — it "
                "initializes the warden and captures the bootstrap token, which "
                "`lets init` prints only once."
            )
        data = json.loads(DEMO_CONFIG.read_text(encoding="utf-8-sig"))
        try:
            return cls(base_url=data["base_url"], token=data["token"])
        except KeyError as exc:
            raise SystemExit(f"{DEMO_CONFIG} is missing key {exc}") from exc

    @classmethod
    def load_production(cls) -> "Settings":
        # Imported lazily so the dev profile never depends on the production
        # tree existing. prod/params.py is the single source of truth shared with
        # the manifest builder and the node provisioner -- any drift between them
        # would make the warden refuse to start.
        from prod import params

        missing = [
            str(path)
            for path in (params.CA_CERT, params.CLIENT_CERT, params.CLIENT_KEY, params.ISSUER_SEED)
            if not path.exists()
        ]
        if missing:
            raise SystemExit(
                "The production profile is not provisioned yet — missing:\n  "
                + "\n  ".join(missing)
                + "\nRun scripts\\bootstrap-prod.ps1 first."
            )

        return cls(
            base_url=params.BASE_URL,
            ca_cert=params.CA_CERT,
            client_cert=params.CLIENT_CERT,
            client_key=params.CLIENT_KEY,
            identity=Identity(
                seed_path=params.ISSUER_SEED,
                kid=params.ISSUER_KID,
                issuer=params.IDENTITY_ISSUER,
                audience=params.IDENTITY_AUDIENCE,
                subject=params.IDENTITY_SUBJECT,
                tenant_id=params.TENANT_ID,
                scopes=params.IDENTITY_SCOPES,
            ),
        )
