"""Short-lived EdDSA JWT identity for the production warden.

Under `--production` the static bearer token is gone. LETS refuses the built-in
authenticator outright and the generic provider verifies an Ed25519 JWT instead:
strict header, a fixed claim set, and a lifetime capped at 15 minutes by default.

`LETSClient` bakes its Authorization header in at construction time, so a token
handed to it once would go stale mid-session and every later call would 401.
Rather than juggling a refresh timer, this mints a fresh token per request as an
httpx auth flow. Ed25519 signing is on the order of microseconds, so the cost is
irrelevant next to the network round trip, and there is no expiry window to get
wrong.

The token is deliberately built by hand rather than with a JWT library: the
provider demands a header of *exactly* {alg, kid, typ} and canonical unpadded
base64url, and most libraries add or reorder members.
"""

from __future__ import annotations

import json
import time
from base64 import urlsafe_b64encode
from collections.abc import Generator
from pathlib import Path
from uuid import uuid4

import httpx
from nacl.signing import SigningKey

# Comfortably inside the provider's 900s ceiling, and short enough that a leaked
# token is worth little.
TOKEN_LIFETIME_S = 300


def _b64url(raw: bytes) -> str:
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _segment(payload: dict) -> str:
    # Compact separators and sorted keys keep the JSON inside the strict parser's
    # accepted subset.
    return _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def mint(
    *,
    seed: bytes,
    kid: str,
    issuer: str,
    audience: str,
    subject: str,
    tenant_id: str,
    scopes: tuple[str, ...] | list[str],
    lifetime_s: int = TOKEN_LIFETIME_S,
    issued_at: int | None = None,
    expires_at: int | None = None,
) -> str:
    """Mint one EdDSA JWT the generic provider will accept.

    The claim overrides exist so the verification suite can mint deliberately
    invalid tokens (expired, wrong audience, missing scope) against the same code
    path a valid one takes.
    """

    now = int(time.time()) if issued_at is None else issued_at
    header = {"alg": "EdDSA", "kid": kid, "typ": "JWT"}
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "tenant_id": tenant_id,
        "jti": uuid4().hex,
        "iat": now,
        "nbf": now,
        "exp": now + lifetime_s if expires_at is None else expires_at,
        "scope": " ".join(scopes),
    }
    signing_input = f"{_segment(header)}.{_segment(claims)}"
    signature = SigningKey(seed).sign(signing_input.encode("ascii")).signature
    return f"{signing_input}.{_b64url(signature)}"


class JWTAuth(httpx.Auth):
    """Stamps a freshly minted EdDSA JWT on every outbound request."""

    def __init__(
        self,
        *,
        seed_path: Path,
        kid: str,
        issuer: str,
        audience: str,
        subject: str,
        tenant_id: str,
        scopes: tuple[str, ...],
    ) -> None:
        self._seed = Path(seed_path).read_bytes()
        if len(self._seed) != 32:
            raise ValueError(f"{seed_path} is not a 32-byte Ed25519 seed")
        self._kid = kid
        self._issuer = issuer
        self._audience = audience
        self._subject = subject
        self._tenant_id = tenant_id
        self._scopes = scopes

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        request.headers["authorization"] = f"Bearer {self.token()}"
        yield request

    def token(self) -> str:
        return mint(
            seed=self._seed,
            kid=self._kid,
            issuer=self._issuer,
            audience=self._audience,
            subject=self._subject,
            tenant_id=self._tenant_id,
            scopes=self._scopes,
        )
