"""Headless checks that the production hardening is real, not decorative.

Split into two phases because `lets serve` takes an exclusive lock on the node
before it validates anything, so the admission gates and the manifest anchor can
only be exercised while the warden is stopped.

  online   the warden is running: mutual TLS is enforced against real
           certificates, and JWT identity is actually verified.
  offline  the warden is stopped: --production refuses development transport and
           trust choices, and a tampered manifest locks the node.

Run it twice -- once with the warden up, once with it down -- or just run it and
follow what it prints. Exits non-zero on any failure.
"""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from demo import identity  # noqa: E402
from prod import params  # noqa: E402

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail else ""))
    if not condition:
        failures.append(name)


# --------------------------------------------------------------------- helpers


def raw_request(
    *,
    client_cert: tuple[Path, Path] | None,
    ca: Path = params.CA_CERT,
    path: str = "/health/ready",
    token: str | None = None,
) -> tuple[str, str]:
    """Return (outcome, detail) for one HTTPS request built by hand.

    Deliberately not httpx: this has to distinguish "TLS refused the client"
    from "the application answered", and report the HTTP status when there is
    one. Under TLS 1.3 a missing client certificate is not a handshake error --
    the server accepts the handshake and then drops the connection without a
    response, so an empty read is the signal.
    """

    context = ssl.create_default_context(cafile=str(ca))
    if client_cert is not None:
        context.load_cert_chain(str(client_cert[0]), str(client_cert[1]))
    request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\naccept: application/json\r\n"
    if token is not None:
        request += f"authorization: Bearer {token}\r\n"
    request += "Connection: close\r\n\r\n"
    try:
        with socket.create_connection((params.WARDEN_HOST, params.WARDEN_PORT), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(request.encode("ascii"))
                data = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
    except ssl.SSLError as exc:
        return "tls-refused", f"{type(exc).__name__}: {exc.reason or exc}"
    except OSError as exc:
        return "tls-refused", f"{type(exc).__name__}: {exc}"
    if not data:
        return "tls-refused", "connection closed with no response"
    status = data.split(b"\r\n", 1)[0].decode("latin-1")
    return "http", status


def token(**overrides) -> str:
    claims = {
        "seed": params.ISSUER_SEED.read_bytes(),
        "kid": params.ISSUER_KID,
        "issuer": params.IDENTITY_ISSUER,
        "audience": params.IDENTITY_AUDIENCE,
        "subject": params.IDENTITY_SUBJECT,
        "tenant_id": params.TENANT_ID,
        "scopes": params.IDENTITY_SCOPES,
    }
    claims.update(overrides)
    return identity.mint(**claims)


def warden_is_up() -> bool:
    try:
        with socket.create_connection((params.WARDEN_HOST, params.WARDEN_PORT), timeout=2):
            return True
    except OSError:
        return False


def serve_attempt(extra: list[str]) -> str:
    """Run `lets serve --production` with deliberately wrong flags; return its error."""

    lets = params.PROJECT_ROOT / ".venv-prod" / "Scripts" / "lets.exe"
    result = subprocess.run(
        [
            str(lets),
            "--config",
            str(params.NODE_CONFIG),
            "serve",
            "--production",
            "--host",
            params.WARDEN_HOST,
            "--port",
            str(params.WARDEN_PORT),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return (result.stderr + result.stdout).strip()


def status_attempt() -> str:
    """Re-verify the manifest without serving.

    `lets status` goes through the same manifest trust registry that `serve`
    does, but returns instead of binding a socket -- so it can confirm a restored
    manifest is accepted again, where a valid `serve` would simply start the
    warden and block.
    """

    lets = params.PROJECT_ROOT / ".venv-prod" / "Scripts" / "lets.exe"
    result = subprocess.run(
        [str(lets), "--config", str(params.NODE_CONFIG), "status"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return (result.stderr + result.stdout).strip()


# ---------------------------------------------------------------- online phase


def online() -> None:
    good = (params.CLIENT_CERT, params.CLIENT_KEY)
    rogue = (params.PKI_DIR / "rogue-client.crt", params.PKI_DIR / "rogue-client.key")

    print("\n== mutual TLS is enforced ==")
    outcome, detail = raw_request(client_cert=good)
    check("trusted client certificate is admitted", outcome == "http" and "200" in detail, detail)

    outcome, detail = raw_request(client_cert=None)
    check("no client certificate is refused", outcome == "tls-refused", detail)

    outcome, detail = raw_request(client_cert=rogue)
    check("client certificate from an untrusted CA is refused", outcome == "tls-refused", detail)

    print("\n== the warden's own certificate is verified ==")
    outcome, detail = raw_request(client_cert=good, ca=params.PKI_DIR / "rogue-ca.crt")
    check("server certificate is rejected under the wrong CA", outcome == "tls-refused", detail)

    print("\n== JWT identity is verified ==")
    # /v1/audit requires lets.audit.read, so it exercises the scope check rather
    # than just authentication.
    audit = "/v1/audit?limit=1"

    outcome, detail = raw_request(client_cert=good, path=audit, token=token())
    check("a valid token is accepted", outcome == "http" and "200" in detail, detail)

    outcome, detail = raw_request(client_cert=good, path=audit)
    check("no token is rejected", outcome == "http" and "401" in detail, detail)

    now = int(time.time())
    outcome, detail = raw_request(
        client_cert=good,
        path=audit,
        token=token(issued_at=now - 4000, expires_at=now - 3600),
    )
    check("an expired token is rejected", outcome == "http" and "401" in detail, detail)

    outcome, detail = raw_request(
        client_cert=good, path=audit, token=token(audience="some-other-warden")
    )
    check("a token for the wrong audience is rejected", outcome == "http" and "401" in detail, detail)

    outcome, detail = raw_request(
        client_cert=good, path=audit, token=token(issuer="impostor-issuer")
    )
    check("a token from the wrong issuer is rejected", outcome == "http" and "401" in detail, detail)

    outcome, detail = raw_request(
        client_cert=good, path=audit, token=token(seed=params.OPERATOR_SEED.read_bytes())
    )
    check(
        "a token signed by an untrusted key is rejected",
        outcome == "http" and "401" in detail,
        detail,
    )

    outcome, detail = raw_request(
        client_cert=good, path=audit, token=token(scopes=("lets.metrics.read",))
    )
    check(
        "a token without lets.audit.read is refused the audit log",
        outcome == "http" and "403" in detail,
        detail,
    )

    outcome, detail = raw_request(
        client_cert=good, path=audit, token=token(scopes=("lets.audit.read",))
    )
    check(
        "the same token with lets.audit.read is admitted",
        outcome == "http" and "200" in detail,
        detail,
    )

    print("\n== the external signer is the one signing ==")
    lets = params.PROJECT_ROOT / ".venv-prod" / "Scripts" / "lets.exe"
    result = subprocess.run(
        [str(lets), "--config", str(params.NODE_CONFIG), "key"],
        capture_output=True,
        text=True,
    )
    document = json.loads(result.stdout) if result.returncode == 0 else {}
    check(
        "runtime provider is generic-production, not builtin",
        document.get("runtime_provider") == "generic-production",
        str(document.get("runtime_provider")),
    )
    manifest = json.loads(params.MANIFEST_FILE.read_text(encoding="utf-8"))
    check(
        "the live signing key is the one the manifest authorizes",
        document.get("key_id") == manifest["wardens"][0]["keys"][0]["key_id"],
        str(document.get("key_id")),
    )


# --------------------------------------------------------------- offline phase


def offline() -> None:
    tls = ["--tls-cert", str(params.WARDEN_CERT), "--tls-key", str(params.WARDEN_KEY)]
    mtls = [*tls, "--client-ca", str(params.CA_CERT)]

    print("\n== --production refuses development transport and trust ==")
    check(
        "refuses to serve without a server certificate",
        "requires --tls-cert and --tls-key" in serve_attempt([]),
        "",
    )
    check(
        "refuses to serve without inbound mTLS",
        "requires --client-ca for inbound mTLS" in serve_attempt(tls),
        "",
    )
    check(
        "refuses the built-in file signer",
        "rejects the built-in file signer" in serve_attempt([*mtls, "--runtime-provider", "builtin"]),
        "",
    )
    check(
        "refuses an explicit cleartext opt-in",
        "rejects insecure client or peer HTTP" in serve_attempt([*mtls, "--allow-insecure-http"]),
        "",
    )

    print("\n== the signed manifest is a live root of trust ==")
    original = params.MANIFEST_FILE.read_bytes()
    try:
        document = json.loads(original)
        # A semantically meaningless edit: the budget still balances against the
        # warden share, so only the signature and digest can catch it.
        document["created_at"] = "2020-01-01T00:00:00Z"
        params.MANIFEST_FILE.write_bytes(json.dumps(document, indent=2).encode("utf-8"))
        message = serve_attempt(mtls)
        check(
            "a tampered manifest stops the node",
            "signed manifest digest does not match" in message,
            message.splitlines()[-1] if message else "",
        )
        check(
            "and every operator command with it",
            "signed manifest digest does not match" in status_attempt(),
        )
    finally:
        params.MANIFEST_FILE.write_bytes(original)

    message = status_attempt()
    check(
        "restoring the manifest clears the failure",
        "signed manifest digest does not match" not in message,
        message.splitlines()[0] if message else "",
    )


def main() -> int:
    up = warden_is_up()
    print(f"production warden at {params.BASE_URL}: {'running' if up else 'stopped'}")
    if up:
        online()
        print("\nNote: the admission gates and the manifest anchor need the warden")
        print("stopped (it locks the node before validating). Stop it and re-run.")
    else:
        offline()
        print("\nNote: the mutual-TLS and JWT checks need the warden running.")
        print("Start it with scripts\\run-prod.ps1 and re-run.")

    print("\n" + "=" * 60)
    if failures:
        print(f"FAILED ({len(failures)}): " + ", ".join(failures))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
