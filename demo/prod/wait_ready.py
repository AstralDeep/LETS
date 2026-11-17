"""Poll the production warden until it reports ready.

A separate script because probing it requires presenting a client certificate,
and PowerShell's Invoke-RestMethod needs a persisted-key X509Certificate2 to do
client auth -- PEM files loaded ephemerally tend to fail at the TLS layer on
Windows. Python's ssl module takes the PEM pair directly.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from prod import params  # noqa: E402

TIMEOUT_S = 60


def probe(path: str) -> str | None:
    context = ssl.create_default_context(cafile=str(params.CA_CERT))
    context.load_cert_chain(str(params.CLIENT_CERT), str(params.CLIENT_KEY))
    try:
        with socket.create_connection((params.WARDEN_HOST, params.WARDEN_PORT), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(
                    f"GET {path} HTTP/1.1\r\nHost: localhost\r\n"
                    "accept: application/json\r\nConnection: close\r\n\r\n".encode("ascii")
                )
                data = b""
                while True:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
    except OSError:
        return None
    if b"\r\n\r\n" not in data:
        return None
    return data.split(b"\r\n\r\n", 1)[1].decode("utf-8", "replace")


def main() -> int:
    deadline = time.time() + TIMEOUT_S
    while time.time() < deadline:
        body = probe("/health/ready")
        if body:
            try:
                if json.loads(body).get("status") == "ready":
                    print("warden ready")
                    return 0
            except ValueError:
                pass
        time.sleep(0.5)

    print(
        f"the production warden did not become ready within {TIMEOUT_S}s.\n"
        f"Check that port {params.WARDEN_PORT} is free and see the console output above.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
