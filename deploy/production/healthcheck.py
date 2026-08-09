"""Fail-closed HTTPS/mTLS readiness probe for the production image."""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import sys
from pathlib import Path

MAX_RESPONSE_BYTES = 65_536
DEFAULT_TIMEOUT_SECONDS = 3.0


def _required_environment(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None or not value or any(ord(character) < 0x20 for character in value):
        raise ValueError(f"{name} must be a non-empty value without control characters")
    return value


def _port(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError("LETS_HEALTHCHECK_PORT must be an integer") from exc
    if not 1 <= parsed <= 65_535:
        raise ValueError("LETS_HEALTHCHECK_PORT must be between 1 and 65535")
    return parsed


def build_request(server_name: str) -> bytes:
    """Build a constant, connection-closing readiness request."""

    if not server_name or "\r" in server_name or "\n" in server_name:
        raise ValueError("healthcheck server name is unsafe")
    try:
        parsed = ipaddress.ip_address(server_name)
    except ValueError:
        host_header = server_name
    else:
        host_header = f"[{server_name}]" if parsed.version == 6 else server_name
    return (
        "GET /health/ready HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")


def is_ready_response(response: bytes) -> bool:
    """Accept only a bounded HTTP 200 response carrying the LETS ready document."""

    if not response or len(response) > MAX_RESPONSE_BYTES:
        return False
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        return False
    lines = head.split(b"\r\n")
    if not lines or lines[0] not in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK"):
        return False
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return bool(document == {"status": "ready"})


def _read_response(stream: ssl.SSLSocket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = stream.recv(min(16_384, MAX_RESPONSE_BYTES + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ValueError("readiness response exceeded its size limit")


def check_ready() -> None:
    """Perform one authenticated, hostname-verifying readiness request."""

    host = _required_environment("LETS_HEALTHCHECK_HOST", "127.0.0.1")
    port = _port(_required_environment("LETS_HEALTHCHECK_PORT", "8443"))
    server_name = _required_environment("LETS_HEALTHCHECK_SERVER_NAME")
    ca_file = Path(_required_environment("LETS_HEALTHCHECK_CA", "/run/secrets/lets_peer_ca.pem"))
    certificate = Path(
        _required_environment("LETS_HEALTHCHECK_CERT", "/run/secrets/lets_peer_cert.pem")
    )
    private_key = Path(
        _required_environment("LETS_HEALTHCHECK_KEY", "/run/secrets/lets_peer_key.pem")
    )

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=certificate, keyfile=private_key)

    with (
        socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT_SECONDS) as connection,
        context.wrap_socket(connection, server_hostname=server_name) as stream,
    ):
        stream.settimeout(DEFAULT_TIMEOUT_SECONDS)
        stream.sendall(build_request(server_name))
        response = _read_response(stream)
    if not is_ready_response(response):
        raise RuntimeError("warden did not return an authenticated ready response")


def main() -> int:
    try:
        check_ready()
    except Exception as exc:
        print(f"LETS readiness probe failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
