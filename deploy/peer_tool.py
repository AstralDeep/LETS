"""Invoke or materialize an exact Ed25519-authenticated peer HTTP request."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

from lets.auth import sign_peer_headers
from lets.canonical import canonical_json, strict_json_loads
from lets.client import PeerClient, RetryPolicy
from lets.crypto import Ed25519Signer


def _load_signer(config_path: Path) -> Ed25519Signer:
    value = strict_json_loads(config_path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("node configuration must be a JSON object")
    warden_id = value.get("warden_id")
    raw_key = value.get("signing_key")
    if not isinstance(warden_id, str) or not isinstance(raw_key, str):
        raise RuntimeError("node configuration has no signing identity")
    base = config_path.resolve().parent
    key_path = (base / raw_key).resolve()
    if not key_path.is_relative_to(base):
        raise RuntimeError("configured signing key escapes the state directory")
    return Ed25519Signer.load_seed_file(warden_id, key_path)


def _stdin_object() -> dict[str, Any]:
    value = strict_json_loads(sys.stdin.read())
    if not isinstance(value, dict):
        raise RuntimeError("peer payload must be a JSON object")
    return cast(dict[str, Any], value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("/var/lib/lets/config.json"))
    commands = parser.add_subparsers(dest="command", required=True)
    call = commands.add_parser("call")
    call.add_argument("--base-url", required=True)
    call.add_argument("--operation", choices=("accept", "finalize"), required=True)
    sign = commands.add_parser("sign")
    sign.add_argument("--path", required=True)
    sign.add_argument("--nonce")
    sign.add_argument("--timestamp", type=int)
    arguments = parser.parse_args()

    signer = _load_signer(arguments.config.resolve())
    payload = _stdin_object()
    if arguments.command == "call":
        with PeerClient(
            arguments.base_url,
            signer=signer,
            timeout=2,
            retry=RetryPolicy(max_attempts=1),
        ) as client:
            if arguments.operation == "accept":
                response = client.accept_transfer(payload)
            else:
                response = client.finalize_transfer(payload)
        print(json.dumps(response, separators=(",", ":"), sort_keys=True))
        return 0

    body = canonical_json(payload)
    headers = sign_peer_headers(
        signer,
        method="POST",
        path=arguments.path,
        body=body,
        timestamp_s=arguments.timestamp,
        nonce=arguments.nonce,
    )
    headers["content-type"] = "application/json"
    print(
        json.dumps(
            {"body": body.decode("utf-8"), "headers": headers},
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
