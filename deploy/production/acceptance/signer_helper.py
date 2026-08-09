#!/app/.venv/bin/python
"""Test-only command signer proving the generic provider subprocess contract."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from pathlib import Path

from nacl.signing import SigningKey

MAX_PAYLOAD_BYTES = 1_048_576


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", required=True, type=Path)
    parser.add_argument("--audit-log", required=True, type=Path)
    arguments = parser.parse_args()
    payload = sys.stdin.buffer.read(MAX_PAYLOAD_BYTES + 1)
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise RuntimeError("signing input exceeds the acceptance helper limit")
    seed = arguments.seed.read_bytes()
    if len(seed) != 32:
        raise RuntimeError("acceptance signer seed is invalid")
    signature = SigningKey(seed).sign(payload).signature
    record = {
        "at_ns": time.time_ns(),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "pid": os.getpid(),
    }
    with arguments.audit_log.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=")
    sys.stdout.buffer.write(encoded + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
