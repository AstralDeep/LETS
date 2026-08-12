"""External Ed25519 signer for the generic-production runtime provider.

This is the whole point of the production signer contract: the warden process
never holds a private key. It spawns this program once per signature, writes the
exact bytes to be signed to stdin, and reads one unpadded base64url Ed25519
signature from stdout. No shell, no framing, no handshake.

A real deployment replaces this file with a PKCS#11, cloud-KMS, or HSM bridge --
the contract is identical, which is the point. Here the key sits in a local file,
which is honest about what this is: a test rig, not key management.

Usage (argv is fixed by the signer_command_json provider option):
    python signer.py <absolute path to 32-byte seed>
"""

from __future__ import annotations

import sys
from pathlib import Path

from nacl.signing import SigningKey

# Unpadded base64url, the encoding the provider's b64url_decode accepts. It
# re-encodes and compares, so the output has to be byte-canonical.
from base64 import urlsafe_b64encode


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: signer.py <seed-file>", file=sys.stderr)
        return 2

    seed = Path(argv[1]).read_bytes()
    if len(seed) != 32:
        print("signer seed must be exactly 32 bytes", file=sys.stderr)
        return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("nothing to sign", file=sys.stderr)
        return 2

    signature = SigningKey(seed).sign(payload).signature
    sys.stdout.write(urlsafe_b64encode(signature).decode("ascii").rstrip("="))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
