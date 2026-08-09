"""Regenerate the committed deterministic OpenAPI document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from lets.api import create_app
from lets.auth import AuthenticationError
from lets.models import IdentityContext


class _DocumentationAuthenticator:
    def authenticate(self, request: object) -> IdentityContext:
        del request
        raise AuthenticationError("documentation-only authenticator")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).parents[1] / "protocol" / "openapi.yaml",
    )
    arguments = parser.parse_args()
    document = create_app(object(), authenticator=_DocumentationAuthenticator()).openapi()
    arguments.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
