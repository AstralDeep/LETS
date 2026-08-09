"""Reject common secret material and broad copies from the container build context."""

from __future__ import annotations

import argparse
import re
import subprocess
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

REQUIRED_IGNORE_RULES = frozenset(
    {
        "**/.env",
        "**/.env.*",
        "!**/.env.example",
        "**/.secrets/**",
        "**/secrets/**",
        "**/*credentials*.json",
        "**/*service-account*.json",
        "**/*service_account*.json",
        "**/id_rsa",
        "**/id_ed25519",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "*.seed",
        "*.token",
    }
)
SENSITIVE_SUFFIXES = frozenset({".ed25519", ".key", ".p12", ".pem", ".pfx", ".seed", ".token"})
SENSITIVE_BASENAMES = frozenset({"id_ed25519", "id_rsa"})
_BROAD_COPY = re.compile(r"^\s*(?:COPY|ADD)\s+(?:--[^\s]+\s+)*[.]\s+", re.MULTILINE)


def _git_files(repository: Path) -> tuple[str, ...]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repository,
        check=True,
        capture_output=True,
    )
    return tuple(item.decode("utf-8") for item in result.stdout.split(b"\0") if item)


def is_sensitive_path(value: str) -> bool:
    path = PurePosixPath(value)
    name = path.name.casefold()
    parts = {part.casefold() for part in path.parts}
    if name == ".env.example":
        return False
    if name == ".env" or name.startswith(".env."):
        return True
    if "secrets" in parts or ".secrets" in parts:
        return True
    if name in SENSITIVE_BASENAMES or path.suffix.casefold() in SENSITIVE_SUFFIXES:
        return True
    return name.endswith(".json") and (
        "credential" in name or "service-account" in name or "service_account" in name
    )


def find_violations(repository: Path) -> tuple[str, ...]:
    problems: list[str] = []
    dockerignore = (repository / ".dockerignore").read_text(encoding="utf-8").splitlines()
    rules = {line.strip() for line in dockerignore if line.strip() and not line.startswith("#")}
    missing = sorted(REQUIRED_IGNORE_RULES - rules)
    if missing:
        problems.append(".dockerignore is missing: " + ", ".join(missing))

    dockerfile = (repository / "Dockerfile").read_text(encoding="utf-8")
    if _BROAD_COPY.search(dockerfile):
        problems.append("Dockerfile must use an explicit COPY allowlist, not COPY/ADD .")

    sensitive = sorted(path for path in _git_files(repository) if is_sensitive_path(path))
    if sensitive:
        problems.append("tracked secret-like build inputs: " + ", ".join(sensitive))
    return tuple(problems)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "repository",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    arguments = parser.parse_args(argv)
    problems = find_violations(arguments.repository.resolve())
    if problems:
        for problem in problems:
            print(f"ERROR: {problem}")
        return 1
    print("container build context policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
