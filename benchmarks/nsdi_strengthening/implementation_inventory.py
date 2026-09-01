"""Generate an exact, evidence-linked implementation and TCB source inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RESULT_SCHEMA = "lets.nsdi-implementation-inventory/v1"
OUTPUT_JSON = "implementation-inventory.json"
OUTPUT_MARKDOWN = "implementation-inventory.md"

NARROW_CORE = (
    "src/lets/authority.py",
    "src/lets/authority_helper.py",
    "src/lets/canonical.py",
    "src/lets/clock.py",
    "src/lets/crypto.py",
    "src/lets/errors.py",
    "src/lets/executor.py",
    "src/lets/executor_authority.py",
    "src/lets/ids.py",
    "src/lets/invariants.py",
    "src/lets/manifest.py",
    "src/lets/models.py",
    "src/lets/policy.py",
    "src/lets/service.py",
    "src/lets/storage/__init__.py",
    "src/lets/storage/schema.py",
    "src/lets/storage/sqlite.py",
    "src/lets/vector.py",
)

FACT_SPECS: tuple[dict[str, Any], ...] = (
    {
        "id": "python-version-range",
        "statement": "The released package supports Python >=3.11 and <3.15.",
        "checks": (("pyproject.toml", r'requires-python\s*=\s*">=3\.11,<3\.15"'),),
    },
    {
        "id": "sqlite-write-atomicity",
        "statement": (
            "Warden and executor stores use explicit-autocommit SQLite connections, WAL, "
            "synchronous=FULL, and BEGIN IMMEDIATE write transactions."
        ),
        "checks": (
            ("src/lets/storage/sqlite.py", r"isolation_level=None"),
            ("src/lets/storage/sqlite.py", r"PRAGMA synchronous = FULL"),
            ("src/lets/storage/sqlite.py", r"PRAGMA journal_mode = WAL"),
            ("src/lets/storage/sqlite.py", r'execute\("BEGIN IMMEDIATE"'),
            ("src/lets/executor.py", r"isolation_level=None"),
            ("src/lets/executor.py", r"PRAGMA synchronous = FULL"),
            ("src/lets/executor.py", r"PRAGMA journal_mode = WAL"),
            ("src/lets/executor.py", r'execute\("BEGIN IMMEDIATE"'),
        ),
    },
    {
        "id": "ed25519-key-format",
        "statement": (
            "Receipts use PyNaCl Ed25519 with 32-byte raw seeds and public keys; key IDs "
            "bind the warden name to a SHA-256 public-key fingerprint prefix."
        ),
        "checks": (
            ("src/lets/crypto.py", r"from nacl\.signing import SigningKey, VerifyKey"),
            ("src/lets/crypto.py", r"len\(seed\) != 32"),
            ("src/lets/crypto.py", r"sha256\(self\.public_key_bytes\)\.hexdigest\(\)\[:32\]"),
            ("src/lets/crypto.py", r'f"\{self\.warden_id\}/ed25519-\{fingerprint\}"'),
        ),
    },
    {
        "id": "canonical-wire-format",
        "statement": (
            "Signed objects use compact, sorted UTF-8 canonical JSON over an integer-only "
            "subset; the strict decoder rejects duplicate keys and floating-point values."
        ),
        "checks": (
            ("src/lets/canonical.py", r'separators=\(",", ":"\)'),
            ("src/lets/canonical.py", r"sort_keys=True"),
            ("src/lets/canonical.py", r"floating-point JSON number is forbidden"),
            ("src/lets/canonical.py", r"duplicate JSON object key"),
        ),
    },
    {
        "id": "operation-identifiers",
        "statement": "Opaque operation identifiers use a validated kind prefix and UUID4 hex.",
        "checks": (("src/lets/ids.py", r'return f"\{kind\}_\{uuid4\(\)\.hex\}"'),),
    },
    {
        "id": "clock-and-uncertainty",
        "statement": (
            "Runtime time is time.time_ns(), and callers declare a non-negative uncertainty "
            "that is checked at authorization and receipt verification boundaries."
        ),
        "checks": (
            ("src/lets/clock.py", r"declared_uncertainty_ns"),
            ("src/lets/clock.py", r"return time\.time_ns\(\)"),
            ("src/lets/executor.py", r"uncertainty > policy\.max_clock_uncertainty_ns"),
            ("src/lets/service.py", r"max_clock_uncertainty_ns"),
        ),
    },
    {
        "id": "executor-claim-store",
        "statement": (
            "The concrete durable executor claim backend inventoried here is a local SQLite "
            "replay store with receipt-claim and per-lease watermark tables."
        ),
        "checks": (
            ("src/lets/executor.py", r"class SQLiteReceiptReplayStore"),
            ("src/lets/executor.py", r"CREATE TABLE receipt_claims"),
            ("src/lets/executor.py", r"CREATE TABLE lease_watermarks"),
        ),
    },
    {
        "id": "rollback-anchors",
        "statement": (
            "Warden and executor rollback anchors have file and process-isolated file "
            "implementations, and their documentation requires an independent rollback domain."
        ),
        "checks": (
            ("src/lets/authority.py", r"class FileAuthorityAnchor"),
            ("src/lets/authority.py", r"class ProcessFileAuthorityAnchor"),
            ("src/lets/executor_authority.py", r"class FileExecutorAuthorityAnchor"),
            ("src/lets/executor_authority.py", r"class ProcessFileExecutorAuthorityAnchor"),
            ("src/lets/executor_authority.py", r"failure/rollback domain independent"),
        ),
    },
)


def _command(arguments: Sequence[str], *, cwd: Path) -> str | None:
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return completed.stdout.strip()


def _git_identity(root: Path) -> dict[str, object]:
    status = _command(("git", "status", "--porcelain=v1", "--untracked-files=all"), cwd=root)
    return {
        "revision": _command(("git", "rev-parse", "HEAD"), cwd=root),
        "tree": _command(("git", "rev-parse", "HEAD^{tree}"), cwd=root),
        "describe": _command(("git", "describe", "--tags", "--always", "--dirty"), cwd=root),
        "dirty": None if status is None else bool(status),
        "status_sha256": None if status is None else hashlib.sha256(status.encode()).hexdigest(),
    }


def _file_record(root: Path, relative: str) -> dict[str, object]:
    path = root / relative
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise RuntimeError(f"could not inventory UTF-8 source file {relative}") from exc
    lines = text.splitlines()
    return {
        "path": relative,
        "physical_lines": len(lines),
        "nonblank_lines": sum(bool(line.strip()) for line in lines),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _source_group(root: Path, files: Sequence[str]) -> dict[str, object]:
    records = [_file_record(root, relative) for relative in files]
    return {
        "file_count": len(records),
        "physical_lines": sum(int(record["physical_lines"]) for record in records),
        "nonblank_lines": sum(int(record["nonblank_lines"]) for record in records),
        "files": records,
    }


def _fact(root: Path, specification: Mapping[str, Any]) -> dict[str, object]:
    evidence: list[dict[str, object]] = []
    for relative, pattern in specification["checks"]:
        path = root / relative
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(f"could not inspect implementation fact source {relative}") from exc
        expression = re.compile(pattern)
        matches = [
            {"line": number, "text": line.strip()}
            for number, line in enumerate(lines, start=1)
            if expression.search(line)
        ]
        if not matches:
            raise RuntimeError(
                f"implementation fact {specification['id']} lost evidence {relative}:/{pattern}/"
            )
        evidence.append(
            {
                "path": relative,
                "pattern": pattern,
                "matches": matches,
            }
        )
    return {
        "id": specification["id"],
        "statement": specification["statement"],
        "verified": True,
        "evidence": evidence,
    }


def generate_inventory(root: Path | None = None) -> dict[str, object]:
    """Return exact source counts and verified implementation facts."""

    repository = Path(__file__).resolve().parents[2] if root is None else root.resolve(strict=True)
    source_root = repository / "src" / "lets"
    if not source_root.is_dir():
        raise ValueError(f"not a LETS repository root: {repository}")
    whole_files = tuple(
        path.relative_to(repository).as_posix()
        for path in sorted(source_root.rglob("*.py"))
        if "__pycache__" not in path.parts
    )
    missing = [relative for relative in NARROW_CORE if not (repository / relative).is_file()]
    if missing:
        raise RuntimeError(f"narrow core inventory paths are missing: {missing}")
    return {
        "schema": RESULT_SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "repository_root": str(repository),
        "git": _git_identity(repository),
        "counting_method": {
            "physical_lines": "UTF-8 str.splitlines() count",
            "nonblank_lines": "physical lines whose Unicode-trimmed content is non-empty",
            "scope_note": (
                "These transparent source-line counts are not semantic SLOC and include "
                "comments and docstrings."
            ),
        },
        "groups": {
            "whole_runtime": _source_group(repository, whole_files),
            "narrow_enforcement_core": _source_group(repository, NARROW_CORE),
        },
        "facts": [_fact(repository, specification) for specification in FACT_SPECS],
        "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def _markdown(inventory: Mapping[str, Any]) -> str:
    groups = inventory["groups"]
    lines = [
        "# LETS implementation inventory",
        "",
        f"- Schema: `{inventory['schema']}`",
        f"- Revision: `{inventory['git']['revision']}`",
        f"- Working tree dirty: `{inventory['git']['dirty']}`",
        "",
        "Counts are transparent physical/nonblank source-line counts, not semantic SLOC.",
        "",
        "| Group | Files | Physical lines | Nonblank lines |",
        "|---|---:|---:|---:|",
    ]
    for identifier, label in (
        ("whole_runtime", "Whole LETS runtime"),
        ("narrow_enforcement_core", "Narrow enforcement core"),
    ):
        group = groups[identifier]
        lines.append(
            f"| {label} | {group['file_count']} | {group['physical_lines']} | "
            f"{group['nonblank_lines']} |"
        )
    lines.extend(("", "## Verified implementation facts", ""))
    for fact in inventory["facts"]:
        citations = []
        for evidence in fact["evidence"]:
            first = evidence["matches"][0]
            citations.append(f"`{evidence['path']}:{first['line']}`")
        lines.append(f"- **{fact['id']}** — {fact['statement']} ({', '.join(citations)})")
    lines.extend(("", "## Narrow enforcement-core files", ""))
    for record in groups["narrow_enforcement_core"]["files"]:
        lines.append(
            f"- `{record['path']}` — {record['physical_lines']} physical, "
            f"{record['nonblank_lines']} nonblank"
        )
    return "\n".join(lines) + "\n"


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8", newline="\n")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_outputs(
    inventory: Mapping[str, Any],
    output: Path,
    *,
    overwrite: bool = False,
) -> tuple[Path, Path]:
    targets = (output / OUTPUT_JSON, output / OUTPUT_MARKDOWN)
    existing = [path for path in targets if path.exists()]
    if existing and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {existing[0]}")
    output.mkdir(parents=True, exist_ok=True)
    _atomic_write(targets[0], json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    _atomic_write(targets[1], _markdown(inventory))
    return targets


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/nsdi-strengthening/implementation"),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    inventory = generate_inventory(arguments.root)
    paths = write_outputs(inventory, arguments.output, overwrite=arguments.overwrite)
    print(json.dumps({"json": str(paths[0]), "markdown": str(paths[1])}))


if __name__ == "__main__":
    main()
