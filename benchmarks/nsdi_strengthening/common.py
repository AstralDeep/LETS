"""Shared, dependency-free evidence helpers for the strengthening experiments."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sqlite3
import statistics
import subprocess
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(*arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository_root(),
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()


def source_identity() -> dict[str, object]:
    status = _git("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "commit": _git("rev-parse", "HEAD"),
        "branch": _git("branch", "--show-current"),
        "dirty": None if status is None else bool(status),
        "tracked_diff": _git("diff", "--stat", "HEAD"),
    }


def environment_identity() -> dict[str, object]:
    return {
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "os_system": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "sqlite_version": sqlite3.sqlite_version,
    }


def nearest_rank(values: Sequence[int], percentage: int) -> int:
    if not values:
        raise ValueError("at least one value is required")
    if not 0 < percentage <= 100:
        raise ValueError("percentage must be in 1..100")
    ordered = sorted(values)
    rank = max(1, (len(ordered) * percentage + 99) // 100)
    return ordered[min(rank - 1, len(ordered) - 1)]


def latency_summary(values: Sequence[int]) -> dict[str, int]:
    if not values:
        raise ValueError("at least one latency sample is required")
    ordered = sorted(values)
    return {
        "samples": len(ordered),
        "minimum_ns": ordered[0],
        "p50_ns": int(statistics.median(ordered)),
        "mean_ns": int(statistics.fmean(ordered)),
        "p95_ns": nearest_rank(ordered, 95),
        "p99_ns": nearest_rank(ordered, 99),
        "maximum_ns": ordered[-1],
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _prepare_output(path: Path, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, value: object, *, overwrite: bool = False) -> None:
    _prepare_output(path, overwrite=overwrite)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_text(path: Path, value: str, *, overwrite: bool = False) -> None:
    _prepare_output(path, overwrite=overwrite)
    path.write_text(value.rstrip() + "\n", encoding="utf-8", newline="\n")


def evidence_manifest(directory: Path, *, exclude: Sequence[str] = ()) -> dict[str, Any]:
    excluded = set(exclude)
    files = []
    for path in sorted(candidate for candidate in directory.rglob("*") if candidate.is_file()):
        relative = path.relative_to(directory).as_posix()
        if relative in excluded:
            continue
        files.append(
            {
                "path": relative,
                "bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return {"schema": "lets.evidence-manifest/v1", "files": files}
