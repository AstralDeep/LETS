"""Stage a generated LETS config as an immutable production runtime input."""

from __future__ import annotations

import argparse
import os
import stat
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any, cast

from lets.canonical import canonical_json, strict_json_loads

DEFAULT_DATABASE_PATH = PurePosixPath("/var/lib/lets/warden.sqlite3")
DEFAULT_REPLAY_DATABASE_PATH = PurePosixPath("/var/lib/lets/peer-replay.sqlite3")
MAX_CONFIG_BYTES = 16_777_216


def _regular_file(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if path.is_symlink():
        raise ValueError(f"{label} must not be a symbolic link")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{label} must name an existing regular file")
    return resolved


def _object(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError(f"generated config exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        decoded = strict_json_loads(path.read_bytes())
    except (UnicodeError, ValueError) as exc:
        raise ValueError("generated config is outside the strict LETS JSON subset") from exc
    if not isinstance(decoded, dict):
        raise ValueError("generated config root must be an object")
    return cast(dict[str, Any], decoded)


def _admit_generated_config(document: Mapping[str, Any], source: Path) -> None:
    if document.get("version") != 1:
        raise ValueError("generated config must use LETS config version 1")
    for name in ("warden_id", "tenant_id", "envelope_id"):
        value = document.get(name)
        if not isinstance(value, str) or not value:
            raise ValueError(f"generated config has no valid {name!r}")
    if document.get("database") != "warden.sqlite3":
        raise ValueError("generated config must use the canonical warden.sqlite3 state path")
    database = _regular_file(source.parent / "warden.sqlite3", "generated state database")
    if database.parent != source.parent:
        raise ValueError("generated state database escaped the config directory")
    replay_database = document.get("replay_database")
    if replay_database is not None:
        if replay_database != "peer-replay.sqlite3":
            raise ValueError(
                "generated config must use the canonical peer-replay.sqlite3 state path"
            )
        replay = _regular_file(
            source.parent / "peer-replay.sqlite3", "generated peer replay database"
        )
        if replay.parent != source.parent:
            raise ValueError("generated peer replay database escaped the config directory")
    runtime = document.get("runtime")
    if not isinstance(runtime, Mapping) or runtime.get("provider") in (None, "", "builtin"):
        raise ValueError("generated config must select an external runtime provider")
    options = runtime.get("options")
    if not isinstance(options, Mapping):
        raise ValueError("generated runtime provider options must be an object")
    if document.get("bootstrap_identities") not in (None, []):
        raise ValueError("generated config contains static bootstrap identities")
    if document.get("allow_insecure_manifest") is not False:
        raise ValueError("generated config was not admitted from a fail-closed signed manifest")
    if "signing_key" in document:
        raise ValueError("generated production config contains a local signing key reference")
    for name in ("manifest", "manifest_digest", "operator_trust"):
        if name not in document:
            raise ValueError(f"generated config is missing production trust field {name!r}")


def stage_config(
    source: Path,
    destination: Path,
    *,
    database_path: PurePosixPath = DEFAULT_DATABASE_PATH,
) -> Path:
    """Create one exclusive, fsynced, read-only config outside writable state."""

    source_file = _regular_file(source, "generated config")
    if not database_path.is_absolute() or database_path != DEFAULT_DATABASE_PATH:
        raise ValueError(
            f"runtime database path must be exactly {DEFAULT_DATABASE_PATH.as_posix()}"
        )
    if not destination.is_absolute():
        raise ValueError("staged config destination must be an absolute path")
    destination_parent = destination.parent.resolve(strict=True)
    if not destination_parent.is_dir():
        raise ValueError("staged config parent must be an existing directory")
    staged = destination_parent / destination.name
    if staged.exists() or staged.is_symlink():
        raise ValueError(f"staged config destination already exists: {staged}")
    if staged.parent == source_file.parent or staged.is_relative_to(source_file.parent):
        raise ValueError("staged config must be outside the writable node state directory")

    document = _object(source_file)
    _admit_generated_config(document, source_file)
    document["database"] = database_path.as_posix()
    if "replay_database" in document:
        document["replay_database"] = DEFAULT_REPLAY_DATABASE_PATH.as_posix()
    payload = canonical_json(document) + b"\n"

    descriptor = -1
    created = False
    try:
        descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(staged, 0o444)
            directory_descriptor = os.open(staged.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        if created:
            with suppress(OSError):
                staged.unlink()
        raise
    if os.name != "nt" and stat.S_IMODE(staged.stat().st_mode) & 0o222:
        raise RuntimeError("staged config retained a write permission")
    return staged


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    arguments = parser.parse_args(argv)
    staged = stage_config(arguments.source, arguments.destination)
    print(f"staged immutable production config: {staged}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
