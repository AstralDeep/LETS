"""Crash-durable, authority-safe recovery bundle primitives.

Recovery bundles deliberately contain a *copy* of the authority checkpoint, not
the independent monotonic authority anchor itself.  Restore admission must
reconcile the bundled database against the live provider-owned anchor.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, cast

from lets.canonical import canonical_json, strict_json_loads
from lets.errors import StorageError, ValidationError

BUNDLE_FORMAT: Final = "LETS-RECOVERY-BUNDLE/1"
_MANIFEST_NAME: Final = "bundle.json"
_ARTIFACT_NAMES: Final[Mapping[str, str]] = {
    "config": "config.json",
    "core_database": "warden.sqlite3",
    "replay_database": "peer-replay.sqlite3",
    "signed_manifest": "cluster-manifest.json",
}
_MAX_BUNDLE_MANIFEST_BYTES: Final = 1_048_576
_MAX_CONFIG_BYTES: Final = 16_777_216
RECOVERY_METADATA_HEADROOM_BYTES: Final = 1_048_576


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    """One exact regular-file binding in a recovery bundle."""

    path: str
    bytes: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "bytes": self.bytes, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class VerifiedBundle:
    """A fully hash- and SQLite-verified bundle."""

    root: Path
    source_schema_version: int
    identity: Mapping[str, object]
    authority_checkpoint: Mapping[str, object] | None
    artifacts: Mapping[str, Path]
    digests: Mapping[str, ArtifactDigest]


def _sha256_file(path: Path) -> tuple[int, str]:
    total = 0
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                total += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise StorageError(f"could not hash recovery artifact: {path}") from exc
    return total, digest.hexdigest()


def _require_regular_file(path: Path, *, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValidationError(f"{label} must be a regular file without symbolic links")


def _fsync_file(path: Path) -> None:
    try:
        with path.open("r+b") as stream:
            os.fsync(stream.fileno())
    except OSError as exc:
        raise StorageError(f"could not durably flush {path}") from exc


def _fsync_directory(path: Path) -> None:
    """Flush a directory entry where the host exposes POSIX directory fsync.

    Windows durable renames use ``MOVEFILE_WRITE_THROUGH`` in
    :func:`_durable_move`; Windows does not expose directory fsync via Python.
    """

    if os.name == "nt":
        return
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError as exc:
        raise StorageError(f"could not durably flush directory {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def require_filesystem_headroom(
    path: Path,
    *,
    required_bytes: int,
    operation: str,
) -> int:
    """Fail before recovery mutation unless an existing directory has exact headroom."""

    if (
        isinstance(required_bytes, bool)
        or not isinstance(required_bytes, int)
        or required_bytes < 0
    ):
        raise ValidationError("recovery headroom requirement must be a non-negative integer")
    if not isinstance(operation, str) or not operation:
        raise ValidationError("recovery headroom operation must be non-empty")
    candidate = Path(os.path.abspath(path))
    is_junction = getattr(candidate, "is_junction", lambda: False)
    if candidate.is_symlink() or is_junction() or not candidate.is_dir():
        raise ValidationError(
            f"{operation} directory must exist and contain no symbolic-link boundary: {candidate}"
        )
    try:
        free = int(shutil.disk_usage(candidate).free)
    except OSError as exc:
        raise StorageError(f"could not inspect filesystem headroom for {operation}") from exc
    if free < required_bytes:
        raise StorageError(
            f"insufficient filesystem headroom for {operation}: "
            f"required={required_bytes}, available={free}"
        )
    return free


def _durable_move(source: Path, destination: Path, *, replace: bool) -> None:
    if os.name == "nt":
        import ctypes

        movefile_replace_existing = 0x1
        movefile_write_through = 0x8
        flags = movefile_write_through | (movefile_replace_existing if replace else 0)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        operation = kernel32.MoveFileExW
        operation.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
        operation.restype = ctypes.c_int
        if not operation(str(source), str(destination), flags):
            error = ctypes.get_last_error()
            raise StorageError(
                f"durable Windows rename failed ({error}): {source} -> {destination}"
            )
        return
    if not replace and destination.exists():
        raise ValidationError(f"destination already exists: {destination}")
    os.replace(source, destination)
    _fsync_directory(destination.parent)


def _copy_regular_file(source: Path, destination: Path, *, maximum: int | None = None) -> None:
    _require_regular_file(source, label=str(source))
    size = source.stat().st_size
    if maximum is not None and size > maximum:
        raise ValidationError(f"recovery input exceeds its {maximum}-byte limit: {source}")
    try:
        with source.open("rb") as reader, destination.open("xb") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
    except OSError as exc:
        raise StorageError(f"could not copy recovery input {source}") from exc


def copy_sqlite_snapshot(source: Path, destination: Path) -> None:
    """Create and fsync one SQLite online-backup snapshot."""

    _require_regular_file(source, label="SQLite source")
    if destination.exists():
        raise ValidationError(f"SQLite backup destination already exists: {destination}")
    source_uri = f"{source.resolve().as_uri()}?mode=ro"
    try:
        with closing(sqlite3.connect(source_uri, uri=True, isolation_level=None)) as origin:
            origin.execute("PRAGMA busy_timeout=5000")
            with closing(sqlite3.connect(destination)) as target:
                origin.backup(target)
                target.commit()
    except sqlite3.Error as exc:
        with suppress(OSError):
            destination.unlink()
        raise StorageError(f"could not create SQLite snapshot from {source}") from exc
    _fsync_file(destination)


def sqlite_diagnostics(
    path: Path,
    *,
    expected_application_id: int,
    expected_schema_version: int | None = None,
    foreign_keys: bool,
) -> dict[str, object]:
    """Verify an immutable bundle database without creating or mutating it."""

    _require_regular_file(path, label="bundled SQLite database")
    uri = f"{path.resolve().as_uri()}?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True)) as connection:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            integrity = tuple(str(row[0]) for row in connection.execute("PRAGMA integrity_check"))
            violation = (
                connection.execute("PRAGMA foreign_key_check").fetchone() if foreign_keys else None
            )
    except sqlite3.Error as exc:
        raise StorageError(f"could not inspect bundled SQLite database: {path}") from exc
    if application_id != expected_application_id:
        raise ValidationError(f"bundled SQLite application identity is invalid: {path}")
    if expected_schema_version is not None and schema_version != expected_schema_version:
        raise ValidationError(
            f"bundled SQLite schema is {schema_version}, expected {expected_schema_version}: {path}"
        )
    if integrity != ("ok",):
        raise ValidationError(f"bundled SQLite integrity check failed: {integrity!r}")
    if violation is not None:
        raise ValidationError("bundled SQLite foreign-key check found a violation")
    return {
        "application_id": application_id,
        "schema_version": schema_version,
        "integrity": list(integrity),
        "foreign_key_violations": 0,
    }


@contextmanager
def node_process_lock(path: Path) -> Iterator[None]:
    """Hold the per-node process lock, failing instead of waiting indefinitely."""

    lock_path = path.resolve()
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        stream = lock_path.open("a+b")
    except OSError as exc:
        raise StorageError(f"could not open LETS node process lock: {lock_path}") from exc
    with stream:
        try:
            if stream.tell() == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
        except OSError as exc:
            raise StorageError(f"could not initialize LETS node process lock: {lock_path}") from exc
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise StorageError(
                    "another LETS process owns this node; stop the server before recovery"
                ) from exc
            try:
                yield
            finally:
                try:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                except OSError as exc:
                    raise StorageError(
                        f"could not release LETS node process lock: {lock_path}"
                    ) from exc
        else:
            import importlib

            fcntl = importlib.import_module("fcntl")
            try:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise StorageError(
                    "another LETS process owns this node; stop the server before recovery"
                ) from exc
            try:
                yield
            finally:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError as exc:
                    raise StorageError(
                        f"could not release LETS node process lock: {lock_path}"
                    ) from exc


def create_recovery_bundle(
    *,
    destination: Path,
    config_path: Path,
    core_database: Path,
    replay_database: Path | None,
    signed_manifest: Path | None,
    source_schema_version: int,
    identity: Mapping[str, object],
    authority_checkpoint: Mapping[str, object] | None,
) -> VerifiedBundle:
    """Create an exclusive recovery directory and publish it with a durable rename."""

    final = destination.resolve()
    if final.exists():
        raise ValidationError(f"recovery bundle destination already exists: {final}")
    final.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{final.name}.", suffix=".tmp", dir=final.parent))
    published = False
    try:
        artifact_paths: dict[str, Path] = {}
        config_target = staging / _ARTIFACT_NAMES["config"]
        _copy_regular_file(config_path, config_target, maximum=_MAX_CONFIG_BYTES)
        artifact_paths["config"] = config_target

        core_target = staging / _ARTIFACT_NAMES["core_database"]
        copy_sqlite_snapshot(core_database, core_target)
        artifact_paths["core_database"] = core_target
        if replay_database is not None:
            replay_target = staging / _ARTIFACT_NAMES["replay_database"]
            copy_sqlite_snapshot(replay_database, replay_target)
            artifact_paths["replay_database"] = replay_target

        if signed_manifest is not None:
            manifest_target = staging / _ARTIFACT_NAMES["signed_manifest"]
            _copy_regular_file(signed_manifest, manifest_target, maximum=_MAX_CONFIG_BYTES)
            artifact_paths["signed_manifest"] = manifest_target

        digests: dict[str, ArtifactDigest] = {}
        for name, artifact_path in sorted(artifact_paths.items()):
            size, digest = _sha256_file(artifact_path)
            digests[name] = ArtifactDigest(
                path=artifact_path.name,
                bytes=size,
                sha256=digest,
            )
        document: dict[str, object] = {
            "format": BUNDLE_FORMAT,
            "created_at_ns": time.time_ns(),
            "source_schema_version": source_schema_version,
            "identity": dict(identity),
            "authority_checkpoint": (
                None if authority_checkpoint is None else dict(authority_checkpoint)
            ),
            "artifacts": {name: digest.to_dict() for name, digest in sorted(digests.items())},
        }
        manifest_target = staging / _MANIFEST_NAME
        payload = canonical_json(document) + b"\n"
        with manifest_target.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(staging)
        _durable_move(staging, final, replace=False)
        published = True
        return verify_recovery_bundle(final)
    finally:
        if not published:
            with suppress(OSError):
                shutil.rmtree(staging)


def _bounded_manifest(path: Path) -> Mapping[str, Any]:
    _require_regular_file(path, label="recovery bundle manifest")
    try:
        manifest_size = path.stat().st_size
    except OSError as exc:
        raise StorageError(f"could not inspect recovery bundle manifest: {path}") from exc
    if manifest_size > _MAX_BUNDLE_MANIFEST_BYTES:
        raise ValidationError("recovery bundle manifest exceeds its size limit")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StorageError(f"could not read recovery bundle manifest: {path}") from exc
    if len(raw) > _MAX_BUNDLE_MANIFEST_BYTES:
        raise ValidationError("recovery bundle manifest exceeds its size limit")
    try:
        decoded = strict_json_loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValidationError("recovery bundle manifest is outside LETS-CJ/1") from exc
    if not isinstance(decoded, Mapping):
        raise ValidationError("recovery bundle manifest root must be an object")
    return cast(Mapping[str, Any], decoded)


def verify_recovery_bundle(destination: Path) -> VerifiedBundle:
    """Verify exact artifact membership, hashes, and each declared SQLite database."""

    requested = Path(os.path.abspath(destination))
    is_junction = getattr(requested, "is_junction", lambda: False)
    if requested.is_symlink() or is_junction() or not requested.is_dir():
        raise ValidationError("recovery bundle must be a directory without symbolic links")
    root = requested.resolve()
    document = _bounded_manifest(root / _MANIFEST_NAME)
    expected = {
        "format",
        "created_at_ns",
        "source_schema_version",
        "identity",
        "authority_checkpoint",
        "artifacts",
    }
    if set(document) != expected or document.get("format") != BUNDLE_FORMAT:
        raise ValidationError("recovery bundle fields or format are invalid")
    created_at = document.get("created_at_ns")
    schema_version = document.get("source_schema_version")
    if (
        isinstance(created_at, bool)
        or not isinstance(created_at, int)
        or created_at < 0
        or isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version < 1
    ):
        raise ValidationError("recovery bundle timestamps or schema version are invalid")
    identity = document.get("identity")
    checkpoint = document.get("authority_checkpoint")
    raw_artifacts = document.get("artifacts")
    if not isinstance(identity, Mapping):
        raise ValidationError("recovery bundle identity must be an object")
    if checkpoint is not None and not isinstance(checkpoint, Mapping):
        raise ValidationError("recovery bundle authority checkpoint must be an object or null")
    if not isinstance(raw_artifacts, Mapping):
        raise ValidationError("recovery bundle artifacts must be an object")
    required = {"config", "core_database"}
    names = set(raw_artifacts)
    if (
        not required.issubset(names)
        or not names.issubset(set(_ARTIFACT_NAMES))
        or (schema_version == 1 and "replay_database" not in names)
        or (schema_version >= 2 and "replay_database" in names)
    ):
        raise ValidationError("recovery bundle artifact set is invalid")

    paths: dict[str, Path] = {}
    digests: dict[str, ArtifactDigest] = {}
    expected_files = {_MANIFEST_NAME}
    for name in sorted(names):
        raw_digest = raw_artifacts[name]
        if not isinstance(name, str) or not isinstance(raw_digest, Mapping):
            raise ValidationError("recovery bundle artifact entries are malformed")
        if set(raw_digest) != {"path", "bytes", "sha256"}:
            raise ValidationError("recovery bundle artifact digest fields are invalid")
        relative = raw_digest.get("path")
        byte_count = raw_digest.get("bytes")
        digest = raw_digest.get("sha256")
        if relative != _ARTIFACT_NAMES[name]:
            raise ValidationError("recovery bundle artifact path is not canonical")
        if (
            isinstance(byte_count, bool)
            or not isinstance(byte_count, int)
            or byte_count < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValidationError("recovery bundle artifact digest is malformed")
        artifact_path = root / relative
        _require_regular_file(artifact_path, label=f"recovery artifact {name}")
        actual_size, actual_digest = _sha256_file(artifact_path)
        if (actual_size, actual_digest) != (byte_count, digest):
            raise ValidationError(f"recovery artifact {name!r} does not match its exact digest")
        expected_files.add(relative)
        paths[name] = artifact_path
        digests[name] = ArtifactDigest(relative, byte_count, digest)

    actual_files: set[str] = set()
    for entry in root.iterdir():
        actual_files.add(entry.name)
        if len(actual_files) > len(_ARTIFACT_NAMES) + 1:
            raise ValidationError("recovery bundle contains too many filesystem entries")
    if actual_files != expected_files:
        raise ValidationError("recovery bundle contains unlisted or missing filesystem entries")

    from lets.auth import SQLitePeerReplayStore
    from lets.storage.schema import APPLICATION_ID

    sqlite_diagnostics(
        paths["core_database"],
        expected_application_id=APPLICATION_ID,
        expected_schema_version=schema_version,
        foreign_keys=True,
    )
    if "replay_database" in paths:
        sqlite_diagnostics(
            paths["replay_database"],
            expected_application_id=SQLitePeerReplayStore.APPLICATION_ID,
            expected_schema_version=SQLitePeerReplayStore.SCHEMA_VERSION,
            foreign_keys=False,
        )
    return VerifiedBundle(
        root=root,
        source_schema_version=schema_version,
        identity=cast(Mapping[str, object], identity),
        authority_checkpoint=(
            None if checkpoint is None else cast(Mapping[str, object], checkpoint)
        ),
        artifacts=paths,
        digests=digests,
    )


def install_verified_artifact(
    source: Path,
    destination: Path,
    *,
    expected: ArtifactDigest | None = None,
) -> None:
    """Copy one artifact and atomically replace its destination.

    When ``expected`` comes from a previously verified bundle manifest, the
    installed bytes are checked against that immutable authority instead of a
    second observation of a potentially changing source path.
    """

    _require_regular_file(source, label="recovery publication source")
    requested_target = Path(os.path.abspath(destination))
    target_junction = getattr(requested_target, "is_junction", lambda: False)
    if requested_target.is_symlink() or target_junction():
        raise ValidationError("recovery publication target must not be a symbolic link")
    target = requested_target.resolve()
    if requested_target.parent.resolve() != target.parent:
        raise ValidationError("recovery publication target crosses a symbolic-link boundary")
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".restore", dir=target.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        with source.open("rb") as reader, temporary.open("r+b") as writer:
            shutil.copyfileobj(reader, writer, length=1024 * 1024)
            writer.flush()
            os.fsync(writer.fileno())
        copied_size, copied_hash = _sha256_file(temporary)
        if expected is None:
            admitted_size, admitted_hash = _sha256_file(source)
        else:
            admitted_size, admitted_hash = expected.bytes, expected.sha256
        if (copied_size, copied_hash) != (admitted_size, admitted_hash):
            raise StorageError("restored artifact copy failed its post-copy digest check")
        _durable_move(temporary, target, replace=True)
    finally:
        with suppress(OSError):
            temporary.unlink()


def preserve_and_remove_artifact(source: Path, destination: Path) -> None:
    """Idempotently copy a sidecar to quarantine, then durably remove its source."""

    requested_target = Path(os.path.abspath(destination))
    if requested_target.exists():
        _require_regular_file(
            requested_target,
            label="recovery preservation target",
        )
        source_junction = getattr(source, "is_junction", lambda: False)
        if source.is_symlink() or source_junction():
            raise ValidationError(f"refusing unsafe recovery preservation source: {source}")
        if not source.exists():
            return
        _require_regular_file(source, label="recovery preservation source")
        source_size, source_hash = _sha256_file(source)
        target_size, target_hash = _sha256_file(requested_target)
        if (source_size, source_hash) != (target_size, target_hash):
            raise ValidationError(
                "live and preserved recovery sidecars differ after an interrupted copy"
            )
        try:
            source.unlink()
        except OSError as exc:
            raise StorageError(f"could not remove preserved recovery source: {source}") from exc
        _fsync_directory(source.parent.resolve())
        return

    _require_regular_file(source, label="recovery preservation source")
    original = source.resolve()
    target = requested_target.resolve()
    install_verified_artifact(original, target)
    try:
        original.unlink()
    except OSError as exc:
        raise StorageError(f"could not remove preserved recovery source: {original}") from exc
    _fsync_directory(original.parent)


def create_recovery_quarantine(quarantine: Path, *, workspace: Path) -> Path:
    """Create and durably publish one empty direct-child quarantine directory."""

    root = Path(os.path.abspath(quarantine))
    boundary = workspace.resolve()
    if root.parent.resolve() != boundary:
        raise ValidationError("recovery quarantine is outside its exact workspace boundary")
    try:
        root.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ValidationError(f"recovery quarantine already exists: {root}") from exc
    except OSError as exc:
        raise StorageError(f"could not create recovery quarantine: {root}") from exc
    _fsync_directory(boundary)
    return root.resolve()


def remove_recovery_quarantine(
    quarantine: Path,
    *,
    workspace: Path,
    expected_names: frozenset[str],
) -> None:
    """Remove one fully admitted quarantine with an exact, non-recursive allow-list."""

    requested = Path(os.path.abspath(quarantine))
    requested_junction = getattr(requested, "is_junction", lambda: False)
    if requested.is_symlink() or requested_junction():
        raise ValidationError("recovery quarantine must not be a symbolic-link boundary")
    root = requested.resolve()
    boundary = workspace.resolve()
    if root == boundary or root.parent != boundary:
        raise ValidationError("recovery quarantine is outside its exact workspace boundary")
    if not root.exists():
        return
    if not root.is_dir():
        raise ValidationError("recovery quarantine must be a regular directory")
    entries = tuple(root.iterdir())
    unexpected = {
        entry.name
        for entry in entries
        if entry.name not in expected_names
        and not any(
            entry.name.startswith(f".{expected}.") and entry.name.endswith(".restore")
            for expected in expected_names
        )
    }
    if unexpected:
        raise ValidationError(
            f"recovery quarantine contains unexpected artifacts: {sorted(unexpected)}"
        )
    for entry in entries:
        entry_junction = getattr(entry, "is_junction", lambda: False)
        if entry.is_symlink() or entry_junction() or not entry.is_file():
            raise ValidationError(f"refusing unsafe recovery quarantine artifact: {entry}")
    for entry in entries:
        try:
            entry.unlink()
        except OSError as exc:
            raise StorageError(f"could not remove recovery quarantine artifact: {entry}") from exc
    try:
        root.rmdir()
    except OSError as exc:
        raise StorageError(f"could not remove empty recovery quarantine: {root}") from exc
    _fsync_directory(boundary)


def read_sqlite_header(path: Path) -> tuple[int, int]:
    """Return ``(application_id, user_version)`` without creating a database."""

    _require_regular_file(path, label="SQLite database")
    try:
        with closing(sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)) as connection:
            return (
                int(connection.execute("PRAGMA application_id").fetchone()[0]),
                int(connection.execute("PRAGMA user_version").fetchone()[0]),
            )
    except sqlite3.Error as exc:
        raise StorageError(f"could not read SQLite database header: {path}") from exc


__all__ = [
    "BUNDLE_FORMAT",
    "RECOVERY_METADATA_HEADROOM_BYTES",
    "ArtifactDigest",
    "VerifiedBundle",
    "copy_sqlite_snapshot",
    "create_recovery_bundle",
    "create_recovery_quarantine",
    "install_verified_artifact",
    "node_process_lock",
    "preserve_and_remove_artifact",
    "read_sqlite_header",
    "remove_recovery_quarantine",
    "require_filesystem_headroom",
    "sqlite_diagnostics",
    "verify_recovery_bundle",
]
