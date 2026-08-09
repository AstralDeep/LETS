"""Validate a fail-closed LETS production Compose environment file."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath

REQUIRED_DIRECTORIES = (
    "LETS_STATE_DIR",
    "LETS_AUTHORITY_DIR",
    "LETS_AUDIT_DIR",
    "LETS_BACKUP_DIR",
    "LETS_TRUST_DIR",
)
REQUIRED_FILES = (
    "LETS_CONFIG_FILE",
    "LETS_TLS_CERT_FILE",
    "LETS_TLS_KEY_FILE",
    "LETS_CLIENT_CA_FILE",
    "LETS_PEER_CA_FILE",
    "LETS_PEER_CERT_FILE",
    "LETS_PEER_KEY_FILE",
)
PRIVATE_KEY_FILES = ("LETS_TLS_KEY_FILE", "LETS_PEER_KEY_FILE")
TLS_TRUST_FILES = (
    "LETS_TLS_CERT_FILE",
    "LETS_TLS_KEY_FILE",
    "LETS_CLIENT_CA_FILE",
    "LETS_PEER_CA_FILE",
    "LETS_PEER_CERT_FILE",
    "LETS_PEER_KEY_FILE",
)
WRITABLE_DIRECTORIES = (
    "LETS_STATE_DIR",
    "LETS_AUTHORITY_DIR",
    "LETS_AUDIT_DIR",
    "LETS_BACKUP_DIR",
)
_IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_PROVIDER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_BOUNDED_INTEGERS = {
    "LETS_PORT": (1, 65_535),
    "LETS_BACKLOG": (1, 65_535),
    "LETS_LIMIT_CONCURRENCY": (1, 3600),
    "LETS_REQUEST_BODY_TIMEOUT_SECONDS": (1, 300),
    "LETS_TIMEOUT_KEEP_ALIVE": (1, 3600),
    "LETS_TIMEOUT_GRACEFUL_SHUTDOWN": (1, 40),
    "LETS_HEALTH_START_PERIOD_SECONDS": (60, 86_400),
}
_AUDIT_BOUNDED_INTEGERS = {
    "LETS_AUDIT_CAPACITY_BYTES": (1, 2**63 - 1),
    "LETS_AUDIT_EXPECTED_DAILY_BYTES": (1, 2**63 - 1),
    "LETS_AUDIT_FORECAST_DAYS": (1, 36_500),
    "LETS_AUDIT_MIN_FREE_BYTES": (1, 2**63 - 1),
}
_STATE_BOUNDARIES = frozenset({"dedicated-filesystem", "enforced-quota"})
_STORAGE_BOUNDARY_REQUIREMENTS = {
    "LETS_AUTHORITY_STORAGE_BOUNDARY": frozenset({"fenced-filesystem"}),
    "LETS_BACKUP_STORAGE_BOUNDARY": frozenset({"dedicated-filesystem"}),
}
_ROLLBACK_DOMAIN_FIELDS = (
    "LETS_STATE_ROLLBACK_DOMAIN",
    "LETS_AUTHORITY_ROLLBACK_DOMAIN",
    "LETS_AUDIT_ROLLBACK_DOMAIN",
    "LETS_BACKUP_ROLLBACK_DOMAIN",
)
_ROLLBACK_DIRECTORIES = (
    "LETS_STATE_DIR",
    "LETS_AUTHORITY_DIR",
    "LETS_AUDIT_DIR",
    "LETS_BACKUP_DIR",
)
_MOUNT_BOUNDARY_FIELDS = {
    "LETS_STATE_DIR": "LETS_STATE_STORAGE_BOUNDARY",
    "LETS_AUTHORITY_DIR": "LETS_AUTHORITY_STORAGE_BOUNDARY",
    "LETS_AUDIT_DIR": "LETS_AUDIT_STORAGE_BOUNDARY",
    "LETS_BACKUP_DIR": "LETS_BACKUP_STORAGE_BOUNDARY",
}
_ROLLBACK_DOMAIN = re.compile(r"^[a-z][a-z0-9+.-]{1,31}://[A-Za-z0-9][A-Za-z0-9._~:/-]{2,254}$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_CPU_LIMIT = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_MEMORY_LIMIT = re.compile(r"^([1-9][0-9]*)([kKmMgG])$")
_FORBIDDEN_SIGNER_EXECUTABLE = re.compile(
    r"^(?:env|(?:ba|da|a|z|k|fi)?sh|pwsh|powershell|python(?:[0-9.]*)?|node|perl|"
    r"ruby|php|java|"
    r"ld(?:[.-].*)?)$",
    re.IGNORECASE,
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_TRUST_ENTRIES = 4096
_FORBIDDEN_STORAGE_FILESYSTEMS = frozenset(
    {
        "9p",
        "afs",
        "aufs",
        "ceph",
        "cifs",
        "devtmpfs",
        "fuse",
        "fuseblk",
        "glusterfs",
        "lustre",
        "nfs",
        "nfs4",
        "overlay",
        "proc",
        "ramfs",
        "smb3",
        "squashfs",
        "sysfs",
        "tmpfs",
        "virtiofs",
    }
)


@dataclass(frozen=True)
class StorageMount:
    mount_id: int
    device: str
    root: PurePosixPath
    mount_point: PurePosixPath
    filesystem_type: str
    source: str
    has_descendant_mount: bool


def _storage_domain_errors(values: Mapping[str, str]) -> tuple[str, ...]:
    errors: list[str] = []
    for field, admitted in _STORAGE_BOUNDARY_REQUIREMENTS.items():
        value = values.get(field, "")
        if value not in admitted:
            choices = " or ".join(sorted(admitted))
            errors.append(f"{field} must be {choices}")

    domains: dict[str, str] = {}
    for field in _ROLLBACK_DOMAIN_FIELDS:
        value = values.get(field, "")
        if _ROLLBACK_DOMAIN.fullmatch(value) is None:
            errors.append(f"{field} must be an explicit scheme://controller-or-volume identifier")
            continue
        normalized = value.casefold()
        previous = domains.get(normalized)
        if previous is not None:
            errors.append(f"{field} and {previous} must name independent rollback domains")
        else:
            domains[normalized] = field
    return tuple(errors)


def _storage_device(path: Path) -> int:
    return int(path.stat().st_dev)


def _storage_device_numbers(device: int) -> tuple[int, int]:
    if os.name != "posix":
        raise ValueError("Linux device-number inspection is unavailable")
    major = getattr(os, "major", None)
    minor = getattr(os, "minor", None)
    if not callable(major) or not callable(minor):
        raise ValueError("Linux device-number inspection is unavailable")
    return int(major(device)), int(minor(device))


def _mountinfo_path(value: str) -> PurePosixPath:
    decoded = value
    for escaped, replacement in (
        (r"\040", " "),
        (r"\011", "\t"),
        (r"\012", "\n"),
        (r"\134", "\\"),
    ):
        decoded = decoded.replace(escaped, replacement)
    return PurePosixPath(decoded)


def _parse_mountinfo(document: str) -> tuple[StorageMount, ...]:
    records: list[tuple[int, str, PurePosixPath, PurePosixPath, str, str]] = []
    for line_number, line in enumerate(document.splitlines(), start=1):
        fields = line.split()
        try:
            separator = fields.index("-")
            mount_id = int(fields[0])
            device = fields[2]
            root = _mountinfo_path(fields[3])
            mount_point = _mountinfo_path(fields[4])
            filesystem_type = fields[separator + 1]
            source = fields[separator + 2]
        except (IndexError, ValueError) as exc:
            raise ValueError(f"/proc/self/mountinfo line {line_number} is malformed") from exc
        if re.fullmatch(r"[0-9]+:[0-9]+", device) is None:
            raise ValueError(f"/proc/self/mountinfo line {line_number} has an invalid device")
        records.append((mount_id, device, root, mount_point, filesystem_type, source))

    observations: list[StorageMount] = []
    for mount_id, device, root, mount_point, filesystem_type, source in records:
        descendant = any(
            other != mount_point and other.is_relative_to(mount_point)
            for *_, other, _filesystem_type, _source in records
        )
        observations.append(
            StorageMount(
                mount_id=mount_id,
                device=device,
                root=root,
                mount_point=mount_point,
                filesystem_type=filesystem_type,
                source=source,
                has_descendant_mount=descendant,
            )
        )
    return tuple(observations)


def _storage_mount(path: Path) -> StorageMount:
    if os.name != "posix":
        raise ValueError(
            "production storage mount evidence requires a Linux host; Docker Desktop paths "
            "are not an admitted production storage boundary"
        )
    mountinfo = Path("/proc/self/mountinfo")
    try:
        observations = _parse_mountinfo(mountinfo.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError("production storage mount evidence is unavailable") from exc
    candidate_path = PurePosixPath(path.as_posix())
    candidates = [
        observation
        for observation in observations
        if candidate_path == observation.mount_point
        or candidate_path.is_relative_to(observation.mount_point)
    ]
    if not candidates:
        raise ValueError(f"no Linux mount record contains production storage path: {path}")
    return max(candidates, key=lambda observation: len(observation.mount_point.parts))


def _storage_device_errors(directories: Mapping[str, Path]) -> tuple[str, ...]:
    errors: list[str] = []
    devices: dict[int, str] = {}
    for field in _ROLLBACK_DIRECTORIES:
        path = directories.get(field)
        if path is None:
            continue
        try:
            device = _storage_device(path)
        except OSError as exc:
            errors.append(f"{field} storage device could not be inspected: {exc}")
            continue
        previous = devices.get(device)
        if previous is not None:
            errors.append(
                f"{field} and {previous} must be on distinct mounted filesystems; "
                "an enforced quota does not create a rollback or failure domain"
            )
        else:
            devices[device] = field
    return tuple(errors)


def _storage_mount_errors(
    values: Mapping[str, str], directories: Mapping[str, Path]
) -> tuple[str, ...]:
    errors: list[str] = []
    mount_owners: dict[int, str] = {}
    for field in _ROLLBACK_DIRECTORIES:
        path = directories.get(field)
        if path is None:
            continue
        try:
            observation = _storage_mount(path)
        except (OSError, ValueError) as exc:
            errors.append(f"{field} mount evidence failed: {exc}")
            continue
        previous = mount_owners.get(observation.mount_id)
        if previous is not None:
            errors.append(f"{field} and {previous} must not share a Linux mount record")
        else:
            mount_owners[observation.mount_id] = field
        boundary_field = _MOUNT_BOUNDARY_FIELDS[field]
        boundary = values.get(boundary_field, "")
        configured = PurePosixPath(path.as_posix())
        if configured != observation.mount_point:
            errors.append(f"{field} must be the exact mountpoint for {boundary_field}={boundary}")
        filesystem_type = observation.filesystem_type.casefold()
        family = filesystem_type.split(".", 1)[0]
        if filesystem_type in _FORBIDDEN_STORAGE_FILESYSTEMS or (
            family in _FORBIDDEN_STORAGE_FILESYSTEMS
        ):
            errors.append(
                f"{field} uses unsupported production filesystem {observation.filesystem_type!r}"
            )
        if observation.has_descendant_mount:
            errors.append(f"{field} must not contain nested mountpoints")
        try:
            major_text, minor_text = observation.device.split(":", 1)
            device = _storage_device(path)
            if _storage_device_numbers(device) != (int(major_text), int(minor_text)):
                errors.append(f"{field} mount record changed during validation")
        except (AttributeError, OSError, ValueError) as exc:
            errors.append(f"{field} mount device could not be cross-checked: {exc}")
    return tuple(errors)


def _storage_fingerprint(values: Mapping[str, str]) -> tuple[tuple[object, ...], ...]:
    fingerprints: list[tuple[object, ...]] = []
    for field in _ROLLBACK_DIRECTORIES:
        path = Path(_required(values, field)).resolve(strict=True)
        metadata = path.stat()
        observation = _storage_mount(path)
        fingerprints.append(
            (
                field,
                str(path),
                int(metadata.st_dev),
                int(metadata.st_ino),
                observation.mount_id,
                observation.device,
                observation.root.as_posix(),
                observation.mount_point.as_posix(),
                observation.filesystem_type,
                observation.source,
            )
        )
    return tuple(fingerprints)


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    junction = getattr(path, "is_junction", None)
    if callable(junction) and bool(junction()):
        return True
    metadata = os.lstat(path)
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    return bool(attributes & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)))


def _reject_link_components(path: Path, field: str) -> None:
    if any(part in {".", ".."} for part in path.parts):
        raise ValueError(f"{field} must not contain dot path components")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if current.exists() and _is_link_or_reparse(current):
            raise ValueError(f"{field} must not contain symbolic links or reparse points")


def _trust_tree_errors(root: Path) -> tuple[str, ...]:
    errors: list[str] = []
    pending = [root]
    entries = 0
    while pending:
        path = pending.pop()
        entries += 1
        if entries > _MAX_TRUST_ENTRIES:
            errors.append(f"LETS_TRUST_DIR exceeds {_MAX_TRUST_ENTRIES} filesystem entries")
            break
        try:
            if _is_link_or_reparse(path):
                errors.append(f"LETS_TRUST_DIR contains a linked or reparse path: {path}")
                continue
            metadata = path.stat()
        except OSError as exc:
            errors.append(f"LETS_TRUST_DIR entry could not be inspected: {path}: {exc}")
            continue
        if path.is_dir():
            try:
                pending.extend(path.iterdir())
            except OSError as exc:
                errors.append(f"LETS_TRUST_DIR directory could not be enumerated: {path}: {exc}")
        elif path.is_file():
            if metadata.st_nlink != 1:
                errors.append(f"LETS_TRUST_DIR file must not be hard linked: {path}")
        else:
            errors.append(f"LETS_TRUST_DIR contains a non-file entry: {path}")
        if os.name != "nt":
            if metadata.st_uid == 10001:
                errors.append(f"LETS_TRUST_DIR entry must not be owned by UID 10001: {path}")
            if stat.S_IMODE(metadata.st_mode) & 0o022:
                errors.append(
                    f"LETS_TRUST_DIR entry must not grant group/other write permissions: {path}"
                )
    return tuple(errors)


def _mapped_trust_file(trust_directory: Path, value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"LETS_CONFIG_FILE {field} must be a trust-container path")
    root = PurePosixPath("/etc/lets/trust")
    container_path = PurePosixPath(value)
    if (
        not container_path.is_absolute()
        or ".." in container_path.parts
        or container_path == root
        or not container_path.is_relative_to(root)
    ):
        raise ValueError(f"LETS_CONFIG_FILE {field} must name a file below {root.as_posix()}")
    relative = container_path.relative_to(root)
    host_path = trust_directory.joinpath(*relative.parts)
    _reject_link_components(host_path, f"LETS_CONFIG_FILE {field}")
    resolved = host_path.resolve(strict=True)
    if not resolved.is_file() or not resolved.is_relative_to(trust_directory):
        raise ValueError(f"LETS_CONFIG_FILE {field} does not map to a regular trust file")
    return resolved


def _server_name(value: str) -> None:
    if len(value) > 253 or value != value.strip():
        raise ValueError("LETS_SERVER_NAME must be a bounded DNS name or IP address")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("LETS_SERVER_NAME must be ASCII") from exc
    with suppress(ValueError):
        ipaddress.ip_address(value)
        return
    labels = value[:-1].split(".") if value.endswith(".") else value.split(".")
    if not labels or any(_DNS_LABEL.fullmatch(label) is None for label in labels):
        raise ValueError("LETS_SERVER_NAME must be a bounded DNS name or IP address")


def _resource_errors(values: Mapping[str, str]) -> tuple[str, ...]:
    errors: list[str] = []
    bind_address = values.get("LETS_BIND_ADDRESS")
    if bind_address is not None:
        try:
            ipaddress.ip_address(bind_address)
        except ValueError:
            errors.append("LETS_BIND_ADDRESS must be an IPv4 or IPv6 address")
    cpu_text = values.get("LETS_CPUS")
    if cpu_text is not None:
        try:
            if _CPU_LIMIT.fullmatch(cpu_text) is None:
                raise InvalidOperation
            cpus = Decimal(cpu_text)
        except InvalidOperation:
            errors.append("LETS_CPUS must be a decimal number")
        else:
            if not cpus.is_finite() or not Decimal("0.1") <= cpus <= Decimal("128"):
                errors.append("LETS_CPUS must be between 0.1 and 128")
    memory_text = values.get("LETS_MEMORY_LIMIT")
    if memory_text is not None:
        match = _MEMORY_LIMIT.fullmatch(memory_text)
        if match is None:
            errors.append("LETS_MEMORY_LIMIT must use a positive k, m, or g suffix")
        else:
            multipliers = {"k": 1024, "m": 1024**2, "g": 1024**3}
            memory_bytes = int(match.group(1)) * multipliers[match.group(2).casefold()]
            if not 256 * 1024**2 <= memory_bytes <= 256 * 1024**3:
                errors.append("LETS_MEMORY_LIMIT must be between 256m and 256g")
    return tuple(errors)


def _generic_provider_errors(options: Mapping[str, object]) -> tuple[str, ...]:
    required_paths = {
        "identity_keys_file": PurePosixPath("/etc/lets/trust"),
        "authority_anchor_path": PurePosixPath("/var/lib/lets-authority"),
        "audit_archive_path": PurePosixPath("/var/lib/lets-audit"),
    }
    required = frozenset(
        {
            "signer_command_json",
            "signer_key_id",
            "signer_public_key",
            "identity_keys_file",
            "identity_issuer",
            "identity_audience",
            "authority_anchor_path",
            "audit_archive_path",
        }
    )
    errors: list[str] = []
    missing = sorted(required - options.keys())
    if missing:
        errors.append("generic-production runtime options are missing: " + ", ".join(missing))
    for name, root in required_paths.items():
        value = options.get(name)
        if not isinstance(value, str):
            errors.append(f"generic-production {name} must be an absolute container path")
            continue
        path = PurePosixPath(value)
        if (
            not path.is_absolute()
            or ".." in path.parts
            or path == root
            or not path.is_relative_to(root)
        ):
            errors.append(f"generic-production {name} must name a file below {root.as_posix()}")

    encoded_command = options.get("signer_command_json")
    if not isinstance(encoded_command, str):
        errors.append("generic-production signer_command_json must be JSON text")
    else:
        try:
            command = json.loads(encoded_command)
        except json.JSONDecodeError:
            errors.append("generic-production signer_command_json must be valid JSON")
        else:
            if (
                not isinstance(command, list)
                or not command
                or any(not isinstance(item, str) or not item for item in command)
            ):
                errors.append(
                    "generic-production signer_command_json must contain a non-empty argument array"
                )
            else:
                executable = PurePosixPath(command[0])
                mutable_roots = (
                    PurePosixPath("/var/lib/lets"),
                    PurePosixPath("/var/lib/lets-authority"),
                    PurePosixPath("/var/lib/lets-audit"),
                    PurePosixPath("/var/lib/lets-backup"),
                    PurePosixPath("/tmp"),
                    PurePosixPath("/run"),
                )
                if (
                    not executable.is_absolute()
                    or ".." in executable.parts
                    or any(
                        executable == root or executable.is_relative_to(root)
                        for root in mutable_roots
                    )
                ):
                    errors.append(
                        "generic-production signer executable must be an absolute immutable-image "
                        "path outside writable and ephemeral mounts"
                    )
                if _FORBIDDEN_SIGNER_EXECUTABLE.fullmatch(executable.name) is not None:
                    errors.append(
                        "generic-production signer executable must be a dedicated helper, not an "
                        "interpreter, shell, environment launcher, or dynamic loader"
                    )
                for argument in command[1:]:
                    candidate_texts = [argument]
                    if "=" in argument:
                        candidate_texts.append(argument.split("=", 1)[1])
                    for candidate_text in candidate_texts:
                        candidate = PurePosixPath(candidate_text)
                        if ".." in candidate.parts:
                            errors.append(
                                "generic-production signer arguments must not contain parent "
                                "traversal"
                            )
                            continue
                        if candidate.is_absolute() and any(
                            candidate == root or candidate.is_relative_to(root)
                            for root in mutable_roots
                        ):
                            errors.append(
                                "generic-production signer arguments must not load code or "
                                "configuration from writable or ephemeral mounts"
                            )
    return tuple(errors)


def _positive_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"LETS_CONFIG_FILE {field} must be a positive integer")
    return value


def _sqlite_page_size(database: Path) -> int:
    if _is_link_or_reparse(database):
        raise ValueError(
            "LETS_STATE_DIR/warden.sqlite3 must not be a symbolic link or reparse point"
        )
    resolved = database.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("LETS_STATE_DIR/warden.sqlite3 must be an existing regular file")
    if resolved.stat().st_nlink != 1:
        raise ValueError("LETS_STATE_DIR/warden.sqlite3 must not be hard linked")
    with resolved.open("rb") as stream:
        header = stream.read(18)
    if len(header) != 18 or header[:16] != b"SQLite format 3\x00":
        raise ValueError("LETS_STATE_DIR/warden.sqlite3 has no valid SQLite header")
    encoded = int.from_bytes(header[16:18], "big")
    page_size = 65_536 if encoded == 1 else encoded
    if page_size < 512 or page_size > 65_536 or page_size & (page_size - 1):
        raise ValueError("LETS_STATE_DIR/warden.sqlite3 uses an invalid SQLite page size")
    return page_size


def _capacity_errors(
    values: Mapping[str, str],
    document: Mapping[str, object],
    state_directory: Path,
) -> tuple[str, ...]:
    errors: list[str] = []
    try:
        max_database_bytes = _positive_integer(
            document.get("max_database_bytes"), "max_database_bytes"
        )
        min_free_disk_bytes = _positive_integer(
            document.get("min_free_disk_bytes"), "min_free_disk_bytes"
        )
        reserve_pages = _positive_integer(document.get("reserve_pages"), "reserve_pages")
        page_size = _sqlite_page_size(state_directory / "warden.sqlite3")
    except (OSError, ValueError) as exc:
        return (str(exc),)

    max_pages = max_database_bytes // page_size
    if max_pages < 1:
        errors.append("LETS_CONFIG_FILE max_database_bytes is smaller than one SQLite page")
        return tuple(errors)
    if reserve_pages > max_pages:
        errors.append("LETS_CONFIG_FILE reserve_pages exceeds the configured logical page capacity")
    worst_case_wal = 32 + max_pages * (page_size + 24)
    max_main_bytes = max_pages * page_size
    database = state_directory / "warden.sqlite3"
    current_main_bytes = database.stat().st_size
    wal = database.with_name(f"{database.name}-wal")
    shared_memory = database.with_name(f"{database.name}-shm")
    for sidecar in (wal, shared_memory):
        if sidecar.exists() and _is_link_or_reparse(sidecar):
            errors.append(f"{sidecar.name} must not be a symbolic link or reparse point")
        if sidecar.exists() and sidecar.stat().st_nlink != 1:
            errors.append(f"{sidecar.name} must not be hard linked")
    wal_bytes = 0
    with suppress(FileNotFoundError):
        wal_bytes = wal.stat().st_size
    current_shm_bytes = 0
    with suppress(FileNotFoundError):
        current_shm_bytes = shared_memory.stat().st_size
    existing_wal_frames = 0
    if wal_bytes > 32:
        frame_bytes = page_size + 24
        existing_wal_frames = (wal_bytes - 32 + frame_bytes - 1) // frame_bytes
    future_wal_frames = existing_wal_frames + max_pages
    extra_frames = max(0, future_wal_frames - 4_062)
    worst_case_shm = (1 + (extra_frames + 4_095) // 4_096) * 32_768
    if current_main_bytes > max_main_bytes:
        errors.append(
            "LETS_STATE_DIR/warden.sqlite3 exceeds the configured logical main-database cap"
        )
    remaining_main_growth = max(0, max_main_bytes - current_main_bytes)
    additional_shared_memory = max(0, worst_case_shm - current_shm_bytes)
    required_headroom = (
        min_free_disk_bytes + remaining_main_growth + worst_case_wal + additional_shared_memory
    )
    baseline_capacity = max_main_bytes + worst_case_wal + worst_case_shm + min_free_disk_bytes
    current_physical_bytes = current_main_bytes + wal_bytes + current_shm_bytes
    current_required_capacity = current_physical_bytes + required_headroom
    required_capacity = max(baseline_capacity, current_required_capacity)

    boundary = values.get("LETS_STATE_STORAGE_BOUNDARY", "")
    if boundary not in _STATE_BOUNDARIES:
        errors.append("LETS_STATE_STORAGE_BOUNDARY must be dedicated-filesystem or enforced-quota")
    raw_capacity = values.get("LETS_STATE_CAPACITY_BYTES", "")
    try:
        capacity = int(raw_capacity)
        if capacity <= 0:
            raise ValueError
    except ValueError:
        errors.append("LETS_STATE_CAPACITY_BYTES must be a positive integer")
        return tuple(errors)
    if capacity < required_capacity:
        errors.append(
            "LETS_STATE_CAPACITY_BYTES is below the configured main-database, worst-case WAL, "
            f"maximum SHM, and emergency-floor requirement of {required_capacity} bytes"
        )
    try:
        filesystem = shutil.disk_usage(state_directory)
    except OSError as exc:
        errors.append(f"LETS_STATE_DIR filesystem capacity could not be inspected: {exc}")
    else:
        if capacity > filesystem.total:
            errors.append("LETS_STATE_CAPACITY_BYTES exceeds the underlying filesystem capacity")
        if filesystem.free < required_headroom:
            errors.append(
                "LETS_STATE_DIR lacks remaining main growth, one worst-case transaction WAL, "
                "additional SHM growth, and the emergency floor: "
                f"{required_headroom} bytes required"
            )
    return tuple(errors)


def _audit_capacity_errors(values: Mapping[str, str], audit_directory: Path) -> tuple[str, ...]:
    errors: list[str] = []
    parsed: dict[str, int] = {}
    for name, (minimum, maximum) in _AUDIT_BOUNDED_INTEGERS.items():
        raw = values.get(name, "")
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{name} must be an integer")
            continue
        if not minimum <= value <= maximum:
            errors.append(f"{name} must be between {minimum} and {maximum}")
            continue
        parsed[name] = value
    if values.get("LETS_AUDIT_STORAGE_BOUNDARY", "") not in _STATE_BOUNDARIES:
        errors.append("LETS_AUDIT_STORAGE_BOUNDARY must be dedicated-filesystem or enforced-quota")
    if len(parsed) != len(_AUDIT_BOUNDED_INTEGERS):
        return tuple(errors)

    current_bytes = 0
    try:
        for child in audit_directory.iterdir():
            if _is_link_or_reparse(child):
                raise ValueError("LETS_AUDIT_DIR must not contain symbolic links or reparse points")
            if not child.is_file():
                raise ValueError("LETS_AUDIT_DIR must contain only regular provider archive files")
            metadata = child.stat()
            if metadata.st_nlink != 1:
                raise ValueError("LETS_AUDIT_DIR provider archive files must not be hard linked")
            current_bytes += metadata.st_size
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
        return tuple(errors)

    forecast_bytes = parsed["LETS_AUDIT_EXPECTED_DAILY_BYTES"] * parsed["LETS_AUDIT_FORECAST_DAYS"]
    required_growth = forecast_bytes + parsed["LETS_AUDIT_MIN_FREE_BYTES"]
    required_capacity = current_bytes + required_growth
    declared_capacity = parsed["LETS_AUDIT_CAPACITY_BYTES"]
    if declared_capacity < required_capacity:
        errors.append(
            "LETS_AUDIT_CAPACITY_BYTES is below current archive bytes plus the declared "
            f"lifecycle forecast and emergency floor of {required_capacity} bytes"
        )
    try:
        filesystem = shutil.disk_usage(audit_directory)
    except OSError as exc:
        errors.append(f"LETS_AUDIT_DIR filesystem capacity could not be inspected: {exc}")
    else:
        if declared_capacity > filesystem.total:
            errors.append("LETS_AUDIT_CAPACITY_BYTES exceeds the underlying filesystem capacity")
        if filesystem.free < required_growth:
            errors.append(
                "LETS_AUDIT_DIR lacks the declared lifecycle growth and emergency floor: "
                f"{required_growth} bytes required"
            )
    return tuple(errors)


def _cleanup_probe_container(name: str) -> None:
    subprocess.run(
        ["docker", "rm", "--force", name],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def validate_runtime_image(
    image: str,
    *,
    provider: str | None = None,
    signer_executable: str | None = None,
) -> str:
    """Run the production SQLite admission check inside the immutable image."""

    container_name = f"lets-production-validator-{os.getpid()}-{secrets.token_hex(8)}"
    if provider is None:
        probe = (
            "import sqlite3; from lets.cli import _require_production_sqlite; "
            "_require_production_sqlite(); print(sqlite3.sqlite_version)"
        )
    else:
        probe = (
            "import sqlite3, sys; from importlib import metadata; "
            "from lets.cli import _require_production_sqlite; _require_production_sqlite(); "
            "provider=sys.argv[1]; "
            "matches=[item for item in metadata.entry_points(group='lets.runtime_providers') "
            "if item.name == provider]; "
            "assert len(matches) == 1 and callable(matches[0].load()), "
            "'runtime provider is missing, duplicated, or unloadable'; "
        )
        if signer_executable is not None:
            probe += (
                "import os, stat; from pathlib import Path; executable=sys.argv[2]; "
                "path=Path(executable); info=path.lstat(); "
                "assert path.is_absolute() and stat.S_ISREG(info.st_mode) "
                "and not path.is_symlink() and os.access(path, os.X_OK), "
                "'signer helper is missing, linked, or not executable'; "
            )
        probe += "print(sqlite3.sqlite_version)"
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        container_name,
        "--pull",
        "always",
        "--network",
        "none",
        "--read-only",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--cpus",
        "1.0",
        "--user",
        "10001:10001",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--entrypoint",
        "python",
        image,
        "-c",
        probe,
    ]
    if provider is not None:
        command.append(provider)
        if signer_executable is not None:
            command.append(signer_executable)
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired as exc:
        with suppress(OSError, subprocess.TimeoutExpired):
            _cleanup_probe_container(container_name)
        raise ValueError("immutable LETS runtime image admission timed out and was fenced") from exc
    except OSError as exc:
        raise ValueError("could not inspect the immutable LETS runtime image") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        suffix = "" if not detail else f": {detail[-1][:512]}"
        raise ValueError(f"immutable LETS runtime image failed SQLite admission{suffix}")
    version = result.stdout.strip().splitlines()
    if not version or re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,}", version[-1]) is None:
        raise ValueError("immutable LETS runtime image returned no SQLite version evidence")
    return version[-1]


def load_environment(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if separator != "=" or not name or name != name.strip():
            raise ValueError(f"invalid environment entry on line {line_number}")
        if name in values:
            raise ValueError(f"duplicate environment entry {name!r}")
        if value != value.strip() or value.startswith(('"', "'")) or "#" in value:
            raise ValueError(
                f"environment value on line {line_number} must use strict unquoted syntax"
            )
        if "$" in value:
            raise ValueError(
                f"environment value on line {line_number} must not use Compose interpolation"
            )
        values[name] = value
    return values


def _required(values: Mapping[str, str], name: str) -> str:
    value = values.get(name)
    if (
        value is None
        or not value
        or "$" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{name} must be set without control characters or '$'")
    return value


def _config_document(path: Path) -> Mapping[str, object]:
    if path.stat().st_size > 16_777_216:
        raise ValueError("LETS_CONFIG_FILE exceeds its 16 MiB validation limit")

    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for name, value in pairs:
            if name in result:
                raise ValueError(f"LETS_CONFIG_FILE contains duplicate field {name!r}")
            result[name] = value
        return result

    def reject_constant(value: str) -> object:
        raise ValueError(f"LETS_CONFIG_FILE contains non-finite number {value}")

    try:
        decoded = json.loads(
            path.read_bytes(),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("LETS_CONFIG_FILE must contain strict UTF-8 JSON") from exc
    if not isinstance(decoded, Mapping):
        raise ValueError("LETS_CONFIG_FILE root must be an object")
    return decoded


def validate_environment(values: Mapping[str, str]) -> tuple[str, ...]:
    errors: list[str] = []

    def capture(action: Callable[[], object]) -> None:
        try:
            action()
        except (OSError, ValueError) as exc:
            errors.append(str(exc))

    image = values.get("LETS_IMAGE", "")
    if _IMAGE_DIGEST.fullmatch(image) is None:
        errors.append("LETS_IMAGE must be an immutable image@sha256:<64 lowercase hex> reference")
    provider = values.get("LETS_RUNTIME_PROVIDER", "")
    if _PROVIDER_NAME.fullmatch(provider) is None or provider == "builtin":
        errors.append("LETS_RUNTIME_PROVIDER must name an external provider entry point")
    capture(lambda: _server_name(_required(values, "LETS_SERVER_NAME")))
    errors.extend(_resource_errors(values))
    errors.extend(_storage_domain_errors(values))
    for name, (minimum, maximum) in _BOUNDED_INTEGERS.items():
        raw = values.get(name)
        if raw is None:
            continue
        try:
            parsed = int(raw)
        except ValueError:
            errors.append(f"{name} must be an integer")
            continue
        if not minimum <= parsed <= maximum:
            errors.append(f"{name} must be between {minimum} and {maximum}")

    directories: dict[str, Path] = {}
    for name in REQUIRED_DIRECTORIES:

        def check_directory(variable: str = name) -> None:
            raw = _required(values, variable)
            path = Path(raw)
            if not path.is_absolute():
                raise ValueError(f"{variable} must be an absolute host path")
            _reject_link_components(path, variable)
            resolved = path.resolve(strict=True)
            if not resolved.is_dir():
                raise ValueError(f"{variable} must name an existing directory")
            directories[variable] = resolved

        capture(check_directory)

    resolved_directories = list(directories.items())
    for index, (left_name, left) in enumerate(resolved_directories):
        for right_name, right in resolved_directories[index + 1 :]:
            if left == right or left.is_relative_to(right) or right.is_relative_to(left):
                errors.append(f"{left_name} and {right_name} must be distinct non-nested paths")
    errors.extend(_storage_device_errors(directories))
    errors.extend(_storage_mount_errors(values, directories))
    trust_directory = directories.get("LETS_TRUST_DIR")
    if trust_directory is not None:
        errors.extend(_trust_tree_errors(trust_directory))

    files: dict[str, Path] = {}
    for name in REQUIRED_FILES:

        def check_file(variable: str = name) -> None:
            raw = _required(values, variable)
            path = Path(raw)
            if not path.is_absolute():
                raise ValueError(f"{variable} must be an absolute host path")
            _reject_link_components(path, variable)
            resolved = path.resolve(strict=True)
            if not resolved.is_file():
                raise ValueError(f"{variable} must name an existing regular file")
            files[variable] = resolved

        capture(check_file)

    if len(set(files.values())) != len(files):
        errors.append("config and TLS/mTLS inputs must be distinct files")
    inode_owners: dict[tuple[int, int], str] = {}
    for name, path in files.items():
        metadata = path.stat()
        inode = (int(metadata.st_dev), int(metadata.st_ino))
        existing = inode_owners.get(inode)
        if existing is not None:
            errors.append(f"{name} and {existing} must not alias the same filesystem inode")
        else:
            inode_owners[inode] = name
        if metadata.st_nlink != 1:
            errors.append(f"{name} must not be hard linked")
    for file_name, file_path in files.items():
        for directory_name in WRITABLE_DIRECTORIES:
            directory = directories.get(directory_name)
            if directory is not None and file_path.is_relative_to(directory):
                errors.append(f"{file_name} must be outside runtime-writable {directory_name}")
    config_path = files.get("LETS_CONFIG_FILE")
    if config_path is not None:
        try:
            document = _config_document(config_path)
            if document.get("version") != 1:
                raise ValueError("LETS_CONFIG_FILE must use LETS config version 1")
            if document.get("database") != "/var/lib/lets/warden.sqlite3":
                raise ValueError(
                    "LETS_CONFIG_FILE database must be the absolute runtime path "
                    "/var/lib/lets/warden.sqlite3"
                )
            replay_database = document.get("replay_database")
            if replay_database is not None and replay_database != (
                "/var/lib/lets/peer-replay.sqlite3"
            ):
                raise ValueError(
                    "LETS_CONFIG_FILE replay_database must be the absolute runtime path "
                    "/var/lib/lets/peer-replay.sqlite3"
                )
            runtime = document.get("runtime")
            if not isinstance(runtime, Mapping) or runtime.get("provider") != provider:
                raise ValueError(
                    "LETS_CONFIG_FILE runtime provider must match LETS_RUNTIME_PROVIDER"
                )
            options = runtime.get("options")
            if not isinstance(options, Mapping):
                raise ValueError("LETS_CONFIG_FILE runtime options must be an object")
            if provider == "generic-production":
                errors.extend(_generic_provider_errors(options))
            if document.get("bootstrap_identities") not in (None, []):
                raise ValueError("LETS_CONFIG_FILE must not contain static bootstrap identities")
            if document.get("allow_insecure_manifest") is not False:
                raise ValueError("LETS_CONFIG_FILE must contain a fail-closed signed manifest")
            for name in ("manifest", "manifest_digest", "operator_trust"):
                if name not in document:
                    raise ValueError(f"LETS_CONFIG_FILE is missing production trust field {name!r}")
            manifest_digest = document.get("manifest_digest")
            if not isinstance(manifest_digest, str) or _DIGEST.fullmatch(manifest_digest) is None:
                raise ValueError("LETS_CONFIG_FILE manifest_digest must be canonical sha256")
            if trust_directory is not None:
                _mapped_trust_file(trust_directory, document.get("manifest"), "manifest")
                if provider == "generic-production":
                    _mapped_trust_file(
                        trust_directory,
                        options.get("identity_keys_file"),
                        "runtime.options.identity_keys_file",
                    )
            if "signing_key" in document:
                raise ValueError("LETS_CONFIG_FILE must not contain a local signing key reference")
            state_directory = directories.get("LETS_STATE_DIR")
            if state_directory is not None:
                errors.extend(_capacity_errors(values, document, state_directory))
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
    audit_directory = directories.get("LETS_AUDIT_DIR")
    if audit_directory is not None:
        errors.extend(_audit_capacity_errors(values, audit_directory))
    if os.name != "nt":
        for name in TLS_TRUST_FILES:
            security_path = files.get(name)
            if security_path is not None and stat.S_IMODE(security_path.stat().st_mode) & 0o022:
                errors.append(f"{name} must not grant group/other write permissions")
            if security_path is not None and security_path.stat().st_uid == 10001:
                errors.append(f"{name} must not be owned by runtime UID 10001")
        for name in PRIVATE_KEY_FILES:
            private_path = files.get(name)
            if private_path is not None and stat.S_IMODE(private_path.stat().st_mode) & 0o077:
                errors.append(f"{name} must not grant group/other permissions")
        protected_parents = {path.parent for path in files.values()}
        if trust_directory is not None:
            protected_parents.add(trust_directory)
        writable_parents = {path.parent for path in directories.values()}
        protected_ancestors = {
            parent
            for protected in protected_parents | writable_parents
            for parent in (protected, *protected.parents)
        }
        for parent in sorted(protected_ancestors, key=str):
            metadata = parent.stat()
            if metadata.st_uid == 10001:
                errors.append(f"security-input ancestor must not be owned by UID 10001: {parent}")
            mode = stat.S_IMODE(metadata.st_mode)
            trusted_sticky_root = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
            if mode & 0o022 and not trusted_sticky_root:
                errors.append(
                    "security-input ancestor must not grant group/other write permissions: "
                    f"{parent}"
                )
        if config_path is not None:
            config_mode = stat.S_IMODE(config_path.stat().st_mode)
            if config_path.stat().st_uid == 10001:
                errors.append("LETS_CONFIG_FILE must not be owned by runtime UID 10001")
            if config_mode & 0o022:
                errors.append("LETS_CONFIG_FILE must not grant group/other write permissions")
    return tuple(errors)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        values = load_environment(arguments.env_file.resolve(strict=True))
        storage_before = _storage_fingerprint(values)
        errors = validate_environment(values)
        sqlite_version = None
        if not errors:
            document = _config_document(Path(values["LETS_CONFIG_FILE"]))
            runtime = document.get("runtime")
            if not isinstance(runtime, Mapping):
                raise ValueError("LETS_CONFIG_FILE runtime options are unavailable")
            provider = values["LETS_RUNTIME_PROVIDER"]
            signer_executable = None
            if provider == "generic-production":
                options = runtime.get("options")
                if not isinstance(options, Mapping):
                    raise ValueError("generic-production runtime options are unavailable")
                encoded = options.get("signer_command_json")
                if not isinstance(encoded, str):
                    raise ValueError("generic-production signer command is unavailable")
                command = json.loads(encoded)
                if not isinstance(command, list) or not command or not isinstance(command[0], str):
                    raise ValueError("generic-production signer command is malformed")
                signer_executable = command[0]
            sqlite_version = validate_runtime_image(
                values["LETS_IMAGE"],
                provider=provider,
                signer_executable=signer_executable,
            )
            if _storage_fingerprint(values) != storage_before:
                errors = ("production storage mount identity changed during validation",)
                sqlite_version = None
    except (OSError, ValueError) as exc:
        errors = (str(exc),)
        sqlite_version = None
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("production environment validation passed")
    print(f"immutable runtime SQLite admission passed: {sqlite_version}")
    if os.name == "nt":
        print(
            "NOTE: verify private-key ACLs manually; POSIX mode checks are unavailable on Windows"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
