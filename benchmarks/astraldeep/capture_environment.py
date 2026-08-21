"""Capture and validate public, exact-revision Astral/LETS case-study evidence.

The manuscript and measured results remain ignored local state.  This tracked
module supplies the deterministic capture and semantic validation boundary; it
never guesses a revision, a result, or a runtime identity.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

EVIDENCE_FORMAT = "lets.case-study-evidence/v1"
RUN_FORMAT = "lets.astraldeep-case-study-run/v1"
RUNTIME_IDENTITIES_FORMAT = "lets.astraldeep-runtime-identities/v1"
REPOSITORY_REVISIONS_FORMAT = "lets.astraldeep-repository-revisions/v1"
EXECUTION_IDENTITY_FORMAT = "lets.astraldeep-execution-identity/v1"
DRIVER_RELATIVE_PATH = "backend/tests/lets_case_study_driver.py"
COMPOSITION_RELATIVE_PATH = "config/astral-composition.json"
PUBLIC_DRIVER_ARGV = ("python", DRIVER_RELATIVE_PATH)
PUBLIC_PROFILE = "astral.case-study-public/v1"
SCOPE_PROFILE = "astral.tools/v1"
BASELINE_RELEASE = "v1.0.10"
REPOSITORY_KEYS = (
    "astraldeep",
    "astral-projection",
    "astral-plane",
    "astral-primitives",
    "lets",
)
_CASE_STUDY_SCOPES = ("read", "write", "search", "system", "files", "execute")
_CASE_STUDY_LIFECYCLE = ("provision", "spawn", "renew", "quiesce", "resume", "close", "revoke")
_CASE_STUDY_TAIL = (
    "parallel-dispatch",
    "recursive-dispatch",
    "warden-outage",
    "receipt-replay",
    "budget-exhaustion",
    "post-revocation-effect",
)
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_COMMAND_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?\Z")
_SENSITIVE_KEY = re.compile(
    r"(?:secret|token|password|credential|private[_-]?key|api[_-]?key|"
    r"(?:^|[_-])phi(?:$|[_-])|patient|medical[_-]?record|mrn|date[_-]?of[_-]?birth|"
    r"(?:^|[_-])dob(?:$|[_-])|(?:^|[_-])ssn(?:$|[_-]))",
    re.IGNORECASE,
)
_SENSITIVE_TEXT = (
    (
        "credential assignment",
        re.compile(r"(?i)\b(?:secret|token|password|api[_-]?key|private[_-]?key)[\"']?\s*[:=]"),
    ),
    ("authorization credential", re.compile(r"(?i)\bauthorization\s*:\s*|\bbearer\s+")),
    ("private key material", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    (
        "JWT-shaped credential",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "provider credential",
        re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"),
    ),
    (
        "email address",
        re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    ("US social security number", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    (
        "patient identifier",
        re.compile(
            r"(?i)\b(?:patient(?:[_ -]?name)?|mrn|medical[_ -]?record|dob|"
            r"date[_ -]?of[_ -]?birth)[\"']?\s*[:=]"
        ),
    ),
    (
        "user-home path",
        re.compile(r"(?i)(?:[A-Z]:[\\/]Users[\\/][^\\/\s]+|/home/[^/\s]+|/Users/[^/\s]+)"),
    ),
)
_MAX_PUBLIC_ARTIFACT_BYTES = 16 * 1024 * 1024


class EvidenceError(ValueError):
    """An evidence input cannot support a public reproducibility claim."""


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant {value!r} is forbidden")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_json_object(path: Path) -> dict[str, Any]:
    """Read a strict JSON object without accepting duplicate or non-finite values."""

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise EvidenceError(f"could not read a strict JSON object from {path.name}") from exc
    if not isinstance(document, dict):
        raise EvidenceError(f"{path.name} must contain a JSON object")
    return document


def canonical_json_bytes(document: object) -> bytes:
    """Return the single canonical byte representation used by tracked tooling."""

    try:
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise EvidenceError("document is not canonical finite JSON") from exc


def canonical_json_sha256(document: object) -> str:
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise EvidenceError(f"could not digest retained artifact {path.name}") from exc
    return digest.hexdigest()


def write_canonical_json_exclusive(path: Path, document: object) -> None:
    """Create, but never replace, a canonical JSON record."""

    payload = canonical_json_bytes(document) + b"\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise EvidenceError(f"refusing to replace retained evidence {path.name}") from exc
    except OSError as exc:
        raise EvidenceError(f"could not create retained evidence {path.name}") from exc


def _write_bytes_exclusive(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(payload)
    except FileExistsError as exc:
        raise EvidenceError(f"refusing to replace retained evidence {path.name}") from exc
    except OSError as exc:
        raise EvidenceError(f"could not create retained evidence {path.name}") from exc


def _git(root: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"})
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=10,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError("local Git metadata is unavailable") from exc
    if result.returncode != 0:
        raise EvidenceError("local Git metadata is unavailable")
    return result.stdout.strip()


def capture_repository_revisions(
    repositories: Mapping[str, Path], *, require_clean: bool = True
) -> dict[str, str]:
    """Capture five exact commits and reject dirty or aliased worktrees."""

    if tuple(sorted(repositories)) != tuple(sorted(REPOSITORY_KEYS)):
        raise EvidenceError("all five canonical repository paths are required exactly once")
    try:
        resolved = {name: path.resolve(strict=True) for name, path in repositories.items()}
    except OSError as exc:
        raise EvidenceError("one or more canonical repository paths are missing") from exc
    if len({os.path.normcase(str(path)) for path in resolved.values()}) != len(resolved):
        raise EvidenceError("repository paths must resolve to five distinct worktrees")
    revisions: dict[str, str] = {}
    for name in REPOSITORY_KEYS:
        root = resolved[name]
        if _git(root, "rev-parse", "--is-inside-work-tree") != "true":
            raise EvidenceError(f"{name} is not a Git worktree")
        revision = _git(root, "rev-parse", "--verify", "HEAD^{commit}")
        if _SHA1.fullmatch(revision) is None:
            raise EvidenceError(f"{name} did not resolve to an exact commit")
        if require_clean and _git(
            root,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ):
            raise EvidenceError(f"{name} is dirty; exact-revision capture is forbidden")
        revisions[name] = revision
    return revisions


def _total_memory_bytes() -> int | None:
    if sys.platform == "win32":

        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong),
                ("available_physical", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong),
                ("available_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended_virtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        try:
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return int(status.total_physical)
        except (AttributeError, OSError):
            return None
        return None
    try:
        return int(os.sysconf("SC_PHYS_PAGES")) * int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def capture_public_environment(additional: Mapping[str, object] | None = None) -> dict[str, object]:
    """Capture non-identifying environment facts; never capture paths, users, or hosts."""

    result: dict[str, object] = {
        "os_system": platform.system(),
        "os_release": platform.release(),
        "machine_architecture": platform.machine(),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "logical_cpu_count": os.cpu_count(),
    }
    memory = _total_memory_bytes()
    if memory is not None:
        result["physical_memory_bytes"] = memory
    if additional:
        for key, value in additional.items():
            if key in result:
                raise EvidenceError(f"additional environment key {key!r} is reserved")
            result[key] = value
    findings = scan_public_value(result, location="environment")
    if findings:
        raise EvidenceError(f"public environment failed sanitization: {findings[0]}")
    return result


def scan_public_value(value: object, *, location: str = "$") -> list[str]:
    """Return redacted finding locations for secret, credential, and PHI shapes."""

    findings: list[str] = []

    def visit(item: object, path: str) -> None:
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                findings.append(f"{path}: non-finite number")
            return
        if isinstance(item, str):
            if any(ord(character) < 32 or ord(character) == 127 for character in item):
                findings.append(f"{path}: control character")
            for label, pattern in _SENSITIVE_TEXT:
                if pattern.search(item):
                    findings.append(f"{path}: {label}")
            return
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str):
                    findings.append(f"{path}: non-string key")
                    continue
                child_path = f"{path}.{key}"
                if _SENSITIVE_KEY.search(key):
                    findings.append(f"{child_path}: sensitive metadata key")
                visit(child, child_path)
            return
        if isinstance(item, Sequence) and not isinstance(item, (bytes, bytearray)):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")
            return
        findings.append(f"{path}: unsupported public value type")

    visit(value, location)
    return findings


def scan_public_text(value: str, *, location: str) -> list[str]:
    """Scan a UTF-8 text artifact while permitting ordinary line formatting."""

    lines = value.splitlines() or [""]
    findings: list[str] = []
    for index, line in enumerate(lines):
        findings.extend(
            scan_public_value(line.replace("\t", " "), location=f"{location}.line[{index + 1}]")
        )
    return findings


def _parse_timestamp(value: object, location: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError(f"{location} must be an RFC 3339 timestamp")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise EvidenceError(f"{location} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise EvidenceError(f"{location} must include a UTC offset")
    return parsed.astimezone(UTC)


def _relative_artifact(root: Path, relative_path: object) -> Path:
    if not isinstance(relative_path, str):
        raise EvidenceError("artifact path must be a string")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise EvidenceError("artifact path is not a canonical relative path")
    candidate = root.joinpath(*pure.parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as exc:
        raise EvidenceError(
            f"retained artifact is missing or escapes its root: {relative_path}"
        ) from exc
    cursor = resolved_root
    for part in pure.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise EvidenceError(f"retained artifact may not traverse a symlink: {relative_path}")
    if not resolved.is_file():
        raise EvidenceError(f"retained artifact is not a regular file: {relative_path}")
    return resolved


def artifact_record(root: Path, relative_path: str, kind: str) -> dict[str, object]:
    path = _relative_artifact(root, relative_path)
    return {
        "kind": kind,
        "relative_path": relative_path,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
    }


def _canonical_file(path: Path, document: object) -> bool:
    try:
        return path.read_bytes() == canonical_json_bytes(document) + b"\n"
    except OSError as exc:
        raise EvidenceError(f"could not read canonical evidence {path.name}") from exc


def _schema_validate(document: Mapping[str, object], schema_path: Path) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise EvidenceError("jsonschema is required for case-study evidence validation") from exc
    schema = read_json_object(schema_path)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(
        schema,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        error = errors[0]
        location = "$" + "".join(
            f"[{item}]" if isinstance(item, int) else f".{item}" for item in error.absolute_path
        )
        raise EvidenceError(f"evidence schema rejected {location} ({error.validator})")


def _require_single_artifact(
    artifacts: Sequence[Mapping[str, object]], kind: str
) -> Mapping[str, object]:
    matches = [artifact for artifact in artifacts if artifact.get("kind") == kind]
    if len(matches) != 1:
        raise EvidenceError(f"evidence must retain exactly one {kind} artifact")
    return matches[0]


def _nearest_rank(ordered: Sequence[float], percentage: int) -> float:
    rank = max(1, math.ceil(len(ordered) * percentage / 100))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _derived_measurements(
    *,
    command_id: str,
    source_artifact: str,
    result: Mapping[str, object],
) -> list[dict[str, object]]:
    raw_measurements = result.get("measurements")
    if not isinstance(raw_measurements, list) or not raw_measurements:
        raise EvidenceError(f"command {command_id} retained no raw measurements")
    output: list[dict[str, object]] = []
    for raw in raw_measurements:
        if not isinstance(raw, Mapping):
            raise EvidenceError(f"command {command_id} retained a malformed raw measurement")
        name = raw.get("name")
        unit = raw.get("unit")
        samples = raw.get("samples")
        exclusions = raw.get("exclusions")
        if (
            not isinstance(name, str)
            or not isinstance(unit, str)
            or not isinstance(samples, list)
            or not samples
            or len(samples) > 100_000
            or not isinstance(exclusions, list)
            or any(not isinstance(item, str) for item in exclusions)
        ):
            raise EvidenceError(f"command {command_id} retained a malformed raw measurement")
        if any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or not math.isfinite(float(value))
            for value in samples
        ):
            raise EvidenceError(f"command {command_id} retained non-finite raw samples")
        ordered = sorted(float(value) for value in samples)

        measurement: dict[str, object] = {
            "name": f"{command_id}.{name}",
            "unit": unit,
            "sample_count": len(ordered),
            "summary": {
                "minimum": ordered[0],
                "p50": _nearest_rank(ordered, 50),
                "p95": _nearest_rank(ordered, 95),
                "p99": _nearest_rank(ordered, 99),
                "maximum": ordered[-1],
                "mean": statistics.fmean(ordered),
            },
            "source_artifact": source_artifact,
        }
        if exclusions:
            measurement["exclusions"] = exclusions
        output.append(measurement)
    return output


def _validate_runtime_identities(document: Mapping[str, object]) -> None:
    required = {
        "format",
        "lets_release",
        "policy_digest",
        "machine_digest",
        "config_epoch",
        "scope_profile",
    }
    optional = {"api_version", "receipt_wire_type", "warden_topology"}
    if set(document) - required - optional or not required.issubset(document):
        raise EvidenceError("runtime identities contain missing or undeclared fields")
    if document.get("format") != RUNTIME_IDENTITIES_FORMAT:
        raise EvidenceError("runtime identities format is unsupported")
    if (
        not isinstance(document.get("lets_release"), str)
        or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(document["lets_release"])) is None
    ):
        raise EvidenceError("runtime LETS release is invalid")
    for field in ("policy_digest", "machine_digest"):
        if (
            not isinstance(document.get(field), str)
            or _SHA256.fullmatch(str(document[field])) is None
        ):
            raise EvidenceError(f"runtime {field} is invalid")
    epoch = document.get("config_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 1:
        raise EvidenceError("runtime config_epoch is invalid")
    if document.get("scope_profile") != SCOPE_PROFILE:
        raise EvidenceError("runtime scope profile is not astral.tools/v1")
    findings = scan_public_value(document, location="runtime_identities")
    if findings:
        raise EvidenceError(f"runtime identities failed sanitization: {findings[0]}")


def _validate_execution_identity(document: Mapping[str, object]) -> None:
    if (
        set(document) != {"format", "astraldeep", "interpreter", "imports"}
        or document.get("format") != EXECUTION_IDENTITY_FORMAT
    ):
        raise EvidenceError("execution identity is malformed")
    deep = document.get("astraldeep")
    interpreter = document.get("interpreter")
    imports = document.get("imports")
    if (
        not isinstance(deep, Mapping)
        or set(deep) != {"commit", "driver_relative_path", "driver_sha256"}
        or deep.get("driver_relative_path") != DRIVER_RELATIVE_PATH
        or not isinstance(deep.get("commit"), str)
        or _SHA1.fullmatch(str(deep["commit"])) is None
        or not isinstance(deep.get("driver_sha256"), str)
        or _SHA256.fullmatch(str(deep["driver_sha256"])) is None
    ):
        raise EvidenceError("execution identity does not bind the canonical Deep driver")
    if (
        not isinstance(interpreter, Mapping)
        or set(interpreter) != {"implementation", "version", "executable_sha256"}
        or not isinstance(interpreter.get("implementation"), str)
        or not interpreter.get("implementation")
        or not isinstance(interpreter.get("version"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(interpreter["version"])) is None
        or not isinstance(interpreter.get("executable_sha256"), str)
        or _SHA256.fullmatch(str(interpreter["executable_sha256"])) is None
    ):
        raise EvidenceError("execution identity interpreter is malformed")
    if not isinstance(imports, Mapping) or set(imports) != {"astralplane", "lets"}:
        raise EvidenceError("execution identity imports are incomplete")
    for name in ("astralplane", "lets"):
        identity = imports.get(name)
        required = {"component_commit", "file_count", "tree_sha256"}
        if name == "lets":
            required.add("release")
        if (
            not isinstance(identity, Mapping)
            or set(identity) != required
            or not isinstance(identity.get("component_commit"), str)
            or _SHA1.fullmatch(str(identity["component_commit"])) is None
            or type(identity.get("file_count")) is not int
            or int(identity["file_count"]) < 1
            or not isinstance(identity.get("tree_sha256"), str)
            or _SHA256.fullmatch(str(identity["tree_sha256"])) is None
        ):
            raise EvidenceError(f"execution identity {name} import is malformed")
        if name == "lets" and (
            not isinstance(identity.get("release"), str)
            or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(identity["release"])) is None
        ):
            raise EvidenceError("execution identity LETS release is malformed")
    findings = scan_public_value(document, location="execution_identity")
    if findings:
        raise EvidenceError(f"execution identity failed sanitization: {findings[0]}")


def _validate_revision_anchor(document: Mapping[str, object]) -> None:
    if set(document) != {"format", "clean", "repositories"}:
        raise EvidenceError("repository revision anchor has unexpected fields")
    if document.get("format") != REPOSITORY_REVISIONS_FORMAT or document.get("clean") is not True:
        raise EvidenceError("repository revision anchor does not attest a clean capture")
    repositories = document.get("repositories")
    if not isinstance(repositories, Mapping) or tuple(sorted(repositories)) != tuple(
        sorted(REPOSITORY_KEYS)
    ):
        raise EvidenceError("repository revision anchor is incomplete")
    if any(
        not isinstance(value, str) or _SHA1.fullmatch(value) is None
        for value in repositories.values()
    ):
        raise EvidenceError("repository revision anchor contains a non-commit value")


def _validate_composition_revisions(
    composition: Mapping[str, object], repositories: Mapping[str, object]
) -> None:
    components = composition.get("components")
    if not isinstance(components, Mapping):
        raise EvidenceError("composition has no component map")
    for name in ("astral-projection", "astral-plane", "astral-primitives"):
        component = components.get(name)
        if not isinstance(component, Mapping) or component.get("commit") != repositories.get(name):
            raise EvidenceError(f"composition pin does not match captured {name} revision")
    lets_component = components.get("lets")
    if (
        not isinstance(lets_component, Mapping)
        or not isinstance(lets_component.get("commit"), str)
        or _SHA1.fullmatch(str(lets_component["commit"])) is None
        or not isinstance(lets_component.get("ref"), str)
        or re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", str(lets_component["ref"])) is None
    ):
        raise EvidenceError("composition does not contain an exact released LETS runtime pin")


def _scan_artifact(path: Path, relative_path: str) -> list[str]:
    size = path.stat().st_size
    if size > _MAX_PUBLIC_ARTIFACT_BYTES:
        return [f"artifact.{relative_path}: exceeds bounded public scanner size"]
    try:
        payload = path.read_bytes()
    except OSError:
        return [f"artifact.{relative_path}: unreadable"]
    if b"\x00" in payload:
        return [f"artifact.{relative_path}: binary content is not public evidence"]
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return [f"artifact.{relative_path}: content is not UTF-8"]
    return scan_public_text(text, location=f"artifact.{relative_path}")


def validate_evidence_bundle(
    document: Mapping[str, object],
    evidence_root: Path,
    *,
    schema_path: Path | None = None,
) -> None:
    """Apply schema and cross-record semantics to a retained public bundle."""

    schema_path = schema_path or Path(__file__).with_name("case-study-evidence.schema.json")
    _schema_validate(document, schema_path)
    evidence_root = evidence_root.resolve(strict=True)

    repositories = document["repositories"]
    if not isinstance(repositories, Mapping):
        raise EvidenceError("repositories must be an object")
    execution_identity = document["execution_identity"]
    if not isinstance(execution_identity, Mapping):
        raise EvidenceError("execution identity must be an object")
    _validate_execution_identity(execution_identity)
    commands = document["commands"]
    artifacts = document["artifacts"]
    measurements = document["measurements"]
    if (
        not isinstance(commands, list)
        or not isinstance(artifacts, list)
        or not isinstance(measurements, list)
    ):
        raise EvidenceError("commands, artifacts, and measurements must be arrays")
    command_ids: set[str] = set()
    first_start: datetime | None = None
    prior_start: datetime | None = None
    latest_finish: datetime | None = None
    for command in commands:
        if not isinstance(command, Mapping):
            raise EvidenceError("command record is malformed")
        command_id = command.get("id")
        if not isinstance(command_id, str) or _COMMAND_ID.fullmatch(command_id) is None:
            raise EvidenceError("command id is not canonical")
        if command_id in command_ids:
            raise EvidenceError("command ids must be unique")
        command_ids.add(command_id)
        if command.get("exit_code") != 0:
            raise EvidenceError(f"command {command_id} did not complete successfully")
        if command.get("argv") != list(PUBLIC_DRIVER_ARGV):
            raise EvidenceError(f"command {command_id} did not use the canonical driver argv")
        started = _parse_timestamp(command.get("started_at"), f"commands.{command_id}.started_at")
        finished = _parse_timestamp(
            command.get("finished_at"), f"commands.{command_id}.finished_at"
        )
        if finished < started:
            raise EvidenceError(f"command {command_id} finished before it started")
        if prior_start is not None and started < prior_start:
            raise EvidenceError("commands are not ordered by start timestamp")
        if first_start is None:
            first_start = started
        prior_start = started
        latest_finish = max(latest_finish, finished) if latest_finish else finished

    reproduced_at = _parse_timestamp(document["reproduced_at"], "reproduced_at")
    if latest_finish is not None and reproduced_at < latest_finish:
        raise EvidenceError("reproduced_at precedes retained command completion")

    retained: dict[str, tuple[Mapping[str, object], Path]] = {}
    casefolded: set[str] = set()
    artifact_paths: list[str] = []
    for raw_artifact in artifacts:
        if not isinstance(raw_artifact, Mapping):
            raise EvidenceError("artifact record is malformed")
        relative_path = raw_artifact.get("relative_path")
        if not isinstance(relative_path, str):
            raise EvidenceError("artifact path is malformed")
        folded = relative_path.casefold()
        if folded in casefolded:
            raise EvidenceError("retained artifact paths must be unique case-insensitively")
        casefolded.add(folded)
        artifact_paths.append(relative_path)
        path = _relative_artifact(evidence_root, relative_path)
        expected_bytes = raw_artifact.get("bytes")
        expected_sha = raw_artifact.get("sha256")
        if path.stat().st_size != expected_bytes or sha256_file(path) != expected_sha:
            raise EvidenceError(f"retained artifact digest mismatch: {relative_path}")
        retained[relative_path] = (raw_artifact, path)
    if artifact_paths != sorted(artifact_paths):
        raise EvidenceError("retained artifact records are not canonically ordered")

    for measurement in measurements:
        if (
            not isinstance(measurement, Mapping)
            or measurement.get("source_artifact") not in retained
        ):
            raise EvidenceError("measurement references an unretained source artifact")

    derived_measurements: list[dict[str, object]] = []
    from benchmarks.astraldeep import run_case_study as case_study_runner

    expected_scenarios = {
        scenario.scenario_id: scenario
        for scenario in case_study_runner.build_scenarios(str(document["mode"]))
    }
    for command in commands:
        command_id = str(command["id"])
        expected = (
            (f"raw/commands/{command_id}.stdout.json", "stdout_sha256", "command-stdout"),
            (f"raw/commands/{command_id}.stderr.txt", "stderr_sha256", "command-stderr"),
        )
        for relative_path, digest_field, kind in expected:
            retained_record = retained.get(relative_path)
            if retained_record is None or retained_record[0].get("kind") != kind:
                raise EvidenceError(f"command {command_id} lacks its retained {kind} artifact")
            if retained_record[0].get("sha256") != command.get(digest_field):
                raise EvidenceError(f"command {command_id} {kind} digest is inconsistent")
        request_relative = f"raw/scenarios/{command_id}.request.json"
        request_record = retained.get(request_relative)
        if request_record is None or request_record[0].get("kind") != "scenario-request":
            raise EvidenceError(f"command {command_id} lacks its retained scenario request")
        request = read_json_object(request_record[1])
        scenario = expected_scenarios.get(command_id)
        if (
            scenario is None
            or not _canonical_file(request_record[1], request)
            or request != (scenario.to_request())
        ):
            raise EvidenceError(f"command {command_id} scenario request is inconsistent")
        stdout_relative = f"raw/commands/{command_id}.stdout.json"
        result = read_json_object(retained[stdout_relative][1])
        if (
            not _canonical_file(retained[stdout_relative][1], result)
            or result.get("format") != "lets.astraldeep-case-study-result/v1"
            or result.get("scenario_id") != command_id
            or result.get("mode") != document["mode"]
            or result.get("status") != "passed"
        ):
            raise EvidenceError(f"command {command_id} result is inconsistent")
        try:
            case_study_runner._validate_result(result, scenario, execution_identity)
        except EvidenceError as exc:
            raise EvidenceError(
                f"command {command_id} retained result violates scenario semantics"
            ) from exc
        derived_measurements.extend(
            _derived_measurements(
                command_id=command_id,
                source_artifact=stdout_relative,
                result=result,
            )
        )
    if derived_measurements != measurements:
        raise EvidenceError("measurement summaries do not derive from retained raw samples")

    composition_record = _require_single_artifact(artifacts, "composition-manifest")
    runtime_record = _require_single_artifact(artifacts, "runtime-identities")
    revisions_record = _require_single_artifact(artifacts, "repository-revisions")
    run_record = _require_single_artifact(artifacts, "case-study-run")
    composition_path = retained[str(composition_record["relative_path"])][1]
    runtime_path = retained[str(runtime_record["relative_path"])][1]
    revisions_path = retained[str(revisions_record["relative_path"])][1]
    run_path = retained[str(run_record["relative_path"])][1]

    composition = read_json_object(composition_path)
    runtime = read_json_object(runtime_path)
    revision_anchor = read_json_object(revisions_path)
    run = read_json_object(run_path)
    _validate_runtime_identities(runtime)
    _validate_revision_anchor(revision_anchor)
    _validate_run_for_capture(run)
    if not _canonical_file(runtime_path, runtime) or not _canonical_file(
        revisions_path, revision_anchor
    ):
        raise EvidenceError("generated identity anchors are not canonical JSON")
    if not _canonical_file(run_path, run):
        raise EvidenceError("case-study run manifest is not canonical JSON")
    run_started = _parse_timestamp(run.get("started_at"), "run.started_at")
    run_finished = _parse_timestamp(run.get("finished_at"), "run.finished_at")
    if run_finished < run_started:
        raise EvidenceError("case-study run finished before it started")
    if first_start is not None and run_started > first_start:
        raise EvidenceError("case-study run started after its first retained command")
    if latest_finish is not None and run_finished < latest_finish:
        raise EvidenceError("case-study run finished before a retained command")
    if reproduced_at < run_finished:
        raise EvidenceError("reproduced_at precedes case-study run completion")
    if sha256_file(composition_path) != document["composition_sha256"]:
        raise EvidenceError("composition_sha256 does not bind the retained manifest bytes")
    if revision_anchor["repositories"] != repositories:
        raise EvidenceError("bundle revisions do not match the retained revision anchor")
    _validate_composition_revisions(composition, repositories)
    deep_identity = execution_identity["astraldeep"]
    import_identities = execution_identity["imports"]
    assert isinstance(deep_identity, Mapping) and isinstance(import_identities, Mapping)
    if deep_identity.get("commit") != repositories.get("astraldeep"):
        raise EvidenceError("execution identity does not match the captured Deep revision")
    components = composition.get("components")
    assert isinstance(components, Mapping)
    plane_component = components.get("astral-plane")
    lets_component = components.get("lets")
    plane_identity = import_identities.get("astralplane")
    lets_identity = import_identities.get("lets")
    if (
        not isinstance(plane_component, Mapping)
        or not isinstance(lets_component, Mapping)
        or not isinstance(plane_identity, Mapping)
        or not isinstance(lets_identity, Mapping)
        or plane_identity.get("component_commit") != plane_component.get("commit")
        or lets_identity.get("component_commit") != lets_component.get("commit")
        or lets_identity.get("release") != lets_component.get("ref")
    ):
        raise EvidenceError("execution imports do not match the retained composition")
    for field in (
        "lets_release",
        "policy_digest",
        "machine_digest",
        "config_epoch",
        "scope_profile",
    ):
        if runtime.get(field) != document.get(field):
            raise EvidenceError(f"bundle {field} does not match authenticated runtime identities")
    compatibility = composition.get("compatibility")
    lets_component = components.get("lets") if isinstance(components, Mapping) else None
    lets_compatibility = compatibility.get("lets") if isinstance(compatibility, Mapping) else None
    if (
        not isinstance(lets_component, Mapping)
        or not isinstance(lets_compatibility, Mapping)
        or lets_component.get("ref") != document["lets_release"]
        or lets_compatibility.get("release") != document["lets_release"]
    ):
        raise EvidenceError("retained composition release does not match runtime LETS identity")
    for field in ("evidence_class", "mode"):
        if run.get(field) != document.get(field):
            raise EvidenceError(f"bundle {field} does not match its run manifest")
    if run.get("execution_identity") != execution_identity:
        raise EvidenceError("bundle execution identity does not match its run manifest")
    if run.get("commands") != commands or run.get("measurements") != measurements:
        raise EvidenceError("bundle commands or measurements do not match its run manifest")
    run_artifacts = run.get("artifacts")
    assert isinstance(run_artifacts, list)
    run_artifact_paths = {
        str(record["relative_path"])
        for record in run_artifacts
        if isinstance(record, Mapping) and "relative_path" in record
    }
    anchor_paths = {
        str(composition_record["relative_path"]),
        str(runtime_record["relative_path"]),
        str(revisions_record["relative_path"]),
        str(run_record["relative_path"]),
    }
    if set(retained) != run_artifact_paths | anchor_paths:
        raise EvidenceError("bundle retained artifacts do not match its run manifest and anchors")
    for raw_record in run_artifacts:
        assert isinstance(raw_record, Mapping)
        relative_path = str(raw_record["relative_path"])
        if dict(retained[relative_path][0]) != dict(raw_record):
            raise EvidenceError(
                f"bundle artifact record differs from its run manifest: {relative_path}"
            )

    sanitization = document["sanitization"]
    if not isinstance(sanitization, Mapping) or sanitization.get("scanner_sha256") != sha256_file(
        Path(__file__)
    ):
        raise EvidenceError("sanitization attestation is not bound to this scanner revision")
    public_fields = {
        "environment": document["environment"],
        "commands": commands,
        "measurements": measurements,
        "notes": document.get("notes"),
    }
    findings = scan_public_value(public_fields, location="bundle")
    for relative_path, (_, path) in retained.items():
        findings.extend(_scan_artifact(path, relative_path))
    if findings:
        raise EvidenceError(f"public evidence failed secret/PHI sanitization: {findings[0]}")


def _validate_run_for_capture(run: Mapping[str, object]) -> None:
    required = {
        "format",
        "evidence_class",
        "mode",
        "status",
        "execution_identity",
        "commands",
        "artifacts",
        "measurements",
        "started_at",
        "finished_at",
    }
    if set(run) != required or run.get("format") != RUN_FORMAT:
        raise EvidenceError("case-study run manifest is malformed")
    if run.get("evidence_class") not in {"release-baseline", "astral-integration"}:
        raise EvidenceError("case-study run evidence class is invalid")
    if run.get("mode") not in {"off", "shadow", "enforce"}:
        raise EvidenceError("case-study run mode is invalid")
    if run.get("status") != "passed":
        raise EvidenceError("only a completely passing case-study run may be captured")
    if run.get("evidence_class") == "release-baseline" and run.get("mode") != "off":
        raise EvidenceError("release-baseline runs must be flag-off")
    execution_identity = run.get("execution_identity")
    if not isinstance(execution_identity, Mapping):
        raise EvidenceError("case-study run execution identity is malformed")
    _validate_execution_identity(execution_identity)
    mode = str(run["mode"])
    expected_ids = [
        *(f"{mode}-scope-{scope}" for scope in _CASE_STUDY_SCOPES),
        *(f"{mode}-lifecycle-{event}" for event in _CASE_STUDY_LIFECYCLE),
        *(f"{mode}-{suffix}" for suffix in _CASE_STUDY_TAIL),
    ]
    commands = run.get("commands")
    observed_ids = (
        [command.get("id") if isinstance(command, Mapping) else None for command in commands]
        if isinstance(commands, list)
        else []
    )
    if observed_ids != expected_ids:
        raise EvidenceError("case-study run does not contain the complete ordered scenario matrix")
    assert isinstance(commands, list)
    if any(
        not isinstance(command, Mapping) or command.get("argv") != list(PUBLIC_DRIVER_ARGV)
        for command in commands
    ):
        raise EvidenceError("case-study run did not use the canonical driver argv")
    artifacts = run.get("artifacts")
    if not isinstance(artifacts, list):
        raise EvidenceError("case-study run artifacts are malformed")
    artifact_paths: list[str] = []
    for artifact in artifacts:
        if not isinstance(artifact, Mapping) or set(artifact) != {
            "kind",
            "relative_path",
            "sha256",
            "bytes",
        }:
            raise EvidenceError("case-study run artifact record is malformed")
        relative_path = artifact.get("relative_path")
        if not isinstance(relative_path, str):
            raise EvidenceError("case-study run artifact path is malformed")
        artifact_paths.append(relative_path)
    if artifact_paths != sorted(set(artifact_paths)):
        raise EvidenceError("case-study run artifacts are not canonical, ordered, and unique")


def capture_case_study_evidence(
    *,
    run_manifest_path: Path,
    composition_path: Path,
    runtime_identities_path: Path,
    repository_paths: Mapping[str, Path],
    output_path: Path,
    additional_environment: Mapping[str, object] | None = None,
    notes: str | None = None,
) -> dict[str, object]:
    """Capture one complete, single-mode evidence bundle without overwriting state."""

    output_path = output_path.resolve()
    root = output_path.parent
    root.mkdir(parents=True, exist_ok=True)
    try:
        run_relative = run_manifest_path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise EvidenceError(
            "run manifest must already be retained beneath the evidence root"
        ) from exc
    run = read_json_object(run_manifest_path)
    _validate_run_for_capture(run)
    runtime = read_json_object(runtime_identities_path)
    _validate_runtime_identities(runtime)
    composition = read_json_object(composition_path)
    try:
        composition_payload = composition_path.read_bytes()
    except OSError as exc:
        raise EvidenceError("could not read exact composition bytes") from exc
    revisions = capture_repository_revisions(repository_paths)
    _validate_composition_revisions(composition, revisions)
    deep_repository = repository_paths.get("astraldeep")
    if not isinstance(deep_repository, Path):
        raise EvidenceError("capture requires the canonical AstralDeep repository path")
    try:
        canonical_composition_payload = (
            deep_repository.resolve(strict=True) / COMPOSITION_RELATIVE_PATH
        ).read_bytes()
    except OSError as exc:
        raise EvidenceError("canonical AstralDeep composition is unavailable") from exc
    if composition_payload != canonical_composition_payload:
        raise EvidenceError("supplied composition bytes do not match the clean AstralDeep worktree")
    from benchmarks.astraldeep import run_case_study as case_study_runner

    observed_execution_identity = case_study_runner.capture_execution_identity(deep_repository)
    if run.get("execution_identity") != observed_execution_identity:
        raise EvidenceError("run execution identity does not match the clean AstralDeep worktree")
    compatibility = composition.get("compatibility")
    lets_compatibility = compatibility.get("lets") if isinstance(compatibility, Mapping) else None
    components = composition.get("components")
    lets_component = components.get("lets") if isinstance(components, Mapping) else None
    if (
        not isinstance(lets_compatibility, Mapping)
        or not isinstance(lets_component, Mapping)
        or runtime["lets_release"] != lets_compatibility.get("release")
        or runtime["lets_release"] != lets_component.get("ref")
    ):
        raise EvidenceError("runtime LETS release does not match the exact composition")

    anchors = root / "anchors"
    composition_anchor = anchors / "astral-composition.json"
    runtime_anchor = anchors / "runtime-identities.json"
    revisions_anchor = anchors / "repository-revisions.json"
    composition_findings = scan_public_text(
        composition_payload.decode("utf-8"),
        location="composition_input",
    )
    input_findings = [
        *composition_findings,
        *scan_public_value(runtime, location="runtime_input"),
        *scan_public_value(run, location="run_input"),
    ]
    if input_findings:
        raise EvidenceError(f"capture input failed pre-retention sanitization: {input_findings[0]}")
    _write_bytes_exclusive(composition_anchor, composition_payload)
    write_canonical_json_exclusive(runtime_anchor, runtime)
    revision_document: dict[str, object] = {
        "format": REPOSITORY_REVISIONS_FORMAT,
        "clean": True,
        "repositories": revisions,
    }
    write_canonical_json_exclusive(revisions_anchor, revision_document)

    artifacts: list[dict[str, object]] = []
    raw_artifacts = run.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise EvidenceError("run manifest artifacts are malformed")
    for raw in raw_artifacts:
        if not isinstance(raw, Mapping):
            raise EvidenceError("run manifest artifact is malformed")
        relative_path = raw.get("relative_path")
        kind = raw.get("kind")
        if not isinstance(relative_path, str) or not isinstance(kind, str):
            raise EvidenceError("run manifest artifact fields are malformed")
        observed = artifact_record(root, relative_path, kind)
        if observed != raw:
            raise EvidenceError(f"run artifact changed after execution: {relative_path}")
        artifacts.append(observed)
    artifacts.extend(
        (
            artifact_record(root, run_relative.as_posix(), "case-study-run"),
            artifact_record(root, "anchors/astral-composition.json", "composition-manifest"),
            artifact_record(root, "anchors/runtime-identities.json", "runtime-identities"),
            artifact_record(root, "anchors/repository-revisions.json", "repository-revisions"),
        )
    )
    artifacts.sort(key=lambda item: str(item["relative_path"]))

    reproduced_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    bundle: dict[str, object] = {
        "format": EVIDENCE_FORMAT,
        "evidence_class": run["evidence_class"],
        "lets_release": runtime["lets_release"],
        "repositories": revisions,
        "execution_identity": run["execution_identity"],
        "composition_sha256": hashlib.sha256(composition_payload).hexdigest(),
        "policy_digest": runtime["policy_digest"],
        "machine_digest": runtime["machine_digest"],
        "config_epoch": runtime["config_epoch"],
        "scope_profile": runtime["scope_profile"],
        "mode": run["mode"],
        "environment": capture_public_environment(additional_environment),
        "commands": run["commands"],
        "artifacts": artifacts,
        "measurements": run["measurements"],
        "sanitization": {
            "profile": PUBLIC_PROFILE,
            "scanner_sha256": sha256_file(Path(__file__)),
            "findings": 0,
        },
        "reproduced_at": reproduced_at,
    }
    if notes is not None:
        bundle["notes"] = notes
    validate_evidence_bundle(bundle, root)
    write_canonical_json_exclusive(output_path, bundle)
    return bundle


def _repository_argument(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or name not in REPOSITORY_KEYS or not raw_path:
        raise argparse.ArgumentTypeError(
            "repository must be one of NAME=PATH for the five canonical names"
        )
    return name, Path(raw_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-manifest", required=True, type=Path)
    parser.add_argument("--composition", required=True, type=Path)
    parser.add_argument("--runtime-identities", required=True, type=Path)
    parser.add_argument("--repository", action="append", required=True, type=_repository_argument)
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--notes")
    parser.add_argument("--output", required=True, type=Path)
    return parser


def _is_ignored_case_study_path(repository: Path, path: Path) -> bool:
    try:
        relative = path.resolve().relative_to(repository.resolve())
    except ValueError:
        return False
    if tuple(part.casefold() for part in relative.parts[:2]) != (
        "results",
        "astraldeep-case-study",
    ):
        return False
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "check-ignore",
            "--quiet",
            "--",
            relative.as_posix(),
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    repository_root = Path(__file__).resolve().parents[2]
    if not _is_ignored_case_study_path(repository_root, arguments.output):
        print(
            "case-study evidence capture refused: --output must be beneath the "
            "Git-ignored results/astraldeep-case-study root",
            file=sys.stderr,
        )
        return 2
    repositories: dict[str, Path] = {}
    for name, path in arguments.repository:
        if name in repositories:
            raise SystemExit(f"duplicate --repository value for {name}")
        repositories[name] = path
    try:
        environment: Mapping[str, object] | None = None
        if arguments.environment is not None:
            environment = read_json_object(arguments.environment)
        capture_case_study_evidence(
            run_manifest_path=arguments.run_manifest,
            composition_path=arguments.composition,
            runtime_identities_path=arguments.runtime_identities,
            repository_paths=repositories,
            output_path=arguments.output,
            additional_environment=environment,
            notes=arguments.notes,
        )
    except EvidenceError as exc:
        print(f"case-study evidence capture refused: {exc}", file=sys.stderr)
        return 2
    print(f"validated evidence created at {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
