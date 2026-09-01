"""Run the pinned AstralDeep matched-host replacement benchmark on SSH alias s1.

This controller is deliberately fail closed.  It authenticates the endpoint against
the retained address and SSH host-key pins, creates a unique private directory below
the authenticated user's normalized home, and confines every remote write to that
directory.  The retained results are sanitized replacement evidence, not a recovery
of the missing historical benchmark artifact.
"""

from __future__ import annotations

import argparse
import base64
import csv
import errno
import hashlib
import hmac
import importlib.metadata
import io
import ipaddress
import json
import os
import platform
import posixpath
import re
import secrets
import shlex
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .matched_host_path import (
    EXPECTED_ASTRALDEEP_COMMIT,
    EXPECTED_COMPONENTS,
    OUTPUT_CSV,
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
)
from .remote_cluster import Credential, load_credentials

SCHEMA = "lets.remote-matched-host/v1"
TARGET_ALIAS = "s1"
RUN_ROOT_NAME = ".lets-nsdi-matched-host"
RUN_ID_PATTERN = re.compile(r"run-[0-9]{8}-[0-9]{6}-[0-9a-f]{8}\Z")
PYTHON_VERSION = "3.12.3"
EXPECTED_REPLACEMENT_SQLITE = "3.45.1"
HISTORICAL_SQLITE = "3.53.4"
UV_VERSION = "0.8.13"
UV_ASSET = "uv-x86_64-unknown-linux-gnu.tar.gz"
UV_ARCHIVE_SHA256 = "8ca3db7b2a3199171cfc0870be1f819cb853ddcec29a5fa28dae30278922b7ba"
UV_RELEASE = f"https://github.com/astral-sh/uv/releases/download/{UV_VERSION}"
ASTRALDEEP_URL = "https://github.com/AstralDeep/AstralDeep.git"
DEFAULT_INVENTORY = Path("results/nsdi-strengthening-2026-08-31/remote/cluster-inventory.json")
DEFAULT_OUTPUT = Path("results/nsdi-strengthening-2026-08-31/remote/matched-host")
BENCHMARK_SOURCE = Path(__file__).with_name("matched_host_path.py")
MANIFEST_NAME = "remote-matched-host-manifest.json"
RETAINED_NAMES = (OUTPUT_JSON, OUTPUT_CSV, OUTPUT_MARKDOWN, MANIFEST_NAME)
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
DIRECT_REQUIREMENTS = (
    "PyNaCl==1.6.2",
    "httpx==0.28.1",
    "pydantic==2.13.4",
)


class RemoteMatchedHostError(RuntimeError):
    """Raised when a safety or reproducibility condition is not met."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _ssh_key_sha256(key: Any) -> str:
    return base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii")


def _quoted(value: str) -> str:
    return shlex.quote(value)


def _make_run_id() -> str:
    timestamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"run-{timestamp}-{secrets.token_hex(4)}"


def _safe_run_id(value: str | None) -> str:
    selected = _make_run_id() if value is None else value
    if RUN_ID_PATTERN.fullmatch(selected) is None:
        raise ValueError("run id must use run-YYYYMMDD-HHMMSS- plus eight lowercase hex digits")
    return selected


def guarded_remote_child(root: str, *parts: str) -> str:
    """Build a lexical POSIX child path from safe basename components."""

    if (
        not root.startswith("/")
        or posixpath.normpath(root) != root
        or "\x00" in root
        or "\n" in root
        or "\r" in root
    ):
        raise ValueError("remote root must be an absolute normalized POSIX path")
    if not parts or any(
        not part
        or part in {".", ".."}
        or "/" in part
        or "\\" in part
        or "\x00" in part
        or "\n" in part
        or "\r" in part
        for part in parts
    ):
        raise ValueError("remote path components must be safe POSIX basenames")
    candidate = str(PurePosixPath(root).joinpath(*parts))
    if posixpath.commonpath((root, candidate)) != root or candidate == root:
        raise ValueError("remote path escapes its guarded root")
    return candidate


def load_s1_inventory(path: Path) -> Mapping[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("inventory must be a JSON object")
    if payload.get("schema") != "lets.remote-cluster-inventory/v1":
        raise ValueError("inventory schema is not supported")
    if payload.get("addresses_retained") is not False:
        raise ValueError("inventory unexpectedly retains addresses")
    servers = payload.get("servers")
    if not isinstance(servers, list):
        raise ValueError("inventory servers must be an array")
    matches = [
        item for item in servers if isinstance(item, Mapping) and item.get("alias") == TARGET_ALIAS
    ]
    if len(matches) != 1:
        raise ValueError("inventory must contain exactly one s1 record")
    selected = matches[0]
    required = {
        "inventory_ok": True,
        "connected": True,
        "kernel": "Linux",
        "architecture": "x86_64",
        "home_absolute": True,
        "home_normalized": True,
        "home_owned": True,
        "login_matches_credential": True,
    }
    for key, expected in required.items():
        if selected.get(key) != expected:
            raise ValueError(f"s1 inventory does not satisfy {key}")
    for key in ("address_sha256", "host_key_sha256", "host_key_type", "home_path_sha256"):
        if not isinstance(selected.get(key), str) or not selected[key]:
            raise ValueError(f"s1 inventory is missing {key}")
    return selected


def load_s1_credential(path: Path) -> Credential:
    matches = [item for item in load_credentials(path) if item.alias == TARGET_ALIAS]
    if len(matches) != 1:
        raise ValueError("credentials must contain exactly one s1 alias")
    return matches[0]


def verify_address_pin(credential: Credential, inventory: Mapping[str, object]) -> None:
    observed = hashlib.sha256(credential.host.encode("utf-8")).hexdigest()
    expected = str(inventory["address_sha256"])
    if not hmac.compare_digest(observed, expected):
        raise RemoteMatchedHostError("s1 address differs from the pinned inventory")


@dataclass(slots=True)
class PinnedFingerprintPolicy:
    """Paramiko missing-host-key policy that accepts only the retained exact pin."""

    expected_type: str
    expected_sha256: str
    verified: bool = False

    def missing_host_key(self, _client: Any, _hostname: str, key: Any) -> None:
        observed_type = key.get_name()
        observed_sha256 = _ssh_key_sha256(key)
        if observed_type != self.expected_type or not hmac.compare_digest(
            observed_sha256, self.expected_sha256
        ):
            raise RemoteMatchedHostError("s1 SSH host key differs from the pinned inventory")
        self.verified = True


_HOME_PROBE = r"""
import json, os, pwd, stat
uid = os.geteuid()
home = os.environ.get("HOME", "")
record = {"home": home, "uid": uid, "owned": False, "normalized": False,
          "pwd_home_matches": False}
try:
    details = os.lstat(home)
    canonical = os.path.realpath(home)
    record["owned"] = stat.S_ISDIR(details.st_mode) and details.st_uid == uid
    record["normalized"] = (os.path.isabs(home) and os.path.normpath(home) == home
                            and canonical == home)
    record["pwd_home_matches"] = os.path.realpath(pwd.getpwuid(uid).pw_dir) == home
except (KeyError, OSError):
    pass
print(json.dumps(record, sort_keys=True))
""".strip()


_PATH_GUARD = r"""
import errno, json, os, stat, sys

home, target, action = sys.argv[1:4]
uid = os.geteuid()

def fail(message):
    print(json.dumps({"ok": False, "error": message}, sort_keys=True))
    raise SystemExit(73)

if not os.path.isabs(home) or os.path.normpath(home) != home or os.path.realpath(home) != home:
    fail("unsafe_home")
if not os.path.isabs(target) or os.path.normpath(target) != target:
    fail("unsafe_target")
try:
    relative = os.path.relpath(target, home)
except ValueError:
    fail("path_escape")
parts = relative.split(os.sep)
if not parts or parts[0] == ".." or any(part in ("", ".", "..") for part in parts):
    fail("path_escape")

flags = os.O_RDONLY | os.O_DIRECTORY
flags |= getattr(os, "O_NOFOLLOW", 0)
try:
    fd = os.open(home, flags)
except OSError:
    fail("home_open")

try:
    root_stat = os.fstat(fd)
    if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != uid
            or root_stat.st_mode & 0o022):
        fail("home_owner")
    limit = len(parts) if action in ("mkdirs", "verify", "create-run") else len(parts) - 1
    for index, part in enumerate(parts[:limit]):
        existed = True
        try:
            next_fd = os.open(part, flags, dir_fd=fd)
        except FileNotFoundError:
            existed = False
            if action not in ("mkdirs", "create-run"):
                fail("missing_parent")
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                existed = True
            try:
                next_fd = os.open(part, flags, dir_fd=fd)
            except OSError:
                fail("created_parent_open")
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                fail("symlink_parent")
            fail("parent_open")
        details = os.fstat(next_fd)
        if (not stat.S_ISDIR(details.st_mode) or details.st_uid != uid
                or details.st_mode & 0o022):
            os.close(next_fd)
            fail("foreign_parent")
        if action == "create-run" and index == len(parts) - 1 and existed:
            os.close(next_fd)
            fail("run_exists")
        os.close(fd)
        fd = next_fd

    if action == "guard-write":
        leaf = parts[-1]
        try:
            details = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            details = None
        if details is not None and (stat.S_ISLNK(details.st_mode) or details.st_uid != uid):
            fail("unsafe_leaf")
    elif action not in ("mkdirs", "verify", "create-run"):
        fail("unknown_action")
finally:
    os.close(fd)

print(json.dumps({"ok": True, "action": action}, sort_keys=True))
""".strip()


def _command_result(stream: Any) -> tuple[int, str, str]:
    output = stream[1].read().decode("utf-8", errors="replace")
    error = stream[2].read().decode("utf-8", errors="replace")
    return stream[1].channel.recv_exit_status(), output, error


@dataclass(slots=True)
class RemoteSession:
    credential: Credential
    inventory: Mapping[str, object]
    client: Any = field(init=False, default=None, repr=False)
    sftp: Any = field(init=False, default=None, repr=False)
    home: str = field(init=False, default="", repr=False)
    uid: int = field(init=False, default=-1, repr=False)
    run_root: str = field(init=False, default="", repr=False)
    commands: list[str] = field(init=False, default_factory=list)

    def connect(self, *, paramiko_module: Any | None = None) -> None:
        verify_address_pin(self.credential, self.inventory)
        if paramiko_module is None:
            try:
                import paramiko as paramiko_module
            except ImportError as exc:  # pragma: no cover - environment diagnostic
                raise RemoteMatchedHostError(
                    "Paramiko is required in the controller environment"
                ) from exc
        policy = PinnedFingerprintPolicy(
            str(self.inventory["host_key_type"]), str(self.inventory["host_key_sha256"])
        )
        client = paramiko_module.SSHClient()
        client.set_missing_host_key_policy(policy)
        try:
            client.connect(
                self.credential.host,
                username=self.credential.username,
                password=self.credential.password,
                look_for_keys=False,
                allow_agent=False,
                timeout=15,
                banner_timeout=15,
                auth_timeout=15,
            )
            transport = client.get_transport()
            if transport is None or not transport.is_active():
                raise RemoteMatchedHostError("s1 SSH transport is not active")
            key = transport.get_remote_server_key()
            if not policy.verified:
                policy.missing_host_key(client, TARGET_ALIAS, key)
            if key.get_name() != policy.expected_type or not hmac.compare_digest(
                _ssh_key_sha256(key), policy.expected_sha256
            ):
                raise RemoteMatchedHostError("s1 SSH host key post-check failed")
            self.client = client
            self.sftp = client.open_sftp()
            probe = self.require(
                f"python3 -I -c {_quoted(_HOME_PROBE)}", "resolving authenticated home"
            )
            details = json.loads(probe)
            home = details.get("home")
            if (
                not isinstance(home, str)
                or details.get("owned") is not True
                or details.get("normalized") is not True
                or details.get("pwd_home_matches") is not True
                or not isinstance(details.get("uid"), int)
            ):
                raise RemoteMatchedHostError("authenticated home is not normalized and user-owned")
            if self.sftp.normalize(home) != home:
                raise RemoteMatchedHostError("SFTP home normalization differs from the login home")
            expected_home_hash = str(self.inventory["home_path_sha256"])
            observed_home_hash = hashlib.sha256(home.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(observed_home_hash, expected_home_hash):
                raise RemoteMatchedHostError("authenticated home differs from the pinned inventory")
            self.home = home
            self.uid = int(details["uid"])
        except Exception as exc:
            client.close()
            self.client = None
            self.sftp = None
            if isinstance(exc, RemoteMatchedHostError):
                raise
            raise RemoteMatchedHostError(
                f"s1 connection or home validation failed: {type(exc).__name__}"
            ) from exc

    def close(self) -> None:
        if self.sftp is not None:
            self.sftp.close()
            self.sftp = None
        if self.client is not None:
            self.client.close()
            self.client = None

    def run(self, command: str, *, timeout: float = 120) -> tuple[int, str, str]:
        if self.client is None:
            raise RemoteMatchedHostError("SSH client is not connected")
        return _command_result(self.client.exec_command(command, timeout=timeout))

    def require(self, command: str, stage: str, *, timeout: float = 120) -> str:
        code, output, error = self.run(command, timeout=timeout)
        if code != 0:
            diagnostic = self.sanitize(error or output)[:500]
            raise RemoteMatchedHostError(f"s1 failed during {stage} (exit {code}): {diagnostic}")
        return output

    def sanitize(self, value: str) -> str:
        return _sanitize_text(value, self)

    def child(self, *parts: str) -> str:
        if not self.run_root:
            raise RemoteMatchedHostError("run root has not been created")
        return guarded_remote_child(self.run_root, *parts)

    def _guard(self, target: str, action: str, stage: str) -> None:
        if not self.home:
            raise RemoteMatchedHostError("authenticated home has not been established")
        if posixpath.commonpath((self.home, target)) != self.home or target == self.home:
            raise RemoteMatchedHostError("remote target is outside the normalized home")
        command = (
            f"python3 -I -c {_quoted(_PATH_GUARD)} {_quoted(self.home)} "
            f"{_quoted(target)} {_quoted(action)}"
        )
        self.require(command, stage)

    def create_run_root(self, run_id: str) -> str:
        if self.run_root:
            raise RemoteMatchedHostError("run root was already created")
        target = guarded_remote_child(self.home, RUN_ROOT_NAME, run_id)
        self._guard(target, "create-run", "creating the exclusive guarded run root")
        self.run_root = target
        return target

    def mkdirs(self, target: str) -> None:
        self._require_in_run(target)
        self._guard(target, "mkdirs", "creating a guarded run directory")

    def guard_write(self, target: str) -> None:
        self._require_in_run(target)
        self._guard(target, "guard-write", "checking a remote write target")

    def verify_path(self, target: str) -> None:
        self._require_in_run(target)
        self._guard(target, "verify", "verifying an existing remote path")

    def _require_in_run(self, target: str) -> None:
        if (
            not self.run_root
            or posixpath.commonpath((self.run_root, target)) != self.run_root
            or target == self.run_root
        ):
            raise RemoteMatchedHostError("remote write target is outside the unique run root")

    def environment(self) -> str:
        paths = {
            "TMPDIR": self.child("tmp"),
            "XDG_CACHE_HOME": self.child("cache", "xdg"),
            "XDG_CONFIG_HOME": self.child("config"),
            "PIP_CACHE_DIR": self.child("cache", "pip"),
            "UV_CACHE_DIR": self.child("cache", "uv"),
            "PYTHONPYCACHEPREFIX": self.child("cache", "pycache"),
            "UV_PYTHON_INSTALL_DIR": self.child("python"),
            "UV_TOOL_DIR": self.child("tools", "uv-tools"),
            "UV_TOOL_BIN_DIR": self.child("tools", "uv-bin"),
            "CARGO_HOME": self.child("cache", "cargo"),
        }
        exports = " ".join(f"{key}={_quoted(value)}" for key, value in paths.items())
        return (
            "set -eu; umask 077; "
            "unset PYTHONPATH PYTHONHOME VIRTUAL_ENV PIP_INDEX_URL PIP_EXTRA_INDEX_URL "
            "PIP_TRUSTED_HOST UV_INDEX UV_INDEX_URL UV_EXTRA_INDEX_URL; "
            f"export {exports}; "
            "export PYTHONNOUSERSITE=1 UV_NO_PROGRESS=1 UV_NO_CONFIG=1 "
            "PIP_CONFIG_FILE=/dev/null PIP_INDEX_URL=https://pypi.org/simple "
            "UV_INDEX_URL=https://pypi.org/simple UV_DEFAULT_INDEX=https://pypi.org/simple "
            "GIT_TERMINAL_PROMPT=0 "
            "GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1; "
        )

    def guarded_command(
        self,
        command: str,
        stage: str,
        *,
        write_targets: Iterable[str],
        timeout: float = 120,
        display: str | None = None,
    ) -> str:
        targets = tuple(write_targets)
        if not targets:
            raise ValueError("a mutating command must declare at least one write target")
        for target in targets:
            self.guard_write(target)
        rendered = self.environment() + command
        self.commands.append(self.sanitize(display or command))
        return self.require(rendered, stage, timeout=timeout)

    def upload(self, source: Path, target: str, *, mode: int = 0o600) -> None:
        if not source.is_file():
            raise ValueError("upload source is not a file")
        self.guard_write(target)
        try:
            with source.open("rb") as incoming, self.sftp.file(target, "wx") as outgoing:
                _copy_stream(incoming, outgoing)
                outgoing.flush()
            self.sftp.chmod(target, mode)
        except Exception as exc:
            raise RemoteMatchedHostError(
                f"s1 exclusive upload failed: {type(exc).__name__}"
            ) from exc
        self.verify_regular_file(target)
        self.commands.append(f"upload {source.name} -> {self.sanitize(target)}")

    def verify_regular_file(self, target: str) -> int:
        self._require_in_run(target)
        attributes = self.sftp.lstat(target)
        if (
            not stat.S_ISREG(attributes.st_mode)
            or stat.S_ISLNK(attributes.st_mode)
            or attributes.st_uid != self.uid
        ):
            raise RemoteMatchedHostError("remote artifact is not a user-owned regular file")
        return int(attributes.st_size)

    def download(self, target: str) -> bytes:
        size = self.verify_regular_file(target)
        if size > MAX_ARTIFACT_BYTES:
            raise RemoteMatchedHostError("remote artifact exceeds the retained evidence size limit")
        with self.sftp.file(target, "rb") as stream:
            payload = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(payload) != size or len(payload) > MAX_ARTIFACT_BYTES:
            raise RemoteMatchedHostError("remote artifact changed or exceeded its size while read")
        return payload


@dataclass(frozen=True, slots=True)
class RecoveryCandidate:
    run_id: str
    timestamp: datetime
    remote_root: str = field(repr=False)
    raw_artifacts: Mapping[str, bytes] = field(repr=False)
    document: Mapping[str, object] = field(repr=False)
    clone_identity: Mapping[str, object] = field(repr=False)
    uv_archive_sha256: str = field(repr=False)


def _copy_stream(source: BinaryIO, destination: Any) -> None:
    for block in iter(lambda: source.read(1024 * 1024), b""):
        destination.write(block)


def _redact_ip_literals(value: str, replacement_text: str = "<redacted-ip>") -> str:
    ipv4_pattern = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
    ipv6_pattern = re.compile(
        r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
        r"(?![0-9A-Fa-f:])"
    )

    def replacement(match: re.Match[str]) -> str:
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            return match.group(0)
        return replacement_text

    return ipv6_pattern.sub(replacement, ipv4_pattern.sub(replacement, value))


def _collision_free_placeholder(preferred: str, forbidden: Sequence[str], used: set[str]) -> str:
    """Choose a retained token that cannot itself contain a forbidden value."""

    if preferred not in used and all(secret not in preferred for secret in forbidden):
        used.add(preferred)
        return preferred
    for candidate in "!#$%&()*+,-/;=?@[]^_`{|}~":
        if candidate not in used and all(secret not in candidate for secret in forbidden):
            used.add(candidate)
            return candidate
    raise RemoteMatchedHostError("could not construct collision-free redaction tokens")


def _credential_expression(secret: str) -> str:
    left = r"(?<![A-Za-z0-9_])" if secret[0].isalnum() or secret[0] == "_" else ""
    right = r"(?![A-Za-z0-9_])" if secret[-1].isalnum() or secret[-1] == "_" else ""
    return left + re.escape(secret) + right


def _sanitize_text(value: str, session: RemoteSession) -> str:
    entries = (
        (session.run_root, "$RUN_ROOT", True),
        (session.home, "$HOME", True),
        (session.credential.password, "<redacted-secret>", False),
        (session.credential.username, "<redacted-user>", False),
        (session.credential.host, "<redacted-address>", False),
    )
    forbidden = tuple(dict.fromkeys(original for original, _token, _literal in entries if original))
    used: set[str] = set()
    replacements: list[tuple[str, str, bool]] = []
    seen: set[str] = set()
    ordered_entries = sorted(entries, key=lambda item: len(item[0]), reverse=True)
    for original, preferred, literal in ordered_entries:
        if original and original not in seen:
            replacements.append(
                (original, _collision_free_placeholder(preferred, forbidden, used), literal)
            )
            seen.add(original)
    ip_placeholder = _collision_free_placeholder("<redacted-ip>", forbidden, used)
    if replacements:
        expressions: list[str] = []
        tokens: dict[str, str] = {}
        for index, (original, token, literal) in enumerate(replacements):
            name = f"secret_{index}"
            expression = re.escape(original) if literal else _credential_expression(original)
            expressions.append(f"(?P<{name}>{expression})")
            tokens[name] = token
        pattern = re.compile("|".join(expressions))
        value = pattern.sub(lambda match: tokens[str(match.lastgroup)], value)
    return _redact_ip_literals(value, ip_placeholder)


def _contains_sensitive_context(value: str, session: RemoteSession) -> bool:
    if any(secret and secret in value for secret in (session.run_root, session.home)):
        return True
    credentials = (
        session.credential.password,
        session.credential.username,
        session.credential.host,
    )
    if any(secret and re.search(_credential_expression(secret), value) for secret in credentials):
        return True
    return _redact_ip_literals(value, "") != value


def validate_uv_archive(path: Path, expected_sha256: str) -> dict[str, str]:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("uv SHA-256 must be 64 lowercase hexadecimal characters")
    actual = sha256_file(path)
    if not hmac.compare_digest(actual, expected_sha256):
        raise RemoteMatchedHostError("uv archive failed its pinned SHA-256")
    prefix = "uv-x86_64-unknown-linux-gnu/"
    root_member = prefix.rstrip("/")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if not members or len(members) > 8:
            raise RemoteMatchedHostError("uv archive member count is unexpected")
        for member in members:
            pure = PurePosixPath(member.name)
            if (
                member.name.startswith("/")
                or ".." in pure.parts
                or not (member.name == root_member or member.name.startswith(prefix))
                or member.issym()
                or member.islnk()
                or not (member.isdir() or member.isfile())
            ):
                raise RemoteMatchedHostError("uv archive contains an unsafe member")
        binary = f"{prefix}uv"
        if binary not in {member.name for member in members if member.isfile()}:
            raise RemoteMatchedHostError("uv archive does not contain the expected uv binary")
    return {"version": UV_VERSION, "asset": UV_ASSET, "sha256": actual}


def fetch_uv_archive(destination: Path) -> dict[str, str]:
    archive_url = f"{UV_RELEASE}/{UV_ASSET}"
    with urllib.request.urlopen(f"{archive_url}.sha256", timeout=60) as response:
        checksum = response.read().decode("ascii", errors="strict").strip().split()[0].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise RemoteMatchedHostError("published uv checksum is malformed")
    with urllib.request.urlopen(archive_url, timeout=180) as response:
        destination.write_bytes(response.read())
    return validate_uv_archive(destination, checksum)


def _remote_sha256(session: RemoteSession, path: str) -> str:
    script = (
        "import hashlib,sys; p=sys.argv[1]; h=hashlib.sha256(); "
        "f=open(p,'rb'); "
        "[(h.update(b)) for b in iter(lambda:f.read(1048576),b'')]; "
        "f.close(); print(h.hexdigest())"
    )
    output = session.require(
        f"python3 -I -c {_quoted(script)} {_quoted(path)}", "hashing a remote input"
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{64}", output):
        raise RemoteMatchedHostError("remote SHA-256 probe returned malformed output")
    return output


def _git_identity(path: Path) -> dict[str, object]:
    def git(*arguments: str) -> str:
        result = subprocess.run(
            ("git", *arguments),
            cwd=path,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )
        return result.stdout.strip()

    status = git("status", "--porcelain=v1", "--untracked-files=all")
    return {
        "commit": git("rev-parse", "HEAD"),
        "tree": git("rev-parse", "HEAD^{tree}"),
        "dirty": bool(status),
        "status_sha256": sha256_bytes(status.encode("utf-8")),
    }


def _probe_remote_environment(session: RemoteSession, python: str, uv: str) -> dict[str, object]:
    probe = (
        "import hashlib,json,platform,sqlite3,sys; "
        "p=sys.executable; h=hashlib.sha256(open(p,'rb').read()).hexdigest(); "
        "print(json.dumps({'python':platform.python_version(),"
        "'implementation':platform.python_implementation(),'sqlite':sqlite3.sqlite_version,"
        "'platform':platform.platform(),'machine':platform.machine(),"
        "'executable_sha256':h},sort_keys=True))"
    )
    environment = json.loads(
        session.require(
            session.environment() + f"{_quoted(python)} -I -c {_quoted(probe)}",
            "capturing the benchmark interpreter environment",
        )
    )
    if not isinstance(environment, dict):
        raise RemoteMatchedHostError("interpreter environment probe is not a JSON object")
    packages = session.require(
        session.environment() + f"{_quoted(uv)} pip freeze --python {_quoted(python)}",
        "capturing installed dependency versions",
    ).splitlines()
    environment["packages"] = sorted(item for item in packages if item.strip())
    if environment.get("python") != PYTHON_VERSION:
        raise RemoteMatchedHostError("benchmark interpreter is not exact CPython 3.12.3")
    if environment.get("implementation") != "CPython":
        raise RemoteMatchedHostError("benchmark interpreter is not CPython")
    if environment.get("sqlite") != EXPECTED_REPLACEMENT_SQLITE:
        raise RemoteMatchedHostError(
            "s1 SQLite no longer matches the diagnosed 3.45.1 replacement environment"
        )
    return environment


def _verify_clone(session: RemoteSession, deep: str) -> dict[str, object]:
    plane = guarded_remote_child(deep, "components", "AstralPlane")
    lets = guarded_remote_child(deep, "components", "LETS")
    projection_git = guarded_remote_child(deep, "components", "AstralProjection", ".git")
    primitives_git = guarded_remote_child(deep, "components", "AstralPrimitives", ".git")
    script = (
        "set -eu; export GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_GLOBAL=/dev/null "
        "GIT_CONFIG_NOSYSTEM=1; "
        f'test "$(git -C {_quoted(deep)} rev-parse HEAD)" = '
        f"{_quoted(EXPECTED_ASTRALDEEP_COMMIT)}; "
        f'test "$(git -C {_quoted(plane)} rev-parse HEAD)" = '
        f"{_quoted(EXPECTED_COMPONENTS['astral-plane'])}; "
        f'test "$(git -C {_quoted(lets)} rev-parse HEAD)" = '
        f"{_quoted(EXPECTED_COMPONENTS['lets'])}; "
        f'test "$(git -C {_quoted(deep)} remote get-url origin)" = {_quoted(ASTRALDEEP_URL)}; '
        f'test -z "$(git -C {_quoted(deep)} status --porcelain=v1 '
        '--untracked-files=all --ignore-submodules=none)"; '
        f"test ! -e {_quoted(projection_git)}; "
        f"test ! -e {_quoted(primitives_git)}; "
        "printf passed"
    )
    verification = session.require(
        script, "verifying the exact clean two-submodule composition"
    ).strip()
    if verification != "passed":
        raise RemoteMatchedHostError("remote Git composition verification failed")
    return {
        "astraldeep": EXPECTED_ASTRALDEEP_COMMIT,
        "astral_plane": EXPECTED_COMPONENTS["astral-plane"],
        "lets": EXPECTED_COMPONENTS["lets"],
        "initialized_submodules": ["components/AstralPlane", "components/LETS"],
        "other_submodules_initialized": False,
        "clean": True,
    }


def benchmark_command(
    python: str,
    benchmark: str,
    deep: str,
    storage: str,
    output: str,
) -> str:
    """Render the fixed replacement benchmark CLI without shell interpolation."""

    return (
        f"{_quoted(python)} {_quoted(benchmark)} --astraldeep-root {_quoted(deep)} "
        f"--storage-root {_quoted(storage)} --output {_quoted(output)} "
        "--trials 10 --operations 1000 --warmups 100"
    )


def validate_benchmark_artifacts(
    artifacts: Mapping[str, bytes], *, expected_benchmark_sha256: str | None = None
) -> dict[str, object]:
    if set(artifacts) != {OUTPUT_JSON, OUTPUT_CSV, OUTPUT_MARKDOWN}:
        raise RemoteMatchedHostError("benchmark did not return its exact three-artifact set")
    try:
        document = json.loads(artifacts[OUTPUT_JSON])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteMatchedHostError("benchmark JSON is malformed") from exc
    if not isinstance(document, Mapping):
        raise RemoteMatchedHostError("benchmark JSON is not an object")
    if document.get("claim") != "replacement-current-composition-not-historical-reproduction":
        raise RemoteMatchedHostError("benchmark result has the wrong replacement claim")
    configuration = document.get("configuration")
    if configuration != {"operations": 1000, "trials": 10, "warmups": 100}:
        raise RemoteMatchedHostError("benchmark result has the wrong fixed configuration")
    environment = document.get("environment")
    if not isinstance(environment, Mapping):
        raise RemoteMatchedHostError("benchmark result has no environment record")
    if environment.get("python") != PYTHON_VERSION:
        raise RemoteMatchedHostError("benchmark JSON did not retain exact Python 3.12.3")
    if environment.get("sqlite") != EXPECTED_REPLACEMENT_SQLITE:
        raise RemoteMatchedHostError("benchmark JSON did not retain SQLite 3.45.1")
    harness = environment.get("harness_repository")
    if (
        not isinstance(harness, Mapping)
        or harness.get("available") is not False
        or harness.get("reason") != "standalone-source-upload"
    ):
        raise RemoteMatchedHostError(
            "benchmark JSON does not identify the standalone harness upload"
        )
    instrumentation = environment.get("instrumentation")
    if expected_benchmark_sha256 is not None and (
        harness.get("benchmark_sha256") != expected_benchmark_sha256
        or not isinstance(instrumentation, Mapping)
        or instrumentation.get("benchmark_sha256") != expected_benchmark_sha256
    ):
        raise RemoteMatchedHostError("benchmark JSON is not bound to the uploaded harness hash")
    astraldeep = environment.get("astraldeep")
    components = environment.get("components")
    if (
        not isinstance(astraldeep, Mapping)
        or astraldeep.get("revision") != EXPECTED_ASTRALDEEP_COMMIT
    ):
        raise RemoteMatchedHostError("benchmark JSON has the wrong AstralDeep commit")
    if not isinstance(components, Mapping):
        raise RemoteMatchedHostError("benchmark JSON has no component identities")
    for name in ("astral-plane", "lets"):
        identity = components.get(name)
        if (
            not isinstance(identity, Mapping)
            or identity.get("revision") != EXPECTED_COMPONENTS[name]
        ):
            raise RemoteMatchedHostError(f"benchmark JSON has the wrong {name} commit")
    scope = document.get("scope")
    if not isinstance(scope, Mapping) or scope.get("historical_artifact_available") is not False:
        raise RemoteMatchedHostError(
            "benchmark JSON does not disclose the missing historical artifact"
        )
    trials = document.get("trials")
    if not isinstance(trials, list) or len(trials) != 20:
        raise RemoteMatchedHostError("benchmark JSON must retain two modes for each of ten trials")
    for trial in trials:
        samples = trial.get("samples") if isinstance(trial, Mapping) else None
        if not isinstance(samples, list) or len(samples) != 1000:
            raise RemoteMatchedHostError(
                "benchmark JSON does not retain 1,000 samples per mode/trial"
            )

    csv_text = artifacts[OUTPUT_CSV].decode("utf-8")
    rows = sum(1 for _row in csv.reader(io.StringIO(csv_text)))
    if rows != 20_001:
        raise RemoteMatchedHostError("benchmark CSV does not contain 20,000 measured operations")
    markdown = artifacts[OUTPUT_MARKDOWN].decode("utf-8")
    if "not an exact" not in markdown or "missing `20260826T231656Z`" not in markdown:
        raise RemoteMatchedHostError("benchmark Markdown omits the replacement disclosure")
    return document


def _recovery_timestamp(run_id: str) -> datetime:
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise RemoteMatchedHostError("remote recovery entry has an invalid run identifier")
    try:
        return datetime.strptime(run_id[4:19], "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
    except ValueError as exc:
        raise RemoteMatchedHostError("remote recovery entry has an invalid timestamp") from exc


def select_latest_recovery_candidate(
    candidates: Sequence[RecoveryCandidate],
) -> RecoveryCandidate:
    if not candidates:
        raise RemoteMatchedHostError("no completed remote run matches the exact evidence contract")
    latest_timestamp = max(candidate.timestamp for candidate in candidates)
    latest = [candidate for candidate in candidates if candidate.timestamp == latest_timestamp]
    if len(latest) != 1:
        raise RemoteMatchedHostError("multiple matching remote runs share the latest timestamp")
    return latest[0]


def _recovery_timing(
    candidate: RecoveryCandidate,
    environment: Mapping[str, object],
    recovered_at: str,
) -> dict[str, object]:
    return {
        "started_at_utc": None,
        "completed_at_utc": recovered_at,
        "run_root_created_at_utc": candidate.timestamp.isoformat(),
        "environment_captured_at_utc": environment.get("captured_at_utc"),
        "recovered_at_utc": recovered_at,
    }


def _safe_recovery_roots(session: RemoteSession) -> list[tuple[str, str]]:
    parent = guarded_remote_child(session.home, RUN_ROOT_NAME)
    session._guard(parent, "verify", "verifying the read-only recovery parent")
    try:
        entries = session.sftp.listdir_attr(parent)
    except OSError as exc:
        raise RemoteMatchedHostError("could not enumerate the guarded recovery parent") from exc
    roots: list[tuple[str, str]] = []
    for entry in entries:
        name = getattr(entry, "filename", None)
        mode = int(getattr(entry, "st_mode", 0))
        owner = int(getattr(entry, "st_uid", -1))
        if not isinstance(name, str) or RUN_ID_PATTERN.fullmatch(name) is None:
            raise RemoteMatchedHostError("recovery parent contains an unexpected entry")
        _recovery_timestamp(name)
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode) or owner != session.uid or mode & 0o022:
            raise RemoteMatchedHostError("recovery parent contains an unsafe run directory")
        target = guarded_remote_child(session.home, RUN_ROOT_NAME, name)
        if session.sftp.normalize(target) != target:
            raise RemoteMatchedHostError("recovery run directory does not normalize in place")
        roots.append((name, target))
    return roots


def _recovery_directory(session: RemoteSession, target: str) -> bool:
    try:
        attributes = session.sftp.lstat(target)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return False
        raise RemoteMatchedHostError("could not inspect a recovery directory") from exc
    mode = int(attributes.st_mode)
    if (
        stat.S_ISLNK(mode)
        or not stat.S_ISDIR(mode)
        or attributes.st_uid != session.uid
        or mode & 0o022
    ):
        raise RemoteMatchedHostError("a recovery candidate contains an unsafe directory")
    if session.sftp.normalize(target) != target:
        raise RemoteMatchedHostError("a recovery candidate directory resolves through a symlink")
    session.verify_path(target)
    return True


def _recovery_regular_file(session: RemoteSession, target: str) -> bool:
    try:
        session.verify_regular_file(target)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return False
        raise RemoteMatchedHostError("could not inspect a recovery file") from exc
    return True


def _load_recovery_candidate(
    session: RemoteSession,
    run_id: str,
    remote_root: str,
    expected_benchmark_sha256: str,
) -> RecoveryCandidate | None:
    session.run_root = remote_root
    required_directories = {
        name: session.child(name)
        for name in ("AstralDeep", "output", "runner", "storage", "uploads")
    }
    directory_presence = [
        _recovery_directory(session, path) for path in required_directories.values()
    ]
    if not all(directory_presence):
        return None

    remote_benchmark = session.child("runner", "matched_host_path.py")
    remote_uv_archive = session.child("uploads", UV_ASSET)
    required_files = (remote_benchmark, remote_uv_archive)
    file_presence = [_recovery_regular_file(session, path) for path in required_files]
    if not all(file_presence):
        return None
    if _remote_sha256(session, remote_benchmark) != expected_benchmark_sha256:
        return None
    uv_archive_sha256 = _remote_sha256(session, remote_uv_archive)
    if uv_archive_sha256 != UV_ARCHIVE_SHA256:
        return None

    result_dir = required_directories["output"]
    try:
        output_entries = session.sftp.listdir_attr(result_dir)
    except OSError as exc:
        raise RemoteMatchedHostError("could not enumerate recovery artifacts") from exc
    expected_names = {OUTPUT_JSON, OUTPUT_CSV, OUTPUT_MARKDOWN}
    if {getattr(entry, "filename", None) for entry in output_entries} != expected_names:
        return None
    raw_artifacts: dict[str, bytes] = {}
    for name in expected_names:
        target = guarded_remote_child(result_dir, name)
        if not _recovery_regular_file(session, target):
            return None
        raw_artifacts[name] = session.download(target)
    try:
        document = validate_benchmark_artifacts(
            raw_artifacts, expected_benchmark_sha256=expected_benchmark_sha256
        )
        clone_identity = _verify_clone(session, required_directories["AstralDeep"])
    except RemoteMatchedHostError:
        return None
    environment = document.get("environment")
    storage_identity = environment.get("storage") if isinstance(environment, Mapping) else None
    if (
        not isinstance(storage_identity, Mapping)
        or storage_identity.get("resolved_root") != required_directories["storage"]
    ):
        return None
    return RecoveryCandidate(
        run_id=run_id,
        timestamp=_recovery_timestamp(run_id),
        remote_root=remote_root,
        raw_artifacts=raw_artifacts,
        document=document,
        clone_identity=clone_identity,
        uv_archive_sha256=uv_archive_sha256,
    )


def _sanitize_object(value: object, session: RemoteSession) -> object:
    if isinstance(value, str):
        return session.sanitize(value)
    if isinstance(value, list):
        return [_sanitize_object(item, session) for item in value]
    if isinstance(value, dict):
        return {str(key): _sanitize_object(item, session) for key, item in value.items()}
    return value


def _string_values(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _string_values(item)
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _string_values(item)


def sanitize_artifacts(artifacts: Mapping[str, bytes], session: RemoteSession) -> dict[str, bytes]:
    retained: dict[str, bytes] = {}
    document = json.loads(artifacts[OUTPUT_JSON])
    sanitized_document = _sanitize_object(document, session)
    retained[OUTPUT_JSON] = (
        json.dumps(sanitized_document, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    for name in (OUTPUT_CSV, OUTPUT_MARKDOWN):
        text = artifacts[name].decode("utf-8")
        retained[name] = session.sanitize(text).encode("utf-8")
    sanitized_values = _string_values(sanitized_document)
    if any(_contains_sensitive_context(value, session) for value in sanitized_values):
        raise RemoteMatchedHostError(
            f"sanitization left credential material in {OUTPUT_JSON} values"
        )
    for name in (OUTPUT_CSV, OUTPUT_MARKDOWN):
        text = retained[name].decode("utf-8")
        if _contains_sensitive_context(text, session):
            raise RemoteMatchedHostError(f"sanitization left credential material in {name}")
    return retained


def _preflight_retained(output: Path, *, overwrite: bool) -> Path:
    if output.absolute().is_symlink():
        raise RemoteMatchedHostError("retained output must not be a symlink")
    output = output.resolve()
    if output.exists():
        if not output.is_dir() or output.is_symlink():
            raise RemoteMatchedHostError("retained output is not a real directory")
        unexpected = [item.name for item in output.iterdir() if item.name not in RETAINED_NAMES]
        if unexpected:
            raise RemoteMatchedHostError("retained output directory contains unexpected files")
        existing = [output / name for name in RETAINED_NAMES if (output / name).exists()]
        if existing and not overwrite:
            raise RemoteMatchedHostError("refusing to overwrite retained matched-host evidence")
    return output


def _write_retained(
    output: Path,
    artifacts: Mapping[str, bytes],
    manifest: Mapping[str, object],
    *,
    overwrite: bool,
) -> tuple[Path, ...]:
    output = _preflight_retained(output, overwrite=overwrite)
    if not output.exists():
        output.mkdir(parents=True)
    payloads = dict(artifacts)
    payloads[MANIFEST_NAME] = (
        json.dumps(manifest, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    written: list[Path] = []
    for name in RETAINED_NAMES:
        target = output / name
        if target.exists() and target.is_symlink():
            raise RemoteMatchedHostError("refusing to replace a symlinked retained artifact")
        if overwrite:
            temporary = output / f".{name}.{secrets.token_hex(6)}.tmp"
            try:
                with temporary.open("xb") as stream:
                    stream.write(payloads[name])
                os.replace(temporary, target)
            finally:
                if temporary.exists():
                    temporary.unlink()
        else:
            with target.open("xb") as stream:
                stream.write(payloads[name])
        written.append(target)
    return tuple(written)


def _source_identity() -> dict[str, object]:
    repository = Path(__file__).resolve().parents[2]
    try:
        git = _git_identity(repository)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        git = {"available": False}
    try:
        paramiko_version: str | None = importlib.metadata.version("paramiko")
    except importlib.metadata.PackageNotFoundError:
        paramiko_version = None
    return {
        "controller_git": git,
        "orchestrator_sha256": sha256_file(Path(__file__).resolve()),
        "benchmark_sha256": sha256_file(BENCHMARK_SOURCE.resolve()),
        "controller_python": platform.python_version(),
        "controller_platform": platform.platform(),
        "controller_paramiko": paramiko_version,
    }


def _prepare_uv(
    directory: Path, supplied: Path | None, supplied_sha256: str | None
) -> tuple[Path, dict[str, str]]:
    destination = directory / UV_ASSET
    if supplied is None:
        return destination, fetch_uv_archive(destination)
    if supplied_sha256 is None:
        raise ValueError("--uv-sha256 is required with --uv-archive")
    source = supplied.resolve(strict=True)
    metadata = validate_uv_archive(source, supplied_sha256)
    return source, metadata


def run_remote_matched_host(
    credentials_path: Path,
    inventory_path: Path,
    output: Path,
    *,
    run_id: str | None = None,
    overwrite: bool = False,
    uv_archive: Path | None = None,
    uv_sha256: str | None = None,
    session_factory: Any = RemoteSession,
) -> dict[str, object]:
    """Execute the fixed remote run and retain only sanitized evidence."""

    selected_run_id = _safe_run_id(run_id)
    output = _preflight_retained(output, overwrite=overwrite)
    credential = load_s1_credential(credentials_path)
    inventory = load_s1_inventory(inventory_path)
    session: RemoteSession = session_factory(credential, inventory)
    source = _source_identity()
    started = datetime.now(UTC).isoformat()
    try:
        session.connect()
        session.create_run_root(selected_run_id)
        directories = (
            ("uploads",),
            ("tools",),
            ("tools", "unpack"),
            ("tools", "uv-tools"),
            ("tools", "uv-bin"),
            ("runner",),
            ("tmp",),
            ("cache",),
            ("cache", "xdg"),
            ("cache", "pip"),
            ("cache", "uv"),
            ("cache", "pycache"),
            ("cache", "cargo"),
            ("config",),
            ("python",),
            ("storage",),
        )
        for parts in directories:
            session.mkdirs(session.child(*parts))

        with tempfile.TemporaryDirectory(prefix="lets-matched-host-controller-") as temporary:
            uv_source, uv_metadata = _prepare_uv(Path(temporary), uv_archive, uv_sha256)
            remote_uv_archive = session.child("uploads", UV_ASSET)
            remote_benchmark = session.child("runner", "matched_host_path.py")
            session.upload(uv_source, remote_uv_archive)
            session.upload(BENCHMARK_SOURCE.resolve(), remote_benchmark)
            if _remote_sha256(session, remote_uv_archive) != uv_metadata["sha256"]:
                raise RemoteMatchedHostError("uploaded uv archive hash differs")
            if _remote_sha256(session, remote_benchmark) != source["benchmark_sha256"]:
                raise RemoteMatchedHostError("uploaded benchmark source hash differs")

        unpack = session.child("tools", "unpack")
        uv = session.child("tools", "uv")
        extracted_uv = session.child("tools", "unpack", "uv-x86_64-unknown-linux-gnu", "uv")
        session.guarded_command(
            f"tar -xzf {_quoted(remote_uv_archive)} -C {_quoted(unpack)}; "
            f"cp {_quoted(extracted_uv)} {_quoted(uv)}; chmod 700 {_quoted(uv)}",
            "installing pinned uv inside the run root",
            write_targets=(unpack, uv),
            display=f"extract verified {UV_ASSET}; install tools/uv",
        )
        uv_version = session.require(
            session.environment() + f"{_quoted(uv)} --version", "verifying pinned uv"
        ).strip()
        if uv_version != f"uv {UV_VERSION}":
            raise RemoteMatchedHostError("home-scoped uv has the wrong version")

        deep = session.child("AstralDeep")
        session.guarded_command(
            f"git clone --filter=blob:none --no-checkout --no-tags {_quoted(ASTRALDEEP_URL)} "
            f"{_quoted(deep)}",
            "cloning public AstralDeep",
            write_targets=(deep,),
            timeout=600,
            display=(
                "git clone --filter=blob:none --no-checkout --no-tags "
                "<public-AstralDeep> $RUN_ROOT/AstralDeep"
            ),
        )
        session.guarded_command(
            f"git -C {_quoted(deep)} checkout --detach {_quoted(EXPECTED_ASTRALDEEP_COMMIT)}; "
            f"git -C {_quoted(deep)} submodule update --init --checkout -- "
            "components/AstralPlane components/LETS",
            "checking out the pinned two-submodule composition",
            write_targets=(deep,),
            timeout=900,
            display=(
                f"git checkout --detach {EXPECTED_ASTRALDEEP_COMMIT}; git submodule update "
                "--init --checkout -- components/AstralPlane components/LETS"
            ),
        )
        clone_identity = _verify_clone(session, deep)

        system_probe = (
            "import json,platform,sys; print(json.dumps({'executable':sys.executable,"
            "'implementation':platform.python_implementation(),'version':platform.python_version()}))"
        )
        system = json.loads(
            session.require(
                f"python3 -I -c {_quoted(system_probe)}", "probing the system interpreter"
            )
        )
        if not isinstance(system, Mapping):
            raise RemoteMatchedHostError("system interpreter probe is not a JSON object")
        system_exact = (
            system.get("version") == PYTHON_VERSION
            and system.get("implementation") == "CPython"
            and isinstance(system.get("executable"), str)
            and str(system["executable"]).startswith("/")
        )
        venv = guarded_remote_child(deep, ".venv")
        python = guarded_remote_child(venv, "bin", "python")
        if system_exact:
            interpreter_command = (
                f"{_quoted(uv)} venv --python {_quoted(str(system['executable']))} "
                f"--no-python-downloads {_quoted(venv)}"
            )
            interpreter_source = "system-exact-cpython-3.12.3"
        else:
            interpreter_command = (
                f"{_quoted(uv)} python install {PYTHON_VERSION}; "
                f"{_quoted(uv)} venv --python {PYTHON_VERSION} "
                f"{_quoted(venv)}"
            )
            interpreter_source = "pinned-home-scoped-uv-managed-cpython-3.12.3"
        session.guarded_command(
            interpreter_command,
            "creating the exact AstralDeep canonical virtual environment",
            write_targets=(venv, session.child("python"), session.child("cache")),
            timeout=900,
            display=f"create AstralDeep/.venv with {interpreter_source}",
        )
        requirements = " ".join(_quoted(item) for item in DIRECT_REQUIREMENTS)
        session.guarded_command(
            f"{_quoted(uv)} pip install --python {_quoted(python)} --only-binary=:all: "
            f"{requirements}",
            "installing the minimal benchmark dependency set",
            write_targets=(venv, session.child("cache")),
            timeout=900,
            display=(
                "uv pip install --python AstralDeep/.venv/bin/python --only-binary=:all: "
                + " ".join(DIRECT_REQUIREMENTS)
            ),
        )
        clone_identity = _verify_clone(session, deep)
        remote_environment = _probe_remote_environment(session, python, uv)
        remote_environment["git"] = session.require(
            "git --version", "capturing the Git version"
        ).strip()
        remote_environment["uv"] = uv_version

        historical_path = guarded_remote_child(
            deep, "benchmarks", "results", "host-mediation-overhead", "20260826T231656Z"
        )
        historical_available = (
            session.require(
                f"if [ -e {_quoted(historical_path)} ]; then printf true; else printf false; fi",
                "checking historical artifact availability",
            ).strip()
            == "true"
        )
        if historical_available:
            raise RemoteMatchedHostError(
                "the original historical artifact unexpectedly exists; "
                "replacement diagnosis changed"
            )

        storage = session.child("storage")
        result_dir = session.child("output")
        session.mkdirs(result_dir)
        command = benchmark_command(python, remote_benchmark, deep, storage, result_dir)
        stdout = session.guarded_command(
            command,
            "running 10 x 1,000 operations per mode after 100 warmups",
            write_targets=(storage, result_dir, session.child("cache"), session.child("tmp")),
            timeout=7200,
            display=(
                "AstralDeep/.venv/bin/python runner/matched_host_path.py "
                "--astraldeep-root AstralDeep --storage-root storage --output output "
                "--trials 10 --operations 1000 --warmups 100"
            ),
        )
        if len(stdout) > 10_000:
            raise RemoteMatchedHostError("benchmark stdout is unexpectedly large")

        raw_artifacts = {
            name: session.download(guarded_remote_child(result_dir, name))
            for name in (OUTPUT_JSON, OUTPUT_CSV, OUTPUT_MARKDOWN)
        }
        benchmark_document = validate_benchmark_artifacts(
            raw_artifacts, expected_benchmark_sha256=str(source["benchmark_sha256"])
        )
        benchmark_environment = benchmark_document["environment"]
        assert isinstance(benchmark_environment, Mapping)
        storage_identity = benchmark_environment.get("storage")
        if (
            not isinstance(storage_identity, Mapping)
            or storage_identity.get("resolved_root") != storage
        ):
            raise RemoteMatchedHostError(
                "benchmark JSON storage identity is outside the guarded storage root"
            )
        retained = sanitize_artifacts(raw_artifacts, session)
        validate_benchmark_artifacts(
            retained, expected_benchmark_sha256=str(source["benchmark_sha256"])
        )
        retained_hashes = {name: sha256_bytes(payload) for name, payload in retained.items()}
        raw_hashes = {name: sha256_bytes(payload) for name, payload in raw_artifacts.items()}
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "status": "passed",
            "claim": "replacement-current-composition-not-historical-reproduction",
            "started_at_utc": started,
            "completed_at_utc": datetime.now(UTC).isoformat(),
            "target_alias": TARGET_ALIAS,
            "remote_scope": {
                "write_boundary": f"$HOME/{RUN_ROOT_NAME}/{selected_run_id}",
                "unique_run_id": selected_run_id,
                "normalized_owned_home_verified": True,
                "symlink_parents_rejected": True,
                "sudo_used": False,
                "docker_used": False,
                "system_paths_written": False,
                "remote_run_retained": True,
            },
            "endpoint_verification": {
                "address_pin_verified": True,
                "host_key_pin_verified": True,
                "host_key_type": inventory["host_key_type"],
            },
            "source": source,
            "remote_source": clone_identity,
            "toolchain": {
                "python_required": PYTHON_VERSION,
                "python_source": interpreter_source,
                "uv": uv_metadata,
                "environment": _sanitize_object(remote_environment, session),
                "direct_requirements": list(DIRECT_REQUIREMENTS),
                "components_installed_as_packages": False,
                "component_import_mode": "exact initialized source trees",
                "harness_delivery": "standalone upload outside the clean Deep root",
            },
            "configuration": {"trials": 10, "operations_per_mode": 1000, "warmups": 100},
            "historical_mismatch_diagnosis": {
                "historical_artifact": "20260826T231656Z",
                "historical_artifact_available": False,
                "historical_sqlite": HISTORICAL_SQLITE,
                "replacement_s1_sqlite": EXPECTED_REPLACEMENT_SQLITE,
                "sqlite_versions_match": False,
                "disclosure": (
                    "The original artifact is unavailable, and the replacement host uses SQLite "
                    "3.45.1 rather than the historical 3.53.4; this run is replacement evidence, "
                    "not an exact reproduction."
                ),
            },
            "commands": session.commands,
            "artifacts": {
                name: {
                    "remote_raw_sha256": raw_hashes[name],
                    "retained_sanitized_sha256": retained_hashes[name],
                }
                for name in (OUTPUT_JSON, OUTPUT_CSV, OUTPUT_MARKDOWN)
            },
            "privacy": {
                "addresses_retained": False,
                "usernames_retained": False,
                "home_paths_retained": False,
                "credentials_retained": False,
            },
        }
        written = _write_retained(output, retained, manifest, overwrite=overwrite)
        return {
            "status": "passed",
            "output": str(output.resolve()),
            "files": [str(path) for path in written],
            "run_id": selected_run_id,
        }
    finally:
        session.close()


def recover_remote_matched_host(
    credentials_path: Path,
    inventory_path: Path,
    output: Path,
    *,
    overwrite: bool = False,
    session_factory: Any = RemoteSession,
) -> dict[str, object]:
    """Retain an already-completed exact run using remote read operations only."""

    output = _preflight_retained(output, overwrite=overwrite)
    credential = load_s1_credential(credentials_path)
    inventory = load_s1_inventory(inventory_path)
    session: RemoteSession = session_factory(credential, inventory)
    source = _source_identity()
    recovered_at = datetime.now(UTC).isoformat()
    try:
        session.connect()
        candidates: list[RecoveryCandidate] = []
        for run_id, remote_root in _safe_recovery_roots(session):
            candidate = _load_recovery_candidate(
                session,
                run_id,
                remote_root,
                str(source["benchmark_sha256"]),
            )
            if candidate is not None:
                candidates.append(candidate)
        selected = select_latest_recovery_candidate(candidates)
        session.run_root = selected.remote_root

        raw_artifacts = selected.raw_artifacts
        retained = sanitize_artifacts(raw_artifacts, session)
        validate_benchmark_artifacts(
            retained, expected_benchmark_sha256=str(source["benchmark_sha256"])
        )
        retained_hashes = {name: sha256_bytes(payload) for name, payload in retained.items()}
        raw_hashes = {name: sha256_bytes(payload) for name, payload in raw_artifacts.items()}
        environment = selected.document.get("environment")
        if not isinstance(environment, Mapping):
            raise RemoteMatchedHostError("recovered result has no environment identity")
        retained_environment = _sanitize_object(environment, session)
        if any(
            _contains_sensitive_context(value, session)
            for value in _string_values(retained_environment)
        ):
            raise RemoteMatchedHostError("recovered environment did not sanitize safely")

        timing = _recovery_timing(selected, environment, recovered_at)
        manifest: dict[str, object] = {
            "schema": SCHEMA,
            "status": "passed",
            "claim": "replacement-current-composition-not-historical-reproduction",
            "started_at_utc": timing["started_at_utc"],
            "completed_at_utc": timing["completed_at_utc"],
            "target_alias": TARGET_ALIAS,
            "recovery": {
                "mode": "read-only-existing-run-retention",
                "benchmark_rerun": False,
                "remote_writes": False,
                "matching_candidate_count": len(candidates),
                "selection": "unique candidate at the greatest run-id UTC timestamp",
                "selected_timestamp_utc": selected.timestamp.isoformat(),
                "run_root_created_at_utc": timing["run_root_created_at_utc"],
                "environment_captured_at_utc": timing["environment_captured_at_utc"],
                "recovered_at_utc": timing["recovered_at_utc"],
            },
            "remote_scope": {
                "write_boundary": f"$HOME/{RUN_ROOT_NAME}/{selected.run_id}",
                "unique_run_id": selected.run_id,
                "normalized_owned_home_verified": True,
                "symlink_parents_rejected": True,
                "sudo_used": False,
                "docker_used": False,
                "system_paths_written": False,
                "remote_run_retained": True,
            },
            "endpoint_verification": {
                "address_pin_verified": True,
                "host_key_pin_verified": True,
                "host_key_type": inventory["host_key_type"],
            },
            "source": source,
            "remote_source": selected.clone_identity,
            "toolchain": {
                "python_required": PYTHON_VERSION,
                "python_source": "exact retained interpreter; provisioning branch not re-executed",
                "uv": {
                    "version": UV_VERSION,
                    "asset": UV_ASSET,
                    "sha256": selected.uv_archive_sha256,
                },
                "environment": retained_environment,
                "direct_requirements": list(DIRECT_REQUIREMENTS),
                "components_installed_as_packages": False,
                "component_import_mode": "exact initialized source trees",
                "harness_delivery": "standalone upload outside the clean Deep root",
            },
            "configuration": {"trials": 10, "operations_per_mode": 1000, "warmups": 100},
            "historical_mismatch_diagnosis": {
                "historical_artifact": "20260826T231656Z",
                "historical_artifact_available": False,
                "historical_sqlite": HISTORICAL_SQLITE,
                "replacement_s1_sqlite": EXPECTED_REPLACEMENT_SQLITE,
                "sqlite_versions_match": False,
                "disclosure": (
                    "The original artifact is unavailable, and the replacement host uses SQLite "
                    "3.45.1 rather than the historical 3.53.4; this run is replacement evidence, "
                    "not an exact reproduction."
                ),
            },
            "commands": {
                "original_run_contract": [
                    "git checkout exact Deep commit and initialize only Plane/LETS",
                    "create exact Deep .venv and install the three direct requirements",
                    ("run matched_host_path.py with trials=10, operations=1000, warmups=100"),
                ],
                "recovery_read_only": [
                    "verify pinned endpoint and normalized owned home",
                    "enumerate guarded run directories without following symlinks",
                    "hash runner/uv inputs and validate exact Git composition",
                    "download and validate the exact JSON/CSV/Markdown artifact set",
                ],
                "original_shell_log_recovered": False,
            },
            "artifacts": {
                name: {
                    "remote_raw_sha256": raw_hashes[name],
                    "retained_sanitized_sha256": retained_hashes[name],
                }
                for name in (OUTPUT_JSON, OUTPUT_CSV, OUTPUT_MARKDOWN)
            },
            "privacy": {
                "addresses_retained": False,
                "usernames_retained": False,
                "home_paths_retained": False,
                "credentials_retained": False,
            },
        }
        written = _write_retained(output, retained, manifest, overwrite=overwrite)
        return {
            "status": "recovered",
            "output": str(output.resolve()),
            "files": [str(path) for path in written],
            "run_id": selected.run_id,
            "benchmark_rerun": False,
            "remote_writes": False,
        }
    finally:
        session.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", required=True, type=Path)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--run-id")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--recover-existing", action="store_true")
    parser.add_argument("--uv-archive", type=Path)
    parser.add_argument("--uv-sha256")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if (arguments.uv_archive is None) != (arguments.uv_sha256 is None):
        print("--uv-archive and --uv-sha256 must be supplied together", file=sys.stderr)
        return 2
    if arguments.recover_existing and (
        arguments.run_id is not None or arguments.uv_archive is not None
    ):
        print("--recover-existing cannot be combined with --run-id or uv inputs", file=sys.stderr)
        return 2
    try:
        if arguments.recover_existing:
            result = recover_remote_matched_host(
                arguments.credentials,
                arguments.inventory,
                arguments.output_dir,
                overwrite=arguments.overwrite,
            )
        else:
            result = run_remote_matched_host(
                arguments.credentials,
                arguments.inventory,
                arguments.output_dir,
                run_id=arguments.run_id,
                overwrite=arguments.overwrite,
                uv_archive=arguments.uv_archive,
                uv_sha256=arguments.uv_sha256,
            )
    except (
        RemoteMatchedHostError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        tarfile.TarError,
    ) as exc:
        print(f"remote matched-host benchmark refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
