"""Run a reproducible LETS experiment on three separately booted Linux SSH endpoints.

The experiment creates one real LETS warden SQLite database and one real local
executor receipt-claim database on each endpoint.  Healthy peer probes and transfer
messages use a controller byte relay over two SSH sessions because the tested
high ports are not directly reachable.  The injected fault is a symmetric
application-path gate at s1 and s2; it is explicitly not a firewall or physical
network partition.  Every remote write and every temporary/cache location is
guarded beneath the authenticated SSH user's normalized home directory.
"""

from __future__ import annotations

import argparse
import base64
import csv
import errno
import hashlib
import html
import io
import ipaddress
import json
import posixpath
import re
import secrets
import select
import shlex
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request
from collections.abc import Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from lets.crypto import Ed25519Signer

from .common import utc_now, write_json, write_text
from .remote_cluster import ALIASES, Credential, load_credentials

SCHEMA = "lets.three-host-linux-experiment/v1"
RUN_ROOT_NAME = ".lets-nsdi-three-host"
RUN_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{7,63}\Z")
UV_VERSION = "0.11.21"
PYTHON_VERSION = "3.12.3"
UV_ASSET = "uv-x86_64-unknown-linux-gnu.tar.gz"
UV_RELEASE = f"https://github.com/astral-sh/uv/releases/download/{UV_VERSION}"
DEFAULT_OUTPUT = Path("results/nsdi-strengthening-2026-08-31/remote")
DEFAULT_INVENTORY = DEFAULT_OUTPUT / "cluster-inventory.json"
PER_SITE_FIGURE_NAME = "three-host-linux-per-site-timeline.svg"
PHASE_END_CSV_NAME = "three-host-linux-phase-end.csv"
PHASE_END_MARKDOWN_NAME = "three-host-linux-phase-end.md"
AGENT_SOURCE = Path(__file__).with_name("remote_three_host_agent.py")
CONTROLLER_SOURCE = Path(__file__).resolve()


@dataclass(frozen=True, slots=True)
class ScenarioSpec:
    name: str
    placement: str
    workload: str
    shares: tuple[int, int, int]
    phase_counts: Mapping[str, tuple[int, int, int]]
    transfer: tuple[str, str, int]


SCENARIOS = (
    ScenarioSpec(
        "equal-placement-equal-workload",
        "equal",
        "equal",
        (10, 10, 10),
        {"normal": (2, 2, 2), "partition": (3, 3, 3), "recovery": (1, 1, 1)},
        ("s2", "s1", 1),
    ),
    ScenarioSpec(
        "equal-placement-skew70-workload",
        "equal",
        "70-percent-s1",
        (10, 10, 10),
        {"normal": (4, 1, 1), "partition": (7, 1, 1), "recovery": (3, 1, 1)},
        ("s2", "s1", 3),
    ),
    ScenarioSpec(
        "skew70-placement-equal-workload",
        "70-percent-s1",
        "equal",
        (21, 4, 5),
        {"normal": (2, 2, 2), "partition": (3, 3, 3), "recovery": (1, 1, 1)},
        ("s1", "s2", 2),
    ),
    ScenarioSpec(
        "skew70-placement-skew70-workload",
        "70-percent-s1",
        "70-percent-s1",
        (21, 4, 5),
        {"normal": (4, 1, 1), "partition": (7, 1, 1), "recovery": (3, 1, 1)},
        ("s2", "s1", 1),
    ),
)


_SCENARIO_DISPLAY_VALUES = {
    "equal": "Equal",
    "70-percent-s1": "70% at s1",
}


def _display_scenario_value(value: object, *, field: str) -> str:
    """Return the paper-facing label for a stable raw scenario token."""

    if not isinstance(value, str) or value not in _SCENARIO_DISPLAY_VALUES:
        raise ValueError(f"unsupported {field} display token: {value!r}")
    return _SCENARIO_DISPLAY_VALUES[value]


def _scenario_panel_label(scenario: Mapping[str, object]) -> str:
    """Describe a scenario without leaking machine-oriented enum spellings."""

    placement = _display_scenario_value(scenario.get("placement"), field="placement")
    demand = _display_scenario_value(scenario.get("workload"), field="demand")
    placement = placement.lower().replace(" at ", " ")
    demand = demand.lower().replace(" at ", " ")
    return f"{placement} authority / {demand} demand"


class RemoteExperimentError(RuntimeError):
    """Failure with optional output-safe stage metadata for the CLI envelope."""

    def __init__(
        self,
        message: str,
        *,
        stage: str | None = None,
        reason: str = "remote_experiment_failed",
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.reason = reason


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_extraction_archive(path: Path, label: str) -> None:
    """Reject traversal, links, and special members before a remote tar extraction."""

    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
    if not members or any(
        member.name.startswith("/")
        or ".." in PurePosixPath(member.name).parts
        or not (member.isdir() or member.isreg())
        for member in members
    ):
        raise RemoteExperimentError(f"{label} archive has an unsafe member")


def guarded_remote_child(home: str, *parts: str) -> str:
    """Return a strict POSIX child path without resolving a shell or symlinks."""

    if (
        not home.startswith("/")
        or home == "/"
        or posixpath.normpath(home) != home
        or "\x00" in home
        or "\n" in home
        or "\r" in home
    ):
        raise ValueError("remote home must be an absolute normalized POSIX path")
    if not parts:
        raise ValueError("a remote child path requires at least one component")
    if any(
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
    candidate = str(PurePosixPath(home).joinpath(*parts))
    if posixpath.commonpath((home, candidate)) != home or candidate == home:
        raise ValueError("remote path escapes the authenticated user's home")
    return candidate


def redact_text(value: str, host: Credential, home: str = "") -> str:
    """Remove the known credential material before a diagnostic can be retained."""

    result = value
    for secret in (host.password, host.username, host.host, home):
        if secret:
            result = result.replace(secret, "<redacted>")
    return result[:500]


def _ssh_key_sha256(key: Any) -> str:
    return base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii")


@dataclass(slots=True)
class PinnedFingerprintPolicy:
    """Accept an otherwise unknown SSH host only when its inventory pin matches."""

    expected_type: str
    expected_sha256: str
    verified: bool = False

    def missing_host_key(self, _client: Any, _hostname: str, key: Any) -> None:
        observed_type = key.get_name()
        observed_sha256 = _ssh_key_sha256(key)
        if observed_type != self.expected_type or not secrets.compare_digest(
            observed_sha256, self.expected_sha256
        ):
            raise RemoteExperimentError("SSH host key differs from the pinned inventory")
        self.verified = True


_HOME_PROBE = r"""
import json, os, pwd, stat
uid = os.geteuid()
home = os.environ.get("HOME", "")
record = {"home": home, "uid": uid, "owned": False, "normalized": False,
          "pwd_home_matches": False, "login": ""}
try:
    details = os.lstat(home)
    canonical = os.path.realpath(home)
    account = pwd.getpwuid(uid)
    record["owned"] = stat.S_ISDIR(details.st_mode) and details.st_uid == uid
    record["normalized"] = (os.path.isabs(home) and os.path.normpath(home) == home
                            and canonical == home)
    record["pwd_home_matches"] = os.path.realpath(account.pw_dir) == home
    record["login"] = account.pw_name
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

if (home == "/" or not os.path.isabs(home) or os.path.normpath(home) != home
        or os.path.realpath(home) != home):
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
    limit = len(parts) if action in ("mkdirs", "verify", "create-exclusive") else len(parts) - 1
    for index, part in enumerate(parts[:limit]):
        existed = True
        try:
            next_fd = os.open(part, flags, dir_fd=fd)
        except FileNotFoundError:
            existed = False
            if action not in ("mkdirs", "create-exclusive"):
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
        if action == "create-exclusive" and index == len(parts) - 1 and existed:
            os.close(next_fd)
            fail("target_exists")
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
    elif action not in ("mkdirs", "verify", "create-exclusive"):
        fail("unknown_action")
finally:
    os.close(fd)

print(json.dumps({"ok": True, "action": action}, sort_keys=True))
""".strip()


_AGENT_PROCESS_CONTROL = r"""
import json, os, signal, stat, sys

pid_path, agent_path, config_path, action = sys.argv[1:5]
record = {"status": "unknown"}
try:
    details = os.lstat(pid_path)
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid():
        record["status"] = "unsafe_pid_file"
    else:
        raw = open(pid_path, encoding="ascii").read(32).strip()
        if not raw.isascii() or not raw.isdigit() or int(raw) <= 1:
            record["status"] = "invalid_pid"
        else:
            pid = int(raw)
            try:
                stat_fields = open(f"/proc/{pid}/stat", encoding="ascii").read().split()
                cmdline = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
            except FileNotFoundError:
                record["status"] = "stopped"
            except (OSError, UnicodeError):
                record["status"] = "foreign_process"
            else:
                expected = {os.fsencode(agent_path), os.fsencode(config_path)}
                if len(stat_fields) >= 3 and stat_fields[2] == "Z":
                    record["status"] = "stopped"
                elif not expected.issubset(set(cmdline)):
                    record["status"] = "foreign_process"
                else:
                    record["status"] = "running_owned_agent"
                    if action in ("term", "kill"):
                        os.kill(pid, signal.SIGTERM if action == "term" else signal.SIGKILL)
                        record["signal_sent"] = action
except FileNotFoundError:
    record["status"] = "missing_pid_file"
print(json.dumps(record, sort_keys=True))
""".strip()


@dataclass(slots=True)
class RemoteHost:
    credential: Credential
    expected_inventory: Mapping[str, object]
    identity_salt: bytes
    client: Any = field(init=False, default=None, repr=False)
    sftp: Any = field(init=False, default=None, repr=False)
    home: str = field(init=False, default="", repr=False)
    uid: int = field(init=False, default=-1, repr=False)
    run_root: str = field(init=False, default="", repr=False)
    scenario_root: str = field(init=False, default="", repr=False)
    host_key_sha256: str = field(init=False, default="")
    address_sha256: str = field(init=False, default="")
    boot_identity: dict[str, object] = field(init=False, default_factory=dict)

    @property
    def alias(self) -> str:
        return self.credential.alias

    def connect(self) -> None:
        try:
            import paramiko
        except ImportError as exc:  # pragma: no cover - environment diagnostic
            raise RemoteExperimentError(
                "Paramiko is required in the controller environment"
            ) from exc
        self.address_sha256 = hashlib.sha256(self.credential.host.encode()).hexdigest()
        if not secrets.compare_digest(
            self.address_sha256, str(self.expected_inventory.get("address_sha256", ""))
        ):
            raise RemoteExperimentError("server address differs from the pinned inventory")
        policy = PinnedFingerprintPolicy(
            str(self.expected_inventory.get("host_key_type", "")),
            str(self.expected_inventory.get("host_key_sha256", "")),
        )
        client = paramiko.SSHClient()
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
                raise RemoteExperimentError("SSH transport is not active")
            key = transport.get_remote_server_key()
            if not policy.verified:
                policy.missing_host_key(client, self.alias, key)
            self.host_key_sha256 = _ssh_key_sha256(key)
            if key.get_name() != policy.expected_type or not secrets.compare_digest(
                self.host_key_sha256, policy.expected_sha256
            ):
                raise RemoteExperimentError("SSH host-key post-check failed")
            self.client = client
            self.sftp = client.open_sftp()
            details = json.loads(
                self.require_run(
                    f"python3 -I -c {_quoted(_HOME_PROBE)}", "resolving authenticated home"
                )
            )
            home = details.get("home")
            if (
                not isinstance(home, str)
                or details.get("owned") is not True
                or details.get("normalized") is not True
                or details.get("pwd_home_matches") is not True
                or details.get("login") != self.credential.username
                or not isinstance(details.get("uid"), int)
            ):
                raise RemoteExperimentError("authenticated home is not normalized and user-owned")
            normalized = self.sftp.normalize(home)
            if normalized != home or not home.startswith("/"):
                raise RemoteExperimentError("authenticated home is not an absolute normalized path")
            observed_home_hash = hashlib.sha256(home.encode("utf-8")).hexdigest()
            if not secrets.compare_digest(
                observed_home_hash, str(self.expected_inventory.get("home_path_sha256", ""))
            ):
                raise RemoteExperimentError("authenticated home differs from the pinned inventory")
            self.home = home
            self.uid = int(details["uid"])
            identity_output = self.require_run(
                "set -eu; printf '%s\\n' \"$(cat /etc/machine-id)\"; "
                "printf '%s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\"; "
                "printf '%s\\n' \"$(hostname)\"; uname -srmo",
                "reading boot identity",
            ).splitlines()
            if len(identity_output) != 4 or any(not value for value in identity_output):
                raise RemoteExperimentError("boot identity probe returned malformed data")
            labels = ("machine_id", "boot_id", "hostname")
            self.boot_identity = {
                "alias": self.alias,
                "kernel": identity_output[3],
                **{
                    f"{label}_sha256": hashlib.sha256(value.encode()).hexdigest()
                    for label, value in zip(labels, identity_output[:3], strict=True)
                },
                **{
                    f"{label}_salted_sha256": hashlib.sha256(
                        self.identity_salt + b"\x00" + value.encode()
                    ).hexdigest()
                    for label, value in zip(labels, identity_output[:3], strict=True)
                },
            }
        except Exception as exc:
            client.close()
            self.client = None
            self.sftp = None
            if isinstance(exc, RemoteExperimentError):
                raise
            raise RemoteExperimentError(
                f"{self.alias} SSH setup failed ({type(exc).__name__})"
            ) from None

    def close(self) -> None:
        if self.sftp is not None:
            self.sftp.close()
            self.sftp = None
        if self.client is not None:
            self.client.close()
            self.client = None

    def child(self, *parts: str) -> str:
        return guarded_remote_child(self.home, *parts)

    def run(self, command: str, *, timeout: float = 120) -> tuple[int, str, str]:
        if self.client is None:
            raise RemoteExperimentError("SSH client is not connected")
        _stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        output = stdout.read().decode("utf-8", errors="replace")
        error = stderr.read().decode("utf-8", errors="replace")
        return stdout.channel.recv_exit_status(), output, error

    def require_run(self, command: str, stage: str, *, timeout: float = 120) -> str:
        code, output, error = self.run(command, timeout=timeout)
        if code != 0:
            diagnostic = redact_text(error or output, self.credential, self.home)
            raise RemoteExperimentError(
                f"{self.alias} failed during {stage} (exit {code}): {diagnostic}",
                stage=f"{self.alias}:{stage}",
                reason=f"remote_command_exit_{code}",
            )
        return output

    def upload(self, source: Path, target: str, *, mode: int = 0o600) -> None:
        if not source.is_file():
            raise ValueError("upload source is not a file")
        self.guard_write(target)
        with source.open("rb") as incoming, self.sftp.file(target, "wx") as outgoing:
            for block in iter(lambda: incoming.read(1024 * 1024), b""):
                outgoing.write(block)
            outgoing.flush()
        self.sftp.chmod(target, mode)
        self.verify_regular_file(target)

    def upload_bytes(self, payload: bytes, target: str, *, mode: int = 0o600) -> None:
        self.guard_write(target)
        with self.sftp.file(target, "wx") as stream:
            stream.write(payload)
            stream.flush()
        self.sftp.chmod(target, mode)
        self.verify_regular_file(target)

    def _guard(self, target: str, action: str, stage: str) -> None:
        self._require_beneath_home(target)
        self.require_run(
            f"python3 -I -c {_quoted(_PATH_GUARD)} {_quoted(self.home)} "
            f"{_quoted(target)} {_quoted(action)}",
            stage,
        )

    def create_exclusive_directory(self, target: str, stage: str) -> None:
        self._guard(target, "create-exclusive", stage)

    def mkdirs(self, target: str, stage: str) -> None:
        self._guard(target, "mkdirs", stage)

    def guard_write(self, target: str) -> None:
        if self.run_root and (
            posixpath.commonpath((self.run_root, target)) != self.run_root
            or target == self.run_root
        ):
            raise RemoteExperimentError("remote write target is outside the unique run root")
        self._guard(target, "guard-write", "checking a remote write target")

    def verify_regular_file(self, target: str) -> None:
        attributes = self.sftp.lstat(target)
        if (
            not stat.S_ISREG(attributes.st_mode)
            or stat.S_ISLNK(attributes.st_mode)
            or attributes.st_uid != self.uid
        ):
            raise RemoteExperimentError("remote artifact is not a user-owned regular file")

    def _require_beneath_home(self, target: str) -> None:
        if (
            not self.home
            or posixpath.commonpath((self.home, target)) != self.home
            or target == self.home
        ):
            raise RemoteExperimentError("remote write target is outside the normalized home")


def _quoted(value: str) -> str:
    return shlex.quote(value)


def _home_environment(host: RemoteHost) -> str:
    paths = {
        "TMPDIR": f"{host.run_root}/tmp",
        "XDG_CACHE_HOME": f"{host.run_root}/cache",
        "XDG_CONFIG_HOME": f"{host.run_root}/config-home",
        "PYTHONPYCACHEPREFIX": f"{host.run_root}/pycache",
        "PIP_CACHE_DIR": f"{host.run_root}/pip-cache",
        "UV_CACHE_DIR": f"{host.run_root}/uv-cache",
        "UV_PYTHON_INSTALL_DIR": f"{host.run_root}/python",
        "UV_PYTHON_BIN_DIR": f"{host.run_root}/python-bin",
        "UV_TOOL_DIR": f"{host.run_root}/uv-tools",
        "UV_TOOL_BIN_DIR": f"{host.run_root}/uv-bin",
        "CARGO_HOME": f"{host.run_root}/cache/cargo",
        "PYTHONNOUSERSITE": "1",
        "UV_NO_PROGRESS": "1",
        "UV_NO_CONFIG": "1",
        "PIP_CONFIG_FILE": "/dev/null",
        "PIP_INDEX_URL": "https://pypi.org/simple",
        "PIP_EXTRA_INDEX_URL": "",
        "PIP_TRUSTED_HOST": "",
        "UV_INDEX_URL": "https://pypi.org/simple",
        "UV_DEFAULT_INDEX": "https://pypi.org/simple",
        "UV_EXTRA_INDEX_URL": "",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    return " ".join(f"{key}={_quoted(value)}" for key, value in paths.items())


def _inventory(path: Path) -> dict[str, Mapping[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "lets.remote-cluster-inventory/v1":
        raise ValueError("inventory schema is not supported")
    servers = payload.get("servers")
    if not isinstance(servers, list):
        raise ValueError("inventory servers must be an array")
    result: dict[str, Mapping[str, object]] = {}
    for item in servers:
        if not isinstance(item, Mapping) or item.get("alias") not in ALIASES:
            raise ValueError("inventory contains an invalid server record")
        if item.get("inventory_ok") is not True:
            raise ValueError("inventory contains a server that did not pass")
        result[str(item["alias"])] = item
    if set(result) != set(ALIASES):
        raise ValueError("inventory must contain exactly s1, s2, and s3")
    return result


def _git(arguments: Sequence[str], *, cwd: Path) -> str:
    result = subprocess.run(
        ("git", *arguments),
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.stdout.strip()


def create_head_archive(repository: Path, destination: Path) -> dict[str, str]:
    commit = _git(("rev-parse", "HEAD"), cwd=repository)
    tree = _git(("rev-parse", "HEAD^{tree}"), cwd=repository)
    subprocess.run(
        ("git", "archive", "--format=tar.gz", f"--output={destination}", "HEAD"),
        cwd=repository,
        check=True,
        capture_output=True,
    )
    validate_extraction_archive(destination, "tracked HEAD")
    return {"commit": commit, "tree": tree, "archive_sha256": sha256_file(destination)}


def fetch_uv_archive(destination: Path) -> dict[str, str]:
    archive_url = f"{UV_RELEASE}/{UV_ASSET}"
    checksum_url = f"{archive_url}.sha256"
    with urllib.request.urlopen(checksum_url, timeout=60) as response:
        checksum_text = response.read().decode("ascii", errors="strict")
    expected = checksum_text.strip().split()[0].lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise RemoteExperimentError("uv release checksum is malformed")
    with urllib.request.urlopen(archive_url, timeout=120) as response:
        payload = response.read()
    actual = sha256_bytes(payload)
    if not hmac_compare(actual, expected):
        raise RemoteExperimentError("uv release archive failed its published SHA-256")
    destination.write_bytes(payload)
    return {"version": UV_VERSION, "asset": UV_ASSET, "sha256": actual}


def hmac_compare(left: str, right: str) -> bool:
    return secrets.compare_digest(left.encode("ascii"), right.encode("ascii"))


def reported_uv_version(output: str) -> str:
    """Return uv's semantic version while allowing its optional build metadata."""

    fields = output.strip().split()
    if len(fields) < 2 or fields[0] != "uv" or re.fullmatch(r"\d+\.\d+\.\d+", fields[1]) is None:
        raise RemoteExperimentError(
            "uv version output is malformed",
            stage="validating pinned uv version",
            reason="uv_version_output_malformed",
        )
    return fields[1]


def _make_run_id() -> str:
    return f"run-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}-{secrets.token_hex(4)}"


def _origin(host: str, port: int) -> str:
    """Validate an inventory address without retaining or rendering it in results."""

    address = ipaddress.ip_address(host)
    rendered = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{rendered}:{port}"


def _bridge_channels(left: Any, right: Any) -> None:
    channels = {left: right, right: left}
    try:
        while channels:
            readable, _, _ = select.select(list(channels), [], [], 15)
            if not readable:
                raise TimeoutError("SSH relay was idle for 15 seconds")
            for source in readable:
                target = channels[source]
                payload = source.recv(65536)
                if payload:
                    target.sendall(payload)
                    continue
                with suppress(Exception):
                    target.shutdown_write()
                channels.pop(source, None)
    finally:
        with suppress(Exception):
            left.close()
        with suppress(Exception):
            right.close()


@contextmanager
def ssh_loopback_relay(source: RemoteHost, target: RemoteHost) -> Any:
    """Relay one source-loopback port over two existing Paramiko sessions."""

    source_transport = source.client.get_transport()
    target_transport = target.client.get_transport()
    if (
        source_transport is None
        or target_transport is None
        or not source_transport.is_active()
        or not target_transport.is_active()
    ):
        raise RemoteExperimentError("SSH relay transport is not active")
    port = int(source_transport.request_port_forward("127.0.0.1", 0))
    errors: list[BaseException] = []

    def relay() -> None:
        try:
            incoming = source_transport.accept(20)
            if incoming is None:
                raise TimeoutError("source SSH port-forward channel was not opened")
            outgoing = target_transport.open_channel(
                "direct-tcpip",
                ("127.0.0.1", _port(target)),
                ("127.0.0.1", 0),
                timeout=20,
            )
            _bridge_channels(incoming, outgoing)
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=relay, name=f"relay-{source.alias}-{target.alias}")
    worker.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        with suppress(Exception):
            source_transport.cancel_port_forward("127.0.0.1", port)
        worker.join(timeout=30)
        if worker.is_alive():
            raise RemoteExperimentError("SSH relay worker did not terminate")
        if errors:
            raise RemoteExperimentError(
                f"{source.alias}->{target.alias} SSH loopback relay failed: "
                f"{type(errors[0]).__name__}"
            )


def _mkdir_run(host: RemoteHost, run_id: str) -> None:
    run_root = host.child(RUN_ROOT_NAME, run_id)
    host.create_exclusive_directory(run_root, "creating the exclusive guarded run directory")
    host.run_root = run_root
    children = (
        "uploads",
        "source",
        "tools",
        "tmp",
        "cache",
        "config-home",
        "pycache",
        "pip-cache",
        "uv-cache",
        "python",
        "python-bin",
        "uv-tools",
        "uv-bin",
        "requests",
        "logs",
    )
    for child in children:
        host.mkdirs(f"{run_root}/{child}", "creating guarded run children")


def _provision_runtime(
    host: RemoteHost,
    source_archive: Path,
    uv_archive: Path,
    agent_source: Path,
) -> dict[str, object]:
    uploaded_source = f"{host.run_root}/uploads/lets-head.tar.gz"
    uploaded_uv = f"{host.run_root}/uploads/{UV_ASSET}"
    uploaded_agent = f"{host.run_root}/agent.py"
    host.upload(source_archive, uploaded_source)
    host.upload(uv_archive, uploaded_uv)
    host.upload(agent_source, uploaded_agent)
    for directory in ("source", "tools"):
        host._guard(f"{host.run_root}/{directory}", "verify", "verifying an extraction directory")
    host.guard_write(f"{host.run_root}/requirements.txt")
    host.guard_write(f"{host.run_root}/venv")
    environment = _home_environment(host)
    host.require_run(
        f"tar -xzf {_quoted(uploaded_source)} -C {_quoted(host.run_root + '/source')}",
        "extracting tracked LETS source",
    )
    host.require_run(
        f"tar -xzf {_quoted(uploaded_uv)} --strip-components=1 "
        f"-C {_quoted(host.run_root + '/tools')}",
        "extracting pinned uv archive",
    )
    uv = _quoted(host.run_root + "/tools/uv")
    version_output = host.require_run(
        f"test -x {uv}; {uv} --version", "validating pinned uv version"
    )
    if reported_uv_version(version_output) != UV_VERSION:
        raise RemoteExperimentError(
            f"{host.alias} uv semantic version differs from the pin",
            stage=f"{host.alias}:validating pinned uv version",
            reason="uv_version_mismatch",
        )
    venv_python = _quoted(host.run_root + "/venv/bin/python")
    install_command = f"env {environment} {uv} python install {PYTHON_VERSION}"
    install_attempts = 0
    for install_attempts in range(1, 4):
        code, output, error = host.run(install_command, timeout=900)
        if code == 0:
            break
        if install_attempts < 3:
            time.sleep(install_attempts)
    else:  # pragma: no cover - requires repeated remote bootstrap failure
        diagnostic = redact_text(error or output, host.credential, host.home)
        raise RemoteExperimentError(
            f"{host.alias} failed during installing pinned CPython after 3 attempts: {diagnostic}",
            stage=f"{host.alias}:installing pinned CPython",
            reason=f"remote_command_exit_{code}",
        )

    host.require_run(
        f"env {environment} {uv} venv --python {PYTHON_VERSION} {_quoted(host.run_root + '/venv')}",
        "creating the pinned virtual environment",
        timeout=300,
    )
    host.require_run(
        f"env {environment} {uv} export --frozen --no-dev --no-emit-project "
        f"--project {_quoted(host.run_root + '/source')} "
        f"--output-file {_quoted(host.run_root + '/requirements.txt')}",
        "exporting the frozen dependency set",
        timeout=300,
    )
    host.require_run(
        f"env {environment} {uv} pip install --python {venv_python} "
        f"--requirement {_quoted(host.run_root + '/requirements.txt')}",
        "installing frozen runtime dependencies",
        timeout=600,
    )
    host.require_run(
        f"env {environment} {uv} pip install --no-deps --python {venv_python} "
        f"{_quoted(host.run_root + '/source')}",
        "installing tracked LETS source",
        timeout=600,
    )
    probe = _quoted(
        "import importlib.metadata,json,platform;print(json.dumps({"
        "'python':platform.python_version(),"
        "'lets_agent':importlib.metadata.version('lets-agent')}))"
    )
    output = host.require_run(
        f"env {environment} {venv_python} -c {probe}",
        "probing the pinned runtime",
    )
    line = next((item for item in reversed(output.splitlines()) if item.startswith("{")), "")
    runtime = json.loads(line)
    if runtime.get("python") != PYTHON_VERSION:
        raise RemoteExperimentError(f"{host.alias} did not provision the pinned Python version")
    return {
        "python": runtime["python"],
        "lets_agent": runtime["lets_agent"],
        "python_install_attempts": install_attempts,
    }


def _configure_scenario(host: RemoteHost, scenario: str, config: Mapping[str, object]) -> None:
    scenario_root = f"{host.run_root}/{scenario}"
    host._require_beneath_home(scenario_root)
    host.create_exclusive_directory(scenario_root, "creating an exclusive scenario directory")
    host.mkdirs(scenario_root + "/requests", "creating the scenario request directory")
    host.mkdirs(scenario_root + "/logs", "creating the scenario log directory")
    host.scenario_root = scenario_root
    checked_config = {**config, "run_root": scenario_root}
    host.upload_bytes(
        json.dumps(checked_config, sort_keys=True, separators=(",", ":")).encode(),
        f"{scenario_root}/agent-config.json",
    )


def _start_agent(host: RemoteHost) -> None:
    environment = _home_environment(host)
    host.guard_write(f"{host.scenario_root}/logs/agent.log")
    host.guard_write(f"{host.scenario_root}/agent.pid")
    command = (
        "set -eu; umask 077; "
        f"env {environment} nohup {_quoted(host.run_root + '/venv/bin/python')} "
        f"{_quoted(host.run_root + '/agent.py')} serve "
        f"--config {_quoted(host.scenario_root + '/agent-config.json')} "
        f">{_quoted(host.scenario_root + '/logs/agent.log')} 2>&1 </dev/null & "
        f"printf '%s' $! >{_quoted(host.scenario_root + '/agent.pid')}"
    )
    host.require_run(command, "starting the experiment agent")


def _local_request(
    host: RemoteHost,
    path: str,
    *,
    body: Mapping[str, object] | None = None,
    allow_http_error: bool = False,
) -> dict[str, Any]:
    request_name = f"request-{secrets.token_hex(12)}.json"
    request_path = f"{host.scenario_root}/requests/{request_name}"
    payload = {
        "method": "GET" if body is None else "POST",
        "path": path,
        **({} if body is None else {"body": dict(body)}),
    }
    host.upload_bytes(json.dumps(payload, separators=(",", ":")).encode(), request_path)
    environment = _home_environment(host)
    command = (
        f"env {environment} {_quoted(host.run_root + '/venv/bin/python')} "
        f"{_quoted(host.run_root + '/agent.py')} request "
        f"--config {_quoted(host.scenario_root + '/agent-config.json')} "
        f"--request {_quoted(request_path)}"
    )
    try:
        code, output, error = host.run(command, timeout=45)
        line = next((item for item in reversed(output.splitlines()) if item.startswith("{")), "")
        if not line:
            diagnostic = redact_text(error, host.credential, host.home)
            raise RemoteExperimentError(
                f"{host.alias} local control request produced no JSON: {diagnostic}"
            )
        result = json.loads(line)
        if code != 0 and not allow_http_error:
            response = result.get("response", {})
            reason = (
                response.get("error", "request_failed")
                if isinstance(response, Mapping)
                else "request_failed"
            )
            raise RemoteExperimentError(f"{host.alias} local control request failed: {reason}")
        return result
    finally:
        with suppress(OSError):
            host.sftp.remove(request_path)


def _wait_ready(host: RemoteHost, *, timeout: float = 45) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error = "not_ready"
    while time.monotonic() < deadline:
        try:
            result = _local_request(host, "/health")
            if result.get("response", {}).get("ready") is True:
                return result["response"]
        except Exception as exc:
            last_error = type(exc).__name__
        time.sleep(0.25)
    raise RemoteExperimentError(f"{host.alias} agent did not become ready ({last_error})")


def _post(host: RemoteHost, path: str, body: Mapping[str, object]) -> dict[str, Any]:
    result = _local_request(host, path, body=body)
    return dict(result["response"])


def _partitioned_post(host: RemoteHost, path: str, body: Mapping[str, object]) -> dict[str, Any]:
    result = _local_request(host, path, body=body, allow_http_error=True)
    return {"http_status": result["http_status"], **dict(result["response"])}


def _authorize(host: RemoteHost, phase: str, index: int) -> dict[str, object]:
    response = _post(
        host,
        "/local/authorize",
        {"request_id": f"authorize-{phase}-{host.alias}-{index:04d}"},
    )
    return {"phase": phase, "alias": host.alias, **response}


def _snapshot(host: RemoteHost) -> dict[str, object]:
    return dict(_local_request(host, "/snapshot")["response"])


def _peer_probe(source: RemoteHost, target: RemoteHost) -> dict[str, object]:
    with ssh_loopback_relay(source, target) as endpoint:
        response = _post(
            source,
            "/proxy/ping",
            {"target_alias": target.alias, "target_endpoint": endpoint},
        )
    response["transport"] = "controller_paramiko_two_ssh_session_relay"
    return response


def _port(host: RemoteHost) -> int:
    return int(host.expected_inventory["experiment_port"])


def _artifact_facts(host: RemoteHost) -> dict[str, object]:
    warden = f"{host.scenario_root}/state/warden.sqlite3"
    executor = f"{host.scenario_root}/state/executor.sqlite3"
    command = (
        "set -eu; "
        f"printf '%s ' \"$(sha256sum {_quoted(warden)} | awk '{{print $1}}')\"; "
        f"printf '%s ' \"$(stat -c %s {_quoted(warden)})\"; "
        f"printf '%s ' \"$(sha256sum {_quoted(executor)} | awk '{{print $1}}')\"; "
        f"printf '%s' \"$(stat -c %s {_quoted(executor)})\""
    )
    values = host.require_run(command, "hashing durable experiment artifacts").split()
    if len(values) != 4 or not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in values[::2]):
        raise RemoteExperimentError(f"{host.alias} returned malformed artifact facts")
    return {
        "warden_sqlite_sha256": values[0],
        "warden_sqlite_bytes": int(values[1]),
        "executor_sqlite_sha256": values[2],
        "executor_sqlite_bytes": int(values[3]),
    }


def _aggregate(snapshots: Sequence[Mapping[str, object]]) -> dict[str, object]:
    fields = (
        "initial_share",
        "transferred_in",
        "transferred_out",
        "free_pool",
        "lease_residual",
        "consumed",
    )
    aggregate = {field: sum(int(item[field]) for item in snapshots) for field in fields}
    aggregate["conservation_holds"] = (
        aggregate["initial_share"] + aggregate["transferred_in"]
        == aggregate["transferred_out"]
        + aggregate["free_pool"]
        + aggregate["lease_residual"]
        + aggregate["consumed"]
    )
    aggregate["all_local_invariants_healthy"] = all(bool(item["healthy"]) for item in snapshots)
    return aggregate


def _central_authorize(
    host: RemoteHost,
    central: RemoteHost,
    request_id: str,
    *,
    partition_active: bool,
) -> dict[str, object]:
    if host.alias == central.alias:
        response = _post(host, "/local/central-authorize", {"request_id": request_id})
        response["transport"] = "central_host_loopback"
        return response
    if partition_active and {host.alias, central.alias} == {"s1", "s2"}:
        response = _partitioned_post(
            host,
            "/proxy/central-authorize",
            {
                "target_alias": central.alias,
                "target_endpoint": "http://127.0.0.1:9",
                "request_id": request_id,
            },
        )
        response.setdefault("authorized", False)
        response.setdefault("reason", str(response.get("error", "unreachable")))
        response["transport"] = "blocked_before_ssh_relay"
        return response
    with ssh_loopback_relay(host, central) as endpoint:
        response = _post(
            host,
            "/proxy/central-authorize",
            {
                "target_alias": central.alias,
                "target_endpoint": endpoint,
                "request_id": request_id,
            },
        )
    response["transport"] = "controller_paramiko_two_ssh_session_relay"
    return response


def _phase_snapshots(
    hosts: Sequence[RemoteHost],
    counters: Mapping[str, Mapping[str, int]],
    *,
    phase: str,
) -> list[dict[str, object]]:
    snapshots = [_snapshot(host) for host in hosts]
    by_alias = {str(item["alias"]): item for item in snapshots}
    for item in snapshots:
        alias = str(item["alias"])
        item["actions_remaining"] = int(item["free_pool"]) + int(item["lease_residual"])
        item["authorized"] = counters[alias]["lets_authorized"]
        item["denied"] = counters[alias]["lets_denied"]
        item["central_authorized"] = counters[alias]["central_authorized"]
        item["central_denied"] = counters[alias]["central_denied"]
        if phase == "partition" and alias in {"s1", "s2"}:
            peer = "s2" if alias == "s1" else "s1"
            item["stranded_on_blocked_peer"] = int(by_alias[peer]["free_pool"]) + int(
                by_alias[peer]["lease_residual"]
            )
        else:
            item["stranded_on_blocked_peer"] = 0
    return snapshots


def _execute_phase(
    spec: ScenarioSpec,
    phase: str,
    hosts: Sequence[RemoteHost],
    central: RemoteHost,
    counters: dict[str, dict[str, int]],
    timeline: list[dict[str, object]],
) -> list[dict[str, object]]:
    counts = spec.phase_counts[phase]
    partition_active = phase == "partition"
    by_alias = {host.alias: host for host in hosts}
    for alias, count in zip(ALIASES, counts, strict=True):
        for index in range(count):
            host = by_alias[alias]
            request_id = f"{spec.name}-{phase}-{alias}-{index:04d}"
            lets_result = _authorize(host, phase, index)
            central_result = _central_authorize(
                host,
                central,
                f"central-{request_id}",
                partition_active=partition_active,
            )
            lets_key = "lets_authorized" if lets_result.get("authorized") is True else "lets_denied"
            central_key = (
                "central_authorized"
                if central_result.get("authorized") is True
                else "central_denied"
            )
            counters[alias][lets_key] += 1
            counters[alias][central_key] += 1
            snapshot = _snapshot(host)
            actions_remaining = int(snapshot["free_pool"]) + int(snapshot["lease_residual"])
            stranded = 0
            if partition_active and alias in {"s1", "s2"}:
                peer_alias = "s2" if alias == "s1" else "s1"
                peer_snapshot = _snapshot(by_alias[peer_alias])
                stranded = int(peer_snapshot["free_pool"]) + int(peer_snapshot["lease_residual"])
            timeline.append(
                {
                    "step": len(timeline),
                    "phase": phase,
                    "site": alias,
                    "lets_authorized": lets_result.get("authorized") is True,
                    "lets_reason": lets_result.get("reason", "authorized_and_claimed"),
                    "lets_latency_ns": lets_result.get("latency_ns"),
                    "central_authorized": central_result.get("authorized") is True,
                    "central_reason": central_result.get(
                        "reason", central_result.get("error", "authorized")
                    ),
                    "central_latency_ns": central_result.get("latency_ns"),
                    "actions_remaining_at_site": actions_remaining,
                    "stranded_on_blocked_peer": stranded,
                    "site_authorized_cumulative": counters[alias]["lets_authorized"],
                    "site_denied_cumulative": counters[alias]["lets_denied"],
                    "central_site_authorized_cumulative": counters[alias]["central_authorized"],
                    "central_site_denied_cumulative": counters[alias]["central_denied"],
                }
            )
    return _phase_snapshots(hosts, counters, phase=phase)


def _central_artifact(host: RemoteHost) -> dict[str, object]:
    path = f"{host.scenario_root}/state/central.sqlite3"
    command = (
        f"printf '%s ' \"$(sha256sum {_quoted(path)} | awk '{{print $1}}')\"; "
        f"printf '%s' \"$(stat -c %s {_quoted(path)})\""
    )
    values = host.require_run(command, "hashing the central baseline database").split()
    if len(values) != 2 or re.fullmatch(r"[0-9a-f]{64}", values[0]) is None:
        raise RemoteExperimentError("central baseline artifact facts are malformed")
    return {"sqlite_sha256": values[0], "sqlite_bytes": int(values[1])}


def _agent_process_status(host: RemoteHost, action: str = "probe") -> str:
    if action not in {"probe", "term", "kill"}:
        raise ValueError("unsupported agent process action")
    output = host.require_run(
        f"python3 -I -c {_quoted(_AGENT_PROCESS_CONTROL)} "
        f"{_quoted(host.scenario_root + '/agent.pid')} "
        f"{_quoted(host.run_root + '/agent.py')} "
        f"{_quoted(host.scenario_root + '/agent-config.json')} {_quoted(action)}",
        f"{action} experiment agent",
    )
    payload = json.loads(output)
    status = payload.get("status")
    if not isinstance(status, str):
        raise RemoteExperimentError(f"{host.alias} returned malformed agent process status")
    return status


def _remove_scenario_secret(host: RemoteHost) -> None:
    config_path = f"{host.scenario_root}/agent-config.json"
    try:
        attributes = host.sftp.lstat(config_path)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return
        raise
    if (
        not stat.S_ISREG(attributes.st_mode)
        or stat.S_ISLNK(attributes.st_mode)
        or attributes.st_uid != host.uid
    ):
        raise RemoteExperimentError(f"{host.alias} scenario secret is not a guarded regular file")
    host.sftp.remove(config_path)
    try:
        host.sftp.lstat(config_path)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ENOENT:
            return
        raise
    raise RemoteExperimentError(f"{host.alias} scenario secret removal was not durable")


def _shutdown_scenario(hosts: Sequence[RemoteHost], *, strict: bool) -> list[str]:
    failures: list[str] = []
    for host in hosts:
        if not host.scenario_root:
            continue
        with suppress(Exception):
            _local_request(host, "/control/shutdown", body={}, allow_http_error=True)
    for host in hosts:
        if not host.scenario_root:
            continue
        try:
            deadline = time.monotonic() + 5
            status = _agent_process_status(host)
            while status == "running_owned_agent" and time.monotonic() < deadline:
                time.sleep(0.1)
                status = _agent_process_status(host)
            if status == "running_owned_agent":
                _agent_process_status(host, "term")
                deadline = time.monotonic() + 5
                while status == "running_owned_agent" and time.monotonic() < deadline:
                    time.sleep(0.1)
                    status = _agent_process_status(host)
            if status == "running_owned_agent":
                _agent_process_status(host, "kill")
                time.sleep(0.2)
                status = _agent_process_status(host)
            if status != "stopped":
                raise RemoteExperimentError(
                    f"{host.alias} agent cleanup ended in unexpected status {status!r}"
                )
            _remove_scenario_secret(host)
        except Exception as exc:
            failures.append(f"{host.alias}:{type(exc).__name__}")
    if strict and failures:
        raise RemoteExperimentError(
            "agent shutdown or scenario-secret cleanup failed on " + ", ".join(failures)
        )
    return failures


def _scenario_failures(result: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    if not all(item.get("delivered") is True for item in result["healthy_peer_probes"]):
        failures.append("healthy SSH-relayed peer probes did not all arrive")
    blocked = result["partition"]["blocked_peer_probes"]
    if not all(
        item.get("http_status") == 503 and item.get("error") == "application_path_partition"
        for item in blocked
    ):
        failures.append("symmetric s1/s2 application-path gates were not both observed")
    partition_timeline = [item for item in result["timeline"] if item["phase"] == "partition"]
    for alias in ALIASES:
        if not any(
            item["site"] == alias and item["lets_authorized"] is True for item in partition_timeline
        ):
            failures.append(f"{alias} made no local LETS progress during the partition")
    if result["partition"]["unaffected_peer_probe"].get("delivered") is not True:
        failures.append("the unaffected s3 peer path did not remain available")
    transfer = result["recovery"]["transfer"]
    if transfer.get("delivered") is not True or transfer.get("finalized") is not True:
        failures.append("the post-heal LETS transfer did not finalize")
    if result["aggregate_final"].get("conservation_holds") is not True:
        failures.append("aggregate LETS conservation failed")
    if not all(item.get("healthy") is True for item in result["final_snapshots"]):
        failures.append("a final local LETS invariant was unhealthy")
    artifacts = result["durable_artifacts"]
    if len({item["warden_sqlite_sha256"] for item in artifacts}) != 3:
        failures.append("warden SQLite artifacts are not distinct across all three endpoints")
    if len({item["executor_sqlite_sha256"] for item in artifacts}) != 3:
        failures.append("executor SQLite artifacts are not distinct across all three endpoints")
    attempted = sum(
        sum(int(value) for value in values.values()) for values in result["phase_counts"].values()
    )
    baseline = result["central_baseline_summary"]
    if baseline["authorized"] + baseline["denied"] != attempted:
        failures.append("central baseline did not execute the identical workload schedule")
    return failures


def _run_scenario(
    spec: ScenarioSpec,
    scenario_index: int,
    hosts: Sequence[RemoteHost],
    runtime_token: str,
) -> dict[str, Any]:
    signers = {alias: Ed25519Signer.generate(alias) for alias in ALIASES}
    public_keys = {
        alias: {
            "key_id": signer.key_id,
            "public_key": base64.b64encode(signer.public_key_bytes).decode("ascii"),
        }
        for alias, signer in signers.items()
    }
    for host, share in zip(hosts, spec.shares, strict=True):
        _configure_scenario(
            host,
            f"scenario-{scenario_index + 1}-{spec.name}",
            {
                "alias": host.alias,
                "warden_id": host.alias,
                "port": _port(host),
                "token": runtime_token,
                "budget": sum(spec.shares),
                "initial_share": share,
                "initial_lease": share,
                "seed": base64.b64encode(signers[host.alias].seed_bytes).decode("ascii"),
                "public_keys": public_keys,
            },
        )
        _start_agent(host)
    health = [_wait_ready(host) for host in hosts]
    by_alias = {host.alias: host for host in hosts}
    central = by_alias["s2"]
    counters = {
        alias: {
            "lets_authorized": 0,
            "lets_denied": 0,
            "central_authorized": 0,
            "central_denied": 0,
        }
        for alias in ALIASES
    }
    timeline: list[dict[str, object]] = []
    try:
        initial = _phase_snapshots(hosts, counters, phase="initial")
        healthy = [
            _peer_probe(by_alias["s1"], by_alias["s2"]),
            _peer_probe(by_alias["s2"], by_alias["s1"]),
            _peer_probe(by_alias["s3"], by_alias["s2"]),
        ]
        normal_snapshots = _execute_phase(spec, "normal", hosts, central, counters, timeline)
        _post(by_alias["s1"], "/control/link", {"peer": "s2", "enabled": False})
        _post(by_alias["s2"], "/control/link", {"peer": "s1", "enabled": False})
        blocked = [
            _partitioned_post(
                by_alias["s1"],
                "/proxy/ping",
                {"target_alias": "s2", "target_endpoint": "http://127.0.0.1:9"},
            ),
            _partitioned_post(
                by_alias["s2"],
                "/proxy/ping",
                {"target_alias": "s1", "target_endpoint": "http://127.0.0.1:9"},
            ),
        ]
        partition_snapshots = _execute_phase(spec, "partition", hosts, central, counters, timeline)
        unaffected = _peer_probe(by_alias["s3"], by_alias["s2"])
        _post(by_alias["s1"], "/control/link", {"peer": "s2", "enabled": True})
        _post(by_alias["s2"], "/control/link", {"peer": "s1", "enabled": True})

        source_alias, target_alias, amount = spec.transfer
        source_host, target_host = by_alias[source_alias], by_alias[target_alias]
        _post(source_host, "/local/close", {"suffix": "recovery"})
        _post(target_host, "/local/close", {"suffix": "recovery"})
        with ssh_loopback_relay(source_host, target_host) as endpoint:
            transfer = _post(
                source_host,
                "/proxy/transfer",
                {
                    "target_alias": target_alias,
                    "target_endpoint": endpoint,
                    "amount": amount,
                    "request_id": f"{spec.name}-post-heal-transfer",
                },
            )
        transfer["transport"] = "controller_paramiko_two_ssh_session_relay"
        recovery_counts = dict(zip(ALIASES, spec.phase_counts["recovery"], strict=True))
        for alias in {source_alias, target_alias}:
            desired = recovery_counts[alias]
            if desired:
                _post(
                    by_alias[alias],
                    "/local/issue",
                    {"amount": desired, "suffix": "recovery"},
                )
        recovery_snapshots = _execute_phase(spec, "recovery", hosts, central, counters, timeline)
        final_snapshots = _phase_snapshots(hosts, counters, phase="final")
    except BaseException:
        _shutdown_scenario(hosts, strict=False)
        raise
    _shutdown_scenario(hosts, strict=True)

    artifacts = [{"alias": host.alias, **_artifact_facts(host)} for host in hosts]
    central_artifact = _central_artifact(central)
    baseline_summary = {
        "authorized": sum(values["central_authorized"] for values in counters.values()),
        "denied": sum(values["central_denied"] for values in counters.values()),
        "per_site": {
            alias: {
                "authorized": counters[alias]["central_authorized"],
                "denied": counters[alias]["central_denied"],
            }
            for alias in ALIASES
        },
        "durable_sqlite": central_artifact,
        "host_alias": central.alias,
    }
    result: dict[str, Any] = {
        "name": spec.name,
        "placement": spec.placement,
        "workload": spec.workload,
        "shares": dict(zip(ALIASES, spec.shares, strict=True)),
        "phase_counts": {
            phase: dict(zip(ALIASES, counts, strict=True))
            for phase, counts in spec.phase_counts.items()
        },
        "health": health,
        "initial_snapshots": initial,
        "healthy_peer_probes": healthy,
        "normal": {"snapshots": normal_snapshots},
        "partition": {
            "fault_model": "symmetric_application_path_gate_not_firewall",
            "blocked_links": ["s1->s2", "s2->s1"],
            "blocked_peer_probes": blocked,
            "snapshots": partition_snapshots,
            "unaffected_peer_probe": unaffected,
        },
        "recovery": {
            "transfer": transfer,
            "snapshots": recovery_snapshots,
        },
        "timeline": timeline,
        "final_snapshots": final_snapshots,
        "aggregate_final": _aggregate(final_snapshots),
        "central_baseline_summary": baseline_summary,
        "durable_artifacts": artifacts,
    }
    failures = _scenario_failures(result)
    result["assertions"] = {"passed": not failures, "failures": failures}
    result["status"] = "passed" if not failures else "failed"
    return result


def run_experiment(
    credentials_path: Path,
    inventory_path: Path,
    repository: Path,
    *,
    run_id: str | None = None,
    base_port: int = 47180,
    uv_archive: Path | None = None,
) -> dict[str, Any]:
    checked_run_id = _make_run_id() if run_id is None else run_id
    if RUN_ID_PATTERN.fullmatch(checked_run_id) is None:
        raise ValueError("run_id must contain 8..64 lowercase letters, digits, or hyphens")
    if not 1024 <= base_port <= 65533:
        raise ValueError("base_port must leave three valid unprivileged TCP ports")
    inventory = _inventory(inventory_path)
    credentials = load_credentials(credentials_path)
    if tuple(item.alias for item in credentials) != ALIASES:
        raise ValueError("credentials are not ordered as s1, s2, s3")

    with tempfile.TemporaryDirectory(prefix="lets-three-host-linux-") as temporary:
        temporary_path = Path(temporary)
        source_archive = temporary_path / "lets-head.tar.gz"
        source = create_head_archive(repository, source_archive)
        if uv_archive is None:
            local_uv = temporary_path / UV_ASSET
            uv = fetch_uv_archive(local_uv)
        else:
            local_uv = uv_archive.resolve()
            if not local_uv.is_file():
                raise ValueError("uv_archive is not a file")
            uv = {"version": UV_VERSION, "asset": local_uv.name, "sha256": sha256_file(local_uv)}
        validate_extraction_archive(local_uv, "uv bootstrap")

        token = secrets.token_urlsafe(32)
        identity_salt = secrets.token_bytes(32)
        hosts: list[RemoteHost] = []
        runtime: list[dict[str, object]] = []
        started_at = utc_now()
        try:
            for index, credential in enumerate(credentials):
                try:
                    _origin(credential.host, base_port + index)
                except ValueError:
                    raise RemoteExperimentError(
                        f"{credential.alias} credential address is not an IP literal"
                    ) from None
                expected = dict(inventory[credential.alias])
                expected["experiment_port"] = base_port + index
                host = RemoteHost(credential, expected, identity_salt)
                host.connect()
                _mkdir_run(host, checked_run_id)
                hosts.append(host)
            if (
                len({host.host_key_sha256 for host in hosts}) != 3
                or len({host.address_sha256 for host in hosts}) != 3
            ):
                raise RemoteExperimentError(
                    "SSH inventory does not identify three distinct endpoints"
                )

            for host in hosts:
                facts = _provision_runtime(host, source_archive, local_uv, AGENT_SOURCE)
                runtime.append({"alias": host.alias, **facts})
            scenarios = [
                _run_scenario(spec, index, hosts, token) for index, spec in enumerate(SCENARIOS)
            ]
            host_identity = [host.boot_identity for host in hosts]
            failures: list[str] = []
            if len({host.address_sha256 for host in hosts}) != 3:
                failures.append("server address fingerprints are not distinct")
            if len({host.host_key_sha256 for host in hosts}) != 3:
                failures.append("SSH host-key fingerprints are not distinct")
            if len({item["boot_id_sha256"] for item in host_identity}) != 3:
                failures.append("Linux boot identifiers are not distinct")
            if any(scenario["status"] != "passed" for scenario in scenarios):
                failures.append("one or more placement/workload scenarios failed")
            result: dict[str, Any] = {
                "schema": SCHEMA,
                "status": "passed" if not failures else "failed",
                "started_at": started_at,
                "completed_at": utc_now(),
                "run_id": checked_run_id,
                "scope": {
                    "deployment": "three separately booted Linux SSH endpoints",
                    "mode": "development",
                    "host_claim": (
                        "distinct SSH endpoints and boot identities; not proof of physical, "
                        "power, rack, or failure-domain independence"
                    ),
                    "peer_transport": (
                        "controller-mediated byte relay over two Paramiko SSH sessions; "
                        "not a direct endpoint-to-endpoint route or WAN measurement"
                    ),
                    "partition": "application-path gate, not firewall or physical partition",
                    "remote_write_boundary": "authenticated normalized home only",
                    "sudo_used": False,
                    "docker_used": False,
                    "production_claimed": False,
                },
                "secrets_retained_in_result": False,
                "home_scoped_runtime_secrets_removed_after_each_scenario": True,
                "raw_addresses_retained": False,
                "address_fingerprints_retained": True,
                "raw_usernames_retained": False,
                "source": source,
                "harness": {
                    "controller_path": "benchmarks/nsdi_strengthening/remote_three_host.py",
                    "controller_sha256": sha256_file(CONTROLLER_SOURCE),
                    "agent_path": "benchmarks/nsdi_strengthening/remote_three_host_agent.py",
                    "agent_sha256": sha256_file(AGENT_SOURCE),
                    "sha256": sha256_bytes(
                        CONTROLLER_SOURCE.read_bytes() + b"\x00" + AGENT_SOURCE.read_bytes()
                    ),
                },
                "runtime_bootstrap": uv,
                "runtime": runtime,
                "host_evidence": {
                    "aliases": list(ALIASES),
                    "address_sha256": [host.address_sha256 for host in hosts],
                    "ssh_host_key_sha256": [host.host_key_sha256 for host in hosts],
                    "distinct_address_hashes": len({host.address_sha256 for host in hosts}),
                    "distinct_ssh_host_keys": len({host.host_key_sha256 for host in hosts}),
                    "identity_hash_salt_b64": base64.b64encode(identity_salt).decode("ascii"),
                    "linux_boot_identity": host_identity,
                },
                "scenario_matrix": {
                    "placements": ["equal", "70-percent-s1"],
                    "workloads": ["equal", "70-percent-s1"],
                    "design": "full-factorial-2x2",
                },
                "scenarios": scenarios,
                "assertions": {"passed": not failures, "failures": failures},
            }
            return result
        finally:
            _shutdown_scenario(hosts, strict=False)
            for host in hosts:
                host.close()


def timeline_csv(result: Mapping[str, Any]) -> str:
    output = io.StringIO(newline="")
    fields = (
        "scenario",
        "placement",
        "workload",
        "step",
        "phase",
        "site",
        "lets_authorized",
        "lets_reason",
        "lets_latency_ns",
        "central_authorized",
        "central_reason",
        "central_latency_ns",
        "actions_remaining_at_site",
        "stranded_on_blocked_peer",
        "site_authorized_cumulative",
        "site_denied_cumulative",
        "central_site_authorized_cumulative",
        "central_site_denied_cumulative",
    )
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for scenario in result["scenarios"]:
        for event in scenario["timeline"]:
            writer.writerow(
                {
                    "scenario": scenario["name"],
                    "placement": scenario["placement"],
                    "workload": scenario["workload"],
                    **{field: event.get(field) for field in fields if field in event},
                }
            )
    return output.getvalue()


PHASE_END_FIELDS = (
    "scenario",
    "placement",
    "workload",
    "site",
    "initial_share",
    "normal_authorized",
    "normal_denied",
    "normal_actions_remaining",
    "normal_stranded",
    "partition_authorized",
    "partition_denied",
    "partition_actions_remaining",
    "partition_stranded",
    "recovery_authorized",
    "recovery_denied",
    "recovery_actions_remaining",
    "recovery_stranded",
    "central_authorized",
    "central_denied",
    "transfer_source",
    "transfer_target",
    "transfer_amount",
)


def _snapshot_map(scenario: Mapping[str, Any], phase: str) -> dict[str, Mapping[str, Any]]:
    phase_payload = scenario.get(phase)
    if not isinstance(phase_payload, Mapping):
        raise ValueError(f"scenario {phase!r} phase is malformed")
    snapshots = phase_payload.get("snapshots")
    if not isinstance(snapshots, list):
        raise ValueError(f"scenario {phase!r} snapshots are malformed")
    mapped: dict[str, Mapping[str, Any]] = {}
    for snapshot in snapshots:
        if not isinstance(snapshot, Mapping) or snapshot.get("alias") not in ALIASES:
            raise ValueError(f"scenario {phase!r} contains a malformed snapshot")
        mapped[str(snapshot["alias"])] = snapshot
    if set(mapped) != set(ALIASES):
        raise ValueError(f"scenario {phase!r} must contain all three site snapshots")
    return mapped


def phase_end_rows(result: Mapping[str, Any]) -> list[dict[str, object]]:
    """Return explicit, cumulative per-site phase endpoints for paper inspection."""

    scenarios = result.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("result scenarios must be an array")
    rows: list[dict[str, object]] = []
    for scenario in scenarios:
        if not isinstance(scenario, Mapping):
            raise ValueError("result contains a malformed scenario")
        snapshots = {
            phase: _snapshot_map(scenario, phase) for phase in ("normal", "partition", "recovery")
        }
        shares = scenario.get("shares")
        baseline = scenario.get("central_baseline_summary")
        recovery = scenario.get("recovery")
        if (
            not isinstance(shares, Mapping)
            or not isinstance(baseline, Mapping)
            or not isinstance(baseline.get("per_site"), Mapping)
            or not isinstance(recovery, Mapping)
            or not isinstance(recovery.get("transfer"), Mapping)
        ):
            raise ValueError("scenario summary fields are malformed")
        transfer = recovery["transfer"]
        for alias in ALIASES:
            central = baseline["per_site"].get(alias)
            if not isinstance(central, Mapping):
                raise ValueError("central baseline is missing a per-site summary")
            row: dict[str, object] = {
                "scenario": scenario.get("name"),
                "placement": scenario.get("placement"),
                "workload": scenario.get("workload"),
                "site": alias,
                "initial_share": int(shares[alias]),
                "central_authorized": int(central["authorized"]),
                "central_denied": int(central["denied"]),
                "transfer_source": transfer.get("source"),
                "transfer_target": transfer.get("target"),
                "transfer_amount": int(transfer["amount"]),
            }
            for phase in ("normal", "partition", "recovery"):
                snapshot = snapshots[phase][alias]
                row.update(
                    {
                        f"{phase}_authorized": int(snapshot["authorized"]),
                        f"{phase}_denied": int(snapshot["denied"]),
                        f"{phase}_actions_remaining": int(snapshot["actions_remaining"]),
                        f"{phase}_stranded": int(snapshot["stranded_on_blocked_peer"]),
                    }
                )
            rows.append(row)
    return rows


def phase_end_csv(result: Mapping[str, Any]) -> str:
    """Render explicit per-site phase endpoints as machine-readable CSV."""

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=PHASE_END_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(phase_end_rows(result))
    return output.getvalue()


def phase_end_markdown(result: Mapping[str, Any]) -> str:
    """Render a compact per-site phase table suitable for paper drafting."""

    lines = [
        "# LETS three-endpoint per-site phase endpoints",
        "",
        "Counts are cumulative for each site at each phase boundary. `A/D/R/S` means "
        "authorized, denied, local actions remaining, and authority stranded on the blocked "
        "peer.",
        "",
        "| Initial placement | Demand | Site | Initial authority | Pre-gate A/D/R/S | "
        "Application-path gate A/D/R/S | Recovery A/D/R/S | Central counter A/D | "
        "Post-heal transfer |",
        "|---|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for row in phase_end_rows(result):
        phase_values = {
            phase: "/".join(
                str(row[f"{phase}_{field}"])
                for field in ("authorized", "denied", "actions_remaining", "stranded")
            )
            for phase in ("normal", "partition", "recovery")
        }
        placement = _display_scenario_value(row["placement"], field="placement")
        demand = _display_scenario_value(row["workload"], field="demand")
        transfer = f"{row['transfer_source']}→{row['transfer_target']}, {row['transfer_amount']}"
        lines.append(
            f"| {placement} | {demand} | {row['site']} | "
            f"{row['initial_share']} | {phase_values['normal']} | "
            f"{phase_values['partition']} | {phase_values['recovery']} | "
            f"{row['central_authorized']}/{row['central_denied']} | {transfer} |"
        )
    lines.extend(
        [
            "",
            "The application-path gate is symmetric between s1 and s2. Stranded authority is "
            "therefore zero for s3 and outside that phase. The central-counter counts use the "
            "same per-operation site/phase schedule as the partitioned wardens.",
            "",
        ]
    )
    return "\n".join(lines)


def per_site_timeline_svg(result: Mapping[str, Any]) -> str:
    """Render deterministic 4-by-3 per-site small multiples on a fixed 0-30 scale."""

    scenarios = result.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("result scenarios must be a non-empty array")
    width = 1500
    panel_width = 430
    panel_height = 142
    column_gap = 34
    row_gap = 54
    margin_left = 72
    margin_top = 112
    plot_left_offset = 42
    plot_right_padding = 12
    plot_top_offset = 29
    plot_bottom_padding = 24
    height = margin_top + len(scenarios) * (panel_height + row_gap) + 8
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title description">',
        ('<title id="title">Per-site state over the retained three-endpoint experiment</title>'),
        (
            '<desc id="description">Four authority-placement and demand scenarios by three '
            "sites, with "
            "cumulative authorized and denied actions, actions remaining, stranded authority, "
            "and application-path gate windows.</desc>"
        ),
        "<style>text{font-family:system-ui,sans-serif;fill:#172033}.title{font-size:18px;"
        "font-weight:700}.subtitle{font-size:11px;fill:#4b5563}.panel-title{font-size:11px;"
        "font-weight:650}.tick{font-size:9px;fill:#5d6678}.axis{stroke:#8590a6;stroke-width:1}"
        ".grid{stroke:#d8dde7;stroke-width:.7}.panel{fill:#fff;stroke:#c7cedb;stroke-width:1}"
        ".partition-window{fill:#ef4444;opacity:.09}.authorized{fill:none;stroke:#1167b1;"
        "stroke-width:2.2}.denied{fill:none;stroke:#b42318;stroke-width:2;stroke-dasharray:5 3}"
        ".remaining{fill:none;stroke:#15803d;stroke-width:2}.stranded{fill:none;stroke:#7e22ce;"
        "stroke-width:2;stroke-dasharray:2 3}.series{vector-effect:non-scaling-stroke}</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        (
            '<text id="title-text" x="24" y="28" class="title">Per-site warden state over '
            "time</text>"
        ),
        (
            '<text x="24" y="48" class="subtitle">Site-event observations at global '
            "operation step; "
            "fixed y-axis 0-30; shading marks the s1↔s2 application-path gate.</text>"
        ),
        '<line x1="24" y1="73" x2="54" y2="73" class="authorized series"/>',
        '<text x="60" y="77" class="subtitle">authorized (cumulative)</text>',
        '<line x1="238" y1="73" x2="268" y2="73" class="denied series"/>',
        '<text x="274" y="77" class="subtitle">denied (cumulative)</text>',
        '<line x1="430" y1="73" x2="460" y2="73" class="remaining series"/>',
        '<text x="466" y="77" class="subtitle">actions remaining</text>',
        '<line x1="600" y1="73" x2="630" y2="73" class="stranded series"/>',
        '<text x="636" y="77" class="subtitle">stranded on blocked peer</text>',
    ]
    for row_index, scenario in enumerate(scenarios):
        if not isinstance(scenario, Mapping):
            raise ValueError("result contains a malformed scenario")
        timeline = scenario.get("timeline")
        initial = scenario.get("initial_snapshots")
        if not isinstance(timeline, list) or not isinstance(initial, list):
            raise ValueError("scenario timeline or initial snapshots are malformed")
        initial_by_alias = {
            str(item["alias"]): item
            for item in initial
            if isinstance(item, Mapping) and item.get("alias") in ALIASES
        }
        if set(initial_by_alias) != set(ALIASES):
            raise ValueError("scenario must contain all three initial site snapshots")
        total_steps = max(1, len(timeline))
        partition_steps = [
            int(event["step"])
            for event in timeline
            if isinstance(event, Mapping) and event.get("phase") == "partition"
        ]
        for column_index, alias in enumerate(ALIASES):
            panel_x = margin_left + column_index * (panel_width + column_gap)
            panel_y = margin_top + row_index * (panel_height + row_gap)
            plot_left = panel_x + plot_left_offset
            plot_right = panel_x + panel_width - plot_right_padding
            plot_top = panel_y + plot_top_offset
            plot_bottom = panel_y + panel_height - plot_bottom_padding
            plot_width = plot_right - plot_left
            plot_height = plot_bottom - plot_top

            def x_coordinate(
                step: float,
                *,
                left: int = plot_left,
                span: int = plot_width,
                steps: int = total_steps,
            ) -> float:
                return left + span * (step + 1) / steps

            def y_coordinate(
                value: int,
                *,
                bottom: int = plot_bottom,
                span: int = plot_height,
            ) -> float:
                bounded = max(0, min(30, value))
                return bottom - span * bounded / 30

            raw_scenario_label = html.escape(
                f"{scenario.get('placement')} placement / {scenario.get('workload')} workload",
                quote=True,
            )
            scenario_label = html.escape(_scenario_panel_label(scenario))
            safe_alias = html.escape(alias, quote=True)
            elements.extend(
                [
                    f'<g class="site-panel" data-scenario="{raw_scenario_label}" '
                    f'data-site="{safe_alias}">',
                    f'<rect x="{panel_x}" y="{panel_y}" width="{panel_width}" '
                    f'height="{panel_height}" rx="3" class="panel"/>',
                    f'<text x="{panel_x + 8}" y="{panel_y + 17}" class="panel-title">'
                    f"{scenario_label} · {safe_alias}</text>",
                ]
            )
            if partition_steps:
                shade_left = max(plot_left, x_coordinate(min(partition_steps) - 0.5))
                shade_right = min(plot_right, x_coordinate(max(partition_steps) + 0.5))
                elements.append(
                    f'<rect x="{shade_left:.1f}" y="{plot_top}" '
                    f'width="{max(1.0, shade_right - shade_left):.1f}" '
                    f'height="{plot_height}" class="partition-window"/>'
                )
            for tick in (0, 10, 20, 30):
                tick_y = y_coordinate(tick)
                elements.append(
                    f'<line x1="{plot_left}" y1="{tick_y:.1f}" x2="{plot_right}" '
                    f'y2="{tick_y:.1f}" class="grid"/>'
                )
                if tick in (0, 30):
                    elements.append(
                        f'<text x="{plot_left - 6}" y="{tick_y + 3:.1f}" '
                        f'text-anchor="end" class="tick">{tick}</text>'
                    )
            elements.extend(
                [
                    f'<line x1="{plot_left}" y1="{plot_top}" x2="{plot_left}" '
                    f'y2="{plot_bottom}" class="axis"/>',
                    f'<line x1="{plot_left}" y1="{plot_bottom}" x2="{plot_right}" '
                    f'y2="{plot_bottom}" class="axis"/>',
                    f'<text x="{plot_left}" y="{plot_bottom + 15}" class="tick">initial</text>',
                    f'<text x="{plot_right}" y="{plot_bottom + 15}" text-anchor="end" '
                    f'class="tick">step {total_steps - 1}</text>',
                ]
            )
            initial_snapshot = initial_by_alias[alias]
            series: dict[str, list[tuple[float, int]]] = {
                "authorized": [(-1.0, int(initial_snapshot["authorized"]))],
                "denied": [(-1.0, int(initial_snapshot["denied"]))],
                "remaining": [(-1.0, int(initial_snapshot["actions_remaining"]))],
                "stranded": [(-1.0, int(initial_snapshot["stranded_on_blocked_peer"]))],
            }
            for event in timeline:
                if not isinstance(event, Mapping) or event.get("site") != alias:
                    continue
                step = float(event["step"])
                series["authorized"].append((step, int(event["site_authorized_cumulative"])))
                series["denied"].append((step, int(event["site_denied_cumulative"])))
                series["remaining"].append((step, int(event["actions_remaining_at_site"])))
                series["stranded"].append((step, int(event["stranded_on_blocked_peer"])))
            for metric in ("authorized", "denied", "remaining", "stranded"):
                points = " ".join(
                    f"{x_coordinate(step):.1f},{y_coordinate(value):.1f}"
                    for step, value in series[metric]
                )
                elements.append(
                    f'<polyline points="{points}" class="{metric} series" data-metric="{metric}"/>'
                )
            elements.append("</g>")
    elements.append("</svg>")
    return "\n".join(elements)


def timeline_svg(result: Mapping[str, Any]) -> str:
    width = 960
    panel_height = 170
    margin_left = 64
    plot_width = width - margin_left - 30
    height = 50 + panel_height * len(result["scenarios"])
    elements = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        "<style>text{font-family:system-ui,sans-serif;fill:#172033}.title{font-size:18px;"
        "font-weight:700}.label{font-size:11px}.axis{stroke:#8590a6;stroke-width:1}.lets{"
        "fill:none;stroke:#1167b1;stroke-width:2.5}.central{fill:none;stroke:#d97706;"
        "stroke-width:2.5}.partition{fill:#ef4444;opacity:.09}</style>",
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        (
            '<text x="24" y="28" class="title">Cumulative authorized operations for four '
            "fixed schedules</text>"
        ),
    ]
    for panel, scenario in enumerate(result["scenarios"]):
        events = scenario["timeline"]
        top = 48 + panel * panel_height
        bottom = top + 118
        total = max(1, len(events))
        maximum = max(1, total)

        def x(index: int, *, event_total: int = total) -> float:
            return margin_left + plot_width * index / max(1, event_total - 1)

        def y(value: int, *, panel_bottom: int = bottom, panel_maximum: int = maximum) -> float:
            return panel_bottom - 92 * value / panel_maximum

        partition_indexes = [
            index for index, event in enumerate(events) if event["phase"] == "partition"
        ]
        if partition_indexes:
            left = x(min(partition_indexes))
            right = x(max(partition_indexes))
            elements.append(
                f'<rect x="{left:.1f}" y="{top + 22}" width="{max(2.0, right - left):.1f}" '
                f'height="96" class="partition"/>'
            )
        elements.extend(
            [
                f'<line x1="{margin_left}" y1="{bottom}" x2="{width - 30}" '
                f'y2="{bottom}" class="axis"/>',
                f'<text x="{margin_left}" y="{top + 13}" class="label">'
                f"({chr(ord('a') + panel)}) "
                f"{html.escape(_scenario_panel_label(scenario))}</text>",
                f'<text x="8" y="{bottom}" class="label">0</text>',
                f'<text x="8" y="{top + 29}" class="label">{maximum}</text>',
            ]
        )
        lets_count = 0
        central_count = 0
        lets_points: list[str] = []
        central_points: list[str] = []
        for index, event in enumerate(events):
            lets_count += int(event["lets_authorized"] is True)
            central_count += int(event["central_authorized"] is True)
            lets_points.append(f"{x(index):.1f},{y(lets_count):.1f}")
            central_points.append(f"{x(index):.1f},{y(central_count):.1f}")
        elements.append(f'<polyline points="{" ".join(lets_points)}" class="lets"/>')
        elements.append(f'<polyline points="{" ".join(central_points)}" class="central"/>')
        elements.append(
            f'<text x="{width - 235}" y="{top + 13}" class="label">'
            '<tspan fill="#1167b1">partitioned wardens</tspan><tspan>  </tspan>'
            '<tspan fill="#d97706">central counter</tspan></text>'
        )
    elements.append("</svg>")
    return "\n".join(elements)


def report_markdown(result: Mapping[str, Any]) -> str:
    scope = result["scope"]
    evidence = result["host_evidence"]
    distinct_boots = len({item["boot_id_sha256"] for item in evidence["linux_boot_identity"]})
    peer_transport = str(scope["peer_transport"]).replace("host-to-host", "endpoint-to-endpoint")
    lines = [
        "# LETS three-endpoint development experiment",
        "",
        f"- **Result:** `{result['status']}`",
        f"- **Run:** `{result['run_id']}`",
        f"- **Tracked source commit:** `{result['source']['commit']}`",
        "",
        "> Scope: three distinct SSH endpoints with distinct Linux boot identities, one real "
        "LETS SQLite warden, and one separate local SQLite executor claim store per endpoint. "
        "This does not prove physical-machine, power, rack, or failure-domain independence. "
        "Peer bytes traversed a controller relay over two SSH sessions, so this is not a direct "
        "endpoint-to-endpoint route or WAN latency measurement.",
        "",
        "## Reproducibility and safety",
        "",
        f"- Remote write boundary: {scope['remote_write_boundary']}.",
        f"- Pinned Python: `{PYTHON_VERSION}`; pinned uv: `{UV_VERSION}`.",
        f"- Source archive SHA-256: `{result['source']['archive_sha256']}`.",
        f"- Harness SHA-256: `{result['harness']['sha256']}`.",
        "- Rerun: `python -m benchmarks.nsdi_strengthening.remote_three_host "
        "--credentials <credential-file> --inventory <inventory.json> --overwrite`.",
        "- No sudo, Docker, system package mutation, credential retention, raw address "
        "retention, or raw username retention.",
        "",
        "## Endpoint and transport evidence",
        "",
        f"- Distinct address fingerprints: **{evidence['distinct_address_hashes']}**.",
        f"- Distinct SSH host keys: **{evidence['distinct_ssh_host_keys']}**.",
        f"- Distinct Linux boot IDs: **{distinct_boots}**.",
        f"- Peer transport: {peer_transport}.",
        "- Inter-warden authentication: HMAC-SHA256 over method, path, timestamp, nonce, body "
        "digest, and source alias; the shared key was never sent on the peer path.",
        "",
        "## Partitioned local progress",
        "",
        "| Initial placement | Demand | Partitioned wardens | Central counter | "
        "Post-heal transfer |",
        "|---|---|---:|---:|---|",
    ]
    conservation_count = 0
    debit_match_count = 0
    envelope_units: set[int] = set()
    for scenario in result["scenarios"]:
        lets_authorized = sum(int(item["authorized"]) for item in scenario["final_snapshots"])
        lets_denied = sum(int(item["denied"]) for item in scenario["final_snapshots"])
        central = scenario["central_baseline_summary"]
        transfer = scenario["recovery"]["transfer"]
        aggregate = scenario["aggregate_final"]
        placement = _display_scenario_value(scenario.get("placement"), field="placement")
        demand = _display_scenario_value(scenario.get("workload"), field="demand")
        conservation_count += int(aggregate["conservation_holds"] is True)
        debit_match_count += int(int(aggregate["consumed"]) == lets_authorized)
        envelope_units.add(int(aggregate["initial_share"]))
        lines.append(
            f"| {placement} | {demand} | "
            f"{lets_authorized}/{lets_denied} | {central['authorized']}/{central['denied']} | "
            f"{transfer['source']}→{transfer['target']}, {transfer['amount']} |"
        )
    scenario_count = len(result["scenarios"])
    if len(envelope_units) != 1:
        raise ValueError("scenario envelopes do not share one displayable initial allocation")
    envelope_units_value = next(iter(envelope_units))
    if conservation_count == scenario_count:
        conservation_summary = f"Every row conserved its {envelope_units_value}-unit envelope."
    else:
        conservation_summary = (
            f"{conservation_count}/{scenario_count} rows conserved their "
            f"{envelope_units_value}-unit envelope."
        )
    if debit_match_count == scenario_count:
        debit_summary = (
            "Each operation cost one unit, so warden debit equaled the authorized count in "
            "every row."
        )
    else:
        debit_summary = (
            f"Warden debit equaled the authorized count in "
            f"{debit_match_count}/{scenario_count} rows."
        )
    lines.extend(
        [
            "",
            conservation_summary,
            debit_summary,
            "",
            "Each fixed schedule includes pre-gate, symmetric s1↔s2 application-path gate, "
            "and recovery phases. Raw events contain cumulative authorized/denied counts, "
            "remaining local actions, phase snapshots, authority stranded on the blocked "
            "counterpart, and the same operation schedule against a durable centralized SQLite "
            "counter on s2.",
            "",
            "The executor claim stores deliberately used LETS's explicit unanchored development "
            "mode. "
            "The result demonstrates separately hosted durable state and executors, but does not "
            "claim production rollback protection, firewall-level partitioning, direct WAN "
            "transport, or physical failure-domain independence.",
            "",
        ]
    )
    if result["assertions"]["failures"]:
        lines.extend(["## Failed assertions", ""])
        lines.extend(f"- {failure}" for failure in result["assertions"]["failures"])
        lines.append("")
    return "\n".join(lines)


def load_retained_result(path: Path) -> Mapping[str, Any]:
    """Load only a completed result envelope for credential-free local rendering."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping) or payload.get("schema") != SCHEMA:
        raise ValueError("retained result uses an unsupported schema")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("retained result does not contain scenarios")
    return payload


def write_supplemental_outputs(
    result: Mapping[str, Any], output_dir: Path, *, overwrite: bool
) -> dict[str, Path]:
    """Write deterministic supplemental views without mutating the raw result."""

    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "per_site_figure": output_dir / PER_SITE_FIGURE_NAME,
        "phase_end_csv": output_dir / PHASE_END_CSV_NAME,
        "phase_end_markdown": output_dir / PHASE_END_MARKDOWN_NAME,
    }
    write_text(
        paths["per_site_figure"],
        per_site_timeline_svg(result),
        overwrite=overwrite,
    )
    write_text(paths["phase_end_csv"], phase_end_csv(result), overwrite=overwrite)
    write_text(
        paths["phase_end_markdown"],
        phase_end_markdown(result),
        overwrite=overwrite,
    )
    return paths


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--credentials", type=Path)
    mode.add_argument(
        "--render-existing",
        type=Path,
        help="render supplemental artifacts from a retained JSON result without SSH",
    )
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--run-id")
    parser.add_argument("--base-port", type=int, default=47180)
    parser.add_argument("--uv-archive", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def failure_envelope(exc: BaseException) -> dict[str, str]:
    """Return actionable failure metadata without echoing exception text."""

    if isinstance(exc, RemoteExperimentError):
        stage = exc.stage or "orchestration"
        reason = exc.reason
    else:
        stage = "controller"
        reason = "unexpected_exception"
    return {
        "status": "failed",
        "error_class": type(exc).__name__,
        "stage": stage,
        "reason": reason,
        "detail": "experiment aborted; no credential, address, username, or home path was emitted",
    }


def main() -> int:
    arguments = _arguments()
    if arguments.render_existing is not None:
        try:
            retained = load_retained_result(arguments.render_existing)
            supplemental = write_supplemental_outputs(
                retained, arguments.output_dir, overwrite=arguments.overwrite
            )
        except Exception as exc:
            print(json.dumps(failure_envelope(exc)))
            return 2
        print(
            json.dumps(
                {
                    "status": "rendered",
                    "mode": "local_retained_result",
                    **{label: str(path) for label, path in supplemental.items()},
                }
            )
        )
        return 0
    if arguments.credentials is None:
        raise AssertionError("argument parser did not select an execution mode")
    try:
        result = run_experiment(
            arguments.credentials,
            arguments.inventory,
            arguments.repository.resolve(),
            run_id=arguments.run_id,
            base_port=arguments.base_port,
            uv_archive=arguments.uv_archive,
        )
    except Exception as exc:
        print(json.dumps(failure_envelope(exc)))
        return 2
    arguments.output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = arguments.output_dir / "three-host-linux-result.json"
    report_path = arguments.output_dir / "three-host-linux-report.md"
    csv_path = arguments.output_dir / "three-host-linux-timeline.csv"
    figure_path = arguments.output_dir / "three-host-linux-timeline.svg"
    write_json(raw_path, result, overwrite=arguments.overwrite)
    write_text(report_path, report_markdown(result), overwrite=arguments.overwrite)
    write_text(csv_path, timeline_csv(result), overwrite=arguments.overwrite)
    write_text(figure_path, timeline_svg(result), overwrite=arguments.overwrite)
    supplemental = write_supplemental_outputs(
        result, arguments.output_dir, overwrite=arguments.overwrite
    )
    print(
        json.dumps(
            {
                "status": result["status"],
                "result": str(raw_path),
                "report": str(report_path),
                "timeline": str(csv_path),
                "figure": str(figure_path),
                **{label: str(path) for label, path in supplemental.items()},
            }
        )
    )
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
