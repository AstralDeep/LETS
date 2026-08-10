"""Run a sustained, chaos-injected soak against one exact production OCI digest."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from contextlib import suppress
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from importlib import metadata
from itertools import pairwise
from pathlib import Path
from typing import Any, TypeGuard, cast

ROOT = Path(__file__).resolve().parents[2]
PROJECT_PREFIX = "lets-production-soak"
COMPOSE_FILE = ROOT / "deploy" / "production" / "acceptance-compose.yaml"
WARDENS = ("warden-a", "warden-b", "warden-c")
TRANSFER_PAIRS_FOR_EVALUATION = (
    ("warden-a", "warden-b"),
    ("warden-b", "warden-a"),
    ("warden-a", "warden-c"),
    ("warden-c", "warden-a"),
    ("warden-b", "warden-c"),
    ("warden-c", "warden-b"),
)
TOXIPROXY = "http://127.0.0.1:28474"
WORKLOAD_PAUSE_PATH = "/scenario/soak-workload-pause.json"
WORKLOAD_PAUSE_ACK_PATH = "/scenario/soak-workload-pause-ack.json"
WORKLOAD_RESTART_PATH = "/scenario/soak-workload-restart.json"
WORKLOAD_RESTART_ACK_PATH = "/scenario/soak-workload-restart-ack.json"
WORKLOAD_START_PATH = "/scenario/soak-workload-start.json"
DEFAULT_EVIDENCE = ROOT / "results" / "generated" / "production-profile-soak.json"
IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
CONTAINER_ID = re.compile(r"\A[0-9a-f]{12,64}\Z")
CONTAINER_NAME = re.compile(r"\A[a-z0-9][a-z0-9_.-]{0,127}\Z")
AUTHORITY_LIFETIME_ID = re.compile(r"\A[0-9a-f]{32}\Z")
AUTHORITY_COUNTER_MAX = (1 << 63) - 1
AUTHORITY_STATUS_FIELDS = frozenset(
    {
        "admission_fenced",
        "enabled",
        "fault_reason",
        "fault_stage",
        "fence_id",
        "fenced_at_monotonic_ns",
        "first_fault",
        "healthy",
        "lifetime_id",
        "namespace_process_id",
        "permanent_faults",
        "retry_not_before_monotonic_ns",
        "state",
        "transport_fault_episodes",
        "transport_faults",
        "transport_recoveries",
        "transport_recovery_attempts",
        "unresolved_transport_faults",
    }
)
EXECUTOR_AUTHORITY_STATUS_FIELDS = frozenset(
    {
        "enabled",
        "fault_reason",
        "fault_stage",
        "first_fault",
        "healthy",
        "lifetime_id",
        "permanent_faults",
        "retry_not_before_monotonic_ns",
        "state",
        "transport_fault_episodes",
        "transport_faults",
        "transport_recoveries",
        "transport_recovery_attempts",
        "unresolved_transport_faults",
    }
)
AUTHORITY_COUNTER_FIELDS = (
    "transport_faults",
    "transport_fault_episodes",
    "transport_recovery_attempts",
    "transport_recoveries",
    "permanent_faults",
)
AUTHORITY_FIRST_FAULT_FIELDS = frozenset(
    {
        "helper_exit_code",
        "helper_pid",
        "mutation_uncertain",
        "operation",
        "reason",
        "request_flushed",
        "stage",
    }
)
AUTHORITY_TRANSPORT_REASONS = frozenset(
    {
        "deadline",
        "helper_eof",
        "helper_pipe",
        "helper_start",
        "helper_start_deadline",
        "helper_start_in_progress",
        "process_lock_deadline",
    }
)
AUTHORITY_OPERATIONS = frozenset({"compare-and-set", "confirm", "initialize", "read"})
EXECUTOR_AUTHORITY_CHECKPOINT_FIELDS = frozenset(
    {
        "audience",
        "claim_digest",
        "claim_sequence",
        "clock_floor_ns",
        "config_epoch",
        "database_instance_id",
        "envelope_id",
        "executor_policy_sha256",
        "format",
        "schema_version",
        "tenant_id",
        "trust_registry_sha256",
    }
)
EXECUTOR_AUTHORITY_CHECKPOINT_FORMAT = "LETS-EXECUTOR-AUTHORITY-ANCHOR/1"
EXECUTOR_AUTHORITY_SCHEMA_VERSION = 5
DEFAULT_RESTART_INTERVAL_SECONDS = 900.0
MIN_RESTART_EPISODES = len(WARDENS)
TARGET_MAXIMUM_ACTIVE_SECONDS_PER_CYCLE = 15.0
HEALTH_CADENCE_LIMIT_SECONDS = 15.0
MAXIMUM_PLANNED_RESTART_SECONDS = 30.0
RELEASE_PATH_ROTATIONS = MIN_RESTART_EPISODES
SMOKE_PATH_ROTATIONS = 1
MINIMUM_RETRY_ALLOWANCE = 24
MAXIMUM_RETRIES_PER_CYCLE = 4
MAXIMUM_RETRIES_PER_HEALTH_SAMPLE = 4
MAXIMUM_CYCLE_LATENCY_SECONDS = 120.0
CHAOS_START_SHUTDOWN_MARGIN_SECONDS = (
    2 * HEALTH_CADENCE_LIMIT_SECONDS + MAXIMUM_PLANNED_RESTART_SECONDS
)
FAILED_EVIDENCE_MAX_CHAOS_EVENTS = 256
FAILED_EVIDENCE_MAX_RESOURCE_SAMPLES = 2_048
FAILED_EVIDENCE_MAX_TEXT_BYTES = 16_384
FAILURE_COMMAND_TIMEOUT_SECONDS = 5.0
FAILURE_DOWN_TIMEOUT_SECONDS = 30.0
FAILURE_LOG_TIMEOUT_SECONDS = 10.0
VOLUME_KEYS = {
    "trust",
    "client",
    "scenario",
    "executor-state",
    "executor-authority",
    *(
        f"warden-{letter}-{kind}"
        for letter in "abc"
        for kind in ("state", "config", "authority", "audit", "pki", "signer")
    ),
}
RESOURCE_PROBE = """
import json
from pathlib import Path

CGROUP = Path("/sys/fs/cgroup")

def required_scalar(name):
    path = CGROUP / name
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"required cgroup v2 scalar is unavailable: {name}: {exc}") from exc
    if not raw.isdecimal():
        raise RuntimeError(f"required cgroup v2 scalar is malformed: {name}={raw!r}")
    value = int(raw)
    if value < 0:
        raise RuntimeError(f"required cgroup v2 scalar is negative: {name}={value}")
    return value

def required_events(name, expected):
    path = CGROUP / name
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError(f"required cgroup v2 events are unavailable: {name}: {exc}") from exc
    events = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2 or not fields[1].isdecimal() or fields[0] in events:
            raise RuntimeError(f"required cgroup v2 events are malformed: {name}={lines!r}")
        events[fields[0]] = int(fields[1])
    missing = sorted(set(expected) - events.keys())
    if missing:
        raise RuntimeError(f"required cgroup v2 event counters are missing: {name}: {missing!r}")
    return events

def sizes(path):
    target = Path(path)
    shared_memory = Path(f"{target}-shm")
    wal = Path(f"{target}-wal")
    return {
        "database_bytes": target.stat().st_size if target.exists() else 0,
        "shared_memory_bytes": shared_memory.stat().st_size if shared_memory.exists() else 0,
        "wal_bytes": wal.stat().st_size if wal.exists() else 0,
    }

init_command = tuple(
    item.decode("utf-8", errors="replace")
    for item in Path("/proc/1/cmdline").read_bytes().split(b"\\0")
    if item
)
if not init_command or Path(init_command[0]).name not in {"tini", "docker-init"}:
    raise RuntimeError(f"container PID 1 is not the configured init shim: {init_command!r}")
if not (CGROUP / "cgroup.controllers").is_file():
    raise RuntimeError("the runtime does not expose a cgroup v2 unified hierarchy")
runtime_processes = []
for proc in Path("/proc").iterdir():
    if not proc.name.isdigit():
        continue
    if proc.name == "1":
        continue
    try:
        command = tuple(
            item.decode("utf-8", errors="replace")
            for item in (proc / "cmdline").read_bytes().split(b"\\0")
            if item
        )
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        continue
    if (
        command
        and Path(command[0]).name not in {"tini", "docker-init"}
        and "serve" in command
        and any(Path(item).name == "lets" for item in command)
    ):
        runtime_processes.append((int(proc.name), command))
if len(runtime_processes) != 1:
    raise RuntimeError(f"expected one LETS serve process, found {runtime_processes!r}")
runtime_pid, runtime_command = runtime_processes[0]
if runtime_pid == 1 or Path(runtime_command[0]).name == "tini":
    raise RuntimeError(f"resource target is the init shim: {runtime_processes!r}")

status = {}
for line in Path(f"/proc/{runtime_pid}/status").read_text().splitlines():
    if line.startswith(("VmRSS:", "VmPeak:")):
        name, value, _unit = line.split()
        status[name.removesuffix(":").lower() + "_bytes"] = int(value) * 1024
document = {
    "audit": sizes("/var/lib/lets-audit/audit.sqlite3"),
    "authority_anchor_bytes": Path("/var/lib/lets-authority/anchor.json").stat().st_size,
    "core": sizes("/var/lib/lets/warden.sqlite3"),
    "cgroup": {
        "memory": {
            "current_bytes": required_scalar("memory.current"),
            "events": required_events(
                "memory.events",
                ("low", "high", "max", "oom", "oom_kill", "oom_group_kill"),
            ),
            "max_bytes": required_scalar("memory.max"),
            "peak_bytes": required_scalar("memory.peak"),
        },
        "pids": {
            "current": required_scalar("pids.current"),
            "events": required_events("pids.events", ("max",)),
            "max": required_scalar("pids.max"),
            "peak": required_scalar("pids.peak"),
        },
        "swap": {
            "current_bytes": required_scalar("memory.swap.current"),
            "events": required_events(
                "memory.swap.events", ("high", "max", "fail")
            ),
            "max_bytes": required_scalar("memory.swap.max"),
            "peak_bytes": required_scalar("memory.swap.peak"),
        },
        "version": 2,
    },
    "fd_count": len(tuple(Path(f"/proc/{runtime_pid}/fd").iterdir())),
    "init": {"cmdline": list(init_command), "pid": 1},
    "process": {
        "cmdline": list(runtime_command),
        "identity": "lets-serve",
        "pid": runtime_pid,
    },
    "rss_bytes": status.get("vmrss_bytes", 0),
    "signer_log_bytes": Path("/var/lib/lets-audit/signer-helper.jsonl").stat().st_size,
    "virtual_peak_bytes": status.get("vmpeak_bytes", 0),
}
print(json.dumps(document, sort_keys=True))
""".strip()
PENDING_TRANSFER_PROBE = r'''
import json
import sqlite3
import sys

transfer_id, target = sys.argv[1:]
connection = sqlite3.connect(
    "file:/var/lib/lets/warden.sqlite3?mode=ro", uri=True, timeout=5
)
connection.row_factory = sqlite3.Row
probe = connection.execute(
    """
    SELECT t.transfer_id, t.sequence, t.status, d.attempts, d.last_attempt_ns,
           d.next_attempt_ns, d.delivered_at_ns, d.superseded_at_ns,
           CASE WHEN d.last_error IS NULL THEN 0 ELSE 1 END AS has_error
    FROM outgoing_transfers AS t
    JOIN peer_delivery_state AS d
      ON d.record_kind = 'transfer'
     AND d.record_id = t.transfer_id
     AND d.target_warden = t.target_warden
    WHERE t.transfer_id = ? AND t.target_warden = ?
    """,
    (transfer_id, target),
).fetchone()
connection.close()
print(json.dumps(None if probe is None else dict(probe), sort_keys=True))
'''.strip()
OUTGOING_STREAM_PROBE = r'''
import json
import sqlite3
import sys

target = sys.argv[1]
connection = sqlite3.connect(
    "file:/var/lib/lets/warden.sqlite3?mode=ro", uri=True, timeout=5
)
connection.row_factory = sqlite3.Row
row = connection.execute(
    """
    SELECT target_warden, acked_through, compacted_through
    FROM outgoing_transfer_streams
    WHERE tenant_id = ? AND envelope_id = ? AND target_warden = ?
    """,
    ("production-acceptance-tenant", "production-acceptance-envelope", target),
).fetchone()
connection.close()
print(json.dumps(None if row is None else dict(row), sort_keys=True))
'''.strip()
INCOMING_STREAM_PROBE = r'''
import json
import sqlite3
import sys

source = sys.argv[1]
connection = sqlite3.connect(
    "file:/var/lib/lets/warden.sqlite3?mode=ro", uri=True, timeout=5
)
connection.row_factory = sqlite3.Row
row = connection.execute(
    """
    SELECT source_warden, contiguous_through, compacted_through
    FROM inbound_transfer_streams
    WHERE tenant_id = ? AND envelope_id = ? AND source_warden = ?
    """,
    ("production-acceptance-tenant", "production-acceptance-envelope", source),
).fetchone()
connection.close()
print(json.dumps(None if row is None else dict(row), sort_keys=True))
'''.strip()


@dataclass(frozen=True, slots=True)
class ResourceBounds:
    max_rss_bytes: int = 256 * 1024 * 1024
    max_rss_growth_bytes: int = 128 * 1024 * 1024
    max_cgroup_memory_peak_bytes: int = 768 * 1024 * 1024
    cgroup_memory_max_bytes: int = 1024 * 1024 * 1024
    cgroup_swap_max_bytes: int = 0
    max_cgroup_pids_peak: int = 192
    cgroup_pids_max: int = 256
    max_fd_count: int = 512
    max_fd_growth: int = 128
    max_core_database_bytes: int = 100 * 1024 * 1024
    max_core_wal_bytes: int = 32 * 1024 * 1024
    fixed_growth_allowance_bytes: int = 8 * 1024 * 1024
    max_core_growth_bytes_per_cycle: int = 128 * 1024
    max_audit_growth_bytes_per_cycle: int = 128 * 1024
    max_signer_growth_bytes_per_cycle: int = 32 * 1024


@dataclass(frozen=True, slots=True)
class SoakConfiguration:
    image: str
    duration_seconds: float
    cycle_interval_seconds: float
    health_interval_seconds: float
    resource_interval_seconds: float
    partition_interval_seconds: float
    partition_duration_seconds: float
    restart_interval_seconds: float
    retry_timeout_seconds: float
    convergence_timeout_seconds: float
    transfer_every_cycles: int
    executor_reopen_every_cycles: int
    initial_share: int
    seed: int
    smoke: bool

    def validate(self) -> None:
        if IMAGE_DIGEST.fullmatch(self.image) is None:
            raise ValueError("image must be an exact name@sha256:<64 lowercase hex> reference")
        positive = {
            "duration_seconds": self.duration_seconds,
            "cycle_interval_seconds": self.cycle_interval_seconds,
            "health_interval_seconds": self.health_interval_seconds,
            "resource_interval_seconds": self.resource_interval_seconds,
            "partition_interval_seconds": self.partition_interval_seconds,
            "partition_duration_seconds": self.partition_duration_seconds,
            "restart_interval_seconds": self.restart_interval_seconds,
            "retry_timeout_seconds": self.retry_timeout_seconds,
            "convergence_timeout_seconds": self.convergence_timeout_seconds,
        }
        invalid = [
            name for name, value in positive.items() if not math.isfinite(value) or value <= 0
        ]
        if invalid:
            raise ValueError(f"soak durations must be positive: {invalid}")
        if self.partition_duration_seconds >= self.partition_interval_seconds:
            raise ValueError("partition duration must be shorter than its interval")
        if self.transfer_every_cycles <= 0 or self.executor_reopen_every_cycles <= 0:
            raise ValueError("cycle frequencies must be positive")
        if not 100 <= self.initial_share <= 1_000_000_000:
            raise ValueError("initial share must be between 100 and 1000000000")
        if self.smoke:
            if self.duration_seconds < 10:
                raise ValueError("a smoke soak must run for at least 10 seconds")
        elif self.duration_seconds < 300:
            raise ValueError("a sustained soak must run for at least 300 seconds")
        shutdown_margin = chaos_start_shutdown_margin_seconds(self)
        minimum_partition_schedule = (
            2 * self.partition_interval_seconds + self.partition_duration_seconds + shutdown_margin
        )
        if self.duration_seconds <= minimum_partition_schedule:
            raise ValueError("duration must permit two bounded partition episodes")
        minimum_restart_schedule = (
            MIN_RESTART_EPISODES * self.restart_interval_seconds + shutdown_margin
        )
        if self.duration_seconds <= minimum_restart_schedule:
            raise ValueError("duration must permit a SIGKILL episode for every warden")
        if self.retry_timeout_seconds > 90:
            raise ValueError("retry timeout must be at most 90 seconds")
        if self.health_interval_seconds > HEALTH_CADENCE_LIMIT_SECONDS:
            raise ValueError("health interval must not exceed the 15-second release bound")
        if self.duration_seconds < semantic_cycle_floor(self) * self.cycle_interval_seconds:
            raise ValueError("duration cannot theoretically cover the semantic cycle floor")


class WorkloadExitedError(RuntimeError):
    """Carry a prematurely exited workload's diagnostics into failure evidence."""

    def __init__(self, *, context: str, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"soak workload exited {context} ({returncode}); "
            f"stdout={_bounded_text(stdout)!r}; stderr={_bounded_text(stderr)!r}"
        )


class FinalVerificationError(RuntimeError):
    """Carry a failed terminal capture after its partial result was persisted."""

    def __init__(self, result: dict[str, Any], *, returncode: int) -> None:
        self.result = result
        self.returncode = returncode
        super().__init__(f"final verification failed with persisted evidence ({returncode})")


def _bounded_text(value: str, *, maximum_bytes: int = FAILED_EVIDENCE_MAX_TEXT_BYTES) -> str:
    if maximum_bytes <= 0:
        return ""
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= maximum_bytes:
        return value
    marker = b"...[truncated to bounded tail]...\n"
    if maximum_bytes <= len(marker):
        return marker[:maximum_bytes].decode("ascii")
    retained = encoded[-(maximum_bytes - len(marker)) :].decode("utf-8", errors="ignore")
    return marker.decode("ascii") + retained


def _require_workload_running(workload: subprocess.Popen[str], *, context: str) -> None:
    returncode = workload.poll()
    if returncode is None:
        return
    stdout, stderr = workload.communicate(timeout=1)
    raise WorkloadExitedError(
        context=context,
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
    )


def semantic_cycle_floor(configuration: SoakConfiguration) -> int:
    rotations = SMOKE_PATH_ROTATIONS if configuration.smoke else RELEASE_PATH_ROTATIONS
    if configuration.smoke:
        transfer_floor = (
            len(TRANSFER_PAIRS_FOR_EVALUATION) - 1
        ) * configuration.transfer_every_cycles + 1
        reopen_floor = configuration.executor_reopen_every_cycles
    else:
        transfer_floor = (
            rotations * len(TRANSFER_PAIRS_FOR_EVALUATION) * configuration.transfer_every_cycles
        )
        reopen_floor = rotations * configuration.executor_reopen_every_cycles
    return max(transfer_floor, reopen_floor)


def minimum_cycle_count(
    configuration: SoakConfiguration,
    *,
    active_workload_seconds: float | None = None,
) -> int:
    active_seconds = (
        configuration.duration_seconds
        if active_workload_seconds is None
        else active_workload_seconds
    )
    if not math.isfinite(active_seconds) or active_seconds < 0:
        raise ValueError("active workload seconds must be finite and non-negative")
    throughput_floor = math.ceil(active_seconds / TARGET_MAXIMUM_ACTIVE_SECONDS_PER_CYCLE)
    return max(semantic_cycle_floor(configuration), throughput_floor)


def minimum_health_sample_count(configuration: SoakConfiguration) -> int:
    return math.ceil(configuration.duration_seconds / configuration.health_interval_seconds) + 1


def chaos_start_shutdown_margin_seconds(configuration: SoakConfiguration) -> float:
    """Reserve enough live workload time for an in-flight cycle or restart handshake."""

    maximum_cycle_latency = min(
        MAXIMUM_CYCLE_LATENCY_SECONDS,
        configuration.retry_timeout_seconds + 30.0,
    )
    return max(
        CHAOS_START_SHUTDOWN_MARGIN_SECONDS,
        maximum_cycle_latency + 30.0,
    )


def may_start_chaos_episode(configuration: SoakConfiguration, *, elapsed_s: float) -> bool:
    """Keep the workload alive long enough to durably acknowledge a new fault episode."""

    return configuration.duration_seconds - elapsed_s > chaos_start_shutdown_margin_seconds(
        configuration
    )


def _next_restart_deadline(
    *, prior_deadline: float, interval_s: float, completed_at: float
) -> float:
    """Keep restart cadence anchored without allowing delayed episodes to bunch together."""

    minimum_gap = min(30.0, interval_s / 4)
    return max(prior_deadline + interval_s, completed_at + minimum_gap)


def _expected_transfer_pair_counts(*, cycles: int, transfer_every_cycles: int) -> dict[str, int]:
    pairs = (
        ("warden-a", "warden-b"),
        ("warden-b", "warden-a"),
        ("warden-a", "warden-c"),
        ("warden-c", "warden-a"),
        ("warden-b", "warden-c"),
        ("warden-c", "warden-b"),
    )
    counts = {f"{source}->{target}": 0 for source, target in pairs}
    prepared = (cycles + transfer_every_cycles - 1) // transfer_every_cycles
    for ordinal in range(prepared):
        source, target = pairs[ordinal % len(pairs)]
        counts[f"{source}->{target}"] += 1
    return counts


def _finite_number(value: object) -> TypeGuard[int | float]:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _valid_authority_status(
    value: object,
    *,
    fenced: bool | None = None,
    terminal: bool = False,
    executor: bool = False,
) -> TypeGuard[dict[str, Any]]:
    """Validate the exact bounded authenticated authority evidence contract."""

    expected_fields = EXECUTOR_AUTHORITY_STATUS_FIELDS if executor else AUTHORITY_STATUS_FIELDS
    if not isinstance(value, dict) or set(value) != expected_fields:
        return False
    state = value.get("state")
    lifetime = value.get("lifetime_id")
    namespace_pid = value.get("namespace_process_id") if not executor else 1
    admission_fenced = value.get("admission_fenced") if not executor else False
    if (
        value.get("enabled") is not True
        or state not in {"healthy", "recoverable_transport_fault", "permanent_fault"}
        or type(value.get("healthy")) is not bool
        or value.get("healthy") is not (state == "healthy")
        or not isinstance(lifetime, str)
        or AUTHORITY_LIFETIME_ID.fullmatch(lifetime) is None
        or type(namespace_pid) is not int
        or namespace_pid <= 0
        or type(admission_fenced) is not bool
        or (fenced is not None and admission_fenced is not fenced)
        or (executor and fenced is not None)
    ):
        return False
    fence_id = value.get("fence_id") if not executor else None
    fenced_at = value.get("fenced_at_monotonic_ns") if not executor else None
    if admission_fenced:
        if (
            not isinstance(fence_id, str)
            or not 1 <= len(fence_id) <= 128
            or type(fenced_at) is not int
            or fenced_at < 0
        ):
            return False
    elif fence_id is not None or fenced_at is not None:
        return False
    counters: dict[str, int] = {}
    for field_name in AUTHORITY_COUNTER_FIELDS:
        counter = value.get(field_name)
        if type(counter) is not int or not 0 <= counter <= AUTHORITY_COUNTER_MAX:
            return False
        counters[field_name] = counter
    unresolved = value.get("unresolved_transport_faults")
    if (
        type(unresolved) is not int
        or unresolved not in {0, 1}
        or counters["transport_faults"] < counters["transport_fault_episodes"]
        or counters["transport_fault_episodes"] < counters["transport_recoveries"]
        or counters["transport_recovery_attempts"] < counters["transport_recoveries"]
        or unresolved != int(state == "recoverable_transport_fault")
        or (state == "permanent_fault" and counters["permanent_faults"] == 0)
    ):
        return False
    fault_stage = value.get("fault_stage")
    fault_reason = value.get("fault_reason")
    retry_not_before = value.get("retry_not_before_monotonic_ns")
    if (fault_stage is not None and fault_stage not in {"pre_begin", "post_commit"}) or (
        fault_reason is not None
        and (
            not isinstance(fault_reason, str)
            or re.fullmatch(r"[a-z0-9_]{1,64}", fault_reason) is None
        )
    ):
        return False
    if state == "healthy":
        if fault_stage is not None or fault_reason is not None or retry_not_before is not None:
            return False
    elif state == "recoverable_transport_fault":
        if (
            fault_stage is None
            or fault_reason is None
            or type(retry_not_before) is not int
            or retry_not_before < 0
        ):
            return False
    elif retry_not_before is not None:
        return False
    first_fault = value.get("first_fault")
    if first_fault is None:
        if counters["transport_faults"] != 0:
            return False
    elif (
        not isinstance(first_fault, dict)
        or set(first_fault) != AUTHORITY_FIRST_FAULT_FIELDS
        or counters["transport_faults"] == 0
        or first_fault.get("stage") not in {"pre_begin", "post_commit"}
        or first_fault.get("operation") not in AUTHORITY_OPERATIONS
        or type(first_fault.get("request_flushed")) is not bool
        or type(first_fault.get("mutation_uncertain")) is not bool
        or first_fault.get("reason") not in AUTHORITY_TRANSPORT_REASONS
        or (
            first_fault.get("operation") == "read" and first_fault.get("mutation_uncertain") is True
        )
        or (
            first_fault.get("reason")
            in {"helper_start", "helper_start_deadline", "helper_start_in_progress"}
            and (
                first_fault.get("request_flushed") is True
                or first_fault.get("mutation_uncertain") is True
            )
        )
    ):
        return False
    else:
        for field_name, positive in (("helper_pid", True), ("helper_exit_code", False)):
            item = first_fault.get(field_name)
            minimum = 1 if positive else -(1 << 31)
            if item is not None and (type(item) is not int or not minimum <= item <= (1 << 31) - 1):
                return False
    if not terminal:
        return True
    return bool(
        state == "healthy"
        and unresolved == 0
        and counters["permanent_faults"] == 0
        and counters["transport_faults"] == counters["transport_fault_episodes"]
        and counters["transport_fault_episodes"] == counters["transport_recovery_attempts"]
        and counters["transport_recovery_attempts"] == counters["transport_recoveries"]
    )


def _valid_executor_authority_status(
    value: object,
    *,
    terminal: bool = False,
) -> TypeGuard[dict[str, Any]]:
    return _valid_authority_status(value, terminal=terminal, executor=True)


def _valid_evidence_identifier(value: object) -> TypeGuard[str]:
    return bool(
        isinstance(value, str)
        and value
        and len(value) <= 512
        and value == value.strip()
        and not any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    )


def _valid_canonical_digest(value: object) -> TypeGuard[str]:
    if (
        not isinstance(value, str)
        or len(value) != 43
        or re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is None
    ):
        return False
    try:
        decoded = base64.urlsafe_b64decode(value + "=")
    except (ValueError, TypeError):
        return False
    return bool(
        len(decoded) == 32
        and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value
    )


def _valid_executor_authority_checkpoint(value: object) -> TypeGuard[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != EXECUTOR_AUTHORITY_CHECKPOINT_FIELDS:
        return False
    clock_floor = value.get("clock_floor_ns")
    if clock_floor is not None and (
        type(clock_floor) is not int or not 0 <= clock_floor <= AUTHORITY_COUNTER_MAX
    ):
        return False
    return not (
        value.get("format") != EXECUTOR_AUTHORITY_CHECKPOINT_FORMAT
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != EXECUTOR_AUTHORITY_SCHEMA_VERSION
        or value.get("audience") != "production-soak-executor"
        or value.get("tenant_id") != "production-acceptance-tenant"
        or value.get("envelope_id") != "production-acceptance-envelope"
        or value.get("config_epoch") != 1
        or not all(
            _valid_evidence_identifier(value.get(field_name))
            for field_name in ("audience", "tenant_id", "envelope_id")
        )
        or type(value.get("config_epoch")) is not int
        or not 1 <= value["config_epoch"] <= AUTHORITY_COUNTER_MAX
        or type(value.get("claim_sequence")) is not int
        or not 0 <= value["claim_sequence"] <= AUTHORITY_COUNTER_MAX
        or not all(
            _valid_canonical_digest(value.get(field_name))
            for field_name in (
                "executor_policy_sha256",
                "trust_registry_sha256",
                "database_instance_id",
                "claim_digest",
            )
        )
        or (value.get("claim_sequence") == 0 and value.get("claim_digest") != "A" * 43)
    )


def _executor_checkpoint_stable_identity(value: dict[str, Any]) -> tuple[object, ...]:
    return tuple(
        value[field_name]
        for field_name in (
            "audience",
            "tenant_id",
            "envelope_id",
            "config_epoch",
            "executor_policy_sha256",
            "trust_registry_sha256",
            "schema_version",
            "database_instance_id",
        )
    )


def evaluate_restart_evidence(
    restarts: object,
    *,
    workload_started_monotonic: float,
) -> dict[str, Any]:
    """Bind each cadence exclusion to one exact host-executed planned restart."""

    if not isinstance(restarts, list) or not _finite_number(workload_started_monotonic):
        return {"passed": False, "reason": "missing restart evidence"}
    bindings: dict[str, dict[str, Any]] = {}
    windows_by_node: dict[str, list[dict[str, Any]]] = {node: [] for node in WARDENS}
    global_windows: list[dict[str, Any]] = []
    host_intervals: list[tuple[float, float]] = []
    for expected_episode, restart in enumerate(restarts):
        if not isinstance(restart, dict):
            return {"passed": False, "reason": "malformed restart record"}
        service = restart.get("service")
        host_started = restart.get("host_operation_started_monotonic_seconds")
        host_completed = restart.get("host_operation_completed_monotonic_seconds")
        coordination = restart.get("workload_coordination")
        if (
            service not in WARDENS
            or service != WARDENS[expected_episode % len(WARDENS)]
            or not _finite_number(host_started)
            or not _finite_number(host_completed)
            or not float(host_started) < float(host_completed)
            or float(host_completed) - float(host_started) > MAXIMUM_PLANNED_RESTART_SECONDS
            or not isinstance(coordination, dict)
        ):
            return {"passed": False, "reason": "unbounded or malformed host restart"}
        armed = coordination.get("armed")
        completed = coordination.get("completed")
        if not isinstance(armed, dict) or not isinstance(completed, dict):
            return {"passed": False, "reason": "restart coordination is incomplete"}
        armed_marker = armed.get("marker")
        armed_ack = armed.get("acknowledgement")
        completed_marker = completed.get("marker")
        recovery_ack = completed.get("recovery_acknowledgement")
        if not all(
            isinstance(item, dict)
            for item in (armed_marker, armed_ack, completed_marker, recovery_ack)
        ):
            return {"passed": False, "reason": "restart marker lifecycle is incomplete"}
        host_armed_started = armed.get("host_armed_started_monotonic_seconds")
        host_monitor_acknowledged = armed.get("host_monitor_acknowledged_monotonic_seconds")
        host_completed_marker = completed.get("host_completed_marker_monotonic_seconds")
        host_monitor_recovered = completed.get("host_monitor_recovered_monotonic_seconds")
        if not all(
            _finite_number(value)
            for value in (
                host_armed_started,
                host_monitor_acknowledged,
                host_completed_marker,
                host_monitor_recovered,
            )
        ) or not float(cast(int | float, host_armed_started)) <= float(
            cast(int | float, host_monitor_acknowledged)
        ) <= float(host_started) < float(host_completed) <= float(
            cast(int | float, host_completed_marker)
        ) <= float(cast(int | float, host_monitor_recovered)):
            return {"passed": False, "reason": "host restart lifecycle is unbound"}
        typed_armed = cast(dict[str, Any], armed_marker)
        typed_ack = cast(dict[str, Any], armed_ack)
        typed_completed = cast(dict[str, Any], completed_marker)
        typed_recovery = cast(dict[str, Any], recovery_ack)
        restart_id = typed_armed.get("restart_id")
        identity = ("armed_monotonic_seconds", "episode", "restart_id", "service")
        if (
            not isinstance(restart_id, str)
            or not restart_id
            or restart_id in bindings
            or any(
                type(document.get("episode")) is not int
                for document in (typed_armed, typed_ack, typed_completed, typed_recovery)
            )
            or typed_armed.get("episode") != expected_episode
            or typed_armed.get("service") != service
            or typed_armed.get("state") != "armed"
            or typed_armed.get("completed_monotonic_seconds") is not None
            or typed_completed.get("state") != "completed"
            or any(typed_completed.get(key) != typed_armed.get(key) for key in identity)
            or any(typed_ack.get(key) != typed_armed.get(key) for key in identity)
            or any(typed_recovery.get(key) != typed_armed.get(key) for key in identity)
        ):
            return {"passed": False, "reason": "restart marker identity is inconsistent"}
        acknowledged = typed_ack.get("acknowledged_monotonic_seconds")
        completed_at = typed_completed.get("completed_monotonic_seconds")
        recovered = typed_recovery.get("recovered_monotonic_seconds")
        if (
            not _finite_number(typed_armed.get("armed_monotonic_seconds"))
            or not _finite_number(acknowledged)
            or not _finite_number(completed_at)
            or not _finite_number(recovered)
            or typed_recovery.get("acknowledged_monotonic_seconds") != acknowledged
            or typed_recovery.get("completed_monotonic_seconds") != completed_at
            or not float(typed_armed["armed_monotonic_seconds"])
            <= float(acknowledged)
            <= float(completed_at)
            <= float(recovered)
            or float(completed_at) - float(acknowledged) > MAXIMUM_PLANNED_RESTART_SECONDS
            or float(recovered) - float(completed_at) > HEALTH_CADENCE_LIMIT_SECONDS
        ):
            return {"passed": False, "reason": "restart acknowledgement timing is invalid"}
        authority_fence = restart.get("authority_fence")
        fence_result = authority_fence.get("result") if isinstance(authority_fence, dict) else None
        fence_terminal = fence_result.get("terminal") if isinstance(fence_result, dict) else None
        terminal_authority = (
            fence_terminal.get("authority_anchor") if isinstance(fence_terminal, dict) else None
        )
        prior_authority = typed_ack.get("prior_authority_anchor")
        new_authority = restart.get("new_authority_anchor")
        recovered_authority = typed_recovery.get("recovered_authority_anchor")
        expected_recovered = typed_completed.get("expected_recovered_authority_identity")
        if (
            not _valid_authority_status(prior_authority, fenced=False, terminal=True)
            or not isinstance(authority_fence, dict)
            or authority_fence.get("prior_authority_anchor") != prior_authority
            or authority_fence.get("host_container_id") != restart.get("prior_container_id")
            or authority_fence.get("host_pid") != restart.get("prior_pid")
            or not isinstance(fence_terminal, dict)
            or fence_terminal.get("restart_id") != restart_id
            or fence_terminal.get("warden_id") != service
            or not _valid_authority_status(terminal_authority, fenced=True, terminal=True)
            or terminal_authority.get("lifetime_id") != prior_authority.get("lifetime_id")
            or terminal_authority.get("namespace_process_id")
            != prior_authority.get("namespace_process_id")
            or any(
                terminal_authority[field_name] < prior_authority[field_name]
                for field_name in AUTHORITY_COUNTER_FIELDS
            )
            or (
                prior_authority.get("first_fault") is not None
                and terminal_authority.get("first_fault") != prior_authority.get("first_fault")
            )
            or not _valid_authority_status(new_authority, fenced=False, terminal=True)
            or recovered_authority != new_authority
            or expected_recovered
            != {
                "lifetime_id": new_authority.get("lifetime_id"),
                "namespace_process_id": new_authority.get("namespace_process_id"),
            }
            or new_authority.get("lifetime_id") == prior_authority.get("lifetime_id")
            or restart.get("new_container_id") == restart.get("prior_container_id")
            or restart.get("new_pid") == restart.get("prior_pid")
        ):
            return {"passed": False, "reason": "restart authority lifetime binding is invalid"}
        window = {
            "end_elapsed_seconds": float(completed_at) - workload_started_monotonic,
            "episode": expected_episode,
            "restart_id": restart_id,
            "service": service,
            "start_elapsed_seconds": float(acknowledged) - workload_started_monotonic,
        }
        if (
            window["start_elapsed_seconds"] < 0
            or float(typed_armed["armed_monotonic_seconds"]) < workload_started_monotonic
            or window["end_elapsed_seconds"] < window["start_elapsed_seconds"]
        ):
            return {"passed": False, "reason": "restart window predates the workload"}
        bindings[restart_id] = {
            **window,
            "armed_marker": typed_armed,
            "completed_marker": typed_completed,
        }
        windows_by_node[cast(str, service)].append(window)
        global_windows.append(window)
        host_intervals.append((float(host_started), float(host_completed)))
    for windows in windows_by_node.values():
        windows.sort(key=lambda item: float(item["start_elapsed_seconds"]))
        if any(
            float(right["start_elapsed_seconds"]) < float(left["end_elapsed_seconds"])
            for left, right in pairwise(windows)
        ):
            return {"passed": False, "reason": "restart windows overlap for one node"}
    global_windows.sort(key=lambda item: float(item["start_elapsed_seconds"]))
    if any(
        float(right["start_elapsed_seconds"]) < float(left["end_elapsed_seconds"])
        for left, right in pairwise(global_windows)
    ):
        return {"passed": False, "reason": "restart windows overlap globally"}
    host_intervals.sort()
    if any(right[0] < left[1] for left, right in pairwise(host_intervals)):
        return {"passed": False, "reason": "host restart operations overlap globally"}
    return {
        "binding_count": len(bindings),
        "bindings": bindings,
        "host_maximum_restart_seconds": max(
            (
                float(item["host_operation_completed_monotonic_seconds"])
                - float(item["host_operation_started_monotonic_seconds"])
                for item in restarts
            ),
            default=0.0,
        ),
        "passed": True,
        "windows_by_node": windows_by_node,
    }


def _maximum_available_gap(
    observations: list[float],
    *,
    duration_seconds: float,
    exclusions: list[dict[str, Any]],
) -> float:
    points = [0.0, *sorted(set(max(0.0, min(duration_seconds, item)) for item in observations))]
    if points[-1] != duration_seconds:
        points.append(duration_seconds)
    maximum = 0.0
    for left, right in pairwise(points):
        cursor = left
        for exclusion in exclusions:
            excluded_start = max(left, float(exclusion["start_elapsed_seconds"]))
            excluded_end = min(right, float(exclusion["end_elapsed_seconds"]))
            if excluded_end <= cursor or excluded_start >= right:
                continue
            maximum = max(maximum, max(0.0, excluded_start - cursor))
            cursor = max(cursor, excluded_end)
        maximum = max(maximum, max(0.0, right - cursor))
    return maximum


def evaluate_health_cadence(
    samples: object,
    *,
    duration_seconds: float,
    interval_seconds: float,
    restart_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Prove real per-node observations cover every non-excluded 15-second window."""

    if (
        not isinstance(samples, list)
        or not samples
        or not _finite_number(duration_seconds)
        or float(duration_seconds) <= 0
        or not _finite_number(interval_seconds)
        or not 0 < float(interval_seconds) <= HEALTH_CADENCE_LIMIT_SECONDS
        or restart_evidence.get("passed") is not True
    ):
        return {"passed": False, "reason": "missing or invalid health cadence inputs"}
    duration = float(duration_seconds)
    interval = float(interval_seconds)
    expected_schedule: list[float] = []
    scheduled = 0.0
    while scheduled < duration:
        expected_schedule.append(scheduled)
        scheduled += interval
    expected_schedule.append(duration)
    if len(samples) != len(expected_schedule):
        return {"passed": False, "reason": "health sample schedule count is incomplete"}
    bindings = restart_evidence.get("bindings")
    windows_by_node = restart_evidence.get("windows_by_node")
    if not isinstance(bindings, dict) or not isinstance(windows_by_node, dict):
        return {"passed": False, "reason": "restart bindings are malformed"}
    observations: dict[str, list[float]] = {node: [] for node in WARDENS}
    unavailable_counts = {node: 0 for node in WARDENS}
    acknowledged_unavailable_restart_ids: set[str] = set()
    prior_started = -math.inf
    prior_completed = -math.inf
    scheduled_samples = zip(samples, expected_schedule, strict=True)
    for index, (sample, expected_scheduled) in enumerate(scheduled_samples):
        if not isinstance(sample, dict):
            return {"passed": False, "reason": "malformed health sample"}
        fields = {
            name: sample.get(name)
            for name in (
                "scheduled_elapsed_seconds",
                "started_elapsed_seconds",
                "completed_elapsed_seconds",
                "deadline_elapsed_seconds",
            )
        }
        if (
            sample.get("schedule_index") != index
            or sample.get("deadline_missed") is not False
            or not all(_finite_number(value) for value in fields.values())
        ):
            return {"passed": False, "reason": "health sample deadline evidence is invalid"}
        scheduled_at = float(cast(int | float, fields["scheduled_elapsed_seconds"]))
        started_at = float(cast(int | float, fields["started_elapsed_seconds"]))
        completed_at = float(cast(int | float, fields["completed_elapsed_seconds"]))
        deadline_at = float(cast(int | float, fields["deadline_elapsed_seconds"]))
        if (
            abs(scheduled_at - expected_scheduled) > 0.002
            or scheduled_at < 0
            or started_at < scheduled_at
            or completed_at < started_at
            or deadline_at < completed_at
            or deadline_at - scheduled_at > HEALTH_CADENCE_LIMIT_SECONDS + 0.002
            or started_at <= prior_started
            or completed_at <= prior_completed
        ):
            return {"passed": False, "reason": "health samples collapsed or missed cadence"}
        prior_started = started_at
        prior_completed = completed_at
        nodes = sample.get("nodes")
        planned_nodes = sample.get("planned_unavailable_nodes")
        if (
            not isinstance(nodes, dict)
            or set(nodes) != set(WARDENS)
            or not isinstance(planned_nodes, list)
            or len(planned_nodes) != len(set(planned_nodes))
            or len(planned_nodes) > 1
            or any(node not in WARDENS for node in planned_nodes)
        ):
            return {"passed": False, "reason": "health sample node set is invalid"}
        if (
            not _finite_number(sample.get("elapsed_seconds"))
            or abs(float(sample["elapsed_seconds"]) - started_at) > 0.001
        ):
            return {"passed": False, "reason": "health sample elapsed origin is inconsistent"}
        actual_planned: list[str] = []
        for node in WARDENS:
            document = nodes[node]
            if not isinstance(document, dict):
                return {"passed": False, "reason": "health node document is malformed"}
            observation = document.get("observation")
            if not isinstance(observation, dict):
                return {"passed": False, "reason": "health node observation is missing"}
            observed_started = observation.get("started_elapsed_seconds")
            observed_metrics = observation.get("metrics_observed_elapsed_seconds")
            observed_completed = observation.get("completed_elapsed_seconds")
            retries = observation.get("request_retries")
            if (
                not _finite_number(observed_started)
                or not _finite_number(observed_completed)
                or float(observed_started) < started_at
                or float(observed_completed) < float(observed_started)
                or float(observed_completed) > completed_at + 0.002
                or isinstance(retries, bool)
                or not isinstance(retries, int)
                or retries < 0
            ):
                return {"passed": False, "reason": "health node timing is invalid"}
            planned = document.get("planned_unavailable")
            if planned is not None:
                if not isinstance(planned, dict) or observed_metrics is not None:
                    return {"passed": False, "reason": "planned unavailability is malformed"}
                restart_id = planned.get("restart_id")
                binding = bindings.get(restart_id)
                expected_marker = (
                    binding.get(f"{planned.get('state')}_marker")
                    if isinstance(binding, dict)
                    else None
                )
                if (
                    not isinstance(binding, dict)
                    or binding.get("service") != node
                    or binding.get("episode") != planned.get("episode")
                    or planned.get("service") != node
                    or planned != expected_marker
                    or float(observed_completed)
                    < float(binding.get("start_elapsed_seconds", math.inf))
                    or float(observed_started)
                    > float(binding.get("end_elapsed_seconds", -math.inf))
                    or (
                        planned.get("state") == "completed"
                        and float(binding.get("end_elapsed_seconds", math.inf))
                        > float(observed_completed) + 0.002
                    )
                ):
                    return {"passed": False, "reason": "unavailable node lacks an exact restart"}
                actual_planned.append(node)
                unavailable_counts[node] += 1
                if planned.get("state") == "armed" and (
                    float(observed_started)
                    <= float(binding["start_elapsed_seconds"])
                    <= float(observed_completed)
                ):
                    acknowledged_unavailable_restart_ids.add(cast(str, restart_id))
                continue
            exporter = document.get("audit_exporter")
            if (
                not isinstance(exporter, dict)
                or not _finite_number(exporter.get("max_stall_s"))
                or float(exporter["max_stall_s"]) != HEALTH_CADENCE_LIMIT_SECONDS
                or not _finite_number(observed_metrics)
                or not float(observed_started)
                <= float(observed_metrics)
                <= float(observed_completed)
            ):
                return {"passed": False, "reason": "health node observation is not live"}
            observations[node].append(float(observed_metrics))
        if sorted(actual_planned) != sorted(cast(list[str], planned_nodes)):
            return {"passed": False, "reason": "planned-unavailable node list is inconsistent"}
    if acknowledged_unavailable_restart_ids != set(bindings):
        return {
            "passed": False,
            "reason": "restart acknowledgement lacks an interrupted health observation",
        }
    maximum_gaps: dict[str, float] = {}
    for node in WARDENS:
        node_windows = windows_by_node.get(node)
        if not isinstance(node_windows, list) or not observations[node]:
            return {"passed": False, "reason": f"{node} lacks cadence evidence"}
        maximum_gaps[node] = _maximum_available_gap(
            observations[node],
            duration_seconds=duration,
            exclusions=cast(list[dict[str, Any]], node_windows),
        )
    maximum_gap = max(maximum_gaps.values(), default=math.inf)
    return {
        "expected_sample_count": len(expected_schedule),
        "maximum_allowed_gap_seconds": HEALTH_CADENCE_LIMIT_SECONDS,
        "maximum_gap_by_node_seconds": {
            node: round(value, 6) for node, value in maximum_gaps.items()
        },
        "maximum_gap_seconds": round(maximum_gap, 6),
        "passed": maximum_gap <= HEALTH_CADENCE_LIMIT_SECONDS + 0.002,
        "planned_unavailable_samples_by_node": unavailable_counts,
        "sample_count": len(samples),
        "strictly_increasing": True,
    }


def evaluate_pause_evidence(
    result: dict[str, Any],
    *,
    configuration: SoakConfiguration,
    partitions: object,
    workload_start: object,
) -> dict[str, Any]:
    """Cross-bind workload pause records to conservative host-authorized intervals."""

    pause_intervals = result.get("pause_intervals")
    if not isinstance(pause_intervals, list) or not isinstance(partitions, list):
        return {"passed": False, "reason": "pause or partition evidence is missing"}
    if (
        result.get("pause_interval_count") != len(pause_intervals)
        or len(pause_intervals) != len(partitions)
        or not _finite_number(result.get("measurement_window_seconds"))
        or abs(float(result["measurement_window_seconds"]) - configuration.duration_seconds) > 0.002
    ):
        return {"passed": False, "reason": "pause counts or measurement window disagree"}
    workload_paused = 0.0
    authorized_paused = 0.0
    prior_workload_end = -math.inf
    prior_host_end = -math.inf
    workload_started = result.get("started_monotonic_seconds")
    if (
        not isinstance(workload_start, dict)
        or workload_start.get("run_id") != result.get("run_id")
        or workload_start.get("started_monotonic_seconds") != workload_started
        or workload_start.get("duration_seconds") != configuration.duration_seconds
        or workload_start.get("schema") != "lets.production-profile-soak-workload-start/v1"
        or workload_start.get("seed") != configuration.seed
        or workload_start.get("cycle_interval_seconds") != configuration.cycle_interval_seconds
        or workload_start.get("health_interval_seconds") != configuration.health_interval_seconds
        or workload_start.get("retry_timeout_seconds") != configuration.retry_timeout_seconds
        or workload_start.get("transfer_every_cycles") != configuration.transfer_every_cycles
        or workload_start.get("executor_reopen_every_cycles")
        != configuration.executor_reopen_every_cycles
        or not _finite_number(workload_started)
    ):
        return {"passed": False, "reason": "workload monotonic origin is missing"}
    seen_pause_ids: set[str] = set()
    bindings: list[dict[str, Any]] = []
    for expected_episode, (pause, partition) in enumerate(
        zip(pause_intervals, partitions, strict=True)
    ):
        if not isinstance(pause, dict) or not isinstance(partition, dict):
            return {"passed": False, "reason": "pause binding is malformed"}
        coordination = partition.get("workload_coordination")
        if not isinstance(coordination, dict):
            return {"passed": False, "reason": "partition lacks workload coordination"}
        marker = coordination.get("marker")
        acknowledgement = coordination.get("acknowledgement")
        authorized_start = coordination.get("authorized_start")
        authorized_end = coordination.get("authorized_end")
        if not all(
            isinstance(item, dict)
            for item in (marker, acknowledgement, authorized_start, authorized_end)
        ):
            return {"passed": False, "reason": "partition pause token is incomplete"}
        typed_marker = cast(dict[str, Any], marker)
        typed_ack = cast(dict[str, Any], acknowledgement)
        typed_start = cast(dict[str, Any], authorized_start)
        typed_end = cast(dict[str, Any], authorized_end)
        identity_matches = bool(
            pause.get("episode") == expected_episode == partition.get("episode")
            and typed_marker.get("episode") == expected_episode
            and typed_ack.get("episode") == expected_episode
            and typed_start.get("episode") == expected_episode
            and pause.get("pause_id")
            == typed_marker.get("pause_id")
            == typed_ack.get("pause_id")
            == typed_start.get("pause_id")
            == typed_end.get("pause_id")
            and pause.get("requested_monotonic_seconds")
            == typed_marker.get("requested_monotonic_seconds")
            == typed_ack.get("requested_monotonic_seconds")
            == typed_start.get("requested_monotonic_seconds")
            == typed_end.get("requested_monotonic_seconds")
            == coordination.get("requested_monotonic_seconds")
            and coordination.get("episode") == expected_episode
            and typed_end.get("episode") == expected_episode
            and coordination.get("pause_id") == pause.get("pause_id")
            and pause.get("observed_monotonic_seconds")
            == typed_ack.get("observed_monotonic_seconds")
            and typed_ack.get("paused") is True
        )
        numeric_fields = (
            typed_marker.get("requested_monotonic_seconds"),
            typed_start.get("authorized_start_monotonic_seconds"),
            typed_start.get("host_boundary_started_monotonic_seconds"),
            typed_start.get("host_boundary_completed_monotonic_seconds"),
            typed_end.get("authorized_end_monotonic_seconds"),
            pause.get("observed_monotonic_seconds"),
            pause.get("resumed_monotonic_seconds"),
            pause.get("observed_elapsed_seconds"),
            pause.get("resumed_elapsed_seconds"),
            pause.get("duration_seconds"),
            pause.get("measurement_clipped_duration_seconds"),
            coordination.get("host_acknowledged_monotonic_seconds"),
            coordination.get("host_request_started_monotonic_seconds"),
            coordination.get("host_resume_started_monotonic_seconds"),
            coordination.get("host_resume_completed_monotonic_seconds"),
            typed_end.get("host_boundary_started_monotonic_seconds"),
            typed_end.get("host_boundary_completed_monotonic_seconds"),
            coordination.get("workload_resume_requested_monotonic_seconds"),
            coordination.get("host_pause_duration_seconds"),
            partition.get("disabled_monotonic_seconds"),
            partition.get("restored_monotonic_seconds"),
        )
        if not identity_matches or not all(_finite_number(value) for value in numeric_fields):
            return {"passed": False, "reason": "pause token or timing is invalid"}
        observed = float(pause["observed_monotonic_seconds"])
        resumed = float(pause["resumed_monotonic_seconds"])
        observed_elapsed = float(pause["observed_elapsed_seconds"])
        resumed_elapsed = float(pause["resumed_elapsed_seconds"])
        recomputed_clipped = max(
            0.0,
            min(configuration.duration_seconds, resumed_elapsed)
            - max(0.0, min(configuration.duration_seconds, observed_elapsed)),
        )
        clipped = float(pause["measurement_clipped_duration_seconds"])
        host_acknowledged = float(coordination["host_acknowledged_monotonic_seconds"])
        host_resume_started = float(coordination["host_resume_started_monotonic_seconds"])
        host_resume_completed = float(coordination["host_resume_completed_monotonic_seconds"])
        workload_resume_requested = float(
            coordination["workload_resume_requested_monotonic_seconds"]
        )
        workload_authorized_start = float(typed_start["authorized_start_monotonic_seconds"])
        workload_authorized_end = float(typed_end["authorized_end_monotonic_seconds"])
        host_boundary_started = float(typed_end["host_boundary_started_monotonic_seconds"])
        host_boundary_completed = float(typed_end["host_boundary_completed_monotonic_seconds"])
        host_start_boundary_started = float(typed_start["host_boundary_started_monotonic_seconds"])
        host_start_boundary_completed = float(
            typed_start["host_boundary_completed_monotonic_seconds"]
        )
        host_request_started = float(coordination["host_request_started_monotonic_seconds"])
        disabled = float(partition["disabled_monotonic_seconds"])
        restored = float(partition["restored_monotonic_seconds"])
        host_duration = host_resume_started - host_acknowledged
        if (
            not isinstance(pause.get("pause_id"), str)
            or not pause["pause_id"]
            or pause["pause_id"] in seen_pause_ids
            or observed < prior_workload_end
            or resumed < observed
            or abs(observed_elapsed - (observed - float(workload_started))) > 0.002
            or abs(resumed_elapsed - (resumed - float(workload_started))) > 0.002
            or not float(typed_marker["requested_monotonic_seconds"]) >= float(workload_started)
            or not float(typed_marker["requested_monotonic_seconds"])
            <= observed
            <= workload_authorized_start
            <= workload_authorized_end
            <= workload_resume_requested
            <= resumed
            or abs(float(pause["duration_seconds"]) - (resumed - observed)) > 0.002
            or abs(clipped - recomputed_clipped) > 0.002
            or not 0 <= clipped <= resumed - observed + 0.002
            or host_acknowledged < prior_host_end
            or not host_request_started
            <= host_acknowledged
            <= host_start_boundary_started
            <= host_start_boundary_completed
            <= disabled
            <= restored
            <= host_boundary_started
            <= host_boundary_completed
            <= host_resume_started
            <= host_resume_completed
            or abs(float(coordination["host_pause_duration_seconds"]) - host_duration) > 0.002
        ):
            return {"passed": False, "reason": "pause intervals overlap or lack containment"}
        seen_pause_ids.add(cast(str, pause["pause_id"]))
        authorized_container_clipped = max(
            0.0,
            min(
                float(workload_started) + configuration.duration_seconds,
                workload_authorized_end,
            )
            - max(float(workload_started), workload_authorized_start),
        )
        authorized = min(authorized_container_clipped, host_duration)
        workload_paused += clipped
        authorized_paused += authorized
        prior_workload_end = resumed
        prior_host_end = host_resume_started
        bindings.append(
            {
                "authorized_pause_seconds": round(authorized, 6),
                "episode": expected_episode,
                "host_pause_seconds": round(host_duration, 6),
                "pause_id": pause["pause_id"],
                "workload_authorized_clipped_pause_seconds": round(
                    authorized_container_clipped,
                    6,
                ),
                "workload_clipped_pause_seconds": round(clipped, 6),
            }
        )
    reported_paused = result.get("paused_workload_seconds")
    reported_active = result.get("active_workload_seconds")
    active_seconds = configuration.duration_seconds - authorized_paused
    if (
        not _finite_number(reported_paused)
        or not _finite_number(reported_active)
        or abs(float(reported_paused) - workload_paused) > 0.002
        or abs(float(reported_active) - (configuration.duration_seconds - workload_paused)) > 0.002
        or active_seconds < 0
    ):
        return {"passed": False, "reason": "reported active-time arithmetic is forged"}
    return {
        "active_workload_seconds": round(active_seconds, 6),
        "authorized_paused_seconds": round(authorized_paused, 6),
        "bindings": bindings,
        "passed": True,
        "workload_reported_paused_seconds": round(workload_paused, 6),
    }


def evaluate_authority_evidence(
    workload: object,
    restarts: object,
    verification: object,
) -> dict[str, Any]:
    """Reconstruct every terminal authority lifetime and the global fault budget."""

    def failed(reason: str) -> dict[str, Any]:
        return {"passed": False, "reason": reason}

    if (
        not isinstance(workload, dict)
        or not isinstance(restarts, list)
        or not isinstance(verification, dict)
    ):
        return failed("authority evidence roots are missing")
    terminal_capture = verification.get("terminal_capture")
    if (
        verification.get("schema") != "lets.production-profile-soak-verification/v1"
        or verification.get("status") != "passed"
        or not isinstance(terminal_capture, dict)
        or set(terminal_capture)
        != {
            "completed_monotonic_seconds",
            "deadline_monotonic_seconds",
            "started_monotonic_seconds",
        }
        or not all(_finite_number(value) for value in terminal_capture.values())
    ):
        return failed("terminal authority capture envelope is malformed")
    capture_started = float(terminal_capture["started_monotonic_seconds"])
    capture_completed = float(terminal_capture["completed_monotonic_seconds"])
    capture_deadline = float(terminal_capture["deadline_monotonic_seconds"])
    if (
        not capture_started <= capture_completed <= capture_deadline
        or abs((capture_deadline - capture_started) - 90.0) > 0.002
    ):
        return failed("terminal authority capture deadline is invalid")
    counters = workload.get("counters")
    executor = workload.get("executor")
    cycles = workload.get("cycles")
    if (
        not isinstance(counters, dict)
        or not isinstance(executor, dict)
        or type(cycles) is not int
        or cycles < 0
    ):
        return failed("executor authority workload evidence is malformed")
    if (
        set(counters)
        != {
            "authorizations",
            "closed",
            "executor_failed_closed",
            "executor_faulting_calls",
            "issued_receipts",
            "issued_roots",
            "quiesced",
            "renewed",
            "resumed",
            "transfers_prepared",
        }
        or any(type(value) is not int or value < 0 for value in counters.values())
        or set(executor)
        != {
            "claims",
            "reopen_count",
            "replay_rejections",
            "status",
            "terminal_statuses",
            "transport_recovery_events",
        }
        or any(
            type(executor.get(field_name)) is not int or executor[field_name] < 0
            for field_name in ("claims", "reopen_count", "replay_rejections")
        )
    ):
        return failed("executor authority workload numeric schema is malformed")
    issued = 2 * cycles
    recovery_events = executor.get("transport_recovery_events")
    workload_terminals = executor.get("terminal_statuses")
    verification_executor = verification.get("executor")
    if (
        not isinstance(recovery_events, list)
        or len(recovery_events) != 1
        or not isinstance(workload_terminals, list)
        or not isinstance(verification_executor, dict)
    ):
        return failed("executor recovery or terminal evidence is incomplete")
    expected_reopens = executor.get("reopen_count")
    workload_configuration = workload.get("configuration")
    reopen_every = (
        workload_configuration.get("executor_reopen_every_cycles")
        if isinstance(workload_configuration, dict)
        else None
    )
    if (
        type(expected_reopens) is not int
        or expected_reopens < 0
        or type(reopen_every) is not int
        or reopen_every <= 0
        or expected_reopens != cycles // reopen_every
        or len(workload_terminals) != expected_reopens + 1
    ):
        return failed("executor workload lifetime count is inconsistent")
    event = recovery_events[0]
    original_error = event.get("original_transport_error") if isinstance(event, dict) else None
    faulted = event.get("faulted_authority_anchor") if isinstance(event, dict) else None
    recovered = event.get("recovered_authority_anchor") if isinstance(event, dict) else None
    if (
        not isinstance(event, dict)
        or set(event)
        != {
            "durable_claim_outcome",
            "faulted_authority_anchor",
            "faulting_call_effect_executed",
            "ordinal",
            "original_call_raised",
            "original_transport_error",
            "phase",
            "primary_returned",
            "protected_effect_executed_after_recovery",
            "receipt_id",
            "recovered_authority_anchor",
            "retry_outcome",
        }
        or type(event.get("ordinal")) is not int
        or event.get("ordinal") != 0
        or event.get("original_call_raised") is not True
        or event.get("phase") != "primary_claim"
        or event.get("primary_returned") is not False
        or event.get("durable_claim_outcome") != "burned_before_response"
        or event.get("retry_outcome") != "replay_rejected"
        or event.get("faulting_call_effect_executed") is not False
        or event.get("protected_effect_executed_after_recovery") is not False
        or not _valid_evidence_identifier(event.get("receipt_id"))
        or not isinstance(original_error, dict)
        or set(original_error)
        != {
            "helper_exit_code",
            "helper_pid",
            "mutation_uncertain",
            "operation",
            "reason",
            "request_flushed",
        }
        or original_error.get("reason") != "helper_eof"
        or original_error.get("operation") != "compare-and-set"
        or original_error.get("request_flushed") is not True
        or original_error.get("mutation_uncertain") is not True
        or not _valid_executor_authority_status(faulted)
        or faulted.get("state") != "recoverable_transport_fault"
        or faulted.get("fault_stage") != "post_commit"
        or faulted.get("fault_reason") != original_error.get("reason")
        or faulted.get("first_fault") != {**original_error, "stage": "post_commit"}
        or tuple(
            faulted.get(field_name)
            for field_name in (
                "transport_faults",
                "transport_fault_episodes",
                "transport_recovery_attempts",
                "transport_recoveries",
                "unresolved_transport_faults",
                "permanent_faults",
            )
        )
        != (1, 1, 0, 0, 1, 0)
        or not _valid_executor_authority_status(recovered, terminal=True)
        or recovered.get("lifetime_id") != faulted.get("lifetime_id")
        or recovered.get("first_fault") != faulted.get("first_fault")
        or any(
            recovered.get(field_name) != 1
            for field_name in (
                "transport_faults",
                "transport_fault_episodes",
                "transport_recovery_attempts",
                "transport_recoveries",
            )
        )
    ):
        return failed("executor post-COMMIT recovery event is not exact")
    if (
        counters.get("issued_receipts") != issued
        or counters.get("executor_faulting_calls") != 1
        or counters.get("executor_failed_closed") != 1
        or counters.get("authorizations") != issued - 1
        or executor.get("claims") != issued
        or executor.get("replay_rejections") != issued + expected_reopens
        or not isinstance(executor.get("status"), dict)
        or executor["status"].get("claim_sequence") != issued
    ):
        return failed("executor durable-claim and protected-effect accounting is inconsistent")

    final_executor_terminal = verification_executor.get("terminal_status")
    verification_executor_fields = {
        "anchor_claim_sequence",
        "authority_anchor",
        "authority_healthy",
        "claim_sequence",
        "database_bytes",
        "integrity",
        "rollback_protected",
        "terminal_status",
        "wal_bytes",
    }
    if (
        set(verification_executor) != verification_executor_fields
        or not isinstance(final_executor_terminal, dict)
        or verification_executor.get("authority_healthy") is not True
        or verification_executor.get("rollback_protected") is not True
        or verification_executor.get("integrity") != ["ok"]
        or type(verification_executor.get("anchor_claim_sequence")) is not int
        or verification_executor["anchor_claim_sequence"] < 0
        or type(verification_executor.get("claim_sequence")) is not int
        or verification_executor["claim_sequence"] < 0
        or type(verification_executor.get("database_bytes")) is not int
        or verification_executor["database_bytes"] < 0
        or type(verification_executor.get("wal_bytes")) is not int
        or verification_executor["wal_bytes"] < 0
    ):
        return failed("final executor authority lifetime is missing")
    all_executor_terminals = [*workload_terminals, final_executor_terminal]
    executor_status_fields = {
        "anchor",
        "authority_anchor",
        "authority_healthy",
        "claim_sequence",
        "database_bytes",
        "integrity",
        "live_claims",
        "live_watermarks",
        "rollback_protected",
        "shared_memory_bytes",
        "wal_bytes",
    }
    executor_lifetimes: set[str] = set()
    prior_claim_sequence = -1
    prior_checkpoint: dict[str, Any] | None = None
    checkpoint_stable_identity: tuple[object, ...] | None = None
    terminal_statuses: list[dict[str, Any]] = []
    for ordinal, terminal in enumerate(all_executor_terminals):
        status = terminal.get("status") if isinstance(terminal, dict) else None
        authority = status.get("authority_anchor") if isinstance(status, dict) else None
        claim_sequence = status.get("claim_sequence") if isinstance(status, dict) else None
        checkpoint = status.get("anchor") if isinstance(status, dict) else None
        lifetime = terminal.get("lifetime_id") if isinstance(terminal, dict) else None
        expected_source = "workload" if ordinal < len(workload_terminals) else "final_verification"
        expected_claim_sequence = (
            2 * reopen_every * (ordinal + 1) if ordinal < expected_reopens else issued
        )
        if (
            not isinstance(terminal, dict)
            or set(terminal) != {"lifetime_id", "ordinal", "source", "status"}
            or type(terminal.get("ordinal")) is not int
            or terminal.get("ordinal") != ordinal
            or terminal.get("source") != expected_source
            or not isinstance(status, dict)
            or set(status) != executor_status_fields
            or not _valid_executor_authority_status(authority, terminal=True)
            or terminal.get("lifetime_id") != authority.get("lifetime_id")
            or not isinstance(lifetime, str)
            or lifetime in executor_lifetimes
            or type(claim_sequence) is not int
            or claim_sequence != expected_claim_sequence
            or claim_sequence < prior_claim_sequence
            or status.get("rollback_protected") is not True
            or status.get("authority_healthy") is not True
            or status.get("integrity") != ["ok"]
            or any(
                type(status.get(field_name)) is not int or status[field_name] < 0
                for field_name in (
                    "database_bytes",
                    "live_claims",
                    "live_watermarks",
                    "shared_memory_bytes",
                    "wal_bytes",
                )
            )
            or status["live_claims"] > claim_sequence
            or status["live_watermarks"] > claim_sequence
            or not _valid_executor_authority_checkpoint(checkpoint)
            or checkpoint.get("claim_sequence") != claim_sequence
            or (
                checkpoint_stable_identity is not None
                and _executor_checkpoint_stable_identity(checkpoint) != checkpoint_stable_identity
            )
            or (
                prior_checkpoint is not None
                and checkpoint["claim_sequence"] == prior_checkpoint["claim_sequence"]
                and checkpoint["claim_digest"] != prior_checkpoint["claim_digest"]
            )
            or (
                prior_checkpoint is not None
                and prior_checkpoint["clock_floor_ns"] is not None
                and (
                    checkpoint["clock_floor_ns"] is None
                    or checkpoint["clock_floor_ns"] < prior_checkpoint["clock_floor_ns"]
                )
            )
        ):
            return failed("executor terminal lifetime chain is invalid")
        if checkpoint_stable_identity is None:
            checkpoint_stable_identity = _executor_checkpoint_stable_identity(checkpoint)
        executor_lifetimes.add(lifetime)
        prior_claim_sequence = claim_sequence
        prior_checkpoint = checkpoint
        terminal_statuses.append(authority)
    if not any(
        terminal.get("lifetime_id") == recovered.get("lifetime_id")
        and terminal.get("status", {}).get("authority_anchor") == recovered
        for terminal in workload_terminals
        if isinstance(terminal, dict)
    ):
        return failed("recovered executor lifetime lacks an exact terminal status")
    if (
        workload_terminals[-1].get("status") != executor.get("status")
        or not isinstance(final_executor_terminal.get("status"), dict)
        or final_executor_terminal["status"].get("authority_anchor")
        != verification_executor.get("authority_anchor")
        or final_executor_terminal["status"].get("claim_sequence")
        != verification_executor.get("claim_sequence")
        or final_executor_terminal["status"].get("integrity")
        != verification_executor.get("integrity")
        or final_executor_terminal["status"].get("authority_healthy")
        != verification_executor.get("authority_healthy")
        or final_executor_terminal["status"].get("rollback_protected")
        != verification_executor.get("rollback_protected")
        or final_executor_terminal["status"].get("database_bytes")
        != verification_executor.get("database_bytes")
        or final_executor_terminal["status"].get("wal_bytes")
        != verification_executor.get("wal_bytes")
        or final_executor_terminal["status"].get("anchor")
        != workload_terminals[-1].get("status", {}).get("anchor")
        or verification_executor.get("anchor_claim_sequence") != issued
        or prior_claim_sequence != issued
    ):
        return failed("executor final lifetime is not bound to the workload head")

    core_terminal_fences = verification.get("terminal_authority_fences")
    if not isinstance(core_terminal_fences, dict) or set(core_terminal_fences) != set(WARDENS):
        return failed("final core terminal fences are incomplete")
    core_lifetimes: set[str] = set()
    core_terminal_by_lifetime: dict[str, dict[str, Any]] = {}
    core_recovery_baselines: dict[str, dict[str, Any]] = {}
    planned_pairs: dict[str, list[tuple[str, str]]] = {node: [] for node in WARDENS}
    authority_fence_fields = {
        "host_container_id",
        "host_exec_attempts",
        "host_pid",
        "prior_authority_anchor",
        "result",
    }
    authority_fence_result_fields = {
        "node",
        "request_retry_count",
        "schema",
        "status",
        "terminal",
    }
    authority_fence_terminal_fields = {
        "authority_anchor",
        "fenced_at_monotonic_ns",
        "lifetime_id",
        "namespace_process_id",
        "restart_id",
        "schema",
        "warden_id",
    }
    for restart in restarts:
        if not isinstance(restart, dict):
            return failed("planned restart authority evidence is malformed")
        service = restart.get("service")
        fence = restart.get("authority_fence")
        prior_authority = fence.get("prior_authority_anchor") if isinstance(fence, dict) else None
        result = fence.get("result") if isinstance(fence, dict) else None
        terminal = result.get("terminal") if isinstance(result, dict) else None
        authority = terminal.get("authority_anchor") if isinstance(terminal, dict) else None
        new_authority = restart.get("new_authority_anchor")
        coordination = restart.get("workload_coordination")
        armed = coordination.get("armed") if isinstance(coordination, dict) else None
        marker = armed.get("marker") if isinstance(armed, dict) else None
        armed_ack = armed.get("acknowledgement") if isinstance(armed, dict) else None
        completed = coordination.get("completed") if isinstance(coordination, dict) else None
        recovery_ack = (
            completed.get("recovery_acknowledgement") if isinstance(completed, dict) else None
        )
        if (
            service not in WARDENS
            or restart.get("signal") != "SIGKILL"
            or restart.get("planned_exit_code") != 137
            or not isinstance(fence, dict)
            or set(fence) != authority_fence_fields
            or type(fence.get("host_exec_attempts")) is not int
            or fence["host_exec_attempts"] < 1
            or not isinstance(marker, dict)
            or not isinstance(armed_ack, dict)
            or not isinstance(result, dict)
            or set(result) != authority_fence_result_fields
            or type(result.get("request_retry_count")) is not int
            or result["request_retry_count"] < 0
            or result.get("schema") != "lets.production-profile-authority-fence/v1"
            or result.get("status") != "passed"
            or result.get("node") != service
            or not isinstance(terminal, dict)
            or set(terminal) != authority_fence_terminal_fields
            or type(terminal.get("namespace_process_id")) is not int
            or terminal["namespace_process_id"] <= 0
            or type(terminal.get("fenced_at_monotonic_ns")) is not int
            or terminal["fenced_at_monotonic_ns"] < 0
            or terminal.get("schema") != "lets.authority-admission-fence/v1"
            or terminal.get("restart_id") != marker.get("restart_id")
            or terminal.get("warden_id") != service
            or not _valid_authority_status(authority, fenced=True, terminal=True)
            or terminal.get("lifetime_id") != authority.get("lifetime_id")
            or terminal.get("namespace_process_id") != authority.get("namespace_process_id")
            or terminal.get("fenced_at_monotonic_ns") != authority.get("fenced_at_monotonic_ns")
            or authority.get("fence_id") != marker.get("restart_id")
            or not _valid_authority_status(new_authority, fenced=False, terminal=True)
            or authority.get("lifetime_id") == new_authority.get("lifetime_id")
            or not isinstance(recovery_ack, dict)
            or recovery_ack.get("recovered_authority_anchor") != new_authority
            or fence.get("host_container_id") != restart.get("prior_container_id")
            or fence.get("host_pid") != restart.get("prior_pid")
            or not _valid_authority_status(prior_authority, fenced=False, terminal=True)
            or prior_authority != armed_ack.get("prior_authority_anchor")
            or authority.get("lifetime_id") != prior_authority.get("lifetime_id")
            or authority.get("namespace_process_id") != prior_authority.get("namespace_process_id")
            or any(
                authority[field_name] < prior_authority[field_name]
                for field_name in AUTHORITY_COUNTER_FIELDS
            )
            or (
                prior_authority.get("first_fault") is not None
                and authority.get("first_fault") != prior_authority.get("first_fault")
            )
        ):
            return failed("planned restart is not bound to exact authority lifetimes")
        old_lifetime = cast(str, authority["lifetime_id"])
        new_lifetime = cast(str, new_authority["lifetime_id"])
        if old_lifetime in core_lifetimes:
            return failed("core terminal authority lifetime was repeated")
        if old_lifetime in executor_lifetimes:
            return failed("authority lifetime identity was reused across stores")
        core_lifetimes.add(old_lifetime)
        core_terminal_by_lifetime[old_lifetime] = authority
        terminal_statuses.append(authority)
        planned_pairs[cast(str, service)].append((old_lifetime, new_lifetime))
        if new_lifetime in core_recovery_baselines:
            return failed("replacement authority lifetime was reused")
        core_recovery_baselines[new_lifetime] = new_authority
    final_core_authorities: dict[str, dict[str, Any]] = {}
    verification_final_health = verification.get("final_health")
    verification_final_nodes = (
        verification_final_health.get("nodes")
        if isinstance(verification_final_health, dict)
        else None
    )
    if not isinstance(workload_configuration, dict) or not isinstance(
        verification_final_nodes, dict
    ):
        return failed("final core pre-fence authority snapshots are missing")
    for node in WARDENS:
        terminal = core_terminal_fences[node]
        authority = terminal.get("authority_anchor") if isinstance(terminal, dict) else None
        if (
            not isinstance(terminal, dict)
            or set(terminal) != authority_fence_terminal_fields
            or type(terminal.get("namespace_process_id")) is not int
            or terminal["namespace_process_id"] <= 0
            or type(terminal.get("fenced_at_monotonic_ns")) is not int
            or terminal["fenced_at_monotonic_ns"] < 0
            or terminal.get("schema") != "lets.authority-admission-fence/v1"
            or terminal.get("warden_id") != node
            or not _valid_authority_status(authority, fenced=True, terminal=True)
            or terminal.get("lifetime_id") != authority.get("lifetime_id")
            or terminal.get("namespace_process_id") != authority.get("namespace_process_id")
            or terminal.get("fenced_at_monotonic_ns") != authority.get("fenced_at_monotonic_ns")
            or terminal.get("restart_id") != authority.get("fence_id")
            or not isinstance(terminal.get("restart_id"), str)
            or terminal.get("restart_id")
            != f"final-verification-{workload_configuration.get('seed')}-{node}"
            or authority.get("lifetime_id") in core_lifetimes
            or authority.get("lifetime_id") in executor_lifetimes
        ):
            return failed("final core authority terminal is invalid or repeated")
        core_lifetimes.add(cast(str, authority["lifetime_id"]))
        core_terminal_by_lifetime[cast(str, authority["lifetime_id"])] = authority
        terminal_statuses.append(authority)
        final_core_authorities[node] = authority

        final_document = verification_final_nodes.get(node)
        final_snapshot = (
            final_document.get("authority_anchor") if isinstance(final_document, dict) else None
        )
        if (
            not _valid_authority_status(final_snapshot, fenced=False, terminal=True)
            or authority["lifetime_id"] != final_snapshot["lifetime_id"]
            or authority["namespace_process_id"] != final_snapshot["namespace_process_id"]
            or any(
                authority[field_name] < final_snapshot[field_name]
                for field_name in AUTHORITY_COUNTER_FIELDS
            )
            or (
                final_snapshot["first_fault"] is not None
                and authority["first_fault"] != final_snapshot["first_fault"]
            )
        ):
            return failed("final core pre-fence status is not covered by its terminal")

    for lifetime, baseline in core_recovery_baselines.items():
        terminal = core_terminal_by_lifetime.get(lifetime)
        if (
            terminal is None
            or terminal["namespace_process_id"] != baseline["namespace_process_id"]
            or any(
                terminal[field_name] < baseline[field_name]
                for field_name in AUTHORITY_COUNTER_FIELDS
            )
            or (
                baseline["first_fault"] is not None
                and terminal["first_fault"] != baseline["first_fault"]
            )
        ):
            return failed("replacement authority status is not covered by its terminal")

    health_samples = workload.get("health_samples")
    if not isinstance(health_samples, list):
        return failed("core authority health lifetime samples are missing")
    observed_by_node: dict[str, list[dict[str, Any]]] = {node: [] for node in WARDENS}
    for sample in health_samples:
        nodes = sample.get("nodes") if isinstance(sample, dict) else None
        if not isinstance(nodes, dict):
            return failed("core authority health sample is malformed")
        for node in WARDENS:
            document = nodes.get(node)
            if not isinstance(document, dict) or "planned_unavailable" in document:
                continue
            authority = document.get("authority_anchor")
            if not _valid_authority_status(authority, fenced=False, terminal=True):
                return failed("core authority health status is invalid")
            terminal = core_terminal_by_lifetime.get(cast(str, authority["lifetime_id"]))
            if (
                terminal is None
                or terminal["namespace_process_id"] != authority["namespace_process_id"]
                or any(
                    terminal[field_name] < authority[field_name]
                    for field_name in AUTHORITY_COUNTER_FIELDS
                )
                or (
                    authority["first_fault"] is not None
                    and terminal["first_fault"] != authority["first_fault"]
                )
            ):
                return failed("core health status is not covered by its exact terminal")
            observed_by_node[node].append(authority)
    for node, observations in observed_by_node.items():
        if not observations:
            return failed("core authority lifetime lacks a health observation")
        transitions: list[tuple[str, str]] = []
        previous = observations[0]
        for current in observations[1:]:
            if current["lifetime_id"] == previous["lifetime_id"]:
                if (
                    current["namespace_process_id"] != previous["namespace_process_id"]
                    or any(
                        current[field_name] < previous[field_name]
                        for field_name in AUTHORITY_COUNTER_FIELDS
                    )
                    or (
                        previous["first_fault"] is not None
                        and current["first_fault"] != previous["first_fault"]
                    )
                ):
                    return failed("core authority counters moved backwards within a lifetime")
            else:
                transitions.append((previous["lifetime_id"], current["lifetime_id"]))
            previous = current
        if transitions != planned_pairs[node]:
            return failed("core authority lifetime changed outside a planned restart")
        final_authority = final_core_authorities[node]
        if (
            final_authority["lifetime_id"] != previous["lifetime_id"]
            or final_authority["namespace_process_id"] != previous["namespace_process_id"]
            or any(
                final_authority[field_name] < previous[field_name]
                for field_name in AUTHORITY_COUNTER_FIELDS
            )
            or (
                previous["first_fault"] is not None
                and final_authority["first_fault"] != previous["first_fault"]
            )
        ):
            return failed("final core terminal is not the last observed lifetime")

    totals = {field_name: 0 for field_name in AUTHORITY_COUNTER_FIELDS}
    for status in terminal_statuses:
        for field_name in AUTHORITY_COUNTER_FIELDS:
            totals[field_name] += cast(int, status[field_name])
    if not (
        totals["transport_faults"]
        == totals["transport_fault_episodes"]
        == totals["transport_recovery_attempts"]
        == totals["transport_recoveries"]
        == 1
        and totals["permanent_faults"] == 0
    ):
        return failed("global authority transport episode budget is not exact")
    return {
        "core_lifetime_count": len(core_lifetimes),
        "executor_lifetime_count": len(executor_lifetimes),
        "global_counters": totals,
        "passed": True,
        "terminal_lifetime_count": len(terminal_statuses),
    }


def evaluate_workload_result(
    result: dict[str, Any],
    configuration: SoakConfiguration,
    *,
    chaos_completed_monotonic: object,
    chaos_started_monotonic: object,
    partitions: object,
    restarts: object,
    workload_start: object,
) -> dict[str, Any]:
    raw_cycles = result.get("cycles")
    cycles = raw_cycles if isinstance(raw_cycles, int) and not isinstance(raw_cycles, bool) else -1
    counters = result.get("counters")
    executor = result.get("executor")
    latency = result.get("latency")
    pair_counts = result.get("transfer_pair_counts")
    audit_progress = result.get("audit_progress")
    if not all(
        isinstance(item, dict)
        for item in (audit_progress, counters, executor, latency, pair_counts)
    ):
        raise RuntimeError("soak workload result is missing required metric objects")
    typed_audit_progress = cast(dict[str, Any], audit_progress)
    typed_counters = cast(dict[str, Any], counters)
    typed_executor = cast(dict[str, Any], executor)
    typed_latency = cast(dict[str, Any], latency)
    typed_pair_counts = cast(dict[str, Any], pair_counts)
    executor_status = typed_executor.get("status")
    latency_buckets = typed_latency.get("buckets_ms")
    if not isinstance(executor_status, dict) or not isinstance(latency_buckets, dict):
        raise RuntimeError("soak workload result is missing executor or latency details")

    expected_transfers = (
        max(0, cycles) + configuration.transfer_every_cycles - 1
    ) // configuration.transfer_every_cycles
    expected_reopens = max(0, cycles) // configuration.executor_reopen_every_cycles
    expected_counters = {
        "authorizations": max(0, 2 * max(0, cycles) - 1),
        "closed": max(0, cycles),
        "executor_failed_closed": int(cycles > 0),
        "executor_faulting_calls": int(cycles > 0),
        "issued_receipts": 2 * max(0, cycles),
        "issued_roots": max(0, cycles),
        "quiesced": max(0, cycles),
        "renewed": max(0, cycles),
        "resumed": max(0, cycles),
        "transfers_prepared": expected_transfers,
    }
    expected_pairs = _expected_transfer_pair_counts(
        cycles=max(0, cycles),
        transfer_every_cycles=configuration.transfer_every_cycles,
    )
    workload_started = result.get("started_monotonic_seconds")
    restart_evidence = evaluate_restart_evidence(
        restarts,
        workload_started_monotonic=(
            float(workload_started) if _finite_number(workload_started) else math.nan
        ),
    )
    pause_evidence = evaluate_pause_evidence(
        result,
        configuration=configuration,
        partitions=partitions,
        workload_start=workload_start,
    )
    validated_active_seconds = (
        float(pause_evidence["active_workload_seconds"])
        if pause_evidence.get("passed") is True
        else configuration.duration_seconds
    )
    semantic_floor = semantic_cycle_floor(configuration)
    active_time_floor = math.ceil(
        validated_active_seconds / TARGET_MAXIMUM_ACTIVE_SECONDS_PER_CYCLE
    )
    required_cycles = minimum_cycle_count(
        configuration,
        active_workload_seconds=validated_active_seconds,
    )
    result_duration = result.get("duration_seconds")
    duration_seconds = float(result_duration) if _finite_number(result_duration) else -1.0
    required_health_samples = (
        math.ceil(duration_seconds / configuration.health_interval_seconds) + 1
        if duration_seconds > 0
        else 1
    )
    maximum_retries = max(
        MINIMUM_RETRY_ALLOWANCE,
        MAXIMUM_RETRIES_PER_CYCLE * max(0, cycles),
    )
    maximum_cycle_latency_ms = (
        min(
            MAXIMUM_CYCLE_LATENCY_SECONDS,
            configuration.retry_timeout_seconds + 30.0,
        )
        * 1_000
    )
    raw_request_retries = result.get("request_retry_count")
    actual_retries = (
        raw_request_retries
        if isinstance(raw_request_retries, int) and not isinstance(raw_request_retries, bool)
        else -1
    )
    raw_health_sample_count = result.get("health_sample_count")
    actual_health_samples = (
        raw_health_sample_count
        if isinstance(raw_health_sample_count, int)
        and not isinstance(raw_health_sample_count, bool)
        else -1
    )
    recorded_health_samples = result.get("health_samples")
    health_monitor = result.get("health_monitor")
    health_monitor_retry_value = (
        health_monitor.get("request_retry_count") if isinstance(health_monitor, dict) else None
    )
    health_monitor_retries = (
        health_monitor_retry_value
        if isinstance(health_monitor_retry_value, int)
        and not isinstance(health_monitor_retry_value, bool)
        else -1
    )
    raw_health_retries = -1
    if isinstance(recorded_health_samples, list):
        raw_health_retries = 0
        for sample in recorded_health_samples:
            nodes = sample.get("nodes") if isinstance(sample, dict) else None
            if not isinstance(nodes, dict) or set(nodes) != set(WARDENS):
                raw_health_retries = -1
                break
            for node in WARDENS:
                document = nodes.get(node)
                observation = document.get("observation") if isinstance(document, dict) else None
                retries = (
                    observation.get("request_retries") if isinstance(observation, dict) else None
                )
                if not isinstance(retries, int) or isinstance(retries, bool) or retries < 0:
                    raw_health_retries = -1
                    break
                raw_health_retries += retries
            if raw_health_retries < 0:
                break
    maximum_health_retries = max(
        MINIMUM_RETRY_ALLOWANCE,
        MAXIMUM_RETRIES_PER_HEALTH_SAMPLE * max(0, actual_health_samples),
    )
    health_cadence = evaluate_health_cadence(
        recorded_health_samples,
        duration_seconds=duration_seconds,
        interval_seconds=configuration.health_interval_seconds,
        restart_evidence=restart_evidence,
    )
    maximum_pending = typed_audit_progress.get("maximum_pending_by_node")
    error_sample_budget = typed_audit_progress.get("error_sample_budget")
    error_sample_count = typed_audit_progress.get("error_sample_count")
    error_samples_by_node = typed_audit_progress.get("error_samples_by_node")
    recorded_error_sample_count = typed_audit_progress.get("recorded_error_sample_count")
    recorded_error_samples_by_node = typed_audit_progress.get("recorded_error_samples_by_node")
    recorded_recovered_error_sample_count = typed_audit_progress.get(
        "recorded_recovered_error_sample_count"
    )
    recorded_unresolved_error_nodes = typed_audit_progress.get("recorded_unresolved_error_nodes")
    recovered_error_sample_count = typed_audit_progress.get("recovered_error_sample_count")
    unresolved_error_nodes = typed_audit_progress.get("unresolved_error_nodes")
    audit_error_recovery = (
        error_sample_budget == 1
        and not isinstance(error_sample_budget, bool)
        and isinstance(error_sample_count, int)
        and not isinstance(error_sample_count, bool)
        and 0 <= error_sample_count <= error_sample_budget
        and isinstance(recovered_error_sample_count, int)
        and not isinstance(recovered_error_sample_count, bool)
        and recovered_error_sample_count == error_sample_count
        and unresolved_error_nodes == []
        and isinstance(error_samples_by_node, dict)
        and set(error_samples_by_node) == set(WARDENS)
        and all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in cast(dict[str, Any], error_samples_by_node).values()
        )
        and sum(cast(dict[str, int], error_samples_by_node).values()) == error_sample_count
        and recorded_error_sample_count == error_sample_count
        and recorded_error_samples_by_node == error_samples_by_node
        and recorded_recovered_error_sample_count == recovered_error_sample_count
        and recorded_unresolved_error_nodes == unresolved_error_nodes
        and typed_audit_progress.get("error_evidence_complete") is True
        and typed_audit_progress.get("error_recovery_passed") is True
    )
    required_rotations = SMOKE_PATH_ROTATIONS if configuration.smoke else RELEASE_PATH_ROTATIONS
    expected_workload_configuration = {
        "cycle_interval_seconds": configuration.cycle_interval_seconds,
        "duration_seconds": configuration.duration_seconds,
        "executor_reopen_every_cycles": (configuration.executor_reopen_every_cycles),
        "health_interval_seconds": configuration.health_interval_seconds,
        "retry_timeout_seconds": configuration.retry_timeout_seconds,
        "seed": configuration.seed,
        "transfer_every_cycles": configuration.transfer_every_cycles,
    }
    chaos_timing = bool(
        isinstance(workload_start, dict)
        and _finite_number(chaos_started_monotonic)
        and _finite_number(chaos_completed_monotonic)
        and float(chaos_started_monotonic) <= float(chaos_completed_monotonic)
        and _finite_number(workload_start.get("host_wait_started_monotonic_seconds"))
        and _finite_number(workload_start.get("host_received_monotonic_seconds"))
        and float(workload_start["host_wait_started_monotonic_seconds"])
        <= float(workload_start["host_received_monotonic_seconds"])
        <= float(chaos_started_monotonic)
        and isinstance(partitions, list)
        and all(
            isinstance(partition, dict)
            and isinstance(partition.get("workload_coordination"), dict)
            and _finite_number(
                partition["workload_coordination"].get("host_request_started_monotonic_seconds")
            )
            and float(partition["workload_coordination"]["host_request_started_monotonic_seconds"])
            >= float(chaos_started_monotonic)
            and _finite_number(
                partition["workload_coordination"].get("host_resume_completed_monotonic_seconds")
            )
            and float(partition["workload_coordination"]["host_resume_completed_monotonic_seconds"])
            <= float(chaos_completed_monotonic)
            for partition in partitions
        )
        and isinstance(restarts, list)
        and all(
            isinstance(restart, dict)
            and isinstance(restart.get("workload_coordination"), dict)
            and isinstance(restart["workload_coordination"].get("armed"), dict)
            and isinstance(restart["workload_coordination"].get("completed"), dict)
            and _finite_number(
                restart["workload_coordination"]["armed"].get(
                    "host_armed_started_monotonic_seconds"
                )
            )
            and float(
                restart["workload_coordination"]["armed"]["host_armed_started_monotonic_seconds"]
            )
            >= float(chaos_started_monotonic)
            and _finite_number(restart.get("host_operation_started_monotonic_seconds"))
            and _finite_number(restart.get("host_operation_completed_monotonic_seconds"))
            and float(restart["host_operation_started_monotonic_seconds"])
            >= float(chaos_started_monotonic)
            and float(restart["host_operation_completed_monotonic_seconds"])
            <= float(chaos_completed_monotonic)
            and _finite_number(
                restart["workload_coordination"]["completed"].get(
                    "host_monitor_recovered_monotonic_seconds"
                )
            )
            and float(
                restart["workload_coordination"]["completed"][
                    "host_monitor_recovered_monotonic_seconds"
                ]
            )
            <= float(chaos_completed_monotonic)
            and isinstance(restart.get("resource_checkpoint"), dict)
            and _finite_number(
                restart["resource_checkpoint"].get("host_observed_monotonic_seconds")
            )
            and float(restart["resource_checkpoint"]["host_observed_monotonic_seconds"])
            >= float(chaos_started_monotonic)
            for restart in restarts
        )
    )
    pair_path_coverage = bool(
        set(typed_pair_counts) == set(expected_pairs)
        and all(
            type(value) is int and value >= required_rotations
            for value in typed_pair_counts.values()
        )
    )
    exact_counter_types = bool(
        set(typed_counters) == set(expected_counters)
        and all(type(value) is int and value >= 0 for value in typed_counters.values())
    )
    exact_pair_types = bool(
        set(typed_pair_counts) == set(expected_pairs)
        and all(type(value) is int and value >= 0 for value in typed_pair_counts.values())
    )
    executor_claims = typed_executor.get("claims")
    executor_reopens = typed_executor.get("reopen_count")
    executor_replays = typed_executor.get("replay_rejections")
    executor_claim_sequence = executor_status.get("claim_sequence")
    checks = {
        "audit_error_recovery": audit_error_recovery,
        "audit_progress": (
            typed_audit_progress.get("bounded_progress") is True
            and int(typed_audit_progress.get("catchup_sample_count", -1)) >= 0
            and int(typed_audit_progress.get("catchup_sample_count", -1)) <= actual_health_samples
            and int(typed_audit_progress.get("sample_count", -1)) == actual_health_samples
            and isinstance(maximum_pending, dict)
            and set(maximum_pending) == set(WARDENS)
            and all(
                not isinstance(value, bool) and isinstance(value, int) and value >= 0
                for value in cast(dict[str, Any], maximum_pending).values()
            )
        ),
        "counter_relationships": exact_counter_types and typed_counters == expected_counters,
        "chaos_start_binding": chaos_timing,
        "cycle_latency_bounded": (
            int(typed_latency.get("count", -1)) == cycles
            and float(typed_latency.get("maximum_ms", math.inf)) <= maximum_cycle_latency_ms
            and int(cast(dict[str, Any], latency_buckets).get("overflow", -1)) == 0
        ),
        "executor_claims": type(executor_claims) is int and executor_claims == 2 * cycles,
        "executor_claim_sequence": (
            type(executor_claim_sequence) is int and executor_claim_sequence == 2 * cycles
        ),
        "executor_reopens": (
            type(executor_reopens) is int and executor_reopens == expected_reopens
        ),
        "executor_replay_rejections": (
            type(executor_replays) is int and executor_replays == 2 * cycles + expected_reopens
        ),
        "health_monitor": (
            isinstance(health_monitor, dict)
            and health_monitor.get("status") == "passed"
            and health_monitor.get("schedule") == "absolute_monotonic"
            and health_monitor.get("joined") is True
            and health_monitor.get("deadline_miss_count") == 0
            and health_monitor.get("samples_truncated") == 0
            and health_monitor.get("audit_error_budget_instances") == 1
            and health_monitor.get("interval_seconds") == configuration.health_interval_seconds
            and health_monitor.get("expected_sample_count") == required_health_samples
            and health_monitor.get("actual_sample_count") == actual_health_samples
            and health_monitor.get("retained_sample_count") == actual_health_samples
            and health_monitor_retries == raw_health_retries
        ),
        "health_samples": (
            actual_health_samples == required_health_samples
            and isinstance(recorded_health_samples, list)
            and len(recorded_health_samples) == actual_health_samples
        ),
        "health_cadence": health_cadence.get("passed") is True,
        "pause_partition_binding": pause_evidence.get("passed") is True,
        "restart_window_binding": restart_evidence.get("passed") is True,
        "minimum_cycles": cycles >= required_cycles,
        "requested_duration": duration_seconds >= configuration.duration_seconds,
        "retry_budget": 0 <= actual_retries <= maximum_retries,
        "health_retry_budget": 0 <= health_monitor_retries <= maximum_health_retries,
        "semantic_path_coverage": (
            cycles >= semantic_floor
            and pair_path_coverage
            and type(executor_reopens) is int
            and executor_reopens >= required_rotations
        ),
        "transfer_pair_rotation": exact_pair_types and typed_pair_counts == expected_pairs,
        "workload_identity": (
            result.get("schema") == "lets.production-profile-soak-workload/v2"
            and result.get("status") == "passed"
            and result.get("configuration") == expected_workload_configuration
            and isinstance(workload_start, dict)
            and workload_start.get("run_id") == result.get("run_id")
            and workload_start.get("started_monotonic_seconds")
            == result.get("started_monotonic_seconds")
        ),
    }
    violations = sorted(name for name, passed in checks.items() if not passed)
    return {
        "checks": checks,
        "metrics": {
            "actual_cycles": cycles,
            "actual_health_samples": actual_health_samples,
            "actual_health_request_retries": health_monitor_retries,
            "raw_health_request_retries": raw_health_retries,
            "actual_request_retries": actual_retries,
            "active_time_cycle_floor": active_time_floor,
            "active_workload_seconds": round(validated_active_seconds, 6),
            "audit_error_recovery": {
                "error_sample_budget": error_sample_budget,
                "error_sample_count": error_sample_count,
                "error_samples_by_node": error_samples_by_node,
                "recorded_error_sample_count": recorded_error_sample_count,
                "recorded_error_samples_by_node": recorded_error_samples_by_node,
                "recorded_recovered_error_sample_count": recorded_recovered_error_sample_count,
                "recorded_unresolved_error_nodes": recorded_unresolved_error_nodes,
                "recovered_error_sample_count": recovered_error_sample_count,
                "unresolved_error_nodes": unresolved_error_nodes,
            },
            "maximum_cycle_latency_ms": maximum_cycle_latency_ms,
            "maximum_health_request_retries": maximum_health_retries,
            "maximum_request_retries": maximum_retries,
            "pause_evidence": pause_evidence,
            "required_cycles": required_cycles,
            "required_health_samples": required_health_samples,
            "restart_evidence": restart_evidence,
            "semantic_cycle_floor": semantic_floor,
            "health_cadence": health_cadence,
        },
        "passed": not violations,
        "violations": violations,
    }


def _run(
    arguments: list[str] | tuple[str, ...],
    *,
    environment: dict[str, str],
    check: bool = True,
    timeout: float = 600,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(
        list(arguments),
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if check and process.returncode != 0:
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(arguments)}\n"
            f"{process.stdout}{process.stderr}"
        )
    return process


class Harness:
    def __init__(self, configuration: SoakConfiguration, *, project: str | None = None) -> None:
        self.configuration = configuration
        self.project = project or f"{PROJECT_PREFIX}-{uuid.uuid4().hex[:12]}"
        self.environment = dict(os.environ)
        self.environment["LETS_PRODUCTION_ACCEPTANCE_IMAGE"] = configuration.image
        self.environment["LETS_ACCEPTANCE_INITIAL_SHARE"] = str(configuration.initial_share)

    @property
    def allowed_volumes(self) -> set[str]:
        return {f"{self.project}_{item}" for item in VOLUME_KEYS}

    @property
    def workload_container(self) -> str:
        return f"{self.project}-workload"

    @property
    def compose_command(self) -> tuple[str, ...]:
        return (
            "docker",
            "compose",
            "--project-name",
            self.project,
            "--project-directory",
            str(ROOT),
            "--file",
            str(COMPOSE_FILE),
        )

    def run(
        self,
        arguments: list[str] | tuple[str, ...],
        *,
        check: bool = True,
        timeout: float = 600,
    ) -> subprocess.CompletedProcess[str]:
        return _run(
            arguments,
            environment=self.environment,
            check=check,
            timeout=timeout,
        )

    def compose(
        self,
        *arguments: str,
        check: bool = True,
        timeout: float = 600,
    ) -> str:
        return self.run(
            [*self.compose_command, *arguments], check=check, timeout=timeout
        ).stdout.strip()

    def container(self, service: str, *, timeout: float = 600) -> str:
        value = self.compose("ps", "-q", service, timeout=timeout)
        if not value:
            raise RuntimeError(f"Compose service {service} has no container")
        return value

    def state(self, service: str, *, timeout: float = 600) -> dict[str, Any]:
        return self.container_state(
            self.container(service, timeout=timeout),
            timeout=timeout,
        )

    def container_state(self, container: str, *, timeout: float = 600) -> dict[str, Any]:
        value = json.loads(
            self.run(
                ["docker", "inspect", "--format", "{{json .State}}", container],
                timeout=timeout,
            ).stdout
        )
        if not isinstance(value, dict):
            raise RuntimeError(f"Docker returned invalid state for {container}")
        return cast(dict[str, Any], value)

    def container_restart_count(self, container: str, *, timeout: float = 600) -> int:
        return int(
            json.loads(
                self.run(
                    ["docker", "inspect", "--format", "{{json .RestartCount}}", container],
                    timeout=timeout,
                ).stdout
            )
        )

    def restart_count(self, service: str, *, timeout: float = 600) -> int:
        container = self.container(service, timeout=timeout)
        return self.container_restart_count(container, timeout=timeout)

    def wait_healthy(self, service: str, *, timeout_s: float = 180) -> None:
        deadline = time.monotonic() + timeout_s
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            last = self.state(service, timeout=max(0.001, remaining))
            health = last.get("Health")
            if isinstance(health, dict) and health.get("Status") == "healthy":
                return
            if last.get("Status") == "exited":
                raise RuntimeError(f"{service} exited before becoming healthy: {last}")
            time.sleep(min(0.5, max(0.0, deadline - time.monotonic())))
        raise RuntimeError(f"{service} did not become healthy: {last}")


def _project_volumes(harness: Harness, *, timeout: float = 600) -> set[str]:
    output = harness.run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={harness.project}",
            "--format",
            "{{.Name}}",
        ],
        timeout=timeout,
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _project_containers(harness: Harness, *, timeout: float = 600) -> set[str]:
    output = harness.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={harness.project}",
            "--format",
            "{{.ID}}",
        ],
        timeout=timeout,
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _project_networks(harness: Harness, *, timeout: float = 600) -> set[str]:
    output = harness.run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={harness.project}",
            "--format",
            "{{.ID}}",
        ],
        timeout=timeout,
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _checked_down(
    harness: Harness,
    *,
    probe_timeout: float = 600,
    down_timeout: float = 180,
) -> dict[str, Any]:
    unexpected = _project_volumes(harness, timeout=probe_timeout) - harness.allowed_volumes
    if unexpected:
        raise RuntimeError(f"refusing to remove unexpected project volumes: {sorted(unexpected)}")
    harness.compose("down", "--volumes", "--remove-orphans", timeout=down_timeout)
    residual = {
        "containers": sorted(_project_containers(harness, timeout=probe_timeout)),
        "networks": sorted(_project_networks(harness, timeout=probe_timeout)),
        "volumes": sorted(_project_volumes(harness, timeout=probe_timeout)),
    }
    if any(residual.values()):
        raise RuntimeError(f"production soak cleanup left project resources: {residual!r}")
    return {
        "performed": True,
        "remaining_containers": 0,
        "remaining_networks": 0,
        "remaining_volumes": 0,
    }


def _preflight_zero(harness: Harness) -> dict[str, Any]:
    resources = {
        "containers": sorted(_project_containers(harness)),
        "networks": sorted(_project_networks(harness)),
        "volumes": sorted(_project_volumes(harness)),
    }
    if any(resources.values()):
        raise RuntimeError(
            f"unique production soak project is not empty before startup: {resources!r}"
        )
    return {
        "containers": 0,
        "networks": 0,
        "passed": True,
        "volumes": 0,
    }


def _proxy_request(method: str, path: str, body: object | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{TOXIPROXY}{path}",
        data=data,
        headers={"content-type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def _wait_toxiproxy() -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            _proxy_request("GET", "/proxies")
            return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.25)
    raise RuntimeError("Toxiproxy control API did not become ready")


def _configure_proxies() -> None:
    for payload in (
        {
            "enabled": True,
            "listen": "0.0.0.0:8666",
            "name": "a_to_b",
            "upstream": "warden-b:8443",
        },
        {
            "enabled": True,
            "listen": "0.0.0.0:8667",
            "name": "b_to_a",
            "upstream": "warden-a:8443",
        },
    ):
        _proxy_request("POST", "/proxies", payload)


def _set_partition(*, enabled: bool) -> None:
    for name in ("a_to_b", "b_to_a"):
        current = _proxy_request("GET", f"/proxies/{name}")
        current["enabled"] = enabled
        updated = _proxy_request("PATCH", f"/proxies/{name}", current)
        if bool(updated.get("enabled")) is not enabled:
            raise RuntimeError(f"Toxiproxy did not set {name} enabled={enabled}")


def _source_tree_digest(environment: dict[str, str]) -> dict[str, Any]:
    listed = _run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        environment=environment,
    )
    paths = sorted(item for item in listed.stdout.split("\0") if item)
    digest = hashlib.sha256(b"lets-production-soak-source/v1\0")
    for relative in paths:
        candidate = ROOT / relative
        resolved = candidate.resolve()
        if not resolved.is_relative_to(ROOT):
            raise RuntimeError(f"Git returned a path outside the repository: {relative!r}")
        if candidate.is_symlink():
            kind = "symlink"
            payload = os.readlink(candidate).encode("utf-8")
        elif candidate.is_file():
            kind = "file"
            payload = candidate.read_bytes()
        elif not candidate.exists():
            kind = "missing"
            payload = b""
        else:
            raise RuntimeError(f"Git-visible soak source is not a file: {relative!r}")
        header = json.dumps(
            {"kind": kind, "path": relative.replace("\\", "/"), "size": len(payload)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(payload)
    revision = _run(
        ["git", "rev-parse", "--verify", "HEAD"], environment=environment
    ).stdout.strip()
    status = _run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
        environment=environment,
    ).stdout
    harness_files = (
        "deploy/production/acceptance-compose.yaml",
        "deploy/production/acceptance/materialize.py",
        "deploy/production/acceptance/soak.py",
        "deploy/production/run_soak.py",
    )
    return {
        "dirty": bool(status),
        "file_count": len(paths),
        "git_commit": revision,
        "git_status_sha256": "sha256:"
        + hashlib.sha256(status.encode("utf-8", errors="surrogateescape")).hexdigest(),
        "harness_file_sha256": {
            relative: "sha256:" + hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in harness_files
        },
        "tree_sha256": f"sha256:{digest.hexdigest()}",
    }


def validate_image_labels(
    labels: dict[str, Any],
    *,
    expected_revision: str,
    expected_version: str,
) -> None:
    expected = {
        "org.opencontainers.image.revision": expected_revision,
        "org.opencontainers.image.version": expected_version,
    }
    mismatches = {
        name: {"actual": labels.get(name), "expected": value}
        for name, value in expected.items()
        if labels.get(name) != value
    }
    if mismatches:
        raise RuntimeError(f"runtime OCI identity labels do not match source/package: {mismatches}")


def validate_package_identity(
    *,
    host_version: str,
    image: dict[str, Any],
    runtime_packages: dict[str, Any],
    workload: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    labels = image.get("labels")
    if not isinstance(labels, dict) or set(runtime_packages) != set(WARDENS):
        raise RuntimeError("soak package identity evidence is incomplete")
    observed = {
        "final_verifier": verification.get("package_version"),
        "oci_label": labels.get("org.opencontainers.image.version"),
        "workload": workload.get("package_version"),
        **{
            f"runtime:{service}": (
                document.get("lets_agent") if isinstance(document, dict) else None
            )
            for service, document in sorted(runtime_packages.items())
        },
    }
    mismatches = {
        name: {"actual": value, "expected": host_version}
        for name, value in observed.items()
        if value != host_version
    }
    if mismatches:
        raise RuntimeError(f"soak package identities do not match exactly: {mismatches}")
    return {
        "expected": host_version,
        "observed": observed,
        "passed": True,
    }


def _image_identity(
    harness: Harness,
    *,
    expected_revision: str,
    expected_version: str,
) -> dict[str, Any]:
    documents: dict[str, dict[str, Any]] = {}
    for service in WARDENS:
        raw = json.loads(harness.run(["docker", "inspect", harness.container(service)]).stdout)
        if not isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict):
            raise RuntimeError(f"Docker returned malformed inspection for {service}")
        documents[service] = cast(dict[str, Any], raw[0])
    configured = {str(document["Config"]["Image"]) for document in documents.values()}
    image_ids = {str(document["Image"]) for document in documents.values()}
    if configured != {harness.configuration.image}:
        raise RuntimeError(f"wardens did not use the exact requested digest: {sorted(configured)}")
    if len(image_ids) != 1 or not next(iter(image_ids)).startswith("sha256:"):
        raise RuntimeError("wardens did not resolve one content-addressed local image")
    image_id = next(iter(image_ids))
    image_document = json.loads(
        harness.run(["docker", "image", "inspect", "--format", "{{json .}}", image_id]).stdout
    )
    if not isinstance(image_document, dict):
        raise RuntimeError("Docker returned malformed runtime image identity")
    repository, index_digest = harness.configuration.image.rsplit("@", 1)
    labels = dict(sorted((image_document.get("Config", {}).get("Labels") or {}).items()))
    validate_image_labels(
        labels,
        expected_revision=expected_revision,
        expected_version=expected_version,
    )
    return {
        "configured_digest": harness.configuration.image,
        "image_id": image_id,
        "index_digest": index_digest,
        "labels": labels,
        "repo_digests": sorted(image_document.get("RepoDigests") or []),
        "repository": repository,
    }


def _runtime_packages(harness: Harness) -> dict[str, Any]:
    result: dict[str, Any] = {}
    command = (
        "import importlib.metadata,json,platform,sqlite3;"
        "print(json.dumps({'lets_agent':importlib.metadata.version('lets-agent'),"
        "'python':platform.python_version(),'sqlite':sqlite3.sqlite_version},sort_keys=True))"
    )
    for service in WARDENS:
        value = json.loads(
            harness.run(
                ["docker", "exec", harness.container(service), "python", "-c", command]
            ).stdout
        )
        if not isinstance(value, dict):
            raise RuntimeError(f"{service} returned malformed package identity")
        result[service] = value
    if len({json.dumps(item, sort_keys=True) for item in result.values()}) != 1:
        raise RuntimeError("wardens disagree on runtime package identity")
    return result


def _resource_sample(
    harness: Harness,
    *,
    elapsed_s: float,
    reason: str,
    planned_sigkill_service: str | None = None,
    command_timeout: float | None = None,
) -> dict[str, Any]:
    nodes: dict[str, Any] = {}
    helper_timeout = 600 if command_timeout is None else command_timeout
    probe_timeout = 30 if command_timeout is None else command_timeout
    for service in WARDENS:
        container = harness.container(service, timeout=helper_timeout)
        resource = json.loads(
            harness.run(
                [
                    "docker",
                    "exec",
                    container,
                    "python",
                    "-c",
                    RESOURCE_PROBE,
                ],
                timeout=probe_timeout,
            ).stdout
        )
        if not isinstance(resource, dict):
            raise RuntimeError(f"{service} returned malformed resource evidence")
        state = harness.container_state(container, timeout=helper_timeout)
        resource["container_init_pid"] = state.get("Pid")
        resource["container_state"] = {
            "exit_code": state.get("ExitCode"),
            "oom_killed": state.get("OOMKilled"),
            "status": state.get("Status"),
        }
        resource["restart_count"] = harness.container_restart_count(
            container,
            timeout=helper_timeout,
        )
        nodes[service] = resource
    sample: dict[str, Any] = {
        "elapsed_seconds": round(elapsed_s, 3),
        "host_observed_monotonic_seconds": time.monotonic(),
        "nodes": nodes,
        "reason": reason,
    }
    if planned_sigkill_service is not None:
        if planned_sigkill_service not in WARDENS:
            raise ValueError(f"unknown planned SIGKILL service: {planned_sigkill_service}")
        sample["planned_sigkill_service"] = planned_sigkill_service
    return sample


def _capture_failure_resource_sample(
    harness: Harness,
    *,
    elapsed_s: float,
    samples: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        samples.append(
            _resource_sample(
                harness,
                elapsed_s=elapsed_s,
                reason="failure",
                command_timeout=FAILURE_COMMAND_TIMEOUT_SECONDS,
            )
        )
    except Exception as exc:
        return {
            "attempted": True,
            "captured": False,
            "error": _bounded_text(str(exc)),
        }
    return {
        "attempted": True,
        "captured": True,
        "sample_index": len(samples) - 1,
    }


def _cgroup_integer_values(
    documents: list[dict[str, Any]],
    *,
    shapes_valid: bool,
    controller: str,
    field: str,
) -> list[int]:
    values: list[int] = []
    if not shapes_valid:
        return values
    for cgroup in documents:
        value = cast(dict[str, Any], cgroup[controller]).get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return []
        values.append(value)
    return values


def _cgroup_event_sets(
    documents: list[dict[str, Any]],
    *,
    shapes_valid: bool,
    controller: str,
    required: set[str],
) -> list[dict[str, int]]:
    values: list[dict[str, int]] = []
    if not shapes_valid:
        return values
    for cgroup in documents:
        events = cast(dict[str, Any], cgroup[controller]).get("events")
        if not isinstance(events, dict) or not required.issubset(events):
            return []
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in events.values()
        ):
            return []
        values.append(cast(dict[str, int], events))
    return values


def evaluate_resource_bounds(
    samples: list[dict[str, Any]],
    *,
    cycles: int,
    bounds: ResourceBounds,
) -> dict[str, Any]:
    if len(samples) < 2:
        raise ValueError("resource evaluation requires baseline and final samples")
    violations: list[str] = []
    measurements: dict[str, Any] = {}
    for node in WARDENS:
        node_samples = [cast(dict[str, Any], sample["nodes"][node]) for sample in samples]
        baseline = node_samples[0]
        cgroup_samples = [cast(dict[str, Any], item.get("cgroup")) for item in node_samples]
        cgroup_shapes_valid = all(
            isinstance(cgroup, dict)
            and cgroup.get("version") == 2
            and all(
                isinstance(cgroup.get(controller), dict)
                for controller in ("memory", "pids", "swap")
            )
            for cgroup in cgroup_samples
        )

        memory_current = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="memory",
            field="current_bytes",
        )
        memory_peak = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="memory",
            field="peak_bytes",
        )
        memory_max = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="memory",
            field="max_bytes",
        )
        memory_events = _cgroup_event_sets(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="memory",
            required={"high", "max", "oom", "oom_group_kill", "oom_kill"},
        )
        swap_current = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="swap",
            field="current_bytes",
        )
        swap_peak = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="swap",
            field="peak_bytes",
        )
        swap_max = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="swap",
            field="max_bytes",
        )
        swap_events = _cgroup_event_sets(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="swap",
            required={"fail", "high", "max"},
        )
        pids_current = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="pids",
            field="current",
        )
        pids_peak = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="pids",
            field="peak",
        )
        pids_max = _cgroup_integer_values(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="pids",
            field="max",
        )
        pids_events = _cgroup_event_sets(
            cgroup_samples,
            shapes_valid=cgroup_shapes_valid,
            controller="pids",
            required={"max"},
        )
        cgroup_probe_valid = all(
            len(values) == len(node_samples)
            for values in (
                memory_current,
                memory_peak,
                memory_max,
                memory_events,
                swap_current,
                swap_peak,
                swap_max,
                swap_events,
                pids_current,
                pids_peak,
                pids_max,
                pids_events,
            )
        )
        peak_rss = max(int(item["rss_bytes"]) for item in node_samples)
        peak_fd = max(int(item["fd_count"]) for item in node_samples)
        peak_core_database = max(int(item["core"]["database_bytes"]) for item in node_samples)
        peak_core_wal = max(int(item["core"]["wal_bytes"]) for item in node_samples)
        peak_core_total = max(
            sum(int(value) for value in item["core"].values()) for item in node_samples
        )
        peak_audit_total = max(
            sum(int(value) for value in item["audit"].values()) for item in node_samples
        )
        peak_signer = max(int(item["signer_log_bytes"]) for item in node_samples)
        baseline_core = sum(int(value) for value in baseline["core"].values())
        baseline_audit = sum(int(value) for value in baseline["audit"].values())
        allowed_core_growth = (
            bounds.fixed_growth_allowance_bytes + cycles * bounds.max_core_growth_bytes_per_cycle
        )
        allowed_audit_growth = (
            bounds.fixed_growth_allowance_bytes + cycles * bounds.max_audit_growth_bytes_per_cycle
        )
        allowed_signer_growth = (
            bounds.fixed_growth_allowance_bytes + cycles * bounds.max_signer_growth_bytes_per_cycle
        )
        checks = {
            "audit_growth": peak_audit_total - baseline_audit <= allowed_audit_growth,
            "cgroup_memory_events": (
                cgroup_probe_valid
                and all(value == 0 for events in memory_events for value in events.values())
            ),
            "cgroup_memory_limit": (
                cgroup_probe_valid
                and all(value == bounds.cgroup_memory_max_bytes for value in memory_max)
            ),
            "cgroup_memory_peak": (
                cgroup_probe_valid
                and all(
                    current <= peak
                    for current, peak in zip(memory_current, memory_peak, strict=True)
                )
                and max(memory_peak, default=bounds.max_cgroup_memory_peak_bytes + 1)
                <= bounds.max_cgroup_memory_peak_bytes
            ),
            "cgroup_pids_events": (
                cgroup_probe_valid
                and all(value == 0 for events in pids_events for value in events.values())
            ),
            "cgroup_pids_limit": (
                cgroup_probe_valid and all(value == bounds.cgroup_pids_max for value in pids_max)
            ),
            "cgroup_pids_peak": (
                cgroup_probe_valid
                and all(
                    current <= peak for current, peak in zip(pids_current, pids_peak, strict=True)
                )
                and max(pids_peak, default=bounds.max_cgroup_pids_peak + 1)
                <= bounds.max_cgroup_pids_peak
            ),
            "cgroup_probe": cgroup_probe_valid,
            "cgroup_swap_events": (
                cgroup_probe_valid
                and all(value == 0 for events in swap_events for value in events.values())
            ),
            "cgroup_swap_limit": (
                cgroup_probe_valid
                and all(value == bounds.cgroup_swap_max_bytes for value in swap_max)
            ),
            "cgroup_swap_usage": (
                cgroup_probe_valid and all(value == 0 for value in (*swap_current, *swap_peak))
            ),
            "container_integrity": all(
                item.get("restart_count") == 0
                and item.get("container_state")
                == {"exit_code": 0, "oom_killed": False, "status": "running"}
                for item in node_samples
            ),
            "core_database": peak_core_database <= bounds.max_core_database_bytes,
            "core_growth": peak_core_total - baseline_core <= allowed_core_growth,
            "core_wal": peak_core_wal <= bounds.max_core_wal_bytes,
            "fd_count": peak_fd <= bounds.max_fd_count,
            "fd_growth": peak_fd - int(baseline["fd_count"]) <= bounds.max_fd_growth,
            "init_process": all(
                isinstance(item.get("init"), dict)
                and item["init"].get("pid") == 1
                and item["init"].get("cmdline")
                and Path(item["init"]["cmdline"][0]).name in {"tini", "docker-init"}
                for item in node_samples
            ),
            "rss": peak_rss <= bounds.max_rss_bytes,
            "rss_growth": peak_rss - int(baseline["rss_bytes"]) <= bounds.max_rss_growth_bytes,
            "runtime_process": all(
                isinstance(item.get("process"), dict)
                and item["process"].get("identity") == "lets-serve"
                and int(item["process"].get("pid", 0)) > 1
                and "serve" in item["process"].get("cmdline", [])
                and int(item.get("rss_bytes", 0)) > 1024 * 1024
                and int(item.get("fd_count", 0)) > 3
                for item in node_samples
            ),
            "signer_growth": (
                peak_signer - int(baseline["signer_log_bytes"]) <= allowed_signer_growth
            ),
        }
        for name, passed in checks.items():
            if not passed:
                violations.append(f"{node}:{name}")
        measurements[node] = {
            "baseline": baseline,
            "checks": checks,
            "final": node_samples[-1],
            "peak": {
                "audit_total_bytes": peak_audit_total,
                "cgroup_memory_bytes": max(memory_peak, default=None),
                "cgroup_pids": max(pids_peak, default=None),
                "cgroup_swap_bytes": max(swap_peak, default=None),
                "core_database_bytes": peak_core_database,
                "core_total_bytes": peak_core_total,
                "core_wal_bytes": peak_core_wal,
                "fd_count": peak_fd,
                "rss_bytes": peak_rss,
                "signer_log_bytes": peak_signer,
            },
        }
    return {
        "bounds": asdict(bounds),
        "measurements": measurements,
        "passed": not violations,
        "violations": violations,
    }


def _pre_sigkill_resource_checkpoint(
    harness: Harness,
    *,
    service: str,
    elapsed_s: float,
    samples: list[dict[str, Any]],
    configuration: SoakConfiguration,
    bounds: ResourceBounds,
) -> dict[str, Any]:
    samples.append(
        _resource_sample(
            harness,
            elapsed_s=elapsed_s,
            reason="pre_sigkill",
            planned_sigkill_service=service,
        )
    )
    evaluation = evaluate_resource_bounds(
        samples,
        cycles=minimum_cycle_count(configuration),
        bounds=bounds,
    )
    if not evaluation["passed"]:
        raise RuntimeError(f"pre-SIGKILL resource bounds failed: {evaluation['violations']!r}")
    return {
        "evaluation_passed": True,
        "host_observed_monotonic_seconds": samples[-1]["host_observed_monotonic_seconds"],
        "sample_index": len(samples) - 1,
        "sample_reason": "pre_sigkill",
        "service": service,
    }


def _scenario_result(harness: Harness, path: str) -> dict[str, Any]:
    command = (
        "import json; from pathlib import Path; "
        f"print(json.dumps(json.loads(Path({path!r}).read_text()),sort_keys=True))"
    )
    output = harness.compose(
        "run",
        "--rm",
        "--no-deps",
        "scenario",
        "python",
        "-c",
        command,
        timeout=60,
    )
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return cast(dict[str, Any], value)
    raise RuntimeError(f"scenario result {path} was not readable: {output}")


def _container_json(
    harness: Harness,
    service: str,
    script: str,
    *arguments: str,
) -> Any:
    output = harness.run(
        [
            "docker",
            "exec",
            harness.container(service),
            "python",
            "-c",
            script,
            *arguments,
        ],
        timeout=30,
    ).stdout
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{service} returned malformed SQLite probe output: {output}") from exc


def _wait_workload_start(
    harness: Harness,
    *,
    expected_run_id: str,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    script = (
        "import sys; from pathlib import Path; "
        f"path=Path({WORKLOAD_START_PATH!r}); "
        "sys.stdout.write(path.read_text() if path.exists() else '')"
    )
    host_wait_started = time.monotonic()
    deadline = host_wait_started + HEALTH_CADENCE_LIMIT_SECONDS
    last = ""
    while time.monotonic() < deadline:
        _require_workload_running(workload, context="before workload startup acknowledgement")
        process = harness.run(
            [
                "docker",
                "exec",
                harness.workload_container,
                "python",
                "-c",
                script,
            ],
            check=False,
            timeout=FAILURE_COMMAND_TIMEOUT_SECONDS,
        )
        last = process.stdout.strip()
        if process.returncode == 0 and last:
            try:
                document = json.loads(last)
            except json.JSONDecodeError:
                document = None
            if (
                isinstance(document, dict)
                and document.get("run_id") == expected_run_id
                and _finite_number(document.get("started_monotonic_seconds"))
                and document.get("duration_seconds") == harness.configuration.duration_seconds
                and document.get("cycle_interval_seconds")
                == harness.configuration.cycle_interval_seconds
                and document.get("health_interval_seconds")
                == harness.configuration.health_interval_seconds
                and document.get("retry_timeout_seconds")
                == harness.configuration.retry_timeout_seconds
                and document.get("transfer_every_cycles")
                == harness.configuration.transfer_every_cycles
                and document.get("executor_reopen_every_cycles")
                == harness.configuration.executor_reopen_every_cycles
                and document.get("seed") == harness.configuration.seed
                and document.get("schema") == "lets.production-profile-soak-workload-start/v1"
            ):
                return {
                    **document,
                    "host_received_monotonic_seconds": time.monotonic(),
                    "host_wait_started_monotonic_seconds": host_wait_started,
                }
        time.sleep(0.05)
    _require_workload_running(workload, context="waiting for workload startup acknowledgement")
    raise RuntimeError(f"workload startup identity was not acknowledged: {last!r}")


def _pause_workload(
    harness: Harness,
    episode: int,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    _require_workload_running(workload, context=f"before partition pause {episode}")
    pause_id = f"{harness.project}-partition-pause-{episode:06d}"
    write_script = (
        "import json,sys,time; from pathlib import Path; "
        f"target=Path({WORKLOAD_PAUSE_PATH!r}); temporary=target.with_suffix('.tmp'); "
        f"Path({WORKLOAD_PAUSE_ACK_PATH!r}).unlink(missing_ok=True); "
        "document={'episode':int(sys.argv[1]),'pause_id':sys.argv[2],"
        "'requested_monotonic_seconds':time.monotonic()}; "
        "temporary.write_text(json.dumps(document,sort_keys=True)+'\\n'); "
        "temporary.replace(target); print(json.dumps(document,sort_keys=True))"
    )
    host_request_started = time.monotonic()
    try:
        marker_process = harness.run(
            [
                "docker",
                "exec",
                harness.workload_container,
                "python",
                "-c",
                write_script,
                str(episode),
                pause_id,
            ],
            timeout=30,
        )
    except Exception:
        _require_workload_running(workload, context=f"during partition pause {episode}")
        raise
    try:
        marker = json.loads(marker_process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"workload pause marker was malformed: {marker_process.stdout!r}"
        ) from exc
    if (
        not isinstance(marker, dict)
        or marker.get("episode") != episode
        or marker.get("pause_id") != pause_id
        or not isinstance(marker.get("requested_monotonic_seconds"), (int, float))
        or isinstance(marker.get("requested_monotonic_seconds"), bool)
    ):
        raise RuntimeError(f"workload pause marker identity mismatch: {marker!r}")
    read_script = (
        "import sys; from pathlib import Path; "
        f"path=Path({WORKLOAD_PAUSE_ACK_PATH!r}); "
        "sys.stdout.write(path.read_text() if path.exists() else '')"
    )
    deadline = time.monotonic() + harness.configuration.retry_timeout_seconds + 30
    last = ""
    while time.monotonic() < deadline:
        _require_workload_running(workload, context=f"during partition pause {episode}")
        process = harness.run(
            [
                "docker",
                "exec",
                harness.workload_container,
                "python",
                "-c",
                read_script,
            ],
            check=False,
            timeout=30,
        )
        last = process.stdout.strip()
        if process.returncode == 0 and last:
            try:
                acknowledgement = json.loads(last)
            except json.JSONDecodeError:
                acknowledgement = None
            if (
                isinstance(acknowledgement, dict)
                and acknowledgement.get("episode") == episode
                and acknowledgement.get("pause_id") == pause_id
                and acknowledgement.get("paused") is True
                and acknowledgement.get("requested_monotonic_seconds")
                == marker["requested_monotonic_seconds"]
                and isinstance(
                    acknowledgement.get("observed_monotonic_seconds"),
                    (int, float),
                )
                and not isinstance(
                    acknowledgement.get("observed_monotonic_seconds"),
                    bool,
                )
            ):
                host_acknowledged = time.monotonic()
                boundary_script = (
                    "import json,time; from pathlib import Path; "
                    f"marker=json.loads(Path({WORKLOAD_PAUSE_PATH!r}).read_text()); "
                    f"ack=json.loads(Path({WORKLOAD_PAUSE_ACK_PATH!r}).read_text()); "
                    "identity=('episode','pause_id','requested_monotonic_seconds'); "
                    "assert all(marker[k]==ack[k] for k in identity); "
                    "document={k:marker[k] for k in identity}; "
                    "document['authorized_start_monotonic_seconds']=time.monotonic(); "
                    "print(json.dumps(document,sort_keys=True))"
                )
                host_boundary_started = time.monotonic()
                boundary_process = harness.run(
                    [
                        "docker",
                        "exec",
                        harness.workload_container,
                        "python",
                        "-c",
                        boundary_script,
                    ],
                    timeout=30,
                )
                host_boundary_completed = time.monotonic()
                try:
                    authorized_start = json.loads(boundary_process.stdout)
                except json.JSONDecodeError as exc:
                    raise RuntimeError(
                        "workload pause authorization boundary was malformed: "
                        f"{boundary_process.stdout!r}"
                    ) from exc
                if (
                    not isinstance(authorized_start, dict)
                    or any(
                        authorized_start.get(key) != marker.get(key)
                        for key in ("episode", "pause_id", "requested_monotonic_seconds")
                    )
                    or not isinstance(
                        authorized_start.get("authorized_start_monotonic_seconds"),
                        (int, float),
                    )
                    or isinstance(
                        authorized_start.get("authorized_start_monotonic_seconds"),
                        bool,
                    )
                ):
                    raise RuntimeError(
                        f"workload pause authorization identity mismatch: {authorized_start!r}"
                    )
                return {
                    **marker,
                    "acknowledgement": acknowledgement,
                    "authorized_start": {
                        **authorized_start,
                        "host_boundary_completed_monotonic_seconds": (host_boundary_completed),
                        "host_boundary_started_monotonic_seconds": (host_boundary_started),
                    },
                    "host_acknowledged_monotonic_seconds": host_acknowledged,
                    "host_request_started_monotonic_seconds": host_request_started,
                    "marker": marker,
                }
        time.sleep(0.1)
    _require_workload_running(workload, context=f"during partition pause {episode}")
    raise RuntimeError(f"workload did not acknowledge partition pause {episode}: {last}")


def _authorize_pause_end(harness: Harness, *, timeout: float = 30) -> dict[str, Any]:
    script = (
        "import json,time; from pathlib import Path; "
        f"marker=json.loads(Path({WORKLOAD_PAUSE_PATH!r}).read_text()); "
        f"ack=json.loads(Path({WORKLOAD_PAUSE_ACK_PATH!r}).read_text()); "
        "identity=('episode','pause_id','requested_monotonic_seconds'); "
        "assert all(marker[k]==ack[k] for k in identity); "
        "document={k:marker[k] for k in identity}; "
        "document['authorized_end_monotonic_seconds']=time.monotonic(); "
        "print(json.dumps(document,sort_keys=True))"
    )
    host_started = time.monotonic()
    process = harness.run(
        ["docker", "exec", harness.workload_container, "python", "-c", script],
        timeout=timeout,
    )
    host_completed = time.monotonic()
    try:
        boundary = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"workload pause end boundary was malformed: {process.stdout!r}"
        ) from exc
    if (
        not isinstance(boundary, dict)
        or not _finite_number(boundary.get("authorized_end_monotonic_seconds"))
        or not isinstance(boundary.get("pause_id"), str)
        or not isinstance(boundary.get("episode"), int)
    ):
        raise RuntimeError(f"workload pause end boundary was invalid: {boundary!r}")
    return {
        **boundary,
        "host_boundary_completed_monotonic_seconds": host_completed,
        "host_boundary_started_monotonic_seconds": host_started,
    }


def _resume_workload(
    harness: Harness,
    *,
    authorized_end: dict[str, Any] | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    script = (
        "import json,sys,time; from pathlib import Path; "
        f"marker=Path({WORKLOAD_PAUSE_PATH!r}); ack=Path({WORKLOAD_PAUSE_ACK_PATH!r}); "
        "request=json.loads(marker.read_text()); acknowledgement=json.loads(ack.read_text()); "
        "identity=('episode','pause_id','requested_monotonic_seconds'); "
        "assert all(request[k]==acknowledgement[k] for k in identity); "
        "assert sys.argv[1]=='emergency' or (request['episode']==int(sys.argv[1]) "
        "and request['pause_id']==sys.argv[2] "
        "and str(request['requested_monotonic_seconds'])==sys.argv[3]); "
        "document={k:request[k] for k in identity}; "
        "document['resume_requested_monotonic_seconds']=time.monotonic(); "
        "marker.unlink(); ack.unlink(); "
        "print(json.dumps(document,sort_keys=True))"
    )
    started = time.monotonic()
    identity_arguments = (
        ["emergency", "", ""]
        if authorized_end is None
        else [
            str(authorized_end["episode"]),
            str(authorized_end["pause_id"]),
            str(authorized_end["requested_monotonic_seconds"]),
        ]
    )
    process = harness.run(
        [
            "docker",
            "exec",
            harness.workload_container,
            "python",
            "-c",
            script,
            *identity_arguments,
        ],
        timeout=timeout,
    )
    try:
        workload_boundary = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"workload resume boundary was malformed: {process.stdout!r}") from exc
    resume_requested = (
        workload_boundary.get("resume_requested_monotonic_seconds")
        if isinstance(workload_boundary, dict)
        else None
    )
    if not isinstance(resume_requested, (int, float)) or isinstance(resume_requested, bool):
        raise RuntimeError(f"workload resume boundary was invalid: {workload_boundary!r}")
    return {
        **cast(dict[str, Any], workload_boundary),
        "host_resume_completed_monotonic_seconds": time.monotonic(),
        "host_resume_started_monotonic_seconds": started,
        "workload_resume_requested_monotonic_seconds": float(resume_requested),
    }


def _wait_restart_acknowledgement(
    harness: Harness,
    *,
    marker: dict[str, Any],
    required_field: str,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    read_script = (
        "import sys; from pathlib import Path; "
        f"path=Path({WORKLOAD_RESTART_ACK_PATH!r}); "
        "sys.stdout.write(path.read_text() if path.exists() else '')"
    )
    deadline = time.monotonic() + HEALTH_CADENCE_LIMIT_SECONDS
    last = ""
    while time.monotonic() < deadline:
        _require_workload_running(workload, context=f"waiting for restart {required_field}")
        process = harness.run(
            [
                "docker",
                "exec",
                harness.workload_container,
                "python",
                "-c",
                read_script,
            ],
            check=False,
            timeout=FAILURE_COMMAND_TIMEOUT_SECONDS,
        )
        last = process.stdout.strip()
        if process.returncode == 0 and last:
            try:
                acknowledgement = json.loads(last)
            except json.JSONDecodeError:
                acknowledgement = None
            identity = ("restart_id", "episode", "service", "armed_monotonic_seconds")
            if (
                isinstance(acknowledgement, dict)
                and all(acknowledgement.get(key) == marker.get(key) for key in identity)
                and isinstance(acknowledgement.get(required_field), (int, float))
                and not isinstance(acknowledgement.get(required_field), bool)
            ):
                if required_field == "recovered_monotonic_seconds" and (
                    acknowledgement.get("completed_monotonic_seconds")
                    != marker.get("completed_monotonic_seconds")
                    or not isinstance(
                        acknowledgement.get("acknowledged_monotonic_seconds"),
                        (int, float),
                    )
                    or float(acknowledgement["recovered_monotonic_seconds"])
                    < float(acknowledgement["acknowledged_monotonic_seconds"])
                    or not _valid_authority_status(
                        acknowledgement.get("recovered_authority_anchor"),
                        fenced=False,
                        terminal=True,
                    )
                    or {
                        "lifetime_id": acknowledgement["recovered_authority_anchor"].get(
                            "lifetime_id"
                        ),
                        "namespace_process_id": acknowledgement["recovered_authority_anchor"].get(
                            "namespace_process_id"
                        ),
                    }
                    != marker.get("expected_recovered_authority_identity")
                ):
                    acknowledgement = None
                if acknowledgement is not None:
                    return cast(dict[str, Any], acknowledgement)
        time.sleep(0.1)
    _require_workload_running(workload, context=f"waiting for restart {required_field}")
    raise RuntimeError(
        f"workload did not provide exact restart {required_field}: marker={marker!r} last={last!r}"
    )


def _arm_restart_window(
    harness: Harness,
    *,
    episode: int,
    service: str,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    restart_id = f"{harness.project}-planned-restart-{episode:06d}-{service}"
    script = (
        "import json,sys,time; from pathlib import Path; "
        f"target=Path({WORKLOAD_RESTART_PATH!r}); temporary=target.with_suffix('.tmp'); "
        f"Path({WORKLOAD_RESTART_ACK_PATH!r}).unlink(missing_ok=True); "
        "document={'armed_monotonic_seconds':time.monotonic(),"
        "'episode':int(sys.argv[1]),'restart_id':sys.argv[2],"
        "'service':sys.argv[3],'state':'armed'}; "
        "temporary.write_text(json.dumps(document,sort_keys=True)+'\\n'); "
        "temporary.replace(target); print(json.dumps(document,sort_keys=True))"
    )
    _require_workload_running(workload, context=f"before arming planned restart {episode}")
    host_armed_started = time.monotonic()
    process = harness.run(
        [
            "docker",
            "exec",
            harness.workload_container,
            "python",
            "-c",
            script,
            str(episode),
            restart_id,
            service,
        ],
        timeout=30,
    )
    try:
        marker = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"planned restart marker was malformed: {process.stdout!r}") from exc
    if (
        not isinstance(marker, dict)
        or marker.get("episode") != episode
        or marker.get("restart_id") != restart_id
        or marker.get("service") != service
        or marker.get("state") != "armed"
        or not isinstance(marker.get("armed_monotonic_seconds"), (int, float))
        or isinstance(marker.get("armed_monotonic_seconds"), bool)
    ):
        raise RuntimeError(f"planned restart marker identity mismatch: {marker!r}")
    acknowledgement = _wait_restart_acknowledgement(
        harness,
        marker=marker,
        required_field="acknowledged_monotonic_seconds",
        workload=workload,
    )
    return {
        "acknowledgement": acknowledgement,
        "host_armed_started_monotonic_seconds": host_armed_started,
        "host_monitor_acknowledged_monotonic_seconds": time.monotonic(),
        "marker": marker,
    }


def _complete_restart_window(
    harness: Harness,
    *,
    armed: dict[str, Any],
    completion_deadline_monotonic: float,
    replacement_authority: dict[str, Any],
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    marker = cast(dict[str, Any], armed["marker"])
    replacement_identity = {
        "lifetime_id": replacement_authority.get("lifetime_id"),
        "namespace_process_id": replacement_authority.get("namespace_process_id"),
    }
    if not _valid_authority_status(replacement_authority, fenced=False, terminal=True):
        raise RuntimeError("planned restart replacement authority is invalid")
    script = (
        "import json,sys,time; from pathlib import Path; "
        f"target=Path({WORKLOAD_RESTART_PATH!r}); document=json.loads(target.read_text()); "
        "assert document['restart_id']==sys.argv[1] and document['state']=='armed'; "
        "document['expected_recovered_authority_identity']=json.loads(sys.argv[2]); "
        "document['completed_monotonic_seconds']=time.monotonic(); "
        "document['state']='completed'; temporary=target.with_suffix('.tmp'); "
        "temporary.write_text(json.dumps(document,sort_keys=True)+'\\n'); "
        "temporary.replace(target); print(json.dumps(document,sort_keys=True))"
    )
    host_completion_started = time.monotonic()
    remaining = completion_deadline_monotonic - host_completion_started
    if remaining <= 0:
        raise RuntimeError("planned restart exceeded its 30s completion-marker budget")
    process = harness.run(
        [
            "docker",
            "exec",
            harness.workload_container,
            "python",
            "-c",
            script,
            str(marker["restart_id"]),
            json.dumps(replacement_identity, sort_keys=True, separators=(",", ":")),
        ],
        timeout=remaining,
    )
    try:
        completed_marker = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"completed restart marker was malformed: {process.stdout!r}") from exc
    if (
        not isinstance(completed_marker, dict)
        or any(
            completed_marker.get(key) != marker.get(key)
            for key in ("armed_monotonic_seconds", "episode", "restart_id", "service")
        )
        or completed_marker.get("state") != "completed"
        or not isinstance(completed_marker.get("completed_monotonic_seconds"), (int, float))
        or isinstance(completed_marker.get("completed_monotonic_seconds"), bool)
    ):
        raise RuntimeError(f"completed restart marker identity mismatch: {completed_marker!r}")
    recovery = _wait_restart_acknowledgement(
        harness,
        marker=completed_marker,
        required_field="recovered_monotonic_seconds",
        workload=workload,
    )
    if recovery.get("recovered_authority_anchor") != replacement_authority:
        raise RuntimeError("sampler recovery did not bind the exact replacement authority")
    cleanup_script = (
        "import json,sys; from pathlib import Path; "
        f"marker=Path({WORKLOAD_RESTART_PATH!r}); ack=Path({WORKLOAD_RESTART_ACK_PATH!r}); "
        "document=json.loads(marker.read_text()); acknowledgement=json.loads(ack.read_text()); "
        "assert document['restart_id']==sys.argv[1]==acknowledgement['restart_id']; "
        "marker.unlink(); ack.unlink()"
    )
    harness.run(
        [
            "docker",
            "exec",
            harness.workload_container,
            "python",
            "-c",
            cleanup_script,
            str(marker["restart_id"]),
        ],
        timeout=30,
    )
    return {
        "host_completed_marker_monotonic_seconds": host_completion_started,
        "host_monitor_recovered_monotonic_seconds": time.monotonic(),
        "marker": completed_marker,
        "recovery_acknowledgement": recovery,
    }


def _settle_cluster(harness: Harness, episode: int) -> dict[str, Any]:
    output_path = f"/scenario/soak-settle-{episode:06d}.json"
    timeout = harness.configuration.convergence_timeout_seconds
    harness.compose(
        "run",
        "--rm",
        "--no-deps",
        "scenario",
        "python",
        "/app/deploy/production/acceptance/soak.py",
        "settle",
        "--convergence-timeout-seconds",
        str(timeout),
        "--retry-timeout-seconds",
        str(harness.configuration.retry_timeout_seconds),
        "--seed",
        str(harness.configuration.seed + 2_000_000 + episode),
        "--output",
        output_path,
        timeout=timeout + harness.configuration.retry_timeout_seconds + 120,
    )
    result = _scenario_result(harness, output_path)
    if result.get("converged") is not True or result.get("status") != "passed":
        raise RuntimeError(f"cluster did not settle before partition: {result!r}")
    return result


def _partition_probe(harness: Harness, episode: int) -> dict[str, Any]:
    output_path = f"/scenario/soak-partition-{episode:06d}.json"
    observation_timeout = min(30.0, harness.configuration.retry_timeout_seconds)
    harness.compose(
        "run",
        "--rm",
        "--no-deps",
        "scenario",
        "python",
        "/app/deploy/production/acceptance/soak.py",
        "partition-probe",
        "--episode",
        str(episode),
        "--observation-timeout-seconds",
        str(observation_timeout),
        "--retry-timeout-seconds",
        str(harness.configuration.retry_timeout_seconds),
        "--seed",
        str(harness.configuration.seed + 1_000_000 + episode),
        "--output",
        output_path,
        timeout=observation_timeout + harness.configuration.retry_timeout_seconds + 120,
    )
    result = _scenario_result(harness, output_path)
    source = result.get("source")
    target = result.get("target")
    expected = (("warden-a", "warden-b"), ("warden-b", "warden-a"))[episode % 2]
    if (
        result.get("durably_pending_observed") is not True
        or (source, target) != expected
        or result.get("status") != "passed"
    ):
        raise RuntimeError(f"partition probe returned invalid observation: {result!r}")

    deadline = time.monotonic() + observation_timeout
    durable: dict[str, Any] | None = None
    candidate: Any = None
    while time.monotonic() < deadline:
        candidate = _container_json(
            harness,
            cast(str, source),
            PENDING_TRANSFER_PROBE,
            str(result["transfer_id"]),
            cast(str, target),
        )
        if (
            isinstance(candidate, dict)
            and candidate.get("transfer_id") == result["transfer_id"]
            and int(candidate.get("sequence", -1)) == int(result["sequence"])
            and candidate.get("status") == "PREPARED"
            and int(candidate.get("attempts", 0)) >= 1
            and candidate.get("has_error") == 1
            and candidate.get("delivered_at_ns") is None
            and candidate.get("superseded_at_ns") is None
        ):
            durable = cast(dict[str, Any], candidate)
            break
        time.sleep(0.1)
    if durable is None:
        raise RuntimeError(
            f"partition {episode} did not persist an exact failed A/B transfer: {candidate!r}"
        )
    result["durable_sql"] = durable
    return result


def _wait_partition_recovery(
    harness: Harness, partitions: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + harness.configuration.convergence_timeout_seconds
    last: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        last = []
        recovered = True
        for partition in partitions:
            observation = cast(dict[str, Any], partition["observation"])
            source = str(observation["source"])
            target = str(observation["target"])
            sequence = int(observation["sequence"])
            outgoing = _container_json(harness, source, OUTGOING_STREAM_PROBE, target)
            incoming = _container_json(harness, target, INCOMING_STREAM_PROBE, source)
            passed = (
                isinstance(outgoing, dict)
                and int(outgoing.get("acked_through", -1)) >= sequence
                and int(outgoing.get("compacted_through", -1)) >= sequence
                and isinstance(incoming, dict)
                and int(incoming.get("contiguous_through", -1)) >= sequence
                and int(incoming.get("compacted_through", -1)) >= sequence
            )
            recovered = recovered and passed
            last.append(
                {
                    "episode": int(observation["episode"]),
                    "incoming_stream": incoming,
                    "outgoing_stream": outgoing,
                    "passed": passed,
                    "sequence": sequence,
                    "source": source,
                    "target": target,
                }
            )
        if recovered:
            return last
        time.sleep(0.5)
    raise RuntimeError(f"exact partition transfer streams did not recover: {last!r}")


def _final_verify(harness: Harness) -> dict[str, Any]:
    command_error: BaseException | None = None
    returncode = -1
    try:
        process = harness.run(
            [
                *harness.compose_command,
                "run",
                "--rm",
                "--no-deps",
                "scenario",
                "python",
                "/app/deploy/production/acceptance/soak.py",
                "verify",
                "--convergence-timeout-seconds",
                str(harness.configuration.convergence_timeout_seconds),
                "--retry-timeout-seconds",
                str(harness.configuration.retry_timeout_seconds),
                "--seed",
                str(harness.configuration.seed),
                "--output",
                "/scenario/soak-verification.json",
            ],
            check=False,
            timeout=harness.configuration.convergence_timeout_seconds + 120,
        )
        returncode = process.returncode
    except BaseException as exc:
        command_error = exc
    try:
        result = _scenario_result(harness, "/scenario/soak-verification.json")
    except BaseException:
        if command_error is not None:
            raise command_error from None
        raise
    if command_error is not None:
        raise FinalVerificationError(result, returncode=returncode) from command_error
    if returncode != 0 or result.get("status") != "passed":
        raise FinalVerificationError(result, returncode=returncode)
    return result


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _write_evidence_atomic(output: Path, evidence: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def _bounded_records(records: list[dict[str, Any]], *, maximum: int) -> list[dict[str, Any]]:
    if len(records) <= maximum:
        return list(records)
    leading = maximum // 2
    return [*records[:leading], *records[-(maximum - leading) :]]


def _partial_resource_evidence(
    samples: list[dict[str, Any]],
    *,
    bounds: ResourceBounds,
    cycles: int,
    evaluation: dict[str, Any] | None,
) -> dict[str, Any]:
    retained = _bounded_records(samples, maximum=FAILED_EVIDENCE_MAX_RESOURCE_SAMPLES)
    if evaluation is None:
        if len(samples) < 2:
            evaluation = {
                "bounds": asdict(bounds),
                "passed": False,
                "reason": "fewer than two resource samples were captured",
                "violations": ["incomplete_resource_sampling"],
            }
        else:
            try:
                evaluation = evaluate_resource_bounds(
                    samples,
                    cycles=max(0, cycles),
                    bounds=bounds,
                )
            except Exception as exc:
                evaluation = {
                    "bounds": asdict(bounds),
                    "passed": False,
                    "reason": _bounded_text(str(exc)),
                    "violations": ["resource_evaluation_error"],
                }
    return {
        "evaluation": evaluation,
        "sample_count": len(samples),
        "samples": retained,
        "samples_retained": len(retained),
        "samples_truncated": len(samples) - len(retained),
    }


def _failed_workload_status(
    workload: subprocess.Popen[str] | None,
    *,
    stdout: str,
    stderr: str,
    error: Exception,
) -> dict[str, Any]:
    if isinstance(error, WorkloadExitedError):
        stdout = error.stdout
        stderr = error.stderr
    if workload is None:
        return {
            "host_cli_terminated": True,
            "return_code": None,
            "started": False,
            "state": "not_started",
            "stderr": _bounded_text(stderr),
            "stdout": _bounded_text(stdout),
        }
    state = "exited"
    collection_error: str | None = None
    try:
        if workload.poll() is None:
            state = "terminated_after_orchestration_failure"
            workload.terminate()
        try:
            collected_stdout, collected_stderr = workload.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            state = "killed_after_orchestration_failure"
            workload.kill()
            collected_stdout, collected_stderr = workload.communicate(timeout=10)
        stdout = stdout or collected_stdout
        stderr = stderr or collected_stderr
    except Exception as exc:
        collection_error = _bounded_text(str(exc))
        if workload.poll() is None:
            try:
                state = "killed_after_collection_failure"
                workload.kill()
                collected_stdout, collected_stderr = workload.communicate(timeout=10)
                stdout = stdout or collected_stdout
                stderr = stderr or collected_stderr
            except Exception as kill_error:
                collection_error = _bounded_text(
                    f"{collection_error}; {type(kill_error).__name__}: {kill_error}"
                )
    result: dict[str, Any] = {
        "host_cli_terminated": workload.poll() is not None,
        "pid": workload.pid,
        "return_code": workload.poll(),
        "started": True,
        "state": state,
        "stderr": _bounded_text(stderr),
        "stdout": _bounded_text(stdout),
    }
    if collection_error is not None:
        result["collection_error"] = collection_error
    return result


def _failed_workload_container_listing(
    harness: Harness,
    *,
    timeout: float,
) -> tuple[str, str] | None:
    """Return the exact named one-off workload only; reject ambiguous Docker output."""

    name = harness.workload_container
    if CONTAINER_NAME.fullmatch(name) is None:
        raise RuntimeError("refusing to inspect an invalid workload container name")
    output = harness.run(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--filter",
            f"name=^/{name}$",
            "--format",
            "{{.ID}}\t{{.Names}}",
        ],
        timeout=timeout,
    ).stdout
    rows = [line.split("\t") for line in output.splitlines() if line.strip()]
    if not rows:
        return None
    if len(rows) != 1 or len(rows[0]) != 2:
        raise RuntimeError("exact workload container inspection returned ambiguous output")
    container_id, listed_name = (item.strip() for item in rows[0])
    if listed_name != name or CONTAINER_ID.fullmatch(container_id) is None:
        raise RuntimeError("exact workload container inspection returned an invalid identity")
    return container_id, listed_name


def _remove_failed_workload_container(
    harness: Harness,
    *,
    host_cli_terminated: bool,
    timeout: float = FAILURE_COMMAND_TIMEOUT_SECONDS,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Fail closed around removal of the exact Compose one-off workload container."""

    name = harness.workload_container
    cleanup_result = {} if result is None else result
    cleanup_result.update(
        {
            "attempted": False,
            "container_name": name,
            "force_removed": False,
            "found": False,
            "labels_validated": False,
            "remaining": False,
        }
    )
    if host_cli_terminated is not True:
        raise RuntimeError("refusing workload cleanup while the host Compose CLI is still active")
    cleanup_result["attempted"] = True
    listed = _failed_workload_container_listing(harness, timeout=timeout)
    if listed is None:
        return cleanup_result
    container_id, _ = listed
    cleanup_result["found"] = True
    cleanup_result["remaining"] = True
    inspection = harness.run(
        [
            "docker",
            "container",
            "inspect",
            "--format",
            "{{json .}}",
            name,
        ],
        timeout=timeout,
    ).stdout
    try:
        document = json.loads(inspection)
    except json.JSONDecodeError as exc:
        raise RuntimeError("exact workload container inspect returned malformed JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError("exact workload container inspect returned a non-object")
    inspected_id = document.get("Id")
    config = document.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    expected_labels = {
        "com.docker.compose.oneoff": "True",
        "com.docker.compose.project": harness.project,
        "com.docker.compose.service": "scenario",
    }
    if (
        document.get("Name") != f"/{name}"
        or not isinstance(inspected_id, str)
        or len(inspected_id) != 64
        or CONTAINER_ID.fullmatch(inspected_id) is None
        or not inspected_id.startswith(container_id)
        or not isinstance(labels, dict)
        or any(labels.get(key) != value for key, value in expected_labels.items())
    ):
        raise RuntimeError(
            "refusing to remove a workload container with mismatched identity labels"
        )
    cleanup_result["labels_validated"] = True
    harness.run(
        ["docker", "container", "rm", "--force", inspected_id],
        timeout=timeout,
    )
    cleanup_result["force_removed"] = True
    cleanup_result["remaining"] = (
        _failed_workload_container_listing(harness, timeout=timeout) is not None
    )
    if cleanup_result["remaining"] is True:
        raise RuntimeError("exact workload container remained after forced removal")
    return cleanup_result


def _inspect_restart_target(
    harness: Harness,
    *,
    service: str,
    container: str,
    timeout: float,
) -> dict[str, Any]:
    raw = harness.run(
        ["docker", "container", "inspect", "--format", "{{json .}}", container],
        timeout=timeout,
    ).stdout
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("planned restart target inspect returned malformed JSON") from exc
    if not isinstance(document, dict):
        raise RuntimeError("planned restart target inspect returned a non-object")
    container_id = document.get("Id")
    state = document.get("State")
    config = document.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    restart_count = document.get("RestartCount")
    expected_labels = {
        "com.docker.compose.oneoff": "False",
        "com.docker.compose.project": harness.project,
        "com.docker.compose.service": service,
    }
    if (
        not isinstance(container_id, str)
        or CONTAINER_ID.fullmatch(container_id) is None
        or len(container_id) != 64
        or not container_id.startswith(container)
        or not isinstance(state, dict)
        or not isinstance(labels, dict)
        or any(labels.get(key) != value for key, value in expected_labels.items())
        or type(restart_count) is not int
        or type(state.get("Pid")) is not int
        or int(state["Pid"]) <= 0
    ):
        raise RuntimeError("planned restart target identity is invalid")
    return {
        "container_id": container_id,
        "host_pid": int(state["Pid"]),
        "oom_killed": state.get("OOMKilled"),
        "restart_count": restart_count,
        "state": {
            "OOMKilled": state.get("OOMKilled"),
            "Pid": int(state["Pid"]),
            "Status": state.get("Status"),
        },
        "status": state.get("Status"),
    }


def _fence_restart_authority(
    harness: Harness,
    *,
    service: str,
    armed: dict[str, Any],
    prior_identity: dict[str, Any],
    deadline_monotonic: float,
    attempt_evidence: dict[str, Any] | None = None,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    def available() -> float:
        return max(0.0, deadline_monotonic - time.monotonic())

    _require_workload_running(workload, context=f"before fencing {service} authority")
    marker = armed.get("marker")
    acknowledgement = armed.get("acknowledgement")
    if not isinstance(marker, dict) or not isinstance(acknowledgement, dict):
        raise RuntimeError("planned restart lacks an exact workload acknowledgement")
    prior_authority = acknowledgement.get("prior_authority_anchor")
    expected_lifetime = (
        prior_authority.get("lifetime_id") if isinstance(prior_authority, dict) else None
    )
    restart_id = marker.get("restart_id")
    if (
        not isinstance(prior_authority, dict)
        or prior_authority.get("enabled") is not True
        or prior_authority.get("state") != "healthy"
        or prior_authority.get("healthy") is not True
        or prior_authority.get("admission_fenced") is not False
        or not isinstance(expected_lifetime, str)
        or re.fullmatch(r"[0-9a-f]{32}", expected_lifetime) is None
        or not isinstance(restart_id, str)
    ):
        raise RuntimeError("planned restart acknowledgement authority status is invalid")
    evidence = {} if attempt_evidence is None else attempt_evidence
    attempts: list[dict[str, Any]] = []
    evidence.update(
        {
            "attempts": attempts,
            "completed_monotonic_seconds": None,
            "deadline_monotonic_seconds": deadline_monotonic,
            "expected_lifetime_id": expected_lifetime,
            "resolved": False,
            "restart_id": restart_id,
            "started_monotonic_seconds": time.monotonic(),
            "status": "in_progress",
        }
    )

    def exception_type(error: BaseException) -> str:
        return f"{type(error).__module__}.{type(error).__qualname__}"[:128]

    def valid_result(result: object) -> bool:
        terminal = result.get("terminal") if isinstance(result, dict) else None
        terminal_authority = (
            terminal.get("authority_anchor") if isinstance(terminal, dict) else None
        )
        return bool(
            isinstance(result, dict)
            and set(result) == {"node", "request_retry_count", "schema", "status", "terminal"}
            and result.get("schema") == "lets.production-profile-authority-fence/v1"
            and result.get("status") == "passed"
            and result.get("node") == service
            and type(result.get("request_retry_count")) is int
            and result["request_retry_count"] >= 0
            and isinstance(terminal, dict)
            and set(terminal)
            == {
                "authority_anchor",
                "fenced_at_monotonic_ns",
                "lifetime_id",
                "namespace_process_id",
                "restart_id",
                "schema",
                "warden_id",
            }
            and terminal.get("schema") == "lets.authority-admission-fence/v1"
            and type(terminal.get("namespace_process_id")) is int
            and terminal["namespace_process_id"] > 0
            and type(terminal.get("fenced_at_monotonic_ns")) is int
            and terminal["fenced_at_monotonic_ns"] >= 0
            and terminal.get("restart_id") == restart_id
            and terminal.get("warden_id") == service
            and terminal.get("lifetime_id") == expected_lifetime
            and _valid_authority_status(terminal_authority, fenced=True, terminal=True)
            and terminal_authority.get("lifetime_id") == expected_lifetime
            and terminal_authority.get("fence_id") == restart_id
            and terminal.get("namespace_process_id")
            == terminal_authority.get("namespace_process_id")
            and terminal.get("fenced_at_monotonic_ns")
            == terminal_authority.get("fenced_at_monotonic_ns")
            and terminal_authority.get("namespace_process_id")
            == prior_authority.get("namespace_process_id")
            and all(
                cast(int, terminal_authority.get(field_name))
                >= cast(int, prior_authority.get(field_name))
                for field_name in AUTHORITY_COUNTER_FIELDS
            )
            and (
                prior_authority.get("first_fault") is None
                or terminal_authority.get("first_fault") == prior_authority.get("first_fault")
            )
        )

    def record_read(
        attempt: dict[str, Any],
        *,
        error: BaseException | None,
        outcome: str,
        returncode: int | None,
    ) -> None:
        observation = {
            "completed_monotonic_seconds": time.monotonic(),
            "error_type": None if error is None else exception_type(error),
            "outcome": outcome,
            "returncode": returncode,
        }
        attempt["read_count"] = min(
            AUTHORITY_COUNTER_MAX,
            cast(int, attempt["read_count"]) + 1,
        )
        if attempt["first_read"] is None:
            attempt["first_read"] = observation
        attempt["last_read"] = observation

    output_attempts: list[tuple[str, dict[str, Any]]] = []
    maximum_post_attempts = 5
    attempt_window = max(
        0.0,
        deadline_monotonic - cast(float, evidence["started_monotonic_seconds"]),
    )
    post_spacing = max(0.25, (attempt_window - 3.0) / (maximum_post_attempts - 1))
    evidence["post_spacing_seconds"] = post_spacing
    next_post_at = cast(float, evidence["started_monotonic_seconds"])
    while time.monotonic() < deadline_monotonic:
        if (
            len(attempts) < maximum_post_attempts
            and time.monotonic() >= next_post_at
            and available() > 1.75
        ):
            attempt_number = len(attempts) + 1
            output_path = (
                "/scenario/authority-fence-"
                f"{int(marker['episode']):06d}-attempt-{attempt_number}.json"
            )
            exec_timeout = min(7.0, max(0.05, available() - 1.5))
            attempt = {
                "exec_completed_monotonic_seconds": None,
                "exec_error_type": None,
                "exec_returncode": None,
                "exec_started_monotonic_seconds": time.monotonic(),
                "exec_timeout_seconds": exec_timeout,
                "first_read": None,
                "last_read": None,
                "ordinal": attempt_number,
                "output_path": output_path,
                "read_count": 0,
            }
            attempts.append(attempt)
            output_attempts.append((output_path, attempt))
            next_post_at = cast(float, evidence["started_monotonic_seconds"]) + (
                len(attempts) * post_spacing
            )
            command = [
                "docker",
                "exec",
                harness.workload_container,
                "python",
                "/app/deploy/production/acceptance/soak.py",
                "fence-authority",
                "--node",
                service,
                "--restart-id",
                restart_id,
                "--expected-lifetime-id",
                expected_lifetime,
                "--retry-timeout-seconds",
                str(min(7.0, exec_timeout)),
                "--seed",
                str(harness.configuration.seed + 3_000_000 + int(marker["episode"])),
                "--output",
                output_path,
            ]
            try:
                executed = harness.run(command, check=False, timeout=exec_timeout)
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                attempt["exec_error_type"] = exception_type(exc)
            else:
                attempt["exec_returncode"] = executed.returncode
            attempt["exec_completed_monotonic_seconds"] = time.monotonic()

        for candidate_path, attempt in reversed(output_attempts):
            if time.monotonic() >= deadline_monotonic:
                break
            read_script = (
                "import json; from pathlib import Path; "
                f"print(json.dumps(json.loads(Path({candidate_path!r}).read_text()),sort_keys=True))"
            )
            read_timeout = min(1.5, available())
            if read_timeout <= 0:
                break
            try:
                read = harness.run(
                    ["docker", "exec", harness.workload_container, "python", "-c", read_script],
                    check=False,
                    timeout=read_timeout,
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                record_read(attempt, error=exc, outcome="command_error", returncode=None)
                continue
            if read.returncode != 0:
                record_read(
                    attempt,
                    error=None,
                    outcome="command_error",
                    returncode=read.returncode,
                )
                continue
            try:
                result = json.loads(read.stdout)
            except json.JSONDecodeError:
                record_read(attempt, error=None, outcome="malformed_json", returncode=0)
                continue
            if not valid_result(result):
                record_read(attempt, error=None, outcome="invalid_response", returncode=0)
                continue
            record_read(attempt, error=None, outcome="valid", returncode=0)
            evidence.update(
                {
                    "completed_monotonic_seconds": time.monotonic(),
                    "resolved": True,
                    "resolved_attempt": attempt["ordinal"],
                    "status": "resolved",
                }
            )
            return {
                "host_container_id": prior_identity["container_id"],
                "host_exec_attempts": len(attempts),
                "host_pid": prior_identity["host_pid"],
                "prior_authority_anchor": prior_authority,
                "result": result,
            }
        if time.monotonic() < deadline_monotonic:
            time.sleep(min(0.1, deadline_monotonic - time.monotonic()))
    evidence.update(
        {
            "completed_monotonic_seconds": time.monotonic(),
            "resolved": False,
            "status": "unresolved",
        }
    )
    raise RuntimeError("authority fence response remained unresolved before the restart deadline")


def _read_restarted_authority(
    harness: Harness,
    *,
    service: str,
    episode: int,
    deadline_monotonic: float,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    """Fetch authenticated no-transaction status for the exact replacement lifetime."""

    def remaining() -> float:
        value = deadline_monotonic - time.monotonic()
        if value <= 0:
            raise RuntimeError("replacement authority check exceeded the restart deadline")
        return value

    _require_workload_running(workload, context=f"binding {service} replacement authority")
    output_path = f"/scenario/authority-status-{episode:06d}.json"
    process = harness.run(
        [
            "docker",
            "exec",
            harness.workload_container,
            "python",
            "/app/deploy/production/acceptance/soak.py",
            "authority-status",
            "--node",
            service,
            "--retry-timeout-seconds",
            str(min(7.0, remaining())),
            "--seed",
            str(harness.configuration.seed + 4_000_000 + episode),
            "--output",
            output_path,
        ],
        timeout=remaining(),
    )
    if process.returncode != 0:
        raise RuntimeError("replacement authority status command failed")
    read_script = (
        "import json; from pathlib import Path; "
        f"print(json.dumps(json.loads(Path({output_path!r}).read_text()),sort_keys=True))"
    )
    raw = harness.run(
        ["docker", "exec", harness.workload_container, "python", "-c", read_script],
        timeout=remaining(),
    ).stdout
    try:
        result = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("replacement authority evidence was malformed") from exc
    authority = result.get("authority_anchor") if isinstance(result, dict) else None
    if (
        not isinstance(result, dict)
        or result.get("schema") != "lets.production-profile-authority-status/v1"
        or result.get("status") != "passed"
        or result.get("node") != service
        or not _valid_authority_status(authority, fenced=False, terminal=True)
    ):
        raise RuntimeError("replacement authority evidence is invalid")
    return authority


def _restart(
    harness: Harness,
    service: str,
    *,
    armed: dict[str, Any],
    completion_deadline_monotonic: float,
    elapsed_s: float,
    evidence_record: dict[str, Any] | None = None,
    workload: subprocess.Popen[str],
) -> dict[str, Any]:
    operation_started = time.monotonic()
    if completion_deadline_monotonic <= operation_started:
        raise RuntimeError("planned restart began after its 30s completion budget")

    def remaining() -> float:
        value = completion_deadline_monotonic - time.monotonic()
        if value <= 0:
            raise RuntimeError("planned restart exceeded its 30s completion budget")
        return value

    prior_container = harness.container(service, timeout=remaining())
    prior_identity = _inspect_restart_target(
        harness,
        service=service,
        container=prior_container,
        timeout=remaining(),
    )
    prior_container = cast(str, prior_identity["container_id"])
    prior = cast(dict[str, Any], prior_identity["state"])
    prior_pid = cast(int, prior_identity["host_pid"])
    prior_restart_count = cast(int, prior_identity["restart_count"])
    if evidence_record is not None:
        evidence_record.update(
            {
                "elapsed_seconds": round(elapsed_s, 3),
                "prior_container_id": prior_container,
                "prior_pid": prior_pid,
                "service": service,
                "status": "restart_target_bound",
            }
        )
    if (
        prior.get("Status") != "running"
        or prior.get("OOMKilled") is not False
        or prior_restart_count != 0
    ):
        raise RuntimeError(f"{service} was unhealthy before planned SIGKILL: {prior!r}")
    marker = cast(dict[str, Any], armed.get("marker"))
    authority_fence_attempt: dict[str, Any] = {
        "episode": marker.get("episode"),
        "service": service,
    }
    if evidence_record is not None:
        evidence_record.update(
            {
                "authority_fence_attempt": authority_fence_attempt,
                "status": "authority_fence_in_progress",
            }
        )
    try:
        authority_fence = _fence_restart_authority(
            harness,
            service=service,
            armed=armed,
            prior_identity=prior_identity,
            deadline_monotonic=completion_deadline_monotonic,
            attempt_evidence=authority_fence_attempt,
            workload=workload,
        )
    except BaseException:
        if evidence_record is not None:
            evidence_record["status"] = "authority_fence_unresolved"
        raise
    if evidence_record is not None:
        evidence_record.update(
            {
                "authority_fence": authority_fence,
                "status": "authority_fenced",
            }
        )
    reinspection = _inspect_restart_target(
        harness,
        service=service,
        container=prior_container,
        timeout=remaining(),
    )
    if reinspection != prior_identity:
        raise RuntimeError("planned restart target changed after authority admission was fenced")
    harness.run(
        ["docker", "container", "kill", "--signal", "SIGKILL", prior_container],
        timeout=remaining(),
    )
    killed = harness.container_state(prior_container, timeout=remaining())
    killed_restart_count = harness.container_restart_count(
        prior_container,
        timeout=remaining(),
    )
    if (
        killed.get("Status") != "exited"
        or int(killed.get("ExitCode", -1)) != 137
        or killed.get("OOMKilled") is not False
        or killed_restart_count != 0
    ):
        raise RuntimeError(f"{service} did not stop only by planned SIGKILL: {killed!r}")
    harness.compose(
        "up",
        "-d",
        "--no-deps",
        "--force-recreate",
        service,
        timeout=remaining(),
    )
    harness.wait_healthy(service, timeout_s=remaining())
    restarted_container = harness.container(service, timeout=remaining())
    restarted_identity = _inspect_restart_target(
        harness,
        service=service,
        container=restarted_container,
        timeout=remaining(),
    )
    restarted_container = cast(str, restarted_identity["container_id"])
    restarted = cast(dict[str, Any], restarted_identity["state"])
    restarted_pid = cast(int, restarted_identity["host_pid"])
    restarted_count = cast(int, restarted_identity["restart_count"])
    episode = cast(int, cast(dict[str, Any], armed["marker"])["episode"])
    restarted_authority = _read_restarted_authority(
        harness,
        service=service,
        episode=episode,
        deadline_monotonic=completion_deadline_monotonic,
        workload=workload,
    )
    old_authority = cast(dict[str, Any], authority_fence["prior_authority_anchor"])
    if (
        restarted_container == prior_container
        or restarted_pid == prior_pid
        or restarted.get("Status") != "running"
        or restarted.get("OOMKilled") is not False
        or restarted_count != 0
        or restarted_authority["lifetime_id"] == old_authority["lifetime_id"]
    ):
        raise RuntimeError(f"{service} restart did not replace process {prior_pid}")
    operation_seconds = time.monotonic() - operation_started
    operation_completed = operation_started + operation_seconds
    result = {
        "completed_at_seconds": round(elapsed_s + operation_seconds, 3),
        "elapsed_seconds": round(elapsed_s, 3),
        "host_operation_completed_monotonic_seconds": operation_completed,
        "host_operation_started_monotonic_seconds": operation_started,
        "authority_fence": authority_fence,
        "new_container_id": restarted_container,
        "new_pid": restarted_pid,
        "new_authority_anchor": restarted_authority,
        "planned_exit_code": int(killed["ExitCode"]),
        "prior_container_id": prior_container,
        "prior_pid": prior_pid,
        "restart_counts": {
            "after": restarted_count,
            "killed": killed_restart_count,
            "prior": prior_restart_count,
        },
        "service": service,
        "signal": "SIGKILL",
        "status": "replacement_authority_bound",
    }
    if evidence_record is not None:
        evidence_record.update(result)
        return evidence_record
    return result


def _restart_integrity(
    harness: Harness,
    restarts: list[dict[str, Any]],
    *,
    chaos_completed_monotonic_seconds: float,
    chaos_started_monotonic_seconds: float,
) -> dict[str, Any]:
    killed_services = {str(item.get("service")) for item in restarts}
    missing_services = sorted(set(WARDENS) - killed_services)
    if len(restarts) < MIN_RESTART_EPISODES or missing_services:
        raise RuntimeError(
            "planned SIGKILL coverage is incomplete: "
            f"count={len(restarts)} missing={missing_services}"
        )
    final: dict[str, Any] = {}
    for service in WARDENS:
        state = harness.state(service)
        restart_count = harness.restart_count(service)
        if (
            state.get("Status") != "running"
            or state.get("OOMKilled") is not False
            or restart_count != 0
        ):
            raise RuntimeError(
                f"{service} has OOM or unplanned automatic restart evidence: "
                f"state={state!r} restart_count={restart_count}"
            )
        final[service] = {
            "exit_code": int(state.get("ExitCode", -1)),
            "oom_killed": bool(state.get("OOMKilled")),
            "restart_count": restart_count,
            "status": state.get("Status"),
        }
    if not chaos_started_monotonic_seconds < chaos_completed_monotonic_seconds:
        raise RuntimeError("chaos lifetime boundaries are invalid")
    chaos_duration_seconds = chaos_completed_monotonic_seconds - chaos_started_monotonic_seconds
    restart_operations = sorted(
        (
            float(item["host_operation_started_monotonic_seconds"])
            - chaos_started_monotonic_seconds,
            float(item["host_operation_completed_monotonic_seconds"])
            - chaos_started_monotonic_seconds,
        )
        for item in restarts
    )
    if not all(
        0 <= started < completed <= chaos_duration_seconds
        for started, completed in restart_operations
    ) or any(right[0] < left[1] for left, right in pairwise(restart_operations)):
        raise RuntimeError("planned SIGKILL lies outside the chaos lifetime")

    def process_lifetimes(operations: list[tuple[float, float]]) -> list[float]:
        lifetimes: list[float] = []
        prior_completed = 0.0
        for operation_started, operation_completed in operations:
            lifetimes.append(max(0.0, operation_started - prior_completed))
            prior_completed = operation_completed
        lifetimes.append(max(0.0, chaos_duration_seconds - prior_completed))
        return lifetimes

    gaps = process_lifetimes(restart_operations)
    longest = max(gaps, default=0.0)
    required = harness.configuration.restart_interval_seconds * 0.8
    if longest < required:
        raise RuntimeError(
            f"soak lacked a long uninterrupted SIGKILL-free window: {longest:.3f} < {required:.3f}"
        )
    per_warden_lifetimes: dict[str, Any] = {}
    for service in WARDENS:
        service_operations = sorted(
            (
                float(item["host_operation_started_monotonic_seconds"])
                - chaos_started_monotonic_seconds,
                float(item["host_operation_completed_monotonic_seconds"])
                - chaos_started_monotonic_seconds,
            )
            for item in restarts
            if item.get("service") == service
        )
        lifetimes = process_lifetimes(service_operations)
        longest_lifetime = max(lifetimes, default=0.0)
        if longest_lifetime < required:
            raise RuntimeError(
                f"{service} lacked a long uninterrupted process lifetime: "
                f"{longest_lifetime:.3f} < {required:.3f}"
            )
        per_warden_lifetimes[service] = {
            "longest_seconds": round(longest_lifetime, 3),
            "passed": True,
            "planned_sigkill_seconds": [round(started, 3) for started, _ in service_operations],
            "segments_seconds": [round(item, 3) for item in lifetimes],
        }
    return {
        "all_wardens_sigkilled": True,
        "chaos_duration_seconds": round(chaos_duration_seconds, 3),
        "final_container_state": final,
        "longest_sigkill_free_seconds": round(longest, 3),
        "minimum_sigkill_free_seconds": round(required, 3),
        "passed": True,
        "per_warden_lifetimes": per_warden_lifetimes,
        "planned_sigkills": len(restarts),
        "restart_count_policy": "all samples and final states equal zero",
    }


def run_soak(
    configuration: SoakConfiguration,
    *,
    output: Path,
    keep: bool = False,
    bounds: ResourceBounds | None = None,
) -> dict[str, Any]:
    resource_bounds = ResourceBounds() if bounds is None else bounds
    harness = Harness(configuration)
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic()
    source_before: dict[str, Any] = {"status": "not_captured"}
    image: dict[str, Any] = {
        "configured_digest": configuration.image,
        "status": "not_inspected",
    }
    partitions: list[dict[str, Any]] = []
    restarts: list[dict[str, Any]] = []
    resource_samples: list[dict[str, Any]] = []
    resource_evaluation: dict[str, Any] | None = None
    partition_recovery: list[dict[str, Any]] = []
    restart_integrity: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    package_identity: dict[str, Any] | None = None
    workload_result: dict[str, Any] = {}
    authority_evaluation: dict[str, Any] | None = None
    workload_evaluation: dict[str, Any] | None = None
    workload_start: dict[str, Any] | None = None
    workload: subprocess.Popen[str] | None = None
    workload_stdout = ""
    workload_stderr = ""
    partitioned = False
    workload_paused = False
    failure_logs = ""
    started_cluster = False
    cleanup_attempted = False
    cleanup: dict[str, Any] = {"performed": False, "reason": "not yet attempted"}
    preflight: dict[str, Any] = {"status": "not_run"}
    chaos_started: float | None = None
    chaos_completed: float | None = None
    phase = "configuration"
    try:
        output.unlink(missing_ok=True)
        configuration.validate()
        phase = "source_identity"
        source_before = _source_tree_digest(harness.environment)
        phase = "preflight"
        preflight = _preflight_zero(harness)
        harness.run(["docker", "pull", configuration.image], timeout=900)
        started_cluster = True
        phase = "cluster_startup"
        harness.compose("up", "-d", "--build", timeout=900)
        _wait_toxiproxy()
        _configure_proxies()
        for service in WARDENS:
            harness.wait_healthy(service)
        runtime_packages = _runtime_packages(harness)
        package_version = metadata.version("lets-agent")
        image = _image_identity(
            harness,
            expected_revision=str(source_before["git_commit"]),
            expected_version=package_version,
        )
        resource_samples.append(_resource_sample(harness, elapsed_s=0.0, reason="baseline"))

        phase = "mixed_workload_and_chaos"
        workload_command = [
            *harness.compose_command,
            "run",
            "--name",
            harness.workload_container,
            "--rm",
            "--no-deps",
            "scenario",
            "python",
            "/app/deploy/production/acceptance/soak.py",
            "run",
            "--duration-seconds",
            str(configuration.duration_seconds),
            "--cycle-interval-seconds",
            str(configuration.cycle_interval_seconds),
            "--health-interval-seconds",
            str(configuration.health_interval_seconds),
            "--retry-timeout-seconds",
            str(configuration.retry_timeout_seconds),
            "--transfer-every-cycles",
            str(configuration.transfer_every_cycles),
            "--executor-reopen-every-cycles",
            str(configuration.executor_reopen_every_cycles),
            "--seed",
            str(configuration.seed),
            "--run-id",
            f"{harness.project}-workload-run",
            "--output",
            "/scenario/soak-workload.json",
        ]
        workload = subprocess.Popen(
            workload_command,
            cwd=ROOT,
            env=harness.environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        workload_start = _wait_workload_start(
            harness,
            expected_run_id=f"{harness.project}-workload-run",
            workload=workload,
        )
        chaos_started = time.monotonic()
        next_partition = chaos_started + configuration.partition_interval_seconds
        restore_partition_at: float | None = None
        next_restart = chaos_started + configuration.restart_interval_seconds
        next_resource = chaos_started + configuration.resource_interval_seconds
        restart_index = 0
        while workload.poll() is None:
            now = time.monotonic()
            elapsed = now - chaos_started
            if (
                not partitioned
                and now >= next_partition
                and may_start_chaos_episode(configuration, elapsed_s=elapsed)
            ):
                episode = len(partitions)
                workload_paused = True
                pause_coordination = _pause_workload(harness, episode, workload)
                pause_coordination["host_acknowledged_at_seconds"] = round(
                    float(pause_coordination["host_acknowledged_monotonic_seconds"])
                    - chaos_started,
                    6,
                )
                settled = _settle_cluster(harness, episode)
                _set_partition(enabled=False)
                partitioned = True
                disabled_at = time.monotonic()
                partition = {
                    "disabled_at_seconds": round(disabled_at - chaos_started, 3),
                    "disabled_monotonic_seconds": disabled_at,
                    "episode": episode,
                    "links": ["a_to_b", "b_to_a"],
                    "workload_coordination": {
                        **pause_coordination,
                        "settled_before_disable": settled,
                    },
                }
                partitions.append(partition)
                observation = _partition_probe(harness, episode)
                observed_at = time.monotonic()
                partition["observation"] = observation
                partition["pending_observed_at_seconds"] = round(observed_at - chaos_started, 3)
                restore_partition_at = observed_at + configuration.partition_duration_seconds
                now = observed_at
                elapsed = now - chaos_started
            if partitioned and restore_partition_at is not None and now >= restore_partition_at:
                _set_partition(enabled=True)
                restored_monotonic = time.monotonic()
                partitioned = False
                authorized_end = _authorize_pause_end(harness)
                resume_coordination = _resume_workload(
                    harness,
                    authorized_end=authorized_end,
                )
                workload_paused = False
                partitions[-1]["workload_coordination"].update(resume_coordination)
                partitions[-1]["workload_coordination"]["authorized_end"] = authorized_end
                partitions[-1]["workload_coordination"]["host_resume_completed_at_seconds"] = round(
                    float(resume_coordination["host_resume_completed_monotonic_seconds"])
                    - chaos_started,
                    6,
                )
                partitions[-1]["workload_coordination"]["host_pause_duration_seconds"] = round(
                    float(resume_coordination["host_resume_started_monotonic_seconds"])
                    - float(
                        partitions[-1]["workload_coordination"][
                            "host_acknowledged_monotonic_seconds"
                        ]
                    ),
                    6,
                )
                pause_start = max(
                    0.0,
                    float(partitions[-1]["workload_coordination"]["host_acknowledged_at_seconds"]),
                )
                pause_end = min(
                    configuration.duration_seconds,
                    float(
                        partitions[-1]["workload_coordination"][
                            "host_resume_started_monotonic_seconds"
                        ]
                    )
                    - chaos_started,
                )
                partitions[-1]["workload_coordination"][
                    "host_measurement_clipped_pause_seconds"
                ] = round(max(0.0, pause_end - pause_start), 6)
                partitions[-1]["restored_at_seconds"] = round(
                    restored_monotonic - chaos_started,
                    3,
                )
                partitions[-1]["restored_monotonic_seconds"] = restored_monotonic
                partitions[-1]["duration_seconds"] = round(
                    float(partitions[-1]["restored_at_seconds"])
                    - float(partitions[-1]["disabled_at_seconds"]),
                    3,
                )
                next_partition = time.monotonic() + configuration.partition_interval_seconds
                restore_partition_at = None
            if now >= next_restart and may_start_chaos_episode(configuration, elapsed_s=elapsed):
                prior_restart_deadline = next_restart
                service = WARDENS[restart_index % len(WARDENS)]
                checkpoint_elapsed = time.monotonic() - chaos_started
                _require_workload_running(
                    workload,
                    context=f"before planned SIGKILL of {service}",
                )
                armed_restart = _arm_restart_window(
                    harness,
                    episode=restart_index,
                    service=service,
                    workload=workload,
                )
                resource_checkpoint = _pre_sigkill_resource_checkpoint(
                    harness,
                    service=service,
                    elapsed_s=checkpoint_elapsed,
                    samples=resource_samples,
                    configuration=configuration,
                    bounds=resource_bounds,
                )
                restart_completion_deadline = (
                    float(armed_restart["host_monitor_acknowledged_monotonic_seconds"])
                    + MAXIMUM_PLANNED_RESTART_SECONDS
                )
                restart_record: dict[str, Any] = {
                    "resource_checkpoint": resource_checkpoint,
                    "service": service,
                    "status": "armed",
                    "workload_coordination": {"armed": armed_restart},
                }
                restarts.append(restart_record)
                restart = _restart(
                    harness,
                    service,
                    armed=armed_restart,
                    completion_deadline_monotonic=restart_completion_deadline,
                    elapsed_s=checkpoint_elapsed,
                    evidence_record=restart_record,
                    workload=workload,
                )
                completed_restart = _complete_restart_window(
                    harness,
                    armed=armed_restart,
                    completion_deadline_monotonic=restart_completion_deadline,
                    replacement_authority=cast(dict[str, Any], restart["new_authority_anchor"]),
                    workload=workload,
                )
                restart["resource_checkpoint"] = resource_checkpoint
                restart["workload_coordination"] = {
                    "armed": armed_restart,
                    "completed": completed_restart,
                }
                restart["status"] = "completed"
                restart_index += 1
                next_restart = _next_restart_deadline(
                    prior_deadline=prior_restart_deadline,
                    interval_s=configuration.restart_interval_seconds,
                    completed_at=time.monotonic(),
                )
            if now >= next_resource:
                resource_samples.append(
                    _resource_sample(harness, elapsed_s=elapsed, reason="interval")
                )
                next_resource = time.monotonic() + configuration.resource_interval_seconds
            time.sleep(0.2)

        workload_stdout, workload_stderr = workload.communicate(timeout=30)
        if workload.returncode != 0:
            chaos_completed = time.monotonic()
            with suppress(Exception):
                workload_result = _scenario_result(
                    harness,
                    "/scenario/soak-workload.json",
                )
            raise RuntimeError(
                f"soak workload failed ({workload.returncode})\n{workload_stdout}{workload_stderr}"
            )
        if partitioned:
            if restore_partition_at is not None:
                while time.monotonic() < restore_partition_at:
                    time.sleep(min(0.2, restore_partition_at - time.monotonic()))
            _set_partition(enabled=True)
            restored_monotonic = time.monotonic()
            partitioned = False
            authorized_end = _authorize_pause_end(harness)
            resume_coordination = _resume_workload(
                harness,
                authorized_end=authorized_end,
            )
            workload_paused = False
            partitions[-1]["workload_coordination"].update(resume_coordination)
            partitions[-1]["workload_coordination"]["authorized_end"] = authorized_end
            partitions[-1]["workload_coordination"]["host_resume_completed_at_seconds"] = round(
                float(resume_coordination["host_resume_completed_monotonic_seconds"])
                - chaos_started,
                6,
            )
            partitions[-1]["workload_coordination"]["host_pause_duration_seconds"] = round(
                float(resume_coordination["host_resume_started_monotonic_seconds"])
                - float(
                    partitions[-1]["workload_coordination"]["host_acknowledged_monotonic_seconds"]
                ),
                6,
            )
            pause_start = max(
                0.0,
                float(partitions[-1]["workload_coordination"]["host_acknowledged_at_seconds"]),
            )
            pause_end = min(
                configuration.duration_seconds,
                float(
                    partitions[-1]["workload_coordination"]["host_resume_started_monotonic_seconds"]
                )
                - chaos_started,
            )
            partitions[-1]["workload_coordination"]["host_measurement_clipped_pause_seconds"] = (
                round(max(0.0, pause_end - pause_start), 6)
            )
            restored = restored_monotonic - chaos_started
            partitions[-1]["restored_at_seconds"] = round(restored, 3)
            partitions[-1]["restored_monotonic_seconds"] = restored_monotonic
            partitions[-1]["duration_seconds"] = round(
                restored - float(partitions[-1]["disabled_at_seconds"]),
                3,
            )
        chaos_completed = time.monotonic()
        for service in WARDENS:
            harness.wait_healthy(service)
        phase = "recovery_and_verification"
        partition_recovery = _wait_partition_recovery(harness, partitions)
        try:
            verification = _final_verify(harness)
        except FinalVerificationError as exc:
            verification = exc.result
            raise
        workload_result = _scenario_result(harness, "/scenario/soak-workload.json")
        workload_evaluation = evaluate_workload_result(
            workload_result,
            configuration,
            chaos_completed_monotonic=chaos_completed,
            chaos_started_monotonic=chaos_started,
            partitions=partitions,
            restarts=restarts,
            workload_start=workload_start,
        )
        authority_evaluation = evaluate_authority_evidence(
            workload_result,
            restarts,
            verification,
        )
        package_identity = validate_package_identity(
            host_version=package_version,
            image=image,
            runtime_packages=runtime_packages,
            workload=workload_result,
            verification=verification,
        )
        resource_samples.append(
            _resource_sample(
                harness,
                elapsed_s=time.monotonic() - chaos_started,
                reason="final",
            )
        )
        phase = "resource_evaluation"
        resource_evaluation = evaluate_resource_bounds(
            resource_samples,
            cycles=int(workload_result["cycles"]),
            bounds=resource_bounds,
        )
        partition_adequacy = len(partitions) >= 2 and all(
            cast(dict[str, Any], item.get("observation", {})).get("durably_pending_observed")
            is True
            for item in partitions
        )
        restart_integrity = _restart_integrity(
            harness,
            restarts,
            chaos_completed_monotonic_seconds=chaos_completed,
            chaos_started_monotonic_seconds=chaos_started,
        )
        adequacy_failures: list[str] = []
        if not workload_evaluation["passed"]:
            adequacy_failures.append(f"workload={workload_evaluation['violations']!r}")
        if authority_evaluation.get("passed") is not True:
            adequacy_failures.append(
                f"authority={authority_evaluation.get('reason', 'invalid evidence')!r}"
            )
        if not resource_evaluation["passed"]:
            adequacy_failures.append(f"resources={resource_evaluation['violations']!r}")
        if not partition_adequacy:
            adequacy_failures.append("partitions=incomplete durable partition coverage")
        if restart_integrity.get("passed") is not True:
            adequacy_failures.append("restarts=integrity verification failed")
        if adequacy_failures:
            raise RuntimeError("soak adequacy failed: " + "; ".join(adequacy_failures))
        source_after = _source_tree_digest(harness.environment)
        if source_after != source_before:
            raise RuntimeError("source tree changed while the production soak was running")
        completed_at = datetime.now(UTC)
        phase = "cleanup"
        cleanup = {
            "performed": False,
            "reason": "--keep requested for investigation",
        }
        if not keep:
            cleanup_attempted = True
            try:
                cleanup = _checked_down(harness)
            except Exception as cleanup_error:
                cleanup = {
                    "error": _bounded_text(str(cleanup_error)),
                    "performed": False,
                    "reason": "cleanup failed",
                }
                raise
            started_cluster = False
        phase = "evidence_publication"
        evidence: dict[str, Any] = {
            "chaos": {
                "partition_recovery": partition_recovery,
                "partitions": partitions,
                "restart_integrity": restart_integrity,
                "restarts": restarts,
            },
            "authority_evaluation": authority_evaluation,
            "cleanup": cleanup,
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "configuration": asdict(configuration),
            "duration_seconds": round(time.monotonic() - started_monotonic, 3),
            "image": image,
            "orchestration": {
                "chaos_completed_monotonic_seconds": chaos_completed,
                "chaos_started_monotonic_seconds": chaos_started,
                "compose_project": harness.project,
                "phase": "completed",
                "preflight": preflight,
                "workload_start": workload_start,
            },
            "package": {
                "host_lets_agent": package_version,
                "identity": package_identity,
                "runtime": runtime_packages,
            },
            "passed": True,
            "resources": {
                "evaluation": resource_evaluation,
                "sample_count": len(resource_samples),
                "samples": resource_samples,
            },
            "schema": "lets.production-profile-soak/v2",
            "source": source_before,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "verification": verification,
            "workload": workload_result,
            "workload_evaluation": workload_evaluation,
        }
        evidence["evidence_payload_sha256"] = _canonical_digest(evidence)
        _write_evidence_atomic(output, evidence)
        print(
            json.dumps(
                {
                    "cycles": workload_result["cycles"],
                    "evidence": str(output),
                    "evidence_payload_sha256": evidence["evidence_payload_sha256"],
                    "partitions": len(partitions),
                    "restarts": len(restarts),
                    "status": "passed",
                },
                sort_keys=True,
            )
        )
        return evidence
    except Exception as error:
        failure_resource_capture: dict[str, Any] = {
            "attempted": False,
            "captured": False,
            "reason": "cluster was not started",
        }
        if started_cluster:
            failure_elapsed = time.monotonic() - (
                chaos_started if chaos_started is not None else started_monotonic
            )
            failure_resource_capture = _capture_failure_resource_sample(
                harness,
                elapsed_s=max(0.0, failure_elapsed),
                samples=resource_samples,
            )
        workload_status = _failed_workload_status(
            workload,
            stdout=workload_stdout,
            stderr=workload_stderr,
            error=error,
        )
        if chaos_started is not None and chaos_completed is None:
            chaos_completed = time.monotonic()
        if started_cluster:
            if partitioned:
                with suppress(Exception):
                    _set_partition(enabled=True)
                partitioned = False
            if workload_paused:
                with suppress(Exception):
                    _resume_workload(
                        harness,
                        timeout=FAILURE_COMMAND_TIMEOUT_SECONDS,
                    )
                workload_paused = False
            with suppress(Exception):
                failure_logs = harness.compose(
                    "logs",
                    "--no-color",
                    "--tail",
                    "200",
                    check=False,
                    timeout=FAILURE_LOG_TIMEOUT_SECONDS,
                )
        if started_cluster and not keep and not cleanup_attempted:
            cleanup_attempted = True
            workload_container_cleanup: dict[str, Any] = {
                "attempted": False,
                "container_name": harness.workload_container,
                "force_removed": False,
                "found": False,
                "labels_validated": False,
                "remaining": False,
            }
            try:
                workload_container_cleanup = _remove_failed_workload_container(
                    harness,
                    host_cli_terminated=workload_status.get("host_cli_terminated") is True,
                    timeout=FAILURE_COMMAND_TIMEOUT_SECONDS,
                    result=workload_container_cleanup,
                )
                down_cleanup = _checked_down(
                    harness,
                    probe_timeout=FAILURE_COMMAND_TIMEOUT_SECONDS,
                    down_timeout=FAILURE_DOWN_TIMEOUT_SECONDS,
                )
                cleanup = {
                    **down_cleanup,
                    "workload_container": workload_container_cleanup,
                }
                started_cluster = False
            except Exception as cleanup_error:
                cleanup = {
                    "error": _bounded_text(str(cleanup_error)),
                    "performed": False,
                    "reason": "cleanup failed",
                    "workload_container": workload_container_cleanup,
                }
        elif keep:
            cleanup = {
                "performed": False,
                "reason": "--keep requested for failure investigation",
            }
        elif not started_cluster and not cleanup_attempted:
            cleanup = {
                "performed": False,
                "reason": "cluster was not started",
            }

        raw_cycles = workload_result.get("cycles", 0)
        cycles = (
            raw_cycles if isinstance(raw_cycles, int) and not isinstance(raw_cycles, bool) else 0
        )
        partial_resources = _partial_resource_evidence(
            resource_samples,
            bounds=resource_bounds,
            cycles=cycles,
            evaluation=resource_evaluation,
        )
        partial_resources["failure_capture"] = failure_resource_capture
        failed_evidence: dict[str, Any] = {
            "chaos": {
                "partition_count": len(partitions),
                "partition_recovery": _bounded_records(
                    partition_recovery,
                    maximum=FAILED_EVIDENCE_MAX_CHAOS_EVENTS,
                ),
                "partitions": _bounded_records(
                    partitions,
                    maximum=FAILED_EVIDENCE_MAX_CHAOS_EVENTS,
                ),
                "restart_count": len(restarts),
                "restart_integrity": restart_integrity,
                "restarts": _bounded_records(
                    restarts,
                    maximum=FAILED_EVIDENCE_MAX_CHAOS_EVENTS,
                ),
            },
            "authority_evaluation": authority_evaluation,
            "cleanup": cleanup,
            "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "configuration": asdict(configuration),
            "duration_seconds": round(time.monotonic() - started_monotonic, 3),
            "error": {
                "docker_logs_tail": _bounded_text(failure_logs),
                "message": _bounded_text(str(error)),
                "type": f"{type(error).__module__}.{type(error).__qualname__}",
            },
            "image": image,
            "orchestration": {
                "chaos_completed_monotonic_seconds": chaos_completed,
                "chaos_started_monotonic_seconds": chaos_started,
                "compose_project": harness.project,
                "phase": phase,
                "preflight": preflight,
                "workload_start": workload_start,
            },
            "passed": False,
            "package": {
                "host_lets_agent": metadata.version("lets-agent"),
                "identity": package_identity,
            },
            "resources": partial_resources,
            "schema": "lets.production-profile-soak/v2",
            "source": source_before,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "verification": verification,
            "workload": workload_result,
            "workload_evaluation": workload_evaluation,
            "workload_status": workload_status,
        }
        failed_evidence["evidence_payload_sha256"] = _canonical_digest(failed_evidence)
        evidence_write_error: str | None = None
        try:
            _write_evidence_atomic(output, failed_evidence)
        except Exception as write_error:
            evidence_write_error = _bounded_text(str(write_error))
        print(
            json.dumps(
                {
                    "evidence": str(output),
                    "evidence_payload_sha256": failed_evidence["evidence_payload_sha256"],
                    "evidence_write_error": evidence_write_error,
                    "status": "failed",
                },
                sort_keys=True,
            )
        )
        if failure_logs:
            print(_bounded_text(failure_logs))
        raise


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--duration-seconds", type=_positive_float, default=3_600.0)
    parser.add_argument("--cycle-interval-seconds", type=_positive_float, default=0.5)
    parser.add_argument("--health-interval-seconds", type=_positive_float, default=10.0)
    parser.add_argument("--resource-interval-seconds", type=_positive_float, default=5.0)
    parser.add_argument("--partition-interval-seconds", type=_positive_float, default=90.0)
    parser.add_argument("--partition-duration-seconds", type=_positive_float, default=20.0)
    parser.add_argument(
        "--restart-interval-seconds",
        type=_positive_float,
        default=DEFAULT_RESTART_INTERVAL_SECONDS,
    )
    parser.add_argument("--retry-timeout-seconds", type=_positive_float, default=90.0)
    parser.add_argument("--convergence-timeout-seconds", type=_positive_float, default=180.0)
    parser.add_argument("--transfer-every-cycles", type=_positive_int, default=3)
    parser.add_argument("--executor-reopen-every-cycles", type=_positive_int, default=10)
    parser.add_argument("--initial-share", type=_positive_int, default=1_000_000)
    parser.add_argument("--seed", type=int, default=20260809)
    parser.add_argument("--output", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--keep", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    configuration = SoakConfiguration(
        image=arguments.image,
        duration_seconds=arguments.duration_seconds,
        cycle_interval_seconds=arguments.cycle_interval_seconds,
        health_interval_seconds=arguments.health_interval_seconds,
        resource_interval_seconds=arguments.resource_interval_seconds,
        partition_interval_seconds=arguments.partition_interval_seconds,
        partition_duration_seconds=arguments.partition_duration_seconds,
        restart_interval_seconds=arguments.restart_interval_seconds,
        retry_timeout_seconds=arguments.retry_timeout_seconds,
        convergence_timeout_seconds=arguments.convergence_timeout_seconds,
        transfer_every_cycles=arguments.transfer_every_cycles,
        executor_reopen_every_cycles=arguments.executor_reopen_every_cycles,
        initial_share=arguments.initial_share,
        seed=arguments.seed,
        smoke=arguments.smoke,
    )
    run_soak(configuration, output=arguments.output, keep=arguments.keep)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
