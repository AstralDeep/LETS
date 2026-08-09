"""Run a sustained, chaos-injected soak against one exact production OCI digest."""

from __future__ import annotations

import argparse
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
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
PROJECT_PREFIX = "lets-production-soak"
COMPOSE_FILE = ROOT / "deploy" / "production" / "acceptance-compose.yaml"
WARDENS = ("warden-a", "warden-b", "warden-c")
TOXIPROXY = "http://127.0.0.1:28474"
WORKLOAD_PAUSE_PATH = "/scenario/soak-workload-pause.json"
WORKLOAD_PAUSE_ACK_PATH = "/scenario/soak-workload-pause-ack.json"
DEFAULT_EVIDENCE = ROOT / "results" / "generated" / "production-profile-soak.json"
IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
DEFAULT_RESTART_INTERVAL_SECONDS = 900.0
MIN_RESTART_EPISODES = len(WARDENS)
RELEASE_MINIMUM_CYCLES = 300
SMOKE_MINIMUM_CYCLES = 3
TARGET_MAXIMUM_SECONDS_PER_CYCLE = 12.0
MINIMUM_RETRY_ALLOWANCE = 24
MAXIMUM_RETRIES_PER_CYCLE = 4
MAXIMUM_CYCLE_LATENCY_SECONDS = 120.0
CHAOS_START_SHUTDOWN_MARGIN_SECONDS = 10.0
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
           d.next_attempt_ns, d.delivered_at_ns, d.superseded_at_ns, d.last_error
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
    max_rss_bytes: int = 768 * 1024 * 1024
    max_rss_growth_bytes: int = 256 * 1024 * 1024
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
        invalid = [name for name, value in positive.items() if value <= 0]
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
        if self.duration_seconds < 2 * self.partition_interval_seconds:
            raise ValueError("duration must permit at least two partition episodes")
        if self.duration_seconds < MIN_RESTART_EPISODES * self.restart_interval_seconds:
            raise ValueError("duration must permit a SIGKILL episode for every warden")
        if self.retry_timeout_seconds > 90:
            raise ValueError("retry timeout must be at most 90 seconds")


def minimum_cycle_count(configuration: SoakConfiguration) -> int:
    duration_target = math.ceil(configuration.duration_seconds / TARGET_MAXIMUM_SECONDS_PER_CYCLE)
    floor = SMOKE_MINIMUM_CYCLES if configuration.smoke else RELEASE_MINIMUM_CYCLES
    return max(floor, duration_target)


def minimum_health_sample_count(configuration: SoakConfiguration) -> int:
    interval_target = (
        math.ceil(
            configuration.duration_seconds
            / max(configuration.health_interval_seconds, TARGET_MAXIMUM_SECONDS_PER_CYCLE)
        )
        + 1
    )
    return max(2, min(minimum_cycle_count(configuration) + 1, interval_target))


def may_start_chaos_episode(configuration: SoakConfiguration, *, elapsed_s: float) -> bool:
    """Keep the workload alive long enough to durably acknowledge a new fault episode."""

    return configuration.duration_seconds - elapsed_s > CHAOS_START_SHUTDOWN_MARGIN_SECONDS


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


def evaluate_health_cadence(samples: object, *, duration_seconds: float) -> dict[str, Any]:
    """Prove health observations cover the run more tightly than exporter stall bounds."""

    if not isinstance(samples, list) or not samples or not math.isfinite(duration_seconds):
        return {"passed": False, "reason": "missing or invalid health samples"}
    timestamps: list[float] = []
    stall_bounds: list[float] = []
    for sample in samples:
        if not isinstance(sample, dict):
            return {"passed": False, "reason": "malformed health sample"}
        elapsed = sample.get("elapsed_seconds")
        if (
            isinstance(elapsed, bool)
            or not isinstance(elapsed, (int, float))
            or not math.isfinite(float(elapsed))
            or float(elapsed) < 0
        ):
            return {"passed": False, "reason": "invalid health-sample timestamp"}
        timestamps.append(float(elapsed))
        nodes = sample.get("nodes")
        if not isinstance(nodes, dict) or set(nodes) != set(WARDENS):
            return {"passed": False, "reason": "health sample omitted a warden"}
        for node in WARDENS:
            document = nodes.get(node)
            exporter = document.get("audit_exporter") if isinstance(document, dict) else None
            maximum_stall = exporter.get("max_stall_s") if isinstance(exporter, dict) else None
            if (
                isinstance(maximum_stall, bool)
                or not isinstance(maximum_stall, (int, float))
                or not math.isfinite(float(maximum_stall))
                or float(maximum_stall) <= 0
            ):
                return {"passed": False, "reason": "health sample omitted an audit stall bound"}
            stall_bounds.append(float(maximum_stall))
    strictly_increasing = all(right > left for left, right in pairwise(timestamps))
    duration_covered = 0 <= timestamps[-1] <= duration_seconds + 0.01
    gaps = [timestamps[0], *[right - left for left, right in pairwise(timestamps)]]
    if duration_covered:
        gaps.append(max(0.0, duration_seconds - timestamps[-1]))
    maximum_gap = max(gaps, default=math.inf)
    maximum_allowed_gap = min(stall_bounds, default=0.0)
    passed = (
        strictly_increasing
        and duration_covered
        and maximum_allowed_gap > 0
        and maximum_gap <= maximum_allowed_gap
    )
    return {
        "first_sample_seconds": timestamps[0],
        "last_sample_seconds": timestamps[-1],
        "maximum_allowed_gap_seconds": maximum_allowed_gap,
        "maximum_gap_seconds": round(maximum_gap, 3),
        "passed": passed,
        "sample_count": len(timestamps),
        "strictly_increasing": strictly_increasing,
    }


def evaluate_workload_result(
    result: dict[str, Any], configuration: SoakConfiguration
) -> dict[str, Any]:
    cycles = int(result.get("cycles", -1))
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
        "authorizations": 2 * max(0, cycles),
        "closed": max(0, cycles),
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
    required_cycles = minimum_cycle_count(configuration)
    required_health_samples = minimum_health_sample_count(configuration)
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
    actual_retries = int(result.get("request_retry_count", -1))
    actual_health_samples = int(result.get("health_sample_count", -1))
    recorded_health_samples = result.get("health_samples")
    health_cadence = evaluate_health_cadence(
        recorded_health_samples,
        duration_seconds=float(result.get("duration_seconds", -1.0)),
    )
    maximum_pending = typed_audit_progress.get("maximum_pending_by_node")
    checks = {
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
        "counter_relationships": typed_counters == expected_counters,
        "cycle_latency_bounded": (
            int(typed_latency.get("count", -1)) == cycles
            and float(typed_latency.get("maximum_ms", math.inf)) <= maximum_cycle_latency_ms
            and int(cast(dict[str, Any], latency_buckets).get("overflow", -1)) == 0
        ),
        "executor_claims": int(typed_executor.get("claims", -1)) == 2 * cycles,
        "executor_claim_sequence": int(executor_status.get("claim_sequence", -1)) == 2 * cycles,
        "executor_reopens": int(typed_executor.get("reopen_count", -1)) == expected_reopens,
        "executor_replay_rejections": int(typed_executor.get("replay_rejections", -1))
        == 2 * cycles + expected_reopens,
        "health_samples": (
            actual_health_samples >= required_health_samples
            and isinstance(recorded_health_samples, list)
            and len(recorded_health_samples) == actual_health_samples
        ),
        "health_cadence": health_cadence.get("passed") is True,
        "minimum_cycles": cycles >= required_cycles,
        "requested_duration": float(result.get("duration_seconds", -1.0))
        >= configuration.duration_seconds,
        "retry_budget": 0 <= actual_retries <= maximum_retries,
        "transfer_pair_rotation": typed_pair_counts == expected_pairs,
    }
    violations = sorted(name for name, passed in checks.items() if not passed)
    return {
        "checks": checks,
        "metrics": {
            "actual_cycles": cycles,
            "actual_health_samples": actual_health_samples,
            "actual_request_retries": actual_retries,
            "maximum_cycle_latency_ms": maximum_cycle_latency_ms,
            "maximum_request_retries": maximum_retries,
            "required_cycles": required_cycles,
            "required_health_samples": required_health_samples,
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

    def container(self, service: str) -> str:
        value = self.compose("ps", "-q", service)
        if not value:
            raise RuntimeError(f"Compose service {service} has no container")
        return value

    def state(self, service: str) -> dict[str, Any]:
        return self.container_state(self.container(service))

    def container_state(self, container: str) -> dict[str, Any]:
        value = json.loads(
            self.run(["docker", "inspect", "--format", "{{json .State}}", container]).stdout
        )
        if not isinstance(value, dict):
            raise RuntimeError(f"Docker returned invalid state for {container}")
        return cast(dict[str, Any], value)

    def container_restart_count(self, container: str) -> int:
        return int(
            json.loads(
                self.run(
                    ["docker", "inspect", "--format", "{{json .RestartCount}}", container]
                ).stdout
            )
        )

    def restart_count(self, service: str) -> int:
        return self.container_restart_count(self.container(service))

    def wait_healthy(self, service: str, *, timeout_s: float = 180) -> None:
        deadline = time.monotonic() + timeout_s
        last: dict[str, Any] = {}
        while time.monotonic() < deadline:
            last = self.state(service)
            health = last.get("Health")
            if isinstance(health, dict) and health.get("Status") == "healthy":
                return
            if last.get("Status") == "exited":
                raise RuntimeError(f"{service} exited before becoming healthy: {last}")
            time.sleep(0.5)
        raise RuntimeError(f"{service} did not become healthy: {last}")


def _project_volumes(harness: Harness) -> set[str]:
    output = harness.run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={harness.project}",
            "--format",
            "{{.Name}}",
        ]
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _project_containers(harness: Harness) -> set[str]:
    output = harness.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={harness.project}",
            "--format",
            "{{.ID}}",
        ]
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _project_networks(harness: Harness) -> set[str]:
    output = harness.run(
        [
            "docker",
            "network",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={harness.project}",
            "--format",
            "{{.ID}}",
        ]
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _checked_down(harness: Harness) -> dict[str, Any]:
    unexpected = _project_volumes(harness) - harness.allowed_volumes
    if unexpected:
        raise RuntimeError(f"refusing to remove unexpected project volumes: {sorted(unexpected)}")
    harness.compose("down", "--volumes", "--remove-orphans", timeout=180)
    residual = {
        "containers": sorted(_project_containers(harness)),
        "networks": sorted(_project_networks(harness)),
        "volumes": sorted(_project_volumes(harness)),
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


def _resource_sample(harness: Harness, *, elapsed_s: float) -> dict[str, Any]:
    nodes: dict[str, Any] = {}
    for service in WARDENS:
        resource = json.loads(
            harness.run(
                [
                    "docker",
                    "exec",
                    harness.container(service),
                    "python",
                    "-c",
                    RESOURCE_PROBE,
                ]
            ).stdout
        )
        if not isinstance(resource, dict):
            raise RuntimeError(f"{service} returned malformed resource evidence")
        state = harness.state(service)
        resource["container_init_pid"] = state.get("Pid")
        resource["container_state"] = {
            "exit_code": state.get("ExitCode"),
            "oom_killed": state.get("OOMKilled"),
            "status": state.get("Status"),
        }
        resource["restart_count"] = harness.restart_count(service)
        nodes[service] = resource
    return {"elapsed_seconds": round(elapsed_s, 3), "nodes": nodes}


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


def _pause_workload(harness: Harness, episode: int) -> dict[str, Any]:
    write_script = (
        "import json,sys; from pathlib import Path; "
        f"target=Path({WORKLOAD_PAUSE_PATH!r}); temporary=target.with_suffix('.tmp'); "
        "temporary.write_text(json.dumps({'episode':int(sys.argv[1])},sort_keys=True)+'\\n'); "
        "temporary.replace(target)"
    )
    harness.run(
        [
            "docker",
            "exec",
            harness.workload_container,
            "python",
            "-c",
            write_script,
            str(episode),
        ],
        timeout=30,
    )
    read_script = (
        "import sys; from pathlib import Path; "
        f"path=Path({WORKLOAD_PAUSE_ACK_PATH!r}); "
        "sys.stdout.write(path.read_text() if path.exists() else '')"
    )
    deadline = time.monotonic() + harness.configuration.retry_timeout_seconds + 30
    last = ""
    while time.monotonic() < deadline:
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
            if acknowledgement == {"episode": episode, "paused": True}:
                return cast(dict[str, Any], acknowledgement)
        time.sleep(0.1)
    raise RuntimeError(f"workload did not acknowledge partition pause {episode}: {last}")


def _resume_workload(harness: Harness) -> None:
    script = (
        "from pathlib import Path; "
        f"Path({WORKLOAD_PAUSE_PATH!r}).unlink(missing_ok=True); "
        f"Path({WORKLOAD_PAUSE_ACK_PATH!r}).unlink(missing_ok=True)"
    )
    harness.run(
        ["docker", "exec", harness.workload_container, "python", "-c", script],
        timeout=30,
    )


def _settle_cluster(harness: Harness, episode: int) -> dict[str, Any]:
    output_path = f"/scenario/soak-settle-{episode:06d}.json"
    timeout = min(60.0, harness.configuration.convergence_timeout_seconds)
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
            and candidate.get("last_error") is not None
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
    harness.compose(
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
        timeout=harness.configuration.convergence_timeout_seconds + 120,
    )
    return _scenario_result(harness, "/scenario/soak-verification.json")


def _canonical_digest(value: dict[str, Any]) -> str:
    payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _restart(harness: Harness, service: str, *, elapsed_s: float) -> dict[str, Any]:
    operation_started = time.monotonic()
    prior_container = harness.container(service)
    prior = harness.container_state(prior_container)
    prior_pid = int(prior["Pid"])
    prior_restart_count = harness.container_restart_count(prior_container)
    if (
        prior.get("Status") != "running"
        or prior.get("OOMKilled") is not False
        or prior_restart_count != 0
    ):
        raise RuntimeError(f"{service} was unhealthy before planned SIGKILL: {prior!r}")
    harness.compose("kill", "--signal", "SIGKILL", service)
    killed = harness.container_state(prior_container)
    killed_restart_count = harness.container_restart_count(prior_container)
    if (
        killed.get("Status") != "exited"
        or int(killed.get("ExitCode", -1)) != 137
        or killed.get("OOMKilled") is not False
        or killed_restart_count != 0
    ):
        raise RuntimeError(f"{service} did not stop only by planned SIGKILL: {killed!r}")
    harness.compose("up", "-d", "--no-deps", service)
    harness.wait_healthy(service)
    restarted_container = harness.container(service)
    restarted = harness.container_state(restarted_container)
    restarted_pid = int(restarted["Pid"])
    restarted_count = harness.container_restart_count(restarted_container)
    if (
        restarted_pid == prior_pid
        or restarted.get("Status") != "running"
        or restarted.get("OOMKilled") is not False
        or restarted_count != 0
    ):
        raise RuntimeError(f"{service} restart did not replace process {prior_pid}")
    operation_seconds = time.monotonic() - operation_started
    return {
        "completed_at_seconds": round(elapsed_s + operation_seconds, 3),
        "elapsed_seconds": round(elapsed_s, 3),
        "new_container_id": restarted_container,
        "new_pid": restarted_pid,
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
    }


def _restart_integrity(
    harness: Harness,
    restarts: list[dict[str, Any]],
    *,
    chaos_duration_seconds: float,
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
    restart_points = sorted(float(item["elapsed_seconds"]) for item in restarts)
    boundaries = [0.0, *restart_points, chaos_duration_seconds]
    gaps = [max(0.0, right - left) for left, right in pairwise(boundaries)]
    longest = max(gaps, default=0.0)
    required = harness.configuration.restart_interval_seconds * 0.8
    if longest < required:
        raise RuntimeError(
            f"soak lacked a long uninterrupted SIGKILL-free window: {longest:.3f} < {required:.3f}"
        )
    per_warden_lifetimes: dict[str, Any] = {}
    for service in WARDENS:
        service_restarts = sorted(
            float(item["elapsed_seconds"]) for item in restarts if item.get("service") == service
        )
        service_boundaries = [0.0, *service_restarts, chaos_duration_seconds]
        lifetimes = [max(0.0, right - left) for left, right in pairwise(service_boundaries)]
        longest_lifetime = max(lifetimes, default=0.0)
        if longest_lifetime < required:
            raise RuntimeError(
                f"{service} lacked a long uninterrupted process lifetime: "
                f"{longest_lifetime:.3f} < {required:.3f}"
            )
        per_warden_lifetimes[service] = {
            "longest_seconds": round(longest_lifetime, 3),
            "passed": True,
            "planned_sigkill_seconds": [round(item, 3) for item in service_restarts],
            "segments_seconds": [round(item, 3) for item in lifetimes],
        }
    return {
        "all_wardens_sigkilled": True,
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
    configuration.validate()
    resource_bounds = ResourceBounds() if bounds is None else bounds
    harness = Harness(configuration)
    started_at = datetime.now(UTC)
    started_monotonic = time.monotonic()
    source_before = _source_tree_digest(harness.environment)
    partitions: list[dict[str, Any]] = []
    restarts: list[dict[str, Any]] = []
    resource_samples: list[dict[str, Any]] = []
    workload_stdout = ""
    workload_stderr = ""
    partitioned = False
    workload_paused = False
    failure_logs = ""
    started_cluster = False
    preflight: dict[str, Any] = {}
    try:
        preflight = _preflight_zero(harness)
        harness.run(["docker", "pull", configuration.image], timeout=900)
        started_cluster = True
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
        resource_samples.append(_resource_sample(harness, elapsed_s=0.0))

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
                pause_acknowledgement = _pause_workload(harness, episode)
                settled = _settle_cluster(harness, episode)
                _set_partition(enabled=False)
                partitioned = True
                disabled_at = time.monotonic()
                partition = {
                    "disabled_at_seconds": round(disabled_at - chaos_started, 3),
                    "episode": episode,
                    "links": ["a_to_b", "b_to_a"],
                    "workload_coordination": {
                        "acknowledgement": pause_acknowledgement,
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
                partitioned = False
                _resume_workload(harness)
                workload_paused = False
                partitions[-1]["restored_at_seconds"] = round(elapsed, 3)
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
                restarts.append(_restart(harness, service, elapsed_s=elapsed))
                restart_index += 1
                next_restart = _next_restart_deadline(
                    prior_deadline=prior_restart_deadline,
                    interval_s=configuration.restart_interval_seconds,
                    completed_at=time.monotonic(),
                )
            if now >= next_resource:
                resource_samples.append(_resource_sample(harness, elapsed_s=elapsed))
                next_resource = time.monotonic() + configuration.resource_interval_seconds
            time.sleep(0.2)

        workload_stdout, workload_stderr = workload.communicate(timeout=30)
        workload_chaos_duration = time.monotonic() - chaos_started
        if workload.returncode != 0:
            raise RuntimeError(
                f"soak workload failed ({workload.returncode})\n{workload_stdout}{workload_stderr}"
            )
        if partitioned:
            if restore_partition_at is not None:
                while time.monotonic() < restore_partition_at:
                    time.sleep(min(0.2, restore_partition_at - time.monotonic()))
            _set_partition(enabled=True)
            partitioned = False
            _resume_workload(harness)
            workload_paused = False
            restored = time.monotonic() - chaos_started
            partitions[-1]["restored_at_seconds"] = round(restored, 3)
            partitions[-1]["duration_seconds"] = round(
                restored - float(partitions[-1]["disabled_at_seconds"]),
                3,
            )
        for service in WARDENS:
            harness.wait_healthy(service)
        partition_recovery = _wait_partition_recovery(harness, partitions)
        verification = _final_verify(harness)
        workload_result = _scenario_result(harness, "/scenario/soak-workload.json")
        workload_evaluation = evaluate_workload_result(workload_result, configuration)
        if not workload_evaluation["passed"]:
            raise RuntimeError(
                f"soak workload bounds failed: {workload_evaluation['violations']!r}"
            )
        package_identity = validate_package_identity(
            host_version=package_version,
            image=image,
            runtime_packages=runtime_packages,
            workload=workload_result,
            verification=verification,
        )
        resource_samples.append(
            _resource_sample(harness, elapsed_s=time.monotonic() - chaos_started)
        )
        resource_evaluation = evaluate_resource_bounds(
            resource_samples,
            cycles=int(workload_result["cycles"]),
            bounds=resource_bounds,
        )
        if not resource_evaluation["passed"]:
            raise RuntimeError(
                f"soak resource bounds failed: {resource_evaluation['violations']!r}"
            )
        if len(partitions) < 2 or not all(
            cast(dict[str, Any], item.get("observation", {})).get("durably_pending_observed")
            is True
            for item in partitions
        ):
            raise RuntimeError(
                "soak did not complete at least two proven durable partition episodes"
            )
        restart_integrity = _restart_integrity(
            harness,
            restarts,
            chaos_duration_seconds=workload_chaos_duration,
        )
        source_after = _source_tree_digest(harness.environment)
        if source_after != source_before:
            raise RuntimeError("source tree changed while the production soak was running")
        completed_at = datetime.now(UTC)
        cleanup: dict[str, Any] = {
            "performed": False,
            "reason": "--keep requested for investigation",
        }
        if not keep:
            cleanup = _checked_down(harness)
            started_cluster = False
        evidence: dict[str, Any] = {
            "chaos": {
                "partition_recovery": partition_recovery,
                "partitions": partitions,
                "restart_integrity": restart_integrity,
                "restarts": restarts,
            },
            "cleanup": cleanup,
            "completed_at": completed_at.isoformat().replace("+00:00", "Z"),
            "configuration": asdict(configuration),
            "duration_seconds": round(time.monotonic() - started_monotonic, 3),
            "image": image,
            "orchestration": {
                "compose_project": harness.project,
                "preflight": preflight,
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
            "schema": "lets.production-profile-soak/v1",
            "source": source_before,
            "started_at": started_at.isoformat().replace("+00:00", "Z"),
            "verification": verification,
            "workload": workload_result,
            "workload_evaluation": workload_evaluation,
        }
        evidence["evidence_payload_sha256"] = _canonical_digest(evidence)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
    except Exception:
        if started_cluster:
            failure_logs = harness.compose(
                "logs", "--no-color", "--tail", "200", check=False, timeout=120
            )
        raise
    finally:
        if partitioned:
            with suppress(Exception):
                _set_partition(enabled=True)
        if workload_paused:
            with suppress(Exception):
                _resume_workload(harness)
        if failure_logs:
            print(failure_logs)
        if started_cluster and not keep:
            _checked_down(harness)


def _positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
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
