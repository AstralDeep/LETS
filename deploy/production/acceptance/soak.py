"""Drive sustained mixed traffic and verify production-profile soak health."""

from __future__ import annotations

import argparse
import json
import math
import re
import ssl
import time
from collections import deque
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, cast

import httpx
from nacl.signing import SigningKey

from lets.canonical import b64url_decode, b64url_encode, canonical_json, strict_json_loads
from lets.crypto import PublicKeyRegistry
from lets.errors import ReplayError
from lets.executor import (
    ExecutorPolicy,
    ReceiptVerifier,
    SQLiteReceiptReplayStore,
    executor_replay_identity,
)
from lets.executor_authority import ProcessFileExecutorAuthorityAnchor
from lets.manifest import ClusterManifest
from lets.models import Receipt

TENANT_ID = "production-acceptance-tenant"
ENVELOPE_ID = "production-acceptance-envelope"
EXECUTOR_AUDIENCE = "production-soak-executor"
NODES = ("warden-a", "warden-b", "warden-c")
NODE_URLS = {node: f"https://{node}:8443" for node in NODES}
TRANSFER_PAIRS = (
    ("warden-a", "warden-b"),
    ("warden-b", "warden-a"),
    ("warden-a", "warden-c"),
    ("warden-c", "warden-a"),
    ("warden-b", "warden-c"),
    ("warden-c", "warden-b"),
)
CLIENT = Path("/test-client")
TRUST = Path("/etc/lets/trust")
EXECUTOR_STATE = Path("/var/lib/lets-executor")
EXECUTOR_AUTHORITY = Path("/var/lib/lets-executor-authority")
EXECUTOR_DATABASE = EXECUTOR_STATE / "soak-replay.sqlite3"
EXECUTOR_ANCHOR = EXECUTOR_AUTHORITY / "soak-replay.anchor.json"
WORKLOAD_PAUSE = Path("/scenario/soak-workload-pause.json")
WORKLOAD_PAUSE_ACK = Path("/scenario/soak-workload-pause-ack.json")
MAX_RECORDED_HEALTH_SAMPLES = 512
AUDIT_ERROR_MAX_BYTES = 4_096
AUDIT_ERROR_SAMPLE_BUDGET = 1
AUDIT_TRANSIENT_CONNECT_BUSY = re.compile(
    r"\AStorageError: could not connect to the audit archive "
    r"\(sqlite_errorname=(SQLITE_BUSY(?:_[A-Z0-9_]+)?), sqlite_errorcode=([0-9]+)\)\Z"
)
LATENCY_BUCKETS_MS = (
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    30_000,
    60_000,
    120_000,
)


def _object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not a JSON object")
    return cast(dict[str, Any], value)


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(CLIENT / "server-ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        certfile=CLIENT / "client-cert.pem",
        keyfile=CLIENT / "client-key.pem",
    )
    return context


class TokenIssuer:
    def __init__(self, *, seed: int) -> None:
        identity = _object(CLIENT / "identity.json")
        self._audience = str(identity["audience"])
        self._issuer = str(identity["issuer"])
        self._key_id = str(identity["kid"])
        self._signer = SigningKey(CLIENT.joinpath("identity.seed").read_bytes())
        self._seed = seed
        self._sequence = 0

    def issue(self) -> str:
        now = int(time.time())
        self._sequence += 1
        header = {"alg": "EdDSA", "kid": self._key_id, "typ": "at+jwt"}
        payload = {
            "aud": self._audience,
            "exp": now + 120,
            "iat": now - 1,
            "iss": self._issuer,
            "jti": f"production-soak-{self._seed}-{self._sequence:012d}",
            "nbf": now - 1,
            "scope": (
                "lets.admin lets.audit.read lets.audit.verify lets.metrics.read "
                "lets.transfer lets.lease.issue"
            ),
            "sub": "production-soak-operator",
            "tenant_id": TENANT_ID,
        }
        encoded_header = b64url_encode(canonical_json(header))
        encoded_payload = b64url_encode(canonical_json(payload))
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = b64url_encode(self._signer.sign(signing_input).signature)
        return f"{encoded_header}.{encoded_payload}.{signature}"


class ClusterClient:
    def __init__(self, *, seed: int, retry_timeout_s: float) -> None:
        self._tokens = TokenIssuer(seed=seed)
        self._tls = _tls_context()
        self._retry_timeout_s = retry_timeout_s
        self.retry_count = 0

    def request(
        self,
        method: str,
        node: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        expected: int = 200,
        retry_timeout_s: float | None = None,
    ) -> dict[str, Any]:
        retry_window = (
            self._retry_timeout_s
            if retry_timeout_s is None
            else min(self._retry_timeout_s, retry_timeout_s)
        )
        if not math.isfinite(retry_window) or retry_window <= 0:
            raise RuntimeError("request retry timeout must be finite and positive")
        deadline = time.monotonic() + retry_window
        last_error = "request was not attempted"
        while time.monotonic() < deadline:
            headers = {"authorization": f"Bearer {self._tokens.issue()}"}
            request_timeout = max(0.001, min(10.0, deadline - time.monotonic()))
            try:
                with httpx.Client(
                    verify=self._tls,
                    headers=headers,
                    timeout=request_timeout,
                ) as client:
                    response = client.request(method, f"{NODE_URLS[node]}{path}", json=body)
            except httpx.TransportError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code == expected:
                    value = response.json()
                    if not isinstance(value, dict):
                        raise RuntimeError(f"{node}{path} returned a non-object response")
                    return cast(dict[str, Any], value)
                last_error = f"HTTP {response.status_code}: {response.text[:500]}"
                if response.status_code not in {429, 500, 502, 503, 504}:
                    raise RuntimeError(f"{method} {node}{path} failed: {last_error}")
            self.retry_count += 1
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        raise RuntimeError(f"{method} {node}{path} did not recover: {last_error}")


@dataclass(slots=True)
class LatencyHistogram:
    count: int = 0
    total_ms: float = 0.0
    minimum_ms: float | None = None
    maximum_ms: float = 0.0
    _buckets: dict[str, int] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._buckets = {str(bound): 0 for bound in LATENCY_BUCKETS_MS}
        self._buckets["overflow"] = 0

    def observe(self, elapsed_s: float) -> None:
        value = elapsed_s * 1_000
        self.count += 1
        self.total_ms += value
        self.minimum_ms = value if self.minimum_ms is None else min(self.minimum_ms, value)
        self.maximum_ms = max(self.maximum_ms, value)
        for bound in LATENCY_BUCKETS_MS:
            if value <= bound:
                self._buckets[str(bound)] += 1
                break
        else:
            self._buckets["overflow"] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "buckets_ms": dict(self._buckets),
            "count": self.count,
            "maximum_ms": round(self.maximum_ms, 3),
            "mean_ms": round(self.total_ms / self.count, 3) if self.count else None,
            "minimum_ms": None if self.minimum_ms is None else round(self.minimum_ms, 3),
        }


def operation_plan(cycle: int) -> dict[str, Any]:
    """Return the deterministic node and transfer schedule for one cycle."""

    if cycle < 0:
        raise ValueError("cycle must be non-negative")
    source, target = TRANSFER_PAIRS[cycle % len(TRANSFER_PAIRS)]
    return {
        "node": NODES[cycle % len(NODES)],
        "transfer_source": source,
        "transfer_target": target,
    }


def scheduled_transfer_pair(cycle: int, transfer_every_cycles: int) -> tuple[str, str] | None:
    """Return the transfer actually scheduled for a workload cycle, if any."""

    if cycle < 0:
        raise ValueError("cycle must be non-negative")
    if transfer_every_cycles <= 0:
        raise ValueError("transfer_every_cycles must be positive")
    if cycle % transfer_every_cycles:
        return None
    transfer_ordinal = cycle // transfer_every_cycles
    return TRANSFER_PAIRS[transfer_ordinal % len(TRANSFER_PAIRS)]


def _verified_manifest() -> ClusterManifest:
    manifest = ClusterManifest.load(TRUST / "manifest.json")
    operator = _object(TRUST / "operator.json")
    key_id = operator.get("key_id")
    public_key = operator.get("public_key")
    if not isinstance(key_id, str) or not isinstance(public_key, str):
        raise RuntimeError("production soak operator trust is malformed")
    manifest.verify_signatures({key_id: b64url_decode(public_key)}, threshold=1)
    if len(manifest.policies) != 1:
        raise RuntimeError("production soak manifest must contain exactly one policy")
    return manifest


def _registry(manifest: ClusterManifest) -> PublicKeyRegistry:
    registry = PublicKeyRegistry()
    for warden in manifest.wardens:
        for key in warden.keys:
            registry.register(
                warden.warden_id,
                key.key_id,
                key.public_key,
                not_before_ns=key.not_before_ns,
                not_after_ns=key.not_after_ns,
            )
    return registry


class ExecutorBoundary:
    def __init__(self, manifest: ClusterManifest) -> None:
        self._registry = _registry(manifest)
        policy = manifest.policies[0]
        self._policy = ExecutorPolicy(
            audience=EXECUTOR_AUDIENCE,
            tenant_id=TENANT_ID,
            envelope_id=ENVELOPE_ID,
            config_epoch=manifest.config_epoch,
            allowed_policy_digests=frozenset({policy.digest}),
            allowed_machine_digests=frozenset({policy.machine.digest}),
            trusted_wardens=frozenset(NODES),
            max_clock_uncertainty_ns=policy.max_clock_uncertainty_ns,
        )
        self._identity = executor_replay_identity(self._policy, self._registry)
        self._anchor: ProcessFileExecutorAuthorityAnchor | None = None
        self._store: SQLiteReceiptReplayStore | None = None
        self._verifier: ReceiptVerifier | None = None
        self.last_receipt: Receipt | None = None
        self.claims = 0
        self.replay_rejections = 0
        self.reopen_count = 0
        self._open(initialize=not EXECUTOR_DATABASE.exists())

    def _open(self, *, initialize: bool) -> None:
        self._anchor = ProcessFileExecutorAuthorityAnchor(EXECUTOR_ANCHOR, timeout_s=5)
        if initialize:
            self._store = SQLiteReceiptReplayStore.initialize(
                EXECUTOR_DATABASE,
                authority_anchor=self._anchor,
                identity=self._identity,
            )
        else:
            self._store = SQLiteReceiptReplayStore(
                EXECUTOR_DATABASE,
                authority_anchor=self._anchor,
            )
        self._verifier = ReceiptVerifier(self._registry, self._store, self._policy)

    @property
    def store(self) -> SQLiteReceiptReplayStore:
        if self._store is None:
            raise RuntimeError("executor replay store is closed")
        return self._store

    @property
    def verifier(self) -> ReceiptVerifier:
        if self._verifier is None:
            raise RuntimeError("executor verifier is closed")
        return self._verifier

    def claim(self, receipt: Receipt) -> None:
        self.verifier.verify_and_claim(receipt)
        self.claims += 1
        self.last_receipt = receipt
        self._require_replay_rejection(receipt)

    def _require_replay_rejection(self, receipt: Receipt) -> None:
        try:
            self.verifier.verify_and_claim(receipt)
        except ReplayError:
            self.replay_rejections += 1
            return
        raise RuntimeError("executor accepted a duplicate production receipt")

    def reopen(self) -> None:
        previous = self.last_receipt
        self.close()
        self._open(initialize=False)
        self.reopen_count += 1
        if previous is not None:
            self._require_replay_rejection(previous)

    def status(self) -> dict[str, Any]:
        status = self.store.status()
        if not status.rollback_protected or not status.authority_healthy:
            raise RuntimeError("executor replay authority is not healthy and rollback protected")
        integrity = self.store.integrity_check()
        if integrity != ("ok",):
            raise RuntimeError(f"executor replay integrity failed: {integrity!r}")
        if self._anchor is None:
            raise RuntimeError("executor authority anchor is closed")
        checkpoint = self._anchor.read_current()
        if checkpoint.claim_sequence != status.claim_sequence:
            raise RuntimeError("executor database and authority anchor claim heads disagree")
        return {
            "anchor": checkpoint.to_dict(),
            "authority_healthy": status.authority_healthy,
            "claim_sequence": status.claim_sequence,
            "database_bytes": status.database_bytes,
            "integrity": list(integrity),
            "live_claims": status.live_claims,
            "live_watermarks": status.live_watermarks,
            "rollback_protected": status.rollback_protected,
            "shared_memory_bytes": status.shared_memory_bytes,
            "wal_bytes": status.wal_bytes,
        }

    def close(self) -> None:
        self._verifier = None
        self._store = None
        if self._anchor is not None:
            self._anchor.close()
            self._anchor = None


def _sum(vectors: list[list[int]]) -> list[int]:
    if not vectors:
        raise RuntimeError("cannot sum an empty vector collection")
    return [sum(vector[index] for vector in vectors) for index in range(len(vectors[0]))]


def _finite_nonnegative(value: object, *, field: str, node: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise RuntimeError(f"{node} audit exporter returned invalid {field}: {value!r}")
    return float(value)


def _allowed_transient_audit_error(value: str) -> bool:
    match = AUDIT_TRANSIENT_CONNECT_BUSY.fullmatch(value)
    if match is None or len(match.group(1)) > 64:
        return False
    error_code = int(match.group(2))
    return error_code <= 0x7FFFFFFF and error_code & 0xFF == 5


def _bounded_audit_exporter(status: object, *, node: str) -> dict[str, Any]:
    if not isinstance(status, dict):
        raise RuntimeError(f"{node} returned malformed audit exporter status: {status!r}")
    pending = status.get("pending")
    maximum_pending = status.get("max_pending")
    if (
        isinstance(pending, bool)
        or not isinstance(pending, int)
        or pending < 0
        or isinstance(maximum_pending, bool)
        or not isinstance(maximum_pending, int)
        or maximum_pending <= 0
    ):
        raise RuntimeError(f"{node} returned invalid audit backlog bounds: {status!r}")
    stalled_for = _finite_nonnegative(status.get("stalled_for_s"), field="stalled_for_s", node=node)
    maximum_stall = _finite_nonnegative(status.get("max_stall_s"), field="max_stall_s", node=node)
    if maximum_stall <= 0:
        raise RuntimeError(f"{node} returned an invalid audit stall bound: {status!r}")
    oldest_pending = status.get("oldest_pending_age_s")
    if pending == 0:
        if oldest_pending is not None:
            raise RuntimeError(f"{node} returned an age for an empty audit backlog: {status!r}")
        oldest_pending_age: float | None = None
    else:
        oldest_pending_age = _finite_nonnegative(
            oldest_pending,
            field="oldest_pending_age_s",
            node=node,
        )
    healthy = status.get("healthy")
    running = status.get("running")
    archive_reconciled = status.get("archive_reconciled")
    publish_blocked = status.get("publish_blocked")
    sink_call_blocked = status.get("sink_call_blocked")
    last_error = status.get("last_error")
    last_success_ns = status.get("last_success_ns")
    if not all(
        isinstance(value, bool)
        for value in (healthy, running, archive_reconciled, publish_blocked, sink_call_blocked)
    ):
        raise RuntimeError(f"{node} returned malformed audit exporter flags: {status!r}")
    if last_error is not None and (
        not isinstance(last_error, str)
        or not last_error.strip()
        or len(last_error.encode("utf-8")) > AUDIT_ERROR_MAX_BYTES
    ):
        raise RuntimeError(f"{node} returned a malformed bounded audit exporter error: {status!r}")
    if isinstance(last_error, str) and not _allowed_transient_audit_error(last_error):
        raise RuntimeError(f"{node} returned a non-tolerable audit exporter error: {status!r}")
    if last_error is not None and (
        isinstance(last_success_ns, bool)
        or not isinstance(last_success_ns, int)
        or last_success_ns <= 0
    ):
        raise RuntimeError(f"{node} audit exporter error lacks a prior success: {status!r}")
    if (
        running is not True
        or publish_blocked is not False
        or sink_call_blocked is not False
        or pending > maximum_pending
        or stalled_for > maximum_stall
        or (oldest_pending_age is not None and oldest_pending_age > maximum_stall)
    ):
        raise RuntimeError(f"{node} audit exporter is not making bounded progress: {status!r}")
    if last_error is not None and archive_reconciled is not False:
        raise RuntimeError(f"{node} returned a reconciled audit exporter error: {status!r}")
    expected_healthy = last_error is None and archive_reconciled is True
    if healthy is not expected_healthy:
        raise RuntimeError(f"{node} returned inconsistent audit exporter health: {status!r}")
    return {
        key: status.get(key)
        for key in (
            "archive_reconciled",
            "healthy",
            "last_error",
            "last_success_ns",
            "max_pending",
            "max_stall_s",
            "oldest_pending_age_s",
            "pending",
            "publish_blocked",
            "running",
            "sink_call_blocked",
            "stalled_for_s",
        )
    } | {"catching_up": healthy is False}


@dataclass
class AuditErrorBudget:
    """Fail live after the single globally tolerated sampled exporter error."""

    sample_budget: int = AUDIT_ERROR_SAMPLE_BUDGET
    error_sample_count: int = 0
    error_samples_by_node: dict[str, int] = field(
        default_factory=lambda: {node: 0 for node in NODES}
    )
    recovered_error_sample_count: int = 0
    unresolved_error_nodes: set[str] = field(default_factory=set)

    def observe_error(self, node: str) -> None:
        observed = self.error_sample_count + 1
        if observed > self.sample_budget:
            raise RuntimeError(
                "sampled audit exporter transient error budget exceeded: "
                f"budget={self.sample_budget} observed={observed} node={node!r}"
            )
        self.error_sample_count = observed
        self.error_samples_by_node[node] += 1
        self.unresolved_error_nodes.add(node)

    def mark_recovered(self, node: str) -> None:
        if node not in self.unresolved_error_nodes:
            raise RuntimeError(f"audit exporter recovery had no sampled error: {node}")
        self.unresolved_error_nodes.remove(node)
        self.recovered_error_sample_count += 1


def _audit_recovery_clean(document: object) -> bool:
    if not isinstance(document, dict):
        return False
    exporter = document.get("audit_exporter")
    outbox = document.get("audit_outbox")
    return bool(
        isinstance(exporter, dict)
        and exporter.get("running") is True
        and exporter.get("healthy") is True
        and exporter.get("archive_reconciled") is True
        and exporter.get("catching_up") is False
        and exporter.get("last_error") is None
        and exporter.get("pending") == 0
        and exporter.get("publish_blocked") is False
        and exporter.get("sink_call_blocked") is False
        and isinstance(outbox, dict)
        and outbox.get("unpublished_count") == 0
        and document.get("ready") is True
        and document.get("service_ready") is True
    )


def _poll_audit_error_recovery(
    client: ClusterClient,
    *,
    node: str,
    initial_exporter: dict[str, Any],
    initial_elapsed_s: float,
    initial_observed_monotonic: float,
) -> dict[str, Any]:
    stalled_for = float(initial_exporter["stalled_for_s"])
    maximum_stall = float(initial_exporter["max_stall_s"])
    remaining_window = maximum_stall - stalled_for
    if not math.isfinite(remaining_window) or remaining_window <= 0:
        raise RuntimeError(f"{node} audit exporter has no remaining recovery window")
    deadline = initial_observed_monotonic + remaining_window
    last: object = None
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            metrics = client.request(
                "GET",
                node,
                "/v1/metrics",
                retry_timeout_s=max(0.001, remaining),
            )
        except RuntimeError as exc:
            last = f"{type(exc).__name__}: {exc}"
            if time.monotonic() >= deadline:
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
            continue
        exporter = _bounded_audit_exporter(metrics.get("audit_exporter"), node=node)
        last = {
            "audit_exporter": exporter,
            "audit_outbox": metrics.get("audit_outbox"),
            "ready": metrics.get("ready"),
            "service_ready": metrics.get("service_ready"),
        }
        observed_at = time.monotonic()
        if observed_at <= deadline and _audit_recovery_clean(last):
            return {
                **cast(dict[str, Any], last),
                "elapsed_seconds": round(
                    initial_elapsed_s + observed_at - initial_observed_monotonic,
                    6,
                ),
                "node": node,
                "remaining_stall_window_seconds": round(remaining_window, 3),
            }
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    raise RuntimeError(
        f"{node} audit exporter did not recover within its remaining "
        f"{remaining_window:.3f}s stall window: {last!r}"
    )


def _health_sample(
    client: ClusterClient,
    *,
    elapsed_s: float,
    audit_error_budget: AuditErrorBudget | None = None,
) -> dict[str, Any]:
    nodes: dict[str, Any] = {}
    audit_catchup_nodes: list[str] = []
    audit_error_recoveries: list[dict[str, Any]] = []
    for node in NODES:
        invariant = client.request("GET", node, "/v1/invariants")
        audit = client.request("GET", node, "/v1/audit/verify")
        metrics = client.request("GET", node, "/v1/metrics")
        metrics_observed_monotonic = time.monotonic()
        audit_exporter = _bounded_audit_exporter(metrics.get("audit_exporter"), node=node)
        capacity = metrics.get("storage_capacity")
        if invariant.get("healthy") is not True or audit.get("valid") is not True:
            raise RuntimeError(f"{node} reported unhealthy invariants or audit chain")
        if not isinstance(capacity, dict) or capacity.get("healthy") is not True:
            raise RuntimeError(f"{node} storage capacity is unhealthy: {capacity!r}")
        if metrics.get("service_ready") is not True:
            raise RuntimeError(f"{node} core service is not ready: {metrics!r}")
        expected_ready = audit_exporter["healthy"] is True
        if metrics.get("ready") is not expected_ready:
            raise RuntimeError(f"{node} returned inconsistent aggregate readiness: {metrics!r}")
        if audit_exporter["catching_up"] is True:
            audit_catchup_nodes.append(node)
        nodes[node] = {
            "audit_exporter": audit_exporter,
            "audit_outbox": metrics.get("audit_outbox"),
            "invariant": {
                key: invariant.get(key)
                for key in (
                    "consumed",
                    "free_pool",
                    "healthy",
                    "lease_residual",
                    "transferred_in",
                    "transferred_out",
                )
            },
            "peer_dispatcher": metrics.get("peer_dispatcher"),
            "ready": metrics.get("ready"),
            "service_ready": metrics.get("service_ready"),
            "receipts": metrics.get("receipts"),
            "storage_capacity": capacity,
            "transfers": metrics.get("transfers"),
        }
        if audit_exporter.get("last_error") is not None:
            if audit_error_budget is None:
                raise RuntimeError(
                    f"{node} sampled an audit exporter error outside the shared "
                    "workload error budget"
                )
            audit_error_budget.observe_error(node)
            recovery = _poll_audit_error_recovery(
                client,
                node=node,
                initial_exporter=audit_exporter,
                initial_elapsed_s=elapsed_s,
                initial_observed_monotonic=metrics_observed_monotonic,
            )
            audit_error_budget.mark_recovered(node)
            audit_error_recoveries.append(recovery)
    sample = {
        "audit_catchup_nodes": audit_catchup_nodes,
        "audit_error_recoveries": audit_error_recoveries,
        "elapsed_seconds": round(elapsed_s, 3),
        "nodes": nodes,
    }
    return sample


def _is_converged(sample: dict[str, Any]) -> bool:
    for node in NODES:
        document = sample["nodes"][node]
        dispatcher = document.get("peer_dispatcher")
        audit_exporter = document.get("audit_exporter")
        outbox = document.get("audit_outbox")
        transfers = document.get("transfers")
        if not isinstance(dispatcher, dict) or not isinstance(audit_exporter, dict):
            return False
        if not isinstance(outbox, dict) or not isinstance(transfers, dict):
            return False
        if (
            document.get("ready") is not True
            or document.get("service_ready") is not True
            or audit_exporter.get("running") is not True
            or audit_exporter.get("healthy") is not True
            or audit_exporter.get("archive_reconciled") is not True
            or audit_exporter.get("catching_up") is not False
            or audit_exporter.get("last_error") is not None
            or dispatcher.get("configured_peers") != len(NODES) - 1
            or dispatcher.get("failed_records") != 0
            or dispatcher.get("last_error") is not None
            or not isinstance(dispatcher.get("last_cycle_ns"), int)
            or int(dispatcher["last_cycle_ns"]) <= 0
            or dispatcher.get("pending_records") != 0
            or dispatcher.get("prepared_transfers") != 0
            or transfers.get("in_flight_count") != 0
            or transfers.get("inbound_gap_count") != 0
            or audit_exporter.get("pending") != 0
            or outbox.get("unpublished_count") != 0
        ):
            return False
    return True


def _conservation_totals(sample: dict[str, Any]) -> dict[str, Any]:
    invariants = [sample["nodes"][node]["invariant"] for node in NODES]
    transferred_in = _sum([cast(list[int], item["transferred_in"]) for item in invariants])
    transferred_out = _sum([cast(list[int], item["transferred_out"]) for item in invariants])
    return {
        "balanced": transferred_in == transferred_out,
        "transferred_in": transferred_in,
        "transferred_out": transferred_out,
    }


def _audit_progress_summary(
    samples: list[dict[str, Any]],
    *,
    audit_error_budget: AuditErrorBudget | None = None,
) -> dict[str, Any]:
    maximum_pending = {node: 0 for node in NODES}
    recorded_error_samples_by_node = {node: 0 for node in NODES}
    catchup_samples = 0
    recorded_error_sample_count = 0
    recorded_recovered_error_sample_count = 0
    recorded_unresolved_error_nodes: set[str] = set()
    for sample in samples:
        catchup_nodes = sample.get("audit_catchup_nodes")
        if not isinstance(catchup_nodes, list):
            raise RuntimeError(f"health sample omitted audit catch-up evidence: {sample!r}")
        if catchup_nodes:
            catchup_samples += 1
        recoveries = sample.get("audit_error_recoveries")
        if not isinstance(recoveries, list):
            raise RuntimeError(f"health sample omitted audit recovery evidence: {sample!r}")
        recovery_by_node: dict[str, dict[str, Any]] = {}
        for recovery in recoveries:
            if not isinstance(recovery, dict) or recovery.get("node") not in NODES:
                raise RuntimeError(f"health sample has malformed audit recovery: {sample!r}")
            recovery_node = cast(str, recovery["node"])
            if recovery_node in recovery_by_node:
                raise RuntimeError(f"health sample duplicated {recovery_node} recovery: {sample!r}")
            recovery_by_node[recovery_node] = cast(dict[str, Any], recovery)
        nodes = sample.get("nodes")
        if not isinstance(nodes, dict):
            raise RuntimeError(f"health sample omitted node evidence: {sample!r}")
        sample_elapsed = sample.get("elapsed_seconds")
        if isinstance(sample_elapsed, bool) or not isinstance(sample_elapsed, (int, float)):
            raise RuntimeError(f"health sample omitted audit recovery time: {sample!r}")
        for node in NODES:
            document = nodes.get(node)
            if not isinstance(document, dict):
                raise RuntimeError(f"health sample omitted {node}: {sample!r}")
            exporter = document.get("audit_exporter")
            if not isinstance(exporter, dict):
                raise RuntimeError(f"health sample omitted {node} audit status: {sample!r}")
            pending = exporter.get("pending")
            if isinstance(pending, bool) or not isinstance(pending, int) or pending < 0:
                raise RuntimeError(f"health sample has invalid {node} audit backlog: {sample!r}")
            maximum_pending[node] = max(maximum_pending[node], pending)
            if exporter.get("last_error") is not None:
                recorded_error_sample_count += 1
                recorded_error_samples_by_node[node] += 1
                recorded_unresolved_error_nodes.add(node)
                recovery = recovery_by_node.pop(node, None)
                if recovery is not None:
                    recovery_elapsed = recovery.get("elapsed_seconds")
                    remaining_window = recovery.get("remaining_stall_window_seconds")
                    if (
                        isinstance(recovery_elapsed, bool)
                        or not isinstance(recovery_elapsed, (int, float))
                        or isinstance(remaining_window, bool)
                        or not isinstance(remaining_window, (int, float))
                        or not float(sample_elapsed) < float(recovery_elapsed)
                        or float(recovery_elapsed) - float(sample_elapsed)
                        > float(remaining_window) + 0.001
                        or not _audit_recovery_clean(recovery)
                    ):
                        raise RuntimeError(
                            f"health sample has invalid bounded {node} audit recovery: {sample!r}"
                        )
                    recorded_recovered_error_sample_count += 1
                    recorded_unresolved_error_nodes.remove(node)
            elif node in recovery_by_node:
                raise RuntimeError(f"health sample recovered unfailed {node}: {sample!r}")
        if recovery_by_node:
            raise RuntimeError(f"health sample has unbound audit recoveries: {sample!r}")
    if audit_error_budget is None:
        error_sample_count = recorded_error_sample_count
        error_samples_by_node = recorded_error_samples_by_node
        recovered_error_sample_count = recorded_recovered_error_sample_count
        unresolved_error_nodes = recorded_unresolved_error_nodes
    else:
        error_sample_count = audit_error_budget.error_sample_count
        error_samples_by_node = dict(audit_error_budget.error_samples_by_node)
        recovered_error_sample_count = audit_error_budget.recovered_error_sample_count
        unresolved_error_nodes = set(audit_error_budget.unresolved_error_nodes)
    error_evidence_complete = (
        error_sample_count == recorded_error_sample_count
        and error_samples_by_node == recorded_error_samples_by_node
        and recovered_error_sample_count == recorded_recovered_error_sample_count
        and unresolved_error_nodes == recorded_unresolved_error_nodes
    )
    error_recovery_passed = (
        error_sample_count <= AUDIT_ERROR_SAMPLE_BUDGET
        and recovered_error_sample_count == error_sample_count
        and not unresolved_error_nodes
        and error_evidence_complete
    )
    return {
        "bounded_progress": error_recovery_passed,
        "catchup_sample_count": catchup_samples,
        "error_evidence_complete": error_evidence_complete,
        "error_recovery_passed": error_recovery_passed,
        "error_sample_budget": AUDIT_ERROR_SAMPLE_BUDGET,
        "error_sample_count": error_sample_count,
        "error_samples_by_node": error_samples_by_node,
        "maximum_pending_by_node": maximum_pending,
        "recorded_error_sample_count": recorded_error_sample_count,
        "recorded_error_samples_by_node": recorded_error_samples_by_node,
        "recorded_recovered_error_sample_count": recorded_recovered_error_sample_count,
        "recorded_unresolved_error_nodes": sorted(recorded_unresolved_error_nodes),
        "recovered_error_sample_count": recovered_error_sample_count,
        "sample_count": len(samples),
        "unresolved_error_nodes": sorted(unresolved_error_nodes),
    }


def _validate_conservation(sample: dict[str, Any]) -> dict[str, Any]:
    totals = _conservation_totals(sample)
    transferred_in = totals["transferred_in"]
    transferred_out = totals["transferred_out"]
    if transferred_in != transferred_out:
        raise RuntimeError(
            f"cluster transfer totals do not conserve: in={transferred_in} out={transferred_out}"
        )
    return totals


def _wait_if_paused(
    client: ClusterClient,
    *,
    audit_error_budget: AuditErrorBudget | None = None,
    health_interval_seconds: float,
    health_samples: deque[dict[str, Any]],
    next_health: float,
    started: float,
) -> tuple[float, int]:
    sample_count = 0
    while WORKLOAD_PAUSE.exists():
        request = _object(WORKLOAD_PAUSE)
        episode = request.get("episode")
        if not isinstance(episode, int) or episode < 0:
            raise RuntimeError(f"invalid workload pause request: {request!r}")
        WORKLOAD_PAUSE_ACK.write_text(
            json.dumps({"episode": episode, "paused": True}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        now = time.monotonic()
        if now >= next_health:
            health_samples.append(
                _health_sample(
                    client,
                    elapsed_s=now - started,
                    audit_error_budget=audit_error_budget,
                )
            )
            sample_count += 1
            next_health = time.monotonic() + health_interval_seconds
        time.sleep(0.05)
    return next_health, sample_count


def run_workload(arguments: argparse.Namespace) -> dict[str, Any]:
    manifest = _verified_manifest()
    policy = manifest.policies[0]
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    executor = ExecutorBoundary(manifest)
    audit_error_budget = AuditErrorBudget()
    health_samples: deque[dict[str, Any]] = deque(maxlen=MAX_RECORDED_HEALTH_SAMPLES)
    health_sample_count = 0
    counters = {
        "authorizations": 0,
        "closed": 0,
        "issued_roots": 0,
        "quiesced": 0,
        "renewed": 0,
        "resumed": 0,
        "transfers_prepared": 0,
    }
    transfer_pair_counts = {f"{source}->{target}": 0 for source, target in TRANSFER_PAIRS}
    latency = LatencyHistogram()
    started = time.monotonic()
    deadline = started + arguments.duration_seconds
    next_health = started
    cycle = 0
    try:
        while time.monotonic() < deadline:
            next_health, pause_health_samples = _wait_if_paused(
                client,
                audit_error_budget=audit_error_budget,
                health_interval_seconds=arguments.health_interval_seconds,
                health_samples=health_samples,
                next_health=next_health,
                started=started,
            )
            health_sample_count += pause_health_samples
            if time.monotonic() >= deadline:
                break
            cycle_started = time.monotonic()
            plan = operation_plan(cycle)
            node = cast(str, plan["node"])
            prefix = f"soak-{arguments.seed}-{cycle:012d}"
            root = client.request(
                "POST",
                node,
                "/v1/roots",
                body={
                    "allocation": [4],
                    "capabilities": ["worker.act"],
                    "envelope_id": ENVELOPE_ID,
                    "policy_digest": policy.digest,
                    "request_id": f"{prefix}-root",
                    "subject_id": f"soak-subject-{cycle % 32:02d}",
                    "tenant_id": TENANT_ID,
                    "ttl_ns": 300_000_000_000,
                },
                expected=201,
            )
            counters["issued_roots"] += 1
            lease_id = str(root["lease_id"])

            first = client.request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/transitions",
                body={
                    "executor_audience": EXECUTOR_AUDIENCE,
                    "nonce": f"{prefix}-nonce-1",
                    "request_id": f"{prefix}-authorize-1",
                    "transition": "act",
                },
            )
            executor.claim(Receipt.from_dict(first))
            counters["authorizations"] += 1

            client.request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/quiesce",
                body={"request_id": f"{prefix}-quiesce"},
            )
            counters["quiesced"] += 1
            client.request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/resume",
                body={"request_id": f"{prefix}-resume"},
            )
            counters["resumed"] += 1
            client.request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/renew",
                body={"request_id": f"{prefix}-renew", "ttl_ns": 300_000_000_000},
            )
            counters["renewed"] += 1

            second = client.request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/transitions",
                body={
                    "executor_audience": EXECUTOR_AUDIENCE,
                    "nonce": f"{prefix}-nonce-2",
                    "request_id": f"{prefix}-authorize-2",
                    "transition": "act",
                },
            )
            executor.claim(Receipt.from_dict(second))
            counters["authorizations"] += 1
            client.request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/close",
                body={"request_id": f"{prefix}-close"},
            )
            counters["closed"] += 1

            transfer_pair = scheduled_transfer_pair(cycle, arguments.transfer_every_cycles)
            if transfer_pair is not None:
                transfer_source, transfer_target = transfer_pair
                client.request(
                    "POST",
                    transfer_source,
                    "/v1/transfers/prepare",
                    body={
                        "amount": [1],
                        "envelope_id": ENVELOPE_ID,
                        "policy_digest": policy.digest,
                        "request_id": f"{prefix}-transfer",
                        "target_warden": transfer_target,
                        "tenant_id": TENANT_ID,
                    },
                    expected=201,
                )
                counters["transfers_prepared"] += 1
                transfer_pair_counts[f"{transfer_source}->{transfer_target}"] += 1

            cycle += 1
            if cycle % arguments.executor_reopen_every_cycles == 0:
                executor.reopen()
            now = time.monotonic()
            if now >= next_health:
                health_samples.append(
                    _health_sample(
                        client,
                        elapsed_s=now - started,
                        audit_error_budget=audit_error_budget,
                    )
                )
                health_sample_count += 1
                next_health = now + arguments.health_interval_seconds
            latency.observe(time.monotonic() - cycle_started)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(arguments.cycle_interval_seconds, remaining))

        final_health = _health_sample(
            client,
            elapsed_s=time.monotonic() - started,
            audit_error_budget=audit_error_budget,
        )
        health_samples.append(final_health)
        health_sample_count += 1
        recorded_health_samples = list(health_samples)
        conservation = _conservation_totals(final_health)
        return {
            "audit_progress": _audit_progress_summary(
                recorded_health_samples,
                audit_error_budget=audit_error_budget,
            ),
            "configuration": {
                "cycle_interval_seconds": arguments.cycle_interval_seconds,
                "duration_seconds": arguments.duration_seconds,
                "executor_reopen_every_cycles": arguments.executor_reopen_every_cycles,
                "health_interval_seconds": arguments.health_interval_seconds,
                "retry_timeout_seconds": arguments.retry_timeout_seconds,
                "seed": arguments.seed,
                "transfer_every_cycles": arguments.transfer_every_cycles,
            },
            "conservation": conservation,
            "counters": counters,
            "cycles": cycle,
            "duration_seconds": round(time.monotonic() - started, 3),
            "executor": {
                "claims": executor.claims,
                "reopen_count": executor.reopen_count,
                "replay_rejections": executor.replay_rejections,
                "status": executor.status(),
            },
            "health_sample_count": health_sample_count,
            "health_samples": recorded_health_samples,
            "latency": latency.to_dict(),
            "package_version": metadata.version("lets-agent"),
            "request_retry_count": client.retry_count,
            "schema": "lets.production-profile-soak-workload/v1",
            "status": "passed",
            "transfer_pair_counts": transfer_pair_counts,
        }
    finally:
        executor.close()


def run_partition_probe(arguments: argparse.Namespace) -> dict[str, Any]:
    """Create and observe one durable A/B transfer while both proxy links are disabled."""

    manifest = _verified_manifest()
    policy = manifest.policies[0]
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    source, target = (("warden-a", "warden-b"), ("warden-b", "warden-a"))[arguments.episode % 2]
    baseline = client.request("GET", source, "/v1/metrics")
    baseline_dispatcher = baseline.get("peer_dispatcher")
    if not isinstance(baseline_dispatcher, dict):
        raise RuntimeError(f"{source} returned malformed peer dispatcher metrics")
    voucher = client.request(
        "POST",
        source,
        "/v1/transfers/prepare",
        body={
            "amount": [1],
            "envelope_id": ENVELOPE_ID,
            "policy_digest": policy.digest,
            "request_id": f"soak-partition-{arguments.seed}-{arguments.episode:06d}",
            "target_warden": target,
            "tenant_id": TENANT_ID,
        },
        expected=201,
    )
    started = time.monotonic()
    deadline = started + arguments.observation_timeout_seconds
    observed_metrics: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        metrics = client.request("GET", source, "/v1/metrics")
        dispatcher = metrics.get("peer_dispatcher")
        if (
            isinstance(dispatcher, dict)
            and int(dispatcher.get("pending_records", 0)) >= 1
            and int(dispatcher.get("prepared_transfers", 0)) >= 1
            and int(dispatcher.get("failed_records", 0))
            > int(baseline_dispatcher.get("failed_records", 0))
            and int(dispatcher.get("last_cycle_ns", 0))
            > int(baseline_dispatcher.get("last_cycle_ns", 0))
            and isinstance(metrics.get("transfers"), dict)
            and int(metrics["transfers"].get("in_flight_count", 0)) >= 1
        ):
            observed_metrics = metrics
            break
        time.sleep(0.1)
    if observed_metrics is None:
        raise RuntimeError(
            "A/B partition did not produce a durable failed pending transfer before the deadline"
        )
    observed_dispatcher = cast(dict[str, Any], observed_metrics["peer_dispatcher"])
    return {
        "baseline": {
            "failed_records": int(baseline_dispatcher.get("failed_records", 0)),
            "last_cycle_ns": int(baseline_dispatcher.get("last_cycle_ns", 0)),
            "pending_records": int(baseline_dispatcher.get("pending_records", 0)),
            "prepared_transfers": int(baseline_dispatcher.get("prepared_transfers", 0)),
        },
        "durably_pending_observed": True,
        "episode": arguments.episode,
        "observation_seconds": round(time.monotonic() - started, 3),
        "observed": {
            "failed_records": int(observed_dispatcher["failed_records"]),
            "last_cycle_ns": int(observed_dispatcher["last_cycle_ns"]),
            "pending_records": int(observed_dispatcher["pending_records"]),
            "prepared_transfers": int(observed_dispatcher["prepared_transfers"]),
            "transfers": observed_metrics.get("transfers"),
        },
        "package_version": metadata.version("lets-agent"),
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-soak-partition/v1",
        "sequence": int(voucher["sequence"]),
        "source": source,
        "status": "passed",
        "target": target,
        "transfer_id": str(voucher["transfer_id"]),
    }


def wait_converged(arguments: argparse.Namespace) -> dict[str, Any]:
    """Wait for all peer, transfer, and audit queues to settle without opening executor state."""

    _verified_manifest()
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    started = time.monotonic()
    deadline = started + arguments.convergence_timeout_seconds
    final_sample: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        final_sample = _health_sample(client, elapsed_s=time.monotonic() - started)
        if _is_converged(final_sample):
            break
        time.sleep(0.25)
    if final_sample is None or not _is_converged(final_sample):
        raise RuntimeError(f"cluster did not settle for partition injection: {final_sample!r}")
    return {
        "converged": True,
        "convergence_seconds": round(time.monotonic() - started, 3),
        "final_health": final_sample,
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-soak-settle/v1",
        "status": "passed",
    }


def verify_final(arguments: argparse.Namespace) -> dict[str, Any]:
    _verified_manifest()
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    started = time.monotonic()
    deadline = started + arguments.convergence_timeout_seconds
    final_sample: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        final_sample = _health_sample(client, elapsed_s=time.monotonic() - started)
        if _is_converged(final_sample):
            break
        time.sleep(0.5)
    if final_sample is None or not _is_converged(final_sample):
        raise RuntimeError(f"cluster did not converge before the soak deadline: {final_sample!r}")
    conservation = _validate_conservation(final_sample)
    anchor = ProcessFileExecutorAuthorityAnchor(EXECUTOR_ANCHOR, timeout_s=5)
    try:
        store = SQLiteReceiptReplayStore(EXECUTOR_DATABASE, authority_anchor=anchor)
        status = store.status()
        integrity = store.integrity_check()
        checkpoint = anchor.read_current()
    finally:
        anchor.close()
    if (
        not status.rollback_protected
        or not status.authority_healthy
        or integrity != ("ok",)
        or checkpoint.claim_sequence != status.claim_sequence
    ):
        raise RuntimeError("final executor replay authority verification failed")
    return {
        "conservation": conservation,
        "converged": True,
        "convergence_seconds": round(time.monotonic() - started, 3),
        "executor": {
            "anchor_claim_sequence": checkpoint.claim_sequence,
            "authority_healthy": status.authority_healthy,
            "claim_sequence": status.claim_sequence,
            "database_bytes": status.database_bytes,
            "integrity": list(integrity),
            "rollback_protected": status.rollback_protected,
            "wal_bytes": status.wal_bytes,
        },
        "final_health": final_sample,
        "package_version": metadata.version("lets-agent"),
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-soak-verification/v1",
        "status": "passed",
    }


def _positive(value: str) -> float:
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
    subcommands = parser.add_subparsers(dest="command", required=True)
    workload = subcommands.add_parser("run")
    workload.add_argument("--duration-seconds", type=_positive, required=True)
    workload.add_argument("--cycle-interval-seconds", type=_positive, default=0.5)
    workload.add_argument("--health-interval-seconds", type=_positive, default=10.0)
    workload.add_argument("--retry-timeout-seconds", type=_positive, default=90.0)
    workload.add_argument("--transfer-every-cycles", type=_positive_int, default=3)
    workload.add_argument("--executor-reopen-every-cycles", type=_positive_int, default=10)
    workload.add_argument("--seed", type=int, default=20260809)
    workload.add_argument("--output", type=Path, required=True)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--convergence-timeout-seconds", type=_positive, default=180.0)
    verify.add_argument("--retry-timeout-seconds", type=_positive, default=90.0)
    verify.add_argument("--seed", type=int, default=20260809)
    verify.add_argument("--output", type=Path, required=True)

    partition = subcommands.add_parser("partition-probe")
    partition.add_argument("--episode", type=int, required=True)
    partition.add_argument("--observation-timeout-seconds", type=_positive, default=30.0)
    partition.add_argument("--retry-timeout-seconds", type=_positive, default=30.0)
    partition.add_argument("--seed", type=int, default=20260809)
    partition.add_argument("--output", type=Path, required=True)

    settle = subcommands.add_parser("settle")
    settle.add_argument("--convergence-timeout-seconds", type=_positive, default=30.0)
    settle.add_argument("--retry-timeout-seconds", type=_positive, default=30.0)
    settle.add_argument("--seed", type=int, default=20260809)
    settle.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    if arguments.command == "run":
        result = run_workload(arguments)
    elif arguments.command == "partition-probe":
        result = run_partition_probe(arguments)
    elif arguments.command == "settle":
        result = wait_converged(arguments)
    else:
        result = verify_final(arguments)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "cycles": result.get("cycles"),
                "output": str(arguments.output),
                "schema": result["schema"],
                "status": result["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
