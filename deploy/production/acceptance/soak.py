"""Drive sustained mixed traffic and verify production-profile soak health."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, TypeGuard, cast

import httpx
from nacl.signing import SigningKey

from lets.canonical import b64url_decode, b64url_encode, canonical_json, strict_json_loads
from lets.crypto import PublicKeyRegistry
from lets.errors import AuthorityAnchorTransportError, ReplayError
from lets.executor import (
    ExecutorPolicy,
    ReceiptVerifier,
    SQLiteReceiptReplayStore,
    executor_replay_identity,
)
from lets.executor_authority import (
    ExecutorAuthorityCheckpoint,
    ProcessFileExecutorAuthorityAnchor,
)
from lets.manifest import ClusterManifest
from lets.models import Receipt
from lets.observation import OBSERVATION_CAPTURE_INTERVAL_SECONDS

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
WORKLOAD_RESTART = Path("/scenario/soak-workload-restart.json")
WORKLOAD_RESTART_ACK = Path("/scenario/soak-workload-restart-ack.json")
_RESTART_ACK_LOCK = threading.Lock()
WORKLOAD_START = Path("/scenario/soak-workload-start.json")
WORKLOAD_RESULT = Path("/scenario/soak-workload.json")
WORKLOAD_JOURNAL = Path("/scenario/soak-workload-journal.json")
WORKLOAD_ARTIFACT_MAX_BYTES = 64 * 1024 * 1024
WORKLOAD_JOURNAL_MAX_BYTES = 2 * 1024 * 1024
WORKLOAD_JOURNAL_CYCLE_SECONDS = 5.0
OBSERVATION_RESPONSE_MAX_BYTES = 20 * 1024
GENERAL_RESPONSE_MAX_BYTES = 2 * 1024 * 1024
HEALTH_CADENCE_LIMIT_SECONDS = 15.0
# A terminal sample may be scheduled milliseconds after the last regular sample
# when the workload duration lands on a cadence boundary.  Wait for one full
# publisher sleep plus bounded scheduling/capture margin so the one permitted
# metrics request observes a new coherent snapshot.  The original cadence
# deadline remains authoritative and still fails closed if publication stalls.
FINAL_HEALTH_OBSERVATION_ADVANCE_SECONDS = OBSERVATION_CAPTURE_INTERVAL_SECONDS + 1.0
MAXIMUM_PLANNED_RESTART_SECONDS = 30.0
MAXIMUM_PLANNED_FENCE_PREPARATION_SECONDS = 120.0
AUTHORITY_FAILURE_DIAGNOSTIC_SECONDS = 7.0
AUDIT_ERROR_MAX_BYTES = 64
AUDIT_ERROR_SAMPLE_BUDGET = 1
AUTHORITY_COUNTER_MAX = (1 << 63) - 1
AUDIT_TRANSIENT_CONNECT_BUSY = "StorageError:sqlite_busy"
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


def _evidence_object(path: Path, *, maximum_bytes: int) -> dict[str, Any]:
    """Read one bounded generated artifact while retaining finite timing values."""

    def finite_float(encoded: str) -> float:
        value = float(encoded)
        if not math.isfinite(value):
            raise ValueError(f"non-finite evidence number is forbidden: {encoded}")
        return value

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite evidence number is forbidden: {value}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate evidence key is forbidden: {key}")
            result[key] = value
        return result

    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise ValueError("evidence byte limit must be a positive integer")
    with path.open("rb") as source:
        encoded = source.read(maximum_bytes + 1)
    if len(encoded) > maximum_bytes:
        raise ValueError(f"{path} exceeds its {maximum_bytes}-byte evidence limit")
    value = json.loads(
        encoded,
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
        parse_float=finite_float,
    )
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not an evidence JSON object")
    return cast(dict[str, Any], value)


def _coordination_object(path: Path) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite coordination number is forbidden: {value}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate coordination key is forbidden: {key}")
            result[key] = value
        return result

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_constant,
    )
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not a coordination JSON object")
    return cast(dict[str, Any], value)


def _bounded_response_json(value: bytes) -> object:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate response key: {key}")
            result[key] = item
        return result

    def reject(constant: str) -> object:
        raise ValueError(f"non-finite response number: {constant}")

    return json.loads(
        value,
        object_pairs_hook=unique,
        parse_constant=reject,
    )


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
    def __init__(
        self,
        *,
        seed: int,
        retry_timeout_s: float,
        abort_event: threading.Event | None = None,
    ) -> None:
        self._tokens = TokenIssuer(seed=seed)
        self._tls = _tls_context()
        self._retry_timeout_s = retry_timeout_s
        self._abort_event = abort_event
        self.retry_count = 0
        self._retry_scope_first_error: str | None = None
        self._retry_scope_last_error: str | None = None
        self.last_request_attempt_count = 0

    def begin_retry_scope(self) -> None:
        self._retry_scope_first_error = None
        self._retry_scope_last_error = None
        self.last_request_attempt_count = 0

    def retry_scope(self) -> dict[str, str | None]:
        return {
            "first_error": self._retry_scope_first_error,
            "last_error": self._retry_scope_last_error,
        }

    def _record_retry_error(self, value: str) -> None:
        bounded = value[:512]
        if self._retry_scope_first_error is None:
            self._retry_scope_first_error = bounded
        self._retry_scope_last_error = bounded

    @staticmethod
    def _retry_component(value: object, *, maximum: int) -> str:
        if not isinstance(value, str) or not value:
            return "none"
        bounded = value[:maximum]
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in bounded):
            return "invalid"
        return bounded

    @classmethod
    def _http_retry_error(
        cls,
        *,
        body: dict[str, Any] | None,
        method: str,
        node: str,
        path: str,
        response_body: bytes,
        response_headers: httpx.Headers,
        response_status: int,
    ) -> str:
        problem_code: object = None
        try:
            problem = _bounded_response_json(response_body)
        except (ValueError, TypeError):
            problem = None
        if isinstance(problem, dict):
            problem_code = problem.get("code")
        correlation: object = None
        if isinstance(body, dict):
            correlation = body.get("request_id", body.get("restart_id"))
        response_id = response_headers.get("x-request-id")
        return (
            f"http_status:{response_status};"
            f"code:{cls._retry_component(problem_code, maximum=64)};"
            f"method:{cls._retry_component(method, maximum=16)};"
            f"node:{cls._retry_component(node, maximum=32)};"
            f"path:{cls._retry_component(path, maximum=160)};"
            f"request:{cls._retry_component(correlation, maximum=128)};"
            f"response:{cls._retry_component(response_id, maximum=128)}"
        )

    def _raise_if_aborted(self) -> None:
        if self._abort_event is not None and self._abort_event.is_set():
            raise RuntimeError("request aborted after the health monitor failed")

    def request(
        self,
        method: str,
        node: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        expected: int = 200,
        retry_timeout_s: float | None = None,
        deadline_monotonic: float | None = None,
        interrupt: Callable[[], None] | None = None,
        single_attempt: bool = False,
    ) -> dict[str, Any]:
        self._raise_if_aborted()
        self.last_request_attempt_count = 0
        retry_window = (
            self._retry_timeout_s
            if retry_timeout_s is None
            else min(self._retry_timeout_s, retry_timeout_s)
        )
        if not math.isfinite(retry_window) or retry_window <= 0:
            raise RuntimeError("request retry timeout must be finite and positive")
        started = time.monotonic()
        deadline = started + retry_window
        if deadline_monotonic is not None:
            if not math.isfinite(deadline_monotonic) or deadline_monotonic <= started:
                raise RuntimeError("request deadline must be finite and in the future")
            deadline = min(deadline, deadline_monotonic)
        last_error = "request was not attempted"
        attempted_requests = 0
        while time.monotonic() < deadline:
            self._raise_if_aborted()
            if interrupt is not None:
                interrupt()
            headers = {"authorization": f"Bearer {self._tokens.issue()}"}
            request_timeout_cap = (
                90.0
                if path == "/v1/maintenance/authority-fence"
                else 65.0
                if path == "/v1/audit/verify"
                else 10.0
            )
            request_timeout = max(
                0.001,
                min(request_timeout_cap, deadline - time.monotonic()),
            )
            try:
                with httpx.Client(
                    verify=self._tls,
                    headers=headers,
                    timeout=request_timeout,
                ) as client:
                    if attempted_requests > 0:
                        self.retry_count += 1
                    attempted_requests += 1
                    self.last_request_attempt_count = attempted_requests
                    maximum_response = (
                        OBSERVATION_RESPONSE_MAX_BYTES
                        if method == "GET" and path == "/v1/metrics"
                        else GENERAL_RESPONSE_MAX_BYTES
                    )
                    with client.stream(
                        method,
                        f"{NODE_URLS[node]}{path}",
                        json=body,
                    ) as response:
                        content_length = response.headers.get("content-length")
                        if (
                            content_length is not None
                            and content_length.isascii()
                            and content_length.isdecimal()
                            and int(content_length) > maximum_response
                        ):
                            raise RuntimeError(f"{node}{path} exceeded its response byte bound")
                        chunks: list[bytes] = []
                        response_bytes = 0
                        for chunk in response.iter_bytes():
                            response_bytes += len(chunk)
                            if response_bytes > maximum_response:
                                raise RuntimeError(f"{node}{path} exceeded its response byte bound")
                            chunks.append(chunk)
                        response_body = b"".join(chunks)
                        response_status = response.status_code
                        response_headers = response.headers
            except httpx.TransportError as exc:
                last_error = f"transport:{type(exc).__name__}"
            else:
                if response_status == expected:
                    value = _bounded_response_json(response_body)
                    if not isinstance(value, dict):
                        raise RuntimeError(f"{node}{path} returned a non-object response")
                    if time.monotonic() > deadline:
                        last_error = "response completed after the shared deadline"
                        self._record_retry_error("deadline:late_response")
                        break
                    return cast(dict[str, Any], value)
                last_error = self._http_retry_error(
                    body=body,
                    method=method,
                    node=node,
                    path=path,
                    response_body=response_body,
                    response_headers=response_headers,
                    response_status=response_status,
                )
                if response_status not in {429, 500, 502, 503, 504}:
                    raise RuntimeError(f"{method} {node}{path} failed: {last_error}")
            finally:
                if attempted_requests > 0 and interrupt is not None:
                    interrupt()
            if single_attempt:
                self._record_retry_error(last_error)
                break
            self._record_retry_error(last_error)
            delay = min(0.2, max(0.0, deadline - time.monotonic()))
            if self._abort_event is None:
                time.sleep(delay)
            elif self._abort_event.wait(delay):
                self._raise_if_aborted()
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


@lru_cache(maxsize=1)
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


class _SoakFaultInjectingExecutorAnchor(ProcessFileExecutorAuthorityAnchor):
    """Inject one classified post-COMMIT lost reply for the acceptance matrix."""

    def __init__(self, state: dict[str, bool]) -> None:
        super().__init__(EXECUTOR_ANCHOR, timeout_s=5)
        self._injection_state = state

    def reconcile(
        self,
        checkpoint: ExecutorAuthorityCheckpoint,
        *,
        claim_digest_at: Callable[[int], bytes | None],
        initialize: bool = False,
    ) -> None:
        super().reconcile(
            checkpoint,
            claim_digest_at=claim_digest_at,
            initialize=initialize,
        )
        if (
            self._injection_state["armed"]
            and not self._injection_state["injected"]
            and checkpoint.claim_sequence > 0
        ):
            self._injection_state["injected"] = True
            self.close()
            raise AuthorityAnchorTransportError(
                "injected detail is sanitized",
                reason="helper_eof",
                operation="compare-and-set",
                request_flushed=True,
                mutation_uncertain=True,
                helper_pid=None,
                helper_exit_code=None,
            )


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
        self.transport_recovery_events: list[dict[str, Any]] = []
        self.lifecycle_admission_failures: list[dict[str, Any]] = []
        self.terminal_statuses: list[dict[str, Any]] = []
        self._terminal_status: dict[str, Any] | None = None
        self._observed_lifetimes: set[str] = set()
        self._transport_injection_state = {"armed": False, "injected": False}
        self._pending_transport_fault: dict[str, Any] | None = None
        self._open(initialize=not EXECUTOR_DATABASE.exists(), phase="startup")

    def _open(self, *, initialize: bool, phase: str) -> None:
        self._transport_injection_state["armed"] = False
        self._anchor = _SoakFaultInjectingExecutorAnchor(self._transport_injection_state)
        try:
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
        except AuthorityAnchorTransportError as exc:
            self.lifecycle_admission_failures.append(
                {
                    "anchor_preserved": EXECUTOR_ANCHOR.exists(),
                    "database_preserved": EXECUTOR_DATABASE.exists(),
                    "error": {
                        "helper_exit_code": exc.helper_exit_code,
                        "helper_pid": exc.helper_pid,
                        "mutation_uncertain": exc.mutation_uncertain,
                        "operation": exc.operation,
                        "reason": exc.reason,
                        "request_flushed": exc.request_flushed,
                    },
                    "phase": phase,
                }
            )
            self._store = None
            self._verifier = None
            self._anchor.close()
            self._anchor = None
            raise
        self._verifier = ReceiptVerifier(self._registry, self._store, self._policy)
        lifetime = self._store.authority_status().get("lifetime_id")
        if (
            not isinstance(lifetime, str)
            or re.fullmatch(r"[0-9a-f]{32}", lifetime) is None
            or lifetime in self._observed_lifetimes
        ):
            raise RuntimeError("executor authority lifetime identity is invalid or reused")
        self._observed_lifetimes.add(lifetime)
        self._terminal_status = None
        self._transport_injection_state["armed"] = True

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

    @property
    def transport_recovery_pending(self) -> bool:
        return self._pending_transport_fault is not None

    def _record_claim(self, receipt: Receipt) -> None:
        self.claims += 1
        self.last_receipt = receipt

    def _require_replay_rejection(self, receipt: Receipt) -> None:
        try:
            self.verifier.verify_and_claim(receipt)
        except ReplayError:
            self.replay_rejections += 1
            return
        raise RuntimeError("executor accepted a duplicate production receipt")

    def _record_transport_failure(
        self,
        receipt: Receipt,
        failure: AuthorityAnchorTransportError,
        *,
        phase: str,
        primary_returned: bool,
        claim_already_counted: bool,
    ) -> None:
        if self.transport_recovery_events or self._pending_transport_fault is not None:
            raise RuntimeError(
                "executor transport recovery budget was already consumed"
            ) from failure
        faulted = self.store.authority_status()
        if (
            faulted.get("state") != "recoverable_transport_fault"
            or faulted.get("unresolved_transport_faults") != 1
            or faulted.get("transport_faults") != 1
            or faulted.get("transport_fault_episodes") != 1
        ):
            raise RuntimeError("executor transport fault status is inconsistent") from failure
        self._pending_transport_fault = {
            "claim_already_counted": claim_already_counted,
            "failure": failure,
            "faulted_authority_anchor": faulted,
            "phase": phase,
            "primary_returned": primary_returned,
            "receipt": receipt,
        }

    def recover_pending_authority(self) -> None:
        pending = self._pending_transport_fault
        if pending is None:
            raise RuntimeError("executor has no pending transport fault to recover")
        faulted = cast(dict[str, Any], pending["faulted_authority_anchor"])
        failure = cast(AuthorityAnchorTransportError, pending["failure"])
        retry_not_before = faulted.get("retry_not_before_monotonic_ns")
        if type(retry_not_before) is not int:
            raise RuntimeError("executor transport recovery omitted its cooldown") from failure
        remaining_ns = retry_not_before - time.monotonic_ns()
        if remaining_ns > 5_000_000_000:
            raise RuntimeError(
                "executor transport recovery cooldown exceeded its bound"
            ) from failure
        if remaining_ns > 0:
            time.sleep(remaining_ns / 1_000_000_000 + 0.001)
        recovered_snapshot = self.store.status()
        if (
            not recovered_snapshot.rollback_protected
            or not recovered_snapshot.authority_healthy
            or recovered_snapshot.authority_checkpoint is None
        ):
            raise RuntimeError("executor transport recovery did not restore exact authority")
        recovered = self.store.authority_status()
        if (
            recovered.get("state") != "healthy"
            or recovered.get("transport_faults") != 1
            or recovered.get("transport_fault_episodes") != 1
            or recovered.get("transport_recovery_attempts") != 1
            or recovered.get("transport_recoveries") != 1
            or recovered.get("unresolved_transport_faults") != 0
            or recovered.get("permanent_faults") != 0
        ):
            raise RuntimeError("executor transport recovery counters are inconsistent")
        pending["recovered_authority_anchor"] = recovered

    def retry_pending_claim(self) -> bool:
        pending = self._pending_transport_fault
        if pending is None or "recovered_authority_anchor" not in pending:
            raise RuntimeError("executor authority must recover before the pending receipt retry")
        receipt = cast(Receipt, pending["receipt"])
        phase = cast(str, pending["phase"])
        primary_returned = cast(bool, pending["primary_returned"])
        claim_already_counted = cast(bool, pending["claim_already_counted"])
        retry_outcome: str
        effect_executed: bool
        replay_failure: ReplayError | None = None
        try:
            self.verifier.verify_and_claim(receipt)
        except ReplayError as exc:
            replay_failure = exc
            retry_outcome = "replay_rejected"
            self.replay_rejections += 1
            if not claim_already_counted:
                self._record_claim(receipt)
            effect_executed = primary_returned or claim_already_counted
        else:
            if primary_returned or claim_already_counted:
                raise RuntimeError("executor reaccepted a receipt known to be durably claimed")
            retry_outcome = "claimed"
            self._record_claim(receipt)
            self._require_replay_rejection(receipt)
            effect_executed = True
        if retry_outcome == "claimed":
            durable_claim_outcome = "claimed_on_retry"
        elif phase == "primary_claim" and not primary_returned:
            durable_claim_outcome = "burned_before_response"
        else:
            durable_claim_outcome = "claimed_before_faulting_probe"
        event = {
            "durable_claim_outcome": durable_claim_outcome,
            "faulting_call_effect_executed": False,
            "faulted_authority_anchor": pending["faulted_authority_anchor"],
            "ordinal": len(self.transport_recovery_events),
            "original_call_raised": True,
            "original_transport_error": {
                "helper_exit_code": cast(
                    AuthorityAnchorTransportError, pending["failure"]
                ).helper_exit_code,
                "helper_pid": cast(AuthorityAnchorTransportError, pending["failure"]).helper_pid,
                "mutation_uncertain": cast(
                    AuthorityAnchorTransportError, pending["failure"]
                ).mutation_uncertain,
                "operation": cast(AuthorityAnchorTransportError, pending["failure"]).operation,
                "reason": cast(AuthorityAnchorTransportError, pending["failure"]).reason,
                "request_flushed": cast(
                    AuthorityAnchorTransportError, pending["failure"]
                ).request_flushed,
            },
            "phase": phase,
            "primary_returned": primary_returned,
            "protected_effect_executed_after_recovery": (
                effect_executed and phase != "reopen_replay_probe"
            ),
            "receipt_id": receipt.receipt_id,
            "recovered_authority_anchor": pending["recovered_authority_anchor"],
            "retry_outcome": retry_outcome,
        }
        self.transport_recovery_events.append(event)
        self._pending_transport_fault = None
        if replay_failure is not None:
            raise replay_failure
        return effect_executed

    def claim_once(self, receipt: Receipt) -> bool:
        if self._pending_transport_fault is not None:
            raise RuntimeError("executor transport fault recovery is pending")
        try:
            self.verifier.verify_and_claim(receipt)
        except AuthorityAnchorTransportError as exc:
            self._record_transport_failure(
                receipt,
                exc,
                phase="primary_claim",
                primary_returned=False,
                claim_already_counted=False,
            )
            raise
        try:
            self._require_replay_rejection(receipt)
        except AuthorityAnchorTransportError as exc:
            self._record_transport_failure(
                receipt,
                exc,
                phase="replay_probe",
                primary_returned=True,
                claim_already_counted=False,
            )
            raise
        self._record_claim(receipt)
        return True

    def reopen(self) -> None:
        previous = self.last_receipt
        self.capture_terminal_status()
        self.close(capture_terminal=False)
        self._open(initialize=False, phase="reopen")
        self.reopen_count += 1
        if previous is not None:
            try:
                self._require_replay_rejection(previous)
            except AuthorityAnchorTransportError as exc:
                self._record_transport_failure(
                    previous,
                    exc,
                    phase="reopen_replay_probe",
                    primary_returned=True,
                    claim_already_counted=True,
                )
                raise

    def status(self) -> dict[str, Any]:
        status = self.store.status()
        if not status.rollback_protected or not status.authority_healthy:
            raise RuntimeError("executor replay authority is not healthy and rollback protected")
        integrity = self.store.integrity_check()
        if integrity != ("ok",):
            raise RuntimeError(f"executor replay integrity failed: {integrity!r}")
        checkpoint = status.authority_checkpoint
        if checkpoint is None:
            raise RuntimeError("executor authority checkpoint is unavailable")
        if checkpoint.claim_sequence != status.claim_sequence:
            raise RuntimeError("executor database and authority anchor claim heads disagree")
        return {
            "anchor": checkpoint.to_dict(),
            "authority_anchor": self.store.authority_status(),
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

    def capture_terminal_status(self) -> dict[str, Any]:
        if self._terminal_status is not None:
            return self._terminal_status
        snapshot = self.status()
        authority = snapshot.get("authority_anchor")
        if not isinstance(authority, dict):
            raise RuntimeError("executor terminal authority status is malformed")
        lifetime = authority.get("lifetime_id")
        if not isinstance(lifetime, str):
            raise RuntimeError("executor terminal authority lifetime is missing")
        terminal = {
            "ordinal": len(self.terminal_statuses),
            "source": "workload",
            "lifetime_id": lifetime,
            "status": snapshot,
        }
        self.terminal_statuses.append(terminal)
        self._terminal_status = snapshot
        return snapshot

    def close(self, *, capture_terminal: bool = True) -> None:
        if capture_terminal and self._store is not None and self._terminal_status is None:
            self.capture_terminal_status()
        self._verifier = None
        self._store = None
        if self._anchor is not None:
            self._anchor.close()
            self._anchor = None

    def failure_snapshot(self) -> dict[str, Any]:
        pending = self._pending_transport_fault
        pending_snapshot: dict[str, Any] | None = None
        if pending is not None:
            failure = cast(AuthorityAnchorTransportError, pending["failure"])
            receipt = cast(Receipt, pending["receipt"])
            pending_snapshot = {
                "faulted_authority_anchor": pending["faulted_authority_anchor"],
                "original_call_raised": True,
                "original_transport_error": {
                    "helper_exit_code": failure.helper_exit_code,
                    "helper_pid": failure.helper_pid,
                    "mutation_uncertain": failure.mutation_uncertain,
                    "operation": failure.operation,
                    "reason": failure.reason,
                    "request_flushed": failure.request_flushed,
                },
                "phase": pending["phase"],
                "primary_returned": pending["primary_returned"],
                "receipt_id": receipt.receipt_id,
            }
            if "recovered_authority_anchor" in pending:
                pending_snapshot["recovered_authority_anchor"] = pending[
                    "recovered_authority_anchor"
                ]
        return {
            "authority_anchor": (None if self._store is None else self._store.authority_status()),
            "claims": self.claims,
            "lifecycle_admission_failures": list(self.lifecycle_admission_failures),
            "pending_transport_fault": pending_snapshot,
            "reopen_count": self.reopen_count,
            "replay_rejections": self.replay_rejections,
            "terminal_statuses": list(self.terminal_statuses),
            "transport_recovery_events": list(self.transport_recovery_events),
        }


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


def _is_finite_number(value: object) -> bool:
    return bool(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


_AUTHORITY_STATUS_FIELDS = frozenset(
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
_AUTHORITY_COUNTER_FIELDS = (
    "transport_faults",
    "transport_fault_episodes",
    "transport_recovery_attempts",
    "transport_recoveries",
    "permanent_faults",
)
_AUTHORITY_FIRST_FAULT_FIELDS = frozenset(
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


def _bounded_authority_anchor_status(
    value: object,
    *,
    node: str,
    require_healthy: bool,
    allow_fenced: bool = False,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _AUTHORITY_STATUS_FIELDS:
        raise RuntimeError(f"{node} returned malformed authority anchor status")
    state = value.get("state")
    healthy = value.get("healthy")
    enabled = value.get("enabled")
    lifetime = value.get("lifetime_id")
    namespace_pid = value.get("namespace_process_id")
    fenced = value.get("admission_fenced")
    if (
        enabled is not True
        or state
        not in {
            "healthy",
            "recoverable_transport_fault",
            "permanent_fault",
        }
        or type(healthy) is not bool
        or healthy is not (state == "healthy")
        or not isinstance(lifetime, str)
        or re.fullmatch(r"[0-9a-f]{32}", lifetime) is None
        or type(namespace_pid) is not int
        or namespace_pid <= 0
        or type(fenced) is not bool
    ):
        raise RuntimeError(f"{node} returned inconsistent authority anchor identity or state")
    if require_healthy and state != "healthy":
        raise RuntimeError(f"{node} authority anchor is not healthy")
    fence_id = value.get("fence_id")
    fenced_at = value.get("fenced_at_monotonic_ns")
    if fenced:
        if (
            not allow_fenced
            or not isinstance(fence_id, str)
            or not 1 <= len(fence_id) <= 128
            or type(fenced_at) is not int
            or fenced_at < 0
        ):
            raise RuntimeError(f"{node} returned invalid fenced authority state")
    elif fence_id is not None or fenced_at is not None:
        raise RuntimeError(f"{node} returned stale authority fence metadata")
    counters: dict[str, int] = {}
    for field_name in _AUTHORITY_COUNTER_FIELDS:
        counter = value.get(field_name)
        if type(counter) is not int or not 0 <= counter <= AUTHORITY_COUNTER_MAX:
            raise RuntimeError(f"{node} returned invalid authority counter {field_name}")
        counters[field_name] = counter
    unresolved = value.get("unresolved_transport_faults")
    if type(unresolved) is not int or unresolved not in {0, 1}:
        raise RuntimeError(f"{node} returned invalid unresolved authority fault gauge")
    if (
        counters["transport_faults"] < counters["transport_fault_episodes"]
        or counters["transport_fault_episodes"] < counters["transport_recoveries"]
        or counters["transport_recovery_attempts"] < counters["transport_recoveries"]
        or unresolved != int(state == "recoverable_transport_fault")
        or (state == "permanent_fault" and counters["permanent_faults"] == 0)
    ):
        raise RuntimeError(f"{node} returned inconsistent authority fault counters")
    fault_stage = value.get("fault_stage")
    fault_reason = value.get("fault_reason")
    retry_not_before = value.get("retry_not_before_monotonic_ns")
    if fault_stage is not None and fault_stage not in {"pre_begin", "post_commit"}:
        raise RuntimeError(f"{node} returned invalid authority fault stage")
    if fault_reason is not None and (
        not isinstance(fault_reason, str) or re.fullmatch(r"[a-z0-9_]{1,64}", fault_reason) is None
    ):
        raise RuntimeError(f"{node} returned invalid authority fault reason")
    if state == "healthy":
        if fault_stage is not None or fault_reason is not None or retry_not_before is not None:
            raise RuntimeError(f"{node} retained current fault metadata while healthy")
    elif state == "recoverable_transport_fault":
        if (
            fault_stage is None
            or fault_reason is None
            or type(retry_not_before) is not int
            or retry_not_before < 0
        ):
            raise RuntimeError(f"{node} omitted recoverable authority fault metadata")
    elif retry_not_before is not None:
        raise RuntimeError(f"{node} retained a retry deadline for a permanent fault")
    first_fault = value.get("first_fault")
    if first_fault is None:
        if counters["transport_faults"] != 0:
            raise RuntimeError(f"{node} omitted its first authority transport fault")
    else:
        if (
            not isinstance(first_fault, dict)
            or set(first_fault) != _AUTHORITY_FIRST_FAULT_FIELDS
            or counters["transport_faults"] == 0
            or first_fault.get("stage") not in {"pre_begin", "post_commit"}
            or first_fault.get("operation") not in AuthorityAnchorTransportError.OPERATIONS
            or type(first_fault.get("request_flushed")) is not bool
            or type(first_fault.get("mutation_uncertain")) is not bool
            or first_fault.get("reason") not in AuthorityAnchorTransportError.REASONS
            or (
                first_fault.get("operation") == "read"
                and first_fault.get("mutation_uncertain") is True
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
            raise RuntimeError(f"{node} returned malformed first authority fault")
        for field_name, positive in (("helper_pid", True), ("helper_exit_code", False)):
            item = first_fault.get(field_name)
            minimum = 1 if positive else -(1 << 31)
            if item is not None and (type(item) is not int or not minimum <= item <= (1 << 31) - 1):
                raise RuntimeError(f"{node} returned invalid first fault {field_name}")
    return {field_name: value[field_name] for field_name in sorted(_AUTHORITY_STATUS_FIELDS)}


_OBSERVATION_DYNAMIC_FIELDS = frozenset(
    {
        "age_ns",
        "authority_anchor",
        "capture_status",
        "fresh",
        "ready",
        "served_at_monotonic_ns",
        "service_ready",
    }
)
_OBSERVATION_IMMUTABLE_FIELDS = frozenset(
    {
        "audit_exporter",
        "audit_outbox",
        "audit_verification",
        "authority_checkpoint",
        "capture_duration_ns",
        "capture_started_monotonic_ns",
        "captured_at_monotonic_ns",
        "captured_at_ns",
        "captured_authority_anchor",
        "checked_at_ns",
        "clock_healthy",
        "core_state_revision",
        "database_instance_id",
        "generation",
        "invariant",
        "invariant_healthy",
        "leases",
        "lifetime_id",
        "max_age_ns",
        "observation_eligible",
        "peer_dispatcher",
        "published_at_monotonic_ns",
        "published_at_ns",
        "receipts",
        "resources",
        "revision",
        "runtime",
        "schema",
        "signing_key_healthy",
        "snapshot_id",
        "sqlite_schema_sha256",
        "storage_capacity",
        "transfers",
    }
)
_AUTHORITY_CHECKPOINT_FIELDS = frozenset(
    {
        "audit_hash",
        "audit_sequence",
        "clock_floor_ns",
        "config_epoch",
        "database_instance_id",
        "envelope_id",
        "format",
        "schema_version",
        "signing_key_id",
        "signing_public_key_sha256",
        "state_digest",
        "state_revision",
        "tenant_id",
        "warden_id",
    }
)


def _validated_authority_checkpoint(value: object, *, node: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _AUTHORITY_CHECKPOINT_FIELDS:
        raise RuntimeError(f"{node} returned malformed authority checkpoint")
    manifest = _verified_manifest()
    local = manifest.warden(node)
    expected_signers = {
        (
            key.key_id,
            b64url_encode(hashlib.sha256(key.public_key).digest()),
        )
        for key in local.keys
    }
    binary_fields = (
        "audit_hash",
        "database_instance_id",
        "signing_public_key_sha256",
        "state_digest",
    )
    try:
        decoded = {
            field_name: b64url_decode(cast(str, value.get(field_name)))
            for field_name in binary_fields
        }
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{node} returned malformed checkpoint digests") from exc
    if (
        value.get("format") != "LETS-AUTHORITY-ANCHOR/1"
        or value.get("warden_id") != node
        or value.get("tenant_id") != manifest.tenant_id
        or value.get("envelope_id") != manifest.envelope_id
        or type(value.get("config_epoch")) is not int
        or value.get("config_epoch") != manifest.config_epoch
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 2
        or (value.get("signing_key_id"), value.get("signing_public_key_sha256"))
        not in expected_signers
        or type(value.get("audit_sequence")) is not int
        or not -1 <= value["audit_sequence"] <= AUTHORITY_COUNTER_MAX
        or type(value.get("state_revision")) is not int
        or not 0 <= value["state_revision"] <= AUTHORITY_COUNTER_MAX
        or type(value.get("clock_floor_ns")) not in {int, type(None)}
        or (
            type(value.get("clock_floor_ns")) is int
            and not 0 <= cast(int, value["clock_floor_ns"]) <= AUTHORITY_COUNTER_MAX
        )
        or any(len(item) != 32 for item in decoded.values())
    ):
        raise RuntimeError(f"{node} returned inconsistent authority checkpoint")
    return cast(dict[str, Any], value)


_CHECKPOINT_STABLE_FIELDS = frozenset(
    {
        "config_epoch",
        "database_instance_id",
        "envelope_id",
        "format",
        "schema_version",
        "signing_key_id",
        "signing_public_key_sha256",
        "tenant_id",
        "warden_id",
    }
)


def _validate_checkpoint_progression(
    prior: dict[str, Any],
    current: dict[str, Any],
    *,
    node: str,
) -> None:
    """Require one authority checkpoint to extend, never splice, its predecessor."""

    prior_floor = prior.get("clock_floor_ns")
    current_floor = current.get("clock_floor_ns")
    if (
        any(current[field] != prior[field] for field in _CHECKPOINT_STABLE_FIELDS)
        or cast(int, current["state_revision"]) < cast(int, prior["state_revision"])
        or cast(int, current["audit_sequence"]) < cast(int, prior["audit_sequence"])
        or (type(prior_floor) is int and type(current_floor) is not int)
        or (type(prior_floor) is int and type(current_floor) is int and current_floor < prior_floor)
        or (
            current["audit_sequence"] == prior["audit_sequence"]
            and (
                current["audit_hash"] != prior["audit_hash"]
                or current["state_revision"] != prior["state_revision"]
                or current["state_digest"] != prior["state_digest"]
            )
        )
    ):
        raise RuntimeError(f"{node} authority checkpoint did not extend its predecessor")


def _observation_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _validated_observation(metrics: object, *, node: str) -> dict[str, Any]:
    if not isinstance(metrics, dict) or set(metrics) != (
        _OBSERVATION_IMMUTABLE_FIELDS | _OBSERVATION_DYNAMIC_FIELDS
    ):
        raise RuntimeError(f"{node} returned a non-exact observation envelope")
    if len(_observation_json(metrics)) > OBSERVATION_RESPONSE_MAX_BYTES:
        raise RuntimeError(f"{node} observation exceeds its response byte bound")

    def integer(field: str, *, minimum: int = 0) -> int:
        value = metrics.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise RuntimeError(f"{node} returned invalid observation {field}")
        return value

    if metrics.get("schema") != "lets.observation-snapshot/v1":
        raise RuntimeError(f"{node} returned an unsupported observation schema")
    generation = metrics.get("generation")
    lifetime = metrics.get("lifetime_id")
    snapshot_id = metrics.get("snapshot_id")
    if (
        not isinstance(generation, str)
        or re.fullmatch(r"[0-9a-f]{32}", generation) is None
        or not isinstance(lifetime, str)
        or re.fullmatch(r"[0-9a-f]{32}", lifetime) is None
        or not isinstance(snapshot_id, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", snapshot_id) is None
    ):
        raise RuntimeError(f"{node} returned invalid observation identity")
    immutable = {
        key: value
        for key, value in metrics.items()
        if key not in _OBSERVATION_DYNAMIC_FIELDS and key != "snapshot_id"
    }
    expected_snapshot_id = f"sha256:{hashlib.sha256(_observation_json(immutable)).hexdigest()}"
    if snapshot_id != expected_snapshot_id:
        raise RuntimeError(f"{node} observation payload digest is invalid")
    revision = integer("revision", minimum=1)
    capture_started = integer("capture_started_monotonic_ns")
    captured_monotonic = integer("captured_at_monotonic_ns")
    published_monotonic = integer("published_at_monotonic_ns")
    capture_duration = integer("capture_duration_ns")
    captured_at_ns = integer("captured_at_ns")
    if (
        not capture_started <= captured_monotonic <= published_monotonic
        or capture_duration != published_monotonic - capture_started
        or integer("published_at_ns") < captured_at_ns
        or integer("max_age_ns") != 15_000_000_000
    ):
        raise RuntimeError(f"{node} returned inconsistent observation timestamps")
    age_ns = integer("age_ns")
    served_at = integer("served_at_monotonic_ns")
    if (
        served_at < published_monotonic
        or age_ns != served_at - captured_monotonic
        or age_ns >= 15_000_000_000
        or metrics.get("fresh") is not True
    ):
        raise RuntimeError(f"{node} returned a stale observation")
    capture_status = metrics.get("capture_status")
    if (
        not isinstance(capture_status, dict)
        or set(capture_status)
        != {
            "attempt_sequence",
            "capture_in_progress",
            "last_attempt_monotonic_ns",
            "last_error_type",
            "last_successful_attempt_sequence",
        }
        or type(capture_status.get("attempt_sequence")) is not int
        or capture_status["attempt_sequence"] <= 0
        or type(capture_status.get("capture_in_progress")) is not bool
        or type(capture_status.get("last_attempt_monotonic_ns")) is not int
        or capture_status["last_attempt_monotonic_ns"] < 0
        or capture_status.get("last_error_type") is not None
        or type(capture_status.get("last_successful_attempt_sequence")) is not int
        or capture_status["last_successful_attempt_sequence"] <= 0
        or capture_status["last_successful_attempt_sequence"] > capture_status["attempt_sequence"]
        or (
            capture_status["capture_in_progress"] is False
            and capture_status["last_successful_attempt_sequence"]
            != capture_status["attempt_sequence"]
        )
    ):
        raise RuntimeError(f"{node} returned an unhealthy capture status")
    captured_authority = _bounded_authority_anchor_status(
        metrics.get("captured_authority_anchor"),
        node=node,
        require_healthy=True,
    )
    current_authority = _bounded_authority_anchor_status(
        metrics.get("authority_anchor"),
        node=node,
        require_healthy=True,
    )
    if (
        captured_authority.get("lifetime_id") != lifetime
        or current_authority.get("lifetime_id") != lifetime
        or captured_authority.get("namespace_process_id")
        != current_authority.get("namespace_process_id")
        or any(
            cast(int, current_authority[field_name]) < cast(int, captured_authority[field_name])
            for field_name in _AUTHORITY_COUNTER_FIELDS
        )
        or (
            captured_authority.get("first_fault") is not None
            and current_authority.get("first_fault") != captured_authority.get("first_fault")
        )
    ):
        raise RuntimeError(f"{node} returned an inconsistent current authority lineage")
    checkpoint = _validated_authority_checkpoint(
        metrics.get("authority_checkpoint"),
        node=node,
    )
    try:
        checkpoint_audit_hash = b64url_decode(cast(str, checkpoint.get("audit_hash")))
        database_instance = b64url_decode(cast(str, checkpoint.get("database_instance_id")))
        state_digest = b64url_decode(cast(str, checkpoint.get("state_digest")))
        signing_digest = b64url_decode(cast(str, checkpoint.get("signing_public_key_sha256")))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{node} returned malformed checkpoint digests") from exc
    audit_sequence = checkpoint.get("audit_sequence")
    state_revision = checkpoint.get("state_revision")
    if (
        checkpoint.get("format") != "LETS-AUTHORITY-ANCHOR/1"
        or checkpoint.get("warden_id") != node
        or checkpoint.get("tenant_id") != TENANT_ID
        or checkpoint.get("envelope_id") != ENVELOPE_ID
        or type(audit_sequence) is not int
        or audit_sequence < -1
        or type(state_revision) is not int
        or state_revision < 0
        or len(checkpoint_audit_hash) != 32
        or len(database_instance) != 32
        or len(state_digest) != 32
        or len(signing_digest) != 32
        or type(metrics.get("core_state_revision")) is not int
        or metrics.get("core_state_revision") != state_revision
        or metrics.get("database_instance_id") != checkpoint.get("database_instance_id")
    ):
        raise RuntimeError(f"{node} returned inconsistent authority checkpoint")
    audit = metrics.get("audit_verification")
    expected_audit_fields = {
        "captured_head_hash",
        "captured_head_sequence",
        "catching_up",
        "error_type",
        "lag",
        "last_full_verification_at_ns",
        "page_size",
        "schema_definition_sha256",
        "sticky_failure",
        "sweep_cursor_sequence",
        "sweep_last_completed_at_ns",
        "sweep_last_completed_head_hash",
        "sweep_last_completed_head_sequence",
        "sweep_target_sequence",
        "valid",
        "verified_through_hash",
        "verified_through_sequence",
    }
    checkpoint_hash_text = f"sha256:{checkpoint_audit_hash.hex()}"
    if (
        not isinstance(audit, dict)
        or set(audit) != expected_audit_fields
        or audit.get("valid") is not True
        or audit.get("sticky_failure") is not False
        or audit.get("catching_up") is not False
        or audit.get("error_type") is not None
        or audit.get("lag") != 0
        or audit.get("captured_head_sequence") != audit_sequence
        or audit.get("verified_through_sequence") != audit_sequence
        or audit.get("captured_head_hash") != checkpoint_hash_text
        or audit.get("verified_through_hash") != checkpoint_hash_text
        or type(audit.get("last_full_verification_at_ns")) is not int
        or audit["last_full_verification_at_ns"] <= 0
        or audit.get("schema_definition_sha256") != metrics.get("sqlite_schema_sha256")
        or not isinstance(audit.get("schema_definition_sha256"), str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            cast(str, audit["schema_definition_sha256"]),
        )
        is None
        or type(audit.get("sweep_cursor_sequence")) is not int
        or audit["sweep_cursor_sequence"] < -1
        or type(audit.get("sweep_target_sequence")) is not int
        or audit["sweep_target_sequence"] < -1
        or audit["sweep_cursor_sequence"] > audit["sweep_target_sequence"]
        or type(audit.get("sweep_last_completed_at_ns")) is not int
        or audit["sweep_last_completed_at_ns"] <= 0
        or audit["sweep_last_completed_at_ns"] > captured_at_ns
        or type(audit.get("sweep_last_completed_head_sequence")) is not int
        or audit["sweep_last_completed_head_sequence"] < -1
        or not isinstance(audit.get("sweep_last_completed_head_hash"), str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            cast(str, audit["sweep_last_completed_head_hash"]),
        )
        is None
    ):
        raise RuntimeError(f"{node} returned an unbound incremental audit proof")
    invariant = metrics.get("invariant")
    resources = metrics.get("resources")
    resource_fields = {
        "consumed",
        "free_pool",
        "initial_share",
        "lease_residual",
        "transferred_in",
        "transferred_out",
    }
    invariant_fields = resource_fields | {
        "checked_at_ns",
        "config_epoch",
        "envelope_id",
        "healthy",
        "tenant_id",
    }
    dimension_count = len(_verified_manifest().resources)

    def resource_vector(value: object) -> TypeGuard[list[int]]:
        return bool(
            isinstance(value, list)
            and len(value) == dimension_count
            and all(type(item) is int and 0 <= item <= AUTHORITY_COUNTER_MAX for item in value)
        )

    resource_vectors_valid = bool(
        isinstance(invariant, dict)
        and all(resource_vector(invariant.get(field)) for field in resource_fields)
    )
    initial_share = invariant.get("initial_share") if isinstance(invariant, dict) else None
    transferred_in = invariant.get("transferred_in") if isinstance(invariant, dict) else None
    free_pool = invariant.get("free_pool") if isinstance(invariant, dict) else None
    lease_residual = invariant.get("lease_residual") if isinstance(invariant, dict) else None
    consumed = invariant.get("consumed") if isinstance(invariant, dict) else None
    transferred_out = invariant.get("transferred_out") if isinstance(invariant, dict) else None
    local_conservation_valid = bool(
        resource_vectors_valid
        and resource_vector(initial_share)
        and resource_vector(transferred_in)
        and resource_vector(free_pool)
        and resource_vector(lease_residual)
        and resource_vector(consumed)
        and resource_vector(transferred_out)
        and all(
            initial_share[index] + transferred_in[index]
            == free_pool[index] + lease_residual[index] + consumed[index] + transferred_out[index]
            for index in range(dimension_count)
        )
    )

    if (
        not isinstance(invariant, dict)
        or set(invariant) != invariant_fields
        or not isinstance(resources, dict)
        or set(resources) != resource_fields
        or any(resources[field] != invariant[field] for field in resource_fields)
        or not resource_vectors_valid
        or not local_conservation_valid
        or invariant.get("tenant_id") != TENANT_ID
        or invariant.get("envelope_id") != ENVELOPE_ID
        or type(invariant.get("config_epoch")) is not int
        or invariant.get("config_epoch") != _verified_manifest().config_epoch
        or type(invariant.get("checked_at_ns")) is not int
        or invariant.get("checked_at_ns") != metrics.get("checked_at_ns")
        or invariant.get("healthy") is not True
        or metrics.get("invariant_healthy") is not True
        or metrics.get("clock_healthy") is not True
        or metrics.get("signing_key_healthy") is not True
        or metrics.get("observation_eligible") is not True
    ):
        raise RuntimeError(f"{node} returned inconsistent core observation facts")
    runtime = metrics.get("runtime")
    capacity = metrics.get("storage_capacity")
    leases = metrics.get("leases")
    receipts = metrics.get("receipts")
    transfers = metrics.get("transfers")
    outbox = metrics.get("audit_outbox")
    peer = metrics.get("peer_dispatcher")
    exporter = metrics.get("audit_exporter")
    capacity_fields = {
        "additional_shared_memory_bytes",
        "database_bytes",
        "effective_database_bytes",
        "filesystem_free_bytes",
        "free_pages",
        "healthy",
        "logical_live_bytes",
        "main_database_bytes",
        "max_database_bytes",
        "max_page_count",
        "min_free_disk_bytes",
        "page_count",
        "page_size",
        "prior_full_error",
        "remaining_main_growth_bytes",
        "required_filesystem_free_bytes",
        "reserve_pages",
        "reusable_bytes",
        "shared_memory_bytes",
        "wal_bytes",
        "worst_case_shared_memory_bytes",
        "worst_case_transaction_wal_bytes",
    }
    transfer_fields = {
        "in_flight_count",
        "inbound_gap_count",
        "incoming_compacted_high_water",
        "incoming_contiguous_high_water",
        "incoming_streams",
        "outgoing_acked_high_water",
        "outgoing_compacted_high_water",
        "outgoing_streams",
    }
    peer_fields = {
        "configured_peers",
        "delivered_records",
        "durable_retry",
        "failed_records",
        "healthy",
        "last_cycle_ns",
        "last_error",
        "pending_records",
        "prepared_transfers",
        "running",
        "superseded_records",
    }
    exporter_fields = {
        "archive_reconciled",
        "configured",
        "healthy",
        "last_error",
        "last_success_ns",
        "max_pending",
        "max_stall_s",
        "oldest_pending_age_s",
        "pending",
        "publish_blocked",
        "publish_timeout_s",
        "running",
        "sink_call_blocked",
        "stalled_for_s",
    }
    capacity_numbers_valid = isinstance(capacity, dict) and all(
        (
            capacity[field_name] is None
            or (type(capacity[field_name]) is int and capacity[field_name] >= 0)
            if field_name in {"filesystem_free_bytes", "max_database_bytes"}
            else type(capacity[field_name]) is int and capacity[field_name] >= 0
        )
        for field_name in capacity_fields - {"healthy", "prior_full_error"}
    )
    by_status = leases.get("by_status") if isinstance(leases, dict) else None
    durable_retry = peer.get("durable_retry") if isinstance(peer, dict) else None
    if (
        not isinstance(runtime, dict)
        or set(runtime) != {"changed_at_ns", "changed_by", "generation", "mode", "reason"}
        or runtime.get("mode") != "ACTIVE"
        or type(runtime.get("generation")) is not int
        or runtime["generation"] < 0
        or type(runtime.get("changed_at_ns")) is not int
        or runtime["changed_at_ns"] < 0
        or not isinstance(runtime.get("changed_by"), str)
        or not isinstance(runtime.get("reason"), str)
        or not isinstance(capacity, dict)
        or set(capacity) != capacity_fields
        or not capacity_numbers_valid
        or type(capacity.get("healthy")) is not bool
        or type(capacity.get("prior_full_error")) is not bool
        or capacity.get("healthy") is not True
        or not isinstance(leases, dict)
        or set(leases) != {"by_status", "total"}
        or type(leases.get("total")) is not int
        or leases["total"] < 0
        or not isinstance(by_status, dict)
        or any(
            not isinstance(key, str) or type(value) is not int or value < 0
            for key, value in by_status.items()
        )
        or sum(cast(dict[str, int], by_status).values()) != leases["total"]
        or not isinstance(receipts, dict)
        or set(receipts) != {"total"}
        or type(receipts.get("total")) is not int
        or receipts["total"] < 0
        or not isinstance(transfers, dict)
        or set(transfers) != transfer_fields
        or any(
            type(transfers[field]) is not int or transfers[field] < 0 for field in transfer_fields
        )
        or not isinstance(outbox, dict)
        or set(outbox) != {"oldest_unpublished_age_ns", "unpublished_count"}
        or type(outbox.get("oldest_unpublished_age_ns")) is not int
        or outbox["oldest_unpublished_age_ns"] < 0
        or type(outbox.get("unpublished_count")) is not int
        or outbox["unpublished_count"] < 0
        or not isinstance(peer, dict)
        or set(peer) != peer_fields
        or any(
            type(peer[field]) is not int or peer[field] < 0
            for field in peer_fields
            - {"durable_retry", "healthy", "last_cycle_ns", "last_error", "running"}
        )
        # last_cycle_ns is None until the dispatcher's first cycle completes
        # after startup or a planned restart.
        or (
            peer.get("last_cycle_ns") is not None
            and (type(peer.get("last_cycle_ns")) is not int or peer["last_cycle_ns"] < 0)
        )
        or type(peer.get("healthy")) is not bool
        or type(peer.get("running")) is not bool
        or (peer.get("last_error") is not None and not isinstance(peer.get("last_error"), str))
        or (
            durable_retry is not None
            and (
                not isinstance(durable_retry, dict)
                or set(durable_retry)
                != {
                    "attempt_count",
                    "exception_class",
                    "next_retry_delay_seconds",
                    "record_kind",
                    "target_warden",
                }
                or type(durable_retry.get("attempt_count")) is not int
                or durable_retry["attempt_count"] < 0
                or not isinstance(durable_retry.get("exception_class"), str)
                or not _is_finite_number(durable_retry.get("next_retry_delay_seconds"))
                or float(durable_retry["next_retry_delay_seconds"]) < 0
                or not isinstance(durable_retry.get("record_kind"), str)
                or not isinstance(durable_retry.get("target_warden"), str)
            )
        )
        or not isinstance(exporter, dict)
        or set(exporter) != exporter_fields
        or any(
            type(exporter[field]) is not bool
            for field in {
                "archive_reconciled",
                "configured",
                "healthy",
                "publish_blocked",
                "running",
                "sink_call_blocked",
            }
        )
        or any(
            type(exporter[field]) is not int or exporter[field] < 0
            for field in {"max_pending", "pending"}
        )
        or any(
            not _is_finite_number(exporter[field]) or float(exporter[field]) < 0
            for field in {"max_stall_s", "publish_timeout_s", "stalled_for_s"}
        )
        or (
            exporter.get("oldest_pending_age_s") is not None
            and (
                not _is_finite_number(exporter.get("oldest_pending_age_s"))
                or float(exporter["oldest_pending_age_s"]) < 0
            )
        )
        or type(exporter.get("last_success_ns")) not in {int, type(None)}
        or (type(exporter.get("last_success_ns")) is int and exporter["last_success_ns"] < 0)
        or (
            exporter.get("last_error") is not None
            and not isinstance(exporter.get("last_error"), str)
        )
    ):
        raise RuntimeError(f"{node} returned inconsistent aggregate readiness")
    if metrics.get("service_ready") is not True:
        raise RuntimeError(f"{node} core service is not ready")
    if metrics.get("ready") is not (
        exporter.get("healthy") is True and peer.get("healthy") is True
    ):
        raise RuntimeError(f"{node} returned inconsistent aggregate readiness")
    metrics["authority_anchor"] = current_authority
    metrics["captured_authority_anchor"] = captured_authority
    metrics["revision"] = revision
    return cast(dict[str, Any], metrics)


_TERMINAL_AUDIT_PROOF_FIELDS = frozenset(
    {
        "authority_checkpoint_sha256",
        "authority_state_revision",
        "database_instance_id",
        "generation",
        "lifetime_id",
        "schema",
        "schema_definition_sha256",
        "startup_full_verification_at_ns",
        "valid",
        "verification_mode",
        "verified_at_ns",
        "verified_head_hash",
        "verified_head_sequence",
    }
)
_AUTHORITY_FENCE_FIELDS = frozenset(
    {
        "authority_anchor",
        "authority_checkpoint",
        "fenced_at_monotonic_ns",
        "lifetime_id",
        "namespace_process_id",
        "restart_id",
        "schema",
        "terminal_audit_proof",
        "warden_id",
    }
)


def _validated_terminal_fence(
    terminal: object,
    *,
    node: str,
    expected_lifetime_id: str,
    restart_id: str,
    full_audit_verification: bool,
    prior_authority: dict[str, Any] | None = None,
    prior_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(terminal, dict) or set(terminal) != _AUTHORITY_FENCE_FIELDS:
        raise RuntimeError(f"{node} returned a non-exact authority fence response")
    authority = _bounded_authority_anchor_status(
        terminal.get("authority_anchor"),
        node=node,
        require_healthy=True,
        allow_fenced=True,
    )
    checkpoint = _validated_authority_checkpoint(
        terminal.get("authority_checkpoint"),
        node=node,
    )
    proof = terminal.get("terminal_audit_proof")
    expected_mode = "full" if full_audit_verification else "trusted-startup-plus-tail"
    if not isinstance(proof, dict) or set(proof) != _TERMINAL_AUDIT_PROOF_FIELDS:
        raise RuntimeError(f"{node} returned malformed terminal audit proof")
    checkpoint_digest = f"sha256:{hashlib.sha256(_observation_json(checkpoint)).hexdigest()}"
    try:
        checkpoint_audit_hash = b64url_decode(cast(str, checkpoint["audit_hash"]))
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{node} returned malformed terminal audit hash") from exc
    if (
        terminal.get("schema") != "lets.authority-admission-fence/v1"
        or terminal.get("restart_id") != restart_id
        or terminal.get("warden_id") != node
        or terminal.get("lifetime_id") != expected_lifetime_id
        or type(terminal.get("namespace_process_id")) is not int
        or terminal["namespace_process_id"] <= 0
        or type(terminal.get("fenced_at_monotonic_ns")) is not int
        or terminal["fenced_at_monotonic_ns"] < 0
        or authority.get("lifetime_id") != expected_lifetime_id
        or authority.get("admission_fenced") is not True
        or authority.get("fence_id") != restart_id
        or terminal.get("namespace_process_id") != authority.get("namespace_process_id")
        or terminal.get("fenced_at_monotonic_ns") != authority.get("fenced_at_monotonic_ns")
        or proof.get("schema") != "lets.terminal-audit-proof/v1"
        or proof.get("valid") is not True
        or proof.get("verification_mode") != expected_mode
        or proof.get("lifetime_id") != expected_lifetime_id
        or not isinstance(proof.get("generation"), str)
        or re.fullmatch(r"[0-9a-f]{32}", cast(str, proof["generation"])) is None
        or type(proof.get("verified_at_ns")) is not int
        or proof["verified_at_ns"] <= 0
        or type(proof.get("startup_full_verification_at_ns")) is not int
        or proof["startup_full_verification_at_ns"] <= 0
        or proof["startup_full_verification_at_ns"] > proof["verified_at_ns"]
        or proof.get("verified_head_sequence") != checkpoint.get("audit_sequence")
        or proof.get("verified_head_hash") != f"sha256:{checkpoint_audit_hash.hex()}"
        or proof.get("authority_state_revision") != checkpoint.get("state_revision")
        or proof.get("database_instance_id") != checkpoint.get("database_instance_id")
        or proof.get("authority_checkpoint_sha256") != checkpoint_digest
        or not isinstance(proof.get("schema_definition_sha256"), str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}",
            cast(str, proof["schema_definition_sha256"]),
        )
        is None
    ):
        raise RuntimeError(f"{node} returned an unbound terminal authority proof")
    if prior_authority is not None and (
        authority.get("namespace_process_id") != prior_authority.get("namespace_process_id")
        or any(
            cast(int, authority[field_name]) < cast(int, prior_authority[field_name])
            for field_name in _AUTHORITY_COUNTER_FIELDS
        )
        or (
            prior_authority.get("first_fault") is not None
            and authority.get("first_fault") != prior_authority.get("first_fault")
        )
    ):
        raise RuntimeError(f"{node} terminal authority status moved backward")
    if prior_observation is not None:
        prior_checkpoint = _validated_authority_checkpoint(
            prior_observation.get("authority_checkpoint"),
            node=node,
        )
        prior_audit = prior_observation.get("audit_verification")
        _validate_checkpoint_progression(prior_checkpoint, checkpoint, node=node)
        if (
            prior_observation.get("lifetime_id") != expected_lifetime_id
            or proof.get("generation") != prior_observation.get("generation")
            or proof.get("schema_definition_sha256")
            != prior_observation.get("sqlite_schema_sha256")
            or not isinstance(prior_audit, dict)
            or proof.get("startup_full_verification_at_ns")
            != prior_audit.get("last_full_verification_at_ns")
        ):
            raise RuntimeError(f"{node} terminal proof is not bound to its prior observation")
    result = dict(terminal)
    result["authority_anchor"] = authority
    result["authority_checkpoint"] = checkpoint
    result["terminal_audit_proof"] = proof
    return result


def _allowed_transient_audit_error(value: str) -> bool:
    return value == AUDIT_TRANSIENT_CONNECT_BUSY


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
    # last_success_ns is volatile and resets to None on process start, so an
    # error before the first acknowledged non-empty batch legitimately reports
    # no prior success; when present the marker must stay a positive integer.
    if last_success_ns is not None and (
        isinstance(last_success_ns, bool)
        or not isinstance(last_success_ns, int)
        or last_success_ns <= 0
    ):
        raise RuntimeError(f"{node} returned a malformed audit success marker: {status!r}")
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
    shared_deadline: float | None = None,
    interrupt: Callable[[], None] | None = None,
) -> dict[str, Any]:
    stalled_for = float(initial_exporter["stalled_for_s"])
    maximum_stall = float(initial_exporter["max_stall_s"])
    remaining_window = maximum_stall - stalled_for
    if not math.isfinite(remaining_window) or remaining_window <= 0:
        raise RuntimeError(f"{node} audit exporter has no remaining recovery window")
    deadline = initial_observed_monotonic + remaining_window
    if shared_deadline is not None:
        deadline = min(deadline, shared_deadline)
    last: object = None
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        try:
            request_options: dict[str, Any] = {
                "retry_timeout_s": max(0.001, remaining),
            }
            if interrupt is not None:
                request_options["interrupt"] = interrupt
            if shared_deadline is None:
                metrics = client.request(
                    "GET",
                    node,
                    "/v1/metrics",
                    **request_options,
                )
            else:
                request_options["deadline_monotonic"] = deadline
                metrics = client.request(
                    "GET",
                    node,
                    "/v1/metrics",
                    **request_options,
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


class PlannedNodeUnavailableError(RuntimeError):
    """Abort one node observation only for an exact orchestrated restart window."""

    def __init__(self, window: dict[str, Any]) -> None:
        self.window = window
        super().__init__(
            "planned node restart interrupted health observation: "
            f"{window.get('service')} {window.get('restart_id')}"
        )


class HealthObservationError(RuntimeError):
    """Retain bounded authority diagnostics without replacing the primary failure."""

    def __init__(
        self,
        node: str,
        cause: BaseException,
        *,
        authority_anchor: dict[str, Any] | None,
        diagnostic: dict[str, Any],
        failed_observation: dict[str, Any],
        retry_errors: dict[str, str | None],
    ) -> None:
        self.node = node
        self.cause_type = f"{type(cause).__module__}.{type(cause).__qualname__}"
        encoded_cause = str(cause).encode("utf-8", errors="replace")[:512]
        self.cause_message = encoded_cause.decode("utf-8", errors="ignore")
        self.authority_anchor = authority_anchor
        self.diagnostic = diagnostic
        self.failed_observation = failed_observation
        self.retry_errors = retry_errors
        super().__init__(
            f"{node} health observation failed ({type(cause).__name__}): {self.cause_message}"
        )


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    encoded = (
        json.dumps(
            value,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    try:
        with temporary.open("wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        with path.open("r+b") as published:
            os.fsync(published.fileno())
        if os.name != "nt":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temporary.exists():
            with suppress(OSError):
                temporary.unlink()


def _coordination_payload_sha256(value: dict[str, Any]) -> str:
    payload = dict(value)
    payload.pop("coordination_payload_sha256", None)
    encoded = json.dumps(
        payload,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _seal_workload_artifact(
    value: dict[str, Any],
    *,
    journal_revision: int,
    maximum_bytes: int = WORKLOAD_ARTIFACT_MAX_BYTES,
) -> dict[str, Any]:
    """Bind one atomic workload artifact to its monotone journal revision."""

    if type(journal_revision) is not int or journal_revision <= 0:
        raise ValueError("workload journal revision must be a positive integer")
    if type(maximum_bytes) is not int or maximum_bytes <= 0:
        raise ValueError("workload artifact byte bound must be a positive integer")
    sealed = dict(value)
    sealed["artifact_revision"] = 1
    sealed["journal_revision"] = journal_revision
    sealed.pop("artifact_payload_sha256", None)
    payload = json.dumps(
        sealed,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    sealed["artifact_payload_sha256"] = f"sha256:{hashlib.sha256(payload).hexdigest()}"
    encoded = json.dumps(
        sealed,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) + 1 > maximum_bytes:
        raise ValueError("workload artifact exceeds its encoded byte bound")
    return sealed


def _restart_acknowledgement(
    marker: dict[str, Any],
    *,
    observed_monotonic: float | None = None,
    quiesced_monotonic: float | None = None,
    recovered_monotonic: float | None = None,
    recovered_authority_anchor: dict[str, Any] | None = None,
    prior_authority_anchor: dict[str, Any] | None = None,
    prior_authority_checkpoint: dict[str, Any] | None = None,
    prior_observation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "armed_monotonic_seconds": marker["armed_monotonic_seconds"],
        "episode": marker["episode"],
        "quiesce_pause_id": marker["quiesce_pause_id"],
        "restart_id": marker["restart_id"],
        "service": marker["service"],
    }

    with _RESTART_ACK_LOCK:
        acknowledgement = dict(identity)
        current: dict[str, Any] | None = None
        if WORKLOAD_RESTART_ACK.exists():
            try:
                current = _coordination_object(WORKLOAD_RESTART_ACK)
            except FileNotFoundError:
                current = None
        if current is not None:
            if (
                any(current.get(key) != value for key, value in identity.items())
                or type(current.get("coordination_revision")) is not int
                or current["coordination_revision"] <= 0
                or current.get("coordination_payload_sha256")
                != _coordination_payload_sha256(current)
            ):
                raise RuntimeError(f"planned restart acknowledgement identity changed: {current!r}")
            acknowledgement = current
        changed = current is None

        def bind(field_name: str, value: object | None, *, error: str) -> None:
            nonlocal changed
            if value is None:
                return
            existing = acknowledgement.get(field_name)
            if existing is not None and existing != value:
                raise RuntimeError(error)
            if existing is None:
                acknowledgement[field_name] = value
                changed = True

        def bind_first(field_name: str, value: object | None) -> None:
            nonlocal changed
            if value is not None and acknowledgement.get(field_name) is None:
                acknowledgement[field_name] = value
                changed = True

        bind(
            "prior_authority_anchor",
            prior_authority_anchor,
            error="planned restart acknowledgement authority identity changed",
        )
        bind(
            "prior_authority_checkpoint",
            prior_authority_checkpoint,
            error="planned restart acknowledgement checkpoint changed",
        )
        bind(
            "prior_observation",
            prior_observation,
            error="planned restart acknowledgement observation identity changed",
        )
        bind_first("observed_monotonic_seconds", observed_monotonic)
        bind(
            "quiesced_monotonic_seconds",
            quiesced_monotonic,
            error="planned restart quiescence timestamp changed",
        )
        if recovered_monotonic is not None:
            bind(
                "completed_monotonic_seconds",
                marker.get("completed_monotonic_seconds"),
                error="planned restart completion timestamp changed",
            )
            bind_first("recovered_monotonic_seconds", recovered_monotonic)
        if recovered_authority_anchor is not None:
            expected = marker.get("expected_recovered_authority_identity")
            actual = {
                "lifetime_id": recovered_authority_anchor.get("lifetime_id"),
                "namespace_process_id": recovered_authority_anchor.get("namespace_process_id"),
            }
            if expected != actual:
                raise RuntimeError("recovered authority does not match the host-bound replacement")
            bind(
                "recovered_authority_anchor",
                recovered_authority_anchor,
                error="planned restart recovered authority identity changed",
            )
        if not changed:
            return acknowledgement
        acknowledgement["coordination_revision"] = (
            1 if current is None else cast(int, current["coordination_revision"]) + 1
        )
        acknowledgement["coordination_payload_sha256"] = _coordination_payload_sha256(
            acknowledgement
        )
        _write_json_atomic(WORKLOAD_RESTART_ACK, acknowledgement)
        return acknowledgement


def _planned_restart_window(
    node: str,
    *,
    observation_started_monotonic: float,
    prior_authority_anchor: dict[str, Any] | None = None,
    prior_authority_checkpoint: dict[str, Any] | None = None,
    prior_observation: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return the durable exact restart marker only when it overlaps this observation."""

    if not WORKLOAD_RESTART.exists():
        return None
    try:
        marker = _coordination_object(WORKLOAD_RESTART)
    except FileNotFoundError:
        return None
    restart_id = marker.get("restart_id")
    episode = marker.get("episode")
    service = marker.get("service")
    state = marker.get("state")
    armed = marker.get("armed_monotonic_seconds")
    completed = marker.get("completed_monotonic_seconds")
    quiesce_pause_id = marker.get("quiesce_pause_id")
    if (
        not isinstance(restart_id, str)
        or not restart_id
        or isinstance(episode, bool)
        or not isinstance(episode, int)
        or episode < 0
        or service not in NODES
        or state not in {"armed", "completed"}
        or not isinstance(quiesce_pause_id, str)
        or not quiesce_pause_id
        or isinstance(armed, bool)
        or not isinstance(armed, (int, float))
        or not math.isfinite(float(armed))
        or float(armed) <= 0
        or (
            state == "completed"
            and (
                isinstance(completed, bool)
                or not isinstance(completed, (int, float))
                or not math.isfinite(float(completed))
                or float(completed) < float(armed)
            )
        )
        or (state == "armed" and completed is not None)
    ):
        raise RuntimeError(f"malformed planned restart marker: {marker!r}")
    if service != node:
        return None
    now = time.monotonic()
    if state == "armed":
        if prior_authority_anchor is None:
            raise RuntimeError("planned restart lacks a completed pre-arm authority observation")
        prior_authority_anchor = _bounded_authority_anchor_status(
            prior_authority_anchor,
            node=node,
            require_healthy=True,
        )
        try:
            pause_acknowledgement = _coordination_object(WORKLOAD_PAUSE_ACK)
        except FileNotFoundError as exc:
            raise RuntimeError(
                "planned restart lacks its main-thread quiescence acknowledgement"
            ) from exc
        quiesced = pause_acknowledgement.get("observed_monotonic_seconds")
        if (
            pause_acknowledgement.get("pause_id") != quiesce_pause_id
            or pause_acknowledgement.get("reason") != "planned_restart"
            or pause_acknowledgement.get("restart_id") != restart_id
            or pause_acknowledgement.get("service") != service
            or pause_acknowledgement.get("paused") is not True
            or isinstance(quiesced, bool)
            or not isinstance(quiesced, (int, float))
            or not math.isfinite(float(quiesced))
            or float(quiesced) > float(armed)
        ):
            raise RuntimeError("planned restart quiescence acknowledgement is invalid")
        acknowledgement = _restart_acknowledgement(
            marker,
            observed_monotonic=now,
            quiesced_monotonic=float(quiesced),
            prior_authority_anchor=prior_authority_anchor,
            prior_authority_checkpoint=prior_authority_checkpoint,
            prior_observation=prior_observation,
        )
    else:
        if not WORKLOAD_RESTART_ACK.exists():
            raise RuntimeError("completed planned restart lacks its pre-SIGKILL acknowledgement")
        try:
            acknowledgement = _coordination_object(WORKLOAD_RESTART_ACK)
        except FileNotFoundError as exc:
            raise RuntimeError(
                "completed planned restart lost its pre-SIGKILL acknowledgement"
            ) from exc
    identity = (
        "armed_monotonic_seconds",
        "episode",
        "quiesce_pause_id",
        "restart_id",
        "service",
    )
    observed = acknowledgement.get("observed_monotonic_seconds")
    quiesced = acknowledgement.get("quiesced_monotonic_seconds")
    acknowledged = acknowledgement.get("acknowledged_monotonic_seconds")
    if (
        any(acknowledgement.get(key) != marker.get(key) for key in identity)
        or type(acknowledgement.get("coordination_revision")) is not int
        or acknowledgement["coordination_revision"] <= 0
        or acknowledgement.get("coordination_payload_sha256")
        != _coordination_payload_sha256(acknowledgement)
        or isinstance(observed, bool)
        or not isinstance(observed, (int, float))
        or not math.isfinite(float(observed))
        or not float(armed) <= float(observed) <= now
        or (
            quiesced is not None
            and (
                isinstance(quiesced, bool)
                or not isinstance(quiesced, (int, float))
                or not math.isfinite(float(quiesced))
                or not float(quiesced) <= float(armed) <= float(observed)
            )
        )
        or (
            acknowledged is not None
            and (
                quiesced is None
                or isinstance(acknowledged, bool)
                or not isinstance(acknowledged, (int, float))
                or not math.isfinite(float(acknowledged))
                or not float(observed) <= float(acknowledged) <= now
                or float(acknowledged) - float(observed) > MAXIMUM_PLANNED_FENCE_PREPARATION_SECONDS
                or not isinstance(acknowledgement.get("fence_terminal_sha256"), str)
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    cast(str, acknowledgement.get("fence_terminal_sha256")),
                )
                is None
                or not isinstance(acknowledgement.get("target_identity_sha256"), str)
                or re.fullmatch(
                    r"sha256:[0-9a-f]{64}",
                    cast(str, acknowledgement.get("target_identity_sha256")),
                )
                is None
                or not isinstance(
                    acknowledgement.get("host_fence_validated_monotonic_seconds"),
                    (int, float),
                )
                or isinstance(acknowledgement.get("host_fence_validated_monotonic_seconds"), bool)
                or not isinstance(
                    acknowledgement.get("host_reinspected_monotonic_seconds"),
                    (int, float),
                )
                or isinstance(acknowledgement.get("host_reinspected_monotonic_seconds"), bool)
                or not isinstance(
                    acknowledgement.get("host_ack_command_started_monotonic_seconds"),
                    (int, float),
                )
                or isinstance(
                    acknowledgement.get("host_ack_command_started_monotonic_seconds"), bool
                )
                or not math.isfinite(
                    float(acknowledgement["host_fence_validated_monotonic_seconds"])
                )
                or not math.isfinite(float(acknowledgement["host_reinspected_monotonic_seconds"]))
                or not math.isfinite(
                    float(acknowledgement["host_ack_command_started_monotonic_seconds"])
                )
                or not float(acknowledgement["host_fence_validated_monotonic_seconds"])
                <= float(acknowledgement["host_reinspected_monotonic_seconds"])
                <= float(acknowledgement["host_ack_command_started_monotonic_seconds"])
            )
        )
    ):
        raise RuntimeError(
            "planned restart acknowledgement is malformed or stale: "
            f"marker={marker!r} acknowledgement={acknowledgement!r}"
        )
    if (
        state == "armed"
        and acknowledged is None
        and now - float(observed) > MAXIMUM_PLANNED_FENCE_PREPARATION_SECONDS
    ):
        raise RuntimeError("planned restart fence preparation exceeded its bounded window")
    if (
        state == "armed"
        and acknowledged is not None
        and now - float(acknowledged) > MAXIMUM_PLANNED_RESTART_SECONDS
    ):
        try:
            refreshed = _coordination_object(WORKLOAD_RESTART)
        except FileNotFoundError:
            refreshed = {}
        refreshed_completed = refreshed.get("completed_monotonic_seconds")
        if (
            any(refreshed.get(key) != marker.get(key) for key in identity)
            or refreshed.get("state") != "completed"
            or isinstance(refreshed_completed, bool)
            or not isinstance(refreshed_completed, (int, float))
            or not math.isfinite(float(refreshed_completed))
            or not float(acknowledged) <= float(refreshed_completed)
            or float(refreshed_completed) - float(acknowledged) > MAXIMUM_PLANNED_RESTART_SECONDS
        ):
            raise RuntimeError("acknowledged planned restart exceeded its live 30s window")
        marker = refreshed
        state = "completed"
        completed = refreshed_completed
    overlaps = state == "armed" or observation_started_monotonic <= float(
        cast(int | float, completed)
    )
    if overlaps:
        if state == "completed":
            if not WORKLOAD_RESTART_ACK.exists():
                raise RuntimeError(
                    "completed planned restart lacks its pre-SIGKILL acknowledgement"
                )
            try:
                acknowledgement = _coordination_object(WORKLOAD_RESTART_ACK)
            except FileNotFoundError as exc:
                raise RuntimeError(
                    "completed planned restart lost its pre-SIGKILL acknowledgement"
                ) from exc
            acknowledged = acknowledgement.get("acknowledged_monotonic_seconds")
        if state == "completed" and (
            any(acknowledgement.get(key) != marker.get(key) for key in identity)
            or isinstance(acknowledged, bool)
            or not isinstance(acknowledged, (int, float))
            or not math.isfinite(float(acknowledged))
            or not float(armed) <= float(acknowledged) <= now
            or (
                float(cast(int | float, completed)) < float(acknowledged)
                or float(cast(int | float, completed)) - float(acknowledged)
                > MAXIMUM_PLANNED_RESTART_SECONDS
            )
        ):
            raise RuntimeError(
                "planned restart acknowledgement is malformed, stale, or expired: "
                f"marker={marker!r} acknowledgement={acknowledgement!r}"
            )
        return marker
    return None


def _acknowledge_completed_restart(
    node: str,
    *,
    observed_monotonic: float,
    authority_anchor: dict[str, Any],
) -> None:
    if not WORKLOAD_RESTART.exists():
        return
    try:
        marker = _coordination_object(WORKLOAD_RESTART)
    except FileNotFoundError:
        return
    completed = marker.get("completed_monotonic_seconds")
    if (
        marker.get("service") == node
        and marker.get("state") == "completed"
        and isinstance(completed, (int, float))
        and not isinstance(completed, bool)
        and math.isfinite(float(completed))
        and float(completed) <= observed_monotonic
    ):
        _restart_acknowledgement(
            marker,
            recovered_monotonic=observed_monotonic,
            recovered_authority_anchor=authority_anchor,
        )


def _require_planned_lifetime_change(
    node: str,
    *,
    prior_authority: dict[str, Any],
    prior_checkpoint: dict[str, Any],
    prior_observation: dict[str, Any],
    current_authority: dict[str, Any],
) -> None:
    """Bind an observed core lifetime change to its completed durable restart episode."""

    try:
        marker = _coordination_object(WORKLOAD_RESTART)
        acknowledgement = _coordination_object(WORKLOAD_RESTART_ACK)
    except FileNotFoundError as exc:
        raise RuntimeError(f"{node} changed lifetime without planned restart evidence") from exc
    identity = (
        "armed_monotonic_seconds",
        "episode",
        "quiesce_pause_id",
        "restart_id",
        "service",
    )
    if (
        marker.get("state") != "completed"
        or marker.get("service") != node
        or any(acknowledgement.get(key) != marker.get(key) for key in identity)
        or acknowledgement.get("prior_authority_anchor") != prior_authority
        or acknowledgement.get("prior_authority_checkpoint") != prior_checkpoint
        or acknowledgement.get("prior_observation") != prior_observation
        or acknowledgement.get("recovered_authority_anchor") != current_authority
        or current_authority.get("lifetime_id") == prior_authority.get("lifetime_id")
    ):
        raise RuntimeError(f"{node} lifetime change is not bound to its planned restart")


def _health_sample(
    client: ClusterClient,
    *,
    elapsed_s: float,
    audit_error_budget: AuditErrorBudget | None = None,
    deadline: float | None = None,
    observation_origin_monotonic: float | None = None,
    planned_restart_reader: Callable[..., dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    origin = (
        time.monotonic() - elapsed_s
        if observation_origin_monotonic is None
        else observation_origin_monotonic
    )

    def request(
        node: str,
        path: str,
        *,
        observation_started: float,
    ) -> dict[str, Any]:
        def interrupt() -> None:
            interrupt_planned_restart(node, observation_started)

        request_options: dict[str, Any] = {}
        request_options["single_attempt"] = True
        if planned_restart_reader is not None:
            request_options["interrupt"] = interrupt
        if deadline is None:
            return client.request("GET", node, path, **request_options)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("cluster health sample exhausted its shared deadline")
        request_options["deadline_monotonic"] = deadline
        return client.request(
            "GET",
            node,
            path,
            **request_options,
        )

    def interrupt_planned_restart(node: str, observation_started: float) -> None:
        if planned_restart_reader is None:
            return
        window = planned_restart_reader(
            node,
            observation_started_monotonic=observation_started,
        )
        if window is not None:
            raise PlannedNodeUnavailableError(window)

    def begin_retry_scope() -> None:
        candidate = getattr(client, "begin_retry_scope", None)
        if callable(candidate):
            candidate()

    def retry_scope() -> dict[str, str | None]:
        candidate = getattr(client, "retry_scope", None)
        if callable(candidate):
            value = candidate()
            if isinstance(value, dict):
                return {
                    "first_error": cast(str | None, value.get("first_error")),
                    "last_error": cast(str | None, value.get("last_error")),
                }
        return {"first_error": None, "last_error": None}

    def observation_request_count(
        *,
        planned_unavailable: bool,
        allow_unattempted_failure: bool = False,
    ) -> int:
        value = getattr(client, "last_request_attempt_count", 1)
        allowed = {0, 1} if planned_unavailable or allow_unattempted_failure else {1}
        if type(value) is not int or value not in allowed:
            raise RuntimeError(
                "health observation did not use its exact single-attempt request budget"
            )
        return value

    def raise_health_failure(
        node: str,
        cause: BaseException,
        *,
        fallback_authority: dict[str, Any] | None,
        observation_snapshot: dict[str, Any] | None,
        observation_started: float,
        metrics_observed_monotonic: float | None,
        retry_count_before: int,
    ) -> None:
        observation_completed = time.monotonic()
        primary_retry_errors = retry_scope()
        failed_observation: dict[str, Any] = {
            "observation": {
                "completed_elapsed_seconds": round(observation_completed - origin, 6),
                "metrics_observed_elapsed_seconds": (
                    None
                    if metrics_observed_monotonic is None
                    else round(metrics_observed_monotonic - origin, 6)
                ),
                "request_count": observation_request_count(
                    planned_unavailable=False,
                    allow_unattempted_failure=True,
                ),
                "request_path": "/v1/metrics",
                "request_retries": int(getattr(client, "retry_count", 0)) - retry_count_before,
                "retry_errors": primary_retry_errors,
                "started_elapsed_seconds": round(observation_started - origin, 6),
            },
            "observation_snapshot": (
                None if observation_snapshot is None else copy.deepcopy(observation_snapshot)
            ),
        }
        diagnostic_started = time.monotonic()
        diagnostic_deadline = diagnostic_started + AUTHORITY_FAILURE_DIAGNOSTIC_SECONDS
        diagnostic_error: str | None = None
        authority_anchor = fallback_authority
        try:
            authority_anchor = _bounded_authority_anchor_status(
                client.request(
                    "GET",
                    node,
                    "/v1/maintenance/authority-status",
                    retry_timeout_s=AUTHORITY_FAILURE_DIAGNOSTIC_SECONDS,
                    deadline_monotonic=diagnostic_deadline,
                ),
                node=node,
                require_healthy=False,
                allow_fenced=True,
            )
        except BaseException as diagnostic_exc:
            diagnostic_error = (
                f"{type(diagnostic_exc).__module__}.{type(diagnostic_exc).__qualname__}"
            )
        diagnostic_completed = time.monotonic()
        raise HealthObservationError(
            node,
            cause,
            authority_anchor=authority_anchor,
            diagnostic={
                "completed_monotonic_seconds": diagnostic_completed,
                "deadline_monotonic_seconds": diagnostic_deadline,
                "error_type": diagnostic_error,
                "started_monotonic_seconds": diagnostic_started,
                "status_captured": authority_anchor is not None,
            },
            failed_observation=failed_observation,
            retry_errors=primary_retry_errors,
        ) from cause

    nodes: dict[str, Any] = {}
    audit_catchup_nodes: list[str] = []
    audit_error_recoveries: list[dict[str, Any]] = []
    planned_unavailable_nodes: list[str] = []
    for node in NODES:
        observation_started = time.monotonic()
        retry_count_before = int(getattr(client, "retry_count", 0))
        begin_retry_scope()
        authority_anchor: dict[str, Any] | None = None
        raw_metrics: dict[str, Any] | None = None
        metrics_observed_monotonic: float | None = None
        try:
            raw_metrics = request(
                node,
                "/v1/metrics",
                observation_started=observation_started,
            )
            metrics_observed_monotonic = time.monotonic()
            metrics = _validated_observation(raw_metrics, node=node)
            authority_anchor = cast(dict[str, Any], metrics["authority_anchor"])
        except PlannedNodeUnavailableError as exc:
            observation_completed = time.monotonic()
            nodes[node] = {
                "observation": {
                    "completed_elapsed_seconds": round(
                        observation_completed - origin,
                        6,
                    ),
                    "metrics_observed_elapsed_seconds": None,
                    "request_retries": int(getattr(client, "retry_count", 0)) - retry_count_before,
                    "retry_errors": retry_scope(),
                    "request_count": observation_request_count(planned_unavailable=True),
                    "request_path": "/v1/metrics",
                    "started_elapsed_seconds": round(observation_started - origin, 6),
                },
                "planned_unavailable": exc.window,
            }
            planned_unavailable_nodes.append(node)
            continue
        except BaseException as exc:
            raise_health_failure(
                node,
                exc,
                fallback_authority=authority_anchor,
                observation_snapshot=raw_metrics,
                observation_started=observation_started,
                metrics_observed_monotonic=metrics_observed_monotonic,
                retry_count_before=retry_count_before,
            )
        if metrics_observed_monotonic is None:
            raise RuntimeError(f"{node} metrics observation time was not retained")
        try:
            audit_exporter = _bounded_audit_exporter(metrics.get("audit_exporter"), node=node)
            capacity = metrics.get("storage_capacity")
            invariant = cast(dict[str, Any], metrics["invariant"])
            if not isinstance(capacity, dict) or capacity.get("healthy") is not True:
                raise RuntimeError(f"{node} storage capacity is unhealthy")
            if metrics.get("service_ready") is not True:
                raise RuntimeError(f"{node} core service is not ready")
            peer_dispatcher = metrics.get("peer_dispatcher")
            expected_ready = (
                audit_exporter["healthy"] is True
                and isinstance(peer_dispatcher, dict)
                and peer_dispatcher.get("healthy") is True
            )
            if metrics.get("ready") is not expected_ready:
                raise RuntimeError(f"{node} returned inconsistent aggregate readiness")
            if audit_exporter["catching_up"] is True:
                audit_catchup_nodes.append(node)
            nodes[node] = {
                "audit_exporter": audit_exporter,
                "audit_outbox": metrics.get("audit_outbox"),
                "authority_anchor": authority_anchor,
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
                "observation_generation": metrics.get("generation"),
                "observation_revision": metrics.get("revision"),
                "observation_snapshot_id": metrics.get("snapshot_id"),
                "observation_snapshot": metrics,
            }
        except BaseException as exc:
            raise_health_failure(
                node,
                exc,
                fallback_authority=authority_anchor,
                observation_snapshot=raw_metrics,
                observation_started=observation_started,
                metrics_observed_monotonic=metrics_observed_monotonic,
                retry_count_before=retry_count_before,
            )
        try:
            if audit_exporter.get("last_error") is not None:
                if audit_error_budget is None:
                    raise RuntimeError(
                        f"{node} sampled an audit exporter error outside the shared "
                        "workload error budget"
                    )
                audit_error_budget.observe_error(node)
            elif (
                audit_error_budget is not None and node in audit_error_budget.unresolved_error_nodes
            ):
                audit_error_budget.mark_recovered(node)
                # The record must equal the retained sample's elapsed_seconds
                # exactly, which is rounded to three decimals below.
                audit_error_recoveries.append(
                    {
                        "elapsed_seconds": round(elapsed_s, 3),
                        "node": node,
                        "recovered_by_later_scheduled_sample": True,
                    }
                )
            observation_completed = time.monotonic()
            _acknowledge_completed_restart(
                node,
                observed_monotonic=observation_completed,
                authority_anchor=cast(dict[str, Any], authority_anchor),
            )
        except PlannedNodeUnavailableError as exc:
            observation_completed = time.monotonic()
            nodes[node] = {
                "observation": {
                    "completed_elapsed_seconds": round(observation_completed - origin, 6),
                    "metrics_observed_elapsed_seconds": None,
                    "request_retries": (
                        int(getattr(client, "retry_count", 0)) - retry_count_before
                    ),
                    "retry_errors": retry_scope(),
                    "request_count": observation_request_count(planned_unavailable=True),
                    "request_path": "/v1/metrics",
                    "started_elapsed_seconds": round(observation_started - origin, 6),
                },
                "planned_unavailable": exc.window,
            }
            planned_unavailable_nodes.append(node)
            continue
        except BaseException as exc:
            raise_health_failure(
                node,
                exc,
                fallback_authority=authority_anchor,
                observation_snapshot=raw_metrics,
                observation_started=observation_started,
                metrics_observed_monotonic=metrics_observed_monotonic,
                retry_count_before=retry_count_before,
            )
        nodes[node]["observation"] = {
            "completed_elapsed_seconds": round(observation_completed - origin, 6),
            "metrics_observed_elapsed_seconds": round(
                metrics_observed_monotonic - origin,
                6,
            ),
            "request_retries": int(getattr(client, "retry_count", 0)) - retry_count_before,
            "retry_errors": retry_scope(),
            "request_count": observation_request_count(planned_unavailable=False),
            "request_path": "/v1/metrics",
            "started_elapsed_seconds": round(observation_started - origin, 6),
        }
    sample = {
        "audit_catchup_nodes": audit_catchup_nodes,
        "audit_error_recoveries": audit_error_recoveries,
        "elapsed_seconds": round(elapsed_s, 3),
        "nodes": nodes,
        "planned_unavailable_nodes": planned_unavailable_nodes,
    }
    return sample


class HealthSampler:
    """Observe health on an absolute schedule independent of mixed-workload latency."""

    def __init__(
        self,
        *,
        started_monotonic: float,
        interval_seconds: float,
        retry_timeout_seconds: float,
        seed: int,
        failure_event: threading.Event,
        on_sample: Callable[[], None] | None = None,
        final_observation_advance_seconds: float = FINAL_HEALTH_OBSERVATION_ADVANCE_SECONDS,
    ) -> None:
        if (
            not math.isfinite(started_monotonic)
            or started_monotonic <= 0
            or not math.isfinite(interval_seconds)
            or interval_seconds <= 0
            or interval_seconds > HEALTH_CADENCE_LIMIT_SECONDS
        ):
            raise ValueError("health monitor schedule is invalid")
        if (
            not math.isfinite(final_observation_advance_seconds)
            or final_observation_advance_seconds <= 0
            or final_observation_advance_seconds >= HEALTH_CADENCE_LIMIT_SECONDS
        ):
            raise ValueError("terminal health observation advance bound is invalid")
        self._started = started_monotonic
        self._interval = interval_seconds
        self._final_observation_advance = float(final_observation_advance_seconds)
        self._client = ClusterClient(seed=seed, retry_timeout_s=retry_timeout_seconds)
        self._audit_error_budget = AuditErrorBudget()
        self._failure_event = failure_event
        self._cancel_event = threading.Event()
        self._schedule_changed = threading.Event()
        self._lock = threading.Lock()
        self._finish_at: float | None = None
        self._finished_at: float | None = None
        self._error: BaseException | None = None
        self._failure_schedule: dict[str, Any] | None = None
        self._current_schedule: dict[str, Any] | None = None
        self._failed_sample: dict[str, Any] | None = None
        self._attempted_sample_count = 0
        self._samples: list[dict[str, Any]] = []
        self._last_observed_monotonic: dict[str, float] = {}
        self._last_authority_status: dict[str, dict[str, Any]] = {}
        self._last_observation_identity: dict[str, dict[str, Any]] = {}
        self._on_sample = on_sample
        self._thread = threading.Thread(
            target=self._run,
            name="lets-production-soak-health-monitor",
            daemon=True,
        )

    @property
    def failure_event(self) -> threading.Event:
        return self._failure_event

    def start(self) -> None:
        self._thread.start()

    def raise_if_failed(self) -> None:
        with self._lock:
            error = self._error
        if error is not None:
            raise RuntimeError(f"independent health monitor failed: {error}") from error

    def _deadline_for(self, scheduled: float) -> float:
        deadline = scheduled + HEALTH_CADENCE_LIMIT_SECONDS
        with self._lock:
            prior_observations = dict(self._last_observed_monotonic)
        marker: dict[str, Any] | None = None
        acknowledgement: dict[str, Any] | None = None
        if WORKLOAD_RESTART.exists():
            try:
                marker = _coordination_object(WORKLOAD_RESTART)
            except FileNotFoundError:
                marker = None
        if WORKLOAD_RESTART_ACK.exists():
            try:
                acknowledgement = _coordination_object(WORKLOAD_RESTART_ACK)
            except FileNotFoundError:
                acknowledgement = None
        for node, observed in prior_observations.items():
            node_deadline = observed + HEALTH_CADENCE_LIMIT_SECONDS
            if isinstance(marker, dict) and marker.get("service") == node:
                marker_started = marker.get("armed_monotonic_seconds")
                marker_completed = marker.get("completed_monotonic_seconds")
                if (
                    isinstance(marker_started, (int, float))
                    and not isinstance(marker_started, bool)
                    and math.isfinite(float(marker_started))
                ):
                    prepared_at = (
                        acknowledgement.get("observed_monotonic_seconds")
                        if isinstance(acknowledgement, dict)
                        else None
                    )
                    acknowledged_at = (
                        acknowledgement.get("acknowledged_monotonic_seconds")
                        if isinstance(acknowledgement, dict)
                        else None
                    )
                    marker_prepared = bool(
                        isinstance(acknowledgement, dict)
                        and acknowledgement.get("restart_id") == marker.get("restart_id")
                        and acknowledgement.get("episode") == marker.get("episode")
                        and acknowledgement.get("service") == marker.get("service")
                        and acknowledgement.get("armed_monotonic_seconds") == marker_started
                        and isinstance(prepared_at, (int, float))
                        and not isinstance(prepared_at, bool)
                        and math.isfinite(float(prepared_at))
                        and float(marker_started) <= float(prepared_at)
                    )
                    marker_acknowledged = bool(
                        marker_prepared
                        and isinstance(acknowledged_at, (int, float))
                        and not isinstance(acknowledged_at, bool)
                        and math.isfinite(float(acknowledged_at))
                        and float(cast(int | float, prepared_at)) <= float(acknowledged_at)
                    )
                    if (
                        marker.get("state") == "armed"
                        and marker_completed is None
                        and marker_prepared
                    ):
                        if not marker_acknowledged and (
                            time.monotonic() - float(cast(int | float, prepared_at))
                            > MAXIMUM_PLANNED_FENCE_PREPARATION_SECONDS
                        ):
                            raise RuntimeError(
                                "planned restart fence preparation exceeded its bounded window"
                            )
                        if marker_acknowledged and (
                            time.monotonic() - float(cast(int | float, acknowledged_at))
                            > MAXIMUM_PLANNED_RESTART_SECONDS
                        ):
                            try:
                                refreshed = _coordination_object(WORKLOAD_RESTART)
                            except FileNotFoundError:
                                refreshed = {}
                            refreshed_completed = refreshed.get("completed_monotonic_seconds")
                            identity = (
                                "armed_monotonic_seconds",
                                "episode",
                                "quiesce_pause_id",
                                "restart_id",
                                "service",
                            )
                            if (
                                any(refreshed.get(key) != marker.get(key) for key in identity)
                                or refreshed.get("state") != "completed"
                                or isinstance(refreshed_completed, bool)
                                or not isinstance(refreshed_completed, (int, float))
                                or not math.isfinite(float(refreshed_completed))
                                or not float(cast(int | float, acknowledged_at))
                                <= float(refreshed_completed)
                                or float(refreshed_completed)
                                - float(cast(int | float, acknowledged_at))
                                > MAXIMUM_PLANNED_RESTART_SECONDS
                            ):
                                raise RuntimeError(
                                    "acknowledged planned restart exceeded its live 30s window"
                                )
                            marker = refreshed
                            marker_completed = refreshed_completed
                        if marker.get("state") == "armed":
                            continue
                    if (
                        marker.get("state") == "completed"
                        and marker_acknowledged
                        and isinstance(marker_completed, (int, float))
                        and not isinstance(marker_completed, bool)
                        and float(marker_completed) >= float(marker_started)
                        and float(marker_completed) >= float(cast(int | float, acknowledged_at))
                        and float(marker_completed) - float(cast(int | float, acknowledged_at))
                        <= MAXIMUM_PLANNED_RESTART_SECONDS
                    ):
                        node_deadline = float(marker_completed) + HEALTH_CADENCE_LIMIT_SECONDS
            deadline = min(deadline, node_deadline)
        return deadline

    def _planned_restart_reader(
        self,
        node: str,
        *,
        observation_started_monotonic: float,
    ) -> dict[str, Any] | None:
        with self._lock:
            prior = self._last_authority_status.get(node)
            prior_copy = None if prior is None else dict(prior)
            prior_identity = self._last_observation_identity.get(node)
            prior_checkpoint = (
                None
                if prior_identity is None
                else dict(cast(dict[str, Any], prior_identity["authority_checkpoint"]))
            )
            prior_observation = (
                None
                if prior_identity is None
                else {
                    "audit_verification": {
                        "last_full_verification_at_ns": prior_identity[
                            "startup_full_verification_at_ns"
                        ]
                    },
                    "authority_checkpoint": prior_checkpoint,
                    "generation": prior_identity["generation"],
                    "lifetime_id": prior_identity["lifetime_id"],
                    "sqlite_schema_sha256": prior_identity["sqlite_schema_sha256"],
                }
            )
        return _planned_restart_window(
            node,
            observation_started_monotonic=observation_started_monotonic,
            prior_authority_anchor=prior_copy,
            prior_authority_checkpoint=prior_checkpoint,
            prior_observation=prior_observation,
        )

    def _final_sample_not_before(self, scheduled: float) -> float:
        """Leave time for one new cache publication before the terminal request."""

        with self._lock:
            prior_observations = tuple(self._last_observed_monotonic.values())
        if not prior_observations:
            return scheduled
        return max(
            scheduled,
            max(prior_observations) + self._final_observation_advance,
        )

    def _sample(self, *, index: int, scheduled: float) -> None:
        deadline = self._deadline_for(scheduled)
        sample_started = time.monotonic()
        with self._lock:
            self._current_schedule = {
                "deadline_elapsed_seconds": round(deadline - self._started, 6),
                "schedule_index": index,
                "scheduled_elapsed_seconds": round(scheduled - self._started, 6),
                "started_elapsed_seconds": round(sample_started - self._started, 6),
            }
        if sample_started > deadline:
            raise RuntimeError(
                f"health sample {index} missed its deadline before starting: "
                f"started={sample_started:.6f} deadline={deadline:.6f}"
            )
        sample = _health_sample(
            self._client,
            elapsed_s=sample_started - self._started,
            audit_error_budget=self._audit_error_budget,
            deadline=deadline,
            observation_origin_monotonic=self._started,
            planned_restart_reader=self._planned_restart_reader,
        )
        completed = time.monotonic()
        sample.update(
            {
                "completed_elapsed_seconds": round(completed - self._started, 6),
                "deadline_elapsed_seconds": round(deadline - self._started, 6),
                "deadline_missed": completed > deadline,
                "schedule_index": index,
                "scheduled_elapsed_seconds": round(scheduled - self._started, 6),
                "started_elapsed_seconds": round(sample_started - self._started, 6),
            }
        )
        if completed > deadline:
            with self._lock:
                self._failed_sample = copy.deepcopy(sample)
            raise RuntimeError(
                f"health sample {index} completed after its deadline: "
                f"completed={completed:.6f} deadline={deadline:.6f}"
            )
        with self._lock:
            # Keep the fully validated raw sample available until every
            # cross-sample lineage check commits. Any later failure can then be
            # diagnosed from evidence rather than from a discarded response.
            self._failed_sample = copy.deepcopy(sample)
            for node in NODES:
                document = sample["nodes"][node]
                if isinstance(document.get("planned_unavailable"), dict):
                    continue
                authority = cast(dict[str, Any], document["authority_anchor"])
                prior_authority = self._last_authority_status.get(node)
                if (
                    prior_authority is not None
                    and authority["lifetime_id"] == prior_authority["lifetime_id"]
                    and (
                        authority["namespace_process_id"] != prior_authority["namespace_process_id"]
                        or any(
                            cast(int, authority[field_name])
                            < cast(int, prior_authority[field_name])
                            for field_name in _AUTHORITY_COUNTER_FIELDS
                        )
                        or (
                            prior_authority.get("first_fault") is not None
                            and authority.get("first_fault") != prior_authority.get("first_fault")
                        )
                    )
                ):
                    raise RuntimeError(f"{node} authority status moved backward")
                snapshot = cast(dict[str, Any], document["observation_snapshot"])
                checkpoint = cast(dict[str, Any], snapshot["authority_checkpoint"])
                current = {
                    "authority_checkpoint": dict(checkpoint),
                    "generation": document.get("observation_generation"),
                    "lifetime_id": authority["lifetime_id"],
                    "revision": document.get("observation_revision"),
                    "snapshot_id": document.get("observation_snapshot_id"),
                    "core_state_revision": snapshot["core_state_revision"],
                    "database_instance_id": snapshot["database_instance_id"],
                    "sqlite_schema_sha256": snapshot["sqlite_schema_sha256"],
                    "startup_full_verification_at_ns": cast(
                        dict[str, Any], snapshot["audit_verification"]
                    )["last_full_verification_at_ns"],
                }
                prior = self._last_observation_identity.get(node)
                if prior is not None:
                    same_lifetime = current["lifetime_id"] == prior["lifetime_id"]
                    if same_lifetime and (
                        current["generation"] != prior["generation"]
                        or cast(int, current["revision"]) <= cast(int, prior["revision"])
                        or current["database_instance_id"] != prior["database_instance_id"]
                        or cast(int, current["core_state_revision"])
                        < cast(int, prior["core_state_revision"])
                    ):
                        raise RuntimeError(
                            f"{node} observation sequence did not advance in one lifetime"
                        )
                    if same_lifetime:
                        if current["sqlite_schema_sha256"] != prior["sqlite_schema_sha256"]:
                            raise RuntimeError(f"{node} SQLite schema identity changed")
                        _validate_checkpoint_progression(
                            cast(dict[str, Any], prior["authority_checkpoint"]),
                            checkpoint,
                            node=node,
                        )
                    else:
                        if current["generation"] == prior["generation"]:
                            raise RuntimeError(
                                f"{node} observation generation survived a lifetime change"
                            )
                        if prior_authority is None:
                            raise RuntimeError(f"{node} lifetime change lost prior authority")
                        _require_planned_lifetime_change(
                            node,
                            prior_authority=prior_authority,
                            prior_checkpoint=cast(dict[str, Any], prior["authority_checkpoint"]),
                            prior_observation={
                                "audit_verification": {
                                    "last_full_verification_at_ns": prior[
                                        "startup_full_verification_at_ns"
                                    ]
                                },
                                "authority_checkpoint": prior["authority_checkpoint"],
                                "generation": prior["generation"],
                                "lifetime_id": prior["lifetime_id"],
                                "sqlite_schema_sha256": prior["sqlite_schema_sha256"],
                            },
                            current_authority=authority,
                        )
                        if current["sqlite_schema_sha256"] != prior["sqlite_schema_sha256"]:
                            raise RuntimeError(
                                f"{node} SQLite schema identity changed across restart"
                            )
                        _validate_checkpoint_progression(
                            cast(dict[str, Any], prior["authority_checkpoint"]),
                            checkpoint,
                            node=node,
                        )
                    if current["snapshot_id"] == prior["snapshot_id"]:
                        raise RuntimeError(f"{node} reused an observation snapshot identity")
                self._last_observation_identity[node] = current
            self._samples.append(sample)
            self._failed_sample = None
            self._current_schedule = None
            for node in NODES:
                document = sample["nodes"][node]
                observation = document.get("observation")
                observed_elapsed = (
                    observation.get("metrics_observed_elapsed_seconds")
                    if isinstance(observation, dict)
                    else None
                )
                if isinstance(observed_elapsed, (int, float)) and not isinstance(
                    observed_elapsed,
                    bool,
                ):
                    self._last_observed_monotonic[node] = self._started + float(observed_elapsed)
                authority_anchor = document.get("authority_anchor")
                if isinstance(authority_anchor, dict):
                    self._last_authority_status[node] = dict(authority_anchor)
        if self._on_sample is not None:
            self._on_sample()

    def _run(self) -> None:
        regular_index = 0
        sample_index = 0
        try:
            while not self._cancel_event.is_set():
                with self._lock:
                    finish_at = self._finish_at
                regular_due = self._started + regular_index * self._interval
                is_final = finish_at is not None and regular_due >= finish_at
                scheduled = finish_at if is_final else regular_due
                if scheduled is None:
                    raise RuntimeError("health monitor lost its schedule")
                not_before = self._final_sample_not_before(scheduled) if is_final else scheduled
                delay = not_before - time.monotonic()
                if delay > 0:
                    self._schedule_changed.wait(delay)
                    self._schedule_changed.clear()
                    continue
                with self._lock:
                    self._attempted_sample_count += 1
                    self._current_schedule = {
                        "deadline_elapsed_seconds": round(
                            scheduled + HEALTH_CADENCE_LIMIT_SECONDS - self._started,
                            6,
                        ),
                        "schedule_index": sample_index,
                        "scheduled_elapsed_seconds": round(
                            scheduled - self._started,
                            6,
                        ),
                        "started_elapsed_seconds": None,
                    }
                self._sample(index=sample_index, scheduled=scheduled)
                sample_index += 1
                if is_final:
                    break
                regular_index += 1
        except BaseException as exc:
            with self._lock:
                self._error = exc
                self._failure_schedule = (
                    None if self._current_schedule is None else dict(self._current_schedule)
                )
            if self._on_sample is not None:
                try:
                    self._on_sample()
                except BaseException as journal_error:
                    exc.add_note(
                        "secondary workload-journal publication error: "
                        f"{type(journal_error).__name__}: {journal_error}"
                    )
            self._failure_event.set()
        finally:
            with self._lock:
                self._finished_at = time.monotonic()

    def finish(self, *, workload_ended_monotonic: float) -> None:
        if not math.isfinite(workload_ended_monotonic) or workload_ended_monotonic < self._started:
            raise RuntimeError("health monitor finish time is invalid")
        with self._lock:
            if self._finish_at is not None:
                raise RuntimeError("health monitor was already finished")
            self._finish_at = workload_ended_monotonic
        self._schedule_changed.set()
        self._thread.join(timeout=2 * HEALTH_CADENCE_LIMIT_SECONDS + 5)
        if self._thread.is_alive():
            self._cancel_event.set()
            self._schedule_changed.set()
            error = RuntimeError("independent health monitor did not join inside its bound")
            with self._lock:
                self._error = error
                self._failure_schedule = (
                    None if self._current_schedule is None else dict(self._current_schedule)
                )
            self._failure_event.set()
            self.raise_if_failed()
        self.raise_if_failed()

    def cancel(self) -> None:
        self._cancel_event.set()
        self._schedule_changed.set()
        if self._thread.ident is not None:
            self._thread.join(timeout=HEALTH_CADENCE_LIMIT_SECONDS + 5)
        if self._thread.is_alive():
            error = RuntimeError("independent health monitor remained alive after cancellation")
            with self._lock:
                self._error = error
                self._failure_schedule = (
                    None if self._current_schedule is None else dict(self._current_schedule)
                )
            self._failure_event.set()
            raise error

    def result(self, *, workload_ended_monotonic: float) -> dict[str, Any]:
        if self._thread.is_alive():
            raise RuntimeError("health monitor result requested before join")
        self.raise_if_failed()
        with self._lock:
            samples = list(self._samples)
            finished_at = self._finished_at
        window = workload_ended_monotonic - self._started
        expected = math.ceil(window / self._interval) + 1
        return {
            "audit_error_budget": self._audit_error_budget,
            "health_monitor": {
                "actual_sample_count": len(samples),
                "audit_error_budget_instances": 1,
                "deadline_miss_count": 0,
                "expected_sample_count": expected,
                "finished_elapsed_seconds": (
                    None if finished_at is None else round(finished_at - self._started, 6)
                ),
                "interval_seconds": self._interval,
                "joined": True,
                "request_retry_count": self._client.retry_count,
                "retained_sample_count": len(samples),
                "samples_truncated": 0,
                "schedule": "absolute_monotonic",
                "status": "passed",
            },
            "samples": samples,
        }

    def failure_snapshot(self, *, workload_ended_monotonic: float) -> dict[str, Any]:
        with self._lock:
            samples = list(self._samples)
            error = self._error
            failure_schedule = (
                None if self._failure_schedule is None else dict(self._failure_schedule)
            )
            finished_at = self._finished_at
            attempted = self._attempted_sample_count
            failed_sample = copy.deepcopy(self._failed_sample)
        window = max(0.0, workload_ended_monotonic - self._started)
        expected = math.ceil(window / self._interval) + 1
        error_document: dict[str, Any] | None = None
        if error is not None:
            error_document = {
                "message": str(error),
                "type": f"{type(error).__module__}.{type(error).__qualname__}",
            }
            if isinstance(error, HealthObservationError):
                error_document.update(
                    {
                        "authority_anchor": error.authority_anchor,
                        "cause_type": error.cause_type,
                        "cause_message": error.cause_message,
                        "diagnostic": error.diagnostic,
                        "failed_observation": error.failed_observation,
                        "node": error.node,
                        "retry_errors": error.retry_errors,
                    }
                )
            if failed_sample is not None:
                error_document["failed_sample"] = failed_sample
        return {
            "health_monitor": {
                "actual_sample_count": len(samples),
                "attempted_sample_count": attempted,
                "audit_error_budget_instances": 1,
                "deadline_miss_count": (
                    1 if error is not None and "deadline" in str(error).lower() else 0
                ),
                "error": error_document,
                "expected_sample_count": expected,
                "failure_schedule": failure_schedule,
                "finished_elapsed_seconds": (
                    None if finished_at is None else round(finished_at - self._started, 6)
                ),
                "interval_seconds": self._interval,
                "joined": not self._thread.is_alive(),
                "request_retry_count": self._client.retry_count,
                "retained_sample_count": len(samples),
                "samples_truncated": 0,
                "schedule": "absolute_monotonic",
                "status": "failed",
            },
            "health_sample_count": len(samples),
            "health_samples": samples,
            "workload_window_seconds": round(
                window,
                6,
            ),
        }


class WorkloadMonitorError(RuntimeError):
    """Carry structured partial sampler evidence to the CLI failure writer."""

    def __init__(self, message: str, *, result: dict[str, Any]) -> None:
        self.result = result
        super().__init__(message)


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
            if exporter is None and isinstance(document.get("planned_unavailable"), dict):
                if node in recovery_by_node:
                    raise RuntimeError(
                        f"health sample recovered planned-unavailable {node}: {sample!r}"
                    )
                continue
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
                recovery = recovery_by_node.pop(node)
                recovery_elapsed = recovery.get("elapsed_seconds")
                if (
                    set(recovery)
                    != {
                        "elapsed_seconds",
                        "node",
                        "recovered_by_later_scheduled_sample",
                    }
                    or recovery.get("recovered_by_later_scheduled_sample") is not True
                    or node not in recorded_unresolved_error_nodes
                    or isinstance(recovery_elapsed, bool)
                    or not isinstance(recovery_elapsed, (int, float))
                    or not math.isfinite(float(recovery_elapsed))
                    or not math.isfinite(float(sample_elapsed))
                    or float(recovery_elapsed) != float(sample_elapsed)
                ):
                    raise RuntimeError(
                        f"health sample has invalid later-scheduled {node} audit recovery: "
                        f"{sample!r}"
                    )
                recorded_recovered_error_sample_count += 1
                recorded_unresolved_error_nodes.remove(node)
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
    *,
    failure_event: threading.Event,
    raise_monitor_error: Callable[[], None],
    started: float,
) -> dict[str, Any] | None:
    if not WORKLOAD_PAUSE.exists():
        return None
    request = _coordination_object(WORKLOAD_PAUSE)
    episode = request.get("episode")
    pause_id = request.get("pause_id")
    reason = request.get("reason")
    requested_monotonic = request.get("requested_monotonic_seconds")
    restart_id = request.get("restart_id")
    service = request.get("service")
    if (
        set(request)
        != {
            "episode",
            "pause_id",
            "reason",
            "requested_monotonic_seconds",
            "restart_id",
            "service",
        }
        or isinstance(episode, bool)
        or not isinstance(episode, int)
        or episode < 0
        or not isinstance(pause_id, str)
        or not pause_id
        or isinstance(requested_monotonic, bool)
        or not isinstance(requested_monotonic, (int, float))
        or not math.isfinite(float(requested_monotonic))
        or float(requested_monotonic) <= 0
        or reason not in {"partition", "planned_restart"}
        or (reason == "partition" and (restart_id is not None or service is not None))
        or (
            reason == "planned_restart"
            and (not isinstance(restart_id, str) or not restart_id or service not in NODES)
        )
    ):
        raise RuntimeError(f"invalid workload pause request: {request!r}")
    observed = time.monotonic()
    acknowledgement = {
        "episode": episode,
        "observed_monotonic_seconds": observed,
        "pause_id": pause_id,
        "paused": True,
        "reason": reason,
        "requested_monotonic_seconds": float(requested_monotonic),
        "restart_id": restart_id,
        "service": service,
    }
    _write_json_atomic(WORKLOAD_PAUSE_ACK, acknowledgement)
    while WORKLOAD_PAUSE.exists():
        raise_monitor_error()
        try:
            current = _coordination_object(WORKLOAD_PAUSE)
        except FileNotFoundError:
            break
        if current != request:
            raise RuntimeError(
                f"workload pause marker changed before resume: {request!r} -> {current!r}"
            )
        if failure_event.wait(0.05):
            raise_monitor_error()
    resumed = time.monotonic()
    return {
        "duration_seconds": round(resumed - observed, 6),
        "episode": episode,
        "observed_elapsed_seconds": round(observed - started, 6),
        "observed_monotonic_seconds": observed,
        "pause_id": pause_id,
        "reason": reason,
        "requested_monotonic_seconds": float(requested_monotonic),
        "restart_id": restart_id,
        "service": service,
        "resumed_elapsed_seconds": round(resumed - started, 6),
        "resumed_monotonic_seconds": resumed,
    }


def _workload_time_evidence(
    pause_intervals: list[dict[str, Any]],
    restart_quiescence_intervals: list[dict[str, Any]],
    *,
    started_monotonic: float,
    measurement_window_seconds: float,
) -> dict[str, Any]:
    measurement_end = started_monotonic + measurement_window_seconds
    paused_seconds = 0.0
    for intervals in (pause_intervals, restart_quiescence_intervals):
        for expected_episode, interval in enumerate(intervals):
            if interval.get("episode") != expected_episode:
                raise RuntimeError(f"invalid workload pause episode evidence: {intervals!r}")
    ordered_intervals = sorted(
        [*pause_intervals, *restart_quiescence_intervals],
        key=lambda interval: float(interval["observed_monotonic_seconds"]),
    )
    prior_end = started_monotonic
    for interval in ordered_intervals:
        observed = float(interval["observed_monotonic_seconds"])
        resumed = float(interval["resumed_monotonic_seconds"])
        if observed < prior_end or resumed < observed:
            raise RuntimeError(
                "invalid or overlapping workload pause evidence: "
                f"partition={pause_intervals!r} restart={restart_quiescence_intervals!r}"
            )
        clipped_start = max(started_monotonic, min(measurement_end, observed))
        clipped_end = max(clipped_start, min(measurement_end, resumed))
        clipped_duration = clipped_end - clipped_start
        interval["measurement_clipped_duration_seconds"] = round(clipped_duration, 6)
        interval["measurement_clipped_end_elapsed_seconds"] = round(
            clipped_end - started_monotonic,
            6,
        )
        interval["measurement_clipped_start_elapsed_seconds"] = round(
            clipped_start - started_monotonic,
            6,
        )
        paused_seconds += clipped_duration
        prior_end = resumed
    active_seconds = measurement_window_seconds - paused_seconds
    if active_seconds < 0:
        raise RuntimeError("workload pause evidence exceeds the measurement window")
    return {
        "active_workload_seconds": round(active_seconds, 6),
        "measurement_window_seconds": round(measurement_window_seconds, 6),
        "pause_interval_count": len(pause_intervals),
        "pause_intervals": pause_intervals,
        "paused_workload_seconds": round(paused_seconds, 6),
        "restart_quiescence_interval_count": len(restart_quiescence_intervals),
        "restart_quiescence_intervals": restart_quiescence_intervals,
    }


def run_workload(arguments: argparse.Namespace) -> dict[str, Any]:
    manifest = _verified_manifest()
    policy = manifest.policies[0]
    failure_event = threading.Event()
    client = ClusterClient(
        seed=arguments.seed,
        retry_timeout_s=arguments.retry_timeout_seconds,
        abort_event=failure_event,
    )
    executor: ExecutorBoundary | None = None
    counters = {
        "authorizations": 0,
        "closed": 0,
        "executor_failed_closed": 0,
        "executor_faulting_calls": 0,
        "issued_receipts": 0,
        "issued_roots": 0,
        "quiesced": 0,
        "renewed": 0,
        "resumed": 0,
        "transfers_prepared": 0,
    }
    transfer_pair_counts = {f"{source}->{target}": 0 for source, target in TRANSFER_PAIRS}
    latency = LatencyHistogram()
    pause_intervals: list[dict[str, Any]] = []
    restart_quiescence_intervals: list[dict[str, Any]] = []
    started = time.monotonic()
    run_id = str(arguments.run_id)
    if not run_id or len(run_id.encode("utf-8")) > 256:
        raise RuntimeError("workload run identity is invalid")
    _write_json_atomic(
        WORKLOAD_START,
        {
            "cycle_interval_seconds": arguments.cycle_interval_seconds,
            "duration_seconds": arguments.duration_seconds,
            "executor_reopen_every_cycles": arguments.executor_reopen_every_cycles,
            "health_interval_seconds": arguments.health_interval_seconds,
            "retry_timeout_seconds": arguments.retry_timeout_seconds,
            "run_id": run_id,
            "schema": "lets.production-profile-soak-workload-start/v1",
            "seed": arguments.seed,
            "started_monotonic_seconds": started,
            "transfer_every_cycles": arguments.transfer_every_cycles,
        },
    )
    deadline = started + arguments.duration_seconds
    cycle = 0
    journal_lock = threading.Lock()
    journal_revision = 0
    journal_last_cycle_publish = started
    journal_counters = dict(counters)
    journal_cycle = 0
    workload_configuration = {
        "cycle_interval_seconds": arguments.cycle_interval_seconds,
        "duration_seconds": arguments.duration_seconds,
        "executor_reopen_every_cycles": arguments.executor_reopen_every_cycles,
        "health_interval_seconds": arguments.health_interval_seconds,
        "retry_timeout_seconds": arguments.retry_timeout_seconds,
        "seed": arguments.seed,
        "transfer_every_cycles": arguments.transfer_every_cycles,
    }
    health_sampler: HealthSampler

    def current_executor() -> ExecutorBoundary:
        if executor is None:
            raise RuntimeError("executor boundary admission did not complete")
        return executor

    def executor_failure_snapshot(error: BaseException) -> dict[str, Any]:
        if executor is not None:
            return executor.failure_snapshot()
        admission_error: dict[str, Any] | None = None
        if isinstance(error, AuthorityAnchorTransportError):
            admission_error = {
                "helper_exit_code": error.helper_exit_code,
                "helper_pid": error.helper_pid,
                "mutation_uncertain": error.mutation_uncertain,
                "operation": error.operation,
                "reason": error.reason,
                "request_flushed": error.request_flushed,
            }
        lifecycle_failures = (
            []
            if admission_error is None
            else [
                {
                    "anchor_preserved": EXECUTOR_ANCHOR.exists(),
                    "database_preserved": EXECUTOR_DATABASE.exists(),
                    "error": admission_error,
                    "phase": "startup",
                }
            ]
        )
        return {
            "admission_error": admission_error,
            "authority_anchor": None,
            "claims": 0,
            "lifecycle_admission_failures": lifecycle_failures,
            "pending_transport_fault": None,
            "reopen_count": 0,
            "replay_rejections": 0,
            "terminal_statuses": [],
            "transport_recovery_events": [],
        }

    def publish_journal() -> None:
        """Atomically retain a compact, bounded monitor/cycle checkpoint."""

        nonlocal journal_revision
        with journal_lock:
            journal_revision += 1
            observed_at = time.monotonic()
            monitor = health_sampler.failure_snapshot(
                workload_ended_monotonic=observed_at,
            )
            health_samples = cast(list[dict[str, Any]], monitor["health_samples"])
            retained_health_samples = (
                health_samples
                if len(health_samples) <= 8
                else health_samples[:1] + health_samples[-7:]
            )
            health_monitor = dict(cast(dict[str, Any], monitor["health_monitor"]))
            if health_monitor.get("error") is None:
                health_monitor["status"] = "running"
                health_monitor["joined"] = False
            partial = {
                "configuration": workload_configuration,
                "counters": dict(journal_counters),
                "cycles": journal_cycle,
                "duration_seconds": round(max(0.0, observed_at - started), 6),
                "health_monitor": health_monitor,
                "health_sample_count": int(monitor["health_sample_count"]),
                "health_samples": retained_health_samples,
                "health_samples_retained": len(retained_health_samples),
                "health_samples_truncated": len(health_samples) - len(retained_health_samples),
                "journal_compact": True,
                "pause_interval_count": len(pause_intervals),
                "pause_intervals": list(pause_intervals),
                "restart_quiescence_interval_count": len(restart_quiescence_intervals),
                "restart_quiescence_intervals": list(restart_quiescence_intervals),
                "run_id": run_id,
                "schema": "lets.production-profile-soak-workload/v2",
                "started_monotonic_seconds": started,
                "status": "failed" if health_monitor.get("error") is not None else "running",
                "workload_window_seconds": monitor["workload_window_seconds"],
            }
            _write_json_atomic(
                WORKLOAD_JOURNAL,
                _seal_workload_artifact(
                    partial,
                    journal_revision=journal_revision,
                    maximum_bytes=WORKLOAD_JOURNAL_MAX_BYTES,
                ),
            )

    health_sampler = HealthSampler(
        started_monotonic=started,
        interval_seconds=arguments.health_interval_seconds,
        retry_timeout_seconds=arguments.retry_timeout_seconds,
        seed=arguments.seed + 1_000_000_000,
        failure_event=failure_event,
        on_sample=publish_journal,
    )
    publish_journal()

    def wait_for_pause_boundary() -> None:
        pause = _wait_if_paused(
            failure_event=failure_event,
            raise_monitor_error=health_sampler.raise_if_failed,
            started=started,
        )
        if pause is None:
            return
        if pause.get("reason") == "planned_restart":
            restart_quiescence_intervals.append(pause)
        elif pause.get("reason") == "partition":
            pause_intervals.append(pause)
        else:  # pragma: no cover - _wait_if_paused rejects this first.
            raise RuntimeError("workload pause reason was not retained")

    def request(*request_arguments: Any, **request_options: Any) -> dict[str, Any]:
        health_sampler.raise_if_failed()
        response = client.request(*request_arguments, **request_options)
        health_sampler.raise_if_failed()
        # A restart pause arriving during a long request is acknowledged at
        # the first post-response boundary, before another mutation can start.
        wait_for_pause_boundary()
        return response

    def recover_executor_transport() -> bool:
        boundary = current_executor()
        boundary.recover_pending_authority()
        health_sampler.raise_if_failed()
        try:
            return boundary.retry_pending_claim()
        except ReplayError:
            event = boundary.transport_recovery_events[-1]
            return event.get("protected_effect_executed_after_recovery") is True

    def execute_executor_claim_once(receipt: Receipt) -> bool:
        return current_executor().claim_once(receipt)

    try:
        executor = ExecutorBoundary(manifest)
        health_sampler.start()
        while time.monotonic() < deadline:
            health_sampler.raise_if_failed()
            wait_for_pause_boundary()
            if time.monotonic() >= deadline:
                break
            cycle_started = time.monotonic()
            plan = operation_plan(cycle)
            node = cast(str, plan["node"])
            prefix = f"soak-{arguments.seed}-{cycle:012d}"
            root = request(
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

            first = request(
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
            counters["issued_receipts"] += 1
            first_receipt = Receipt.from_dict(first)
            try:
                first_effect_executed = execute_executor_claim_once(first_receipt)
            except AuthorityAnchorTransportError:
                counters["executor_faulting_calls"] += 1
                first_effect_executed = recover_executor_transport()
            if first_effect_executed:
                counters["authorizations"] += 1
            else:
                counters["executor_failed_closed"] += 1
            health_sampler.raise_if_failed()

            request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/quiesce",
                body={"request_id": f"{prefix}-quiesce"},
            )
            counters["quiesced"] += 1
            request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/resume",
                body={"request_id": f"{prefix}-resume"},
            )
            counters["resumed"] += 1
            request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/renew",
                body={"request_id": f"{prefix}-renew", "ttl_ns": 300_000_000_000},
            )
            counters["renewed"] += 1

            second = request(
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
            counters["issued_receipts"] += 1
            second_receipt = Receipt.from_dict(second)
            try:
                second_effect_executed = execute_executor_claim_once(second_receipt)
            except AuthorityAnchorTransportError:
                counters["executor_faulting_calls"] += 1
                second_effect_executed = recover_executor_transport()
            if second_effect_executed:
                counters["authorizations"] += 1
            else:
                counters["executor_failed_closed"] += 1
            health_sampler.raise_if_failed()
            request(
                "POST",
                node,
                f"/v1/leases/{lease_id}/close",
                body={"request_id": f"{prefix}-close"},
            )
            counters["closed"] += 1

            transfer_pair = scheduled_transfer_pair(cycle, arguments.transfer_every_cycles)
            if transfer_pair is not None:
                transfer_source, transfer_target = transfer_pair
                request(
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
                try:
                    current_executor().reopen()
                except AuthorityAnchorTransportError:
                    counters["executor_faulting_calls"] += 1
                    if not current_executor().transport_recovery_pending:
                        raise
                    recover_executor_transport()
                health_sampler.raise_if_failed()
            latency.observe(time.monotonic() - cycle_started)
            with journal_lock:
                journal_counters = dict(counters)
                journal_cycle = cycle
            if time.monotonic() - journal_last_cycle_publish >= WORKLOAD_JOURNAL_CYCLE_SECONDS:
                publish_journal()
                journal_last_cycle_publish = time.monotonic()
            remaining = deadline - time.monotonic()
            if remaining > 0 and failure_event.wait(
                min(arguments.cycle_interval_seconds, remaining)
            ):
                health_sampler.raise_if_failed()

        workload_ended = time.monotonic()
        health_sampler.finish(workload_ended_monotonic=workload_ended)
        monitor_result = health_sampler.result(
            workload_ended_monotonic=workload_ended,
        )
        recorded_health_samples = cast(list[dict[str, Any]], monitor_result["samples"])
        if not recorded_health_samples:
            raise RuntimeError("independent health monitor retained no observations")
        final_health = recorded_health_samples[-1]
        conservation = _conservation_totals(final_health)
        audit_error_budget = cast(AuditErrorBudget, monitor_result["audit_error_budget"])
        time_evidence = _workload_time_evidence(
            pause_intervals,
            restart_quiescence_intervals,
            started_monotonic=started,
            measurement_window_seconds=arguments.duration_seconds,
        )
        boundary = current_executor()
        final_executor_status = boundary.capture_terminal_status()
        if len(boundary.terminal_statuses) != boundary.reopen_count + 1:
            raise RuntimeError("executor terminal lifetime evidence is incomplete")
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
            "duration_seconds": round(workload_ended - started, 6),
            "executor": {
                "claims": boundary.claims,
                "reopen_count": boundary.reopen_count,
                "replay_rejections": boundary.replay_rejections,
                "status": final_executor_status,
                "terminal_statuses": list(boundary.terminal_statuses),
                "transport_recovery_events": list(boundary.transport_recovery_events),
            },
            "health_monitor": monitor_result["health_monitor"],
            "health_sample_count": len(recorded_health_samples),
            "health_samples": recorded_health_samples,
            "latency": latency.to_dict(),
            "package_version": metadata.version("lets-agent"),
            "request_retry_count": client.retry_count,
            "run_id": run_id,
            "schema": "lets.production-profile-soak-workload/v2",
            "started_monotonic_seconds": started,
            "status": "passed",
            **time_evidence,
            "transfer_pair_counts": transfer_pair_counts,
        }
    except BaseException as error:
        monitor_error: BaseException | None = None
        cancel_error: BaseException | None = None
        try:
            health_sampler.cancel()
        except BaseException as exc:
            cancel_error = exc
        try:
            health_sampler.raise_if_failed()
        except BaseException as exc:
            monitor_error = exc
        if cancel_error is not None:
            error.add_note(f"secondary health-monitor cancellation error: {cancel_error}")
        if monitor_error is not None:
            monitor_induced = isinstance(error, RuntimeError) and (
                str(error).startswith("request aborted after the health monitor failed")
                or str(error).startswith("independent health monitor")
                or error is monitor_error
            )
            if monitor_induced:
                ended = time.monotonic()
                partial = {
                    "configuration": {
                        "cycle_interval_seconds": arguments.cycle_interval_seconds,
                        "duration_seconds": arguments.duration_seconds,
                        "executor_reopen_every_cycles": (arguments.executor_reopen_every_cycles),
                        "health_interval_seconds": arguments.health_interval_seconds,
                        "retry_timeout_seconds": arguments.retry_timeout_seconds,
                        "seed": arguments.seed,
                        "transfer_every_cycles": arguments.transfer_every_cycles,
                    },
                    "counters": counters,
                    "cycles": cycle,
                    "duration_seconds": round(ended - started, 6),
                    "error": {
                        "message": str(monitor_error),
                        "type": (
                            f"{type(monitor_error).__module__}.{type(monitor_error).__qualname__}"
                        ),
                    },
                    "pause_interval_count": len(pause_intervals),
                    "pause_intervals": pause_intervals,
                    "restart_quiescence_interval_count": len(restart_quiescence_intervals),
                    "restart_quiescence_intervals": restart_quiescence_intervals,
                    "executor": executor_failure_snapshot(error),
                    "schema": "lets.production-profile-soak-workload/v2",
                    "run_id": run_id,
                    "started_monotonic_seconds": started,
                    "status": "failed",
                    **health_sampler.failure_snapshot(
                        workload_ended_monotonic=ended,
                    ),
                }
                raise WorkloadMonitorError(str(monitor_error), result=partial) from error
            error.add_note(f"secondary health-monitor failure: {monitor_error}")
        ended = time.monotonic()
        partial = {
            "configuration": {
                "cycle_interval_seconds": arguments.cycle_interval_seconds,
                "duration_seconds": arguments.duration_seconds,
                "executor_reopen_every_cycles": arguments.executor_reopen_every_cycles,
                "health_interval_seconds": arguments.health_interval_seconds,
                "retry_timeout_seconds": arguments.retry_timeout_seconds,
                "seed": arguments.seed,
                "transfer_every_cycles": arguments.transfer_every_cycles,
            },
            "counters": counters,
            "cycles": cycle,
            "duration_seconds": round(ended - started, 6),
            "error": {
                "message": str(error)
                .encode("utf-8", errors="replace")[:512]
                .decode("utf-8", errors="ignore"),
                "type": f"{type(error).__module__}.{type(error).__qualname__}",
            },
            "executor": executor_failure_snapshot(error),
            "pause_interval_count": len(pause_intervals),
            "pause_intervals": pause_intervals,
            "restart_quiescence_interval_count": len(restart_quiescence_intervals),
            "restart_quiescence_intervals": restart_quiescence_intervals,
            "run_id": run_id,
            "schema": "lets.production-profile-soak-workload/v2",
            "started_monotonic_seconds": started,
            "status": "failed",
            **health_sampler.failure_snapshot(workload_ended_monotonic=ended),
        }
        try:
            publish_journal()
        except BaseException as journal_error:
            error.add_note(
                "secondary workload-journal publication error: "
                f"{type(journal_error).__name__}: {journal_error}"
            )
        raise WorkloadMonitorError(str(error), result=partial) from error
    finally:
        if executor is not None:
            executor.close(capture_terminal=False)


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
    converged = False
    while time.monotonic() < deadline:
        final_sample = _health_sample(
            client,
            elapsed_s=time.monotonic() - started,
            deadline=deadline,
        )
        if _is_converged(final_sample) and time.monotonic() <= deadline:
            converged = True
            break
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    if final_sample is None or not converged:
        raise RuntimeError(f"cluster did not settle for partition injection: {final_sample!r}")
    return {
        "converged": True,
        "convergence_seconds": round(time.monotonic() - started, 3),
        "final_health": final_sample,
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-soak-settle/v1",
        "status": "passed",
    }


def fence_authority_for_restart(arguments: argparse.Namespace) -> dict[str, Any]:
    """Fence one exact core lifetime for a host-coordinated planned SIGKILL."""

    _verified_manifest()
    if arguments.node not in NODES:
        raise RuntimeError("authority fence node is invalid")
    marker = _coordination_object(WORKLOAD_RESTART)
    acknowledgement = _coordination_object(WORKLOAD_RESTART_ACK)
    identity = (
        "armed_monotonic_seconds",
        "episode",
        "quiesce_pause_id",
        "restart_id",
        "service",
    )
    if (
        marker.get("state") != "armed"
        or any(acknowledgement.get(key) != marker.get(key) for key in identity)
        or marker.get("restart_id") != arguments.restart_id
        or marker.get("service") != arguments.node
        or type(acknowledgement.get("coordination_revision")) is not int
        or acknowledgement["coordination_revision"] <= 0
        or acknowledgement.get("coordination_payload_sha256")
        != _coordination_payload_sha256(acknowledgement)
        or acknowledgement.get("acknowledged_monotonic_seconds") is not None
        or isinstance(acknowledgement.get("quiesced_monotonic_seconds"), bool)
        or not isinstance(acknowledgement.get("quiesced_monotonic_seconds"), (int, float))
        or not math.isfinite(float(acknowledgement["quiesced_monotonic_seconds"]))
        or isinstance(acknowledgement.get("observed_monotonic_seconds"), bool)
        or not isinstance(acknowledgement.get("observed_monotonic_seconds"), (int, float))
        or not math.isfinite(float(acknowledgement["observed_monotonic_seconds"]))
        or not float(acknowledgement["quiesced_monotonic_seconds"])
        <= float(marker["armed_monotonic_seconds"])
        <= float(acknowledgement["observed_monotonic_seconds"])
    ):
        raise RuntimeError("planned restart fence preparation is not exact or quiesced")
    prior_authority = _bounded_authority_anchor_status(
        acknowledgement.get("prior_authority_anchor"),
        node=arguments.node,
        require_healthy=True,
    )
    prior_observation = acknowledgement.get("prior_observation")
    if (
        not isinstance(prior_observation, dict)
        or set(prior_observation)
        != {
            "audit_verification",
            "authority_checkpoint",
            "generation",
            "lifetime_id",
            "sqlite_schema_sha256",
        }
        or prior_observation.get("lifetime_id") != arguments.expected_lifetime_id
    ):
        raise RuntimeError("planned restart lacks its exact prior observation binding")
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    terminal = client.request(
        "POST",
        arguments.node,
        "/v1/maintenance/authority-fence",
        body={
            "expected_lifetime_id": arguments.expected_lifetime_id,
            "full_audit_verification": False,
            "restart_id": arguments.restart_id,
        },
        single_attempt=True,
    )
    terminal = _validated_terminal_fence(
        terminal,
        node=arguments.node,
        expected_lifetime_id=arguments.expected_lifetime_id,
        restart_id=arguments.restart_id,
        full_audit_verification=False,
        prior_authority=prior_authority,
        prior_observation=cast(dict[str, Any], prior_observation),
    )
    return {
        "node": arguments.node,
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-authority-fence/v1",
        "status": "passed",
        "terminal": terminal,
    }


def read_authority_status(arguments: argparse.Namespace) -> dict[str, Any]:
    """Read one exact no-transaction authority status for host restart binding."""

    _verified_manifest()
    if arguments.node not in NODES:
        raise RuntimeError("authority status node is invalid")
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    authority = _bounded_authority_anchor_status(
        client.request("GET", arguments.node, "/v1/maintenance/authority-status"),
        node=arguments.node,
        require_healthy=True,
    )
    return {
        "authority_anchor": authority,
        "node": arguments.node,
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-authority-status/v1",
        "status": "passed",
    }


def verify_final(arguments: argparse.Namespace) -> dict[str, Any]:
    _verified_manifest()
    workload_result = _evidence_object(
        WORKLOAD_RESULT,
        maximum_bytes=WORKLOAD_ARTIFACT_MAX_BYTES,
    )
    workload_executor = workload_result.get("executor")
    if not isinstance(workload_executor, dict):
        raise RuntimeError("workload result omitted executor lifetime evidence")
    workload_terminals = workload_executor.get("terminal_statuses")
    if not isinstance(workload_terminals, list) or not workload_terminals:
        raise RuntimeError("workload result omitted executor terminal lifetimes")
    workload_final = workload_executor.get("status")
    if not isinstance(workload_final, dict):
        raise RuntimeError("workload result omitted its final executor status")
    client = ClusterClient(seed=arguments.seed, retry_timeout_s=arguments.retry_timeout_seconds)
    started = time.monotonic()
    convergence_deadline = started + arguments.convergence_timeout_seconds
    final_sample: dict[str, Any] | None = None
    converged = False
    while time.monotonic() < convergence_deadline:
        final_sample = _health_sample(
            client,
            elapsed_s=time.monotonic() - started,
            deadline=convergence_deadline,
        )
        if _is_converged(final_sample) and time.monotonic() <= convergence_deadline:
            converged = True
            break
        time.sleep(min(0.5, max(0.0, convergence_deadline - time.monotonic())))
    if final_sample is None or not converged:
        raise RuntimeError(f"cluster did not converge before the soak deadline: {final_sample!r}")
    conservation = _validate_conservation(final_sample)
    capture_started = time.monotonic()
    capture_deadline = capture_started + 90.0
    core_terminal_fences: dict[str, dict[str, Any]] = {}
    core_full_audit_verifications: dict[str, dict[str, Any]] = {}
    executor_evidence: dict[str, Any] | None = None

    def remaining_capture_seconds() -> float:
        remaining = capture_deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("terminal authority capture exceeded its shared 90s deadline")
        return remaining

    try:
        anchor = ProcessFileExecutorAuthorityAnchor(
            EXECUTOR_ANCHOR,
            timeout_s=min(5.0, remaining_capture_seconds()),
        )
        try:
            try:
                store = SQLiteReceiptReplayStore(EXECUTOR_DATABASE, authority_anchor=anchor)
            except AuthorityAnchorTransportError as exc:
                executor_evidence = {
                    "admission_error": {
                        "helper_exit_code": exc.helper_exit_code,
                        "helper_pid": exc.helper_pid,
                        "mutation_uncertain": exc.mutation_uncertain,
                        "operation": exc.operation,
                        "reason": exc.reason,
                        "request_flushed": exc.request_flushed,
                    },
                    "anchor_preserved": EXECUTOR_ANCHOR.is_file(),
                    "database_preserved": EXECUTOR_DATABASE.is_file(),
                    "pending_transport_fault": None,
                    "phase": "final_verification_startup",
                }
                raise
            remaining_capture_seconds()
            status = store.status()
            integrity = store.integrity_check()
            remaining_capture_seconds()
            checkpoint = status.authority_checkpoint
            executor_authority = store.authority_status()
        finally:
            anchor.close()
        if (
            not status.rollback_protected
            or not status.authority_healthy
            or integrity != ("ok",)
            or checkpoint is None
            or checkpoint.claim_sequence != status.claim_sequence
            or workload_final.get("claim_sequence") != status.claim_sequence
            or executor_authority.get("lifetime_id")
            in {
                terminal.get("lifetime_id")
                for terminal in workload_terminals
                if isinstance(terminal, dict)
            }
        ):
            raise RuntimeError("final executor replay authority verification failed")
        executor_terminal_status = {
            "anchor": checkpoint.to_dict(),
            "authority_anchor": executor_authority,
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
        executor_evidence = {
            "anchor_claim_sequence": checkpoint.claim_sequence,
            "authority_anchor": executor_authority,
            "authority_healthy": status.authority_healthy,
            "claim_sequence": status.claim_sequence,
            "database_bytes": status.database_bytes,
            "integrity": list(integrity),
            "rollback_protected": status.rollback_protected,
            "terminal_status": {
                "lifetime_id": executor_authority["lifetime_id"],
                "ordinal": len(workload_terminals),
                "source": "final_verification",
                "status": executor_terminal_status,
            },
            "wal_bytes": status.wal_bytes,
        }

        def fence_core(node: str) -> tuple[dict[str, Any], int]:
            final_node = final_sample["nodes"][node]
            prior_authority = _bounded_authority_anchor_status(
                final_node.get("authority_anchor"),
                node=node,
                require_healthy=True,
            )
            fence_id = f"final-verification-{arguments.seed}-{node}"
            remaining = remaining_capture_seconds()
            fence_client = ClusterClient(
                seed=arguments.seed + 3_000_000_000 + NODES.index(node),
                retry_timeout_s=arguments.retry_timeout_seconds,
            )
            terminal = fence_client.request(
                "POST",
                node,
                "/v1/maintenance/authority-fence",
                body={
                    "expected_lifetime_id": prior_authority["lifetime_id"],
                    "full_audit_verification": True,
                    "restart_id": fence_id,
                },
                retry_timeout_s=remaining,
                deadline_monotonic=capture_deadline,
            )
            remaining_capture_seconds()
            terminal = _validated_terminal_fence(
                terminal,
                node=node,
                expected_lifetime_id=cast(str, prior_authority["lifetime_id"]),
                restart_id=fence_id,
                full_audit_verification=True,
                prior_authority=prior_authority,
                prior_observation=cast(dict[str, Any], final_node["observation_snapshot"]),
            )
            return terminal, fence_client.retry_count

        with ThreadPoolExecutor(max_workers=len(NODES)) as fence_pool:
            fence_futures = {node: fence_pool.submit(fence_core, node) for node in NODES}
            for node in NODES:
                terminal, fence_retries = fence_futures[node].result(
                    timeout=remaining_capture_seconds()
                )
                core_terminal_fences[node] = terminal
                core_full_audit_verifications[node] = dict(
                    cast(dict[str, Any], terminal["terminal_audit_proof"])
                )
                client.retry_count += fence_retries
        capture_completed = time.monotonic()
        remaining_capture_seconds()
    except BaseException as exc:
        capture_completed = time.monotonic()
        partial = {
            "conservation": conservation,
            "converged": True,
            "executor": executor_evidence,
            "final_health": final_sample,
            "full_audit_verifications": core_full_audit_verifications,
            "package_version": metadata.version("lets-agent"),
            "request_retry_count": client.retry_count,
            "schema": "lets.production-profile-soak-verification/v1",
            "status": "failed",
            "terminal_authority_fences": core_terminal_fences,
            "terminal_capture": {
                "completed_monotonic_seconds": capture_completed,
                "deadline_monotonic_seconds": capture_deadline,
                "error": {
                    "message": str(exc)
                    .encode("utf-8", errors="replace")[:512]
                    .decode("utf-8", errors="ignore"),
                    "type": f"{type(exc).__module__}.{type(exc).__qualname__}",
                },
                "started_monotonic_seconds": capture_started,
            },
        }
        raise WorkloadMonitorError("terminal authority capture failed", result=partial) from exc
    return {
        "conservation": conservation,
        "converged": True,
        "convergence_seconds": round(capture_started - started, 3),
        "executor": executor_evidence,
        "final_health": final_sample,
        "full_audit_verifications": core_full_audit_verifications,
        "terminal_authority_fences": core_terminal_fences,
        "terminal_capture": {
            "completed_monotonic_seconds": capture_completed,
            "deadline_monotonic_seconds": capture_deadline,
            "started_monotonic_seconds": capture_started,
        },
        "package_version": metadata.version("lets-agent"),
        "request_retry_count": client.retry_count,
        "schema": "lets.production-profile-soak-verification/v1",
        "status": "passed",
    }


def _positive(value: str) -> float:
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
    subcommands = parser.add_subparsers(dest="command", required=True)
    workload = subcommands.add_parser("run")
    workload.add_argument("--duration-seconds", type=_positive, required=True)
    workload.add_argument("--cycle-interval-seconds", type=_positive, default=0.5)
    workload.add_argument("--health-interval-seconds", type=_positive, default=10.0)
    workload.add_argument("--retry-timeout-seconds", type=_positive, default=90.0)
    workload.add_argument("--transfer-every-cycles", type=_positive_int, default=3)
    workload.add_argument("--executor-reopen-every-cycles", type=_positive_int, default=10)
    workload.add_argument("--seed", type=int, default=20260809)
    workload.add_argument("--run-id", default="standalone-production-soak")
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
    fence = subcommands.add_parser("fence-authority")
    fence.add_argument("--node", choices=NODES, required=True)
    fence.add_argument("--restart-id", required=True)
    fence.add_argument("--expected-lifetime-id", required=True)
    fence.add_argument("--retry-timeout-seconds", type=_positive, default=28.0)
    fence.add_argument("--seed", type=int, default=20260809)
    fence.add_argument("--output", type=Path, required=True)
    authority_status = subcommands.add_parser("authority-status")
    authority_status.add_argument("--node", choices=NODES, required=True)
    authority_status.add_argument("--retry-timeout-seconds", type=_positive, default=7.0)
    authority_status.add_argument("--seed", type=int, default=20260809)
    authority_status.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    workload_error: WorkloadMonitorError | None = None
    try:
        if arguments.command == "run":
            result = run_workload(arguments)
        elif arguments.command == "partition-probe":
            result = run_partition_probe(arguments)
        elif arguments.command == "settle":
            result = wait_converged(arguments)
        elif arguments.command == "fence-authority":
            result = fence_authority_for_restart(arguments)
        elif arguments.command == "authority-status":
            result = read_authority_status(arguments)
        else:
            result = verify_final(arguments)
    except WorkloadMonitorError as exc:
        result = exc.result
        workload_error = exc
    if arguments.command == "run":
        journal_revision = 1
        if WORKLOAD_JOURNAL.exists():
            try:
                existing = _evidence_object(
                    WORKLOAD_JOURNAL,
                    maximum_bytes=WORKLOAD_JOURNAL_MAX_BYTES,
                )
                existing_revision = existing.get("journal_revision")
                if type(existing_revision) is int and existing_revision > 0:
                    journal_revision = existing_revision + 1
            except BaseException as exc:
                if workload_error is not None:
                    workload_error.add_note(
                        f"secondary workload-journal read error: {type(exc).__name__}: {exc}"
                    )
        result = _seal_workload_artifact(
            result,
            journal_revision=journal_revision,
        )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json_atomic(arguments.output, result)
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
    if workload_error is not None:
        raise workload_error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
