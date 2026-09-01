"""Replacement matched-path benchmark for AstralDeep final dispatch.

This runner is deliberately *not* presented as a reproduction of the missing
``20260826T231656Z`` host-control artifact.  It measures the same narrow class
of operation against the current clean AstralDeep reference composition:

* AstralDeep ``04f04ee93718d2ff681726e2a47a2550a837612d``;
* AstralPlane ``4a1d990387428436041dd70d9c417e9e86000b6c``; and
* LETS v1.0.11 ``6245189920c686353c4ced7a208d56ec266f745c``.

The timed enforce path uses the real ``GovernedFinalDispatch`` and gateway
classes, a real SQLite-backed ``WardenService``, the public receipt verifier,
the real SQLite replay store, and the process-file executor authority anchor.
Host binding, Plane effect coordination, and audit persistence are isolated
in-memory adapters, matching the scope of the historical paper description.
No HTTP, PostgreSQL, model/provider, or external-tool work is included.

All timing hooks are wrappers or subclasses owned by this benchmark.  The
runner does not patch AstralDeep or LETS runtime source files.
"""

from __future__ import annotations

import argparse
import asyncio
import contextvars
import csv
import hashlib
import importlib
import importlib.metadata
import io
import json
import math
import os
import platform
import shutil
import sqlite3
import statistics
import subprocess
import sys
import time
from collections import defaultdict
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any, Literal

RESULT_SCHEMA = "lets.nsdi-matched-host-path/v1"
SAMPLE_SCHEMA = "lets.nsdi-matched-host-path-sample/v1"
OUTPUT_JSON = "matched-host-path.json"
OUTPUT_CSV = "matched-host-path-samples.csv"
OUTPUT_MARKDOWN = "matched-host-path.md"

EXPECTED_ASTRALDEEP_COMMIT = "04f04ee93718d2ff681726e2a47a2550a837612d"
EXPECTED_COMPONENTS = {
    "astral-plane": "4a1d990387428436041dd70d9c417e9e86000b6c",
    "lets": "6245189920c686353c4ced7a208d56ec266f745c",
}
EXPECTED_LETS_REF = "v1.0.11"
BENCHMARK_CLOCK_NS = 1_000_000_000_000_000
AUTHORITY_HELPER_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.dont_write_bytecode=True;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "runpy.run_module('lets.authority_helper',run_name='__main__')"
)
TENANT_ID = "nsdi-host-path"
ENVELOPE_ID = "matched-dispatch"
WARDEN_ID = "warden-matched-path"
EXECUTOR_AUDIENCE = "executor-matched-path"
OWNER_ID = "owner-matched-path"
AGENT_ID = "agent-matched-path"
RUNTIME_ID = "runtime-matched-path"
TOOL_ID = "benchmark.counter"
SCOPE = "tools:execute"
Mode = Literal["off", "enforce"]


class BenchmarkRefusal(RuntimeError):  # noqa: N818 - refusal is the CLI contract term
    """A prerequisite or evidence-integrity check failed."""


@dataclass(frozen=True, slots=True)
class Configuration:
    trials: int = 10
    operations: int = 1_000
    warmups: int = 100


@dataclass(slots=True)
class _Trace:
    values: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    def add(self, label: str, duration_ns: int) -> None:
        self.values[label] += max(0, int(duration_ns))
        self.counts[label] += 1


_ACTIVE_TRACE: contextvars.ContextVar[_Trace | None] = contextvars.ContextVar(
    "lets_matched_host_path_trace", default=None
)
_ACTIVE_ANCHOR_LABEL: contextvars.ContextVar[str] = contextvars.ContextVar(
    "lets_matched_host_path_anchor_label", default="rollback_anchor_other_ns"
)


@contextmanager
def _span(label: str) -> Iterator[None]:
    trace = _ACTIVE_TRACE.get()
    if trace is None:
        yield
        return
    started = time.perf_counter_ns()
    try:
        yield
    finally:
        trace.add(label, time.perf_counter_ns() - started)


def _timed(label: str, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    with _span(label):
        return function(*args, **kwargs)


def _command(arguments: Sequence[str], *, cwd: Path) -> str:
    try:
        completed = subprocess.run(
            list(arguments),
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise BenchmarkRefusal(f"command failed: {' '.join(arguments)}") from exc
    return completed.stdout.strip()


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise BenchmarkRefusal(f"could not hash required file: {path.name}") from exc


def _git_identity(root: Path) -> dict[str, object]:
    status = _command(
        ("git", "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"),
        cwd=root,
    )
    return {
        "revision": _command(("git", "rev-parse", "HEAD"), cwd=root),
        "tree": _command(("git", "rev-parse", "HEAD^{tree}"), cwd=root),
        "describe": _command(("git", "describe", "--tags", "--always", "--dirty"), cwd=root),
        "dirty": bool(status),
        "status_sha256": hashlib.sha256(status.encode("utf-8")).hexdigest(),
    }


def _harness_repository_identity(source: Path | None = None) -> dict[str, object]:
    """Describe the harness checkout without requiring a standalone upload to be Git-backed."""

    selected = Path(__file__).resolve() if source is None else source.resolve(strict=True)
    try:
        candidate = selected.parents[2]
        top_level = Path(_command(("git", "rev-parse", "--show-toplevel"), cwd=candidate)).resolve(
            strict=True
        )
        if top_level != candidate.resolve(strict=True):
            raise BenchmarkRefusal("harness source is not rooted at its expected repository")
        identity = _git_identity(candidate)
    except (BenchmarkRefusal, IndexError, OSError):
        return {
            "available": False,
            "reason": "standalone-source-upload",
            "benchmark_sha256": _sha256_file(selected),
        }
    return {"available": True, **identity}


def _canonical_interpreter(root: Path) -> Path:
    relative = Path(".venv/Scripts/python.exe") if os.name == "nt" else Path(".venv/bin/python")
    try:
        executable = (root / relative).resolve(strict=True)
    except OSError as exc:
        raise BenchmarkRefusal("AstralDeep canonical .venv interpreter is unavailable") from exc
    if executable != Path(sys.executable).resolve():
        raise BenchmarkRefusal(
            "run this benchmark with the clean AstralDeep worktree's canonical .venv interpreter"
        )
    return executable


def _validate_composition_document(document: object) -> dict[str, object]:
    if not isinstance(document, dict):
        raise BenchmarkRefusal("AstralDeep composition is not a JSON object")
    components = document.get("components")
    if not isinstance(components, dict):
        raise BenchmarkRefusal("AstralDeep composition has no component map")
    for component, expected in EXPECTED_COMPONENTS.items():
        value = components.get(component)
        if not isinstance(value, dict) or value.get("commit") != expected:
            raise BenchmarkRefusal(f"AstralDeep {component} pin is not the replacement target")
    lets_value = components["lets"]
    assert isinstance(lets_value, dict)
    if lets_value.get("ref") != EXPECTED_LETS_REF:
        raise BenchmarkRefusal("AstralDeep LETS release ref is not v1.0.11")
    return document


def validate_astraldeep_root(root: Path) -> dict[str, object]:
    """Require the exact clean, initialized replacement composition."""

    try:
        selected = root.resolve(strict=True)
    except OSError as exc:
        raise BenchmarkRefusal("AstralDeep root does not exist") from exc
    identity = _git_identity(selected)
    if identity["revision"] != EXPECTED_ASTRALDEEP_COMMIT:
        raise BenchmarkRefusal("AstralDeep revision is not the replacement target")
    if identity["dirty"]:
        raise BenchmarkRefusal("AstralDeep replacement worktree is dirty")
    composition_path = selected / "config/astral-composition.json"
    try:
        composition_bytes = composition_path.read_bytes()
        composition = _validate_composition_document(json.loads(composition_bytes))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BenchmarkRefusal("AstralDeep composition could not be read exactly") from exc

    component_roots = {
        "astral-plane": selected / "components/AstralPlane",
        "lets": selected / "components/LETS",
    }
    component_identities: dict[str, object] = {}
    for component, component_root in component_roots.items():
        required_source = (
            component_root / "src/astralplane/__init__.py"
            if component == "astral-plane"
            else component_root / "src/lets/__init__.py"
        )
        if not required_source.is_file():
            raise BenchmarkRefusal(f"AstralDeep {component} submodule is not initialized")
        observed = _git_identity(component_root)
        if observed["revision"] != EXPECTED_COMPONENTS[component] or observed["dirty"]:
            raise BenchmarkRefusal(f"AstralDeep {component} checkout is not exact and clean")
        component_identities[component] = observed

    executable = _canonical_interpreter(selected)
    return {
        "astraldeep_root": selected,
        "astraldeep": identity,
        "components": component_identities,
        "composition": composition,
        "composition_sha256": hashlib.sha256(composition_bytes).hexdigest(),
        "interpreter_sha256": _sha256_file(executable),
    }


def _bootstrap_runtime(root: Path) -> SimpleNamespace:
    """Import only the exact Deep and component trees selected above."""

    source_roots = (
        root / "backend",
        root / "components/LETS/src",
        root / "components/AstralPlane/src",
    )
    for source_root in reversed(source_roots):
        sys.path.insert(0, str(source_root))

    lets_package = importlib.import_module("lets")
    plane_package = importlib.import_module("astralplane")
    expected_origins = {
        "lets": source_roots[1],
        "astralplane": source_roots[2],
    }
    for name, package in (("lets", lets_package), ("astralplane", plane_package)):
        try:
            origin = Path(package.__file__).resolve(strict=True)
            origin.relative_to(expected_origins[name].resolve(strict=True))
        except (AttributeError, OSError, ValueError) as exc:
            raise BenchmarkRefusal(
                f"{name} was not imported from the exact Deep component"
            ) from exc

    modules = {
        "authority": importlib.import_module("lets.authority"),
        "clock": importlib.import_module("lets.clock"),
        "crypto": importlib.import_module("lets.crypto"),
        "executor": importlib.import_module("lets.executor"),
        "executor_authority": importlib.import_module("lets.executor_authority"),
        "integrations": importlib.import_module("lets.integrations"),
        "models": importlib.import_module("lets.models"),
        "policy": importlib.import_module("lets.policy"),
        "service": importlib.import_module("lets.service"),
        "storage": importlib.import_module("lets.storage"),
        "governed_dispatch": importlib.import_module("orchestrator.governed_dispatch"),
        "lets_client": importlib.import_module("orchestrator.lets_client"),
        "lets_config": importlib.import_module("orchestrator.lets_config"),
        "lets_gateway": importlib.import_module("orchestrator.lets_gateway"),
        "scope_profile": importlib.import_module("orchestrator.lets_scope_profile"),
        "audit_recorder": importlib.import_module("audit.recorder"),
    }
    return SimpleNamespace(**modules, lets_package=lets_package, plane_package=plane_package)


def _authority_helper_command(runtime: SimpleNamespace) -> tuple[str, ...]:
    """Launch the helper from the exact source tree even when LETS is not installed."""

    try:
        package_file = Path(runtime.lets_package.__file__).resolve(strict=True)
        source_root = package_file.parents[1]
        package_file.relative_to(source_root)
    except (AttributeError, IndexError, OSError, ValueError) as exc:
        raise BenchmarkRefusal("exact LETS helper source is unavailable") from exc
    return (
        sys.executable,
        "-I",
        "-c",
        AUTHORITY_HELPER_BOOTSTRAP,
        str(source_root),
        "--format",
        "executor",
    )


class _TimedTransaction:
    def __init__(self, inner: Any, label: str) -> None:
        self._inner = inner
        self._label = label
        self._started = 0

    def __enter__(self) -> Any:
        self._started = time.perf_counter_ns()
        try:
            return self._inner.__enter__()
        except BaseException:
            trace = _ACTIVE_TRACE.get()
            if trace is not None:
                trace.add(self._label, time.perf_counter_ns() - self._started)
            raise

    def __exit__(self, *exc: object) -> object:
        try:
            return self._inner.__exit__(*exc)
        finally:
            trace = _ACTIVE_TRACE.get()
            if trace is not None:
                trace.add(self._label, time.perf_counter_ns() - self._started)


class _TimedWardenStorage:
    def __init__(self, inner: Any) -> None:
        self._inner = inner

    @property
    def metadata(self) -> Any:
        return self._inner.metadata

    def write(self) -> _TimedTransaction:
        return _TimedTransaction(self._inner.write(), "warden_transaction_ns")

    def capacity_recovery(self) -> _TimedTransaction:
        return _TimedTransaction(self._inner.capacity_recovery(), "warden_transaction_ns")

    def read(self) -> Any:
        return self._inner.read()

    def close(self) -> None:
        self._inner.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _ServiceClient:
    """Protocol-neutral in-process transport into the real WardenService."""

    def __init__(self, service: Any, identity: Any) -> None:
        self._service = service
        self._identity = identity
        self.authorization_calls = 0

    def authorize(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        self.authorization_calls += 1
        receipt = self._service.authorize(
            request_id=payload["request_id"],
            identity=self._identity,
            lease_id=lease_id,
            transition=payload["transition"],
            audience=payload["executor_audience"],
            nonce=payload["nonce"],
            evidence=payload.get("evidence"),
            expected_state=payload.get("expected_state"),
            expected_sequence=payload.get("expected_sequence"),
        )
        return receipt.to_dict()

    def close(self) -> None:
        return None


class _TimedWardenClient:
    """Time the complete production-shaped Astral-to-Warden adapter call."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def authorize_tool(self, *args: Any, **kwargs: Any) -> Any:
        return _timed("warden_request_inclusive_ns", self._inner.authorize_tool, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class _AuditSink:
    def __init__(self) -> None:
        self.count = 0

    async def record(self, _event: object) -> None:
        with _span("audit_ns"):
            self.count += 1


class _Coordinator:
    """Deterministic in-memory Plane coordinator used only by this benchmark."""

    def __init__(self, binding: object) -> None:
        self.binding = binding
        self.counts: dict[str, int] = defaultdict(int)

    def prepare_authorization(self, **_values: object) -> None:
        with _span("coordinator_prepare_ns"):
            self.counts["prepare"] += 1

    def record_receipt(self, **_values: object) -> None:
        with _span("coordinator_receipt_ns"):
            self.counts["receipt"] += 1

    def claim_for_execution(self, *, envelope: object, **_values: object) -> None:
        with _span("coordinator_claim_ns"):
            receipt = envelope.receipt  # type: ignore[attr-defined]
            self.binding.lease_sequence = receipt.resulting_sequence
            self.counts["claim"] += 1

    def record_outcome(self, **_values: object) -> None:
        with _span("coordinator_outcome_ns"):
            self.counts["outcome"] += 1

    def fail_before_execution(self, **_values: object) -> None:
        with _span("coordinator_failure_ns"):
            self.counts["failure"] += 1


class _Plane:
    @contextmanager
    def transaction(self, **_values: object) -> Iterator[object]:
        with _span("host_plane_transaction_ns"):
            yield object()


class _BindingRepository:
    def __init__(self, binding: object) -> None:
        self.binding = binding

    def get_active_binding(self, _transaction: object, **_values: object) -> object:
        with _span("host_binding_lookup_ns"):
            return self.binding


@dataclass(slots=True)
class _Rig:
    dispatch: Any
    executor: Any
    binding: Any
    warden_service: Any
    audit_identity: Any
    warden_storage: Any
    replay_store: Any
    executor_anchor: Any
    service_client: _ServiceClient
    coordinator: _Coordinator
    audit_sink: _AuditSink
    audit_module: Any
    original_get_recorder: Any
    original_context_builder: Any
    governed_dispatch_module: Any
    capability_name: str
    effect_count: int = 0

    def close(self) -> None:
        self.audit_module.get_recorder = self.original_get_recorder
        self.governed_dispatch_module.build_protected_dispatch_context = (
            self.original_context_builder
        )
        self.warden_storage.close()
        close = getattr(self.executor_anchor, "close", None)
        if callable(close):
            close()


def _instrumented_runtime_classes(runtime: SimpleNamespace) -> SimpleNamespace:
    service_base = runtime.service.WardenService
    replay_base = runtime.executor.SQLiteReceiptReplayStore
    verifier_base = runtime.executor.ReceiptVerifier
    anchor_base = runtime.executor_authority.ProcessFileExecutorAuthorityAnchor
    auth_gateway_base = runtime.lets_gateway.LetsAuthorizationGateway
    executor_gateway_base = runtime.lets_gateway.ReceiptExecutorGateway

    class TimedWardenService(service_base):
        def _sign_record(self, record: object) -> object:
            return _timed("warden_signing_serialization_ns", super()._sign_record, record)

    class TimedReplayStore(replay_base):
        @contextmanager
        def _write(self) -> Iterator[Any]:
            token = _ACTIVE_ANCHOR_LABEL.set("rollback_anchor_claim_ns")
            try:
                with _span("replay_transaction_ns"), super()._write() as connection:
                    yield connection
            finally:
                _ACTIVE_ANCHOR_LABEL.reset(token)

        def claim(self, *args: Any, **kwargs: Any) -> None:
            return _timed("replay_claim_ns", super().claim, *args, **kwargs)

        def status(self, *args: Any, **kwargs: Any) -> Any:
            token = _ACTIVE_ANCHOR_LABEL.set("rollback_anchor_status_ns")
            try:
                return _timed(
                    "executor_replay_status_inclusive_ns",
                    super().status,
                    *args,
                    **kwargs,
                )
            finally:
                _ACTIVE_ANCHOR_LABEL.reset(token)

    class TimedVerifier(verifier_base):
        def _verify_at(self, *args: Any, **kwargs: Any) -> None:
            return _timed("executor_verify_ns", super()._verify_at, *args, **kwargs)

        def verify_and_claim(self, *args: Any, **kwargs: Any) -> None:
            return _timed(
                "executor_verifier_inclusive_ns", super().verify_and_claim, *args, **kwargs
            )

    class TimedAnchor(anchor_base):
        def reconcile(self, *args: Any, **kwargs: Any) -> None:
            return _timed(_ACTIVE_ANCHOR_LABEL.get(), super().reconcile, *args, **kwargs)

        def reconcile_and_confirm(self, *args: Any, **kwargs: Any) -> None:
            return _timed(
                _ACTIVE_ANCHOR_LABEL.get(),
                super().reconcile_and_confirm,
                *args,
                **kwargs,
            )

        def confirm(self, *args: Any, **kwargs: Any) -> None:
            return _timed(_ACTIVE_ANCHOR_LABEL.get(), super().confirm, *args, **kwargs)

    class TimedAuthorizationGateway(auth_gateway_base):
        @staticmethod
        def _validate_binding(*args: Any, **kwargs: Any) -> None:
            return _timed(
                "host_binding_policy_ns", auth_gateway_base._validate_binding, *args, **kwargs
            )

        @staticmethod
        def _validate_receipt(*args: Any, **kwargs: Any) -> None:
            return _timed(
                "host_receipt_validation_ns",
                auth_gateway_base._validate_receipt,
                *args,
                **kwargs,
            )

        async def authorize(self, *args: Any, **kwargs: Any) -> Any:
            with _span("host_gateway_inclusive_ns"):
                return await super().authorize(*args, **kwargs)

    class TimedExecutorGateway(executor_gateway_base):
        def verify_and_claim(self, *args: Any, **kwargs: Any) -> Any:
            return _timed(
                "executor_gateway_inclusive_ns", super().verify_and_claim, *args, **kwargs
            )

        def claim_and_invoke(self, *args: Any, **kwargs: Any) -> Any:
            return _timed(
                "executor_claim_invoke_inclusive_ns",
                super().claim_and_invoke,
                *args,
                **kwargs,
            )

    return SimpleNamespace(
        WardenService=TimedWardenService,
        ReplayStore=TimedReplayStore,
        Verifier=TimedVerifier,
        Anchor=TimedAnchor,
        AuthorizationGateway=TimedAuthorizationGateway,
        ExecutorGateway=TimedExecutorGateway,
    )


def _policy(runtime: SimpleNamespace) -> Any:
    bindings = runtime.scope_profile.SCOPE_BINDINGS
    return runtime.policy.PolicySpec(
        policy_id="nsdi-matched-host-policy",
        policy_version="v1",
        dimensions=tuple(
            runtime.policy.ResourceDimension(f"scope_{index}", "count")
            for index in range(runtime.scope_profile.RESOURCE_DIMENSIONS)
        ),
        machine=runtime.policy.MachineSpec(
            machine_id="nsdi-matched-host-machine",
            initial_state="ready",
            transitions=tuple(
                runtime.policy.TransitionSpec(
                    binding.transition,
                    "ready",
                    "ready",
                    binding.unit_cost(),
                    binding.capability,
                )
                for binding in bindings
            ),
        ),
        max_lease_ttl_ns=1_000_000_000_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )


def _build_rig(runtime: SimpleNamespace, root: Path, *, budget: int, mode: Mode) -> _Rig:
    classes = _instrumented_runtime_classes(runtime)
    policy = _policy(runtime)
    clock = runtime.clock.ManualClock(BENCHMARK_CLOCK_NS)
    signer = runtime.crypto.Ed25519Signer.generate(WARDEN_ID)
    registry = runtime.crypto.PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    allocation = (0, 0, 0, 0, 0, budget)

    warden_root = root / "warden"
    executor_root = root / "executor"
    authority_root = root / "executor-authority"
    for directory in (warden_root, executor_root, authority_root):
        directory.mkdir()
    raw_storage = runtime.storage.SQLiteStorage.initialize(
        warden_root / "warden.sqlite3",
        signer.warden_id,
        allocation,
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        initial_local_share=allocation,
        receipt_ttl_ns=policy.receipt_ttl_ns,
        transfer_gap_window=policy.transfer_gap_window,
    )
    storage = _TimedWardenStorage(raw_storage)
    service = classes.WardenService(storage, signer=signer, clock=clock, trust_registry=registry)
    service.register_policy(policy)
    identity = runtime.models.IdentityContext(AGENT_ID, TENANT_ID, frozenset({"lets.lease.issue"}))
    grant = service.issue_root(
        request_id="matched-host-root",
        identity=identity,
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        subject_id=AGENT_ID,
        allocation=allocation,
        capabilities={binding.capability for binding in runtime.scope_profile.SCOPE_BINDINGS},
        policy_digest=policy.digest,
        ttl_ns=1_000_000_000_000_000,
    )

    public_client = _ServiceClient(service, identity)
    profile = runtime.integrations.ReplicaProfile(
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        policy_digest=policy.digest,
        default_allocation=allocation,
        default_capabilities=frozenset(
            binding.capability for binding in runtime.scope_profile.SCOPE_BINDINGS
        ),
        default_ttl_ns=1_000_000_000_000_000,
    )
    replica = runtime.integrations.ReplicaAuthorizer(public_client, profile)
    astral = runtime.integrations.AstralDeepAuthorizer(
        replica,
        runtime.integrations.AstralDeepProfile(
            scope_capabilities={
                binding.scope: binding.capability
                for binding in runtime.scope_profile.SCOPE_BINDINGS
            },
            scope_transitions={
                binding.scope: binding.transition
                for binding in runtime.scope_profile.SCOPE_BINDINGS
            },
        ),
    )
    typed_client = runtime.lets_client.LetsWardenClient(
        client=public_client,
        replica_authorizer=replica,
        astral_authorizer=astral,
        identity=runtime.lets_client.LetsClientIdentity(
            tenant_id=TENANT_ID,
            envelope_id=ENVELOPE_ID,
            warden_id=signer.warden_id,
            policy_digest=policy.digest,
            machine_digest=policy.machine.digest,
            config_epoch=1,
        ),
        default_allocation=allocation,
        default_ttl_ns=1_000_000_000_000_000,
    )

    executor_policy = runtime.executor.ExecutorPolicy(
        audience=EXECUTOR_AUDIENCE,
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        config_epoch=1,
        allowed_policy_digests=frozenset({policy.digest}),
        allowed_machine_digests=frozenset({policy.machine.digest}),
        trusted_wardens=frozenset({signer.warden_id}),
        max_clock_uncertainty_ns=0,
    )
    anchor = classes.Anchor(
        authority_root / "executor.anchor",
        helper_command=_authority_helper_command(runtime),
    )
    replay = classes.ReplayStore.initialize(
        executor_root / "executor.sqlite3",
        authority_anchor=anchor,
        identity=runtime.executor.executor_replay_identity(executor_policy, registry),
    )
    verifier = classes.Verifier(registry, replay, executor_policy, clock=clock)

    binding = SimpleNamespace(
        binding_id="binding-matched-path",
        owner_id=OWNER_ID,
        agent_id=AGENT_ID,
        runtime_id=RUNTIME_ID,
        runtime_generation=1,
        population="server_dynamic",
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        warden_id=signer.warden_id,
        lease_id=grant.lease_id,
        lineage_id=grant.lineage_id,
        subject_id=AGENT_ID,
        policy_digest=policy.digest,
        machine_digest=policy.machine.digest,
        config_epoch=1,
        capabilities=tuple(binding.capability for binding in runtime.scope_profile.SCOPE_BINDINGS),
        lease_sequence=0,
        lease_expires_at_ns=grant.expires_at_ns,
        state="active",
    )
    coordinator = _Coordinator(binding)
    executor = classes.ExecutorGateway(
        verifier,
        replay_status=replay.status,
        effect_coordinator=coordinator,
    )
    config = runtime.lets_config.LetsHostConfig(
        master_enabled=mode != "off",
        mode=mode,
        environment="test",
        governed_cohorts=("server_dynamic", "byo_user"),
        governed_agent_allowlist=(),
    )
    authorization = classes.AuthorizationGateway(
        config,
        _TimedWardenClient(typed_client) if mode == "enforce" else None,
        effect_coordinator=coordinator if mode == "enforce" else None,
    )
    repository = _BindingRepository(binding)

    async def resolve(_agent_id: str, _owner_id: str | None) -> Any:
        with _span("host_runtime_resolver_ns"):
            return runtime.governed_dispatch.DispatchRuntime(
                owner_id=OWNER_ID,
                agent_id=AGENT_ID,
                population="server_dynamic",
                runtime_id=RUNTIME_ID,
                runtime_generation=1,
                executor_audience=EXECUTOR_AUDIENCE,
                executor_conformant=True,
                dispatch_posture="protected_executor",
            )

    dispatch = (
        runtime.governed_dispatch.GovernedFinalDispatch.off()
        if mode == "off"
        else runtime.governed_dispatch.GovernedFinalDispatch.active(
            gateway=authorization,
            plane=_Plane(),
            authority_repository=repository,
            runtime_resolver=resolve,
        )
    )

    audit_sink = _AuditSink()
    audit_module = runtime.audit_recorder
    original_get_recorder = audit_module.get_recorder
    audit_module.get_recorder = lambda: audit_sink

    governed_module = runtime.governed_dispatch
    original_context_builder = governed_module.build_protected_dispatch_context

    def timed_context_builder(*args: Any, **kwargs: Any) -> Any:
        return _timed("host_context_policy_ns", original_context_builder, *args, **kwargs)

    governed_module.build_protected_dispatch_context = timed_context_builder
    return _Rig(
        dispatch=dispatch,
        executor=executor,
        binding=binding,
        warden_service=service,
        audit_identity=runtime.models.IdentityContext(
            "matched-host-auditor", TENANT_ID, frozenset()
        ),
        warden_storage=storage,
        replay_store=replay,
        executor_anchor=anchor,
        service_client=public_client,
        coordinator=coordinator,
        audit_sink=audit_sink,
        audit_module=audit_module,
        original_get_recorder=original_get_recorder,
        original_context_builder=original_context_builder,
        governed_dispatch_module=governed_module,
        capability_name=str(runtime.lets_gateway.LETS_CALLER_CAPABILITY),
    )


def _exclusive(values: Mapping[str, int]) -> dict[str, int]:
    """Derive a non-overlapping decomposition from explicitly nested spans."""

    def get(name: str) -> int:
        return int(values.get(name, 0))

    authorization_coordinator = get("coordinator_prepare_ns") + get("coordinator_receipt_ns")
    executor_coordinator = get("coordinator_claim_ns") + get("coordinator_outcome_ns")
    return {
        "host_runtime_resolver_exclusive_ns": get("host_runtime_resolver_ns"),
        "host_plane_transaction_exclusive_ns": max(
            0, get("host_plane_transaction_ns") - get("host_binding_lookup_ns")
        ),
        "host_binding_lookup_exclusive_ns": get("host_binding_lookup_ns"),
        "host_context_policy_exclusive_ns": get("host_context_policy_ns"),
        "host_binding_policy_exclusive_ns": get("host_binding_policy_ns"),
        "host_receipt_validation_exclusive_ns": get("host_receipt_validation_ns"),
        "warden_transaction_exclusive_ns": max(
            0, get("warden_transaction_ns") - get("warden_signing_serialization_ns")
        ),
        "warden_signing_serialization_exclusive_ns": get("warden_signing_serialization_ns"),
        "warden_request_adapter_ns": max(
            0, get("warden_request_inclusive_ns") - get("warden_transaction_ns")
        ),
        "host_gateway_other_ns": max(
            0,
            get("host_gateway_inclusive_ns")
            - get("warden_request_inclusive_ns")
            - authorization_coordinator
            - get("audit_ns")
            - get("host_binding_policy_ns")
            - get("host_receipt_validation_ns"),
        ),
        "executor_replay_transaction_exclusive_ns": max(
            0, get("replay_transaction_ns") - get("rollback_anchor_claim_ns")
        ),
        "executor_replay_claim_overhead_ns": max(
            0, get("replay_claim_ns") - get("replay_transaction_ns")
        ),
        "executor_verifier_overhead_ns": max(
            0,
            get("executor_verifier_inclusive_ns")
            - get("executor_verify_ns")
            - get("replay_claim_ns"),
        ),
        "executor_verify_exclusive_ns": get("executor_verify_ns"),
        "rollback_anchor_claim_exclusive_ns": get("rollback_anchor_claim_ns"),
        "executor_replay_status_exclusive_ns": max(
            0,
            get("executor_replay_status_inclusive_ns") - get("rollback_anchor_status_ns"),
        ),
        "rollback_anchor_status_exclusive_ns": get("rollback_anchor_status_ns"),
        "receipt_handoff_host_validation_ns": max(
            0,
            get("executor_gateway_inclusive_ns")
            - get("executor_verifier_inclusive_ns")
            - get("executor_replay_status_inclusive_ns")
            - get("coordinator_claim_ns"),
        ),
        "executor_bookkeeping_ns": max(
            0,
            get("executor_claim_invoke_inclusive_ns")
            - get("executor_gateway_inclusive_ns")
            - get("application_ns")
            - get("coordinator_outcome_ns"),
        ),
        "host_dispatch_framework_ns": max(
            0,
            get("end_to_end_ns")
            - get("host_runtime_resolver_ns")
            - get("host_plane_transaction_ns")
            - get("host_context_policy_ns")
            - get("host_gateway_inclusive_ns")
            - get("executor_claim_invoke_inclusive_ns")
            - get("application_ns") * (1 if get("executor_claim_invoke_inclusive_ns") == 0 else 0),
        ),
        "coordinator_total_ns": authorization_coordinator + executor_coordinator,
        "audit_exclusive_ns": get("audit_ns"),
        "application_exclusive_ns": get("application_ns"),
    }


async def _operation(rig: _Rig, *, mode: Mode, operation_index: int) -> dict[str, object]:
    final_arguments: dict[str, object] = {"value": 1}
    trace = _Trace()
    token = _ACTIVE_TRACE.set(trace)

    def actuator() -> int:
        with _span("application_ns"):
            rig.effect_count += 1
            return rig.effect_count

    def invoke(capabilities: Mapping[str, object]) -> int:
        if mode == "off":
            return actuator()
        return rig.executor.claim_and_invoke(
            metadata=capabilities[rig.capability_name],
            final_arguments=final_arguments,
            owner_id=OWNER_ID,
            binding_id=rig.binding.binding_id,
            lease_id=rig.binding.lease_id,
            lineage_id=rig.binding.lineage_id,
            agent_id=AGENT_ID,
            runtime_id=RUNTIME_ID,
            runtime_generation=1,
            tool_id=TOOL_ID,
            executor_audience=EXECUTOR_AUDIENCE,
            actuator=actuator,
            failure_is_uncertain=True,
        )

    started = time.perf_counter_ns()
    try:
        result = await rig.dispatch.execute(
            owner_id=OWNER_ID,
            agent_id=AGENT_ID,
            tool_id=TOOL_ID,
            scope=SCOPE,
            channel="mcp",
            audit_correlation_id=f"matched-host-{operation_index}",
            final_arguments=final_arguments,
            invoke=invoke,
            authorized_effect={"effect_class": "execute"},
            actor_user_id=OWNER_ID,
            auth_principal=OWNER_ID,
            conversation_id=None,
        )
    finally:
        trace.add("end_to_end_ns", time.perf_counter_ns() - started)
        _ACTIVE_TRACE.reset(token)
    values = dict(trace.values)
    exclusive = _exclusive(values)
    if sum(exclusive.values()) != values["end_to_end_ns"]:
        raise BenchmarkRefusal("timing spans do not form one non-overlapping decomposition")
    return {
        "format": SAMPLE_SCHEMA,
        "mode": mode,
        "operation_index": operation_index,
        "result": result,
        "timing_ns": values,
        "exclusive_ns": exclusive,
        "span_counts": dict(trace.counts),
    }


def _nearest_rank(values: Sequence[int], percentile: float) -> int:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("at least one value is required")
    rank = max(1, math.ceil(len(ordered) * percentile))
    return ordered[min(rank - 1, len(ordered) - 1)]


def _summary(values: Sequence[int]) -> dict[str, int]:
    return {
        "minimum": min(values),
        "p50": int(statistics.median(values)),
        "mean": int(statistics.fmean(values)),
        "p95": _nearest_rank(values, 0.95),
        "p99": _nearest_rank(values, 0.99),
        "maximum": max(values),
    }


def _summaries(samples: Sequence[Mapping[str, object]]) -> dict[str, object]:
    labels = sorted(
        {
            label
            for sample in samples
            for section in ("timing_ns", "exclusive_ns")
            for label in cast_mapping(sample[section])
        }
    )
    return {
        label: _summary(
            [
                int(cast_mapping(sample[section]).get(label, 0))
                for sample in samples
                for section in ("timing_ns", "exclusive_ns")
                if label in cast_mapping(sample[section])
            ]
        )
        for label in labels
    }


def cast_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError("expected mapping")
    return value


def _run_mode(
    runtime: SimpleNamespace,
    storage_root: Path,
    *,
    mode: Mode,
    trial: int,
    warmups: int,
    operations: int,
) -> dict[str, object]:
    with TemporaryDirectory(prefix=f"lets-matched-{trial}-{mode}-", dir=storage_root) as temp:
        rig = _build_rig(runtime, Path(temp), budget=warmups + operations, mode=mode)
        try:

            async def execute_sequence() -> list[dict[str, object]]:
                for index in range(warmups):
                    await _operation(rig, mode=mode, operation_index=-(index + 1))
                return [
                    await _operation(rig, mode=mode, operation_index=index)
                    for index in range(operations)
                ]

            samples = asyncio.run(execute_sequence())
            status = rig.replay_store.status()
            invariants_healthy = rig.warden_service.invariant_snapshot(
                identity=rig.audit_identity
            ).healthy
            return {
                "trial": trial,
                "mode": mode,
                "samples": samples,
                "summary_ns": _summaries(samples),
                "effects": rig.effect_count,
                "warden_authorization_calls": rig.service_client.authorization_calls,
                "audit_events": rig.audit_sink.count,
                "coordinator_counts": dict(rig.coordinator.counts),
                "warden_invariants_healthy": bool(invariants_healthy),
                "executor_rollback_protected": bool(status.rollback_protected),
                "executor_authority_state": (
                    "healthy" if status.authority_healthy else "unhealthy"
                ),
                "warden_database": Path(rig.warden_storage.path).name,
                "executor_database": Path(rig.replay_store.path).name,
                "storage_scope": {
                    "warden_anchor": "none",
                    "executor_anchor": "process-file",
                    "independent_rollback_domain_established": False,
                },
            }
        finally:
            rig.close()


def _storage_identity(root: Path) -> dict[str, object]:
    stat = root.stat()
    usage = shutil.disk_usage(root)
    return {
        "resolved_root": str(root),
        "device_id": int(stat.st_dev),
        "drive": root.drive,
        "disk_total_bytes": usage.total,
        "disk_used_bytes_before": usage.used,
        "disk_free_bytes_before": usage.free,
        "allocation": "fresh sibling temporary directory per trial and mode",
        "warden_executor_same_device": True,
    }


def _environment(identity: Mapping[str, object], storage_root: Path) -> dict[str, object]:
    root = Path(identity["astraldeep_root"])
    sqlite_connection = sqlite3.connect(":memory:")
    try:
        sqlite_compile_options = sorted(
            str(row[0]) for row in sqlite_connection.execute("PRAGMA compile_options")
        )
    finally:
        sqlite_connection.close()
    installed_packages = sorted(
        (
            {
                "name": distribution.metadata["Name"] or distribution.name,
                "version": distribution.version,
            }
            for distribution in importlib.metadata.distributions()
        ),
        key=lambda package: (str(package["name"]).casefold(), str(package["version"])),
    )
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
        "executable_sha256": identity["interpreter_sha256"],
        "installed_packages": installed_packages,
        "sqlite_compile_options": sqlite_compile_options,
        "storage": _storage_identity(storage_root),
        "harness_repository": _harness_repository_identity(),
        "astraldeep": identity["astraldeep"],
        "components": identity["components"],
        "composition_sha256": identity["composition_sha256"],
        "instrumentation": {
            "benchmark_sha256": _sha256_file(Path(__file__).resolve()),
            "governed_dispatch_sha256": _sha256_file(
                root / "backend/orchestrator/governed_dispatch.py"
            ),
            "lets_gateway_sha256": _sha256_file(root / "backend/orchestrator/lets_gateway.py"),
            "warden_service_sha256": _sha256_file(root / "components/LETS/src/lets/service.py"),
            "executor_sha256": _sha256_file(root / "components/LETS/src/lets/executor.py"),
            "executor_authority_sha256": _sha256_file(
                root / "components/LETS/src/lets/executor_authority.py"
            ),
        },
    }


def run_benchmark(
    astraldeep_root: Path,
    storage_root: Path,
    configuration: Configuration,
) -> dict[str, object]:
    if configuration.trials <= 0 or configuration.operations <= 0 or configuration.warmups < 0:
        raise BenchmarkRefusal("trials/operations must be positive and warmups non-negative")
    identity = validate_astraldeep_root(astraldeep_root)
    runtime = _bootstrap_runtime(Path(identity["astraldeep_root"]))
    storage_root = storage_root.resolve(strict=True)
    trials: list[dict[str, object]] = []
    for trial in range(configuration.trials):
        order: tuple[Mode, Mode] = ("off", "enforce") if trial % 2 == 0 else ("enforce", "off")
        for ordinal, mode in enumerate(order):
            result = _run_mode(
                runtime,
                storage_root,
                mode=mode,
                trial=trial,
                warmups=configuration.warmups,
                operations=configuration.operations,
            )
            result["order_ordinal"] = ordinal
            trials.append(result)

    for trial in trials:
        mode = trial["mode"]
        expected = configuration.warmups + configuration.operations
        if mode == "off" and trial["warden_authorization_calls"] != 0:
            raise BenchmarkRefusal("off path unexpectedly called the Warden")
        if mode == "enforce" and trial["warden_authorization_calls"] != expected:
            raise BenchmarkRefusal("enforce path did not authorize every effect exactly once")
        if trial["effects"] != expected:
            raise BenchmarkRefusal("physical effect count does not match warmups plus operations")
        if not trial["warden_invariants_healthy"]:
            raise BenchmarkRefusal("Warden conservation invariants did not remain healthy")
        if mode == "enforce" and not trial["executor_rollback_protected"]:
            raise BenchmarkRefusal("executor replay store was not rollback protected")
        if mode == "enforce":
            if trial["audit_events"] != expected:
                raise BenchmarkRefusal("enforce path did not append one audit event per effect")
            coordinator = cast_mapping(trial["coordinator_counts"])
            if any(
                coordinator.get(stage) != expected
                for stage in ("prepare", "receipt", "claim", "outcome")
            ):
                raise BenchmarkRefusal("effect coordinator did not observe every enforce stage")

    return {
        "format": RESULT_SCHEMA,
        "claim": "replacement-current-composition-not-historical-reproduction",
        "configuration": asdict(configuration),
        "environment": _environment(identity, storage_root),
        "scope": {
            "included": [
                "GovernedFinalDispatch.execute",
                "in-memory host binding lookup and policy checks",
                "real SQLite WardenService authorization transaction",
                "Ed25519 signing and canonical receipt serialization",
                "receipt handoff and host/executor binding validation",
                "public ReceiptVerifier policy/time/signature verification",
                "SQLite replay claim with process-file rollback anchor",
                "in-memory audit sink and effect coordinator",
                "deterministic counter effect",
            ],
            "excluded": [
                "fixture creation and root lease issuance",
                "HTTP transport",
                "PostgreSQL or production AstralPlane persistence",
                "provider/model calls",
                "external tool work",
                "process startup",
                "independent storage rollback domains",
            ],
            "historical_artifact": "benchmarks/results/host-mediation-overhead/20260826T231656Z",
            "historical_artifact_available": False,
        },
        "trials": trials,
    }


def _flatten_samples(document: Mapping[str, object]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    trials = document.get("trials")
    if not isinstance(trials, list):
        raise BenchmarkRefusal("result document has no trial list")
    for trial in trials:
        if not isinstance(trial, Mapping):
            raise BenchmarkRefusal("trial result is malformed")
        samples = trial.get("samples")
        if not isinstance(samples, list):
            raise BenchmarkRefusal("trial has no sample list")
        for sample in samples:
            if not isinstance(sample, Mapping):
                raise BenchmarkRefusal("sample is malformed")
            row: dict[str, object] = {
                "trial": trial["trial"],
                "order_ordinal": trial["order_ordinal"],
                "mode": trial["mode"],
                "operation_index": sample["operation_index"],
                "result": sample["result"],
            }
            for section in ("timing_ns", "exclusive_ns"):
                values = cast_mapping(sample[section])
                row.update({str(key): value for key, value in values.items()})
            rows.append(row)
    return rows


def _csv_bytes(document: Mapping[str, object]) -> bytes:
    rows = _flatten_samples(document)
    fields = [
        "trial",
        "order_ordinal",
        "mode",
        "operation_index",
        "result",
        *sorted(
            {key for row in rows for key in row}
            - {"trial", "order_ordinal", "mode", "operation_index", "result"}
        ),
    ]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("utf-8")


def _markdown(document: Mapping[str, object]) -> str:
    configuration = cast_mapping(document["configuration"])
    trials = document["trials"]
    assert isinstance(trials, list)
    lines = [
        "# Replacement matched final-dispatch benchmark",
        "",
        "> This is a current-composition replacement experiment. It is not an exact",
        "> reproduction of the missing `20260826T231656Z` artifact or its 74.778 ms result.",
        "",
        f"Trials: {configuration['trials']}; warmups/mode: {configuration['warmups']}; "
        f"measured operations/mode: {configuration['operations']}.",
        "",
        "| Trial | Order | Mode | End-to-end p50 (ms) | p95 (ms) | p99 (ms) |",
        "|---:|---:|:---|---:|---:|---:|",
    ]
    for trial in trials:
        assert isinstance(trial, Mapping)
        summary = cast_mapping(cast_mapping(trial["summary_ns"])["end_to_end_ns"])
        lines.append(
            f"| {trial['trial']} | {trial['order_ordinal']} | {trial['mode']} | "
            f"{int(summary['p50']) / 1_000_000:.6f} | "
            f"{int(summary['p95']) / 1_000_000:.6f} | "
            f"{int(summary['p99']) / 1_000_000:.6f} |"
        )
    lines.extend(
        (
            "",
            "The JSON retains every inclusive span, derived exclusive span, span call count,",
            "environment identity, Git/component identity, and storage posture. The CSV retains",
            "one row per measured operation. Fixture construction and root issuance are excluded.",
            "",
            "The Warden is unanchored. The executor uses a process-file anchor, but its anchor",
            "and replay database are intentionally within the same temporary storage root, so this",
            "does not establish independent rollback domains. AstralPlane is pinned by the",
            "composition, but the timed host binding/effect-coordinator adapters are deterministic",
            "and in-memory; no PostgreSQL transaction is included.",
        )
    )
    return "\n".join(lines) + "\n"


def write_outputs(
    document: Mapping[str, object], output: Path, *, overwrite: bool
) -> tuple[Path, ...]:
    output = output.resolve()
    targets = (output / OUTPUT_JSON, output / OUTPUT_CSV, output / OUTPUT_MARKDOWN)
    if output.exists():
        if not output.is_dir():
            raise BenchmarkRefusal("output path is not a directory")
        existing = [target for target in targets if target.exists()]
        if existing and not overwrite:
            raise BenchmarkRefusal("refusing to overwrite retained matched-path evidence")
        unexpected = [path for path in output.iterdir() if path not in targets]
        if unexpected:
            raise BenchmarkRefusal("output directory contains unexpected files")
    else:
        output.mkdir(parents=True)
    payloads = (
        (json.dumps(document, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8"),
        _csv_bytes(document),
        _markdown(document).encode("utf-8"),
    )
    for target, payload in zip(targets, payloads, strict=True):
        target.write_bytes(payload)
    return targets


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--astraldeep-root", required=True, type=Path)
    parser.add_argument("--storage-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--trials", type=int, default=10)
    parser.add_argument("--operations", type=int, default=1_000)
    parser.add_argument("--warmups", type=int, default=100)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        document = run_benchmark(
            arguments.astraldeep_root,
            arguments.storage_root,
            Configuration(
                trials=arguments.trials,
                operations=arguments.operations,
                warmups=arguments.warmups,
            ),
        )
        paths = write_outputs(document, arguments.output, overwrite=arguments.overwrite)
    except (BenchmarkRefusal, OSError, ValueError, TypeError) as exc:
        print(f"matched host-path benchmark refused: {exc}", file=sys.stderr)
        return 2
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
