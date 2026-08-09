"""Hard acceptance: real wardens, real HTTP, durable state, and injected faults."""

from __future__ import annotations

import json
import os
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from lets.canonical import b64url_decode
from lets.crypto import PublicKeyRegistry
from lets.errors import ReplayError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import Receipt
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("LETS_RUN_DOCKER_E2E") != "1",
        reason="set LETS_RUN_DOCKER_E2E=1 after starting compose.yaml",
    ),
]

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ("docker", "compose", "--project-directory", str(ROOT))
TOKEN = os.environ.get("LETS_BOOTSTRAP_TOKEN", "lets-acceptance-token-change-me-2026")
TENANT_ID = "acceptance-tenant"
ENVELOPE_ID = "acceptance-envelope"
CONFIG_EPOCH = 1
INITIAL_BUDGET = (300,)
MAX_CLOCK_UNCERTAINTY_NS = 1_000_000_000
AUTHORIZATION = {"authorization": f"Bearer {TOKEN}"}
NODES = {
    "warden-a": "http://127.0.0.1:18741",
    "warden-b": "http://127.0.0.1:18742",
    "warden-c": "http://127.0.0.1:18743",
}
TOXIPROXY = "http://127.0.0.1:18474"


def acceptance_policy() -> PolicySpec:
    dimension = ResourceDimension(
        "operations",
        "count",
        "Finite authorization operations available to this cluster.",
    )
    return PolicySpec(
        policy_id="acceptance-policy",
        policy_version="v1",
        dimensions=(dimension,),
        machine=MachineSpec(
            machine_id="acceptance-worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), "worker.act"),),
        ),
        max_lease_ttl_ns=600_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=MAX_CLOCK_UNCERTAINTY_NS,
        transfer_gap_window=8,
    )


def _request(
    method: str,
    base_url: str,
    path: str,
    *,
    body: Mapping[str, Any] | None = None,
    authenticated: bool = True,
    expected: int = 200,
) -> dict[str, Any]:
    headers = AUTHORIZATION if authenticated else {}
    with httpx.Client(base_url=base_url, timeout=10, headers=headers) as client:
        response = client.request(method, path, json=body)
    assert response.status_code == expected, response.text
    decoded = response.json()
    assert isinstance(decoded, dict)
    return cast(dict[str, Any], decoded)


def _compose(*arguments: str, input_object: Mapping[str, Any] | None = None) -> str:
    process = subprocess.run(
        [*COMPOSE, *arguments],
        cwd=ROOT,
        input=None if input_object is None else json.dumps(input_object),
        check=False,
        capture_output=True,
        text=True,
        timeout=90,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    return process.stdout.strip()


def _peer_call(
    source: str,
    proxy_url: str,
    operation: str,
    payload: Mapping[str, Any],
    *,
    succeeds: bool = True,
) -> dict[str, Any] | None:
    process = subprocess.run(
        [
            *COMPOSE,
            "exec",
            "-T",
            source,
            "python",
            "/app/deploy/peer_tool.py",
            "call",
            "--base-url",
            proxy_url,
            "--operation",
            operation,
        ],
        cwd=ROOT,
        input=json.dumps(payload),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if not succeeds:
        assert process.returncode != 0, process.stdout
        return None
    assert process.returncode == 0, process.stdout + process.stderr
    decoded = json.loads(process.stdout)
    assert isinstance(decoded, dict)
    return cast(dict[str, Any], decoded)


def _signed_envelope(
    source: str,
    path: str,
    payload: Mapping[str, Any],
) -> tuple[dict[str, str], bytes]:
    nonce = f"acceptance-replay-{uuid.uuid4().hex}"
    process = subprocess.run(
        [
            *COMPOSE,
            "exec",
            "-T",
            source,
            "python",
            "/app/deploy/peer_tool.py",
            "sign",
            "--path",
            path,
            "--nonce",
            nonce,
        ],
        cwd=ROOT,
        input=json.dumps(payload),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    decoded = json.loads(process.stdout)
    assert isinstance(decoded, dict)
    headers = decoded["headers"]
    body = decoded["body"]
    assert isinstance(headers, dict) and isinstance(body, str)
    return cast(dict[str, str], headers), body.encode()


def _set_proxy(name: str, *, enabled: bool) -> None:
    with httpx.Client(base_url=TOXIPROXY, timeout=5) as client:
        current = client.get(f"/proxies/{name}")
        current.raise_for_status()
        payload = current.json()
        payload["enabled"] = enabled
        response = client.patch(f"/proxies/{name}", json=payload)
        response.raise_for_status()
        assert response.json()["enabled"] is enabled


def _wait_ready(warden_id: str, *, timeout_s: float = 45) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{NODES[warden_id]}/health/ready", timeout=2)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    raise AssertionError(f"{warden_id} did not become ready")


def _wait_for_state(
    description: str,
    probe: Callable[[], dict[str, Any]],
    accepted: Callable[[dict[str, Any]], bool],
    *,
    timeout_s: float = 60,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = probe()
        if accepted(last):
            return last
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}; last state={last!r}")


def _sum_vectors(vectors: Sequence[Sequence[int]]) -> tuple[int, ...]:
    dimensions = len(vectors[0])
    return tuple(sum(vector[index] for vector in vectors) for index in range(dimensions))


def test_real_three_node_fault_recovery_and_conservation(tmp_path: Path) -> None:
    """Exercise the production service across three independent OS processes."""

    scenario: dict[str, Any] = {"schema": "lets.acceptance-scenario/v1"}
    infos: dict[str, dict[str, Any]] = {}
    keys: dict[str, dict[str, Any]] = {}
    container_pids: list[int] = []
    for warden_id, base_url in NODES.items():
        assert _request("GET", base_url, "/health/live")["status"] == "live"
        assert _request("GET", base_url, "/health/ready")["status"] == "ready"
        infos[warden_id] = _request("GET", base_url, "/v1/info")
        keys[warden_id] = _request("GET", base_url, "/v1/keys")
        assert infos[warden_id]["warden_id"] == warden_id
        container_id = _compose("ps", "-q", warden_id)
        inspected = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Pid}}", container_id],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        container_pids.append(int(inspected.stdout.strip()))
    assert len(set(container_pids)) == 3
    assert len({key["keys"][0]["key_id"] for key in keys.values()}) == 3
    manifest_digests = {info["metadata"]["manifest_digest"] for info in infos.values()}
    assert len(manifest_digests) == 1
    manifest_digest = manifest_digests.pop()
    assert isinstance(manifest_digest, str) and manifest_digest.startswith("sha256:")
    scenario["nodes"] = {
        "distinct_process_ids": container_pids,
        "distinct_key_ids": {
            warden_id: document["keys"][0]["key_id"] for warden_id, document in keys.items()
        },
        "manifest_digest": manifest_digest,
    }

    denied = _request(
        "GET",
        NODES["warden-a"],
        "/v1/invariants",
        authenticated=False,
        expected=401,
    )
    assert denied["code"] == "authentication_required"

    policy = acceptance_policy()
    policy_body = policy.to_dict()
    for base_url in NODES.values():
        registered = _request("POST", base_url, "/v1/policies", body=policy_body, expected=201)
        assert registered["policy_digest"] == policy.digest

    roots: dict[str, dict[str, Any]] = {}
    for warden_id, allocation in (("warden-a", 30), ("warden-b", 20), ("warden-c", 10)):
        roots[warden_id] = _request(
            "POST",
            NODES[warden_id],
            "/v1/roots",
            body={
                "request_id": f"root-{uuid.uuid4().hex}",
                "tenant_id": TENANT_ID,
                "envelope_id": ENVELOPE_ID,
                "subject_id": warden_id,
                "allocation": [allocation],
                "capabilities": ["worker.act"],
                "policy_digest": policy.digest,
                "ttl_ns": 300_000_000_000,
            },
            expected=201,
        )

    receipt_c = _request(
        "POST",
        NODES["warden-c"],
        f"/v1/leases/{roots['warden-c']['lease_id']}/transitions",
        body={
            "request_id": f"authorize-{uuid.uuid4().hex}",
            "transition": "act",
            "executor_audience": "executor-c",
            "nonce": f"nonce-{uuid.uuid4().hex}",
        },
    )
    assert receipt_c["warden_id"] == "warden-c"

    source_transfer_baseline = _request("GET", NODES["warden-a"], "/v1/invariants")[
        "transferred_out"
    ][0]
    target_transfer_baseline = _request("GET", NODES["warden-b"], "/v1/invariants")[
        "transferred_in"
    ][0]

    _set_proxy("a_to_b", enabled=False)
    _set_proxy("b_to_a", enabled=False)
    try:
        vouchers = [
            _request(
                "POST",
                NODES["warden-a"],
                "/v1/transfers/prepare",
                body={
                    "request_id": f"transfer-{uuid.uuid4().hex}",
                    "tenant_id": TENANT_ID,
                    "envelope_id": ENVELOPE_ID,
                    "target_warden": "warden-b",
                    "amount": [10],
                    "policy_digest": policy.digest,
                },
                expected=201,
            )
            for _ in range(2)
        ]
        first, second = sorted(vouchers, key=lambda item: cast(int, item["sequence"]))
        partitioned_metrics = _wait_for_state(
            "durable dispatcher retry state during partition",
            lambda: _request("GET", NODES["warden-a"], "/v1/metrics"),
            lambda state: (
                state["peer_dispatcher"]["pending_records"] >= 2
                and state["peer_dispatcher"]["failed_records"] >= 1
            ),
        )

        accept_path = f"/v1/transfers/{second['source_warden']}/{second['sequence']}/accept"
        unsigned = _request(
            "POST",
            NODES["warden-b"],
            accept_path,
            body=second,
            authenticated=False,
            expected=401,
        )
        assert unsigned["code"] == "authentication_required"
        replay_headers, replay_body = _signed_envelope("warden-a", accept_path, second)
        accepted_second = httpx.post(
            f"{NODES['warden-b']}{accept_path}",
            content=replay_body,
            headers=replay_headers,
            timeout=10,
        )
        assert accepted_second.status_code == 200, accepted_second.text
        ack_second = accepted_second.json()
        assert ack_second["sequence"] == second["sequence"]
        assert ack_second["contiguous_watermark"] < second["sequence"]
        exact_replay = httpx.post(
            f"{NODES['warden-b']}{accept_path}",
            content=replay_body,
            headers=replay_headers,
            timeout=10,
        )
        assert exact_replay.status_code == 409, exact_replay.text
        assert exact_replay.json()["code"] == "replay_detected"
        scenario["reordered_transfer"] = {
            "sent_sequence_first": second["sequence"],
            "missing_sequence": first["sequence"],
            "contiguous_watermark": ack_second["contiguous_watermark"],
            "exact_http_replay_status": exact_replay.status_code,
            "exact_http_replay_code": exact_replay.json()["code"],
        }

        receipt_a = _request(
            "POST",
            NODES["warden-a"],
            f"/v1/leases/{roots['warden-a']['lease_id']}/transitions",
            body={
                "request_id": f"authorize-{uuid.uuid4().hex}",
                "transition": "act",
                "executor_audience": "executor-a",
                "nonce": f"nonce-{uuid.uuid4().hex}",
            },
        )
        receipt_b = _request(
            "POST",
            NODES["warden-b"],
            f"/v1/leases/{roots['warden-b']['lease_id']}/transitions",
            body={
                "request_id": f"authorize-{uuid.uuid4().hex}",
                "transition": "act",
                "executor_audience": "executor-b",
                "nonce": f"nonce-{uuid.uuid4().hex}",
            },
        )
        assert receipt_a["warden_id"] == "warden-a"
        assert receipt_b["warden_id"] == "warden-b"
        scenario["partition"] = {
            "links_disabled": ["a_to_b", "b_to_a"],
            "durable_peer_delivery": partitioned_metrics["peer_dispatcher"],
            "local_progress_receipts": [
                receipt_a["receipt_id"],
                receipt_b["receipt_id"],
            ],
        }

        key_before_restart = keys["warden-b"]
        pid_before_restart = container_pids[1]
        _compose("kill", "-s", "SIGKILL", "warden-b")
        _compose("up", "-d", "--no-deps", "warden-b")
        _wait_ready("warden-b")
        assert _request("GET", NODES["warden-b"], "/v1/keys") == key_before_restart
        restarted_container = _compose("ps", "-q", "warden-b")
        pid_after_restart = int(
            subprocess.run(
                ["docker", "inspect", "--format", "{{.State.Pid}}", restarted_container],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        )
        assert pid_after_restart != pid_before_restart

        replay_after_restart = httpx.post(
            f"{NODES['warden-b']}{accept_path}",
            content=replay_body,
            headers=replay_headers,
            timeout=10,
        )
        assert replay_after_restart.status_code == 409, replay_after_restart.text
        assert replay_after_restart.json()["code"] == "replay_detected"
        duplicate_second = _peer_call("warden-a", "http://warden-b:8080", "accept", second)
        assert duplicate_second == ack_second
        scenario["restart_recovery"] = {
            "signal": "SIGKILL",
            "pid_before": pid_before_restart,
            "pid_after": pid_after_restart,
            "signing_key_stable": True,
            "exact_http_replay_status_after_restart": replay_after_restart.status_code,
            "exact_http_replay_code_after_restart": replay_after_restart.json()["code"],
            "application_duplicate_ack_stable": True,
        }
    finally:
        _set_proxy("a_to_b", enabled=True)
        _set_proxy("b_to_a", enabled=True)

    converged = _wait_for_state(
        "automatic transfer finalization and bilateral checkpoint delivery",
        lambda: {
            "source_metrics": _request("GET", NODES["warden-a"], "/v1/metrics"),
            "target_metrics": _request("GET", NODES["warden-b"], "/v1/metrics"),
        },
        lambda state: (
            state["source_metrics"]["peer_dispatcher"]["pending_records"] == 0
            and state["source_metrics"]["peer_dispatcher"]["prepared_transfers"] == 0
            and state["source_metrics"]["transfers"]["outgoing_compacted_high_water"]
            >= second["sequence"]
            and state["target_metrics"]["transfers"]["incoming_compacted_high_water"]
            >= second["sequence"]
        ),
    )
    scenario["dispatcher_convergence"] = {
        "automatic_accept_finalize_checkpoint": True,
        "source_peer_dispatcher": converged["source_metrics"]["peer_dispatcher"],
        "source_compacted_high_water": converged["source_metrics"]["transfers"][
            "outgoing_compacted_high_water"
        ],
        "target_compacted_high_water": converged["target_metrics"]["transfers"][
            "incoming_compacted_high_water"
        ],
    }

    warden_a_key = keys["warden-a"]["keys"][0]
    registry = PublicKeyRegistry()
    registry.register(
        "warden-a",
        warden_a_key["key_id"],
        b64url_decode(warden_a_key["public_key"]),
    )
    replay_path = tmp_path / "executor-replay.sqlite3"
    replay_store = SQLiteReceiptReplayStore.initialize(replay_path)
    verifier = ReceiptVerifier(
        registry,
        replay_store,
        ExecutorPolicy(
            audience="executor-a",
            tenant_id=TENANT_ID,
            envelope_id=ENVELOPE_ID,
            config_epoch=CONFIG_EPOCH,
            allowed_policy_digests=frozenset({policy.digest}),
            allowed_machine_digests=frozenset({policy.machine.digest}),
            trusted_wardens=frozenset({"warden-a"}),
            max_clock_uncertainty_ns=MAX_CLOCK_UNCERTAINTY_NS,
        ),
    )
    verifier.verify_and_claim(Receipt.from_dict(receipt_a))
    reopened_store = SQLiteReceiptReplayStore(replay_path)
    reopened_verifier = ReceiptVerifier(registry, reopened_store, verifier.policy)
    with pytest.raises(ReplayError):
        reopened_verifier.verify_and_claim(Receipt.from_dict(receipt_a))
    assert reopened_store.integrity_check() == ("ok",)
    scenario["independent_executor"] = {
        "receipt_id": receipt_a["receipt_id"],
        "signature_verified": True,
        "durable_replay_rejected_after_reopen": True,
        "replay_store_integrity": ["ok"],
    }

    snapshots = [_request("GET", base_url, "/v1/invariants") for base_url in NODES.values()]
    assert all(snapshot["healthy"] is True for snapshot in snapshots)
    assert _sum_vectors([snapshot["initial_share"] for snapshot in snapshots]) == INITIAL_BUDGET
    transferred_in = _sum_vectors([snapshot["transferred_in"] for snapshot in snapshots])
    transferred_out = _sum_vectors([snapshot["transferred_out"] for snapshot in snapshots])
    assert transferred_in == transferred_out
    assert snapshots[0]["transferred_out"][0] == source_transfer_baseline + 20
    assert snapshots[1]["transferred_in"][0] == target_transfer_baseline + 20
    conserved = _sum_vectors(
        [
            tuple(
                snapshot["free_pool"][index]
                + snapshot["lease_residual"][index]
                + snapshot["consumed"][index]
                for index in range(len(INITIAL_BUDGET))
            )
            for snapshot in snapshots
        ]
    )
    assert conserved == INITIAL_BUDGET
    audits = {
        warden_id: _request("GET", base_url, "/v1/audit/verify")["valid"]
        for warden_id, base_url in NODES.items()
    }
    assert all(value is True for value in audits.values())
    scenario["conservation"] = {
        "initial_budget": list(INITIAL_BUDGET),
        "transferred_in": list(transferred_in),
        "transferred_out": list(transferred_out),
        "free_plus_residual_plus_consumed": list(conserved),
        "local_invariants_healthy": [snapshot["healthy"] for snapshot in snapshots],
        "audit_chains_valid": audits,
    }
    evidence_path = os.environ.get("LETS_E2E_SCENARIO_EVIDENCE")
    if evidence_path:
        destination = Path(evidence_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(scenario, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
