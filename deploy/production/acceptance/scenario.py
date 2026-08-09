"""Exercise mTLS, JWT, partition, restart, and convergence inside the cluster network."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import ssl
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import httpx
from nacl.signing import SigningKey

from lets.canonical import b64url_decode, b64url_encode, canonical_json, strict_json_loads
from lets.cli import _sqlite_wal_reset_safe
from lets.crypto import PublicKeyRegistry
from lets.errors import ReplayError, StorageError
from lets.executor import (
    ExecutorPolicy,
    ReceiptVerifier,
    SQLiteReceiptReplayStore,
    executor_replay_identity,
)
from lets.executor_authority import ProcessFileExecutorAuthorityAnchor
from lets.manifest import ClusterManifest
from lets.models import Receipt
from lets.policy import PolicySpec

TENANT_ID = "production-acceptance-tenant"
ENVELOPE_ID = "production-acceptance-envelope"
NODES = {
    "warden-a": "https://warden-a:8443",
    "warden-b": "https://warden-b:8443",
    "warden-c": "https://warden-c:8443",
}
CLIENT = Path("/test-client")
TRUST = Path("/etc/lets/trust")
STATE = Path("/scenario/state.json")
RESULT = Path("/scenario/result.json")
EXECUTOR_AUDIENCE = "production-executor"
EXECUTOR_STATE = Path("/var/lib/lets-executor")
EXECUTOR_AUTHORITY = Path("/var/lib/lets-executor-authority")
EXECUTOR_DATABASE = EXECUTOR_STATE / "replay.sqlite3"
EXECUTOR_STALE_DATABASE = EXECUTOR_STATE / "pre-claim.sqlite3"
EXECUTOR_ANCHOR = EXECUTOR_AUTHORITY / "replay.anchor.json"


def _object(path: Path) -> dict[str, Any]:
    value = strict_json_loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} is not an object")
    return cast(dict[str, Any], value)


def _tls_context(*, wrong_client: bool = False, client_certificate: bool = True) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(CLIENT / "server-ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_certificate:
        prefix = "wrong-client" if wrong_client else "client"
        context.load_cert_chain(
            certfile=CLIENT / f"{prefix}-cert.pem",
            keyfile=CLIENT / f"{prefix}-key.pem",
        )
    return context


def _token(*, expired: bool = False) -> str:
    identity = _object(CLIENT / "identity.json")
    now = int(time.time())
    if expired:
        issued_at, not_before, expires_at = now - 120, now - 120, now - 60
    else:
        issued_at, not_before, expires_at = now - 1, now - 1, now + 120
    header = {"alg": "EdDSA", "kid": identity["kid"], "typ": "at+jwt"}
    payload = {
        "aud": identity["audience"],
        "exp": expires_at,
        "iat": issued_at,
        "iss": identity["issuer"],
        "jti": f"production-acceptance-{uuid.uuid4().hex}",
        "nbf": not_before,
        "scope": "lets.admin lets.audit.read lets.audit.verify lets.metrics.read lets.transfer",
        "sub": "production-acceptance-operator",
        "tenant_id": TENANT_ID,
    }
    encoded_header = b64url_encode(canonical_json(header))
    encoded_payload = b64url_encode(canonical_json(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signer = SigningKey(CLIENT.joinpath("identity.seed").read_bytes())
    signature = b64url_encode(signer.sign(signing_input).signature)
    return f"{encoded_header}.{encoded_payload}.{signature}"


def _client(*, token: str | None = None, context: ssl.SSLContext | None = None) -> httpx.Client:
    headers = {} if token is None else {"authorization": f"Bearer {token}"}
    return httpx.Client(
        verify=_tls_context() if context is None else context,
        headers=headers,
        timeout=10,
    )


def _request(
    method: str,
    node: str,
    path: str,
    *,
    body: Mapping[str, Any] | None = None,
    expected: int = 200,
    token: str | None = None,
) -> dict[str, Any]:
    with _client(token=_token() if token is None else token) as client:
        response = client.request(method, f"{NODES[node]}{path}", json=body)
    if response.status_code != expected:
        raise AssertionError(f"{method} {node}{path}: {response.status_code} {response.text}")
    value = response.json()
    if not isinstance(value, dict):
        raise AssertionError(f"{node}{path} did not return an object")
    return cast(dict[str, Any], value)


def _wait(
    description: str,
    probe: Callable[[], dict[str, Any]],
    accepted: Callable[[dict[str, Any]], bool],
    *,
    timeout_s: float = 90,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = probe()
        if accepted(last):
            return last
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {description}: {last!r}")


def _sum(vectors: Sequence[Sequence[int]]) -> tuple[int, ...]:
    return tuple(sum(vector[index] for vector in vectors) for index in range(len(vectors[0])))


def security_phase() -> None:
    for context_name, context in (
        ("no client certificate", _tls_context(client_certificate=False)),
        ("untrusted client certificate", _tls_context(wrong_client=True)),
    ):
        try:
            with _client(token=_token(), context=context) as client:
                client.get(f"{NODES['warden-a']}/health/live")
        except httpx.TransportError:
            pass
        else:
            raise AssertionError(f"TLS admitted {context_name}")

    with _client() as client:
        unauthenticated = client.get(f"{NODES['warden-a']}/v1/invariants")
    if unauthenticated.status_code != 401:
        raise AssertionError(f"missing JWT returned {unauthenticated.status_code}")
    with _client(token=_token(expired=True)) as client:
        expired = client.get(f"{NODES['warden-a']}/v1/invariants")
    if expired.status_code != 401:
        raise AssertionError(f"expired JWT returned {expired.status_code}")

    identities = {}
    for warden_id in NODES:
        live = _request("GET", warden_id, "/health/live")
        ready = _request("GET", warden_id, "/health/ready")
        info = _request("GET", warden_id, "/v1/info")
        keys = _request("GET", warden_id, "/v1/keys")
        if live != {"status": "live"} or ready != {"status": "ready"}:
            raise AssertionError(f"{warden_id} health documents are invalid")
        if info["metadata"]["runtime_provider"] != "generic-production":
            raise AssertionError(f"{warden_id} did not use generic-production")
        sqlite_version = info["metadata"].get("sqlite_version")
        if not isinstance(sqlite_version, str):
            raise AssertionError(f"{warden_id} returned no SQLite version evidence")
        try:
            parsed_sqlite = tuple(int(item) for item in sqlite_version.split("."))
        except ValueError as exc:
            raise AssertionError(f"{warden_id} returned malformed SQLite version evidence") from exc
        if not _sqlite_wal_reset_safe(parsed_sqlite):
            raise AssertionError(f"{warden_id} loaded vulnerable SQLite {sqlite_version}")
        identities[warden_id] = {
            "key_id": keys["keys"][0]["key_id"],
            "manifest_digest": info["metadata"]["manifest_digest"],
            "sqlite_version": sqlite_version,
        }
    if len({value["key_id"] for value in identities.values()}) != 3:
        raise AssertionError("wardens do not have independent signer identities")
    if len({value["manifest_digest"] for value in identities.values()}) != 1:
        raise AssertionError("wardens disagree on the signed manifest")
    print(
        json.dumps(
            {
                "expired_jwt_rejected": True,
                "mTLS": True,
                "missing_client_certificate_rejected": True,
                "missing_jwt_rejected": True,
                "phase": "security",
                "sqlite_wal_reset_fix": True,
                "status": "passed",
                "untrusted_client_certificate_rejected": True,
                "wardens": identities,
            }
        )
    )


def executor_phase() -> None:
    """Prove the production executor rejects duplicate and stale replay state."""

    manifest = ClusterManifest.load(TRUST / "manifest.json")
    operator = _object(TRUST / "operator.json")
    operator_key_id = operator.get("key_id")
    operator_public_key = operator.get("public_key")
    if not isinstance(operator_key_id, str) or not isinstance(operator_public_key, str):
        raise RuntimeError("acceptance operator trust is malformed")
    manifest.verify_signatures(
        {operator_key_id: b64url_decode(operator_public_key)},
        threshold=1,
    )
    if len(manifest.policies) != 1:
        raise RuntimeError("acceptance manifest has no unique policy")
    policy = manifest.policies[0]
    root = _request(
        "POST",
        "warden-a",
        "/v1/roots",
        body={
            "allocation": [2],
            "capabilities": ["worker.act"],
            "envelope_id": ENVELOPE_ID,
            "policy_digest": policy.digest,
            "request_id": f"production-executor-root-{uuid.uuid4().hex}",
            "subject_id": "production-executor-subject",
            "tenant_id": TENANT_ID,
            "ttl_ns": 300_000_000_000,
        },
        expected=201,
    )
    receipt_document = _request(
        "POST",
        "warden-a",
        f"/v1/leases/{root['lease_id']}/transitions",
        body={
            "executor_audience": EXECUTOR_AUDIENCE,
            "nonce": f"production-executor-effect-{uuid.uuid4().hex}",
            "request_id": f"production-executor-authorize-{uuid.uuid4().hex}",
            "transition": "act",
        },
    )
    receipt = Receipt.from_dict(receipt_document)

    registry = PublicKeyRegistry()
    for key in manifest.warden("warden-a").keys:
        registry.register(
            "warden-a",
            key.key_id,
            key.public_key,
            not_before_ns=key.not_before_ns,
            not_after_ns=key.not_after_ns,
        )
    executor_policy = ExecutorPolicy(
        audience=EXECUTOR_AUDIENCE,
        tenant_id=TENANT_ID,
        envelope_id=ENVELOPE_ID,
        config_epoch=manifest.config_epoch,
        allowed_policy_digests=frozenset({policy.digest}),
        allowed_machine_digests=frozenset({policy.machine.digest}),
        trusted_wardens=frozenset({"warden-a"}),
        max_clock_uncertainty_ns=policy.max_clock_uncertainty_ns,
    )
    identity = executor_replay_identity(executor_policy, registry)
    anchor = ProcessFileExecutorAuthorityAnchor(EXECUTOR_ANCHOR, timeout_s=5)
    try:
        replay_store = SQLiteReceiptReplayStore.initialize(
            EXECUTOR_DATABASE,
            authority_anchor=anchor,
            identity=identity,
        )
        if not replay_store.rollback_protected:
            raise AssertionError("executor replay store did not admit its independent anchor")
        if replay_store.checkpoint_wal()[0] != 0:
            raise AssertionError("executor replay store was not quiescent before snapshot")
        shutil.copyfile(EXECUTOR_DATABASE, EXECUTOR_STALE_DATABASE)

        verifier = ReceiptVerifier(registry, replay_store, executor_policy)
        verifier.verify_and_claim(receipt)
        anchored = anchor.read_current()
        if anchored.identity != identity or anchored.claim_sequence != 1:
            raise AssertionError("executor claim did not advance the identity-bound anchor")
        if replay_store.checkpoint_wal()[0] != 0:
            raise AssertionError("executor replay store checkpoint remained busy after claim")

        reopened_store = SQLiteReceiptReplayStore(
            EXECUTOR_DATABASE,
            authority_anchor=anchor,
        )
        reopened_verifier = ReceiptVerifier(registry, reopened_store, executor_policy)
        try:
            reopened_verifier.verify_and_claim(receipt)
        except ReplayError:
            pass
        else:
            raise AssertionError("executor accepted a duplicate receipt after reopen")

        expected_parent = EXECUTOR_STATE.resolve(strict=True)
        if EXECUTOR_DATABASE.parent.resolve(strict=True) != expected_parent:
            raise AssertionError("executor replay path escaped its dedicated test volume")
        for suffix in ("-wal", "-shm"):
            Path(f"{EXECUTOR_DATABASE}{suffix}").unlink(missing_ok=True)
        os.replace(EXECUTOR_STALE_DATABASE, EXECUTOR_DATABASE)
        directory_fd = os.open(expected_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        try:
            SQLiteReceiptReplayStore(EXECUTOR_DATABASE, authority_anchor=anchor)
        except StorageError as exc:
            if "older than its monotonic authority anchor" not in str(exc):
                raise AssertionError(f"unexpected stale executor rejection: {exc}") from exc
        else:
            raise AssertionError("executor admitted a pre-claim database behind its anchor")
    finally:
        anchor.close()

    print(
        json.dumps(
            {
                "anchor_claim_sequence": 1,
                "anchored_replay_store": True,
                "duplicate_receipt_rejected_after_reopen": True,
                "independent_state_and_anchor_domains": True,
                "phase": "executor",
                "receipt_id": receipt.receipt_id,
                "stale_database_restore_rejected": True,
                "status": "passed",
            },
            sort_keys=True,
        )
    )


def prepare_phase() -> None:
    manifest = _object(TRUST / "manifest.json")
    policies = manifest.get("policies")
    if not isinstance(policies, list) or len(policies) != 1 or not isinstance(policies[0], dict):
        raise RuntimeError("acceptance manifest has no unique policy")
    policy = PolicySpec.from_dict(policies[0])
    baseline_a = _request("GET", "warden-a", "/v1/invariants")
    baseline_b = _request("GET", "warden-b", "/v1/invariants")
    voucher = _request(
        "POST",
        "warden-a",
        "/v1/transfers/prepare",
        body={
            "amount": [10],
            "envelope_id": ENVELOPE_ID,
            "policy_digest": policy.digest,
            "request_id": f"production-transfer-{uuid.uuid4().hex}",
            "target_warden": "warden-b",
            "tenant_id": TENANT_ID,
        },
        expected=201,
    )
    pending = _wait(
        "durable peer retry during the TLS partition",
        lambda: _request("GET", "warden-a", "/v1/metrics"),
        lambda value: (
            value["peer_dispatcher"]["pending_records"] >= 1
            and value["peer_dispatcher"]["failed_records"] >= 1
        ),
    )
    STATE.write_text(
        json.dumps(
            {
                "baseline_in": baseline_b["transferred_in"],
                "baseline_out": baseline_a["transferred_out"],
                "sequence": voucher["sequence"],
                "transfer_id": voucher["transfer_id"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "failed_records": pending["peer_dispatcher"]["failed_records"],
                "phase": "prepare",
                "sequence": voucher["sequence"],
                "status": "passed",
            }
        )
    )


def converge_phase() -> None:
    state = _object(STATE)
    sequence = int(state["sequence"])
    converged = _wait(
        "mTLS transfer finalization and checkpoint convergence",
        lambda: {
            "source": _request("GET", "warden-a", "/v1/metrics"),
            "target": _request("GET", "warden-b", "/v1/metrics"),
        },
        lambda value: (
            value["source"]["peer_dispatcher"]["pending_records"] == 0
            and value["source"]["peer_dispatcher"]["prepared_transfers"] == 0
            and value["source"]["transfers"]["outgoing_compacted_high_water"] >= sequence
            and value["target"]["transfers"]["incoming_compacted_high_water"] >= sequence
        ),
    )
    snapshots = [_request("GET", item, "/v1/invariants") for item in NODES]
    if not all(snapshot["healthy"] is True for snapshot in snapshots):
        raise AssertionError("a warden reported unhealthy invariants")
    transferred_in = _sum([snapshot["transferred_in"] for snapshot in snapshots])
    transferred_out = _sum([snapshot["transferred_out"] for snapshot in snapshots])
    if transferred_in != transferred_out:
        raise AssertionError("cluster transfer totals do not conserve")
    if snapshots[0]["transferred_out"][0] != int(state["baseline_out"][0]) + 10:
        raise AssertionError("source transfer total did not advance")
    if snapshots[1]["transferred_in"][0] != int(state["baseline_in"][0]) + 10:
        raise AssertionError("target transfer total did not advance")
    audits = {item: _request("GET", item, "/v1/audit/verify")["valid"] for item in NODES}
    if not all(audits.values()):
        raise AssertionError("an audit chain failed verification")
    result = {
        "audit_chains_valid": audits,
        "conservation": True,
        "mTLS": True,
        "phase": "converge",
        "provider": "generic-production",
        "sequence": sequence,
        "source_dispatcher": converged["source"]["peer_dispatcher"],
        "status": "passed",
        "transferred_in": list(transferred_in),
        "transferred_out": list(transferred_out),
    }
    RESULT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("security", "executor", "prepare", "converge"))
    phase = parser.parse_args().phase
    {
        "security": security_phase,
        "executor": executor_phase,
        "prepare": prepare_phase,
        "converge": converge_phase,
    }[phase]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
