"""Qualify the public client and authorizers against authenticated local warden HTTP routes.
Signed wire fixtures and durable executor claims independently check authority and restart safety.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from lets.api import create_app
from lets.auth import StaticBearerAuthenticator
from lets.canonical import b64url_decode, canonical_json, strict_json_loads
from lets.client import (
    LETSClient,
    LETSClientError,
    PermissionDeniedError,
    RemoteValidationError,
    RequestConflictError,
    RetryPolicy,
)
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import PolicyError, ReplayError, SignatureError, ValidationError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.integrations import (
    AstralDeepAuthorizer,
    AstralDeepProfile,
    ReplicaAuthorizer,
    ReplicaProfile,
)
from lets.models import IdentityContext, LeaseGrant, Receipt
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "public-receipt-v1.json"
POLICY = PolicySpec(
    "public-policy",
    "v1",
    (ResourceDimension("operations", "count"),),
    MachineSpec("worker", "ready", (TransitionSpec("act", "ready", "ready", (1,), "worker.act"),)),
    10_000,
    100,
    0,
    8,
)


class LocalWardenTransport(httpx.BaseTransport):
    def __init__(self, app: Any) -> None:
        self.app = app
        self.requests: list[tuple[str, str, bytes]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        body = request.read()
        self.requests.append((request.method, request.url.path, body))

        async def send() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=self.app, raise_app_exceptions=True)
            ) as client:
                response = await client.request(
                    request.method, request.url, headers=request.headers, content=body
                )
                return httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    content=response.content,
                    request=request,
                )

        return asyncio.run(send())


@dataclass
class PublicRig:
    app: Any
    transport: LocalWardenTransport
    client: LETSClient
    authorizer: AstralDeepAuthorizer
    grant: dict[str, Any]
    registry: PublicKeyRegistry
    clock: ManualClock
    replay_path: Path

    def receipt(
        self, *, request_id: str = "effect", nonce: str = "public-effect-nonce-01"
    ) -> Receipt:
        wire = self.authorizer.authorize_tool(
            operation_id=request_id,
            lease_id=self.grant["lease_id"],
            declared_scope="tools:execute",
            executor_audience="executor",
            nonce=nonce,
            expected_state="ready",
            expected_sequence=0,
        )
        return Receipt.from_dict(dict(wire))

    def verifier(self, *, initialize: bool = True, audience: str = "executor") -> ReceiptVerifier:
        factory = SQLiteReceiptReplayStore.initialize if initialize else SQLiteReceiptReplayStore
        return ReceiptVerifier(
            self.registry,
            factory(self.replay_path, allow_unanchored=True),
            ExecutorPolicy(
                audience=audience,
                tenant_id="tenant",
                envelope_id="envelope",
                config_epoch=1,
                allowed_policy_digests=frozenset({POLICY.digest}),
                allowed_machine_digests=frozenset({POLICY.machine.digest}),
                trusted_wardens=frozenset({"warden"}),
                max_clock_uncertainty_ns=0,
            ),
            clock=self.clock,
        )


@pytest.fixture
def public_rig(tmp_path: Path) -> Iterator[PublicRig]:
    clock = ManualClock(1_000_000)
    signer = Ed25519Signer.from_seed("warden", bytes(range(32)))
    registry = PublicKeyRegistry(clock=clock)
    registry.register_signer(signer)
    storage = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3",
        "warden",
        (100,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant",
        envelope_id="envelope",
        receipt_ttl_ns=100,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=8,
    )
    service = WardenService(storage, signer=signer, trust_registry=registry, clock=clock)
    service.register_policy(POLICY)
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator(
            {
                "agent-token": IdentityContext("agent", "tenant", frozenset({"lets.lease.issue"})),
                "stranger-token": IdentityContext("stranger", "tenant", frozenset()),
                "other-tenant-token": IdentityContext("agent", "other-tenant", frozenset()),
            }
        ),
    )
    transport = LocalWardenTransport(app)
    with LETSClient(
        "https://warden.test",
        token="agent-token",
        transport=transport,
        retry=RetryPolicy(max_attempts=1),
    ) as client:
        authorizer = AstralDeepAuthorizer(
            ReplicaAuthorizer(
                client,
                ReplicaProfile(
                    "tenant", "envelope", POLICY.digest, (10,), frozenset({"worker.act"}), 1_000
                ),
            ),
            AstralDeepProfile({"tools:execute": "worker.act"}, {"tools:execute": "act"}),
        )
        grant = dict(
            authorizer.provision_agent(
                operation_id="provision", agent_id="agent", declared_scopes={"tools:execute"}
            )
        )
        try:
            yield PublicRig(
                app,
                transport,
                client,
                authorizer,
                grant,
                registry,
                clock,
                tmp_path / "executor.sqlite3",
            )
        finally:
            storage.close()


def test_public_authorizer_round_trip_and_signed_claim(public_rig: PublicRig) -> None:
    grant = LeaseGrant.from_dict(public_rig.grant)
    assert grant.to_dict() == public_rig.grant
    assert public_rig.registry.verify(
        grant.warden_id,
        grant.key_id,
        canonical_json(grant.unsigned_payload()),
        b64url_decode(grant.signature),
    )
    receipt = public_rig.receipt()
    assert receipt.subject_id == "agent"
    assert receipt.lease_id == grant.lease_id
    assert receipt.cost == (1,)
    assert receipt.resulting_sequence == 1
    method, path, body = public_rig.transport.requests[-1]
    assert method == "POST"
    assert path == f"/v1/leases/{grant.lease_id}/transitions"
    assert body == (
        b'{"executor_audience":"executor","expected_sequence":0,"expected_state":"ready",'
        b'"nonce":"public-effect-nonce-01","request_id":"effect","transition":"act"}'
    )
    public_rig.verifier().verify_and_claim(receipt)
    assert public_rig.client.lease(grant.lease_id)["residual"] == [9]
    assert public_rig.receipt().to_dict() == receipt.to_dict()
    assert public_rig.client.lease(grant.lease_id)["residual"] == [9]


def test_public_receipt_claim_survives_fresh_instance_and_process(public_rig: PublicRig) -> None:
    receipt = public_rig.receipt()
    public_rig.verifier().verify_and_claim(receipt)
    with pytest.raises(ReplayError):
        public_rig.verifier(initialize=False).verify_and_claim(receipt)
    public_key = public_rig.registry.public_key(receipt.warden_id, receipt.key_id)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "\n".join(
                (
                    "import json, sys",
                    "from lets.clock import ManualClock",
                    "from lets.crypto import PublicKeyRegistry",
                    "from lets.errors import ReplayError",
                    "from lets.executor import (ExecutorPolicy, ReceiptVerifier, "
                    "SQLiteReceiptReplayStore)",
                    "from lets.models import Receipt",
                    "payload = json.load(sys.stdin)",
                    "receipt = Receipt.from_dict(payload['receipt'])",
                    "registry = PublicKeyRegistry(clock=ManualClock(1_000_000))",
                    "registry.register(receipt.warden_id, receipt.key_id, "
                    "bytes.fromhex(payload['key']))",
                    "store = SQLiteReceiptReplayStore(sys.argv[1], allow_unanchored=True)",
                    "verifier = ReceiptVerifier(registry, store, "
                    "ExecutorPolicy(audience='executor'), "
                    "clock=ManualClock(1_000_000))",
                    "try:",
                    "    verifier.verify_and_claim(receipt)",
                    "except ReplayError:",
                    "    print('durable replay rejected')",
                    "else:",
                    "    raise AssertionError('fresh process authorized a replay')",
                )
            ),
            str(public_rig.replay_path),
        ],
        input=json.dumps({"receipt": receipt.to_dict(), "key": public_key.hex()}),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert child.returncode == 0, child.stdout + child.stderr
    assert child.stdout.strip() == "durable replay rejected"


def test_executor_rejects_unsigned_receipt(public_rig: PublicRig) -> None:
    receipt = replace(public_rig.receipt(), signature="")
    verifier = public_rig.verifier()
    with pytest.raises(SignatureError):
        verifier.verify_and_claim(receipt)


def test_executor_rejects_tampered_receipt(public_rig: PublicRig) -> None:
    receipt = public_rig.receipt()
    verifier = public_rig.verifier()
    with pytest.raises(SignatureError):
        verifier.verify_and_claim(replace(receipt, nonce="changed-effect-nonce-01"))
    verifier.verify_and_claim(receipt)


def test_executor_rejects_wrong_audience(public_rig: PublicRig) -> None:
    receipt = public_rig.receipt()
    with pytest.raises(PolicyError, match="audience"):
        public_rig.verifier(audience="other-executor").verify_and_claim(receipt)


@pytest.mark.parametrize("signature", ["sha256:" + "a" * 64, "%%%", "a"])
def test_executor_rejects_malformed_local_hash_receipts(
    public_rig: PublicRig,
    signature: str,
) -> None:
    with pytest.raises(SignatureError):
        public_rig.verifier().verify_and_claim(replace(public_rig.receipt(), signature=signature))


@pytest.mark.parametrize("response", [{}, {"lease_id": "invented"}, {"type": "lets.receipt/v1"}])
@pytest.mark.parametrize("operation", ["provision", "authorize"])
def test_public_client_rejects_empty_or_incomplete_authority(
    response: dict[str, Any],
    operation: str,
) -> None:
    def send(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            201 if operation == "provision" else 200, json=response, request=request
        )

    with LETSClient("https://warden.test", transport=httpx.MockTransport(send)) as client:
        authorizer = ReplicaAuthorizer(
            client,
            ReplicaProfile(
                "tenant", "envelope", POLICY.digest, (10,), frozenset({"worker.act"}), 1_000
            ),
        )
        with pytest.raises(RemoteValidationError):
            if operation == "provision":
                authorizer.provision(request_id="provision", replica_id="agent")
            else:
                authorizer.authorize_effect(
                    request_id="effect",
                    lease_id="lease",
                    transition="act",
                    executor_audience="executor",
                    nonce="public-effect-nonce-01",
                )


def test_public_client_rejects_noncanonical_audience_before_transport(
    public_rig: PublicRig,
) -> None:
    before = len(public_rig.transport.requests)
    error: Exception | None = None
    try:
        public_rig.client.authorize(
            public_rig.grant["lease_id"],
            {
                "request_id": "wrong-wire",
                "transition": "act",
                "audience": "executor",
                "nonce": "public-effect-nonce-01",
            },
        )
    except (ValueError, LETSClientError) as caught:
        error = caught
    assert isinstance(error, ValueError), "canonical audience must fail before transport"
    assert len(public_rig.transport.requests) == before


@pytest.mark.parametrize("token", ["stranger-token", "other-tenant-token"])
def test_real_warden_rejects_identity_and_tenant_spoofing(
    public_rig: PublicRig, token: str
) -> None:
    with (
        LETSClient(
            "https://warden.test",
            token=token,
            transport=LocalWardenTransport(public_rig.app),
            retry=RetryPolicy(max_attempts=1),
        ) as client,
        pytest.raises(PermissionDeniedError),
    ):
        client.authorize(
            public_rig.grant["lease_id"],
            {
                "request_id": "unauthorized",
                "transition": "act",
                "executor_audience": "executor",
                "nonce": "public-effect-nonce-01",
            },
        )
    assert public_rig.client.lease(public_rig.grant["lease_id"])["residual"] == [10]


def test_real_warden_rejects_changed_content_under_same_request(public_rig: PublicRig) -> None:
    receipt = public_rig.receipt()
    with pytest.raises(RequestConflictError):
        public_rig.receipt(nonce="changed-effect-nonce-01")
    public_rig.verifier().verify_and_claim(receipt)
    assert public_rig.client.lease(public_rig.grant["lease_id"])["residual"] == [9]


def test_released_public_exports_remain_available() -> None:
    expected = {
        "lets.integrations": {
            "A2ATaskProfile",
            "AstralDeepAuthorizer",
            "AstralDeepProfile",
            "AudienceBinding",
            "AuthorizerClient",
            "ReplicaAuthorizer",
            "ReplicaProfile",
            "TaskLedger",
        },
        "lets.client": {"LETSClient", "RetryPolicy"},
        "lets.executor": {"ExecutorPolicy", "ReceiptVerifier", "SQLiteReceiptReplayStore"},
        "lets.models": {"Receipt", "LeaseGrant"},
    }
    for module_name, symbols in expected.items():
        module = importlib.import_module(module_name)
        assert symbols <= set(vars(module)), f"released exports removed from {module_name}"
        if module_name == "lets.integrations":
            assert symbols <= set(module.__all__)


def test_independent_signed_wire_fixture(tmp_path: Path) -> None:
    encoded = FIXTURE_PATH.read_bytes().rstrip(b"\n")
    wire = strict_json_loads(encoded)
    assert canonical_json(wire) == encoded
    receipt = Receipt.from_dict(wire)
    assert canonical_json(receipt.to_dict()) == encoded
    assert receipt.executor_audience == "executor"
    assert receipt.cost == (1,)
    clock = ManualClock(100)
    registry = PublicKeyRegistry(clock=clock)
    registry.register(
        "warden",
        "warden/ed25519-56475aa75463474c0285df5dbf2bcab7",
        bytes.fromhex("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"),
    )
    verifier = ReceiptVerifier(
        registry,
        SQLiteReceiptReplayStore.initialize(tmp_path / "fixture.sqlite3", allow_unanchored=True),
        ExecutorPolicy(audience="executor"),
        clock=clock,
    )
    verifier.verify_and_claim(receipt)
    with pytest.raises(ValidationError):
        Receipt.from_dict({**wire, "audience": "executor"})
