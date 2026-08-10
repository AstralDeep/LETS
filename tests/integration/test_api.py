from __future__ import annotations

import asyncio
import json
import logging
import tomllib
from collections.abc import AsyncIterator, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from jsonschema import Draft202012Validator

import deploy.start_warden as start_warden_module
import lets.cli as cli_module
from lets import __version__
from lets.api import create_app
from lets.auth import (
    PeerMessageAuthenticator,
    SQLitePeerReplayStore,
    StaticBearerAuthenticator,
    sign_peer_headers,
)
from lets.canonical import b64url_encode, canonical_json
from lets.cli import main as cli_main
from lets.client import (
    LETSClient,
    PermissionDeniedError,
    RetryPolicy,
)
from lets.clock import SystemClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import ClockUncertainError, PolicyError, SignatureError, ValidationError
from lets.manifest import (
    ClusterManifest,
    ManifestPublicKey,
    ManifestSignature,
    WardenManifest,
)
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


class StubService:
    warden_id = "warden-b"

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def issue_root(self, **arguments: Any) -> Mapping[str, Any]:
        self.calls.append(("issue_root", arguments))
        identity = arguments["identity"]
        return {"authenticated_subject": identity.subject_id, "lease_id": "lease-1"}

    def register_policy(self, policy: object, *, identity: IdentityContext) -> str:
        self.calls.append(("register_policy", {"policy": policy, "identity": identity}))
        return "sha256:" + "1" * 64

    def accept_transfer(self, **arguments: Any) -> Mapping[str, Any]:
        self.calls.append(("accept_transfer", arguments))
        identity = arguments["identity"]
        voucher = arguments["voucher"]
        return {
            "authenticated_peer": identity.subject_id,
            "source_warden": voucher["source_warden"],
            "sequence": voucher["sequence"],
        }

    def ingest_revocation(self, **arguments: Any) -> Mapping[str, Any]:
        self.calls.append(("ingest_revocation", arguments))
        return {
            "authenticated_peer": arguments["identity"].subject_id,
            "issuer_warden": arguments["revocation"]["issuer_warden"],
        }

    def invariant_snapshot(self, **arguments: Any) -> object:
        del arguments
        raise ClockUncertainError("clock is outside its configured safety bound")


def _identity(*, admin: bool = True) -> IdentityContext:
    return IdentityContext(
        subject_id="operator-a",
        tenant_id="tenant-a",
        scopes=frozenset({"lets.admin"}) if admin else frozenset(),
        authentication_method="test-bearer",
    )


def _request(app: object, method: str, path: str, **options: Any) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(  # type: ignore[arg-type]
            app=app,
            raise_app_exceptions=False,
        )
        async with httpx.AsyncClient(transport=transport, base_url="https://node.test") as client:
            return await client.request(method, path, **options)

    return asyncio.run(send())


def _root_payload() -> dict[str, Any]:
    return {
        "request_id": "request-1",
        "tenant_id": "tenant-a",
        "envelope_id": "envelope-a",
        "subject_id": "agent-a",
        "allocation": [10],
        "capabilities": ["effect.use"],
        "policy_digest": "sha256:" + "1" * 64,
        "ttl_ns": 1_000_000,
    }


def test_actual_asgi_client_auth_identity_and_problem_response() -> None:
    service = StubService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )

    denied = _request(app, "POST", "/v1/roots", json=_root_payload())
    assert denied.status_code == 401
    assert denied.headers["content-type"].startswith("application/problem+json")
    assert denied.headers["x-request-id"] == denied.json()["request_id"]
    assert denied.headers["cache-control"] == "no-store"

    accepted = _request(
        app,
        "POST",
        "/v1/roots",
        json=_root_payload(),
        headers={"authorization": "Bearer valid-token", "x-request-id": "trace-1"},
    )
    assert accepted.status_code == 201
    assert accepted.json()["authenticated_subject"] == "operator-a"
    assert accepted.headers["x-request-id"] == "trace-1"
    assert service.calls[0][1]["identity"] == _identity()


def test_actual_warden_service_over_asgi_registers_policy_and_issues_root(
    tmp_path: Path,
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        tmp_path / "warden.sqlite3",
        "warden-a",
        (20,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        receipt_ttl_ns=10_000,
        max_clock_uncertainty_ns=1_000_000,
    )
    policy = PolicySpec(
        policy_id="runtime",
        policy_version="v1",
        dimensions=(ResourceDimension("actions", "count"),),
        machine=MachineSpec(
            machine_id="agent",
            initial_state="ready",
            transitions=(TransitionSpec("run", "ready", "ready", (1,), "agent.run"),),
        ),
        max_lease_ttl_ns=1_000_000_000,
        receipt_ttl_ns=10_000,
        max_clock_uncertainty_ns=1_000_000,
        transfer_gap_window=64,
    )
    try:
        service = WardenService(store, signer=signer)
        app = create_app(
            service,
            authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
            signer=signer,
        )
        rejected = _request(
            app,
            "POST",
            "/v1/policies",
            json={**policy.to_dict(), "unexpected": True},
            headers={"authorization": "Bearer valid-token"},
        )
        assert rejected.status_code == 422
        registered = _request(
            app,
            "POST",
            "/v1/policies",
            json=policy.to_dict(),
            headers={"authorization": "Bearer valid-token"},
        )
        assert registered.status_code == 201
        issued = _request(
            app,
            "POST",
            "/v1/roots",
            json={
                **_root_payload(),
                "capabilities": ["agent.run"],
                "policy_digest": registered.json()["policy_digest"],
            },
            headers={"authorization": "Bearer valid-token"},
        )
        assert issued.status_code == 201, issued.text
        assert issued.json()["subject_id"] == "agent-a"
        assert issued.json()["allocation"] == [10]
    finally:
        store.close()


def test_policy_registration_requires_transport_admin_scope() -> None:
    service = StubService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("user-token", _identity(admin=False)),
    )

    response = _request(
        app,
        "POST",
        "/v1/policies",
        json={"policy_version": "v1"},
        headers={"authorization": "Bearer user-token"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "policy_denied"
    assert service.calls == []


def test_authority_fence_endpoint_requires_admin_and_exact_string_identifiers() -> None:
    calls: list[tuple[str, str]] = []

    def fence(restart_id: str, expected_lifetime_id: str) -> Mapping[str, object]:
        calls.append((restart_id, expected_lifetime_id))
        return {
            "schema": "lets.authority-admission-fence/v1",
            "restart_id": restart_id,
            "lifetime_id": expected_lifetime_id,
        }

    service = StubService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("admin-token", _identity()),
        authority_fence_provider=fence,
    )
    body = {"restart_id": "restart-1", "expected_lifetime_id": "a" * 32}
    accepted = _request(
        app,
        "POST",
        "/v1/maintenance/authority-fence",
        json=body,
        headers={"authorization": "Bearer admin-token"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["restart_id"] == "restart-1"
    assert calls == [("restart-1", "a" * 32)]

    for malformed in (
        {**body, "restart_id": 7},
        {**body, "expected_lifetime_id": True},
    ):
        rejected = _request(
            app,
            "POST",
            "/v1/maintenance/authority-fence",
            json=malformed,
            headers={"authorization": "Bearer admin-token"},
        )
        assert rejected.status_code == 422
    assert calls == [("restart-1", "a" * 32)]

    denied_app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("user-token", _identity(admin=False)),
        authority_fence_provider=fence,
    )
    denied = _request(
        denied_app,
        "POST",
        "/v1/maintenance/authority-fence",
        json=body,
        headers={"authorization": "Bearer user-token"},
    )
    assert denied.status_code == 403


def test_authority_status_endpoint_is_independent_of_database_metrics() -> None:
    authority = {
        "enabled": True,
        "state": "permanent_fault",
        "healthy": False,
        "lifetime_id": "a" * 32,
        "first_fault": {"reason": "helper_eof"},
    }

    def unavailable_metrics() -> Mapping[str, object]:
        raise RuntimeError("database must not be opened")

    metrics_identity = IdentityContext(
        subject_id="monitor-a",
        tenant_id="tenant-a",
        scopes=frozenset({"lets.metrics.read"}),
        authentication_method="test-bearer",
    )
    app = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("metrics-token", metrics_identity),
        metrics_provider=unavailable_metrics,
        authority_status_provider=lambda: authority,
    )

    response = _request(
        app,
        "GET",
        "/v1/maintenance/authority-status",
        headers={"authorization": "Bearer metrics-token"},
    )

    assert response.status_code == 200
    assert response.json() == authority

    denied = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("user-token", _identity(admin=False)),
        authority_status_provider=lambda: authority,
    )
    response = _request(
        denied,
        "GET",
        "/v1/maintenance/authority-status",
        headers={"authorization": "Bearer user-token"},
    )
    assert response.status_code == 403


def test_liveness_readiness_and_error_hierarchy_mapping() -> None:
    service = StubService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
        readiness_check=lambda: False,
    )

    assert _request(app, "GET", "/health/live").status_code == 200
    not_ready = _request(app, "GET", "/health/ready")
    assert not_ready.status_code == 503
    assert not_ready.json()["code"] == "not_ready"
    clock = _request(
        app,
        "GET",
        "/v1/invariants",
        headers={"authorization": "Bearer valid-token"},
    )
    assert clock.status_code == 503
    assert clock.json()["code"] == "clock_uncertain"


def test_request_path_readiness_and_metrics_do_not_run_deep_pragma_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signer = Ed25519Signer.generate("warden-a")
    store = SQLiteStorage.initialize(
        tmp_path / "bounded-readiness.sqlite3",
        signer.warden_id,
        (20,),
        signing_key_id=signer.key_id,
        signing_public_key=signer.public_key_bytes,
        tenant_id="tenant-a",
        envelope_id="envelope-a",
    )
    try:
        service = WardenService(store, signer=signer)

        def forbidden_deep_scan() -> object:
            raise AssertionError("request path invoked a deep SQLite PRAGMA scan")

        monkeypatch.setattr(store, "pragma_integrity_check", forbidden_deep_scan)
        monkeypatch.setattr(store, "pragma_foreign_key_check", forbidden_deep_scan)
        assert service.ready()
        metrics = cli_module._metrics_provider(service, store, _identity())
        assert metrics["ready"] is True
        assert metrics["invariant_healthy"] is True
    finally:
        store.close()


def test_signed_peer_body_tamper_and_durable_replay(tmp_path: Path) -> None:
    source = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    registry.register_signer(source)
    peer_auth = PeerMessageAuthenticator(
        registry, SQLitePeerReplayStore.initialize(tmp_path / "replay.db")
    )
    service = StubService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
        peer_authenticator=peer_auth,
        peer_tenant_id="tenant-a",
    )
    path = "/v1/transfers/warden-a/7/accept"
    voucher = {"source_warden": "warden-a", "sequence": 7, "amount": [2]}
    body = canonical_json(voucher)
    headers = {
        **sign_peer_headers(
            source,
            method="POST",
            path=path,
            body=body,
            nonce="signed-request-nonce-0001",
        ),
        "content-type": "application/json",
    }

    accepted = _request(app, "POST", path, content=body, headers=headers)
    assert accepted.status_code == 200
    assert accepted.json()["authenticated_peer"] == "warden-a"

    replay = _request(app, "POST", path, content=body, headers=headers)
    assert replay.status_code == 409
    assert replay.json()["code"] == "replay_detected"

    other_headers = {
        **sign_peer_headers(
            source,
            method="POST",
            path=path,
            body=body,
            nonce="signed-request-nonce-0002",
        ),
        "content-type": "application/json",
    }
    tampered = canonical_json({**voucher, "amount": [200]})
    rejected = _request(app, "POST", path, content=tampered, headers=other_headers)
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "invalid_signature"

    duplicate_path = "/v1/transfers/warden-a/8/accept"
    duplicate_body = b'{"source_warden":"warden-a","source_warden":"warden-a","sequence":8}'
    duplicate_headers = {
        **sign_peer_headers(
            source,
            method="POST",
            path=duplicate_path,
            body=duplicate_body,
            nonce="signed-request-nonce-0003",
        ),
        "content-type": "application/json",
    }
    duplicate = _request(
        app,
        "POST",
        duplicate_path,
        content=duplicate_body,
        headers=duplicate_headers,
    )
    assert duplicate.status_code == 422
    assert duplicate.json()["code"] == "validation_error"

    relay_path = "/v1/peer/revocations"
    relay_body = canonical_json({"issuer_warden": "warden-owner", "branch_lease_id": "lease-owned"})
    relay_headers = {
        **sign_peer_headers(
            source,
            method="POST",
            path=relay_path,
            body=relay_body,
            nonce="signed-request-nonce-0004",
        ),
        "content-type": "application/json",
    }
    relayed = _request(app, "POST", relay_path, content=relay_body, headers=relay_headers)
    assert relayed.status_code == 200
    assert relayed.json() == {
        "authenticated_peer": "warden-a",
        "issuer_warden": "warden-owner",
    }


def test_sync_client_retries_idempotent_calls_only_and_maps_problems() -> None:
    attempts = 0

    def retry_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(
                503,
                json={
                    "type": "urn:lets:problem:storage_error",
                    "title": "Service Unavailable",
                    "status": 503,
                    "detail": "try another node",
                    "code": "storage_error",
                },
                request=request,
            )
        return httpx.Response(201, json={"lease_id": "lease-1"}, request=request)

    client = LETSClient(
        "https://node.test",
        token="token",
        transport=httpx.MockTransport(retry_handler),
        retry=RetryPolicy(max_attempts=2, initial_backoff_s=0),
        sleep=lambda _: None,
    )
    assert client.issue_root(_root_payload())["lease_id"] == "lease-1"
    assert attempts == 2
    client.close()

    denied_attempts = 0

    def denial(request: httpx.Request) -> httpx.Response:
        nonlocal denied_attempts
        denied_attempts += 1
        return httpx.Response(
            403,
            json={
                "type": "urn:lets:problem:policy_denied",
                "title": "Request Denied",
                "status": 403,
                "detail": "scope denied",
                "code": "policy_denied",
            },
            request=request,
        )

    denied_client = LETSClient(
        "https://node.test",
        transport=httpx.MockTransport(denial),
        retry=RetryPolicy(max_attempts=3, initial_backoff_s=0),
    )
    with pytest.raises(PermissionDeniedError):
        denied_client._request("POST", "/unsafe", payload={}, idempotent=False)
    assert denied_attempts == 1
    denied_client.close()


def test_authenticated_policy_problem_from_service_is_consistent() -> None:
    class DenyingService(StubService):
        def issue_root(self, **arguments: Any) -> Mapping[str, Any]:
            del arguments
            raise PolicyError("allocation denied")

    app = create_app(
        DenyingService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )
    response = _request(
        app,
        "POST",
        "/v1/roots",
        json=_root_payload(),
        headers={"authorization": "Bearer valid-token"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "policy_denied"
    assert response.json()["type"] == "urn:lets:problem:policy_denied"


def test_json_boundary_rejects_duplicate_keys_and_non_finite_constants() -> None:
    app = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )
    base_headers = {
        "authorization": "Bearer valid-token",
        "content-type": "application/json",
    }
    duplicate = _request(
        app,
        "POST",
        "/v1/roots",
        content=(
            b'{"request_id":"one","request_id":"two","tenant_id":"tenant-a",'
            b'"envelope_id":"envelope-a","subject_id":"agent-a","allocation":[1],'
            b'"capabilities":[],"policy_digest":"sha256:' + b"1" * 64 + b'","ttl_ns":1}'
        ),
        headers=base_headers,
    )
    assert duplicate.status_code == 422
    non_finite = _request(
        app,
        "POST",
        "/v1/roots",
        content=(
            b'{"request_id":"one","tenant_id":"tenant-a",'
            b'"envelope_id":"envelope-a","subject_id":"agent-a","allocation":[NaN],'
            b'"capabilities":[],"policy_digest":"sha256:' + b"1" * 64 + b'","ttl_ns":1}'
        ),
        headers=base_headers,
    )
    assert non_finite.status_code == 422

    nested_duplicate = _request(
        app,
        "POST",
        "/v1/envelopes",
        content=(
            b'{"tenant_id":"tenant-a","envelope_id":"envelope-a",'
            b'"config_epoch":1,"budget":[1],"local_share":[1],'
            b'"config":{"signed":1,"signed":2}}'
        ),
        headers=base_headers,
    )
    assert nested_duplicate.status_code == 422

    floating = _request(
        app,
        "POST",
        "/v1/roots",
        content=(
            b'{"request_id":"one","tenant_id":"tenant-a",'
            b'"envelope_id":"envelope-a","subject_id":"agent-a",'
            b'"allocation":[1.5],"capabilities":[],"policy_digest":"sha256:'
            + b"1" * 64
            + b'","ttl_ns":1}'
        ),
        headers=base_headers,
    )
    assert floating.status_code == 422

    lone_surrogate = _request(
        app,
        "POST",
        "/v1/roots",
        content=(
            b'{"request_id":"one","tenant_id":"tenant-a",'
            b'"envelope_id":"envelope-a","subject_id":"\\ud800",'
            b'"allocation":[1],"capabilities":[],"policy_digest":"sha256:'
            + b"1" * 64
            + b'","ttl_ns":1}'
        ),
        headers=base_headers,
    )
    assert lone_surrogate.status_code == 422


def test_body_limit_runs_before_client_and_peer_authentication(tmp_path: Path) -> None:
    signer = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    registry.register_signer(signer)
    app = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
        peer_authenticator=PeerMessageAuthenticator(
            registry,
            SQLitePeerReplayStore.initialize(tmp_path / "body-limit-replay.sqlite3"),
        ),
        peer_tenant_id="tenant-a",
        maximum_body_bytes=64,
    )
    client = _request(
        app,
        "POST",
        "/v1/roots",
        content=b"x" * 65,
        headers={"content-type": "application/json"},
    )
    assert client.status_code == 413

    peer = _request(
        app,
        "POST",
        "/v1/transfers/warden-a/1/accept",
        content=b"x" * 65,
        headers={"content-type": "application/json"},
    )
    assert peer.status_code == 413


def test_slow_chunked_body_times_out_before_authentication_and_closes_connection() -> None:
    class CountingAuthenticator:
        def __init__(self) -> None:
            self.calls = 0

        def authenticate(self, request: object) -> IdentityContext:
            del request
            self.calls += 1
            return _identity()

    class SlowChunkedBody(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            yield b"{"
            await asyncio.sleep(0.3)
            yield b"}"

    service = StubService()
    authenticator = CountingAuthenticator()
    app = create_app(
        service,
        authenticator=authenticator,
        request_body_timeout_s=0.05,
    )

    timed_out = _request(
        app,
        "POST",
        "/v1/roots",
        content=SlowChunkedBody(),
        headers={"content-type": "application/json"},
    )

    assert timed_out.status_code == 408
    assert timed_out.headers["connection"] == "close"
    assert timed_out.json()["type"] == "urn:lets:problem:request_body_timeout"
    assert timed_out.json()["title"] == "Request Timeout"
    assert timed_out.json()["code"] == "request_body_timeout"
    assert authenticator.calls == 0
    assert service.calls == []

    accepted = _request(
        app,
        "POST",
        "/v1/roots",
        json=_root_payload(),
        headers={"authorization": "Bearer valid-token"},
    )
    assert accepted.status_code == 201
    assert authenticator.calls == 1
    assert service.calls[0][0] == "issue_root"


def test_client_disconnect_during_body_is_quiet_and_never_authenticates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class CountingAuthenticator:
        def __init__(self) -> None:
            self.calls = 0

        def authenticate(self, request: object) -> IdentityContext:
            del request
            self.calls += 1
            return _identity()

    service = StubService()
    authenticator = CountingAuthenticator()
    app = create_app(service, authenticator=authenticator, request_body_timeout_s=1)
    sent: list[dict[str, Any]] = []
    incoming = iter(
        (
            {"type": "http.request", "body": b"{", "more_body": True},
            {"type": "http.disconnect"},
        )
    )

    async def receive() -> dict[str, Any]:
        return next(incoming)

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope: dict[str, Any] = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/v1/roots",
        "raw_path": b"/v1/roots",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "client": ("127.0.0.1", 12345),
        "server": ("warden", 8443),
    }

    with caplog.at_level(logging.ERROR, logger="lets.api"):
        asyncio.run(app(scope, receive, send))

    assert authenticator.calls == 0
    assert service.calls == []
    assert "unhandled LETS API error" not in caplog.text
    starts = [message for message in sent if message["type"] == "http.response.start"]
    assert starts and starts[0]["status"] == 400


@pytest.mark.parametrize(
    "timeout",
    [True, "30", 0, -1, float("nan"), float("inf"), 300.001],
)
def test_request_body_timeout_must_be_a_finite_bounded_number(timeout: object) -> None:
    with pytest.raises(ValueError, match="request_body_timeout_s"):
        create_app(
            StubService(),
            authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
            request_body_timeout_s=timeout,  # type: ignore[arg-type]
        )


def test_unexpected_api_error_is_logged_without_request_body(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class CrashingService(StubService):
        def issue_root(self, **arguments: Any) -> Mapping[str, Any]:
            del arguments
            raise RuntimeError("diagnostic marker")

    app = create_app(
        CrashingService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )
    with caplog.at_level(logging.ERROR, logger="lets.api"):
        response = _request(
            app,
            "POST",
            "/v1/roots",
            json=_root_payload(),
            headers={
                "authorization": "Bearer valid-token",
                "x-request-id": "logging-request",
            },
        )

    assert response.status_code == 500
    assert response.json()["detail"] == "the warden could not complete the request"
    assert "logging-request" in caplog.text
    assert "/v1/roots" in caplog.text
    assert "agent-a" not in caplog.text


def test_reclaim_route_and_openapi_return_a_resource_vector() -> None:
    class ReclaimService(StubService):
        def reclaim_expired(self, **arguments: Any) -> tuple[int, ...]:
            self.calls.append(("reclaim_expired", arguments))
            return (3, 5)

    service = ReclaimService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )

    response = _request(
        app,
        "POST",
        "/v1/maintenance/reclaim",
        json={},
        headers={"authorization": "Bearer valid-token"},
    )

    assert response.status_code == 200
    assert response.json() == {"reclaimed": [3, 5]}
    assert service.calls[0][0] == "reclaim_expired"

    document = _request(app, "GET", "/v1/openapi.json").json()
    reclaim_schema = document["components"]["schemas"]["ReclaimResult"]
    assert reclaim_schema["properties"]["reclaimed"] == {
        "$ref": "#/components/schemas/ResourceVector"
    }
    Draft202012Validator(document["components"]["schemas"]["ResourceVector"]).validate(
        response.json()["reclaimed"]
    )


def test_runtime_drain_control_has_strict_authenticated_wire_contract() -> None:
    class RuntimeService(StubService):
        def runtime_status(self, **arguments: Any) -> dict[str, object]:
            self.calls.append(("runtime_status", arguments))
            return {
                "mode": "ACTIVE",
                "generation": 0,
                "reason": "schema initialization",
                "changed_at_ns": 0,
                "changed_by": "lets-migration",
            }

        def set_runtime_mode(self, **arguments: Any) -> dict[str, object]:
            self.calls.append(("set_runtime_mode", arguments))
            if arguments["mode"] not in {"ACTIVE", "DRAINING"}:
                raise ValidationError("runtime mode must be ACTIVE or DRAINING")
            return {
                "mode": arguments["mode"],
                "generation": 1,
                "reason": arguments["reason"],
                "changed_at_ns": 10,
                "changed_by": arguments["identity"].subject_id,
            }

    service = RuntimeService()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )
    headers = {"authorization": "Bearer valid-token"}

    status = _request(app, "GET", "/v1/maintenance/runtime", headers=headers)
    assert status.status_code == 200
    assert status.json()["mode"] == "ACTIVE"
    changed = _request(
        app,
        "POST",
        "/v1/maintenance/runtime",
        headers=headers,
        json={
            "request_id": "drain-request",
            "mode": "DRAINING",
            "reason": "planned upgrade",
        },
    )
    assert changed.status_code == 200
    assert changed.json() == {
        "mode": "DRAINING",
        "generation": 1,
        "reason": "planned upgrade",
        "changed_at_ns": 10,
        "changed_by": "operator-a",
    }
    invalid = _request(
        app,
        "POST",
        "/v1/maintenance/runtime",
        headers=headers,
        json={"request_id": "bad", "mode": "PAUSED", "reason": "not supported"},
    )
    assert invalid.status_code == 422
    document = _request(app, "GET", "/v1/openapi.json").json()
    runtime_path = document["paths"]["/v1/maintenance/runtime"]
    assert runtime_path["post"]["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RuntimeModeRequest"
    }
    assert runtime_path["get"]["responses"]["200"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/RuntimeStatus"
    }


def test_openapi_exports_strict_body_and_security_contracts() -> None:
    app = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )

    document = _request(app, "GET", "/v1/openapi.json").json()

    issue = document["paths"]["/v1/roots"]["post"]
    assert issue["requestBody"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/IssueRootRequest"
    }
    assert issue["security"] == [{"bearerAuth": []}]
    peer = document["paths"]["/v1/transfers/{source_warden}/{sequence}/accept"]["post"]
    assert peer["security"] == [
        {
            "peerWardenId": [],
            "peerKeyId": [],
            "peerTimestamp": [],
            "peerNonce": [],
            "peerContentSha256": [],
            "peerSignature": [],
        }
    ]
    assert "application/problem+json" in peer["responses"]["default"]["content"]
    published = json.loads(
        (Path(__file__).parents[2] / "protocol" / "openapi.yaml").read_text(encoding="utf-8")
    )
    assert document == published
    project = tomllib.loads(
        (Path(__file__).parents[2] / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert document["info"]["version"] == __version__ == project["project"]["version"]


def test_openapi_matches_problem_validation_and_transport_identifier_runtime() -> None:
    app = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )
    document = _request(app, "GET", "/v1/openapi.json").json()
    schemas = document["components"]["schemas"]

    assert "HTTPValidationError" not in schemas
    assert "ValidationError" not in schemas
    assert schemas["WardenId"]["pattern"] == r"^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$"
    assert schemas["KeyId"]["pattern"] == r"^[A-Za-z0-9][A-Za-z0-9._~:/+-]{0,511}$"

    peer = document["paths"]["/v1/transfers/{source_warden}/{sequence}/accept"]["post"]
    parameters = {parameter["name"]: parameter for parameter in peer["parameters"]}
    assert parameters["source_warden"]["schema"] == {"$ref": "#/components/schemas/WardenId"}
    assert parameters["sequence"]["schema"] == {"type": "integer", "minimum": 1}
    assert peer["responses"]["422"] == {
        "description": "RFC 9457 LETS validation problem",
        "content": {
            "application/problem+json": {"schema": {"$ref": "#/components/schemas/Problem"}}
        },
    }
    assert schemas["CheckpointRequest"]["properties"]["through_sequence"]["minimum"] == 1

    invalid_sequence = _request(
        app,
        "POST",
        "/v1/transfers/warden-a/0/accept",
        json={},
    )
    assert invalid_sequence.status_code == 422
    assert invalid_sequence.headers["content-type"].startswith("application/problem+json")
    assert invalid_sequence.json()["code"] == "validation_error"

    invalid_warden = _request(
        app,
        "POST",
        "/v1/transfers/-warden-a/1/accept",
        json={},
    )
    assert invalid_warden.status_code == 422
    assert invalid_warden.headers["content-type"].startswith("application/problem+json")


def test_openapi_requires_all_six_peer_headers_and_typed_successes() -> None:
    app = create_app(
        StubService(),
        authenticator=StaticBearerAuthenticator.single("valid-token", _identity()),
    )
    document = _request(app, "GET", "/v1/openapi.json").json()
    schemes = document["components"]["securitySchemes"]
    expected_headers = {
        "peerWardenId": "X-LETS-Warden-ID",
        "peerKeyId": "X-LETS-Key-ID",
        "peerTimestamp": "X-LETS-Timestamp",
        "peerNonce": "X-LETS-Nonce",
        "peerContentSha256": "X-LETS-Content-SHA256",
        "peerSignature": "X-LETS-Signature",
    }
    assert {name: schemes[name]["name"] for name in expected_headers} == expected_headers

    required_together = {name: [] for name in expected_headers}
    for path in (
        "/v1/transfers/{source_warden}/{sequence}/accept",
        "/v1/transfers/{target_warden}/{sequence}/finalize",
        "/v1/peer/revocations",
        "/v1/peer/transfer-checkpoints",
    ):
        assert document["paths"][path]["post"]["security"] == [required_together]

    for path_item in document["paths"].values():
        for operation in path_item.values():
            if not isinstance(operation, dict) or "responses" not in operation:
                continue
            for status, response in operation["responses"].items():
                if status.startswith("2"):
                    schema = response["content"]["application/json"]["schema"]
                    assert schema.get("$ref", "").startswith("#/components/schemas/")


def test_manifest_cli_bootstrap_preloads_peer_trust_policy_and_verified_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_signer = Ed25519Signer.generate("warden-a")
    peer_signer = Ed25519Signer.generate("warden-b")
    operator = Ed25519Signer.generate("operator-a")
    seed_path = tmp_path / "local.seed"
    local_signer.save_seed_file(seed_path)
    resources = (ResourceDimension("actions", "count"),)
    policy = PolicySpec(
        policy_id="runtime",
        policy_version="v1",
        dimensions=resources,
        machine=MachineSpec(
            machine_id="agent",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    name="run",
                    source="ready",
                    target="ready",
                    cost=(1,),
                    capability="agent.run",
                ),
            ),
        ),
        max_lease_ttl_ns=1_000_000,
        receipt_ttl_ns=10_000,
        max_clock_uncertainty_ns=100,
        transfer_gap_window=64,
    )
    unsigned = ClusterManifest(
        tenant_id="tenant-a",
        envelope_id="envelope-a",
        config_epoch=1,
        created_at="2026-08-09T05:00:00Z",
        resources=resources,
        initial_budget=(100,),
        wardens=(
            WardenManifest(
                "warden-a",
                "https://warden-a:8741",
                "https://warden-a:8741",
                (60,),
                (ManifestPublicKey(local_signer.key_id, local_signer.public_key_bytes),),
                {},
            ),
            WardenManifest(
                "warden-b",
                "https://warden-b:8741",
                "https://warden-b:8741",
                (40,),
                (ManifestPublicKey(peer_signer.key_id, peer_signer.public_key_bytes),),
                {},
            ),
        ),
        policies=(policy,),
        extensions={},
    )
    manifest = replace(
        unsigned,
        signatures=(
            ManifestSignature(
                operator.key_id,
                operator.sign(canonical_json(unsigned.unsigned_dict())),
            ),
        ),
    )
    manifest_path = tmp_path / "cluster.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()), encoding="utf-8")
    config_path = tmp_path / "node" / "config.json"

    for label, validity in (
        ("expired", {"not_after": "2000-01-01T00:00:00Z"}),
        ("future", {"not_before": "2200-01-01T00:00:00Z"}),
    ):
        invalid_unsigned = replace(
            unsigned,
            wardens=(
                replace(
                    unsigned.wardens[0],
                    keys=(
                        ManifestPublicKey(
                            local_signer.key_id,
                            local_signer.public_key_bytes,
                            **validity,
                        ),
                    ),
                ),
                unsigned.wardens[1],
            ),
        )
        invalid_manifest = replace(
            invalid_unsigned,
            signatures=(
                ManifestSignature(
                    operator.key_id,
                    operator.sign(canonical_json(invalid_unsigned.unsigned_dict())),
                ),
            ),
        )
        invalid_manifest_path = tmp_path / f"{label}-cluster.json"
        invalid_manifest_path.write_text(
            json.dumps(invalid_manifest.to_dict()),
            encoding="utf-8",
        )
        invalid_config_path = tmp_path / f"{label}-node" / "config.json"
        with pytest.raises(SystemExit):
            cli_main(
                [
                    "--config",
                    str(invalid_config_path),
                    "init",
                    "--warden-id",
                    "warden-a",
                    "--manifest",
                    str(invalid_manifest_path),
                    "--operator-key",
                    f"{operator.key_id}={b64url_encode(operator.public_key_bytes)}",
                    "--signing-seed-file",
                    str(seed_path),
                ]
            )
        assert not invalid_config_path.parent.exists()

    result = cli_main(
        [
            "--config",
            str(config_path),
            "init",
            "--warden-id",
            "warden-a",
            "--manifest",
            str(manifest_path),
            "--operator-key",
            f"{operator.key_id}={b64url_encode(operator.public_key_bytes)}",
            "--signing-seed-file",
            str(seed_path),
        ]
    )

    assert result == 0
    config = json.loads(config_path.read_text(encoding="utf-8"))
    assert config["manifest_digest"] == manifest.digest
    assert config["local_share"] == [60]
    assert config["trusted_peers"] == [
        {
            "warden_id": "warden-b",
            "key_id": peer_signer.key_id,
            "public_key": b64url_encode(peer_signer.public_key_bytes),
        }
    ]
    assert config["operator_trust"]["accepted_signatures"] == [operator.key_id]
    runtime_registry = cli_module._manifest_trust_registry(
        config,
        local_signer,
        clock=SystemClock(declared_uncertainty_ns=0),
    )
    proof = b"manifest-derived-peer-trust"
    assert runtime_registry.verify(
        "warden-b",
        peer_signer.key_id,
        proof,
        peer_signer.sign(proof),
    )
    future_unsigned = replace(
        unsigned,
        wardens=(
            replace(
                unsigned.wardens[0],
                keys=(
                    ManifestPublicKey(
                        local_signer.key_id,
                        local_signer.public_key_bytes,
                        not_before="2200-01-01T00:00:00Z",
                    ),
                ),
            ),
            unsigned.wardens[1],
        ),
    )
    future_manifest = replace(
        future_unsigned,
        signatures=(
            ManifestSignature(
                operator.key_id,
                operator.sign(canonical_json(future_unsigned.unsigned_dict())),
            ),
        ),
    )
    future_manifest_path = tmp_path / "future-cluster.json"
    future_manifest_path.write_text(json.dumps(future_manifest.to_dict()), encoding="utf-8")
    future_config = json.loads(json.dumps(config))
    future_config["manifest"] = str(future_manifest_path)
    future_config["manifest_digest"] = future_manifest.digest
    with pytest.raises(SignatureError, match="validity interval"):
        cli_module._manifest_trust_registry(
            future_config,
            local_signer,
            clock=SystemClock(declared_uncertainty_ns=0),
        )
    operator_path = tmp_path / "operator.json"
    operator_path.write_text(
        json.dumps(
            {
                "key_id": operator.key_id,
                "public_key": b64url_encode(operator.public_key_bytes),
                "threshold": 1,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SignatureError, match="validity interval"):
        start_warden_module._verify_manifest(
            config_path,
            future_config,
            future_manifest_path,
            operator_path,
        )
    drifted_peers = dict(config)
    drifted_peers["trusted_peers"] = []
    with pytest.raises(ValidationError, match="does not exactly match"):
        cli_module._manifest_trust_registry(
            drifted_peers,
            local_signer,
            clock=SystemClock(declared_uncertainty_ns=0),
        )
    drifted_operator = json.loads(json.dumps(config))
    drifted_operator["operator_trust"]["keys"][0]["public_key"] = b64url_encode(
        peer_signer.public_key_bytes
    )
    with pytest.raises(ValidationError, match="roles must use disjoint"):
        cli_module._manifest_trust_registry(
            drifted_operator,
            local_signer,
            clock=SystemClock(declared_uncertainty_ns=0),
        )
    aliased_operator = json.loads(json.dumps(config))
    aliased_operator["operator_trust"]["keys"].append(
        {
            "key_id": "operator-alias",
            "public_key": b64url_encode(operator.public_key_bytes),
        }
    )
    with pytest.raises(ValidationError, match="aliases must not reuse"):
        cli_module._manifest_trust_registry(
            aliased_operator,
            local_signer,
            clock=SystemClock(declared_uncertainty_ns=0),
        )
    assert cli_main(["--config", str(config_path), "info"]) == 0
    backup_path = tmp_path / "backup.sqlite3"
    assert cli_main(["--config", str(config_path), "backup", "--output", str(backup_path)]) == 0
    assert backup_path.is_file()

    race_path = tmp_path / "race.sqlite3"
    original_link = cli_module.os.link

    def create_racer_before_link(source: str, destination: Path) -> None:
        Path(destination).write_bytes(b"racer-owned-content")
        original_link(source, destination)

    monkeypatch.setattr(cli_module.os, "link", create_racer_before_link)
    with pytest.raises(SystemExit):
        cli_main(["--config", str(config_path), "backup", "--output", str(race_path)])
    assert race_path.read_bytes() == b"racer-owned-content"
