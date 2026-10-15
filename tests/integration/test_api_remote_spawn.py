"""Tests for the remote-children and peer lease-status routes in src/lets/api.py:
client-authenticated remote spawn reaches the service with the parent path parameter,
and peer-signed lease-status lookups are dispatched with a peer identity.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import httpx

from lets.api import create_app
from lets.auth import (
    PeerMessageAuthenticator,
    SQLitePeerReplayStore,
    StaticBearerAuthenticator,
    sign_peer_headers,
)
from lets.canonical import canonical_json
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.models import IdentityContext


class RemoteSpawnStub:
    warden_id = "warden-b"

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def spawn_remote(self, **arguments: Any) -> Mapping[str, Any]:
        self.calls.append(("spawn_remote", arguments))
        return {
            "authenticated_subject": arguments["identity"].subject_id,
            "parent_id": arguments["parent_id"],
            "target_warden": arguments["target_warden"],
        }

    def peer_lease_status(self, **arguments: Any) -> Mapping[str, Any]:
        self.calls.append(("peer_lease_status", arguments))
        return {
            "authenticated_peer": arguments["identity"].subject_id,
            "lease_id": arguments["lease_id"],
        }


def _request(app: object, method: str, path: str, **options: Any) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="https://node.test") as client:
            return await client.request(method, path, **options)

    return asyncio.run(send())


def test_remote_children_and_peer_lease_status_routes(tmp_path: Path) -> None:
    source = Ed25519Signer.generate("warden-a")
    registry = PublicKeyRegistry()
    registry.register_signer(source)
    identity = IdentityContext(
        subject_id="agent-a",
        tenant_id="tenant-a",
        scopes=frozenset({"lets.lease.manage"}),
        authentication_method="test-bearer",
    )
    service = RemoteSpawnStub()
    app = create_app(
        service,
        authenticator=StaticBearerAuthenticator.single("valid-token", identity),
        peer_authenticator=PeerMessageAuthenticator(
            registry, SQLitePeerReplayStore.initialize(tmp_path / "replay.db")
        ),
        peer_tenant_id="tenant-a",
    )

    spawned = _request(
        app,
        "POST",
        "/v1/leases/lease-parent/remote-children",
        headers={"authorization": "Bearer valid-token"},
        json={
            "request_id": "remote-1",
            "target_warden": "warden-c",
            "subject_id": "agent-a",
            "allocation": [3],
            "capabilities": ["worker.act"],
            "ttl_ns": 1000,
            "expected_sequence": 0,
        },
    )
    assert spawned.status_code == 201
    assert spawned.json() == {
        "authenticated_subject": "agent-a",
        "parent_id": "lease-parent",
        "target_warden": "warden-c",
    }
    name, arguments = service.calls[0]
    assert name == "spawn_remote"
    assert arguments["allocation"] == [3]
    assert arguments["expected_sequence"] == 0

    rejected = _request(
        app,
        "POST",
        "/v1/leases/lease-parent/remote-children",
        headers={"authorization": "Bearer valid-token"},
        json={"request_id": "remote-2", "target_warden": "warden-c"},
    )
    assert rejected.status_code == 422

    path = "/v1/peer/lease-status"
    body = canonical_json({"lease_id": "lease-child"})
    headers = {
        **sign_peer_headers(
            source, method="POST", path=path, body=body, nonce="lease-status-nonce-0001"
        ),
        "content-type": "application/json",
    }
    status = _request(app, "POST", path, content=body, headers=headers)
    assert status.status_code == 200
    assert status.json() == {"authenticated_peer": "warden-a", "lease_id": "lease-child"}
    unsigned = _request(
        app, "POST", path, content=body, headers={"content-type": "application/json"}
    )
    assert unsigned.status_code == 401
