from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from lets.errors import PolicyError, ValidationError
from lets.integrations import (
    AstralDeepAuthorizer,
    AstralDeepProfile,
    ReplicaAuthorizer,
    ReplicaProfile,
)


class RecordingClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str | None, dict[str, Any]]] = []

    def _record(
        self,
        operation: str,
        lease_id: str | None,
        payload: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        copied = dict(payload)
        self.calls.append((operation, lease_id, copied))
        return {"operation": operation, "lease_id": lease_id, "payload": copied}

    def issue_root(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("issue_root", None, payload)

    def spawn(self, parent_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("spawn", parent_id, payload)

    def authorize(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("authorize", lease_id, payload)

    def renew(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("renew", lease_id, payload)

    def quiesce(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("quiesce", lease_id, payload)

    def resume(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("resume", lease_id, payload)

    def close_lease(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("close", lease_id, payload)

    def revoke_branch(self, lease_id: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._record("revoke", lease_id, payload)


def _replicas(client: RecordingClient) -> ReplicaAuthorizer:
    return ReplicaAuthorizer(
        client,
        ReplicaProfile(
            tenant_id="tenant-a",
            envelope_id="agents",
            policy_digest="sha256:" + "1" * 64,
            default_allocation=(100, 10_000),
            default_capabilities=frozenset({"astral.tools.read", "astral.tools.execute"}),
            default_ttl_ns=1_000_000,
        ),
    )


def test_replica_adapter_maps_root_and_child_without_copying_opaque_state() -> None:
    client = RecordingClient()
    adapter = _replicas(client)

    adapter.provision(
        request_id="operation-root",
        replica_id="agent-root",
        capabilities={"astral.tools.read"},
        lineage_id="lineage-a",
    )
    adapter.replicate(
        request_id="operation-child",
        parent_lease_id="lease-root",
        replica_id="agent-child",
        allocation=(10, 100),
        capabilities={"astral.tools.read"},
        ttl_ns=1000,
        expected_sequence=3,
    )

    root = client.calls[0][2]
    child = client.calls[1][2]
    assert root["tenant_id"] == "tenant-a"
    assert root["lineage_id"] == "lineage-a"
    assert child["expected_sequence"] == 3
    forbidden = {"token", "credentials", "memory", "workspace", "owner_identity"}
    assert not forbidden.intersection(root)
    assert not forbidden.intersection(child)


def test_replica_adapter_enforces_profile_capability_and_vector_bounds() -> None:
    adapter = _replicas(RecordingClient())

    with pytest.raises(PolicyError, match="exceed"):
        adapter.provision(
            request_id="operation",
            replica_id="agent",
            capabilities={"unconfigured.power"},
        )
    with pytest.raises(ValidationError):
        adapter.replicate(
            request_id="operation",
            parent_lease_id="parent",
            replica_id="agent",
            allocation=(1,),
            capabilities={"astral.tools.read"},
            ttl_ns=1,
        )
    with pytest.raises(ValidationError, match="ttl_ns"):
        adapter.provision(request_id="operation", replica_id="agent", ttl_ns=0)


def test_astraldeep_profile_maps_only_declared_public_scopes() -> None:
    client = RecordingClient()
    adapter = AstralDeepAuthorizer(
        _replicas(client),
        AstralDeepProfile(
            scope_capabilities={
                "tools:read": "astral.tools.read",
                "tools:execute": "astral.tools.execute",
            },
            scope_transitions={
                "tools:read": "read",
                "tools:execute": "execute",
            },
        ),
    )

    adapter.provision_agent(
        operation_id="astral-create-1",
        agent_id="agent-a",
        declared_scopes={"tools:read"},
    )
    adapter.authorize_tool(
        operation_id="astral-hop-1",
        lease_id="lease-a",
        declared_scope="tools:execute",
        executor_audience="astraldeep-tool-gateway",
        nonce="hop-nonce-1",
        expected_sequence=0,
    )

    assert client.calls[0][2]["capabilities"] == ["astral.tools.read"]
    assert client.calls[1][2]["transition"] == "execute"
    assert client.calls[1][2]["executor_audience"] == "astraldeep-tool-gateway"

    with pytest.raises(PolicyError, match="not mapped"):
        adapter.authorize_tool(
            operation_id="astral-hop-2",
            lease_id="lease-a",
            declared_scope="tools:system",
            executor_audience="astraldeep-tool-gateway",
            nonce="hop-nonce-2",
        )


def test_astraldeep_profile_rejects_unknown_or_incomplete_scope_maps() -> None:
    with pytest.raises(ValidationError, match="unknown"):
        AstralDeepProfile(
            scope_capabilities={"tools:invented": "capability"},
            scope_transitions={"tools:invented": "transition"},
        )
    with pytest.raises(ValidationError, match="every"):
        AstralDeepProfile(
            scope_capabilities={"tools:read": "capability"},
            scope_transitions={},
        )
