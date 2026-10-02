"""Integration conformance tests for the MCP authorizer profile.

Validates discovery without authority, actual AuthorizerClient invocation,
empty tool scope fail-closed behavior, host confirmation denial,
unknown tools, changed arguments, changed tools, lost replies,
cancellations, mismatched audience/tenant, missing receipts,
effect digest verification, and durable replay protection across restarts.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from lets.canonical import canonical_digest
from lets.errors import PolicyError, ValidationError
from lets.integrations.mcp import MCPAuthorizer, MCPProfile


class RecordingAuthorizerClient:
    """Mock client recording authorizer calls with configurable denial."""

    def __init__(self, deny: bool = False) -> None:
        self.deny = deny
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def issue_root(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return {"id": "root-1", "status": "issued"}

    def spawn(
        self, parent_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        return {"id": "child-1", "status": "spawned"}

    def authorize(
        self, lease_id: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        if self.deny:
            raise PolicyError("Warden denied authorization lease.")
        self.calls.append((lease_id, payload))
        return {
            "status": "authorized",
            "lease_id": lease_id,
            "request_id": payload.get("request_id"),
            "token": "signed-token-xyz",
        }


def test_discovery_without_authority() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"search", "fetch"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)
    manifest = [
        {"name": "search", "description": "Search index"},
        {"name": "rm", "description": "Delete files"},
    ]
    discovered = auth.discover_tools(manifest)
    assert len(discovered) == 1
    assert discovered[0]["name"] == "search"
    assert discovered[0]["authorized"] is False


def test_client_authorize_invoked() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"calc"}),
    )
    client = RecordingAuthorizerClient()
    auth = MCPAuthorizer(client, profile)

    receipt = auth.authorize_invocation(
        "req-auth-1",
        "calc",
        {"val": 10},
        audience="aud-1",
        tenant="tenant-1",
    )
    assert len(client.calls) == 1
    lease_id, payload = client.calls[0]
    assert lease_id == "mcp-root-lease"
    assert payload["request_id"] == "req-auth-1"
    assert payload["tool"] == "calc"
    assert payload["audience"] == "aud-1"
    assert payload["tenant_id"] == "tenant-1"
    assert receipt.auth_record["status"] == "authorized"


def test_warden_authorization_denial() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"calc"}),
    )
    client = RecordingAuthorizerClient(deny=True)
    auth = MCPAuthorizer(client, profile)

    with pytest.raises(PolicyError, match="Warden denied authorization"):
        auth.authorize_invocation(
            "req-denied",
            "calc",
            {"val": 10},
            audience="aud-1",
            tenant="tenant-1",
        )


def test_profile_empty_tool_scope_fails_closed() -> None:
    with pytest.raises(ValidationError, match="requires at least one allowed tool"):
        MCPProfile(
            expected_audience="aud-1",
            expected_tenant="tenant-1",
            allowed_tools=frozenset(),
        )


def test_host_confirmation_denial() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"calc"}),
        enforce_confirmation_gate=True,
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    with pytest.raises(PolicyError, match="Host confirmation gate rejected"):
        auth.authorize_invocation(
            "req-gate-1",
            "calc",
            {"val": 1},
            audience="aud-1",
            tenant="tenant-1",
            host_confirmed=False,
        )


def test_audience_and_tenant_enforcement() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"tool"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    with pytest.raises(PolicyError, match="Mismatched audience"):
        auth.authorize_invocation(
            "req-1",
            "tool",
            {"a": 1},
            audience="wrong-aud",
            tenant="tenant-1",
        )

    with pytest.raises(PolicyError, match="Mismatched tenant"):
        auth.authorize_invocation(
            "req-2",
            "tool",
            {"a": 1},
            audience="aud-1",
            tenant="wrong-tenant",
        )


def test_unknown_tool_out_of_scope() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"read"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    with pytest.raises(PolicyError, match="Tool write not permitted"):
        auth.authorize_invocation(
            "req-scope-1",
            "write",
            {"target": "/etc"},
            audience="aud-1",
            tenant="tenant-1",
        )


def test_changed_arguments_on_same_request_id() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"tool"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    auth.authorize_invocation(
        "req-id-100",
        "tool",
        {"param": "alpha"},
        audience="aud-1",
        tenant="tenant-1",
    )

    with pytest.raises(ValidationError, match="Changed arguments detected"):
        auth.authorize_invocation(
            "req-id-100",
            "tool",
            {"param": "beta"},
            audience="aud-1",
            tenant="tenant-1",
        )


def test_changed_tool_on_same_request_id() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"toolA", "toolB"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    auth.authorize_invocation(
        "req-diff-tool",
        "toolA",
        {"param": "fixed"},
        audience="aud-1",
        tenant="tenant-1",
    )

    with pytest.raises(ValidationError, match="Mismatched tool"):
        auth.authorize_invocation(
            "req-diff-tool",
            "toolB",
            {"param": "fixed"},
            audience="aud-1",
            tenant="tenant-1",
        )


def test_verify_and_claim_and_duplicate_invocation() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"calc"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    receipt = auth.authorize_invocation(
        "req-200",
        "calc",
        {"val": 42},
        audience="aud-1",
        tenant="tenant-1",
    )
    auth.verify_and_claim("req-200", receipt.effect_digest)

    # Duplicate invocation must fail
    with pytest.raises(PolicyError, match="Duplicate invocation"):
        auth.verify_and_claim("req-200", receipt.effect_digest)

    with pytest.raises(PolicyError, match="Duplicate invocation"):
        auth.authorize_invocation(
            "req-200",
            "calc",
            {"val": 42},
            audience="aud-1",
            tenant="tenant-1",
        )


def test_effect_digest_mismatch() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"calc"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    auth.authorize_invocation(
        "req-effect-mismatch",
        "calc",
        {"val": 42},
        audience="aud-1",
        tenant="tenant-1",
    )

    fake_digest = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="Effect digest mismatch"):
        auth.verify_and_claim("req-effect-mismatch", fake_digest)

    with pytest.raises(ValidationError, match="must match sha256"):
        auth.verify_and_claim("req-effect-mismatch", "invalid-digest")


def test_missing_receipt() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"calc"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    fake_digest = "sha256:" + "0" * 64
    with pytest.raises(ValidationError, match="Missing receipt"):
        auth.verify_and_claim("non-existent-req", fake_digest)


def test_cancellation_and_lost_reply() -> None:
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"ping"}),
    )
    auth = MCPAuthorizer(RecordingAuthorizerClient(), profile)

    receipt = auth.authorize_invocation(
        "req-300",
        "ping",
        {},
        audience="aud-1",
        tenant="tenant-1",
    )
    auth.cancel_invocation("req-300")

    with pytest.raises(PolicyError, match="Cannot claim cancelled request"):
        auth.verify_and_claim("req-300", receipt.effect_digest)

    # Cannot cancel already claimed execution
    auth2 = MCPAuthorizer(RecordingAuthorizerClient(), profile)
    receipt2 = auth2.authorize_invocation(
        "req-301",
        "ping",
        {},
        audience="aud-1",
        tenant="tenant-1",
    )
    auth2.verify_and_claim("req-301", receipt2.effect_digest)
    with pytest.raises(PolicyError, match="Cannot cancel already-executed"):
        auth2.cancel_invocation("req-301")


def test_durable_replay_protection_across_restarts() -> None:
    """Verifies that an adapter restarted with shared durable registry rejects."""
    profile = MCPProfile(
        expected_audience="aud-1",
        expected_tenant="tenant-1",
        allowed_tools=frozenset({"transfer"}),
    )
    client = RecordingAuthorizerClient()
    durable_store: set[str] = set()

    # Session 1: Authorize and execute
    auth1 = MCPAuthorizer(client, profile, replay_registry=durable_store)
    receipt1 = auth1.authorize_invocation(
        "req-restart-1",
        "transfer",
        {"amount": 100},
        audience="aud-1",
        tenant="tenant-1",
    )
    auth1.verify_and_claim(
        "req-restart-1", receipt1.effect_digest, durable_store=durable_store
    )
    assert "req-restart-1" in durable_store

    # Session 2: Simulated adapter restart reading durable replay store
    auth2 = MCPAuthorizer(client, profile, replay_registry=durable_store)
    with pytest.raises(PolicyError, match="Duplicate invocation"):
        auth2.authorize_invocation(
            "req-restart-1",
            "transfer",
            {"amount": 100},
            audience="aud-1",
            tenant="tenant-1",
        )

    with pytest.raises(PolicyError, match="Duplicate invocation"):
        auth2.verify_and_claim("req-restart-1", receipt1.effect_digest)


def test_canonical_digest_lets_cj1() -> None:
    """Verifies canonical JSON rejects NaN and produces deterministic digests."""
    data = {"b": 2, "a": 1}
    digest = canonical_digest(data)
    assert digest.startswith("sha256:")
    assert len(digest) == 71

    # NaN float rejection in LETS-CJ/1
    with pytest.raises(ValueError, match="canonical JSON numbers must be integers"):
        canonical_digest({"val": float("nan")})
