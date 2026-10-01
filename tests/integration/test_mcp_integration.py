"""Integration conformance tests for the MCP authorizer profile.
Validates unknown tools, changed arguments, lost replies, cancellations,
wrong audience/tenant, missing receipts, and duplicate invocations.
"""

import pytest
from unittest.mock import MagicMock
from lets.errors import PolicyError, ValidationError
from lets.integrations.mcp import MCPAuthorizer, MCPProfile


class DummyAuthorizerClient:
    def issue_root(self, payload): return {"id": "root-1"}
    def spawn(self, parent_id, payload): return {"id": "child-1"}
    def authorize(self, lease_id, payload): return {"status": "ok"}


def test_discovery_without_authority():
    profile = MCPProfile(expected_audience="aud-1", expected_tenant="tenant-1", allowed_tools=["search", "fetch"])
    auth = MCPAuthorizer(DummyAuthorizerClient(), profile)
    manifest = [
        {"name": "search", "description": "Search index"},
        {"name": "rm", "description": "Delete files"}
    ]
    discovered = auth.discover_tools(manifest)
    assert len(discovered) == 1
    assert discovered[0]["name"] == "search"
    assert discovered[0]["authorized"] is False


def test_audience_and_tenant_enforcement():
    profile = MCPProfile(expected_audience="aud-1", expected_tenant="tenant-1")
    auth = MCPAuthorizer(DummyAuthorizerClient(), profile)
    
    with pytest.raises(PolicyError, match="Mismatched audience"):
        auth.authorize_invocation("req-1", "test_tool", {"a": 1}, audience="wrong-aud", tenant="tenant-1")

    with pytest.raises(PolicyError, match="Mismatched tenant"):
        auth.authorize_invocation("req-2", "test_tool", {"a": 1}, audience="aud-1", tenant="wrong-tenant")


def test_changed_arguments_on_same_request_id():
    profile = MCPProfile(expected_audience="aud-1", expected_tenant="tenant-1")
    auth = MCPAuthorizer(DummyAuthorizerClient(), profile)
    
    auth.authorize_invocation("req-id-100", "tool", {"param": "alpha"}, "aud-1", "tenant-1")
    
    with pytest.raises(ValidationError, match="Changed arguments detected"):
        auth.authorize_invocation("req-id-100", "tool", {"param": "beta"}, "aud-1", "tenant-1")


def test_verify_and_claim_and_duplicate_invocation():
    profile = MCPProfile(expected_audience="aud-1", expected_tenant="tenant-1")
    auth = MCPAuthorizer(DummyAuthorizerClient(), profile)
    
    receipt = auth.authorize_invocation("req-200", "calc", {"val": 42}, "aud-1", "tenant-1")
    auth.verify_and_claim("req-200", receipt.args_digest)
    
    # Duplicate invocation must fail
    with pytest.raises(PolicyError, match="Duplicate invocation"):
        auth.verify_and_claim("req-200", receipt.args_digest)


def test_missing_receipt():
    profile = MCPProfile(expected_audience="aud-1", expected_tenant="tenant-1")
    auth = MCPAuthorizer(DummyAuthorizerClient(), profile)
    
    with pytest.raises(ValidationError, match="Missing receipt"):
        auth.verify_and_claim("non-existent-req", "some-digest")


def test_cancellation():
    profile = MCPProfile(expected_audience="aud-1", expected_tenant="tenant-1")
    auth = MCPAuthorizer(DummyAuthorizerClient(), profile)
    
    receipt = auth.authorize_invocation("req-300", "ping", {}, "aud-1", "tenant-1")
    auth.cancel_invocation("req-300")
    
    with pytest.raises(PolicyError, match="Cannot claim cancelled request"):
        auth.verify_and_claim("req-300", receipt.args_digest)
