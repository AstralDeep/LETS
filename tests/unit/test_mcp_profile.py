import pytest
from lets.integrations.ports import ReplicaAuthorizer, ReplicaProfile
from lets.integrations.mcp import (
    MCPProtectedToolAuthorizer,
    MCPToolRecord,
    ToolExecutionState,
    ToolNotFoundError,
    PermissionDeniedError,
    ArgumentMismatchError,
    DuplicateInvocationError,
    TenantMismatchError,
    ReceiptMissingError,
    compute_arguments_digest,
)


class DummyAuthorizerClient:
    def __init__(self):
        self.authorized_calls = []

    def issue_root(self, payload): return {"lease_id": "root-1"}
    def spawn(self, parent_id, payload): return {"lease_id": "spawn-1"}
    def authorize(self, lease_id, payload):
        self.authorized_calls.append((lease_id, payload))
        return {"lease_id": f"lease-{payload['request_id']}"}
    def renew(self, lease_id, payload): return {}
    def quiesce(self, lease_id, payload): return {}
    def resume(self, lease_id, payload): return {}
    def close_lease(self, lease_id, payload): return {}
    def revoke_branch(self, lease_id, payload): return {}


@pytest.fixture
def authorizer():
    client = DummyAuthorizerClient()
    profile = ReplicaProfile(
        tenant_id="tenant-alpha",
        envelope_id="env-001",
        policy_digest="sha256:" + "a" * 64,
        default_allocation=(100,),
        default_capabilities=frozenset(["fs.read", "net.http"]),
        default_ttl_ns=60_000_000_000,
    )
    rep_auth = ReplicaAuthorizer(client, profile)
    allowed = {
        "read_file": frozenset(["fs.read"]),
        "fetch_url": frozenset(["net.http"]),
        "delete_root": frozenset(["admin.all"]),  # Not in replica capabilities
    }
    return MCPProtectedToolAuthorizer(rep_auth, allowed_tools=allowed)


def test_discovery_without_authority(authorizer):
    tools = authorizer.discover_tools("tenant-alpha")
    assert tools == ["delete_root", "fetch_url", "read_file"]


def test_successful_tool_lifecycle(authorizer):
    record = authorizer.authorize_tool_call(
        request_id="req-101",
        tenant_id="tenant-alpha",
        tool_name="read_file",
        arguments={"path": "/tmp/test.txt"},
        executor_audience="worker-agent-1",
    )
    assert record.state == ToolExecutionState.AUTHORIZED
    assert record.lease_id == "lease-req-101"

    # Verify and claim
    claimed = authorizer.verify_and_claim("req-101", "tenant-alpha", "worker-agent-1")
    assert claimed.state == ToolExecutionState.CLAIMED
    assert claimed.receipt_claim is not None

    # Complete execution
    completed = authorizer.complete_execution(
        "req-101",
        result={"content": "hello world"},
        receipt_claim=claimed.receipt_claim,
    )
    assert completed.state == ToolExecutionState.COMPLETED
    assert completed.result == {"content": "hello world"}


def test_unknown_tool(authorizer):
    with pytest.raises(ToolNotFoundError):
        authorizer.authorize_tool_call(
            request_id="req-102",
            tenant_id="tenant-alpha",
            tool_name="non_existent_tool",
            arguments={},
            executor_audience="worker-agent-1",
        )


def test_permission_denied(authorizer):
    with pytest.raises(PermissionDeniedError):
        authorizer.authorize_tool_call(
            request_id="req-103",
            tenant_id="tenant-alpha",
            tool_name="delete_root",
            arguments={},
            executor_audience="worker-agent-1",
        )


def test_changed_arguments_on_same_request_id(authorizer):
    authorizer.authorize_tool_call(
        request_id="req-104",
        tenant_id="tenant-alpha",
        tool_name="read_file",
        arguments={"path": "/tmp/a.txt"},
        executor_audience="worker-agent-1",
    )
    with pytest.raises(ArgumentMismatchError):
        authorizer.authorize_tool_call(
            request_id="req-104",
            tenant_id="tenant-alpha",
            tool_name="read_file",
            arguments={"path": "/tmp/b.txt"},  # Changed arguments!
            executor_audience="worker-agent-1",
        )


def test_tenant_mismatch(authorizer):
    authorizer.authorize_tool_call(
        request_id="req-105",
        tenant_id="tenant-alpha",
        tool_name="read_file",
        arguments={"path": "/tmp/a.txt"},
        executor_audience="worker-agent-1",
    )
    with pytest.raises(TenantMismatchError):
        authorizer.authorize_tool_call(
            request_id="req-105",
            tenant_id="tenant-beta",  # Different tenant!
            tool_name="read_file",
            arguments={"path": "/tmp/a.txt"},
            executor_audience="worker-agent-1",
        )


def test_duplicate_claim_and_missing_receipt(authorizer):
    authorizer.authorize_tool_call(
        request_id="req-106",
        tenant_id="tenant-alpha",
        tool_name="read_file",
        arguments={"path": "/tmp/a.txt"},
        executor_audience="worker-agent-1",
    )
    claimed = authorizer.verify_and_claim("req-106", "tenant-alpha", "worker-agent-1")
    
    # Duplicate claim raises DuplicateInvocationError
    with pytest.raises(DuplicateInvocationError):
        authorizer.verify_and_claim("req-106", "tenant-alpha", "worker-agent-1")

    # Missing/wrong receipt on complete
    with pytest.raises(ReceiptMissingError):
        authorizer.complete_execution("req-106", result={}, receipt_claim="invalid-receipt")


def test_cancellation(authorizer):
    authorizer.authorize_tool_call(
        request_id="req-107",
        tenant_id="tenant-alpha",
        tool_name="read_file",
        arguments={"path": "/tmp/a.txt"},
        executor_audience="worker-agent-1",
    )
    cancelled = authorizer.cancel_execution("req-107", reason="Timeout")
    assert cancelled.state == ToolExecutionState.CANCELED
    assert cancelled.error_message == "Timeout"
