"""Optional host-neutral mapping from Model Context Protocol (MCP) 2024-11-05 tool execution
operations to LETS authorization calls, leases, receipts and claims. Built on ReplicaAuthorizer
with tool storage and policy behind a host-supplied ToolLedger.
See docs/integration.md for the request/effect digest binding contract.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
from threading import RLock
from typing import Any, Protocol

from lets.canonical import canonical_json
from lets.ids import require_identifier
from lets.integrations.ports import ReplicaAuthorizer, WireObject

MAPPING_VERSION = "lets.mcp-profile/v1"


@dataclass(frozen=True, slots=True)
class MCPRevision:
    version: str
    spec_revision: str


PINNED_REVISION = MCPRevision("2024-11-05", "4b1e569941a35bf0c8e274c43cb0023a1a36427d")


class ToolExecutionState(Enum):
    DISCOVERED = "TOOL_STATE_DISCOVERED"
    AUTHORIZED = "TOOL_STATE_AUTHORIZED"
    CLAIMED = "TOOL_STATE_CLAIMED"
    COMPLETED = "TOOL_STATE_COMPLETED"
    FAILED = "TOOL_STATE_FAILED"
    CANCELED = "TOOL_STATE_CANCELED"
    REJECTED = "TOOL_STATE_REJECTED"


TERMINAL_STATES = frozenset(
    {
        ToolExecutionState.COMPLETED,
        ToolExecutionState.FAILED,
        ToolExecutionState.CANCELED,
        ToolExecutionState.REJECTED,
    }
)


class MCPProfileError(Exception):
    def __init__(self, name: str, code: int, message: str) -> None:
        super().__init__(message)
        self.name = name
        self.code = code
        self.message = message


class ToolNotFoundError(MCPProfileError):
    def __init__(self, message: str) -> None:
        super().__init__("ToolNotFound", -32601, message)


class PermissionDeniedError(MCPProfileError):
    def __init__(self, message: str) -> None:
        super().__init__("PermissionDenied", -32001, message)


class ArgumentMismatchError(MCPProfileError):
    def __init__(self, message: str) -> None:
        super().__init__("ArgumentMismatch", -32602, message)


class DuplicateInvocationError(MCPProfileError):
    def __init__(self, message: str) -> None:
        super().__init__("DuplicateInvocation", -32002, message)


class TenantMismatchError(MCPProfileError):
    def __init__(self, message: str) -> None:
        super().__init__("TenantMismatch", -32003, message)


class ReceiptMissingError(MCPProfileError):
    def __init__(self, message: str) -> None:
        super().__init__("ReceiptMissing", -32004, message)


@dataclass(frozen=True, slots=True)
class MCPToolRecord:
    request_id: str
    tenant_id: str
    tool_name: str
    arguments_digest: str
    state: ToolExecutionState
    lease_id: str | None = None
    receipt_claim: str | None = None
    executor_audience: str | None = None
    result: WireObject | None = None
    error_message: str | None = None


class ToolLedger(Protocol):
    def get(self, request_id: str) -> MCPToolRecord | None: ...
    def save(self, record: MCPToolRecord) -> None: ...


class InMemoryToolLedger:
    def __init__(self) -> None:
        self._lock = RLock()
        self._records: dict[str, MCPToolRecord] = {}

    def get(self, request_id: str) -> MCPToolRecord | None:
        with self._lock:
            return self._records.get(request_id)

    def save(self, record: MCPToolRecord) -> None:
        with self._lock:
            self._records[record.request_id] = record


def compute_arguments_digest(arguments: Mapping[str, Any]) -> str:
    serialized = canonical_json(arguments)
    return hashlib.sha256(serialized).hexdigest()


class MCPProtectedToolAuthorizer:
    def __init__(
        self,
        authorizer: ReplicaAuthorizer,
        ledger: ToolLedger | None = None,
        allowed_tools: Mapping[str, frozenset[str]] | None = None,
    ) -> None:
        self._authorizer = authorizer
        self._ledger = ledger if ledger is not None else InMemoryToolLedger()
        self._allowed_tools = allowed_tools if allowed_tools is not None else {}
        self._lock = RLock()

    def discover_tools(self, tenant_id: str) -> list[str]:
        """Discovery without authority - returns tools available to host without granting leases."""
        require_identifier(tenant_id, field="tenant_id")
        return sorted(self._allowed_tools.keys())

    def authorize_tool_call(
        self,
        request_id: str,
        tenant_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        executor_audience: str,
    ) -> MCPToolRecord:
        require_identifier(request_id, field="request_id")
        require_identifier(tenant_id, field="tenant_id")
        require_identifier(tool_name, field="tool_name")
        require_identifier(executor_audience, field="executor_audience")

        args_digest = compute_arguments_digest(arguments)

        with self._lock:
            existing = self._ledger.get(request_id)
            if existing is not None:
                if existing.tenant_id != tenant_id:
                    raise TenantMismatchError(
                        f"Request {request_id} belongs to different tenant {existing.tenant_id}"
                    )
                if existing.arguments_digest != args_digest or existing.tool_name != tool_name:
                    raise ArgumentMismatchError(
                        f"Changed arguments or tool on same request ID {request_id}"
                    )
                return existing

            if tool_name not in self._allowed_tools:
                raise ToolNotFoundError(f"Tool '{tool_name}' is not registered in host catalog")

            required_caps = self._allowed_tools[tool_name]
            # Verify tool permissions through authorizer
            replica = self._authorizer.profile
            if not required_caps.issubset(replica.default_capabilities):
                raise PermissionDeniedError(
                    f"Host permissions do not cover tool requirements for '{tool_name}'"
                )

            # Issue lease via authorizer
            auth_response = self._authorizer.client.authorize(
                replica.envelope_id,
                {
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "tool": tool_name,
                    "arguments_digest": args_digest,
                    "audience": executor_audience,
                },
            )
            lease_id = str(auth_response.get("lease_id", f"lease-{request_id}"))

            record = MCPToolRecord(
                request_id=request_id,
                tenant_id=tenant_id,
                tool_name=tool_name,
                arguments_digest=args_digest,
                state=ToolExecutionState.AUTHORIZED,
                lease_id=lease_id,
                executor_audience=executor_audience,
            )
            self._ledger.save(record)
            return record

    def verify_and_claim(
        self,
        request_id: str,
        tenant_id: str,
        executor_audience: str,
    ) -> MCPToolRecord:
        with self._lock:
            record = self._ledger.get(request_id)
            if record is None:
                raise ToolNotFoundError(f"Tool request {request_id} not found")
            if record.tenant_id != tenant_id:
                raise TenantMismatchError(f"Tenant mismatch on claim for request {request_id}")
            if record.executor_audience != executor_audience:
                raise PermissionDeniedError(
                    f"Audience mismatch: expected {record.executor_audience}, "
                    f"got {executor_audience}"
                )
            if record.state in TERMINAL_STATES or record.state == ToolExecutionState.CLAIMED:
                raise DuplicateInvocationError(
                    f"Request {request_id} already in state {record.state.value}"
                )

            receipt = hashlib.sha256(
                f"{request_id}:{record.lease_id}:{executor_audience}".encode()
            ).hexdigest()
            updated = replace(
                record,
                state=ToolExecutionState.CLAIMED,
                receipt_claim=receipt,
            )
            self._ledger.save(updated)
            return updated

    def complete_execution(
        self,
        request_id: str,
        result: WireObject,
        receipt_claim: str,
    ) -> MCPToolRecord:
        with self._lock:
            record = self._ledger.get(request_id)
            if record is None:
                raise ToolNotFoundError(f"Tool request {request_id} not found")
            if not record.receipt_claim or record.receipt_claim != receipt_claim:
                raise ReceiptMissingError("Valid receipt claim required to complete execution")
            if record.state in TERMINAL_STATES:
                raise DuplicateInvocationError(
                    f"Request {request_id} already terminal ({record.state.value})"
                )

            updated = replace(
                record,
                state=ToolExecutionState.COMPLETED,
                result=result,
            )
            self._ledger.save(updated)
            return updated

    def cancel_execution(self, request_id: str, reason: str = "User cancelled") -> MCPToolRecord:
        with self._lock:
            record = self._ledger.get(request_id)
            if record is None:
                raise ToolNotFoundError(f"Tool request {request_id} not found")
            if record.state in TERMINAL_STATES:
                return record

            updated = replace(
                record,
                state=ToolExecutionState.CANCELED,
                error_message=reason,
            )
            self._ledger.save(updated)
            return updated
