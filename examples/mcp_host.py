"""Example host seam from a transport-verified MCP tools/call to a protected tool effect.
The host owns MCP transport, user IAM and the tool gate; the profile binds LETS authority and
the executor verifies and claims the receipt immediately before the effect.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from lets.errors import ValidationError
from lets.executor import ReceiptVerifier
from lets.integrations.mcp import MCPToolAuthorization, MCPToolProfile
from lets.models import IdentityContext


class MCPToolHost:
    def __init__(
        self,
        profile: MCPToolProfile,
        verifier: ReceiptVerifier,
        effect: Callable[[str, str, Mapping[str, Any]], Any],
    ) -> None:
        self.profile = profile
        self.verifier = verifier
        self.effect = effect

    def discover(self) -> list[dict[str, Any]]:
        return [descriptor.to_mcp() for descriptor in self.profile.descriptors()]

    def authorize(
        self,
        identity: IdentityContext,
        *,
        operation_id: str,
        lease_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        verified_executor_id: str,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> MCPToolAuthorization:
        return self.profile.authorize_tool(
            identity,
            operation_id=operation_id,
            lease_id=lease_id,
            tool_name=tool_name,
            arguments=arguments,
            verified_executor_id=verified_executor_id,
            expected_state=expected_state,
            expected_sequence=expected_sequence,
        )

    def execute(
        self,
        identity: IdentityContext,
        arguments: Mapping[str, Any],
        *,
        authorization: MCPToolAuthorization | None,
    ) -> Any:
        if authorization is None:
            raise ValidationError("MCP tool effect requires a receipt")
        receipt = self.profile.bind_receipt(authorization, authorization.receipt)
        self.verifier.verify_and_claim(receipt)
        return self.effect(authorization.operation_id, authorization.tool_name, arguments)

    def call(
        self,
        identity: IdentityContext,
        *,
        operation_id: str,
        lease_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        verified_executor_id: str,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> Any:
        authorization = self.authorize(
            identity,
            operation_id=operation_id,
            lease_id=lease_id,
            tool_name=tool_name,
            arguments=arguments,
            verified_executor_id=verified_executor_id,
            expected_state=expected_state,
            expected_sequence=expected_sequence,
        )
        return self.execute(identity, arguments, authorization=authorization)
