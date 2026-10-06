import unittest
from unittest.mock import MagicMock

from lets.integrations.mcp import MCPAuthorizer, MCPProfile


class TestMCPProfile(unittest.TestCase):
    def test_mcp_authorization_mapping(self) -> None:
        client = MagicMock()
        client.authorize.return_value = {"status": "authorized", "receipt": "mock-receipt"}

        profile = MCPProfile(
            tenant_id="tenant-mcp",
            envelope_id="env-mcp",
            policy_digest="sha256:digest",
            tool_capabilities={"run_command": "mcp.cmd.run"},
            tool_transitions={"run_command": "execute"},
        )

        authorizer = MCPAuthorizer(client, profile)

        result = authorizer.authorize_tool(
            agent_id="agent-1",
            tool_name="run_command",
            request_id="req-123",
            audience="executor-node-1",
            evidence={"cmd": "ls"},
        )

        self.assertEqual(result["status"], "authorized")
        client.authorize.assert_called_once_with(
            "env-mcp",
            {
                "request_id": "req-123",
                "agent_id": "agent-1",
                "capability": "mcp.cmd.run",
                "transition": "execute",
                "executor_audience": "executor-node-1",
                "evidence": {"cmd": "ls"},
            },
        )

    def test_unknown_tool_fails_closed(self) -> None:
        client = MagicMock()
        profile = MCPProfile(
            tenant_id="tenant-mcp",
            envelope_id="env-mcp",
            policy_digest="sha256:digest",
            tool_capabilities={},
        )
        authorizer = MCPAuthorizer(client, profile)

        with self.assertRaises(ValueError):
            authorizer.authorize_tool(
                agent_id="agent-1",
                tool_name="unknown_tool",
                request_id="req-456",
                audience="executor-node-1",
            )
        client.authorize.assert_not_called()


if __name__ == "__main__":
    unittest.main()
