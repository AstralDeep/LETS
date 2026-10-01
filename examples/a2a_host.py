"""Example host dispatch from transport-verified identity to the A2ATaskProfile methods. It is a
sketch of the seam, not a server; authentication and transport stay with the host.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from lets.errors import ExpiredError, PolicyError
from lets.integrations.a2a import A2AProfileError, A2ATaskProfile, task_to_a2a
from lets.models import IdentityContext


class A2AHost:
    def __init__(
        self,
        profile: A2ATaskProfile,
        *,
        parent_lease_id: str,
        executor_subject: str,
        allocation: tuple[int, ...],
        capabilities: frozenset[str],
        ttl_ns: int,
    ) -> None:
        self.profile = profile
        self._admission = {
            "parent_lease_id": parent_lease_id,
            "subject_id": executor_subject,
            "allocation": allocation,
            "capabilities": capabilities,
            "ttl_ns": ttl_ns,
        }

    def handle(
        self, identity: IdentityContext, method: str, params: Mapping[str, Any]
    ) -> dict[str, Any]:
        try:
            if method == "SendMessage":
                message = params["message"]
                record = self.profile.admit(
                    identity,
                    task_id=params["taskId"],
                    context_id=message["contextId"],
                    content={"message": message},
                    **self._admission,  # type: ignore[arg-type]
                )
                return task_to_a2a(record)
            if method == "GetTask":
                return task_to_a2a(self.profile.get_task(identity, params["id"]))
            if method == "SubscribeToTask":
                return task_to_a2a(self.profile.subscribe(identity, params["id"]))
            if method == "CancelTask":
                return task_to_a2a(self.profile.cancel_task(identity, params["id"]))
            raise A2AProfileError("UnsupportedOperationError", -32004, f"unsupported: {method}")
        except A2AProfileError:
            raise
        except (PolicyError, ExpiredError) as error:
            raise PermissionError(str(error)) from error
