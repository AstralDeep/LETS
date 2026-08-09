"""Thin AstralDeep profile with no imports from the AstralDeep repository."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from lets.errors import PolicyError, ValidationError
from lets.ids import require_identifier
from lets.integrations.ports import ReplicaAuthorizer, WireObject
from lets.vector import ResourceVector

ASTRAL_TOOL_SCOPES = frozenset(
    {
        "tools:read",
        "tools:write",
        "tools:search",
        "tools:system",
        "tools:files",
        "tools:execute",
    }
)


@dataclass(frozen=True, slots=True)
class AstralDeepProfile:
    """Explicit mapping from Astral scopes into declared LETS policy names."""

    scope_capabilities: Mapping[str, str]
    scope_transitions: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.scope_capabilities:
            raise ValidationError("AstralDeep profile requires at least one scope mapping")
        if set(self.scope_capabilities) - ASTRAL_TOOL_SCOPES:
            raise ValidationError("AstralDeep profile contains an unknown declared tool scope")
        if set(self.scope_transitions) != set(self.scope_capabilities):
            raise ValidationError("every AstralDeep scope must map to one LETS transition")
        for value in (*self.scope_capabilities.values(), *self.scope_transitions.values()):
            require_identifier(value, field="AstralDeep LETS mapping")


class AstralDeepAuthorizer:
    """Translate already-mediated Astral lifecycle/tool events into LETS calls.

    AstralDeep remains responsible for human identity, RFC 8693 attenuation,
    owner isolation, PHI/egress policy, confirmations, and its own audit chain.
    This adapter adds quantitative lineage escrow; it does not replace or
    weaken any Astral gate.
    """

    def __init__(self, authorizer: ReplicaAuthorizer, profile: AstralDeepProfile) -> None:
        self.authorizer = authorizer
        self.profile = profile

    def provision_agent(
        self,
        *,
        operation_id: str,
        agent_id: str,
        declared_scopes: frozenset[str] | set[str] | tuple[str, ...],
        allocation: ResourceVector | None = None,
        ttl_ns: int | None = None,
    ) -> WireObject:
        capabilities = self._capabilities(declared_scopes)
        return self.authorizer.provision(
            request_id=operation_id,
            replica_id=agent_id,
            allocation=allocation,
            capabilities=capabilities,
            ttl_ns=ttl_ns,
        )

    def replicate_agent(
        self,
        *,
        operation_id: str,
        parent_lease_id: str,
        agent_id: str,
        declared_scopes: frozenset[str] | set[str] | tuple[str, ...],
        allocation: ResourceVector,
        ttl_ns: int,
        expected_sequence: int | None = None,
    ) -> WireObject:
        capabilities = self._capabilities(declared_scopes)
        return self.authorizer.replicate(
            request_id=operation_id,
            parent_lease_id=parent_lease_id,
            replica_id=agent_id,
            allocation=allocation,
            capabilities=capabilities,
            ttl_ns=ttl_ns,
            expected_sequence=expected_sequence,
        )

    def authorize_tool(
        self,
        *,
        operation_id: str,
        lease_id: str,
        declared_scope: str,
        executor_audience: str,
        nonce: str,
        evidence: Mapping[str, Any] | None = None,
        expected_state: str | None = None,
        expected_sequence: int | None = None,
    ) -> WireObject:
        if declared_scope not in self.profile.scope_transitions:
            raise PolicyError(f"AstralDeep scope {declared_scope!r} is not mapped by this profile")
        return self.authorizer.authorize_effect(
            request_id=operation_id,
            lease_id=lease_id,
            transition=self.profile.scope_transitions[declared_scope],
            executor_audience=executor_audience,
            nonce=nonce,
            evidence=evidence,
            expected_state=expected_state,
            expected_sequence=expected_sequence,
        )

    def _capabilities(
        self,
        scopes: frozenset[str] | set[str] | tuple[str, ...],
    ) -> frozenset[str]:
        selected = frozenset(scopes)
        unknown = selected - self.profile.scope_capabilities.keys()
        if unknown:
            raise PolicyError(
                f"AstralDeep scopes are not mapped by this profile: {sorted(unknown)}"
            )
        if not selected:
            raise PolicyError("an AstralDeep agent must declare at least one mapped scope")
        return frozenset(self.profile.scope_capabilities[item] for item in selected)
