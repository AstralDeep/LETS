from __future__ import annotations

import tempfile
from contextlib import suppress
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import PolicyError, ValidationError
from lets.models import IdentityContext, LeaseStatus
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage


def _identity(subject: str, *scopes: str) -> IdentityContext:
    return IdentityContext(subject, "tenant", frozenset(scopes))


def _policy() -> PolicySpec:
    return PolicySpec(
        "trace-policy",
        "v1",
        (ResourceDimension("steps", "count"),),
        MachineSpec(
            "trace-machine",
            "ready",
            (TransitionSpec("step", "ready", "ready", (1,), "trace.step"),),
        ),
        10_000,
        100,
        0,
        4,
    )


Action = tuple[int, int, int]


@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=2),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=0, max_value=6),
        ),
        min_size=1,
        max_size=40,
    )
)
@settings(max_examples=35, deadline=None)
def test_random_lifecycle_traces_conform_to_conservation_and_attenuation(
    actions: list[Action],
) -> None:
    with tempfile.TemporaryDirectory(prefix="lets-trace-") as directory:
        path = Path(directory) / "warden.sqlite3"
        clock = ManualClock(1_000_000)
        signer = Ed25519Signer.generate("warden")
        store = SQLiteStorage.initialize(
            path,
            "warden",
            (25,),
            signing_key_id=signer.key_id,
            signing_public_key=signer.public_key_bytes,
            tenant_id="tenant",
            envelope_id="envelope",
            receipt_ttl_ns=100,
            transfer_gap_window=4,
        )
        registry = PublicKeyRegistry(clock=clock)
        registry.register_signer(signer)
        service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
        policy = _policy()
        service.register_policy(policy)
        root = service.issue_root(
            request_id="trace-root",
            identity=_identity("issuer", "lets.lease.issue"),
            tenant_id="tenant",
            envelope_id="envelope",
            subject_id="root",
            allocation=(20,),
            capabilities={"trace.step"},
            policy_digest=policy.digest,
            ttl_ns=1_000,
        )
        lease_ids = [root.lease_id]
        parent_of: dict[str, str | None] = {root.lease_id: None}
        try:
            for index, (kind, selector, amount) in enumerate(actions):
                lease_id = lease_ids[selector % len(lease_ids)]
                snapshot = service.snapshot(
                    identity=_identity("auditor", "lets.lease.manage"),
                    lease_id=lease_id,
                )
                owner = snapshot.grant.subject_id
                if kind == 0:
                    try:
                        child = service.spawn(
                            request_id=f"trace-spawn-{index}",
                            identity=_identity(owner),
                            parent_id=lease_id,
                            subject_id=f"child-{index}",
                            allocation=(amount,),
                            capabilities={"trace.step"},
                            ttl_ns=500,
                        )
                    except (PolicyError, ValidationError):
                        pass
                    else:
                        lease_ids.append(child.lease_id)
                        parent_of[child.lease_id] = lease_id
                        assert child.capabilities.issubset(snapshot.grant.capabilities)
                        assert child.expires_at_ns <= snapshot.grant.expires_at_ns
                elif kind == 1:
                    with suppress(PolicyError):
                        service.authorize(
                            request_id=f"trace-authorize-{index}",
                            identity=_identity(owner),
                            lease_id=lease_id,
                            transition="step",
                            audience="executor",
                            nonce=f"trace-nonce-{index:08d}",
                        )
                else:
                    service.close(
                        request_id=f"trace-close-{index}",
                        identity=_identity(owner),
                        lease_id=lease_id,
                    )

                invariant = service.invariant_snapshot(identity=_identity("auditor"))
                assert invariant.healthy
                for candidate in lease_ids:
                    current = service.snapshot(
                        identity=_identity("auditor", "lets.lease.manage"),
                        lease_id=candidate,
                    )
                    assert all(value >= 0 for value in current.residual)
                    parent_id = parent_of[candidate]
                    if parent_id is not None:
                        parent = service.snapshot(
                            identity=_identity("auditor", "lets.lease.manage"),
                            lease_id=parent_id,
                        )
                        assert current.grant.capabilities.issubset(parent.grant.capabilities)
                        assert current.grant.expires_at_ns <= parent.grant.expires_at_ns
                    if current.status in {LeaseStatus.CLOSED, LeaseStatus.EXPIRED}:
                        assert not any(current.residual)
        finally:
            store.close()
