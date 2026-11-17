"""The governing policy for the demo agent fleet.

A LETS policy is immutable and content-addressed: its ``digest`` is derived from
its contents, and every lease is bound to that exact digest. Changing anything
here produces a different policy that existing leases will not accept.

Dimension order is load-bearing. Index ``i`` of every vector in this demo —
the warden's ``--budget``, a lease ``allocation``, a transition ``cost`` — refers
to ``DIMENSIONS[i]``. LETS treats units as declarative labels and does no unit
math, so the ordering is the only thing tying a number to a meaning.
"""

from __future__ import annotations

from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec

SECOND_NS = 1_000_000_000

DIMENSIONS = (
    ResourceDimension("actions", "count", "protected tool invocations"),
    ResourceDimension("tokens", "token", "model tokens"),
)

# Capabilities the root lease is granted. `agent.publish` is deliberately
# excluded: it is declared by the machine below but never held by the root, so a
# child asking for it is refused for exceeding its parent rather than for naming
# a capability the policy has never heard of. Those are different failures, and
# the demo is only interesting if it shows the first one.
ROOT_CAPABILITIES = ("agent.research", "agent.summarize")
WITHHELD_CAPABILITY = "agent.publish"

POLICY = PolicySpec(
    policy_id="agent-fleet",
    policy_version="v1",
    dimensions=DIMENSIONS,
    machine=MachineSpec(
        machine_id="worker",
        initial_state="ready",
        transitions=(
            # cost vectors are positional: (actions, tokens)
            TransitionSpec("research", "ready", "ready", (1, 500), "agent.research"),
            TransitionSpec("summarize", "ready", "ready", (1, 200), "agent.summarize"),
            TransitionSpec("publish", "ready", "ready", (5, 100), WITHHELD_CAPABILITY),
        ),
    ),
    # An hour, so nothing expires part-way through a demonstration.
    max_lease_ttl_ns=3_600 * SECOND_NS,
    receipt_ttl_ns=1 * SECOND_NS,
    max_clock_uncertainty_ns=50_000_000,
    transfer_gap_window=64,
)

# What each transition costs, for the UI to display without re-deriving it.
TRANSITION_COSTS = {
    transition.name: list(transition.cost) for transition in POLICY.machine.transitions
}
TRANSITION_CAPABILITIES = {
    transition.name: transition.capability for transition in POLICY.machine.transitions
}

ROOT_ALLOCATION = [2_000, 200_000]
ROOT_TTL_NS = 3_600 * SECOND_NS


def dimension_labels() -> list[dict[str, str]]:
    return [{"id": d.id, "unit": d.unit, "description": d.description} for d in DIMENSIONS]
