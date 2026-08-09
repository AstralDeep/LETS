"""Exhaustive state-space checker for the abstract LETS conservation kernel.

The checker explores local issuance, recursive spawn, consumption, closure,
expiry/reclamation, transfer preparation, transfer acceptance, and duplicate
acceptance.  It deliberately abstracts away signatures and HSM labels; those
are covered by unit tests in the executable reference implementation.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, order=True)
class Lease:
    lease_id: int
    warden: int
    parent_id: int
    residual: int
    active: bool


@dataclass(frozen=True)
class State:
    pools: tuple[int, int]
    leases: tuple[Lease, ...]
    consumed: int
    transfer_amount: int
    transfer_source: int
    transfer_target: int
    transfer_prepared: bool
    transfer_accepted: bool
    next_lease_id: int


BUDGET = 4
MAX_LEASES = 4
MAX_DEPTH = 10


def conservation(state: State) -> int:
    lease_rights = sum(lease.residual for lease in state.leases)
    in_flight = (
        state.transfer_amount if state.transfer_prepared and not state.transfer_accepted else 0
    )
    return sum(state.pools) + lease_rights + state.consumed + in_flight


def validate(state: State) -> None:
    if conservation(state) != BUDGET:
        raise AssertionError(f"conservation failure: {state}")
    if min(state.pools) < 0 or state.consumed < 0 or state.transfer_amount < 0:
        raise AssertionError(f"negative state: {state}")
    if any(lease.residual < 0 for lease in state.leases):
        raise AssertionError(f"negative lease: {state}")
    ids = {lease.lease_id for lease in state.leases}
    if len(ids) != len(state.leases):
        raise AssertionError(f"duplicate lease id: {state}")


def replace_lease(state: State, changed: Lease) -> tuple[Lease, ...]:
    return tuple(
        sorted(changed if lease.lease_id == changed.lease_id else lease for lease in state.leases)
    )


def successors(state: State) -> Iterable[tuple[str, State]]:
    # Issue a root lease from either warden.
    if len(state.leases) < MAX_LEASES:
        for warden in (0, 1):
            if state.pools[warden] > 0:
                amount = 1
                pools = list(state.pools)
                pools[warden] -= amount
                lease = Lease(state.next_lease_id, warden, -1, amount, True)
                yield (
                    "issue",
                    State(
                        tuple(pools),
                        tuple(sorted((*state.leases, lease))),
                        state.consumed,
                        state.transfer_amount,
                        state.transfer_source,
                        state.transfer_target,
                        state.transfer_prepared,
                        state.transfer_accepted,
                        state.next_lease_id + 1,
                    ),
                )

    # Recursive spawn partitions one unit from a parent.
    if len(state.leases) < MAX_LEASES:
        for parent in state.leases:
            if parent.active and parent.residual > 0:
                changed = Lease(
                    parent.lease_id,
                    parent.warden,
                    parent.parent_id,
                    parent.residual - 1,
                    True,
                )
                leases = list(replace_lease(state, changed))
                leases.append(Lease(state.next_lease_id, parent.warden, parent.lease_id, 1, True))
                yield (
                    "spawn",
                    State(
                        state.pools,
                        tuple(sorted(leases)),
                        state.consumed,
                        state.transfer_amount,
                        state.transfer_source,
                        state.transfer_target,
                        state.transfer_prepared,
                        state.transfer_accepted,
                        state.next_lease_id + 1,
                    ),
                )

    # Consume one right.
    for lease in state.leases:
        if lease.active and lease.residual > 0:
            changed = Lease(lease.lease_id, lease.warden, lease.parent_id, lease.residual - 1, True)
            yield (
                "consume",
                State(
                    state.pools,
                    replace_lease(state, changed),
                    state.consumed + 1,
                    state.transfer_amount,
                    state.transfer_source,
                    state.transfer_target,
                    state.transfer_prepared,
                    state.transfer_accepted,
                    state.next_lease_id,
                ),
            )

    # Close/reclaim returns the residual exactly once to the local pool.
    for lease in state.leases:
        if lease.active:
            pools = list(state.pools)
            pools[lease.warden] += lease.residual
            changed = Lease(lease.lease_id, lease.warden, lease.parent_id, 0, False)
            yield (
                "close",
                State(
                    tuple(pools),
                    replace_lease(state, changed),
                    state.consumed,
                    state.transfer_amount,
                    state.transfer_source,
                    state.transfer_target,
                    state.transfer_prepared,
                    state.transfer_accepted,
                    state.next_lease_id,
                ),
            )

    # At most one transfer is modeled. It moves a pool right, not a lease right.
    if not state.transfer_prepared:
        for source, target in ((0, 1), (1, 0)):
            if state.pools[source] > 0:
                pools = list(state.pools)
                pools[source] -= 1
                yield (
                    "prepare_transfer",
                    State(
                        tuple(pools),
                        state.leases,
                        state.consumed,
                        1,
                        source,
                        target,
                        True,
                        False,
                        state.next_lease_id,
                    ),
                )
    elif not state.transfer_accepted:
        pools = list(state.pools)
        pools[state.transfer_target] += state.transfer_amount
        yield (
            "accept_transfer",
            State(
                tuple(pools),
                state.leases,
                state.consumed,
                state.transfer_amount,
                state.transfer_source,
                state.transfer_target,
                True,
                True,
                state.next_lease_id,
            ),
        )
    else:
        # Duplicate delivery is an idempotent self-loop. We record but do not enqueue it.
        yield "duplicate_accept", state


def main() -> None:
    initial = State((BUDGET // 2, BUDGET - BUDGET // 2), (), 0, 0, -1, -1, False, False, 0)
    queue = deque([(initial, 0)])
    seen = {initial}
    transitions = 0
    self_loops = 0
    while queue:
        state, depth = queue.popleft()
        validate(state)
        if depth >= MAX_DEPTH:
            continue
        for _label, nxt in successors(state):
            transitions += 1
            validate(nxt)
            if nxt == state:
                self_loops += 1
                continue
            if nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, depth + 1))
    result = {
        "budget": BUDGET,
        "max_depth": MAX_DEPTH,
        "max_leases": MAX_LEASES,
        "states_checked": len(seen),
        "transitions_checked": transitions,
        "idempotent_duplicate_self_loops": self_loops,
        "violations": 0,
    }
    out = Path(__file__).resolve().parents[1] / "results" / "model_check.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
