"""Bounded explicit-state checker for two-dimensional LETS resources.

This module is intentionally independent from :mod:`formal.model_checker`.  It
models two resource dimensions, attenuated delegation, heterogeneous action
costs, and two-phase inter-warden transfers.  The normal transition relation is
checked after every edge for component-wise conservation and spendable bounds.

The included mutant charges a ``(1, 5)`` action by subtracting ``(1, 0)`` from
the lease while still adding ``(1, 5)`` to consumed resources.  Breadth-first
search therefore returns a shortest vector-accounting counterexample.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

Vector = tuple[int, int]
ZERO: Vector = (0, 0)


@dataclass(frozen=True, order=True)
class ActionCost:
    name: str
    cost: Vector


ACTION_COSTS: tuple[ActionCost, ...] = (
    ActionCost("inspect_configuration", (1, 0)),
    ActionCost("restart_service", (0, 3)),
    ActionCost("rotate_credential", (1, 5)),
)

ROOT_ALLOCATIONS: tuple[Vector, ...] = ((1, 0), (0, 3), (1, 5), (2, 5))
SPAWN_ALLOCATIONS: tuple[Vector, ...] = ((1, 0), (0, 3), (1, 5))
TRANSFER_AMOUNTS: tuple[Vector, ...] = ((1, 0), (0, 3), (1, 5))


@dataclass(frozen=True, order=True)
class Lease:
    lease_id: int
    warden: int
    parent_id: int | None
    allocation: Vector
    residual: Vector
    active: bool


@dataclass(frozen=True, order=True)
class Transfer:
    transfer_id: int
    source: int
    target: int
    amount: Vector
    status: str


@dataclass(frozen=True)
class State:
    free: tuple[Vector, Vector]
    leases: tuple[Lease, ...]
    consumed: Vector
    in_flight: Vector
    transfers: tuple[Transfer, ...]
    next_lease_id: int
    next_transfer_id: int


@dataclass(frozen=True)
class Bounds:
    initial_free: tuple[Vector, Vector] = ((2, 5), (1, 3))
    max_leases: int = 2
    max_transfers: int = 1
    max_depth: int = 10


@dataclass(frozen=True)
class Edge:
    action: str
    state: State


class ModelViolationError(ValueError):
    """A named safety-property violation in a candidate state."""

    def __init__(self, property_name: str, message: str) -> None:
        super().__init__(message)
        self.property_name = property_name


def vadd(left: Vector, right: Vector) -> Vector:
    return left[0] + right[0], left[1] + right[1]


def vsub(left: Vector, right: Vector) -> Vector:
    return left[0] - right[0], left[1] - right[1]


def vleq(left: Vector, right: Vector) -> bool:
    return left[0] <= right[0] and left[1] <= right[1]


def vsum(vectors: Iterable[Vector]) -> Vector:
    total = ZERO
    for vector in vectors:
        total = vadd(total, vector)
    return total


def initial_state(bounds: Bounds) -> State:
    return State(
        free=bounds.initial_free,
        leases=(),
        consumed=ZERO,
        in_flight=ZERO,
        transfers=(),
        next_lease_id=0,
        next_transfer_id=0,
    )


def total_budget(bounds: Bounds) -> Vector:
    return vsum(bounds.initial_free)


def accounted_total(state: State) -> Vector:
    return vsum(
        (
            *state.free,
            *(lease.residual for lease in state.leases),
            state.consumed,
            state.in_flight,
        )
    )


def spendable_total(state: State) -> Vector:
    return vsum((*state.free, *(lease.residual for lease in state.leases)))


def validate_state(state: State, bounds: Bounds) -> None:
    """Assert all modeled invariants for ``state``.

    Conservation is checked before the spendable bound so the deliberately
    incorrect debit is classified as a conservation error rather than merely a
    downstream bound failure.
    """

    vectors = [*state.free, state.consumed, state.in_flight]
    vectors.extend(lease.allocation for lease in state.leases)
    vectors.extend(lease.residual for lease in state.leases)
    vectors.extend(transfer.amount for transfer in state.transfers)
    if any(len(vector) != 2 for vector in vectors):
        raise ModelViolationError("vector_shape", "all resource vectors must have two dimensions")
    if any(component < 0 for vector in vectors for component in vector):
        raise ModelViolationError(
            "nonnegative_resources", "resource components must be nonnegative"
        )

    lease_ids = [lease.lease_id for lease in state.leases]
    if len(lease_ids) != len(set(lease_ids)):
        raise ModelViolationError("unique_lease_ids", "lease identifiers must be unique")
    transfer_ids = [transfer.transfer_id for transfer in state.transfers]
    if len(transfer_ids) != len(set(transfer_ids)):
        raise ModelViolationError("unique_transfer_ids", "transfer identifiers must be unique")

    by_id = {lease.lease_id: lease for lease in state.leases}
    for lease in state.leases:
        if not vleq(lease.residual, lease.allocation):
            raise ModelViolationError("residual_bound", "lease residual exceeds its allocation")
        if not lease.active and lease.residual != ZERO:
            raise ModelViolationError(
                "closed_lease_empty", "closed lease retains residual resources"
            )
        if lease.parent_id is not None:
            parent = by_id.get(lease.parent_id)
            if parent is None or parent.lease_id >= lease.lease_id:
                raise ModelViolationError(
                    "delegation_parent", "delegated lease lacks an earlier parent"
                )
            if parent.warden != lease.warden:
                raise ModelViolationError(
                    "delegation_warden", "child and parent must share a warden"
                )

    prepared_total = vsum(
        transfer.amount for transfer in state.transfers if transfer.status == "prepared"
    )
    if any(transfer.status not in {"prepared", "accepted"} for transfer in state.transfers):
        raise ModelViolationError("transfer_status", "unknown transfer status")
    if prepared_total != state.in_flight:
        raise ModelViolationError(
            "in_flight_correspondence",
            f"in-flight {state.in_flight} does not match prepared transfers {prepared_total}",
        )

    expected = total_budget(bounds)
    observed = accounted_total(state)
    if observed != expected:
        raise ModelViolationError(
            "per_dimension_conservation",
            f"accounted total {observed} differs from initial budget {expected}",
        )
    spendable = spendable_total(state)
    if not vleq(spendable, expected):
        raise ModelViolationError(
            "per_dimension_spendable_bound",
            f"spendable total {spendable} exceeds initial budget {expected}",
        )


def _replace_lease(state: State, replacement: Lease) -> tuple[Lease, ...]:
    return tuple(
        replacement if item.lease_id == replacement.lease_id else item for item in state.leases
    )


def _replace_transfer(state: State, replacement: Transfer) -> tuple[Transfer, ...]:
    return tuple(
        replacement if item.transfer_id == replacement.transfer_id else item
        for item in state.transfers
    )


def _with_free(state: State, warden: int, value: Vector) -> tuple[Vector, Vector]:
    free = list(state.free)
    free[warden] = value
    return free[0], free[1]


def normal_successors(state: State, bounds: Bounds) -> Iterator[Edge]:
    """Yield deterministic normal transitions from ``state``."""

    if len(state.leases) < bounds.max_leases:
        for warden in range(2):
            for allocation in ROOT_ALLOCATIONS:
                if not vleq(allocation, state.free[warden]):
                    continue
                lease = Lease(
                    lease_id=state.next_lease_id,
                    warden=warden,
                    parent_id=None,
                    allocation=allocation,
                    residual=allocation,
                    active=True,
                )
                yield Edge(
                    f"issue_root(w={warden},allocation={allocation})",
                    State(
                        free=_with_free(state, warden, vsub(state.free[warden], allocation)),
                        leases=(*state.leases, lease),
                        consumed=state.consumed,
                        in_flight=state.in_flight,
                        transfers=state.transfers,
                        next_lease_id=state.next_lease_id + 1,
                        next_transfer_id=state.next_transfer_id,
                    ),
                )

        for parent in state.leases:
            if not parent.active:
                continue
            for allocation in SPAWN_ALLOCATIONS:
                if not vleq(allocation, parent.residual):
                    continue
                child = Lease(
                    lease_id=state.next_lease_id,
                    warden=parent.warden,
                    parent_id=parent.lease_id,
                    allocation=allocation,
                    residual=allocation,
                    active=True,
                )
                debited_parent = Lease(
                    lease_id=parent.lease_id,
                    warden=parent.warden,
                    parent_id=parent.parent_id,
                    allocation=parent.allocation,
                    residual=vsub(parent.residual, allocation),
                    active=True,
                )
                yield Edge(
                    f"spawn(parent={parent.lease_id},allocation={allocation})",
                    State(
                        free=state.free,
                        leases=(*_replace_lease(state, debited_parent), child),
                        consumed=state.consumed,
                        in_flight=state.in_flight,
                        transfers=state.transfers,
                        next_lease_id=state.next_lease_id + 1,
                        next_transfer_id=state.next_transfer_id,
                    ),
                )

    parent_ids = {lease.parent_id for lease in state.leases if lease.active}
    for lease in state.leases:
        if not lease.active:
            continue
        for action in ACTION_COSTS:
            if not vleq(action.cost, lease.residual):
                continue
            debited = Lease(
                lease_id=lease.lease_id,
                warden=lease.warden,
                parent_id=lease.parent_id,
                allocation=lease.allocation,
                residual=vsub(lease.residual, action.cost),
                active=True,
            )
            yield Edge(
                f"authorize(lease={lease.lease_id},action={action.name},cost={action.cost})",
                State(
                    free=state.free,
                    leases=_replace_lease(state, debited),
                    consumed=vadd(state.consumed, action.cost),
                    in_flight=state.in_flight,
                    transfers=state.transfers,
                    next_lease_id=state.next_lease_id,
                    next_transfer_id=state.next_transfer_id,
                ),
            )

        if lease.lease_id not in parent_ids:
            closed = Lease(
                lease_id=lease.lease_id,
                warden=lease.warden,
                parent_id=lease.parent_id,
                allocation=lease.allocation,
                residual=ZERO,
                active=False,
            )
            yield Edge(
                f"close(lease={lease.lease_id},refund={lease.residual})",
                State(
                    free=_with_free(
                        state,
                        lease.warden,
                        vadd(state.free[lease.warden], lease.residual),
                    ),
                    leases=_replace_lease(state, closed),
                    consumed=state.consumed,
                    in_flight=state.in_flight,
                    transfers=state.transfers,
                    next_lease_id=state.next_lease_id,
                    next_transfer_id=state.next_transfer_id,
                ),
            )

    if len(state.transfers) < bounds.max_transfers:
        for source, target in ((0, 1), (1, 0)):
            for amount in TRANSFER_AMOUNTS:
                if not vleq(amount, state.free[source]):
                    continue
                transfer = Transfer(
                    transfer_id=state.next_transfer_id,
                    source=source,
                    target=target,
                    amount=amount,
                    status="prepared",
                )
                yield Edge(
                    f"prepare_transfer(source={source},target={target},amount={amount})",
                    State(
                        free=_with_free(state, source, vsub(state.free[source], amount)),
                        leases=state.leases,
                        consumed=state.consumed,
                        in_flight=vadd(state.in_flight, amount),
                        transfers=(*state.transfers, transfer),
                        next_lease_id=state.next_lease_id,
                        next_transfer_id=state.next_transfer_id + 1,
                    ),
                )

    for transfer in state.transfers:
        if transfer.status != "prepared":
            continue
        accepted = Transfer(
            transfer_id=transfer.transfer_id,
            source=transfer.source,
            target=transfer.target,
            amount=transfer.amount,
            status="accepted",
        )
        yield Edge(
            f"accept_transfer(id={transfer.transfer_id},amount={transfer.amount})",
            State(
                free=_with_free(
                    state,
                    transfer.target,
                    vadd(state.free[transfer.target], transfer.amount),
                ),
                leases=state.leases,
                consumed=state.consumed,
                in_flight=vsub(state.in_flight, transfer.amount),
                transfers=_replace_transfer(state, accepted),
                next_lease_id=state.next_lease_id,
                next_transfer_id=state.next_transfer_id,
            ),
        )


def mutant_successors(state: State) -> Iterator[Edge]:
    """Yield the isolated cross-dimension debit fault.

    The rotate action costs ``(1, 5)``.  This mutant subtracts only ``(1, 0)``
    from residual while adding the full cost to consumed resources.
    """

    full_cost = (1, 5)
    incorrect_debit = (1, 0)
    for lease in state.leases:
        if not lease.active or not vleq(full_cost, lease.residual):
            continue
        debited = Lease(
            lease_id=lease.lease_id,
            warden=lease.warden,
            parent_id=lease.parent_id,
            allocation=lease.allocation,
            residual=vsub(lease.residual, incorrect_debit),
            active=True,
        )
        yield Edge(
            (
                "MUTANT_cross_dimension_debit"
                f"(lease={lease.lease_id},cost={full_cost},debited={incorrect_debit})"
            ),
            State(
                free=state.free,
                leases=_replace_lease(state, debited),
                consumed=vadd(state.consumed, full_cost),
                in_flight=state.in_flight,
                transfers=state.transfers,
                next_lease_id=state.next_lease_id,
                next_transfer_id=state.next_transfer_id,
            ),
        )


def _action_kind(action: str) -> str:
    if action.startswith("authorize"):
        for item in ACTION_COSTS:
            if f"action={item.name}" in action:
                return f"authorize:{item.name}"
    return action.split("(", 1)[0]


def _state_payload(state: State) -> dict[str, object]:
    return {
        "free": [list(vector) for vector in state.free],
        "residual": [
            {
                "lease_id": lease.lease_id,
                "warden": lease.warden,
                "parent_id": lease.parent_id,
                "allocation": list(lease.allocation),
                "residual": list(lease.residual),
                "active": lease.active,
            }
            for lease in state.leases
        ],
        "consumed": list(state.consumed),
        "in_flight": list(state.in_flight),
        "transfers": [
            {
                "transfer_id": transfer.transfer_id,
                "source": transfer.source,
                "target": transfer.target,
                "amount": list(transfer.amount),
                "status": transfer.status,
            }
            for transfer in state.transfers
        ],
    }


def _trace(
    state: State,
    parent: dict[State, tuple[State, str] | None],
    final_action: str | None = None,
    final_state: State | None = None,
) -> list[dict[str, object]]:
    steps: list[tuple[str, State]] = []
    cursor = state
    while parent[cursor] is not None:
        previous, action = parent[cursor]  # type: ignore[misc]
        steps.append((action, cursor))
        cursor = previous
    steps.reverse()
    if final_action is not None and final_state is not None:
        steps.append((final_action, final_state))
    return [
        {"step": index, "action": action, "state": _state_payload(item)}
        for index, (action, item) in enumerate(steps, start=1)
    ]


def explore(bounds: Bounds, *, include_mutant: bool) -> dict[str, object]:
    """Run deterministic BFS and return machine-readable evidence."""

    start = initial_state(bounds)
    validate_state(start, bounds)
    queue: deque[State] = deque([start])
    parent: dict[State, tuple[State, str] | None] = {start: None}
    depth: dict[State, int] = {start: 0}
    states_by_depth: Counter[int] = Counter({0: 1})
    transitions_by_depth: Counter[int] = Counter()
    action_counts: Counter[str] = Counter()
    transitions_checked = 0
    cutoff_states: list[State] = []
    maximum_depth = 0

    while queue:
        current = queue.popleft()
        current_depth = depth[current]
        maximum_depth = max(maximum_depth, current_depth)
        if current_depth == bounds.max_depth:
            cutoff_states.append(current)
            continue

        edges: Sequence[Edge] = tuple(normal_successors(current, bounds))
        if include_mutant:
            edges = (*edges, *tuple(mutant_successors(current)))
        for edge in edges:
            transitions_checked += 1
            transitions_by_depth[current_depth] += 1
            action_counts[_action_kind(edge.action)] += 1
            try:
                validate_state(edge.state, bounds)
            except ModelViolationError as violation:
                counterexample = _trace(
                    current,
                    parent,
                    final_action=edge.action,
                    final_state=edge.state,
                )
                return {
                    "passed": False,
                    "termination": "counterexample",
                    "frontier_exhausted": False,
                    "states_checked": len(parent),
                    "transitions_checked": transitions_checked,
                    "maximum_shortest_depth": maximum_depth,
                    "states_by_shortest_depth": {
                        str(key): states_by_depth[key] for key in sorted(states_by_depth)
                    },
                    "transitions_by_source_depth": {
                        str(key): transitions_by_depth[key] for key in sorted(transitions_by_depth)
                    },
                    "action_counts": dict(sorted(action_counts.items())),
                    "cutoff_states": len(cutoff_states),
                    "unseen_successors_at_cutoff": None,
                    "violated_property": violation.property_name,
                    "violation": str(violation),
                    "counterexample_depth": len(counterexample),
                    "shortest_trace": counterexample,
                }
            if edge.state not in parent:
                parent[edge.state] = (current, edge.action)
                depth[edge.state] = current_depth + 1
                states_by_depth[current_depth + 1] += 1
                queue.append(edge.state)

    unseen_at_cutoff: set[State] = set()
    cutoff_transition_count = 0
    for current in cutoff_states:
        for edge in normal_successors(current, bounds):
            cutoff_transition_count += 1
            if edge.state not in parent:
                unseen_at_cutoff.add(edge.state)
        if include_mutant:
            for edge in mutant_successors(current):
                cutoff_transition_count += 1
                if edge.state not in parent:
                    unseen_at_cutoff.add(edge.state)

    frontier_exhausted = not unseen_at_cutoff
    return {
        "passed": True,
        "termination": "frontier_exhausted" if frontier_exhausted else "depth_limit",
        "frontier_exhausted": frontier_exhausted,
        "states_checked": len(parent),
        "transitions_checked": transitions_checked,
        "maximum_shortest_depth": maximum_depth,
        "states_by_shortest_depth": {
            str(key): states_by_depth[key] for key in sorted(states_by_depth)
        },
        "transitions_by_source_depth": {
            str(key): transitions_by_depth[key] for key in sorted(transitions_by_depth)
        },
        "action_counts": dict(sorted(action_counts.items())),
        "cutoff_states": len(cutoff_states),
        "cutoff_transitions_probed": cutoff_transition_count,
        "unseen_successors_at_cutoff": len(unseen_at_cutoff),
        "violated_property": None,
        "violation": None,
        "counterexample_depth": None,
        "shortest_trace": [],
    }


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounds_payload(bounds: Bounds) -> dict[str, object]:
    return {
        "initial_free": [list(vector) for vector in bounds.initial_free],
        "total_budget": list(total_budget(bounds)),
        "max_leases": bounds.max_leases,
        "max_transfers": bounds.max_transfers,
        "max_depth": bounds.max_depth,
    }


def run_suite(bounds: Bounds | None = None) -> dict[str, object]:
    if bounds is None:
        bounds = Bounds()
    baseline = explore(bounds, include_mutant=False)
    mutant = explore(bounds, include_mutant=True)
    expected_property = "per_dimension_conservation"
    mutant_killed = not bool(mutant["passed"]) and mutant["violated_property"] == expected_property
    source_path = Path(__file__).resolve()
    config_payload = {
        "bounds": _bounds_payload(bounds),
        "action_costs": {item.name: list(item.cost) for item in ACTION_COSTS},
        "root_allocations": [list(vector) for vector in ROOT_ALLOCATIONS],
        "spawn_allocations": [list(vector) for vector in SPAWN_ALLOCATIONS],
        "transfer_amounts": [list(vector) for vector in TRANSFER_AMOUNTS],
        "mutant": "cross_dimension_debit",
    }
    return {
        "schema_version": 1,
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "checker": "standalone_bounded_two_dimensional_explicit_state_bfs",
        "dimensions": ["operation_tokens", "service_impact_units"],
        "bounds": _bounds_payload(bounds),
        "action_costs": config_payload["action_costs"],
        "modeled_actions": [
            "issue_root",
            "attenuated_spawn",
            "authorize",
            "close_leaf",
            "prepare_transfer",
            "accept_transfer",
        ],
        "invariants": [
            "component-wise conservation of free + residual + consumed + in-flight",
            "component-wise spendable free + residual <= initial budget",
            "prepared transfers exactly equal explicit in-flight resources",
            "child delegation is warden-local and debits parent residual",
        ],
        "baseline": baseline,
        "mutant": {
            "name": "cross_dimension_debit",
            "description": "charge (1,5), debit residual by only (1,0)",
            "expected_property": expected_property,
            "killed": mutant_killed,
            **mutant,
        },
        "success": bool(baseline["passed"]) and mutant_killed,
        "model_sha256": _sha256_bytes(source_path.read_bytes()),
        "configuration_sha256": _sha256_bytes(
            json.dumps(config_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ),
    }


def render_markdown(result: dict[str, object]) -> str:
    baseline = result["baseline"]
    mutant = result["mutant"]
    assert isinstance(baseline, dict)
    assert isinstance(mutant, dict)
    costs = result["action_costs"]
    assert isinstance(costs, dict)
    trace = mutant["shortest_trace"]
    assert isinstance(trace, list)
    lines = [
        "# Two-dimensional bounded model-checking results",
        "",
        f"Generated: `{result['generated_at_utc']}`",
        "",
        "This is standalone evidence; it does not alter the retained scalar checker.",
        "",
        "## Configuration",
        "",
        f"- Bounds: `{json.dumps(result['bounds'], sort_keys=True)}`",
        f"- Heterogeneous costs: `{json.dumps(costs, sort_keys=True)}`",
        f"- Model SHA-256: `{result['model_sha256']}`",
        f"- Configuration SHA-256: `{result['configuration_sha256']}`",
        "",
        "## Baseline",
        "",
        f"- Passed all checked invariants: **{str(baseline['passed']).lower()}**",
        f"- Termination: `{baseline['termination']}`",
        f"- Frontier exhausted: **{str(baseline['frontier_exhausted']).lower()}**",
        f"- States checked: **{baseline['states_checked']}**",
        f"- Transitions checked: **{baseline['transitions_checked']}**",
        f"- Maximum shortest depth: **{baseline['maximum_shortest_depth']}**",
        f"- Cutoff states: **{baseline['cutoff_states']}**",
        f"- Cutoff transitions probed: **{baseline['cutoff_transitions_probed']}**",
        f"- Unseen successors at cutoff: **{baseline['unseen_successors_at_cutoff']}**",
        "",
        "Action coverage:",
        "",
        "| Action kind | Explored transitions |",
        "|---|---:|",
    ]
    action_counts = baseline["action_counts"]
    assert isinstance(action_counts, dict)
    lines.extend(f"| `{name}` | {count} |" for name, count in action_counts.items())
    lines.extend(
        [
            "",
            "## Vector-accounting mutant",
            "",
            f"- Mutant: `{mutant['name']}`",
            f"- Killed: **{str(mutant['killed']).lower()}**",
            f"- Violated property: `{mutant['violated_property']}`",
            f"- Shortest counterexample depth: **{mutant['counterexample_depth']}**",
            f"- States checked before detection: **{mutant['states_checked']}**",
            f"- Transitions checked before detection: **{mutant['transitions_checked']}**",
            "",
            "Shortest trace:",
            "",
        ]
    )
    for step in trace:
        assert isinstance(step, dict)
        lines.append(f"{step['step']}. `{step['action']}`")
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "A passing baseline establishes only the listed invariants over this finite "
            "configuration. "
            "If `frontier_exhausted` is false, unseen successors remain beyond the recorded depth. "
            "The mutant result shows sensitivity to one deliberately injected "
            "vector-accounting fault; "
            "it is not a proof about all possible implementation defects.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_new(path: Path, data: str, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-depth", type=int, default=Bounds.max_depth)
    parser.add_argument("--max-leases", type=int, default=Bounds.max_leases)
    parser.add_argument("--max-transfers", type=int, default=Bounds.max_transfers)
    parser.add_argument(
        "--json-out",
        type=Path,
        default=Path("results/nsdi-strengthening-2026-08-31/formal/vector-model.json"),
    )
    parser.add_argument(
        "--markdown-out",
        type=Path,
        default=Path("results/nsdi-strengthening-2026-08-31/formal/VECTOR-MODEL-RESULTS.md"),
    )
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    if args.max_depth < 0 or args.max_leases < 0 or args.max_transfers < 0:
        raise SystemExit("bounds must be nonnegative")
    bounds = Bounds(
        max_depth=args.max_depth,
        max_leases=args.max_leases,
        max_transfers=args.max_transfers,
    )
    result = run_suite(bounds)
    json_text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    markdown_text = render_markdown(result)
    _write_new(args.json_out, json_text, overwrite=args.overwrite)
    _write_new(args.markdown_out, markdown_text, overwrite=args.overwrite)
    print(json_text, end="")
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
