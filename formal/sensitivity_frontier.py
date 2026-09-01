"""Standalone frontier and mutation-sensitivity analysis for the LETS model.

This module deliberately leaves :mod:`formal.model_checker` and its retained
evidence unchanged.  Frontier mode repeats the checker's breadth-first search
while retaining shortest-depth statistics and probing (without enqueuing) the
successors at the configured cutoff.  Sensitivity mode layers observation-only
metadata over the existing state so properties that the compact retained model
cannot represent directly can still be challenged by isolated mutants.

The analysis is bounded evidence, not a proof.  Resource ceilings and a wall
clock deadline are mandatory so an accidental parameter increase fails as an
explicit incomplete analysis instead of consuming unbounded resources.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
from collections import Counter, deque
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import formal.model_checker as retained
from formal.model_checker import Bounds, InvariantViolationError, Lease, State

SCHEMA = "lets.formal-sensitivity-frontier/v1"
DEFAULT_MAX_STATES = 250_000
DEFAULT_MAX_TRANSITIONS = 2_000_000
DEFAULT_TIMEOUT_SECONDS = 60.0
SENSITIVITY_INITIAL_SHARES = (2, 1)
SENSITIVITY_MAX_LEASES = 3
SENSITIVITY_MAX_TRANSFERS = 2
SENSITIVITY_MAX_RECEIPTS = 2
SENSITIVITY_MAX_DEPTH = 6

Termination = Literal[
    "counterexample",
    "depth_limit",
    "frontier_exhausted",
    "invariant_violation",
    "resource_limit",
]


@dataclass(frozen=True, order=True, slots=True)
class AuthorizationEvent:
    receipt_id: int
    expected_sequence: int
    prior_sequence: int


@dataclass(frozen=True, order=True, slots=True)
class InboundEvent:
    transfer_id: int
    source: int
    target: int
    sequence: int
    has_source_voucher: bool


@dataclass(frozen=True, order=True, slots=True)
class CheckpointEvent:
    source: int
    target: int
    through_sequence: int


@dataclass(frozen=True, slots=True)
class SensitivityState:
    core: State
    claim_events: tuple[int, ...] = ()
    authorization_events: tuple[AuthorizationEvent, ...] = ()
    inbound_events: tuple[InboundEvent, ...] = ()
    checkpoints: tuple[CheckpointEvent, ...] = ()


@dataclass(frozen=True, slots=True)
class MutantSpec:
    mutant_id: str
    expected_property: str
    description: str

    @property
    def digest(self) -> str:
        return _json_digest(asdict(self))


MUTANTS = (
    MutantSpec(
        "spawn_without_parent_debit",
        "global_conservation",
        "Spawn creates child residual without reducing the parent residual.",
    ),
    MutantSpec(
        "timeout_source_restore_after_accept",
        "global_conservation",
        "A timeout restores source capacity after the target accepted the transfer.",
    ),
    MutantSpec(
        "duplicate_claim_accepted",
        "claim_at_most_once",
        "An already claimed receipt is accepted as another settlement event.",
    ),
    MutantSpec(
        "close_parent_with_live_descendant",
        "active_descendant_has_active_ancestors",
        "Close reclaims a parent while one of its descendants remains active.",
    ),
    MutantSpec(
        "stale_sequence_authorization",
        "authorization_sequence_freshness",
        "Authorization accepts an expected sequence older than the lease sequence.",
    ),
    MutantSpec(
        "ghost_inbound_without_voucher",
        "transfer_origin",
        "Inbound acceptance credits a target without a corresponding source voucher.",
    ),
    MutantSpec(
        "noncontiguous_checkpoint",
        "checkpoint_contiguity",
        "A checkpoint advances through a sequence whose earlier prefix is not finalized.",
    ),
)
MUTANT_BY_ID = {mutant.mutant_id: mutant for mutant in MUTANTS}


class SensitivityPropertyError(AssertionError):
    def __init__(self, property_name: str, message: str) -> None:
        super().__init__(message)
        self.property_name = property_name


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _json_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _analyzer_digest() -> str:
    return _sha256(Path(__file__))


def _model_digest() -> str:
    model_path = Path(retained.__file__)
    return _sha256(model_path)


def _bounds_payload(bounds: Bounds) -> dict[str, object]:
    return {
        "initial_shares": list(bounds.initial_shares),
        "budget": bounds.budget,
        "max_leases": bounds.max_leases,
        "max_transfers": bounds.max_transfers,
        "max_receipts": bounds.max_receipts,
        "max_depth": bounds.max_depth,
        "max_action_amount": bounds.max_action_amount,
    }


def _resource_reason(
    *,
    started: float,
    states: int,
    transitions: int,
    max_states: int,
    max_transitions: int,
    timeout_seconds: float,
) -> str | None:
    if states > max_states:
        return f"state limit exceeded ({states} > {max_states})"
    if transitions > max_transitions:
        return f"transition limit exceeded ({transitions} > {max_transitions})"
    elapsed = time.monotonic() - started
    if elapsed > timeout_seconds:
        return f"deadline exceeded ({elapsed:.3f}s > {timeout_seconds:.3f}s)"
    return None


def analyze_frontier(
    bounds: Bounds,
    *,
    max_states: int = DEFAULT_MAX_STATES,
    max_transitions: int = DEFAULT_MAX_TRANSITIONS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Explore through ``bounds.max_depth`` and inspect its unexpanded frontier."""

    _validate_resource_limits(max_states, max_transitions, timeout_seconds)
    started = time.monotonic()
    initial = retained.initial_state(bounds)
    queue = deque([(initial, 0)])
    seen = {initial}
    states_by_depth: Counter[int] = Counter({0: 1})
    expanded_transitions_by_depth: Counter[int] = Counter()
    checked_transitions_by_depth: Counter[int] = Counter()
    self_loops_by_depth: Counter[int] = Counter()
    cutoff_states = 0
    cutoff_probe_transitions = 0
    cutoff_probe_labels: Counter[str] = Counter()
    unseen_cutoff_successors: set[State] = set()
    expanded_transitions = 0
    maximum_depth = 0
    violation: dict[str, object] | None = None
    resource_limit: str | None = None

    while queue and violation is None and resource_limit is None:
        resource_limit = _resource_reason(
            started=started,
            states=len(seen),
            transitions=expanded_transitions + cutoff_probe_transitions,
            max_states=max_states,
            max_transitions=max_transitions,
            timeout_seconds=timeout_seconds,
        )
        if resource_limit is not None:
            break
        state, depth = queue.popleft()
        maximum_depth = max(maximum_depth, depth)
        try:
            retained.validate(state, bounds)
        except InvariantViolationError as exc:
            violation = {"property": exc.invariant, "message": str(exc), "depth": depth}
            break

        if depth >= bounds.max_depth:
            cutoff_states += 1
            for label, candidate in retained.successors(state, bounds):
                cutoff_probe_transitions += 1
                checked_transitions_by_depth[depth] += 1
                cutoff_probe_labels[label.split("(", 1)[0]] += 1
                resource_limit = _resource_reason(
                    started=started,
                    states=len(seen) + len(unseen_cutoff_successors),
                    transitions=expanded_transitions + cutoff_probe_transitions,
                    max_states=max_states,
                    max_transitions=max_transitions,
                    timeout_seconds=timeout_seconds,
                )
                if resource_limit is not None:
                    break
                try:
                    retained.validate(candidate, bounds)
                except InvariantViolationError as exc:
                    violation = {
                        "property": exc.invariant,
                        "message": str(exc),
                        "depth": depth + 1,
                        "action": label,
                    }
                    break
                if candidate != state and candidate not in seen:
                    unseen_cutoff_successors.add(candidate)
            continue

        for label, candidate in retained.successors(state, bounds):
            expanded_transitions += 1
            expanded_transitions_by_depth[depth] += 1
            checked_transitions_by_depth[depth] += 1
            resource_limit = _resource_reason(
                started=started,
                states=len(seen),
                transitions=expanded_transitions + cutoff_probe_transitions,
                max_states=max_states,
                max_transitions=max_transitions,
                timeout_seconds=timeout_seconds,
            )
            if resource_limit is not None:
                break
            try:
                retained.validate(candidate, bounds)
            except InvariantViolationError as exc:
                violation = {
                    "property": exc.invariant,
                    "message": str(exc),
                    "depth": depth + 1,
                    "action": label,
                }
                break
            if candidate == state:
                self_loops_by_depth[depth] += 1
            elif candidate not in seen:
                if len(seen) >= max_states:
                    resource_limit = f"state limit reached ({max_states})"
                    break
                seen.add(candidate)
                states_by_depth[depth + 1] += 1
                queue.append((candidate, depth + 1))

    if resource_limit is not None:
        termination: Termination = "resource_limit"
    elif violation is not None:
        termination = "invariant_violation"
    elif cutoff_states > 0 and unseen_cutoff_successors:
        termination = "depth_limit"
    else:
        termination = "frontier_exhausted"

    elapsed = time.monotonic() - started
    depth_keys = sorted(states_by_depth)
    return {
        "schema": "lets.frontier-analysis/v1",
        "bounds": _bounds_payload(bounds),
        "states_checked": len(seen),
        "expanded_transitions_checked": expanded_transitions,
        "self_loops_checked": sum(self_loops_by_depth.values()),
        "maximum_depth_reached": maximum_depth,
        "states_by_shortest_depth": {str(depth): states_by_depth[depth] for depth in depth_keys},
        "transitions_by_source_shortest_depth": {
            str(depth): checked_transitions_by_depth[depth]
            for depth in sorted(checked_transitions_by_depth)
        },
        "expanded_transitions_by_source_shortest_depth": {
            str(depth): expanded_transitions_by_depth[depth]
            for depth in sorted(expanded_transitions_by_depth)
        },
        "self_loops_by_source_shortest_depth": {
            str(depth): self_loops_by_depth[depth] for depth in sorted(self_loops_by_depth)
        },
        "cutoff_depth": bounds.max_depth,
        "cutoff_states": cutoff_states,
        "cutoff_probe_transitions": cutoff_probe_transitions,
        "cutoff_probe_action_kinds": dict(sorted(cutoff_probe_labels.items())),
        "unseen_successors_at_cutoff": len(unseen_cutoff_successors),
        "termination": termination,
        "frontier_exhausted": termination == "frontier_exhausted",
        "passed": violation is None and resource_limit is None,
        "violation": violation,
        "resource_limit": resource_limit,
        "elapsed_seconds": elapsed,
        "model_digest": _model_digest(),
        "analyzer_digest": _analyzer_digest(),
    }


def _replace_lease(core: State, changed: Lease) -> tuple[Lease, ...]:
    return tuple(
        sorted(changed if lease.lease_id == changed.lease_id else lease for lease in core.leases)
    )


def _successful_base_metadata(
    state: SensitivityState,
    candidate: State,
) -> tuple[
    tuple[int, ...],
    tuple[AuthorizationEvent, ...],
    tuple[InboundEvent, ...],
]:
    claim_events = list(state.claim_events)
    authorization_events = list(state.authorization_events)
    inbound_events = list(state.inbound_events)

    new_claims = candidate.claimed_receipts - state.core.claimed_receipts
    claim_events.extend(sorted(new_claims))

    known_receipts = {receipt.receipt_id for receipt in state.core.receipts}
    for receipt in candidate.receipts:
        if receipt.receipt_id not in known_receipts:
            prior = next(
                lease.sequence for lease in state.core.leases if lease.lease_id == receipt.lease_id
            )
            authorization_events.append(AuthorizationEvent(receipt.receipt_id, prior, prior))

    previous_transfers = {transfer.transfer_id: transfer for transfer in state.core.transfers}
    for transfer in candidate.transfers:
        previous = previous_transfers.get(transfer.transfer_id)
        if previous is not None and previous.status == "PREPARED" and transfer.status == "ACCEPTED":
            inbound_events.append(
                InboundEvent(
                    transfer.transfer_id,
                    transfer.source,
                    transfer.target,
                    transfer.sequence,
                    True,
                )
            )

    return tuple(claim_events), tuple(authorization_events), tuple(inbound_events)


def _valid_checkpoint_successors(
    state: SensitivityState,
) -> Iterable[tuple[str, SensitivityState]]:
    streams = sorted({(item.source, item.target) for item in state.core.transfers})
    for source, target in streams:
        transfers = {
            item.sequence: item
            for item in state.core.transfers
            if item.source == source and item.target == target
        }
        through = 0
        while transfers.get(through + 1) is not None and (
            transfers[through + 1].status == "FINALIZED"
        ):
            through += 1
        prior = max(
            (
                checkpoint.through_sequence
                for checkpoint in state.checkpoints
                if checkpoint.source == source and checkpoint.target == target
            ),
            default=0,
        )
        if through > prior:
            checkpoint = CheckpointEvent(source, target, through)
            yield (
                f"checkpoint(source={source},target={target},through={through})",
                replace(
                    state,
                    checkpoints=tuple(sorted((*state.checkpoints, checkpoint))),
                ),
            )


def _base_sensitivity_successors(
    state: SensitivityState,
    bounds: Bounds,
) -> Iterable[tuple[str, SensitivityState]]:
    for label, core_candidate in retained.successors(state.core, bounds):
        claims, authorizations, inbound = _successful_base_metadata(state, core_candidate)
        yield (
            label,
            replace(
                state,
                core=core_candidate,
                claim_events=claims,
                authorization_events=authorizations,
                inbound_events=inbound,
            ),
        )
    yield from _valid_checkpoint_successors(state)


def _fault_successors(
    state: SensitivityState,
    bounds: Bounds,
    mutant_id: str,
) -> Iterable[tuple[str, SensitivityState]]:
    core = state.core
    if mutant_id == "spawn_without_parent_debit":
        if len(core.leases) >= bounds.max_leases:
            return
        for parent in core.leases:
            if not parent.active:
                continue
            for amount in range(1, min(parent.residual, bounds.max_action_amount) + 1):
                child = Lease(
                    core.next_lease_id,
                    parent.warden,
                    parent.lease_id,
                    amount,
                    True,
                    0,
                )
                candidate = replace(
                    core,
                    leases=tuple(sorted((*core.leases, child))),
                    next_lease_id=core.next_lease_id + 1,
                )
                yield (
                    f"faulty_spawn_without_debit(parent={parent.lease_id},amount={amount})",
                    replace(state, core=candidate),
                )
        return

    if mutant_id == "timeout_source_restore_after_accept":
        for transfer in core.transfers:
            if transfer.status != "ACCEPTED":
                continue
            pools = list(core.pools)
            pools[transfer.source] += transfer.amount
            yield (
                f"faulty_timeout_restore(transfer={transfer.transfer_id})",
                replace(state, core=replace(core, pools=tuple(pools))),
            )
        return

    if mutant_id == "duplicate_claim_accepted":
        for receipt_id in sorted(core.claimed_receipts):
            yield (
                f"faulty_duplicate_claim(receipt={receipt_id})",
                replace(state, claim_events=(*state.claim_events, receipt_id)),
            )
        return

    if mutant_id == "close_parent_with_live_descendant":
        for parent in core.leases:
            if not parent.active or not any(
                child.parent_id == parent.lease_id and child.active for child in core.leases
            ):
                continue
            pools = list(core.pools)
            pools[parent.warden] += parent.residual
            changed = replace(
                parent,
                residual=0,
                active=False,
                sequence=parent.sequence + 1,
            )
            candidate = replace(
                core,
                pools=tuple(pools),
                leases=_replace_lease(core, changed),
            )
            yield (
                f"faulty_close_live_parent(lease={parent.lease_id})",
                replace(state, core=candidate),
            )
        return

    if mutant_id == "stale_sequence_authorization":
        if len(core.receipts) >= bounds.max_receipts:
            return
        for lease in core.leases:
            if not lease.active or lease.sequence <= 0:
                continue
            for cost in range(1, min(lease.residual, bounds.max_action_amount) + 1):
                candidate = retained.authorize(core, lease.lease_id, cost)
                receipt = candidate.receipts[-1]
                event = AuthorizationEvent(
                    receipt.receipt_id,
                    lease.sequence - 1,
                    lease.sequence,
                )
                yield (
                    (
                        "faulty_stale_authorize("
                        f"lease={lease.lease_id},expected={lease.sequence - 1},cost={cost})"
                    ),
                    replace(
                        state,
                        core=candidate,
                        authorization_events=(*state.authorization_events, event),
                    ),
                )
        return

    if mutant_id == "ghost_inbound_without_voucher":
        source = 0
        target = 1
        pools = list(core.pools)
        pools[target] += 1
        ghost = InboundEvent(0, source, target, 1, False)
        yield (
            "faulty_ghost_inbound(source=0,target=1,sequence=1,amount=1)",
            replace(
                state,
                core=replace(core, pools=tuple(pools)),
                inbound_events=(*state.inbound_events, ghost),
            ),
        )
        return

    if mutant_id == "noncontiguous_checkpoint":
        streams = sorted({(item.source, item.target) for item in core.transfers})
        for source, target in streams:
            transfers = {
                item.sequence: item
                for item in core.transfers
                if item.source == source and item.target == target
            }
            finalized = sorted(
                sequence
                for sequence, transfer in transfers.items()
                if transfer.status == "FINALIZED"
            )
            if not finalized:
                continue
            through = max(finalized)
            contiguous = 0
            while transfers.get(contiguous + 1) is not None and (
                transfers[contiguous + 1].status == "FINALIZED"
            ):
                contiguous += 1
            if through <= contiguous:
                continue
            prior = max(
                (
                    checkpoint.through_sequence
                    for checkpoint in state.checkpoints
                    if checkpoint.source == source and checkpoint.target == target
                ),
                default=0,
            )
            if through <= prior:
                continue
            checkpoint = CheckpointEvent(source, target, through)
            yield (
                (
                    "faulty_noncontiguous_checkpoint("
                    f"source={source},target={target},through={through})"
                ),
                replace(
                    state,
                    checkpoints=tuple(sorted((*state.checkpoints, checkpoint))),
                ),
            )
        return

    raise ValueError(f"unknown mutant {mutant_id!r}")


def _sensitivity_successors(
    state: SensitivityState,
    bounds: Bounds,
    mutant_id: str | None,
) -> Iterable[tuple[str, SensitivityState]]:
    yield from _base_sensitivity_successors(state, bounds)
    if mutant_id is not None:
        yield from _fault_successors(state, bounds, mutant_id)


def _validate_active_ancestors(state: SensitivityState) -> None:
    leases = {lease.lease_id: lease for lease in state.core.leases}
    for lease in state.core.leases:
        if not lease.active:
            continue
        parent_id = lease.parent_id
        visited: set[int] = set()
        while parent_id is not None:
            if parent_id in visited:
                break
            visited.add(parent_id)
            parent = leases.get(parent_id)
            if parent is None or not parent.active:
                raise SensitivityPropertyError(
                    "active_descendant_has_active_ancestors",
                    f"active lease {lease.lease_id} has inactive or missing ancestor {parent_id}",
                )
            parent_id = parent.parent_id


def _validate_claim_events(state: SensitivityState) -> None:
    duplicated = [
        receipt_id for receipt_id, count in Counter(state.claim_events).items() if count > 1
    ]
    if duplicated:
        raise SensitivityPropertyError(
            "claim_at_most_once",
            f"receipt claims were accepted more than once: {sorted(duplicated)}",
        )


def _validate_authorization_events(state: SensitivityState) -> None:
    for event in state.authorization_events:
        if event.expected_sequence != event.prior_sequence:
            raise SensitivityPropertyError(
                "authorization_sequence_freshness",
                (
                    f"receipt {event.receipt_id} accepted expected sequence "
                    f"{event.expected_sequence} at prior sequence {event.prior_sequence}"
                ),
            )


def _validate_inbound_events(state: SensitivityState) -> None:
    transfers = {transfer.transfer_id: transfer for transfer in state.core.transfers}
    for event in state.inbound_events:
        transfer = transfers.get(event.transfer_id)
        if (
            not event.has_source_voucher
            or transfer is None
            or transfer.source != event.source
            or transfer.target != event.target
            or transfer.sequence != event.sequence
            or transfer.status not in {"ACCEPTED", "FINALIZED"}
        ):
            raise SensitivityPropertyError(
                "transfer_origin",
                (
                    f"inbound ({event.source},{event.target},{event.sequence}) "
                    "has no corresponding accepted source voucher"
                ),
            )


def _validate_checkpoints(state: SensitivityState) -> None:
    for checkpoint in state.checkpoints:
        transfers = {
            item.sequence: item
            for item in state.core.transfers
            if item.source == checkpoint.source and item.target == checkpoint.target
        }
        missing = [
            sequence
            for sequence in range(1, checkpoint.through_sequence + 1)
            if transfers.get(sequence) is None or transfers[sequence].status != "FINALIZED"
        ]
        if missing:
            raise SensitivityPropertyError(
                "checkpoint_contiguity",
                (
                    f"checkpoint through {checkpoint.through_sequence} has a nonfinalized "
                    f"prefix at sequences {missing}"
                ),
            )


def validate_sensitivity(state: SensitivityState, bounds: Bounds) -> None:
    """Evaluate independent analyzer properties, then the retained invariants."""

    _validate_active_ancestors(state)
    _validate_claim_events(state)
    _validate_authorization_events(state)
    _validate_inbound_events(state)
    _validate_checkpoints(state)
    retained.validate(state.core, bounds)


def _trace_to(
    state: SensitivityState,
    final_action: str,
    parents: dict[SensitivityState, tuple[SensitivityState, str]],
) -> tuple[str, ...]:
    trace = [final_action]
    cursor = state
    while cursor in parents:
        cursor, action = parents[cursor]
        trace.append(action)
    trace.reverse()
    return tuple(trace)


def analyze_sensitivity_case(
    bounds: Bounds,
    *,
    mutant: MutantSpec | None,
    max_states: int = DEFAULT_MAX_STATES,
    max_transitions: int = DEFAULT_MAX_TRANSITIONS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Run one breadth-first baseline or isolated-mutant analysis."""

    _validate_resource_limits(max_states, max_transitions, timeout_seconds)
    started = time.monotonic()
    initial = SensitivityState(retained.initial_state(bounds))
    queue = deque([(initial, 0)])
    seen = {initial}
    parents: dict[SensitivityState, tuple[SensitivityState, str]] = {}
    transitions = 0
    maximum_depth = 0
    violation: dict[str, object] | None = None
    trace: tuple[str, ...] = ()
    resource_limit: str | None = None
    reached_cutoff = False
    mutant_id = None if mutant is None else mutant.mutant_id

    validate_sensitivity(initial, bounds)
    while queue and violation is None and resource_limit is None:
        resource_limit = _resource_reason(
            started=started,
            states=len(seen),
            transitions=transitions,
            max_states=max_states,
            max_transitions=max_transitions,
            timeout_seconds=timeout_seconds,
        )
        if resource_limit is not None:
            break
        state, depth = queue.popleft()
        maximum_depth = max(maximum_depth, depth)
        if depth >= bounds.max_depth:
            reached_cutoff = True
            continue
        for label, candidate in _sensitivity_successors(state, bounds, mutant_id):
            transitions += 1
            resource_limit = _resource_reason(
                started=started,
                states=len(seen),
                transitions=transitions,
                max_states=max_states,
                max_transitions=max_transitions,
                timeout_seconds=timeout_seconds,
            )
            if resource_limit is not None:
                break
            try:
                validate_sensitivity(candidate, bounds)
            except SensitivityPropertyError as exc:
                trace = _trace_to(state, label, parents)
                violation = {
                    "property": exc.property_name,
                    "message": str(exc),
                }
                break
            except InvariantViolationError as exc:
                trace = _trace_to(state, label, parents)
                violation = {"property": exc.invariant, "message": str(exc)}
                break
            if candidate != state and candidate not in seen:
                if len(seen) >= max_states:
                    resource_limit = f"state limit reached ({max_states})"
                    break
                seen.add(candidate)
                parents[candidate] = (state, label)
                queue.append((candidate, depth + 1))

    if violation is not None:
        termination: Termination = "counterexample"
    elif resource_limit is not None:
        termination = "resource_limit"
    elif reached_cutoff:
        termination = "depth_limit"
    else:
        termination = "frontier_exhausted"

    violated_property = None if violation is None else violation["property"]
    expected_property = None if mutant is None else mutant.expected_property
    killed = mutant is not None and violation is not None
    expected_property_killed = killed and violated_property == expected_property
    elapsed = time.monotonic() - started
    result: dict[str, object] = {
        "mutant_id": "baseline" if mutant is None else mutant.mutant_id,
        "mutant_digest": None if mutant is None else mutant.digest,
        "description": "Unmodified analyzer semantics." if mutant is None else mutant.description,
        "expected_property": expected_property,
        "passed": violation is None and resource_limit is None,
        "killed": killed,
        "expected_property_killed": expected_property_killed,
        "violated_property": violated_property,
        "violation_message": None if violation is None else violation["message"],
        "counterexample_depth": None if violation is None else len(trace),
        "trace": list(trace),
        "states_checked": len(seen),
        "transitions_checked": transitions,
        "maximum_depth_reached": maximum_depth,
        "termination": termination,
        "resource_limit": resource_limit,
        "elapsed_seconds": elapsed,
        "model_digest": _model_digest(),
        "analyzer_digest": _analyzer_digest(),
    }
    return result


def sensitivity_bounds(depth: int = SENSITIVITY_MAX_DEPTH) -> Bounds:
    return Bounds(
        initial_shares=SENSITIVITY_INITIAL_SHARES,
        max_leases=SENSITIVITY_MAX_LEASES,
        max_transfers=SENSITIVITY_MAX_TRANSFERS,
        max_receipts=SENSITIVITY_MAX_RECEIPTS,
        max_depth=depth,
        max_action_amount=2,
    )


def analyze_sensitivity_suite(
    bounds: Bounds | None = None,
    *,
    max_states: int = DEFAULT_MAX_STATES,
    max_transitions: int = DEFAULT_MAX_TRANSITIONS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    """Run the passing baseline and every isolated mutant under common bounds."""

    selected = sensitivity_bounds() if bounds is None else bounds
    baseline = analyze_sensitivity_case(
        selected,
        mutant=None,
        max_states=max_states,
        max_transitions=max_transitions,
        timeout_seconds=timeout_seconds,
    )
    mutants = [
        analyze_sensitivity_case(
            selected,
            mutant=mutant,
            max_states=max_states,
            max_transitions=max_transitions,
            timeout_seconds=timeout_seconds,
        )
        for mutant in MUTANTS
    ]
    baseline_passed = baseline["passed"] is True
    all_mutants_killed = all(item["expected_property_killed"] is True for item in mutants)
    configuration = {
        "bounds": _bounds_payload(selected),
        "mutants": [asdict(item) for item in MUTANTS],
    }
    return {
        "schema": "lets.mutation-sensitivity/v1",
        "bounds": _bounds_payload(selected),
        "baseline": baseline,
        "mutants": mutants,
        "baseline_passed": baseline_passed,
        "all_mutants_killed": all_mutants_killed,
        "passed": baseline_passed and all_mutants_killed,
        "configuration_digest": _json_digest(configuration),
        "model_digest": _model_digest(),
        "analyzer_digest": _analyzer_digest(),
    }


def run_analysis(
    *,
    mode: Literal["all", "frontier", "sensitivity"],
    frontier_bounds: Bounds,
    sensitivity_depth: int = SENSITIVITY_MAX_DEPTH,
    max_states: int = DEFAULT_MAX_STATES,
    max_transitions: int = DEFAULT_MAX_TRANSITIONS,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, object]:
    generated_at = datetime.now(UTC).isoformat()
    payload: dict[str, object] = {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "mode": mode,
        "model_digest": _model_digest(),
        "analyzer_digest": _analyzer_digest(),
        "limits": {
            "max_states_per_case": max_states,
            "max_transitions_per_case": max_transitions,
            "timeout_seconds_per_case": timeout_seconds,
        },
    }
    frontier: dict[str, object] | None = None
    sensitivity: dict[str, object] | None = None
    if mode in {"all", "frontier"}:
        frontier = analyze_frontier(
            frontier_bounds,
            max_states=max_states,
            max_transitions=max_transitions,
            timeout_seconds=timeout_seconds,
        )
        payload["frontier"] = frontier
    if mode in {"all", "sensitivity"}:
        sensitivity = analyze_sensitivity_suite(
            sensitivity_bounds(sensitivity_depth),
            max_states=max_states,
            max_transitions=max_transitions,
            timeout_seconds=timeout_seconds,
        )
        payload["sensitivity"] = sensitivity

    frontier_completed = frontier is None or frontier["passed"] is True
    sensitivity_completed = sensitivity is None or sensitivity["passed"] is True
    payload["success"] = frontier_completed and sensitivity_completed
    payload["configuration_digest"] = _json_digest(
        {
            "mode": mode,
            "frontier_bounds": _bounds_payload(frontier_bounds),
            "sensitivity_depth": sensitivity_depth,
            "limits": payload["limits"],
        }
    )
    return payload


def render_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# LETS formal sensitivity and frontier analysis",
        "",
        f"- Generated: `{payload['generated_at']}`",
        f"- Mode: `{payload['mode']}`",
        f"- Model digest: `{payload['model_digest']}`",
        f"- Analyzer digest: `{payload['analyzer_digest']}`",
        f"- Configuration digest: `{payload['configuration_digest']}`",
        f"- Success: `{str(payload['success']).lower()}`",
        "",
    ]
    frontier = payload.get("frontier")
    if isinstance(frontier, dict):
        lines.extend(
            [
                "## Frontier",
                "",
                f"- Termination: `{frontier['termination']}`.",
                f"- Frontier exhausted: `{str(frontier['frontier_exhausted']).lower()}`.",
                f"- States checked: `{frontier['states_checked']}`.",
                (f"- Expanded transitions checked: `{frontier['expanded_transitions_checked']}`."),
                f"- Cutoff states: `{frontier['cutoff_states']}`.",
                f"- Cutoff transitions probed: `{frontier['cutoff_probe_transitions']}`.",
                (
                    "- Unseen successors beyond the cutoff: "
                    f"`{frontier['unseen_successors_at_cutoff']}`."
                ),
                "",
                "| Shortest depth | States | Checked outgoing transitions |",
                "|---:|---:|---:|",
            ]
        )
        states = frontier["states_by_shortest_depth"]
        transitions = frontier["transitions_by_source_shortest_depth"]
        if isinstance(states, dict) and isinstance(transitions, dict):
            for depth in sorted(states, key=int):
                lines.append(f"| {depth} | {states[depth]} | {transitions.get(depth, 0)} |")
        lines.append("")

    sensitivity = payload.get("sensitivity")
    if isinstance(sensitivity, dict):
        lines.extend(
            [
                "## Mutation sensitivity",
                "",
                f"- Baseline passed: `{str(sensitivity['baseline_passed']).lower()}`.",
                f"- All mutants killed: `{str(sensitivity['all_mutants_killed']).lower()}`.",
                "",
                "### Baseline",
                "",
                (
                    f"States: `{sensitivity['baseline']['states_checked']}`; "
                    f"transitions: `{sensitivity['baseline']['transitions_checked']}`; "
                    f"termination: `{sensitivity['baseline']['termination']}`."
                ),
                "",
                ("| Mutant | Killed | Violated property | Depth | States | Transitions | Trace |"),
                "|---|:---:|---|---:|---:|---:|---|",
            ]
        )
        mutants = sensitivity["mutants"]
        if isinstance(mutants, list):
            for item in mutants:
                if not isinstance(item, dict):
                    continue
                trace = " → ".join(str(action) for action in item["trace"])
                trace = trace.replace("|", "\\|")
                lines.append(
                    "| "
                    f"`{item['mutant_id']}` | "
                    f"{str(item['expected_property_killed']).lower()} | "
                    f"`{item['violated_property']}` | "
                    f"{item['counterexample_depth']} | "
                    f"{item['states_checked']} | "
                    f"{item['transitions_checked']} | {trace} |"
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _validate_resource_limits(
    max_states: int,
    max_transitions: int,
    timeout_seconds: float,
) -> None:
    if max_states <= 0 or max_transitions <= 0:
        raise ValueError("state and transition limits must be positive")
    if timeout_seconds <= 0 or not timeout_seconds < float("inf"):
        raise ValueError("timeout_seconds must be finite and positive")


def _atomic_write(path: Path, content: str, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing output without --overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_outputs(
    payload: dict[str, object],
    *,
    output: Path,
    markdown_output: Path,
    overwrite: bool,
) -> None:
    if output.resolve() == markdown_output.resolve():
        raise ValueError("JSON and Markdown outputs must use different paths")
    existing = [path for path in (output, markdown_output) if path.exists()]
    if existing and not overwrite:
        joined = ", ".join(str(path) for path in existing)
        raise FileExistsError(
            f"refusing to overwrite existing output without --overwrite: {joined}"
        )
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _atomic_write(output, encoded, overwrite=overwrite)
    _atomic_write(markdown_output, render_markdown(payload), overwrite=overwrite)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("all", "frontier", "sensitivity"), default="all")
    parser.add_argument("--shares", type=int, nargs="+", default=(1, 1, 1))
    parser.add_argument("--depth", type=int, default=9)
    parser.add_argument("--leases", type=int, default=3)
    parser.add_argument("--transfers", type=int, default=2)
    parser.add_argument("--receipts", type=int, default=2)
    parser.add_argument("--max-action-amount", type=int, default=1)
    parser.add_argument("--sensitivity-depth", type=int, default=SENSITIVITY_MAX_DEPTH)
    parser.add_argument("--max-states", type=int, default=DEFAULT_MAX_STATES)
    parser.add_argument("--max-transitions", type=int, default=DEFAULT_MAX_TRANSITIONS)
    parser.add_argument("--timeout-seconds", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/generated/formal/sensitivity-frontier.json"),
    )
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    markdown_output = (
        arguments.output.with_suffix(".md")
        if arguments.markdown_output is None
        else arguments.markdown_output
    )
    if not arguments.overwrite:
        existing = [path for path in (arguments.output, markdown_output) if path.exists()]
        if existing:
            joined = ", ".join(str(path) for path in existing)
            raise FileExistsError(
                f"refusing to overwrite existing output without --overwrite: {joined}"
            )
    frontier_bounds = Bounds(
        initial_shares=tuple(arguments.shares),
        max_leases=arguments.leases,
        max_transfers=arguments.transfers,
        max_receipts=arguments.receipts,
        max_depth=arguments.depth,
        max_action_amount=arguments.max_action_amount,
    )
    payload = run_analysis(
        mode=arguments.mode,
        frontier_bounds=frontier_bounds,
        sensitivity_depth=arguments.sensitivity_depth,
        max_states=arguments.max_states,
        max_transitions=arguments.max_transitions,
        timeout_seconds=arguments.timeout_seconds,
    )
    write_outputs(
        payload,
        output=arguments.output,
        markdown_output=markdown_output,
        overwrite=arguments.overwrite,
    )
    print(
        json.dumps(
            {
                "json": str(arguments.output),
                "markdown": str(markdown_output),
                "success": payload["success"],
            },
            sort_keys=True,
        )
    )
    return 0 if payload["success"] is True else 1


if __name__ == "__main__":
    sys.exit(main())
