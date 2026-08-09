"""Bounded state-space checker for distributed LETS escrow and replay safety.

This model is deliberately executable with the repository's Python environment.
It explores message loss/reordering (any prepared transfer may arrive), duplicate
transfer delivery, duplicate receipt claims, out-of-order receipt claims, local
issuance, recursive spawn, consumption, closure, and transfer finalization.

Passing a bounded check is not a mathematical proof.  It is a finite exhaustive
search over the supplied ``Bounds`` and complements the executable service,
property, crash-recovery, and Docker fault tests.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import deque
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

TransferStatus = Literal["PREPARED", "ACCEPTED", "FINALIZED"]


@dataclass(frozen=True, order=True, slots=True)
class Lease:
    lease_id: int
    warden: int
    parent_id: int | None
    residual: int
    active: bool
    sequence: int


@dataclass(frozen=True, order=True, slots=True)
class Transfer:
    transfer_id: int
    source: int
    target: int
    sequence: int
    amount: int
    status: TransferStatus


@dataclass(frozen=True, order=True, slots=True)
class Receipt:
    receipt_id: int
    lease_id: int
    warden: int
    sequence: int
    nonce: int


@dataclass(frozen=True, slots=True)
class State:
    pools: tuple[int, ...]
    leases: tuple[Lease, ...]
    consumed: int
    transfers: tuple[Transfer, ...]
    receipts: tuple[Receipt, ...]
    claimed_receipts: frozenset[int]
    claimed_nonces: frozenset[int]
    executor_watermarks: tuple[tuple[int, int], ...]
    next_lease_id: int
    next_transfer_id: int
    next_receipt_id: int


@dataclass(frozen=True, slots=True)
class Bounds:
    initial_shares: tuple[int, ...] = (1, 1, 1)
    max_leases: int = 3
    max_transfers: int = 2
    max_receipts: int = 2
    max_depth: int = 9
    max_action_amount: int = 1

    def __post_init__(self) -> None:
        if len(self.initial_shares) < 2:
            raise ValueError("the distributed model requires at least two wardens")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in self.initial_shares
        ):
            raise ValueError("initial shares must be non-negative integers")
        for name in (
            "max_leases",
            "max_transfers",
            "max_receipts",
            "max_depth",
            "max_action_amount",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    @property
    def budget(self) -> int:
        return sum(self.initial_shares)


@dataclass(frozen=True, slots=True)
class Violation:
    invariant: str
    message: str
    trace: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CheckResult:
    schema: str
    bounds: dict[str, object]
    states_checked: int
    transitions_checked: int
    maximum_depth_reached: int
    self_loops_checked: int
    violations: tuple[Violation, ...]
    model_digest: str

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["passed"] = self.passed
        return payload


class InvariantViolationError(AssertionError):
    def __init__(self, invariant: str, message: str) -> None:
        super().__init__(message)
        self.invariant = invariant


def initial_state(bounds: Bounds) -> State:
    return State(
        pools=bounds.initial_shares,
        leases=(),
        consumed=0,
        transfers=(),
        receipts=(),
        claimed_receipts=frozenset(),
        claimed_nonces=frozenset(),
        executor_watermarks=(),
        next_lease_id=1,
        next_transfer_id=1,
        next_receipt_id=1,
    )


def _replace_lease(state: State, changed: Lease) -> tuple[Lease, ...]:
    return tuple(
        sorted(changed if lease.lease_id == changed.lease_id else lease for lease in state.leases)
    )


def _replace_transfer(state: State, changed: Transfer) -> tuple[Transfer, ...]:
    return tuple(
        sorted(
            changed if transfer.transfer_id == changed.transfer_id else transfer
            for transfer in state.transfers
        )
    )


def _watermark(state: State, lease_id: int) -> int:
    return dict(state.executor_watermarks).get(lease_id, 0)


def issue_root(state: State, warden: int, amount: int = 1) -> State:
    if amount <= 0 or state.pools[warden] < amount:
        raise ValueError("root issuance is not enabled")
    pools = list(state.pools)
    pools[warden] -= amount
    lease = Lease(state.next_lease_id, warden, None, amount, True, 0)
    return replace(
        state,
        pools=tuple(pools),
        leases=tuple(sorted((*state.leases, lease))),
        next_lease_id=state.next_lease_id + 1,
    )


def spawn(state: State, parent_id: int, amount: int = 1) -> State:
    parent = next((lease for lease in state.leases if lease.lease_id == parent_id), None)
    if parent is None or not parent.active or amount <= 0 or parent.residual < amount:
        raise ValueError("spawn is not enabled")
    changed = replace(parent, residual=parent.residual - amount, sequence=parent.sequence + 1)
    child = Lease(state.next_lease_id, parent.warden, parent.lease_id, amount, True, 0)
    return replace(
        state,
        leases=tuple(sorted((*_replace_lease(state, changed), child))),
        next_lease_id=state.next_lease_id + 1,
    )


def authorize(state: State, lease_id: int, cost: int = 1) -> State:
    lease = next((candidate for candidate in state.leases if candidate.lease_id == lease_id), None)
    if lease is None or not lease.active or cost <= 0 or lease.residual < cost:
        raise ValueError("authorization is not enabled")
    sequence = lease.sequence + 1
    changed = replace(lease, residual=lease.residual - cost, sequence=sequence)
    receipt = Receipt(
        receipt_id=state.next_receipt_id,
        lease_id=lease.lease_id,
        warden=lease.warden,
        sequence=sequence,
        nonce=state.next_receipt_id,
    )
    return replace(
        state,
        leases=_replace_lease(state, changed),
        consumed=state.consumed + cost,
        receipts=tuple(sorted((*state.receipts, receipt))),
        next_receipt_id=state.next_receipt_id + 1,
    )


def close_lease(state: State, lease_id: int) -> State:
    lease = next((candidate for candidate in state.leases if candidate.lease_id == lease_id), None)
    has_live_child = any(child.parent_id == lease_id and child.active for child in state.leases)
    if lease is None or not lease.active or has_live_child:
        raise ValueError("closure is not enabled")
    pools = list(state.pools)
    pools[lease.warden] += lease.residual
    changed = replace(lease, residual=0, active=False, sequence=lease.sequence + 1)
    return replace(state, pools=tuple(pools), leases=_replace_lease(state, changed))


def prepare_transfer(state: State, source: int, target: int, amount: int = 1) -> State:
    if source == target or amount <= 0 or state.pools[source] < amount:
        raise ValueError("transfer preparation is not enabled")
    pools = list(state.pools)
    pools[source] -= amount
    sequence = (
        max(
            (
                transfer.sequence
                for transfer in state.transfers
                if transfer.source == source and transfer.target == target
            ),
            default=0,
        )
        + 1
    )
    transfer = Transfer(
        state.next_transfer_id,
        source,
        target,
        sequence,
        amount,
        "PREPARED",
    )
    return replace(
        state,
        pools=tuple(pools),
        transfers=tuple(sorted((*state.transfers, transfer))),
        next_transfer_id=state.next_transfer_id + 1,
    )


def accept_transfer(
    state: State,
    transfer_id: int,
    *,
    duplicate_credit_fault: bool = False,
) -> State:
    transfer = next(
        (candidate for candidate in state.transfers if candidate.transfer_id == transfer_id), None
    )
    if transfer is None or transfer.status not in {"PREPARED", "ACCEPTED", "FINALIZED"}:
        raise ValueError("transfer acceptance is not enabled")
    if transfer.status != "PREPARED" and not duplicate_credit_fault:
        return state
    pools = list(state.pools)
    pools[transfer.target] += transfer.amount
    changed = replace(transfer, status="ACCEPTED")
    return replace(state, pools=tuple(pools), transfers=_replace_transfer(state, changed))


def finalize_transfer(state: State, transfer_id: int) -> State:
    transfer = next(
        (candidate for candidate in state.transfers if candidate.transfer_id == transfer_id), None
    )
    if transfer is None:
        raise ValueError("transfer finalization is not enabled")
    if transfer.status == "FINALIZED":
        return state
    if transfer.status != "ACCEPTED":
        raise ValueError("only an accepted transfer may be finalized")
    return replace(
        state,
        transfers=_replace_transfer(state, replace(transfer, status="FINALIZED")),
    )


def claim_receipt(state: State, receipt_id: int) -> State:
    receipt = next(
        (candidate for candidate in state.receipts if candidate.receipt_id == receipt_id), None
    )
    if receipt is None:
        raise ValueError("receipt claim is not enabled")
    if receipt.receipt_id in state.claimed_receipts or receipt.nonce in state.claimed_nonces:
        return state
    if receipt.sequence <= _watermark(state, receipt.lease_id):
        return state
    watermarks = dict(state.executor_watermarks)
    watermarks[receipt.lease_id] = receipt.sequence
    return replace(
        state,
        claimed_receipts=state.claimed_receipts | {receipt.receipt_id},
        claimed_nonces=state.claimed_nonces | {receipt.nonce},
        executor_watermarks=tuple(sorted(watermarks.items())),
    )


def conserved_rights(state: State) -> int:
    in_flight = sum(
        transfer.amount for transfer in state.transfers if transfer.status == "PREPARED"
    )
    return (
        sum(state.pools)
        + sum(lease.residual for lease in state.leases)
        + state.consumed
        + in_flight
    )


def validate(state: State, bounds: Bounds) -> None:
    if conserved_rights(state) != bounds.budget:
        raise InvariantViolationError(
            "global_conservation",
            f"expected {bounds.budget} rights, observed {conserved_rights(state)}",
        )
    if any(value < 0 for value in state.pools) or state.consumed < 0:
        raise InvariantViolationError("nonnegative_rights", "pool or consumption became negative")
    if any(lease.residual < 0 for lease in state.leases):
        raise InvariantViolationError("nonnegative_rights", "lease residual became negative")
    lease_ids = [lease.lease_id for lease in state.leases]
    if len(lease_ids) != len(set(lease_ids)):
        raise InvariantViolationError("unique_lease_ids", "duplicate lease identifier")
    known_leases = {lease.lease_id: lease for lease in state.leases}
    for lease in state.leases:
        if lease.parent_id is not None:
            parent = known_leases.get(lease.parent_id)
            if parent is None or parent.warden != lease.warden or parent.lease_id >= lease.lease_id:
                raise InvariantViolationError(
                    "lineage_attenuation",
                    "child lacks an earlier parent on the same warden",
                )
    transfer_ids = [transfer.transfer_id for transfer in state.transfers]
    if len(transfer_ids) != len(set(transfer_ids)):
        raise InvariantViolationError("unique_transfer_ids", "duplicate transfer identifier")
    stream_sequences = [
        (transfer.source, transfer.target, transfer.sequence) for transfer in state.transfers
    ]
    if len(stream_sequences) != len(set(stream_sequences)):
        raise InvariantViolationError(
            "unique_stream_sequences", "duplicate transfer stream sequence"
        )
    for transfer in state.transfers:
        if (
            transfer.source == transfer.target
            or transfer.amount <= 0
            or transfer.status not in {"PREPARED", "ACCEPTED", "FINALIZED"}
        ):
            raise InvariantViolationError("transfer_type", "malformed transfer state")
    receipt_ids = [receipt.receipt_id for receipt in state.receipts]
    nonces = [receipt.nonce for receipt in state.receipts]
    lease_sequences = [(receipt.lease_id, receipt.sequence) for receipt in state.receipts]
    if len(receipt_ids) != len(set(receipt_ids)) or len(nonces) != len(set(nonces)):
        raise InvariantViolationError(
            "unique_receipt_identity", "duplicate receipt identifier or nonce"
        )
    if len(lease_sequences) != len(set(lease_sequences)):
        raise InvariantViolationError("unique_receipt_sequence", "duplicate sequence for one lease")
    if not state.claimed_receipts.issubset(receipt_ids):
        raise InvariantViolationError("claim_origin", "executor claimed an unknown receipt")
    if not state.claimed_nonces.issubset(nonces):
        raise InvariantViolationError("claim_origin", "executor claimed an unknown nonce")
    expected_claimed_nonces = {
        receipt.nonce for receipt in state.receipts if receipt.receipt_id in state.claimed_receipts
    }
    if state.claimed_nonces != expected_claimed_nonces:
        raise InvariantViolationError(
            "claim_binding", "claimed receipt identifiers and nonces are not bound one-to-one"
        )
    expected_watermarks: dict[int, int] = {}
    for receipt in state.receipts:
        if receipt.receipt_id in state.claimed_receipts:
            expected_watermarks[receipt.lease_id] = max(
                expected_watermarks.get(receipt.lease_id, 0), receipt.sequence
            )
    if dict(state.executor_watermarks) != expected_watermarks:
        raise InvariantViolationError(
            "executor_watermark",
            "executor watermark is not the maximum successfully claimed sequence",
        )
    for receipt in state.receipts:
        receipt_lease = known_leases.get(receipt.lease_id)
        if (
            receipt_lease is None
            or receipt.warden != receipt_lease.warden
            or receipt.sequence > receipt_lease.sequence
        ):
            raise InvariantViolationError(
                "receipt_origin", "receipt is not backed by its lease sequence"
            )


def successors(
    state: State,
    bounds: Bounds,
    *,
    duplicate_credit_fault: bool = False,
) -> Iterable[tuple[str, State]]:
    if len(state.leases) < bounds.max_leases:
        for warden, pool in enumerate(state.pools):
            for amount in range(1, min(pool, bounds.max_action_amount) + 1):
                yield f"issue_root(w={warden},amount={amount})", issue_root(state, warden, amount)
        for lease in state.leases:
            if lease.active:
                for amount in range(1, min(lease.residual, bounds.max_action_amount) + 1):
                    yield (
                        f"spawn(parent={lease.lease_id},amount={amount})",
                        spawn(state, lease.lease_id, amount),
                    )
    if len(state.receipts) < bounds.max_receipts:
        for lease in state.leases:
            if lease.active:
                for cost in range(1, min(lease.residual, bounds.max_action_amount) + 1):
                    yield (
                        f"authorize(lease={lease.lease_id},cost={cost})",
                        authorize(state, lease.lease_id, cost),
                    )
    for lease in state.leases:
        if lease.active and not any(
            child.parent_id == lease.lease_id and child.active for child in state.leases
        ):
            yield f"close(lease={lease.lease_id})", close_lease(state, lease.lease_id)
    if len(state.transfers) < bounds.max_transfers:
        for source, pool in enumerate(state.pools):
            for target in range(len(state.pools)):
                if source == target:
                    continue
                for amount in range(1, min(pool, bounds.max_action_amount) + 1):
                    yield (
                        f"prepare(source={source},target={target},amount={amount})",
                        prepare_transfer(state, source, target, amount),
                    )
    for transfer in state.transfers:
        if transfer.status == "PREPARED":
            yield (
                f"accept(transfer={transfer.transfer_id})",
                accept_transfer(state, transfer.transfer_id),
            )
        else:
            yield (
                f"duplicate_accept(transfer={transfer.transfer_id})",
                accept_transfer(
                    state,
                    transfer.transfer_id,
                    duplicate_credit_fault=duplicate_credit_fault,
                ),
            )
        if transfer.status == "ACCEPTED":
            yield (
                f"finalize(transfer={transfer.transfer_id})",
                finalize_transfer(state, transfer.transfer_id),
            )
        elif transfer.status == "FINALIZED":
            yield (
                f"duplicate_finalize(transfer={transfer.transfer_id})",
                finalize_transfer(state, transfer.transfer_id),
            )
    for receipt in state.receipts:
        label = "claim" if receipt.receipt_id not in state.claimed_receipts else "duplicate_claim"
        if receipt.receipt_id not in state.claimed_receipts and receipt.sequence <= _watermark(
            state, receipt.lease_id
        ):
            label = "stale_claim"
        yield f"{label}(receipt={receipt.receipt_id})", claim_receipt(state, receipt.receipt_id)


def _model_digest() -> str:
    return "sha256:" + hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def check_model(
    bounds: Bounds | None = None,
    *,
    duplicate_credit_fault: bool = False,
) -> CheckResult:
    if bounds is None:
        bounds = Bounds()
    initial = initial_state(bounds)
    queue = deque([(initial, 0)])
    seen = {initial}
    parents: dict[State, tuple[State, str]] = {}
    transitions = 0
    self_loops = 0
    maximum_depth = 0
    violations: list[Violation] = []

    while queue and not violations:
        state, depth = queue.popleft()
        maximum_depth = max(maximum_depth, depth)
        validate(state, bounds)
        if depth >= bounds.max_depth:
            continue
        for label, candidate in successors(
            state,
            bounds,
            duplicate_credit_fault=duplicate_credit_fault,
        ):
            transitions += 1
            try:
                validate(candidate, bounds)
            except InvariantViolationError as exc:
                trace: list[str] = [label]
                cursor = state
                while cursor in parents:
                    cursor, action = parents[cursor]
                    trace.append(action)
                trace.reverse()
                violations.append(Violation(exc.invariant, str(exc), tuple(trace)))
                break
            if candidate == state:
                self_loops += 1
            elif candidate not in seen:
                seen.add(candidate)
                parents[candidate] = (state, label)
                queue.append((candidate, depth + 1))

    return CheckResult(
        schema="lets.bounded-model-check/v1",
        bounds={
            "initial_shares": list(bounds.initial_shares),
            "budget": bounds.budget,
            "max_leases": bounds.max_leases,
            "max_transfers": bounds.max_transfers,
            "max_receipts": bounds.max_receipts,
            "max_depth": bounds.max_depth,
            "max_action_amount": bounds.max_action_amount,
        },
        states_checked=len(seen),
        transitions_checked=transitions,
        maximum_depth_reached=maximum_depth,
        self_loops_checked=self_loops,
        violations=tuple(violations),
        model_digest=_model_digest(),
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--depth", type=int, default=9)
    parser.add_argument("--leases", type=int, default=3)
    parser.add_argument("--transfers", type=int, default=2)
    parser.add_argument("--receipts", type=int, default=2)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/generated/formal/bounded-check.json"),
    )
    parser.add_argument(
        "--inject-duplicate-credit-fault",
        action="store_true",
        help="verify that the checker produces a counterexample for double credit",
    )
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    bounds = Bounds(
        max_depth=arguments.depth,
        max_leases=arguments.leases,
        max_transfers=arguments.transfers,
        max_receipts=arguments.receipts,
    )
    result = check_model(
        bounds,
        duplicate_credit_fault=arguments.inject_duplicate_credit_fault,
    )
    payload = result.to_dict()
    payload["generated_at"] = datetime.now(UTC).isoformat()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not result.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
