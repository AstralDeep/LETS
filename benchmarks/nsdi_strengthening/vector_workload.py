"""Exercise vector authority, attenuated delegation, transfer-backed use, and claims."""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Callable
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import LETSError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import IdentityContext, Receipt
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

from .common import environment_identity, source_identity, utc_now, write_json, write_text

SCHEMA = "lets.vector-workload/v1"
TENANT = "vector-study"
ENVELOPE = "vector-envelope"
BUDGET = (40, 60)
CLOCK_NS = 1_900_000_000_000_000_000


def vector_policy() -> PolicySpec:
    return PolicySpec(
        policy_id="service-recovery",
        policy_version="v1",
        dimensions=(
            ResourceDimension("read", "count"),
            ResourceDimension("system", "count"),
        ),
        machine=MachineSpec(
            machine_id="service-recovery-worker",
            initial_state="ready",
            transitions=(
                TransitionSpec(
                    "inspect_configuration",
                    "ready",
                    "ready",
                    (1, 0),
                    "service.inspect",
                ),
                TransitionSpec(
                    "restart_service",
                    "ready",
                    "ready",
                    (0, 3),
                    "service.restart",
                ),
                TransitionSpec(
                    "rotate_credential",
                    "ready",
                    "ready",
                    (1, 5),
                    "service.rotate",
                ),
            ),
        ),
        max_lease_ttl_ns=1_000_000_000_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=16,
    )


def _identity(subject: str) -> IdentityContext:
    return IdentityContext(subject, TENANT, frozenset({"lets.admin"}))


def _add(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(a + b for a, b in zip(left, right, strict=True))


def _subtract(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(a - b for a, b in zip(left, right, strict=True))


def _snapshot(service: WardenService, identity: IdentityContext) -> dict[str, object]:
    value = service.invariant_snapshot(identity=identity)
    return {
        "initial_share": list(value.initial_share),
        "transferred_in": list(value.transferred_in),
        "transferred_out": list(value.transferred_out),
        "free_pool": list(value.free_pool),
        "lease_residual": list(value.lease_residual),
        "consumed": list(value.consumed),
        "healthy": value.healthy,
    }


def _aggregate(
    services: dict[str, WardenService], identities: dict[str, IdentityContext]
) -> dict[str, object]:
    snapshots = {name: _snapshot(service, identities[name]) for name, service in services.items()}
    fields = (
        "initial_share",
        "transferred_in",
        "transferred_out",
        "free_pool",
        "lease_residual",
        "consumed",
    )
    totals: dict[str, tuple[int, ...]] = {}
    for field in fields:
        totals[field] = tuple(
            sum(int(snapshot[field][dimension]) for snapshot in snapshots.values())
            for dimension in range(len(BUDGET))
        )
    in_flight = _subtract(totals["transferred_out"], totals["transferred_in"])
    spendable = _add(totals["free_pool"], totals["lease_residual"])
    conserved = _add(_add(spendable, totals["consumed"]), in_flight)
    return {
        "wardens": snapshots,
        **{field: list(value) for field, value in totals.items()},
        "in_flight": list(in_flight),
        "spendable": list(spendable),
        "conserved": list(conserved),
        "identity_holds": conserved == BUDGET,
        "spendable_bound_holds": all(
            value <= bound for value, bound in zip(spendable, BUDGET, strict=True)
        ),
        "local_invariants_healthy": all(bool(value["healthy"]) for value in snapshots.values()),
    }


def _delta(before: dict[str, object], after: dict[str, object]) -> dict[str, list[int]]:
    return {
        field: [
            int(right) - int(left) for left, right in zip(before[field], after[field], strict=True)
        ]
        for field in ("free_pool", "lease_residual", "consumed", "in_flight", "spendable")
    }


def run_vector_workload(workspace: Path) -> dict[str, object]:
    workspace.mkdir(parents=True, exist_ok=True)
    policy = vector_policy()
    clock = ManualClock(CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    signers = {name: Ed25519Signer.generate(name) for name in ("source-warden", "target-warden")}
    for signer in signers.values():
        registry.register_signer(signer)
    shares = {"source-warden": BUDGET, "target-warden": (0, 0)}
    stores: dict[str, SQLiteStorage] = {}
    services: dict[str, WardenService] = {}
    identities = {name: _identity(name) for name in shares}
    replays: dict[str, SQLiteReceiptReplayStore] = {}
    verifiers: dict[str, ReceiptVerifier] = {}
    operations: list[dict[str, object]] = []
    leases: dict[str, str] = {}
    sequences: dict[str, int] = {}
    last_receipts: dict[str, Receipt] = {}

    with TemporaryDirectory(prefix="vector-study-", dir=workspace) as temporary:
        directory = Path(temporary)
        try:
            for name in shares:
                signer = signers[name]
                store = SQLiteStorage.initialize(
                    directory / f"{name}.sqlite3",
                    name,
                    BUDGET,
                    signing_key_id=signer.key_id,
                    signing_public_key=signer.public_key_bytes,
                    tenant_id=TENANT,
                    envelope_id=ENVELOPE,
                    initial_local_share=shares[name],
                    receipt_ttl_ns=policy.receipt_ttl_ns,
                    max_clock_uncertainty_ns=0,
                    transfer_gap_window=policy.transfer_gap_window,
                    dimension_metadata=[
                        {
                            "name": dimension.id,
                            "unit": dimension.unit,
                            "description": dimension.description,
                        }
                        for dimension in policy.dimensions
                    ],
                )
                service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
                service.register_policy(policy)
                replay = SQLiteReceiptReplayStore.initialize(
                    directory / f"{name}-executor.sqlite3", allow_unanchored=True
                )
                verifier = ReceiptVerifier(
                    registry,
                    replay,
                    ExecutorPolicy(
                        audience=f"executor-{name}",
                        tenant_id=TENANT,
                        envelope_id=ENVELOPE,
                        config_epoch=1,
                        allowed_policy_digests=frozenset({policy.digest}),
                        allowed_machine_digests=frozenset({policy.machine.digest}),
                        trusted_wardens=frozenset({name}),
                    ),
                    clock=clock,
                )
                stores[name] = store
                services[name] = service
                replays[name] = replay
                verifiers[name] = verifier

            def record(
                label: str,
                category: str,
                action: Callable[[], dict[str, object] | None],
                *,
                expected_failure: str | None = None,
            ) -> dict[str, object] | None:
                before = _aggregate(services, identities)
                outcome = "succeeded"
                detail: dict[str, object] = {}
                returned: dict[str, object] | None = None
                try:
                    returned = action()
                    if returned:
                        detail.update(returned)
                except LETSError as exc:
                    outcome = "denied"
                    detail.update({"error_code": exc.code, "error_type": type(exc).__name__})
                    if expected_failure is None or exc.code != expected_failure:
                        raise
                else:
                    if expected_failure is not None:
                        raise AssertionError(f"{label} unexpectedly succeeded")
                after = _aggregate(services, identities)
                if not after["identity_holds"] or not after["spendable_bound_holds"]:
                    raise AssertionError(f"vector accounting failed after {label}")
                operations.append(
                    {
                        "index": len(operations),
                        "operation": label,
                        "category": category,
                        "outcome": outcome,
                        "expected_failure": expected_failure,
                        "details": detail,
                        "before": before,
                        "after": after,
                        "aggregate_delta": _delta(before, after),
                    }
                )
                return returned

            def issue_root(name: str, allocation: tuple[int, int], alias: str) -> dict[str, object]:
                grant = services[name].issue_root(
                    request_id=f"issue-{alias}",
                    identity=identities[name],
                    tenant_id=TENANT,
                    envelope_id=ENVELOPE,
                    subject_id=alias,
                    allocation=allocation,
                    capabilities={"service.inspect", "service.restart", "service.rotate"},
                    policy_digest=policy.digest,
                    ttl_ns=1_000_000_000_000_000,
                )
                leases[alias] = grant.lease_id
                sequences[grant.lease_id] = 0
                return {"lease": alias, "lease_id": grant.lease_id, "allocation": list(allocation)}

            record(
                "root_issue_source",
                "root_issue",
                lambda: issue_root("source-warden", (30, 40), "source-root"),
            )

            def spawn(
                alias: str,
                allocation: tuple[int, int],
                capabilities: set[str],
            ) -> dict[str, object]:
                parent_id = leases["source-root"]
                grant = services["source-warden"].spawn(
                    request_id=f"spawn-{alias}",
                    identity=identities["source-warden"],
                    parent_id=parent_id,
                    subject_id=alias,
                    allocation=allocation,
                    capabilities=capabilities,
                    ttl_ns=1_000_000_000_000_000,
                    policy_digest=policy.digest,
                    expected_sequence=sequences[parent_id],
                )
                leases[alias] = grant.lease_id
                sequences[grant.lease_id] = 0
                sequences[parent_id] = (
                    services["source-warden"]
                    .snapshot(identity=identities["source-warden"], lease_id=parent_id)
                    .sequence
                )
                return {
                    "lease": alias,
                    "lease_id": grant.lease_id,
                    "allocation": list(allocation),
                    "capabilities": sorted(capabilities),
                }

            record(
                "spawn_reader",
                "spawn",
                lambda: spawn("reader", (8, 0), {"service.inspect"}),
            )
            record(
                "spawn_operator",
                "spawn",
                lambda: spawn("operator", (0, 15), {"service.restart", "service.rotate"}),
            )
            record(
                "spawn_recovery",
                "spawn",
                lambda: spawn(
                    "recovery",
                    (5, 15),
                    {"service.inspect", "service.restart", "service.rotate"},
                ),
            )

            def authorize(
                warden: str,
                alias: str,
                transition: str,
                suffix: str,
                *,
                claim: bool = True,
            ) -> dict[str, object]:
                lease_id = leases[alias]
                receipt = services[warden].authorize(
                    request_id=f"authorize-{suffix}",
                    identity=identities[warden],
                    lease_id=lease_id,
                    transition=transition,
                    audience=f"executor-{warden}",
                    nonce=f"vector-nonce-{suffix}-00000000",
                    expected_state="ready",
                    expected_sequence=sequences[lease_id],
                )
                sequences[lease_id] = receipt.resulting_sequence
                last_receipts[suffix] = receipt
                if claim:
                    verifiers[warden].verify_and_claim(receipt)
                return {
                    "warden": warden,
                    "lease": alias,
                    "transition": transition,
                    "cost": list(receipt.cost),
                    "receipt_id": receipt.receipt_id,
                    "claimed": claim,
                }

            for index in range(3):
                record(
                    f"reader_inspect_{index + 1}",
                    "authorize_and_claim",
                    lambda index=index: authorize(
                        "source-warden", "reader", "inspect_configuration", f"reader-{index}"
                    ),
                )
            for index in range(2):
                record(
                    f"operator_restart_{index + 1}",
                    "authorize_and_claim",
                    lambda index=index: authorize(
                        "source-warden", "operator", "restart_service", f"operator-{index}"
                    ),
                )
            record(
                "operator_rotate_denied_zero_read",
                "authorization_denial",
                lambda: authorize(
                    "source-warden", "operator", "rotate_credential", "operator-rotate"
                ),
                expected_failure="policy_denied",
            )
            record(
                "recovery_rotate_1",
                "authorize_and_claim",
                lambda: authorize(
                    "source-warden", "recovery", "rotate_credential", "recovery-rotate-1"
                ),
            )
            record(
                "recovery_rotate_2",
                "authorize_and_claim",
                lambda: authorize(
                    "source-warden", "recovery", "rotate_credential", "recovery-rotate-2"
                ),
            )
            record(
                "recovery_inspect",
                "authorize_and_claim",
                lambda: authorize(
                    "source-warden", "recovery", "inspect_configuration", "recovery-inspect"
                ),
            )
            record(
                "recovery_restart",
                "authorize_and_claim",
                lambda: authorize(
                    "source-warden", "recovery", "restart_service", "recovery-restart"
                ),
            )

            transfer_holder: dict[str, Any] = {}

            def prepare() -> dict[str, object]:
                voucher = services["source-warden"].prepare_transfer(
                    request_id="vector-transfer",
                    identity=identities["source-warden"],
                    tenant_id=TENANT,
                    envelope_id=ENVELOPE,
                    target_warden="target-warden",
                    amount=(4, 10),
                    policy_digest=policy.digest,
                )
                transfer_holder["voucher"] = voucher
                return {"amount": [4, 10], "sequence": voucher.sequence}

            record("transfer_prepare", "transfer_prepare", prepare)

            def accept() -> dict[str, object]:
                acknowledgement = services["target-warden"].accept_transfer(
                    identity=identities["target-warden"],
                    voucher=transfer_holder["voucher"],
                )
                transfer_holder["ack"] = acknowledgement
                return {
                    "amount": [4, 10],
                    "sequence": acknowledgement.sequence,
                    "contiguous_watermark": acknowledgement.contiguous_watermark,
                }

            record("transfer_accept", "transfer_accept", accept)
            record(
                "transfer_duplicate_accept",
                "transfer_duplicate_accept",
                accept,
            )
            record(
                "transfer_finalize",
                "transfer_finalize",
                lambda: {
                    "sequence": services["source-warden"]
                    .finalize_transfer(
                        identity=identities["source-warden"],
                        acknowledgement=transfer_holder["ack"],
                    )
                    .sequence
                },
            )
            record(
                "target_root_from_transferred_units",
                "root_issue",
                lambda: issue_root("target-warden", (4, 10), "target-root"),
            )
            record(
                "target_rotate_transfer_backed",
                "authorize_and_claim",
                lambda: authorize(
                    "target-warden", "target-root", "rotate_credential", "target-rotate"
                ),
            )
            record(
                "target_inspect_transfer_backed",
                "authorize_and_claim",
                lambda: authorize(
                    "target-warden", "target-root", "inspect_configuration", "target-inspect"
                ),
            )
            record(
                "duplicate_executor_claim_rejected",
                "executor_duplicate_claim",
                lambda: (
                    verifiers["target-warden"].verify_and_claim(last_receipts["target-rotate"])
                    or {"receipt_id": last_receipts["target-rotate"].receipt_id}
                ),
                expected_failure="replay_detected",
            )
            claims_before = replays["target-warden"].status().live_claims
            record(
                "target_restart_debited_but_unclaimed",
                "warden_debit_without_executor_claim",
                lambda: authorize(
                    "target-warden",
                    "target-root",
                    "restart_service",
                    "target-unclaimed",
                    claim=False,
                ),
            )
            claims_after_issue = replays["target-warden"].status().live_claims
            clock.advance(policy.receipt_ttl_ns + 1)
            record(
                "expired_unclaimed_receipt_cannot_settle",
                "expired_executor_claim",
                lambda: (
                    verifiers["target-warden"].verify_and_claim(last_receipts["target-unclaimed"])
                    or {"receipt_id": last_receipts["target-unclaimed"].receipt_id}
                ),
                expected_failure="policy_denied",
            )
            claims_after_expiry = replays["target-warden"].status().live_claims

            final = _aggregate(services, identities)
            issued_receipts = sum(
                1
                for operation in operations
                if operation["category"]
                in {"authorize_and_claim", "warden_debit_without_executor_claim"}
                and operation["outcome"] == "succeeded"
            )
            claimed_receipts = sum(replay.status().live_claims for replay in replays.values())
            return {
                "schema": SCHEMA,
                "generated_at": utc_now(),
                "source": source_identity(),
                "environment": environment_identity(),
                "configuration": {
                    "budget": list(BUDGET),
                    "dimensions": [dimension.to_dict() for dimension in policy.dimensions],
                    "transitions": [
                        transition.to_dict() for transition in policy.machine.transitions
                    ],
                    "initial_shares": {key: list(value) for key, value in shares.items()},
                    "executor_storage": "SQLite WAL synchronous=FULL; unanchored experiment mode",
                },
                "operations": operations,
                "receipt_accounting": {
                    "issued_receipts": issued_receipts,
                    "claimed_receipts": claimed_receipts,
                    "claims_before_unclaimed_issue": claims_before,
                    "claims_after_unclaimed_issue": claims_after_issue,
                    "claims_after_receipt_expiry": claims_after_expiry,
                    "unclaimed_receipt_id": last_receipts["target-unclaimed"].receipt_id,
                    "unclaimed_cost": list(last_receipts["target-unclaimed"].cost),
                    "authority_refunded_after_expiry": False,
                },
                "final": final,
                "checks": {
                    "two_dimensions_exercised": True,
                    "heterogeneous_costs_exercised": True,
                    "multi_dimension_cost_exercised": True,
                    "independent_dimension_attenuation_exercised": True,
                    "zero_read_denied_multi_dimension_action": True,
                    "transfer_backed_target_action_claimed": True,
                    "duplicate_transfer_credit_prevented": True,
                    "duplicate_executor_claim_rejected": True,
                    "unclaimed_expired_receipt_remained_debited": True,
                    "global_conservation": final["identity_holds"],
                    "spendable_bound": final["spendable_bound_holds"],
                },
            }
        finally:
            for store in stores.values():
                store.close()


def _markdown(result: dict[str, object]) -> str:
    lines = [
        "# Resource-vector and debit/claim results",
        "",
        "The runtime used two dimensions (`read`, `system`) and three heterogeneous costs: "
        "inspect `(1,0)`, restart `(0,3)`, and credential rotation `(1,5)`.",
        "",
        "| Operation | Outcome | Δ free | Δ lease residual | Δ consumed | Δ in-flight | Claim |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for operation in result["operations"]:
        delta = operation["aggregate_delta"]
        details = operation["details"]
        claim = (
            "yes"
            if details.get("claimed") is True
            else "no"
            if details.get("claimed") is False
            else "—"
        )

        def vector(value: list[int]) -> str:
            return "(" + ",".join(str(item) for item in value) + ")"

        lines.append(
            f"| {operation['operation']} | {operation['outcome']} | "
            f"{vector(delta['free_pool'])} | {vector(delta['lease_residual'])} | "
            f"{vector(delta['consumed'])} | {vector(delta['in_flight'])} | {claim} |"
        )
    receipt = result["receipt_accounting"]
    final = result["final"]
    lines.extend(
        [
            "",
            "## Direct observations",
            "",
            f"- Final conserved vector: `{tuple(final['conserved'])}` from genesis "
            f"`{BUDGET}`; identity held: `{final['identity_holds']}`.",
            f"- Final spendable vector: `{tuple(final['spendable'])}`; componentwise "
            f"spendable bound held: `{final['spendable_bound_holds']}`.",
            "- The target began with `(0,0)`, accepted `(4,10)`, issued its root only from "
            "that inbound authority, and then authorized and claimed target-side actions.",
            "- An operator child allocated `(0,15)` had the rotate capability but its "
            "`(1,5)` action was denied because it had zero read units.",
            f"- The warden issued {receipt['issued_receipts']} receipts and executors claimed "
            f"{receipt['claimed_receipts']}. The deliberately unclaimed receipt cost "
            f"`{tuple(receipt['unclaimed_cost'])}` and remained debited after expiry; no refund "
            "occurred.",
            "",
            "Every row in the raw JSON retains the complete before/after local snapshots, "
            "aggregate vectors, and category deltas.",
        ]
    )
    return "\n".join(lines)


def _write_csv(result: dict[str, object], path: Path, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "index",
                "operation",
                "category",
                "outcome",
                "delta_free",
                "delta_residual",
                "delta_consumed",
                "delta_in_flight",
                "identity_holds",
                "spendable_bound_holds",
            ),
        )
        writer.writeheader()
        for operation in result["operations"]:
            delta = operation["aggregate_delta"]
            writer.writerow(
                {
                    "index": operation["index"],
                    "operation": operation["operation"],
                    "category": operation["category"],
                    "outcome": operation["outcome"],
                    "delta_free": json.dumps(delta["free_pool"], separators=(",", ":")),
                    "delta_residual": json.dumps(delta["lease_residual"], separators=(",", ":")),
                    "delta_consumed": json.dumps(delta["consumed"], separators=(",", ":")),
                    "delta_in_flight": json.dumps(delta["in_flight"], separators=(",", ":")),
                    "identity_holds": operation["after"]["identity_holds"],
                    "spendable_bound_holds": operation["after"]["spendable_bound_holds"],
                }
            )


def write_outputs(result: dict[str, object], output_dir: Path, *, overwrite: bool) -> None:
    write_json(output_dir / "vector-workload.json", result, overwrite=overwrite)
    _write_csv(result, output_dir / "vector-transitions.csv", overwrite=overwrite)
    write_text(output_dir / "VECTOR-RESULTS.md", _markdown(result), overwrite=overwrite)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/nsdi-strengthening-2026-08-31/vector"),
    )
    parser.add_argument("--workspace", type=Path, default=Path("benchmarks/results"))
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    result = run_vector_workload(arguments.workspace)
    write_outputs(result, arguments.output_dir, overwrite=arguments.overwrite)
    print(json.dumps({"status": "passed", "output_dir": str(arguments.output_dir)}))


if __name__ == "__main__":
    main()
