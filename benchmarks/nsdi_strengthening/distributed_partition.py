"""Quantify local-share progress, stranded authority, and a central baseline.

This experiment executes the real LETS warden and executor SQLite paths for
three logical sites with disjoint stores.  A deterministic connectivity schedule
isolates site A from a durable centralized counter while every site retains
access to its local warden and executor.  It is deliberately labelled as a
single-process, single-host experiment; it does not substitute for independent
failure domains.
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import LETSError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

from .common import (
    environment_identity,
    latency_summary,
    source_identity,
    utc_now,
    write_json,
    write_text,
)

SCHEMA = "lets.partition-comparison/v1"
TENANT = "partition-study"
ENVELOPE = "partition-envelope"
AUDIENCE_PREFIX = "partition-executor"
CLOCK_NS = 1_900_000_000_000_000_000
SITES = ("site-a", "site-b", "site-c")


def _policy() -> PolicySpec:
    return PolicySpec(
        policy_id="partition-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("actions", "count"),),
        machine=MachineSpec(
            machine_id="partition-worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), "partition.act"),),
        ),
        max_lease_ttl_ns=1_000_000_000_000_000_000,
        receipt_ttl_ns=60_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )


def _identity(site: str) -> IdentityContext:
    return IdentityContext(site, TENANT, frozenset({"lets.admin"}))


@dataclass(slots=True)
class Site:
    name: str
    signer: Ed25519Signer
    store: SQLiteStorage
    service: WardenService
    replay: SQLiteReceiptReplayStore
    verifier: ReceiptVerifier
    identity: IdentityContext
    lease_id: str | None = None
    sequence: int = 0
    authorized: int = 0
    denied: int = 0

    def issue(self, amount: int, *, suffix: str) -> None:
        if amount <= 0:
            self.lease_id = None
            self.sequence = 0
            return
        grant = self.service.issue_root(
            request_id=f"root-{self.name}-{suffix}",
            identity=self.identity,
            tenant_id=TENANT,
            envelope_id=ENVELOPE,
            subject_id=self.name,
            allocation=(amount,),
            capabilities={"partition.act"},
            policy_digest=_policy().digest,
            ttl_ns=1_000_000_000_000_000,
        )
        self.lease_id = grant.lease_id
        self.sequence = 0

    def close_lease(self, *, suffix: str) -> None:
        if self.lease_id is None:
            return
        self.service.close(
            request_id=f"close-{self.name}-{suffix}",
            identity=self.identity,
            lease_id=self.lease_id,
            expected_sequence=self.sequence,
        )
        self.lease_id = None
        self.sequence = 0

    def authorize(self, index: int) -> tuple[bool, str, int]:
        start = time.perf_counter_ns()
        if self.lease_id is None:
            self.denied += 1
            return False, "no_local_lease", time.perf_counter_ns() - start
        try:
            receipt = self.service.authorize(
                request_id=f"authorize-{self.name}-{index:06d}",
                identity=self.identity,
                lease_id=self.lease_id,
                transition="act",
                audience=f"{AUDIENCE_PREFIX}-{self.name}",
                nonce=f"partition-nonce-{self.name}-{index:08d}",
                expected_state="ready",
                expected_sequence=self.sequence,
            )
            self.verifier.verify_and_claim(receipt)
        except LETSError as exc:
            self.denied += 1
            return False, exc.code, time.perf_counter_ns() - start
        self.sequence = receipt.resulting_sequence
        self.authorized += 1
        return True, "authorized_and_claimed", time.perf_counter_ns() - start

    def snapshot(self) -> dict[str, int | bool]:
        value = self.service.invariant_snapshot(identity=self.identity)
        return {
            "initial_share": value.initial_share[0],
            "transferred_in": value.transferred_in[0],
            "transferred_out": value.transferred_out[0],
            "free_pool": value.free_pool[0],
            "lease_residual": value.lease_residual[0],
            "consumed": value.consumed[0],
            "spendable": value.free_pool[0] + value.lease_residual[0],
            "healthy": value.healthy,
        }


class CentralCounter:
    """A durable serialized counter baseline with idempotent request records."""

    def __init__(self, path: Path, budget: int) -> None:
        self.connection = sqlite3.connect(path, isolation_level=None)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute(
            "CREATE TABLE counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
            "remaining INTEGER NOT NULL, consumed INTEGER NOT NULL)"
        )
        self.connection.execute("INSERT INTO counter VALUES(1, ?, 0)", (budget,))
        self.connection.execute(
            "CREATE TABLE requests(request_id TEXT PRIMARY KEY, site TEXT NOT NULL, "
            "outcome TEXT NOT NULL)"
        )

    def authorize(self, request_id: str, site: str) -> tuple[bool, str, int]:
        start = time.perf_counter_ns()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            prior = self.connection.execute(
                "SELECT outcome FROM requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if prior is not None:
                self.connection.rollback()
                return prior[0] == "authorized", "idempotent_replay", time.perf_counter_ns() - start
            remaining = int(
                self.connection.execute(
                    "SELECT remaining FROM counter WHERE singleton=1"
                ).fetchone()[0]
            )
            outcome = "authorized" if remaining > 0 else "budget_exhausted"
            if remaining > 0:
                self.connection.execute(
                    "UPDATE counter SET remaining=remaining-1, consumed=consumed+1 "
                    "WHERE singleton=1"
                )
            self.connection.execute(
                "INSERT INTO requests VALUES(?, ?, ?)", (request_id, site, outcome)
            )
            self.connection.commit()
            return outcome == "authorized", outcome, time.perf_counter_ns() - start
        except BaseException:
            if self.connection.in_transaction:
                self.connection.rollback()
            raise

    def snapshot(self) -> dict[str, int]:
        remaining, consumed = self.connection.execute(
            "SELECT remaining, consumed FROM counter WHERE singleton=1"
        ).fetchone()
        return {"remaining": int(remaining), "consumed": int(consumed)}

    def close(self) -> None:
        self.connection.close()


def _schedule(total: int, weights: tuple[int, int, int]) -> list[str]:
    if total <= 0 or sum(weights) <= 0 or any(weight < 0 for weight in weights):
        raise ValueError("invalid deterministic schedule")
    result: list[str] = []
    accumulator = [0, 0, 0]
    weight_total = sum(weights)
    for _ in range(total):
        for index, weight in enumerate(weights):
            accumulator[index] += weight
        selected = max(range(3), key=lambda index: (accumulator[index], -index))
        accumulator[selected] -= weight_total
        result.append(SITES[selected])
    return result


def _snapshots(sites: dict[str, Site]) -> dict[str, dict[str, int | bool]]:
    return {name: sites[name].snapshot() for name in SITES}


def _aggregate(snapshots: dict[str, dict[str, int | bool]]) -> dict[str, int | bool]:
    integer_fields = (
        "initial_share",
        "transferred_in",
        "transferred_out",
        "free_pool",
        "lease_residual",
        "consumed",
        "spendable",
    )
    result: dict[str, int | bool] = {
        field: sum(int(snapshot[field]) for snapshot in snapshots.values())
        for field in integer_fields
    }
    result["healthy"] = all(bool(snapshot["healthy"]) for snapshot in snapshots.values())
    return result


def _initialize_sites(
    directory: Path,
    *,
    budget: int,
    shares: tuple[int, int, int],
) -> dict[str, Site]:
    directory.mkdir(parents=True, exist_ok=True)
    clock = ManualClock(CLOCK_NS)
    registry = PublicKeyRegistry(clock=clock)
    policy = _policy()
    raw: dict[str, tuple[Ed25519Signer, SQLiteStorage, WardenService]] = {}
    for name, share in zip(SITES, shares, strict=True):
        signer = Ed25519Signer.generate(name)
        registry.register_signer(signer)
        store = SQLiteStorage.initialize(
            directory / f"{name}.sqlite3",
            name,
            (budget,),
            signing_key_id=signer.key_id,
            signing_public_key=signer.public_key_bytes,
            tenant_id=TENANT,
            envelope_id=ENVELOPE,
            initial_local_share=(share,),
            receipt_ttl_ns=policy.receipt_ttl_ns,
            max_clock_uncertainty_ns=0,
            transfer_gap_window=policy.transfer_gap_window,
        )
        service = WardenService(store, signer=signer, clock=clock, trust_registry=registry)
        service.register_policy(policy)
        raw[name] = signer, store, service

    sites: dict[str, Site] = {}
    for name in SITES:
        signer, store, service = raw[name]
        replay = SQLiteReceiptReplayStore.initialize(
            directory / f"{name}-executor.sqlite3", allow_unanchored=True
        )
        verifier = ReceiptVerifier(
            registry,
            replay,
            ExecutorPolicy(
                audience=f"{AUDIENCE_PREFIX}-{name}",
                tenant_id=TENANT,
                envelope_id=ENVELOPE,
                config_epoch=1,
                allowed_policy_digests=frozenset({policy.digest}),
                allowed_machine_digests=frozenset({policy.machine.digest}),
                trusted_wardens=frozenset({name}),
            ),
            clock=clock,
        )
        site = Site(name, signer, store, service, replay, verifier, _identity(name))
        site.issue(shares[SITES.index(name)], suffix="initial")
        sites[name] = site
    return sites


def _rebalance_after_partition(
    sites: dict[str, Site], schedule: list[str], start_index: int
) -> list[dict[str, object]]:
    future = Counter(schedule[start_index:])
    target = sites["site-a"]
    target.close_lease(suffix="recovery")
    transfer_needed = max(0, future["site-a"] - int(target.snapshot()["free_pool"]))
    transfers: list[dict[str, object]] = []
    for donor_name in ("site-b", "site-c"):
        donor = sites[donor_name]
        donor.close_lease(suffix="recovery")
        donor_free = int(donor.snapshot()["free_pool"])
        surplus = max(0, donor_free - future[donor_name])
        amount = min(surplus, transfer_needed)
        if amount:
            voucher = donor.service.prepare_transfer(
                request_id=f"recovery-transfer-{donor_name}",
                identity=donor.identity,
                tenant_id=TENANT,
                envelope_id=ENVELOPE,
                target_warden="site-a",
                amount=(amount,),
                policy_digest=_policy().digest,
            )
            acknowledgement = target.service.accept_transfer(
                identity=target.identity, voucher=voucher
            )
            donor.service.finalize_transfer(
                identity=donor.identity, acknowledgement=acknowledgement
            )
            transfer_needed -= amount
            transfers.append(
                {
                    "source": donor_name,
                    "target": "site-a",
                    "amount": amount,
                    "sequence": voucher.sequence,
                    "accepted_once": True,
                    "finalized": True,
                }
            )
        retain = min(future[donor_name], int(donor.snapshot()["free_pool"]))
        donor.issue(retain, suffix="recovery")
    target_allocation = min(future["site-a"], int(target.snapshot()["free_pool"]))
    target.issue(target_allocation, suffix="recovery")
    return transfers


def _run_lets(
    directory: Path,
    *,
    name: str,
    budget: int,
    shares: tuple[int, int, int],
    schedule: list[str],
    partition_start: int,
    partition_end: int,
) -> dict[str, object]:
    sites = _initialize_sites(directory, budget=budget, shares=shares)
    events: list[dict[str, object]] = []
    transfers: list[dict[str, object]] = []
    try:
        for index, site_name in enumerate(schedule):
            if index == partition_end:
                transfers = _rebalance_after_partition(sites, schedule, index)
            phase = (
                "normal"
                if index < partition_start
                else "partition"
                if index < partition_end
                else "recovery"
            )
            site = sites[site_name]
            success, reason, latency_ns = site.authorize(index)
            snapshots = _snapshots(sites)
            aggregate = _aggregate(snapshots)
            if int(aggregate["consumed"]) > budget:
                raise AssertionError("aggregate LETS authorization exceeded genesis budget")
            events.append(
                {
                    "index": index,
                    "phase": phase,
                    "site": site_name,
                    "authorized": success,
                    "reason": reason,
                    "latency_ns": latency_ns,
                    "site_authorized": {key: value.authorized for key, value in sites.items()},
                    "site_denied": {key: value.denied for key, value in sites.items()},
                    "snapshots": snapshots,
                    "aggregate": aggregate,
                }
            )
        final_snapshots = _snapshots(sites)
        final_aggregate = _aggregate(final_snapshots)
        connected_latencies = [
            int(event["latency_ns"])
            for event in events
            if event["phase"] != "partition" and event["authorized"]
        ]
        partition_success = Counter(
            str(event["site"])
            for event in events
            if event["phase"] == "partition" and event["authorized"]
        )
        partition_denied = Counter(
            str(event["site"])
            for event in events
            if event["phase"] == "partition" and not event["authorized"]
        )
        first_exhaustion = next(
            (
                event
                for event in events
                if event["phase"] == "partition" and not event["authorized"]
            ),
            None,
        )
        return {
            "scheme": "lets",
            "scenario": name,
            "events": events,
            "recovery_transfers": transfers,
            "summary": {
                "authorized": sum(site.authorized for site in sites.values()),
                "denied": sum(site.denied for site in sites.values()),
                "partition_authorized_by_site": dict(partition_success),
                "partition_denied_by_site": dict(partition_denied),
                "first_partition_exhaustion_index": (
                    None if first_exhaustion is None else first_exhaustion["index"]
                ),
                "remote_spendable_at_first_exhaustion": (
                    None
                    if first_exhaustion is None
                    else sum(
                        int(snapshot["spendable"])
                        for site_key, snapshot in first_exhaustion["snapshots"].items()
                        if site_key != first_exhaustion["site"]
                    )
                ),
                "normal_latency_ns": latency_summary(connected_latencies),
                "final_snapshots": final_snapshots,
                "final_aggregate": final_aggregate,
                "conservation_healthy": bool(final_aggregate["healthy"])
                and int(final_aggregate["initial_share"]) == budget
                and int(final_aggregate["consumed"])
                == sum(site.authorized for site in sites.values()),
            },
        }
    finally:
        for site in sites.values():
            site.store.close()


def _run_central(
    path: Path,
    *,
    name: str,
    budget: int,
    schedule: list[str],
    partition_start: int,
    partition_end: int,
) -> dict[str, object]:
    counter = CentralCounter(path, budget)
    events: list[dict[str, object]] = []
    site_authorized = Counter()
    site_denied = Counter()
    try:
        for index, site in enumerate(schedule):
            phase = (
                "normal"
                if index < partition_start
                else "partition"
                if index < partition_end
                else "recovery"
            )
            reachable = not (phase == "partition" and site == "site-a")
            if reachable:
                success, reason, latency_ns = counter.authorize(f"central-{name}-{index:06d}", site)
            else:
                success, reason, latency_ns = False, "central_unreachable", 0
            if success:
                site_authorized[site] += 1
            else:
                site_denied[site] += 1
            snapshot = counter.snapshot()
            events.append(
                {
                    "index": index,
                    "phase": phase,
                    "site": site,
                    "reachable": reachable,
                    "authorized": success,
                    "reason": reason,
                    "latency_ns": latency_ns,
                    "site_authorized": {key: site_authorized[key] for key in SITES},
                    "site_denied": {key: site_denied[key] for key in SITES},
                    "snapshot": snapshot,
                }
            )
        normal_latencies = [
            int(event["latency_ns"])
            for event in events
            if event["reachable"] and event["phase"] != "partition" and event["authorized"]
        ]
        partition_success = Counter(
            str(event["site"])
            for event in events
            if event["phase"] == "partition" and event["authorized"]
        )
        partition_denied = Counter(
            str(event["site"])
            for event in events
            if event["phase"] == "partition" and not event["authorized"]
        )
        final = counter.snapshot()
        return {
            "scheme": "centralized_counter",
            "scenario": name,
            "events": events,
            "summary": {
                "authorized": sum(site_authorized.values()),
                "denied": sum(site_denied.values()),
                "partition_authorized_by_site": dict(partition_success),
                "partition_denied_by_site": dict(partition_denied),
                "normal_latency_ns": latency_summary(normal_latencies),
                "final": final,
                "counter_identity_healthy": final["remaining"] + final["consumed"] == budget,
            },
        }
    finally:
        counter.close()


def run_experiment(
    workspace: Path,
    *,
    total_requests: int = 300,
    partition_start: int = 60,
    partition_end: int = 210,
) -> dict[str, object]:
    if not 0 < partition_start < partition_end < total_requests:
        raise ValueError("partition bounds must fall strictly within the workload")
    if total_requests % 300:
        raise ValueError("total_requests must be a positive multiple of 300")
    scenarios = (
        ("balanced_equal_shares", (1, 1, 1), (100, 100, 100)),
        ("skew_equal_shares", (70, 15, 15), (100, 100, 100)),
        ("skew_demand_placed_shares", (70, 15, 15), (210, 45, 45)),
    )
    multiplier = total_requests // 300
    output: list[dict[str, object]] = []
    workspace.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="partition-study-", dir=workspace) as temporary:
        root = Path(temporary)
        for name, weights, base_shares in scenarios:
            shares = tuple(value * multiplier for value in base_shares)
            schedule = _schedule(total_requests, weights)
            output.append(
                _run_lets(
                    root / name,
                    name=name,
                    budget=total_requests,
                    shares=shares,
                    schedule=schedule,
                    partition_start=partition_start,
                    partition_end=partition_end,
                )
            )
            output.append(
                _run_central(
                    root / f"{name}-central.sqlite3",
                    name=name,
                    budget=total_requests,
                    schedule=schedule,
                    partition_start=partition_start,
                    partition_end=partition_end,
                )
            )
    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "source": source_identity(),
        "environment": environment_identity(),
        "topology": {
            "classification": "three_logical_sites_single_process_single_physical_host",
            "independent_warden_databases": True,
            "independent_executor_claim_databases": True,
            "independent_hosts": False,
            "network_fault": "deterministic reachability injection at the client boundary",
            "claim_limit": (
                "This is runtime accounting evidence, not the requested independent-host or "
                "wide-area availability experiment."
            ),
        },
        "configuration": {
            "total_requests": total_requests,
            "partition_start_index": partition_start,
            "partition_end_index_exclusive": partition_end,
            "isolated_site": "site-a",
            "central_counter_site": "site-b",
        },
        "runs": output,
    }


def _summary_markdown(result: dict[str, object]) -> str:
    lines = [
        "# Partition, skew, and centralized-counter results",
        "",
        "> Scope: three logical sites with separate durable warden and executor stores in one "
        "Python process on one physical host. This is not independent-host evidence.",
        "",
        "| Scenario | Scheme | Authorized | Denied | Partition A authorized | "
        "Partition A denied | Remote authority at first LETS exhaustion | Normal p50 (ms) | "
        "Normal p95 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for run in result["runs"]:
        summary = run["summary"]
        latency = summary["normal_latency_ns"]
        lines.append(
            "| {scenario} | {scheme} | {authorized} | {denied} | {pa} | {pd} | {remote} | "
            "{p50:.3f} | {p95:.3f} |".format(
                scenario=run["scenario"],
                scheme=run["scheme"],
                authorized=summary["authorized"],
                denied=summary["denied"],
                pa=summary["partition_authorized_by_site"].get("site-a", 0),
                pd=summary["partition_denied_by_site"].get("site-a", 0),
                remote=(
                    "—"
                    if summary.get("remote_spendable_at_first_exhaustion") is None
                    else summary["remote_spendable_at_first_exhaustion"]
                ),
                p50=latency["p50_ns"] / 1_000_000,
                p95=latency["p95_ns"] / 1_000_000,
            )
        )
    lines.extend(
        [
            "",
            "LETS authorizations include a durable warden debit, receipt verification, and a "
            "durable executor claim. The centralized baseline is one durable serialized SQLite "
            "counter transaction. Both exclude real network transport and application work.",
            "",
            "The raw JSON and CSV preserve every request, phase, decision, latency, per-site "
            "snapshot, transfer, and aggregate accounting value.",
        ]
    )
    return "\n".join(lines)


def _write_csv(result: dict[str, object], path: Path, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing evidence: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        fields = (
            "scenario",
            "scheme",
            "index",
            "phase",
            "site",
            "authorized",
            "reason",
            "latency_ns",
            "aggregate_consumed",
            "aggregate_spendable",
            "central_remaining",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for run in result["runs"]:
            for event in run["events"]:
                aggregate = event.get("aggregate", {})
                central = event.get("snapshot", {})
                writer.writerow(
                    {
                        "scenario": run["scenario"],
                        "scheme": run["scheme"],
                        "index": event["index"],
                        "phase": event["phase"],
                        "site": event["site"],
                        "authorized": event["authorized"],
                        "reason": event["reason"],
                        "latency_ns": event["latency_ns"],
                        "aggregate_consumed": aggregate.get("consumed", ""),
                        "aggregate_spendable": aggregate.get("spendable", ""),
                        "central_remaining": central.get("remaining", ""),
                    }
                )


def _polyline(points: list[tuple[float, float]], color: str, *, dash: str = "") -> str:
    rendered = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    dashed = f' stroke-dasharray="{dash}"' if dash else ""
    return (
        f'<polyline points="{rendered}" fill="none" stroke="{color}" stroke-width="2.2"{dashed}/>'
    )


def _figure_svg(result: dict[str, object]) -> str:
    lets = next(
        run
        for run in result["runs"]
        if run["scenario"] == "skew_equal_shares" and run["scheme"] == "lets"
    )
    central = next(
        run
        for run in result["runs"]
        if run["scenario"] == "skew_equal_shares" and run["scheme"] == "centralized_counter"
    )
    config = result["configuration"]
    total = int(config["total_requests"])
    start = int(config["partition_start_index"])
    end = int(config["partition_end_index_exclusive"])
    width, height = 1120, 820
    left, right = 95, 30
    plot_width = width - left - right
    panel_height = 175
    panel_tops = (130, 365, 600)
    colors = {"site-a": "#2563eb", "site-b": "#ea580c", "site-c": "#16a34a"}

    def x(index: int) -> float:
        return left + plot_width * index / max(1, total - 1)

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        "<style>text{font-family:Arial,sans-serif;fill:#111827}.axis{stroke:#9ca3af;stroke-width:1}"
        ".label{font-size:13px}.title{font-size:20px;font-weight:700}.small{font-size:11px}</style>",
        f'<text x="{left}" y="34" class="title">Skewed demand, equal initial shares</text>',
        f'<text x="{left}" y="55" class="label">70/15/15 demand; partition isolates '
        "site A from the central counter</text>",
    ]
    for top in panel_tops:
        shade_x = x(start)
        shade_width = x(end) - shade_x
        parts.append(
            f'<rect x="{shade_x:.1f}" y="{top}" width="{shade_width:.1f}" '
            f'height="{panel_height}" fill="#fee2e2" opacity="0.72"/>'
        )
        parts.append(
            f'<line x1="{left}" y1="{top + panel_height}" x2="{width - right}" '
            f'y2="{top + panel_height}" class="axis"/>'
        )
        parts.append(
            f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top + panel_height}" class="axis"/>'
        )
        parts.append(
            f'<line x1="{x(end):.1f}" y1="{top}" x2="{x(end):.1f}" '
            f'y2="{top + panel_height}" stroke="#991b1b" stroke-width="1.4" '
            'stroke-dasharray="5,4"/>'
        )
    parts.append(f'<text x="{x(start) + 8:.1f}" y="153" class="small">partition</text>')
    parts.append(f'<text x="{x(end) + 6:.1f}" y="153" class="small">recovery + transfer</text>')

    # Panel 1: per-site and aggregate completed actions.
    top = panel_tops[0]
    maximum = total
    for site in SITES:
        points = [
            (
                x(int(event["index"])),
                top + panel_height * (1 - int(event["site_authorized"][site]) / maximum),
            )
            for event in lets["events"]
        ]
        parts.append(_polyline(points, colors[site]))
    aggregate_points = [
        (
            x(int(event["index"])),
            top
            + panel_height
            * (1 - sum(int(value) for value in event["site_authorized"].values()) / maximum),
        )
        for event in lets["events"]
    ]
    central_points = [
        (
            x(int(event["index"])),
            top + panel_height * (1 - int(event["snapshot"]["consumed"]) / maximum),
        )
        for event in central["events"]
    ]
    parts.append(_polyline(aggregate_points, "#7c3aed", dash="7,4"))
    parts.append(_polyline(central_points, "#111827", dash="2,4"))
    parts.append(f'<text x="{left}" y="{top - 7}" class="label">completed actions</text>')
    parts.append(
        f'<text x="{left - 9}" y="{top + panel_height + 4}" text-anchor="end" '
        'class="small">0</text>'
    )
    parts.append(
        f'<text x="{left - 9}" y="{top + panel_height / 2 + 4:.1f}" text-anchor="end" '
        'class="small">150</text>'
    )
    parts.append(f'<text x="{left - 9}" y="{top + 4}" text-anchor="end" class="small">300</text>')

    # Panel 2: local spendable LETS authority.
    top = panel_tops[1]
    maximum = 120
    for site in SITES:
        points = [
            (
                x(int(event["index"])),
                top
                + panel_height
                * (1 - min(maximum, int(event["snapshots"][site]["spendable"])) / maximum),
            )
            for event in lets["events"]
        ]
        parts.append(_polyline(points, colors[site]))
    parts.append(f'<text x="{left}" y="{top - 7}" class="label">local spendable</text>')
    parts.append(
        f'<text x="{left - 9}" y="{top + panel_height + 4}" text-anchor="end" '
        'class="small">0</text>'
    )
    parts.append(f'<text x="{left - 9}" y="{top + 4}" text-anchor="end" class="small">120</text>')

    # Panel 3: cumulative denials.
    top = panel_tops[2]
    max_denied = max(
        1,
        max(sum(int(v) for v in event["site_denied"].values()) for event in central["events"]),
    )
    lets_denied = [
        (
            x(int(event["index"])),
            top
            + panel_height * (1 - sum(int(v) for v in event["site_denied"].values()) / max_denied),
        )
        for event in lets["events"]
    ]
    central_denied = [
        (
            x(int(event["index"])),
            top
            + panel_height * (1 - sum(int(v) for v in event["site_denied"].values()) / max_denied),
        )
        for event in central["events"]
    ]
    parts.append(_polyline(lets_denied, "#7c3aed"))
    parts.append(_polyline(central_denied, "#111827", dash="2,4"))
    parts.append(f'<text x="{left}" y="{top - 7}" class="label">cumulative denials</text>')
    parts.append(
        f'<text x="{left - 9}" y="{top + panel_height + 4}" text-anchor="end" '
        'class="small">0</text>'
    )
    parts.append(
        f'<text x="{left - 9}" y="{top + 4}" text-anchor="end" class="small">{max_denied}</text>'
    )
    for tick in (0, start, end, total - 1):
        parts.append(
            f'<text x="{x(tick):.1f}" y="{height - 25}" text-anchor="middle" '
            f'class="small">{tick}</text>'
        )
    parts.append(
        f'<text x="{width / 2 - 45:.1f}" y="{height - 7}" class="label">request index</text>'
    )

    for legend_x, y, label, color, dash in (
        (95, 79, "LETS site A", colors["site-a"], ""),
        (250, 79, "LETS site B", colors["site-b"], ""),
        (405, 79, "LETS site C", colors["site-c"], ""),
        (95, 104, "LETS aggregate / denial", "#7c3aed", "7,4"),
        (330, 104, "centralized counter", "#111827", "2,4"),
    ):
        dashed = f' stroke-dasharray="{dash}"' if dash else ""
        parts.append(
            f'<line x1="{legend_x}" y1="{y}" x2="{legend_x + 28}" y2="{y}" '
            f'stroke="{color}" stroke-width="2.2"{dashed}/>'
        )
        parts.append(f'<text x="{legend_x + 34}" y="{y + 4}" class="small">{label}</text>')
    parts.append("</svg>")
    return "\n".join(parts)


def write_outputs(result: dict[str, object], output_dir: Path, *, overwrite: bool) -> None:
    write_json(output_dir / "partition-results.json", result, overwrite=overwrite)
    _write_csv(result, output_dir / "partition-events.csv", overwrite=overwrite)
    write_text(
        output_dir / "PARTITION-RESULTS.md",
        _summary_markdown(result),
        overwrite=overwrite,
    )
    write_text(
        output_dir / "partition-skew-equal-shares.svg",
        _figure_svg(result),
        overwrite=overwrite,
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/nsdi-strengthening-2026-08-31/distributed"),
    )
    parser.add_argument("--workspace", type=Path, default=Path("benchmarks/results"))
    parser.add_argument("--total-requests", type=int, default=300)
    parser.add_argument("--partition-start", type=int, default=60)
    parser.add_argument("--partition-end", type=int, default=210)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    result = run_experiment(
        arguments.workspace,
        total_requests=arguments.total_requests,
        partition_start=arguments.partition_start,
        partition_end=arguments.partition_end,
    )
    write_outputs(result, arguments.output_dir, overwrite=arguments.overwrite)
    print(json.dumps({"status": "passed", "output_dir": str(arguments.output_dir)}))


if __name__ == "__main__":
    main()
