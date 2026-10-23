"""Grid runner for E1: enumerates cells (topology x load x skew x seed), drives one cell at a time
on each cluster described by an endpoints file that carries the ordered site roster (configure,
synchronized start, timed iptables faults via faults.py, collection, teardown), verifies the
actuator-side safety bound (unanchored restore controls may break it without failing a run), and
writes per-run JSON plus flat CSVs for analysis.py and report.py.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import dataclasses
import gzip
import json
import os
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from benchmarks.fair_baselines.common import (
    DEFAULT_ENVELOPE,
    DEFAULT_SITES,
    PLACEMENTS,
    SCHEMA,
    RunConfig,
    SystemSpec,
    default_systems,
    default_topologies,
    resolve_topology,
    site_roster,
    validate_shares,
)
from benchmarks.fair_baselines.faults import (
    DryRunFaultDriver,
    EndpointFaultDriver,
    FaultDriver,
    FaultInjector,
    SiteEndpoint,
    fault_schedule,
    link_label,
    parse_drop_counters,
)
from benchmarks.nsdi_strengthening.common import (
    environment_identity,
    evidence_manifest,
    source_identity,
    utc_now,
    write_json,
)
from lets.crypto import Ed25519Signer

NS_PER_S = 1_000_000_000
COUNTER_LEAD_S = 1.0
PROBE_JOIN_S = 60.0
REQUEST_FIELDS = (
    "run_id",
    "topology",
    "load",
    "theta",
    "seed",
    "placement",
    "system",
    "site",
    "index",
    "request_id",
    "planned_offset_ns",
    "arrival_offset_ns",
    "outcome",
    "reason",
    "t_auth_ns",
    "attempts",
    "messages",
    "deadline_ns",
)
EVENT_FIELDS = ("run_id", "system", "site", "offset_ns", "kind", "value", "detail")
FAULT_FIELDS = (
    "run_id",
    "scheduled_offset_s",
    "kind",
    "link",
    "site",
    "command",
    "ok",
    "sent_offset_s",
    "returned_offset_s",
)
MESSAGE_FIELDS = (
    "run_id",
    "topology",
    "load",
    "theta",
    "seed",
    "placement",
    "system",
    "site",
    "messages",
)
RUN_FIELDS = (
    "run_id",
    "topology",
    "load",
    "theta",
    "seed",
    "placement",
    "envelope",
    "cluster",
    "status",
    "start_wall_ns",
    "plan_size",
    "system",
    "authorized",
    "denied",
    "timeout",
    "effects",
    "safety_margin",
    "safety_ok",
    "messages",
    "dropped_packets",
)


class ControllerError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Cell:
    topology: str
    load: float
    theta: float
    seed: int
    placement: str

    @property
    def run_id(self) -> str:
        return f"{self.topology}-L{self.load:g}-T{self.theta:g}-{self.placement}-S{self.seed:03d}"


@dataclass(frozen=True, slots=True)
class Cluster:
    name: str
    sites: dict[str, SiteEndpoint]


@dataclass(frozen=True, slots=True)
class GridOptions:
    systems: tuple[str, ...]
    envelope: int
    pre_s: float
    partition_s: float
    post_s: float
    deadline_s: float
    rtt_ms: float
    loss_pct: float
    peer_timeout_s: float = 2.0
    raft_timeout_s: float = 2.0
    ready_timeout_s: float = 45.0
    sites: tuple[str, ...] = DEFAULT_SITES
    shares: dict[str, int] | None = None


def load_endpoints(path: Path) -> tuple[list[Cluster], str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    token_env = str(payload.get("token_env", "LETS_E1_TOKEN"))
    token = os.environ.get(token_env) or str(payload.get("token", ""))
    if len(token) < 16:
        raise ControllerError(f"no shared token: set {token_env} or add token to {path}")
    try:
        roster = site_roster(payload.get("sites", DEFAULT_SITES))
    except ValueError as exc:
        raise ControllerError(f"{path}: {exc}") from None
    clusters = []
    for entry in payload["clusters"]:
        name = str(entry["name"])
        listed = entry["sites"]
        if not isinstance(listed, Mapping) or set(listed) != set(roster):
            raise ControllerError(
                f"cluster {name!r} must describe exactly the sites {list(roster)}"
            )
        try:
            sites = {site: SiteEndpoint.from_dict(site, listed[site]) for site in roster}
        except (ValueError, KeyError, TypeError) as exc:
            raise ControllerError(f"cluster {name!r}: {exc}") from None
        clusters.append(Cluster(name, sites))
    if not clusters:
        raise ControllerError("endpoints file lists no clusters")
    return clusters, token


def cluster_roster(clusters: Sequence[Cluster]) -> tuple[str, ...]:
    rosters = {tuple(cluster.sites) for cluster in clusters}
    if len(rosters) != 1:
        raise ControllerError("every cluster must list the same sites in the same order")
    return rosters.pop()


def grid_cells(
    topologies: Sequence[str],
    loads: Sequence[float],
    thetas: Sequence[float],
    seeds: Sequence[int],
    placements: Sequence[str],
    sites: Sequence[str] = DEFAULT_SITES,
) -> list[Cell]:
    for topology in topologies:
        try:
            resolve_topology(topology, sites)
        except ValueError as exc:
            raise ControllerError(str(exc)) from None
    for placement in placements:
        if placement not in PLACEMENTS:
            raise ControllerError(f"unknown placement {placement!r}")
    return [
        Cell(topology, load, theta, seed, placement)
        for topology in topologies
        for load in loads
        for theta in thetas
        for placement in placements
        for seed in seeds
    ]


class SiteClient:
    def __init__(self, endpoint: SiteEndpoint, token: str, timeout_s: float = 30.0) -> None:
        self.endpoint = endpoint
        self.token = token
        self.timeout_s = timeout_s

    def call(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            f"{self.endpoint.control_url}{path}",
            data=data,
            method=method,
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise ControllerError(
                f"{self.endpoint.site} {method} {path} -> {exc.code}: {detail}"
            ) from None
        except (OSError, urllib.error.URLError) as exc:
            raise ControllerError(
                f"{self.endpoint.site} {method} {path} unreachable: {exc}"
            ) from None
        if not isinstance(payload, dict):
            raise ControllerError(f"{self.endpoint.site} {path}: non-object response")
        return payload


def probe_links(clients: Mapping[str, Any], sites: Sequence[str]) -> list[dict[str, object]]:
    pairs = [(site, target) for site in clients for target in sites if target != site]
    if not pairs:
        return []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(pairs), 64)) as pool:
        futures = [
            pool.submit(clients[site].call, "POST", "/probe/peer", {"target": target})
            for site, target in pairs
        ]
        return [
            {"source": site, **future.result()}
            for (site, _target), future in zip(pairs, futures, strict=True)
        ]


def run_config(cell: Cell, options: GridOptions) -> RunConfig:
    return RunConfig(
        run_id=cell.run_id,
        topology=cell.topology,
        load=cell.load,
        theta=cell.theta,
        seed=cell.seed,
        placement=cell.placement,
        envelope=options.envelope,
        systems=options.systems,
        pre_s=options.pre_s,
        partition_s=options.partition_s,
        post_s=options.post_s,
        deadline_s=options.deadline_s,
        peer_timeout_s=options.peer_timeout_s,
        raft_timeout_s=options.raft_timeout_s,
        sites=options.sites,
        explicit_shares=options.shares,
        extra={"rtt_ms": options.rtt_ms, "loss_pct": options.loss_pct},
    )


def verify_safety(
    envelope: int, site_results: Mapping[str, Mapping[str, Any]]
) -> dict[str, dict[str, object]]:
    verdicts: dict[str, dict[str, object]] = {}
    systems: set[str] = set()
    for payload in site_results.values():
        systems.update(payload["effects"].keys())
        systems.update(payload["messages"].keys())
    for system in sorted(systems):
        ids: list[str] = []
        authorized = 0
        for payload in site_results.values():
            entry = payload["effects"].get(system)
            if entry is not None:
                ids.extend(str(item) for item in entry["request_ids"])
            authorized += sum(
                1
                for record in payload["records"]
                if record["system"] == system and record["outcome"] == "authorized"
            )
        duplicates = len(ids) - len(set(ids))
        verdicts[system] = {
            "effects": len(ids),
            "authorized_records": authorized,
            "duplicate_effects": duplicates,
            "safety_margin": envelope - len(ids),
            "safety_ok": duplicates == 0 and len(ids) <= envelope and authorized == len(ids),
        }
    return verdicts


def unexpected_safety_failures(safety: Mapping[str, Mapping[str, object]]) -> list[str]:
    return [
        system
        for system, verdict in sorted(safety.items())
        if not verdict["safety_ok"] and not SystemSpec.parse(system).expected_unsafe
    ]


class CellRunner:
    def __init__(
        self,
        cluster: Cluster,
        token: str,
        options: GridOptions,
        driver: FaultDriver,
        output_dir: Path,
        log: Any = sys.stderr,
    ) -> None:
        self.cluster = cluster
        self.token = token
        self.options = options
        self.injector = FaultInjector(driver, cluster.sites)
        self.clients = {
            site: SiteClient(endpoint, token) for site, endpoint in cluster.sites.items()
        }
        self.output_dir = output_dir
        self.log = log

    def _say(self, message: str) -> None:
        print(f"[{utc_now()}] [{self.cluster.name}] {message}", file=self.log, flush=True)

    def prepare(self) -> None:
        for site, client in self.clients.items():
            health = client.call("GET", "/health")
            if health.get("site") != site:
                raise ControllerError(f"{site}: endpoint reports site {health.get('site')!r}")
            if health.get("run_id") is not None:
                client.call("POST", "/run/teardown")
        self.injector.prepare(self.options.rtt_ms / 2, self.options.loss_pct)

    def cleanup(self) -> None:
        self.injector.cleanup()

    def _configure(self, config: RunConfig) -> dict[str, dict[str, Any]]:
        signers = {site: Ed25519Signer.generate(site) for site in self.cluster.sites}
        public_keys = {
            site: {
                "key_id": signer.key_id,
                "public_key": base64.b64encode(signer.public_key_bytes).decode("ascii"),
            }
            for site, signer in signers.items()
        }
        configured = {}
        for site, client in self.clients.items():
            peers = {
                peer: endpoint.peer_url
                for peer, endpoint in self.cluster.sites.items()
                if peer != site
            }
            configured[site] = client.call(
                "POST",
                "/run/configure",
                {
                    "config": config.to_dict(),
                    "peers": peers,
                    "keys": {
                        "seed": base64.b64encode(signers[site].seed_bytes).decode("ascii"),
                        "public_keys": public_keys,
                    },
                    "raft": {
                        "self": self.cluster.sites[site].raft_address,
                        "peers": {
                            peer: endpoint.raft_address
                            for peer, endpoint in self.cluster.sites.items()
                            if peer != site
                        },
                    },
                },
            )
        return configured

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + self.options.ready_timeout_s
        while True:
            statuses = {
                site: client.call("GET", "/run/status") for site, client in self.clients.items()
            }
            if all(status.get("ready") is True for status in statuses.values()):
                return
            if time.monotonic() >= deadline:
                raise ControllerError(f"sites never became ready: {statuses}")
            time.sleep(0.5)

    def _probe_links(self) -> list[dict[str, object]]:
        return probe_links(self.clients, list(self.cluster.sites))

    def _fault_thread(
        self,
        config: RunConfig,
        start_at_ns: int,
        faults: list[dict[str, object]],
        counters: dict[str, Any],
        failures: list[str],
    ) -> None:
        topology = config.resolved_topology()
        probe_worker: threading.Thread | None = None

        def probe_during_cut() -> None:
            try:
                counters["probes_during_cut"] = self._probe_links()
            except Exception as exc:
                failures.append(f"in-cut probes failed: {exc}")

        def sleep_until(offset_s: float) -> None:
            delay = (start_at_ns + int(offset_s * NS_PER_S) - time.time_ns()) / NS_PER_S
            if delay > 0:
                time.sleep(delay)

        try:
            for scheduled in fault_schedule(topology, config.pre_s, config.partition_s):
                if scheduled.kind == "heal":
                    sleep_until(scheduled.offset_s - COUNTER_LEAD_S)
                    counters[f"before_heal_{len(faults)}"] = {
                        site: parse_drop_counters(output)
                        for site, output in self.injector.counters().items()
                    }
                    sleep_until(scheduled.offset_s)
                    results = self.injector.heal()
                else:
                    sleep_until(scheduled.offset_s)
                    results = self.injector.cut(scheduled.links)
                for result in results:
                    faults.append(
                        {
                            "scheduled_offset_s": scheduled.offset_s,
                            "kind": scheduled.kind,
                            "link": ",".join(sorted(link_label(link) for link in scheduled.links)),
                            "site": result.site,
                            "command": result.command,
                            "ok": result.ok,
                            "sent_offset_s": (result.sent_wall_ns - start_at_ns) / NS_PER_S,
                            "returned_offset_s": (result.returned_wall_ns - start_at_ns) / NS_PER_S,
                        }
                    )
                if scheduled.kind == "cut" and scheduled.offset_s == config.pre_s:
                    probe_worker = threading.Thread(
                        target=probe_during_cut, name=f"probes-{config.run_id}", daemon=True
                    )
                    probe_worker.start()
        except Exception as exc:
            failures.append(f"fault injection failed: {exc}")
            try:
                self.injector.heal()
            except Exception as heal_exc:
                failures.append(f"heal after failure also failed: {heal_exc}")
        if probe_worker is not None:
            probe_worker.join(timeout=PROBE_JOIN_S)
            if probe_worker.is_alive():
                failures.append("in-cut probes did not finish")

    def run_cell(self, cell: Cell) -> dict[str, Any]:
        config = run_config(cell, self.options)
        self._say(f"configuring {config.run_id}")
        started = utc_now()
        configured = self._configure(config)
        failures: list[str] = []
        faults: list[dict[str, object]] = []
        counters: dict[str, Any] = {}
        site_results: dict[str, dict[str, Any]] = {}
        try:
            self._wait_ready()
            probes_before = self._probe_links()
            if not all(probe.get("reachable") for probe in probes_before):
                raise ControllerError(f"links are not all up before the run: {probes_before}")
            start_at_ns = time.time_ns() + 2 * NS_PER_S
            for client in self.clients.values():
                client.call("POST", "/run/start", {"start_at_epoch_ns": start_at_ns})
            worker = threading.Thread(
                target=self._fault_thread,
                args=(config, start_at_ns, faults, counters, failures),
                name=f"faults-{config.run_id}",
                daemon=True,
            )
            worker.start()
            hard_deadline = start_at_ns + int(
                (config.arrival_window_s + config.deadline_s + 20) * NS_PER_S
            )
            while True:
                statuses = {
                    site: client.call("GET", "/run/status") for site, client in self.clients.items()
                }
                if all(status.get("status") == "done" for status in statuses.values()):
                    break
                if time.time_ns() > hard_deadline:
                    raise ControllerError(
                        f"run did not finish before the hard deadline: {statuses}"
                    )
                time.sleep(1.0)
            worker.join(timeout=60)
            if worker.is_alive():
                failures.append("fault thread did not finish")
            probes_after = self._probe_links()
            for site, client in self.clients.items():
                site_results[site] = client.call("GET", "/run/results")
        finally:
            try:
                self.injector.heal()
            except Exception as exc:
                failures.append(f"final heal failed: {exc}")
            for site, client in self.clients.items():
                try:
                    client.call("POST", "/run/teardown")
                except ControllerError as exc:
                    failures.append(f"{site} teardown failed: {exc}")
        safety = verify_safety(config.envelope, site_results)
        if unexpected_safety_failures(safety):
            failures.append("safety check failed")
        result = {
            "schema": SCHEMA,
            "run_id": config.run_id,
            "cluster": self.cluster.name,
            "cell": {
                "topology": cell.topology,
                "load": cell.load,
                "theta": cell.theta,
                "seed": cell.seed,
                "placement": cell.placement,
            },
            "config": config.to_dict(),
            "started_at": started,
            "finished_at": utc_now(),
            "start_at_epoch_ns": start_at_ns,
            "configured": configured,
            "probes_before": probes_before,
            "probes_after": probes_after,
            "faults": faults,
            "drop_counters": counters,
            "sites": site_results,
            "safety": safety,
            "failures": failures,
            "status": "passed" if not failures else "failed",
        }
        self._say(f"{config.run_id}: {result['status']} {json.dumps(summarize(result))}")
        return result


def summarize(result: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}
    for payload in result["sites"].values():
        for record in payload["records"]:
            entry = summary.setdefault(
                record["system"], {"authorized": 0, "denied": 0, "timeout": 0}
            )
            entry[record["outcome"]] += 1
    return summary


def run_path(output_dir: Path, run_id: str) -> Path:
    return output_dir / "runs" / f"{run_id}.json.gz"


def write_run(result: Mapping[str, Any], output_dir: Path) -> Path:
    path = run_path(output_dir, str(result["run_id"]))
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(result, indent=1, sort_keys=True, ensure_ascii=False).encode("utf-8")
    with gzip.open(path, "wb", compresslevel=9) as stream:
        stream.write(encoded)
    return path


def read_run(path: Path) -> dict[str, Any]:
    if path.suffix == ".gz":
        with gzip.open(path, "rb") as stream:
            payload = json.loads(stream.read().decode("utf-8"))
    else:
        payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ControllerError(f"{path}: run payload is not an object")
    return payload


def run_files(output_dir: Path) -> list[Path]:
    runs_dir = output_dir / "runs"
    return sorted([*runs_dir.glob("*.json"), *runs_dir.glob("*.json.gz")])


def assemble(output_dir: Path) -> dict[str, int]:
    paths = run_files(output_dir)
    counts = {"runs": 0, "requests": 0, "events": 0, "faults": 0, "messages": 0}
    with (
        (output_dir / "requests.csv").open("w", encoding="utf-8", newline="") as requests_file,
        (output_dir / "events.csv").open("w", encoding="utf-8", newline="") as events_file,
        (output_dir / "faults.csv").open("w", encoding="utf-8", newline="") as faults_file,
        (output_dir / "runs.csv").open("w", encoding="utf-8", newline="") as runs_file,
        (output_dir / "messages.csv").open("w", encoding="utf-8", newline="") as messages_file,
    ):
        requests_writer = csv.DictWriter(requests_file, REQUEST_FIELDS, lineterminator="\n")
        events_writer = csv.DictWriter(events_file, EVENT_FIELDS, lineterminator="\n")
        faults_writer = csv.DictWriter(faults_file, FAULT_FIELDS, lineterminator="\n")
        runs_writer = csv.DictWriter(runs_file, RUN_FIELDS, lineterminator="\n")
        messages_writer = csv.DictWriter(messages_file, MESSAGE_FIELDS, lineterminator="\n")
        for writer in (requests_writer, events_writer, faults_writer, runs_writer, messages_writer):
            writer.writeheader()
        for path in paths:
            result = read_run(path)
            cell = result["cell"]
            run_id = result["run_id"]
            base = {"run_id": run_id, **cell}
            counts["runs"] += 1
            outcomes = summarize(result)
            dropped = 0
            for snapshot in result["drop_counters"].values():
                if isinstance(snapshot, dict):
                    for rows in snapshot.values():
                        dropped += sum(int(row["packets"]) for row in rows)
            for system, verdict in result["safety"].items():
                messages = sum(
                    int(payload["messages"].get(system, 0)) for payload in result["sites"].values()
                )
                runs_writer.writerow(
                    {
                        **base,
                        "envelope": result["config"]["envelope"],
                        "cluster": result["cluster"],
                        "status": result["status"],
                        "start_wall_ns": result["start_at_epoch_ns"],
                        "plan_size": next(iter(result["sites"].values()))["plan_size"],
                        "system": system,
                        **outcomes.get(system, {"authorized": 0, "denied": 0, "timeout": 0}),
                        "effects": verdict["effects"],
                        "safety_margin": verdict["safety_margin"],
                        "safety_ok": verdict["safety_ok"],
                        "messages": messages,
                        "dropped_packets": dropped,
                    }
                )
            for site, payload in result["sites"].items():
                for system, messages in payload["messages"].items():
                    messages_writer.writerow(
                        {**base, "system": system, "site": site, "messages": messages}
                    )
                    counts["messages"] += 1
                for record in payload["records"]:
                    requests_writer.writerow(
                        {**base, **{key: record[key] for key in REQUEST_FIELDS if key in record}}
                    )
                    counts["requests"] += 1
                for event in payload["events"]:
                    events_writer.writerow({"run_id": run_id, **event})
                    counts["events"] += 1
            for fault in result["faults"]:
                faults_writer.writerow({"run_id": run_id, **fault})
                counts["faults"] += 1
    return counts


def write_manifest(output_dir: Path, command: Sequence[str], extra: Mapping[str, Any]) -> None:
    manifest = {
        "schema": "lets.fair-baselines-manifest/v1",
        "generated_at": utc_now(),
        "command": list(command),
        "source": source_identity(),
        "environment": environment_identity(),
        **extra,
        "files": evidence_manifest(output_dir, exclude=("MANIFEST.json",))["files"],
    }
    write_json(output_dir / "MANIFEST.json", manifest, overwrite=True)


def read_manifest(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    return payload if isinstance(payload, dict) else None


def run_record(manifest: Mapping[str, Any]) -> dict[str, Any] | None:
    command = manifest.get("command")
    if not isinstance(command, list) or not command:
        return None
    if command[0] == "run":
        run_command, source, environment = (
            command,
            manifest.get("source"),
            manifest.get("environment"),
        )
    elif command[0] == "assemble" and isinstance(manifest.get("run_command"), list):
        run_command = manifest["run_command"]
        source, environment = manifest.get("run_source"), manifest.get("run_environment")
    else:
        return None
    outcomes = manifest.get("outcomes", {})
    tally: dict[str, int] = {}
    for status in outcomes.values():
        tally[str(status)] = tally.get(str(status), 0) + 1
    return {
        "generated_at": manifest.get("generated_at"),
        "command": run_command,
        "source": source,
        "environment": environment,
        "cells": manifest.get("grid", {}).get("cells"),
        "outcomes": tally,
    }


def merge_run_history(manifests: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        for entry in manifest.get("run_history", []):
            records.setdefault(str(entry.get("generated_at")), dict(entry))
        own = run_record(manifest)
        if own is not None and not (
            manifest.get("command", [""])[0] == "assemble" and manifest.get("run_history")
        ):
            records.setdefault(str(own["generated_at"]), own)
    return [records[key] for key in sorted(records)]


def run_outcomes(output_dir: Path) -> dict[str, str]:
    outcomes = {}
    for path in run_files(output_dir):
        result = read_run(path)
        outcomes[str(result["run_id"])] = str(result.get("status", "unknown"))
    return outcomes


def run_grid(
    clusters: Sequence[Cluster],
    token: str,
    cells: Sequence[Cell],
    options: GridOptions,
    output_dir: Path,
    *,
    driver: FaultDriver | None = None,
    overwrite: bool = False,
    log: Any = sys.stderr,
) -> dict[str, Any]:
    if cluster_roster(clusters) != tuple(options.sites):
        raise ControllerError("the grid's sites do not match the clusters' sites")
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "runs").mkdir(exist_ok=True)
    pending = [
        cell for cell in cells if overwrite or not run_path(output_dir, cell.run_id).exists()
    ]
    skipped = len(cells) - len(pending)
    runners = [
        CellRunner(cluster, token, options, driver or EndpointFaultDriver(), output_dir, log)
        for cluster in clusters
    ]
    for runner in runners:
        runner.prepare()
    queue: list[Cell] = list(pending)
    queue_lock = threading.Lock()
    outcomes: dict[str, str] = {}

    def work(runner: CellRunner) -> None:
        while True:
            with queue_lock:
                if not queue:
                    return
                cell = queue.pop(0)
            try:
                result = runner.run_cell(cell)
            except Exception as exc:
                result = {
                    "schema": SCHEMA,
                    "run_id": cell.run_id,
                    "cluster": runner.cluster.name,
                    "cell": {
                        "topology": cell.topology,
                        "load": cell.load,
                        "theta": cell.theta,
                        "seed": cell.seed,
                        "placement": cell.placement,
                    },
                    "config": run_config(cell, options).to_dict(),
                    "status": "error",
                    "failures": [f"{type(exc).__name__}: {exc}", traceback.format_exc()[-2000:]],
                    "sites": {},
                    "safety": {},
                    "faults": [],
                    "drop_counters": {},
                    "start_at_epoch_ns": 0,
                }
                print(f"[{runner.cluster.name}] {cell.run_id}: ERROR {exc}", file=log, flush=True)
            write_run(result, output_dir)
            with queue_lock:
                outcomes[cell.run_id] = str(result["status"])

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(runners)) as pool:
            futures = [pool.submit(work, runner) for runner in runners]
            for future in futures:
                future.result()
    finally:
        for runner in runners:
            try:
                runner.cleanup()
            except Exception as exc:
                print(f"[{runner.cluster.name}] cleanup failed: {exc}", file=log, flush=True)
    counts = assemble(output_dir)
    return {"skipped": skipped, "outcomes": outcomes, "assembled": counts}


def _float_list(values: Sequence[str]) -> tuple[float, ...]:
    return tuple(float(value) for value in values)


def parse_shares(
    values: Sequence[str] | None, sites: Sequence[str], envelope: int
) -> dict[str, int] | None:
    if values is None:
        return None
    table: dict[str, int] = {}
    for item in values:
        site, separator, units = item.partition("=")
        if not separator or not units.isdigit():
            raise ControllerError(f"--shares entries look like SITE=UNITS, not {item!r}")
        table[site] = int(units)
    try:
        return validate_shares(table, sites, envelope, "--shares")
    except ValueError as exc:
        raise ControllerError(str(exc)) from None


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the grid on the clusters in an endpoints file")
    run.add_argument("--endpoints", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--topologies", nargs="+", default=None)
    run.add_argument("--loads", nargs="+", default=["0.7", "2.0"])
    run.add_argument("--thetas", nargs="+", default=["0", "0.5", "1"])
    run.add_argument("--seeds", type=int, default=20)
    run.add_argument("--seed-offset", type=int, default=1)
    run.add_argument("--placements", nargs="+", default=["equal"])
    run.add_argument(
        "--shares",
        nargs="+",
        default=None,
        metavar="SITE=UNITS",
        help="explicit per-site shares for the explicit placement",
    )
    run.add_argument("--systems", nargs="+", default=None)
    run.add_argument("--envelope", type=int, default=DEFAULT_ENVELOPE)
    run.add_argument("--pre-s", type=float, default=5.0)
    run.add_argument("--partition-s", type=float, default=30.0)
    run.add_argument("--post-s", type=float, default=15.0)
    run.add_argument("--deadline-s", type=float, default=20.0)
    run.add_argument("--rtt-ms", type=float, default=50.0)
    run.add_argument("--loss-pct", type=float, default=0.0)
    run.add_argument("--overwrite", action="store_true")
    run.add_argument("--dry-run-faults", action="store_true", help="record fault commands only")
    assemble_parser = sub.add_parser("assemble", help="rebuild the CSVs from runs/*.json")
    assemble_parser.add_argument("--output", type=Path, required=True)
    assemble_parser.add_argument("--merge-manifest", type=Path, action="append", default=[])
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.command == "assemble":
        counts = assemble(arguments.output)
        previous = read_manifest(arguments.output / "MANIFEST.json")
        merged = [m for m in (read_manifest(p) for p in arguments.merge_manifest) if m]
        carried: dict[str, Any] = {}
        if previous is not None:
            carried = {
                key: previous[key]
                for key in ("grid", "run_command", "run_source", "run_environment")
                if key in previous
            }
            if "run_command" not in previous and run_record(previous) is not None:
                carried["run_command"] = previous.get("command")
                carried["run_source"] = previous.get("source")
                carried["run_environment"] = previous.get("environment")
        outcomes = run_outcomes(arguments.output)
        if "grid" in carried:
            carried["grid"] = {**carried["grid"], "cells": len(outcomes)}
        history = merge_run_history([*([previous] if previous else []), *merged])
        write_manifest(
            arguments.output,
            ["assemble"],
            {**carried, "outcomes": outcomes, "run_history": history, "assembled": counts},
        )
        print(json.dumps(counts))
        return 0
    clusters, token = load_endpoints(arguments.endpoints)
    sites = cluster_roster(clusters)
    systems = tuple(arguments.systems or default_systems(sites))
    for name in systems:
        SystemSpec.parse(name, sites)
    shares = parse_shares(arguments.shares, sites, arguments.envelope)
    if (shares is None) != ("explicit" not in arguments.placements):
        raise ControllerError("--shares and the explicit placement go together")
    options = GridOptions(
        systems=systems,
        envelope=arguments.envelope,
        pre_s=arguments.pre_s,
        partition_s=arguments.partition_s,
        post_s=arguments.post_s,
        deadline_s=arguments.deadline_s,
        rtt_ms=arguments.rtt_ms,
        loss_pct=arguments.loss_pct,
        sites=sites,
        shares=shares,
    )
    cells = grid_cells(
        arguments.topologies or default_topologies(sites),
        _float_list(arguments.loads),
        _float_list(arguments.thetas),
        range(arguments.seed_offset, arguments.seed_offset + arguments.seeds),
        arguments.placements,
        sites,
    )
    driver: FaultDriver | None = DryRunFaultDriver() if arguments.dry_run_faults else None
    previous = read_manifest(arguments.output / "MANIFEST.json")
    outcome = run_grid(
        clusters,
        token,
        cells,
        options,
        arguments.output,
        driver=driver,
        overwrite=arguments.overwrite,
    )
    command = [part for part in (sys.argv[1:] if argv is None else list(argv))]
    write_manifest(
        arguments.output,
        command,
        {
            "grid": {
                "cells": len(cells),
                "skipped": outcome["skipped"],
                "sites": list(sites),
                "options": dataclasses.asdict(options),
                "clusters": [
                    {
                        "name": cluster.name,
                        "sites": {s: e.to_dict() for s, e in cluster.sites.items()},
                    }
                    for cluster in clusters
                ],
            },
            "outcomes": outcome["outcomes"],
            "run_history": merge_run_history([previous] if previous else []),
            "assembled": outcome["assembled"],
        },
    )
    failed = sum(1 for status in outcome["outcomes"].values() if status != "passed")
    print(json.dumps({"cells": len(cells), "failed": failed, **outcome["assembled"]}))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
