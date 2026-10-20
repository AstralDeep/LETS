"""Tests for benchmarks/fair_baselines/controller.py plus analysis.py on real
output: grid enumeration, endpoint loading for three- and seven-site rosters, safety verification,
dry-fault grid runs against three and five loopback agents with the LETS delegation tree, CSV
assembly, the per-site table, and the lease-tree cost table.
"""

from __future__ import annotations

import csv
import json
import threading
import time
from pathlib import Path

import pytest

from benchmarks.fair_baselines import analysis
from benchmarks.fair_baselines.common import default_systems, default_topologies
from benchmarks.fair_baselines.controller import (
    Cell,
    ControllerError,
    GridOptions,
    assemble,
    cluster_roster,
    grid_cells,
    load_endpoints,
    main,
    merge_run_history,
    parse_shares,
    probe_links,
    read_run,
    run_config,
    run_grid,
    run_outcomes,
    run_path,
    run_record,
    summarize,
    verify_safety,
    write_manifest,
)
from benchmarks.fair_baselines.faults import DryRunFaultDriver
from tests.benchmarks.conftest import FIVE_SITES, LoopbackCluster

EXAMPLE = Path("benchmarks/fair_baselines/examples/seven-site-endpoints.json")
SEVEN = ("uk1", "uk2", "az1", "use2", "usw2", "euw2", "apse1")


def test_grid_cells_enumerate_and_name_runs() -> None:
    cells = grid_cells(["split-s1", "bridge-s3"], [0.7, 2.0], [0.0, 1.0], [1, 2], ["equal"])
    assert len(cells) == 16
    assert cells[0].run_id == "split-s1-L0.7-T0-equal-S001"
    assert len({cell.run_id for cell in cells}) == 16
    with pytest.raises(ControllerError, match="unknown topology"):
        grid_cells(["mesh"], [1.0], [0.0], [1], ["equal"])
    with pytest.raises(ControllerError, match="unknown placement"):
        grid_cells(["split-s1"], [1.0], [0.0], [1], ["random"])
    seven = grid_cells(["isolate-use2", "halves"], [0.7], [1.0], [1, 2], ["explicit"], SEVEN)
    assert [cell.run_id for cell in seven][:2] == [
        "isolate-use2-L0.7-T1-explicit-S001",
        "isolate-use2-L0.7-T1-explicit-S002",
    ]
    with pytest.raises(ControllerError, match="unknown topology"):
        grid_cells(["split-s1"], [1.0], [0.0], [1], ["equal"], SEVEN)


def test_load_endpoints_requires_a_token_and_clusters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "endpoints.json"
    site = {
        "control_url": "http://127.0.0.1:1",
        "peer_ip": "10.0.0.1",
        "peer_port": 1,
        "raft_port": 2,
        "fault_exec": ["dry"],
    }
    path.write_text(
        json.dumps({"clusters": [{"name": "a", "sites": {s: site for s in ("s1", "s2", "s3")}}]})
    )
    monkeypatch.delenv("LETS_E1_TOKEN", raising=False)
    with pytest.raises(ControllerError, match="no shared token"):
        load_endpoints(path)
    monkeypatch.setenv("LETS_E1_TOKEN", "x" * 20)
    clusters, token = load_endpoints(path)
    assert token == "x" * 20 and clusters[0].name == "a"
    path.write_text(json.dumps({"token": "y" * 20, "clusters": []}))
    monkeypatch.delenv("LETS_E1_TOKEN")
    with pytest.raises(ControllerError, match="no clusters"):
        load_endpoints(path)
    assert cluster_roster(clusters) == ("s1", "s2", "s3")


def _endpoints_payload(sites: list[str] | None, clusters: list[dict[str, object]]) -> str:
    payload: dict[str, object] = {"token": "y" * 20, "clusters": clusters}
    if sites is not None:
        payload["sites"] = sites
    return json.dumps(payload)


def test_load_endpoints_validates_the_site_roster(tmp_path: Path) -> None:
    site = {
        "control_url": "http://127.0.0.1:1",
        "peer_ip": "10.0.0.1",
        "peer_port": 1,
        "raft_port": 2,
        "fault_exec": ["dry"],
    }
    path = tmp_path / "endpoints.json"
    roster = ["b", "a", "c", "d", "e"]
    path.write_text(
        _endpoints_payload(roster, [{"name": "x", "sites": dict.fromkeys(roster, site)}])
    )
    clusters, _ = load_endpoints(path)
    assert list(clusters[0].sites) == roster
    assert cluster_roster(clusters) == tuple(roster)
    path.write_text(
        _endpoints_payload(roster, [{"name": "x", "sites": dict.fromkeys(roster[:4], site)}])
    )
    with pytest.raises(ControllerError, match="exactly the sites"):
        load_endpoints(path)
    path.write_text(
        _endpoints_payload(roster, [{"name": "x", "sites": dict.fromkeys([*roster, "z"], site)}])
    )
    with pytest.raises(ControllerError, match="exactly the sites"):
        load_endpoints(path)
    path.write_text(_endpoints_payload(["a", "b"], [{"name": "x", "sites": {}}]))
    with pytest.raises(ControllerError, match="at least 3"):
        load_endpoints(path)
    path.write_text(_endpoints_payload(["a", "b", "c-d"], [{"name": "x", "sites": {}}]))
    with pytest.raises(ControllerError, match="site alias"):
        load_endpoints(path)
    path.write_text(
        _endpoints_payload(
            roster, [{"name": "x", "sites": {**dict.fromkeys(roster, site), "a": {"peer_ip": 1}}}]
        )
    )
    with pytest.raises(ControllerError, match="cluster 'x'"):
        load_endpoints(path)
    path.write_text(_endpoints_payload(None, [{"name": "x", "sites": dict.fromkeys(roster, site)}]))
    with pytest.raises(ControllerError, match="exactly the sites \\['s1', 's2', 's3'\\]"):
        load_endpoints(path)
    first = {"name": "x", "sites": dict.fromkeys(roster, site)}
    second = {"name": "y", "sites": dict.fromkeys(reversed(roster), site)}
    path.write_text(_endpoints_payload(roster, [first, second]))
    clusters, _ = load_endpoints(path)
    assert list(clusters[1].sites) == roster


def test_example_seven_site_endpoints_file_loads(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LETS_E1_TOKEN", "x" * 20)
    clusters, token = load_endpoints(EXAMPLE)
    assert token == "x" * 20 and cluster_roster(clusters) == SEVEN
    assert clusters[0].name == "seven-site"
    assert all(endpoint.fault_exec_quote for endpoint in clusters[0].sites.values())
    assert clusters[0].sites["apse1"].raft_address == "203.0.113.17:9801"
    assert default_systems(SEVEN)[0] == "central-noretry@uk2"
    assert default_topologies(SEVEN) == (
        "isolate-uk1",
        "halves",
        "full-isolation",
        "flapping-uk1-uk2",
    )


def test_parse_shares() -> None:
    assert parse_shares(None, SEVEN, 30) is None
    values = [f"{site}={units}" for site, units in zip(SEVEN, (9, 6, 3, 3, 3, 3, 3), strict=True)]
    assert parse_shares(values, SEVEN, 30) == dict(zip(SEVEN, (9, 6, 3, 3, 3, 3, 3), strict=True))
    with pytest.raises(ControllerError, match="SITE=UNITS"):
        parse_shares(["uk1"], SEVEN, 30)
    with pytest.raises(ControllerError, match="SITE=UNITS"):
        parse_shares(["uk1=many"], SEVEN, 30)
    with pytest.raises(ControllerError, match="sum to the envelope"):
        parse_shares(values, SEVEN, 31)
    with pytest.raises(ControllerError, match="exactly the sites"):
        parse_shares(values[:-1], SEVEN, 27)


def test_verify_safety_flags_duplicates_and_overflow() -> None:
    def site(effects: list[str], authorized: int) -> dict[str, object]:
        return {
            "effects": {"lets": {"count": len(effects), "request_ids": effects}},
            "messages": {"lets": 0, "static-quota": 0},
            "records": [{"system": "lets", "outcome": "authorized"}] * authorized,
        }

    good = verify_safety(3, {"s1": site(["r1", "r2"], 2), "s2": site(["r3"], 1)})
    assert good["lets"]["safety_ok"] is True and good["lets"]["safety_margin"] == 0
    assert good["static-quota"]["effects"] == 0
    duplicate = verify_safety(3, {"s1": site(["r1"], 1), "s2": site(["r1"], 1)})
    assert duplicate["lets"]["safety_ok"] is False and duplicate["lets"]["duplicate_effects"] == 1
    overflow = verify_safety(1, {"s1": site(["r1", "r2"], 2)})
    assert overflow["lets"]["safety_ok"] is False and overflow["lets"]["safety_margin"] == -1
    mismatch = verify_safety(5, {"s1": site(["r1"], 2)})
    assert mismatch["lets"]["safety_ok"] is False


def _options() -> GridOptions:
    return GridOptions(
        systems=(
            "central-noretry@s2",
            "central-retry@s3",
            "static-quota",
            "raft-quorum",
            "lets",
            "lets-tree-d2-f2",
        ),
        envelope=9,
        pre_s=0.5,
        partition_s=1.0,
        post_s=0.5,
        deadline_s=1.0,
        rtt_ms=0.0,
        loss_pct=0.0,
        peer_timeout_s=1.0,
        raft_timeout_s=1.0,
    )


def test_run_config_carries_grid_options() -> None:
    config = run_config(Cell("flapping-s1-s2", 0.7, 0.5, 4, "equal"), _options())
    assert config.run_id == "flapping-s1-s2-L0.7-T0.5-equal-S004"
    assert config.extra == {"rtt_ms": 0.0, "loss_pct": 0.0}
    assert config.systems[0] == "central-noretry@s2"
    assert config.sites == ("s1", "s2", "s3") and config.explicit_shares is None
    shares = dict(zip(FIVE_SITES, (5, 1, 1, 1, 1), strict=True))
    options = GridOptions(
        systems=("static-quota", "lets"),
        envelope=9,
        pre_s=0.5,
        partition_s=1.0,
        post_s=0.5,
        deadline_s=1.0,
        rtt_ms=0.0,
        loss_pct=0.0,
        sites=FIVE_SITES,
        shares=shares,
    )
    config = run_config(Cell("isolate-uk1", 0.7, 0.5, 4, "explicit"), options)
    assert config.sites == FIVE_SITES and config.shares == shares
    assert config.resolved_topology().cut_links == frozenset(
        frozenset({"uk1", other}) for other in FIVE_SITES[1:]
    )


def test_grid_runs_on_loopback_agents_and_renders_everything(
    loopback_cluster: LoopbackCluster, tmp_path: Path
) -> None:
    endpoints_path = tmp_path / "endpoints.json"
    endpoints_path.write_text(json.dumps(loopback_cluster.endpoints()))
    clusters, token = load_endpoints(endpoints_path)
    output = tmp_path / "out"
    cells = grid_cells(["bridge-s3", "flapping-s1-s2"], [2.0], [1.0], [1], ["equal"])
    driver = DryRunFaultDriver()
    log = (tmp_path / "log.txt").open("w", encoding="utf-8")
    outcome = run_grid(clusters, token, cells, _options(), output, driver=driver, log=log)
    log.close()
    assert outcome["skipped"] == 0
    assert outcome["outcomes"] == {cell.run_id: "passed" for cell in cells}
    assert outcome["assembled"]["runs"] == 2
    kinds = [command for _, command in driver.commands]
    assert any("netem" in command or "qdisc del" in command for command in kinds)
    assert any("-j DROP" in command for command in kinds)
    assert any("-F" in command for command in kinds)
    run_payload = read_run(run_path(output, cells[0].run_id))
    assert run_path(output, cells[0].run_id).suffix == ".gz"
    assert run_payload["status"] == "passed"
    assert all(verdict["safety_ok"] for verdict in run_payload["safety"].values())
    assert run_payload["faults"] and run_payload["faults"][0]["kind"] == "cut"
    assert "probes_during_cut" in run_payload["drop_counters"]
    assert all(probe["reachable"] for probe in run_payload["probes_before"])
    flapping = read_run(run_path(output, cells[1].run_id))
    assert sum(1 for fault in flapping["faults"] if fault["kind"] == "heal") >= 2
    summary = summarize(run_payload)
    assert set(summary) == set(_options().systems)
    with (output / "runs.csv").open(encoding="utf-8") as stream:
        runs_rows = list(csv.DictReader(stream))
    assert len(runs_rows) == 2 * len(_options().systems)
    assert all(row["safety_ok"] == "True" for row in runs_rows)
    with (output / "messages.csv").open(encoding="utf-8") as stream:
        assert len(list(csv.DictReader(stream))) == 2 * 3 * len(_options().systems)
    rerun = run_grid(clusters, token, cells, _options(), output, driver=driver, log=log)
    assert rerun["skipped"] == 2 and rerun["outcomes"] == {}
    write_manifest(output, ["test"], {"note": "unit"})
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["note"] == "unit" and manifest["files"]
    assert analysis.main(["--output", str(output)]) == 0
    table = (output / "per-site.md").read_text(encoding="utf-8")
    assert "| bridge-s3 |" in table and "| flapping-s1-s2 |" in table
    with (output / "per-site.csv").open(encoding="utf-8") as stream:
        per_site = list(csv.DictReader(stream))
    assert len(per_site) == 2 * len(_options().systems) * 3
    assert all(float(row["messages_per_run"]) >= 0 for row in per_site)
    with (output / "delegation.csv").open(encoding="utf-8") as stream:
        delegation = list(csv.DictReader(stream))
    assert {row["system"] for row in delegation} == {"lets", "lets-tree-d2-f2"}
    assert {row["topology"] for row in delegation} == {"bridge-s3", "flapping-s1-s2"}
    tree_rows = [row for row in delegation if row["system"] == "lets-tree-d2-f2"]
    assert all(row["depth"] == "2" and float(row["leases_per_tree"]) >= 3 for row in tree_rows)
    assert all(float(row["lease_ops_per_run"]) >= 9 for row in tree_rows)
    assert "lease-tree build costs" in (output / "delegation.md").read_text(encoding="utf-8")
    tree_safety = [row for row in runs_rows if row["system"] == "lets-tree-d2-f2"]
    assert len(tree_safety) == 2 and all(row["safety_ok"] == "True" for row in tree_safety)
    assert main(["assemble", "--output", str(output)]) == 0


def _five_options() -> GridOptions:
    return GridOptions(
        systems=("central-noretry@uk2", "central-retry@az1", "static-quota", "raft-quorum", "lets"),
        envelope=10,
        pre_s=0.5,
        partition_s=1.0,
        post_s=0.5,
        deadline_s=1.0,
        rtt_ms=0.0,
        loss_pct=0.0,
        peer_timeout_s=1.0,
        raft_timeout_s=1.0,
        sites=FIVE_SITES,
    )


def test_grid_runs_on_five_loopback_agents(
    five_site_cluster: LoopbackCluster, tmp_path: Path
) -> None:
    endpoints_path = tmp_path / "endpoints.json"
    endpoints_path.write_text(json.dumps(five_site_cluster.endpoints()))
    clusters, token = load_endpoints(endpoints_path)
    assert cluster_roster(clusters) == FIVE_SITES
    output = tmp_path / "out"
    cells = grid_cells(["isolate-uk1", "halves"], [2.0], [1.0], [1], ["equal"], FIVE_SITES)
    driver = DryRunFaultDriver()
    with pytest.raises(ControllerError, match="do not match"):
        run_grid(clusters, token, cells, _options(), output, driver=driver)
    options = _five_options()
    log = (tmp_path / "log.txt").open("w", encoding="utf-8")
    outcome = run_grid(clusters, token, cells, options, output, driver=driver, log=log)
    log.close()
    assert outcome["outcomes"] == {cell.run_id: "passed" for cell in cells}
    isolate = read_run(run_path(output, cells[0].run_id))
    assert isolate["config"]["sites"] == list(FIVE_SITES)
    assert set(isolate["sites"]) == set(FIVE_SITES)
    configured = isolate["configured"]["uk1"]
    assert configured["sites"] == list(FIVE_SITES)
    assert configured["shares"] == {"uk1": 2, "uk2": 2, "az1": 2, "use2": 2, "apse1": 2}
    assert set(configured["site_demand"]) == set(FIVE_SITES)
    assert all(verdict["safety_ok"] for verdict in isolate["safety"].values())
    cut = [fault for fault in isolate["faults"] if fault["kind"] == "cut"]
    assert {fault["link"] for fault in cut} == {"apse1-uk1,az1-uk1,uk1-uk2,uk1-use2"}
    assert [fault["site"] for fault in cut] == list(FIVE_SITES)
    isolated = next(fault for fault in cut if fault["site"] == "uk1")
    assert isolated["command"].count("iptables -A LETS_E1") == 4 * 2
    assert all(
        fault["command"].count("iptables -A LETS_E1") == 2
        for fault in cut
        if fault["site"] != "uk1"
    )
    assert len(isolate["probes_before"]) == 5 * 4
    probes = isolate["drop_counters"]["probes_during_cut"]
    assert len(probes) == 5 * 4 and all(probe["reachable"] for probe in probes)
    halves = read_run(run_path(output, cells[1].run_id))
    halves_cut = {fault["link"] for fault in halves["faults"] if fault["kind"] == "cut"}
    assert halves_cut == {"apse1-az1,apse1-uk1,apse1-uk2,az1-use2,uk1-use2,uk2-use2"}
    with (output / "messages.csv").open(encoding="utf-8") as stream:
        assert len(list(csv.DictReader(stream))) == 2 * 5 * len(options.systems)
    assert analysis.main(["--output", str(output)]) == 0
    with (output / "per-site.csv").open(encoding="utf-8") as stream:
        per_site = list(csv.DictReader(stream))
    assert {row["site"] for row in per_site} == set(FIVE_SITES)
    assert {row["topology"] for row in per_site} == {"isolate-uk1", "halves"}
    assert all(row["share"] == "2" for row in per_site if row["system"] == "lets")


def test_grid_records_errors_from_unreachable_clusters(tmp_path: Path) -> None:
    endpoints_path = tmp_path / "endpoints.json"
    dead = {
        "control_url": "http://127.0.0.1:9",
        "peer_ip": "127.0.0.1",
        "peer_port": 9,
        "raft_port": 9,
        "fault_exec": ["dry"],
    }
    endpoints_path.write_text(
        json.dumps(
            {
                "token": "t" * 20,
                "clusters": [{"name": "dead", "sites": {s: dead for s in ("s1", "s2", "s3")}}],
            }
        )
    )
    clusters, token = load_endpoints(endpoints_path)
    cells = grid_cells(["split-s1"], [2.0], [0.0], [1], ["equal"])
    with pytest.raises(ControllerError, match="unreachable"):
        run_grid(clusters, token, cells, _options(), tmp_path / "out", driver=DryRunFaultDriver())


class _ProbeClient:
    def __init__(self, site: str, seen: list[tuple[str, str, int]]) -> None:
        self.site = site
        self.seen = seen

    def call(self, method: str, path: str, body: dict[str, str]) -> dict[str, object]:
        time.sleep(0.01)
        self.seen.append((self.site, body["target"], threading.get_ident()))
        return {"target": body["target"], "reachable": True, "latency_ns": 1}


def test_probe_links_queries_every_ordered_pair_concurrently() -> None:
    seen: list[tuple[str, str, int]] = []
    clients = {site: _ProbeClient(site, seen) for site in FIVE_SITES}
    probes = probe_links(clients, list(FIVE_SITES))
    assert [(p["source"], p["target"]) for p in probes] == [
        (s, t) for s in FIVE_SITES for t in FIVE_SITES if s != t
    ]
    assert len(seen) == 5 * 4 and len({thread for _, _, thread in seen}) > 1
    assert probe_links({}, list(FIVE_SITES)) == []


def test_main_assemble_on_empty_directory(tmp_path: Path) -> None:
    (tmp_path / "runs").mkdir()
    assert main(["assemble", "--output", str(tmp_path)]) == 0
    assert assemble(tmp_path)["runs"] == 0


def test_assemble_merges_run_history_and_recounts_outcomes(tmp_path: Path) -> None:
    output = tmp_path / "grid"
    (output / "runs").mkdir(parents=True)
    first = {
        "schema": "lets.fair-baselines-manifest/v1",
        "generated_at": "2026-10-16T07:19:20Z",
        "command": ["run", "--seeds", "20"],
        "source": {"commit": "aaaa"},
        "environment": {"python_version": "3.11"},
        "grid": {"cells": 480},
        "outcomes": {"x": "passed", "y": "failed", "z": "passed"},
    }
    second = {
        **first,
        "generated_at": "2026-10-16T09:48:00Z",
        "command": ["run", "--topologies", "flapping-s1-s2"],
        "source": {"commit": "bbbb"},
        "grid": {"cells": 120},
        "outcomes": {"y": "passed"},
    }
    (tmp_path / "first.json").write_text(json.dumps(first), encoding="utf-8")
    (output / "MANIFEST.json").write_text(json.dumps(second), encoding="utf-8")
    assert run_record({"command": ["assemble"]}) is None
    legacy = run_record(
        {
            "command": ["assemble"],
            "generated_at": "2026-10-16T09:48:33Z",
            "run_command": ["run", "--topologies", "flapping-s1-s2"],
            "run_source": {"commit": "bbbb"},
            "run_environment": {},
            "grid": {"cells": 120},
            "outcomes": {"y": "passed"},
        }
    )
    assert legacy is not None and legacy["command"][1] == "--topologies" and legacy["cells"] == 120
    assert merge_run_history([first, second, first])[0]["cells"] == 480
    (output / "runs" / "a-L0.7-T0-equal-S001.json").write_text(
        json.dumps({"run_id": "a-L0.7-T0-equal-S001", "status": "passed"}), encoding="utf-8"
    )
    assert run_outcomes(output) == {"a-L0.7-T0-equal-S001": "passed"}
    (output / "runs" / "a-L0.7-T0-equal-S001.json").unlink()
    command = [
        "assemble",
        "--output",
        str(output),
        "--merge-manifest",
        str(tmp_path / "first.json"),
    ]
    assert main(command) == 0
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["command"] == ["assemble"] and manifest["outcomes"] == {}
    assert manifest["grid"]["cells"] == 0
    assert manifest["run_command"] == ["run", "--topologies", "flapping-s1-s2"]
    history = manifest["run_history"]
    assert [entry["generated_at"] for entry in history] == [
        "2026-10-16T07:19:20Z",
        "2026-10-16T09:48:00Z",
    ]
    assert history[0]["outcomes"] == {"passed": 2, "failed": 1} and history[0]["cells"] == 480
    assert history[1]["source"] == {"commit": "bbbb"} and history[1]["cells"] == 120
    assert main(["assemble", "--output", str(output)]) == 0
    again = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert [entry["generated_at"] for entry in again["run_history"]] == [
        "2026-10-16T07:19:20Z",
        "2026-10-16T09:48:00Z",
    ]


def test_main_run_uses_dry_faults_and_records_cell_errors(
    loopback_cluster: LoopbackCluster, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoints_path = tmp_path / "endpoints.json"
    endpoints_path.write_text(json.dumps(loopback_cluster.endpoints()))
    output = tmp_path / "out"
    argv = [
        "run",
        "--endpoints",
        str(endpoints_path),
        "--output",
        str(output),
        "--topologies",
        "split-s1",
        "--loads",
        "2.0",
        "--thetas",
        "0",
        "--seeds",
        "1",
        "--systems",
        "static-quota",
        "lets",
        "--envelope",
        "6",
        "--pre-s",
        "0.3",
        "--partition-s",
        "0.6",
        "--post-s",
        "0.3",
        "--deadline-s",
        "0.5",
        "--rtt-ms",
        "0",
        "--dry-run-faults",
    ]
    monkeypatch.setenv("LETS_E1_TOKEN", loopback_cluster.token)
    assert main(argv) == 0
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["grid"]["cells"] == 1 and manifest["outcomes"] == {
        "split-s1-L2-T0-equal-S001": "passed"
    }
    assert manifest["command"] == argv

    from benchmarks.fair_baselines import controller as module

    def explode(self: object, cell: Cell) -> dict[str, object]:
        raise RuntimeError("boom")

    monkeypatch.setattr(module.CellRunner, "run_cell", explode)
    assert main([*argv, "--overwrite"]) == 1
    payload = read_run(run_path(output, "split-s1-L2-T0-equal-S001"))
    assert payload["status"] == "error" and "boom" in payload["failures"][0]
    with pytest.raises(ValueError, match="unknown system"):
        main(["run", "--endpoints", str(endpoints_path), "--output", str(output), "--systems", "x"])


def test_main_run_with_explicit_shares(
    loopback_cluster: LoopbackCluster, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    endpoints_path = tmp_path / "endpoints.json"
    endpoints_path.write_text(json.dumps(loopback_cluster.endpoints()))
    output = tmp_path / "out"
    monkeypatch.setenv("LETS_E1_TOKEN", loopback_cluster.token)
    base = [
        "run",
        "--endpoints",
        str(endpoints_path),
        "--output",
        str(output),
        "--topologies",
        "cut-s2-s3",
        "--loads",
        "1.0",
        "--thetas",
        "0",
        "--seeds",
        "1",
        "--systems",
        "static-quota",
        "lets",
        "--envelope",
        "6",
        "--pre-s",
        "0.3",
        "--partition-s",
        "0.6",
        "--post-s",
        "0.3",
        "--deadline-s",
        "0.5",
        "--rtt-ms",
        "0",
        "--dry-run-faults",
    ]
    with pytest.raises(ControllerError, match="go together"):
        main([*base, "--shares", "s1=3", "s2=2", "s3=1"])
    with pytest.raises(ControllerError, match="go together"):
        main([*base, "--placements", "explicit"])
    assert main([*base, "--placements", "explicit", "--shares", "s1=3", "s2=2", "s3=1"]) == 0
    payload = read_run(run_path(output, "cut-s2-s3-L1-T0-explicit-S001"))
    assert payload["configured"]["s1"]["shares"] == {"s1": 3, "s2": 2, "s3": 1}
    assert payload["config"]["explicit_shares"] == {"s1": 3, "s2": 2, "s3": 1}
    assert {fault["link"] for fault in payload["faults"]} == {"s2-s3"}
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["grid"]["sites"] == ["s1", "s2", "s3"]
