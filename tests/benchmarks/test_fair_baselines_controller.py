"""Tests for benchmarks/fair_baselines/controller.py plus analysis.py and figures.py on real
output: grid enumeration, endpoint loading, safety verification, a dry-fault grid run against
three loopback agents, CSV assembly, the per-site table, and figure rendering.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from benchmarks.fair_baselines import analysis, figures
from benchmarks.fair_baselines.controller import (
    Cell,
    ControllerError,
    GridOptions,
    assemble,
    grid_cells,
    load_endpoints,
    main,
    read_run,
    run_config,
    run_grid,
    run_path,
    summarize,
    verify_safety,
    write_manifest,
)
from benchmarks.fair_baselines.faults import DryRunFaultDriver
from tests.benchmarks.conftest import LoopbackCluster


def test_grid_cells_enumerate_and_name_runs() -> None:
    cells = grid_cells(["split-s1", "bridge-s3"], [0.7, 2.0], [0.0, 1.0], [1, 2], ["equal"])
    assert len(cells) == 16
    assert cells[0].run_id == "split-s1-L0.7-T0-equal-S001"
    assert len({cell.run_id for cell in cells}) == 16
    with pytest.raises(ControllerError, match="unknown topology"):
        grid_cells(["mesh"], [1.0], [0.0], [1], ["equal"])


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
        systems=("central-noretry@s2", "central-retry@s3", "static-quota", "raft-quorum", "lets"),
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
    assert figures.main(["--output", str(output), "--formats", "svg"]) == 0
    assert (output / "figures" / "cdf-panel-L2-T1.svg").exists()
    assert (output / "figures" / "cdf-flapping-L2-T1.svg").exists()
    assert (output / "figures" / "completions-T1.svg").exists()
    assert main(["assemble", "--output", str(output)]) == 0


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


def test_main_assemble_on_empty_directory(tmp_path: Path) -> None:
    (tmp_path / "runs").mkdir()
    assert main(["assemble", "--output", str(tmp_path)]) == 0
    assert assemble(tmp_path)["runs"] == 0


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
