"""Tests for benchmarks/fair_baselines/analysis.py and local_cluster.py on synthetic data:
bootstrap intervals, censored CDFs, link-state reconstruction, stranded-capacity integration per
system kind for three and seven sites, table rendering, the lease-tree build cost table, and the
compose/endpoints documents for any roster.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.fair_baselines import local_cluster
from benchmarks.fair_baselines.analysis import (
    LinkState,
    RequestRow,
    authorization_cdf,
    bootstrap_ci,
    completion_by_seed,
    delegation_markdown,
    delegation_rows,
    link_states,
    per_site_csv,
    per_site_markdown,
    per_site_rows,
    quantile,
    stranded_capacity,
    summary_rows,
    topology_description,
    tree_builds,
)

SEVEN = ("uk1", "uk2", "az1", "use2", "usw2", "euw2", "apse1")


def _row(
    system: str, site: str, outcome: str, t_auth_ns: int | None, seed: int = 1, **kw: object
) -> RequestRow:
    return RequestRow(
        run_id=f"split-s1-L2-T1-equal-S{seed:03d}",
        topology="split-s1",
        load=2.0,
        theta=1.0,
        seed=seed,
        placement="equal",
        system=system,
        site=site,
        outcome=outcome,
        arrival_offset_ns=0,
        t_auth_ns=t_auth_ns,
        deadline_ns=2_000_000_000,
        messages=1,
        **kw,  # type: ignore[arg-type]
    )


def test_bootstrap_quantile_and_cdf() -> None:
    mean, low, high = bootstrap_ci([0.5, 0.7, 0.9, 1.0], resamples=500)
    assert low <= mean <= high and abs(mean - 0.775) < 1e-9
    assert bootstrap_ci([0.4]) == (0.4, 0.4, 0.4)
    with pytest.raises(ValueError):
        bootstrap_ci([])
    assert quantile([], 0.5) is None
    assert quantile([3.0, 1.0, 2.0], 0.5) == 2.0
    assert quantile([3.0, 1.0, 2.0], 0.95) == 3.0
    rows = [
        _row("lets", "s1", "authorized", 100_000_000),
        _row("lets", "s1", "authorized", 300_000_000),
        _row("lets", "s1", "timeout", None),
        _row("lets", "s1", "denied", None),
    ]
    xs, ys = authorization_cdf(rows)
    assert xs == [0.0, 0.1, 0.3] and ys == [0.0, 0.25, 0.5]
    assert authorization_cdf([]) == ([], [])
    by_seed = completion_by_seed([*rows, _row("lets", "s2", "authorized", 1, seed=2)])
    assert by_seed[(("split-s1", 2.0, 1.0, "equal"), "lets")] == [0.5, 1.0]


def test_link_states_follow_cut_and_heal_offsets() -> None:
    faults = [
        {"run_id": "r", "kind": "cut", "link": "s1-s2,s1-s3", "returned_offset_s": "5.0"},
        {"run_id": "r", "kind": "heal", "link": "s1-s2,s1-s3", "returned_offset_s": "35.0"},
        {"run_id": "r", "kind": "cut", "link": "s1-s2", "returned_offset_s": "40.0"},
        {"run_id": "r", "kind": "probe", "link": "", "returned_offset_s": "41.0"},
    ]
    state = link_states(faults)["r"]
    link = frozenset({"s1", "s2"})
    assert state.link_up(link, 4.9) and not state.link_up(link, 5.0)
    assert not state.link_up(frozenset({"s1", "s3"}), 20.0)
    assert state.link_up(frozenset({"s2", "s3"}), 20.0)
    assert state.link_up(link, 35.0) and not state.link_up(link, 50.0)


def _events(system: str, entries: list[tuple[str, float, str, int]]) -> list[dict[str, str]]:
    return [
        {
            "run_id": "r",
            "system": system,
            "site": site,
            "offset_ns": str(int(offset * 1e9)),
            "kind": kind,
            "value": str(value),
            "detail": "",
        }
        for site, offset, kind, value in entries
    ]


def test_stranded_capacity_per_system_kind() -> None:
    cut = LinkState([(5.0, 15.0, frozenset({"s1", "s2"})), (5.0, 15.0, frozenset({"s1", "s3"}))])
    shares = {"s1": 10, "s2": 10, "s3": 10}
    static = stranded_capacity(
        "static-quota",
        _events("static-quota", [("s1", 6.0, "waiting", 1), ("s1", 8.0, "waiting", 0)]),
        cut,
        shares,
        30,
        20.0,
    )
    assert static.peak_units == 20 and abs(static.unit_seconds - 40.0) < 1e-6
    lets_open = stranded_capacity(
        "lets",
        _events("lets", [("s1", 16.0, "waiting", 1), ("s1", 17.0, "waiting", 0)]),
        cut,
        shares,
        30,
        20.0,
    )
    assert lets_open.peak_units == 0
    lets_cut = stranded_capacity(
        "lets",
        _events(
            "lets", [("s1", 6.0, "waiting", 1), ("s2", 7.0, "free", 4), ("s1", 8.0, "waiting", 0)]
        ),
        cut,
        shares,
        30,
        20.0,
    )
    assert lets_cut.peak_units == 20 and lets_cut.unit_seconds < 40.0
    central = stranded_capacity(
        "central-retry@s2",
        _events(
            "central-retry@s2",
            [("s2", 1.0, "free", 7), ("s1", 6.0, "waiting", 2), ("s1", 8.0, "waiting", 0)],
        ),
        cut,
        shares,
        30,
        20.0,
    )
    assert central.peak_units == 7
    reachable = stranded_capacity(
        "central-retry@s3",
        _events("central-retry@s3", [("s2", 6.0, "waiting", 2), ("s2", 8.0, "waiting", 0)]),
        cut,
        shares,
        30,
        20.0,
    )
    assert reachable.peak_units == 0
    raft = stranded_capacity(
        "raft-quorum",
        _events("raft-quorum", [("s1", 6.0, "waiting", 1), ("s1", 8.0, "waiting", 0)]),
        cut,
        shares,
        30,
        20.0,
    )
    assert raft.peak_units == 30
    quorum = stranded_capacity(
        "raft-quorum",
        _events("raft-quorum", [("s2", 6.0, "waiting", 1), ("s2", 8.0, "waiting", 0)]),
        cut,
        shares,
        30,
        20.0,
    )
    assert quorum.peak_units == 0
    assert stranded_capacity("lets", [], cut, shares, 30, 0.0).unit_seconds == 0.0


def test_stranded_capacity_for_seven_sites() -> None:
    shares = dict(zip(SEVEN, (5, 5, 4, 4, 4, 4, 4), strict=True))
    isolate = LinkState(
        [(5.0, 15.0, frozenset({"use2", other})) for other in SEVEN if other != "use2"]
    )
    waiting = _events("lets", [("use2", 6.0, "waiting", 1), ("use2", 8.0, "waiting", 0)])
    lets = stranded_capacity("lets", waiting, isolate, shares, 30, 20.0, sites=SEVEN)
    assert lets.peak_units == 26 and abs(lets.unit_seconds - 52.0) < 1e-6
    raft = stranded_capacity(
        "raft-quorum",
        _events("raft-quorum", [("use2", 6.0, "waiting", 1), ("use2", 8.0, "waiting", 0)]),
        isolate,
        shares,
        30,
        20.0,
        sites=SEVEN,
    )
    assert raft.peak_units == 30
    quorum = stranded_capacity(
        "raft-quorum",
        _events("raft-quorum", [("uk1", 6.0, "waiting", 1), ("uk1", 8.0, "waiting", 0)]),
        isolate,
        shares,
        30,
        20.0,
        sites=SEVEN,
    )
    assert quorum.peak_units == 0
    halves = LinkState([(5.0, 15.0, link) for link in resolve_halves()])
    minority = stranded_capacity(
        "raft-quorum",
        _events("raft-quorum", [("apse1", 6.0, "waiting", 1), ("apse1", 8.0, "waiting", 0)]),
        halves,
        shares,
        30,
        20.0,
        sites=SEVEN,
    )
    assert minority.peak_units == 30
    majority = stranded_capacity(
        "raft-quorum",
        _events("raft-quorum", [("uk1", 6.0, "waiting", 1), ("uk1", 8.0, "waiting", 0)]),
        halves,
        shares,
        30,
        20.0,
        sites=SEVEN,
    )
    assert majority.peak_units == 0
    central = stranded_capacity(
        "central-retry@uk2",
        _events("central-retry@uk2", [("use2", 6.0, "waiting", 1), ("use2", 8.0, "waiting", 0)]),
        isolate,
        shares,
        30,
        20.0,
        sites=SEVEN,
    )
    assert central.peak_units == 30
    static = _events("static-quota", [("use2", 6.0, "waiting", 1), ("use2", 8.0, "waiting", 0)])
    derived = stranded_capacity("static-quota", static, isolate, shares, 30, 20.0)
    assert derived.peak_units == 26
    assert topology_description("halves", SEVEN).startswith("halves: cut apse1-az1, apse1-uk1")
    assert "intact apse1-euw2" in topology_description("halves", SEVEN)
    assert topology_description("isolate-uk1", SEVEN).startswith("isolate-uk1: cut ")
    assert "toggle every 3 s" in topology_description("flapping-uk1-apse1", SEVEN)


def resolve_halves() -> frozenset[frozenset[str]]:
    from benchmarks.fair_baselines.common import resolve_topology

    return resolve_topology("halves", SEVEN).cut_links


def test_per_site_table_and_summary_render() -> None:
    requests = [
        _row("lets", "s1", "authorized", 50_000_000, seed=1),
        _row("lets", "s1", "timeout", None, seed=1),
        _row("lets", "s2", "authorized", 60_000_000, seed=1),
        _row("lets", "s1", "authorized", 70_000_000, seed=2),
        _row("lets", "s2", "denied", None, seed=2),
        _row("static-quota", "s1", "authorized", 1_000_000, seed=1),
        _row("static-quota", "s1", "authorized", 1_000_000, seed=2),
    ]
    runs = [
        {
            "run_id": "split-s1-L2-T1-equal-S001",
            "envelope": "30",
            "shares": json.dumps({"s1": 10, "s2": 10, "s3": 10}),
        },
        {
            "run_id": "split-s1-L2-T1-equal-S002",
            "envelope": "30",
            "shares": json.dumps({"s1": 10, "s2": 10, "s3": 10}),
        },
    ]
    messages = [
        {"run_id": "split-s1-L2-T1-equal-S001", "system": "lets", "site": "s1", "messages": "4"},
        {"run_id": "split-s1-L2-T1-equal-S002", "system": "lets", "site": "s1", "messages": "6"},
    ]
    table = per_site_rows(requests, [], [], runs, messages)
    assert len(table) == 3
    lets_s1 = next(row for row in table if row["system"] == "lets" and row["site"] == "s1")
    assert lets_s1["seeds"] == 2 and lets_s1["share"] == 10
    assert lets_s1["requests_per_run"] == 1.5 and lets_s1["messages_per_run"] == 5.0
    assert lets_s1["completion_mean"] == 0.75
    assert lets_s1["t_auth_p50_s"] == 0.05
    markdown = per_site_markdown(table, "Title")
    assert markdown.startswith("# Title") and "| split-s1 | 2 | 1 | lets | s1 | 10 |" in markdown
    assert per_site_csv(table).splitlines()[0].startswith("topology,load,theta")
    assert per_site_csv([]) == ""
    summary = summary_rows(table)
    assert [row["system"] for row in summary] == ["lets", "static-quota"]
    assert summary[0]["requests_per_run"] == 2.5
    assert topology_description("bridge-s3") == "bridge-s3: cut s1-s2; intact s1-s3, s2-s3"
    assert "toggle every 3 s" in topology_description("flapping-s1-s2")


def test_local_cluster_documents_and_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    compose = local_cluster.compose_document(2, "tok", "img")
    services = compose["services"]
    assert isinstance(services, dict) and len(services) == 6
    s1 = services["lets-e1-1-s1"]
    assert isinstance(s1, dict)
    assert s1["cap_add"] == ["NET_ADMIN"]
    assert s1["networks"] == {"cluster1": {"ipv4_address": "10.231.1.11"}}
    assert s1["ports"] == ["127.0.0.1:9711:9701"]
    assert s1["environment"] == {"LETS_E1_TOKEN": "tok"}
    endpoints = local_cluster.endpoints_document(2, "tok")
    clusters = endpoints["clusters"]
    assert endpoints["sites"] == ["s1", "s2", "s3"]
    assert isinstance(clusters, list) and clusters[1]["sites"]["s3"]["peer_ip"] == "10.231.1.13"
    seven = local_cluster.compose_document(2, "tok", "img", SEVEN)
    seven_services = seven["services"]
    assert isinstance(seven_services, dict) and len(seven_services) == 14
    apse1 = seven_services["lets-e1-1-apse1"]
    assert isinstance(apse1, dict)
    assert apse1["networks"] == {"cluster1": {"ipv4_address": "10.231.1.17"}}
    assert apse1["ports"] == ["127.0.0.1:9717:9701"]
    assert apse1["command"][:2] == ["--site", "apse1"]
    seven_endpoints = local_cluster.endpoints_document(2, "tok", SEVEN)
    assert seven_endpoints["sites"] == list(SEVEN)
    seven_clusters = seven_endpoints["clusters"]
    assert isinstance(seven_clusters, list)
    assert list(seven_clusters[0]["sites"]) == list(SEVEN)
    assert seven_clusters[1]["sites"]["use2"]["control_url"] == "http://127.0.0.1:9714"
    assert seven_clusters[1]["sites"]["use2"]["fault_exec"][2] == "lets-e1-1-use2"
    ten = tuple(f"site{index}" for index in range(10))
    assert local_cluster.control_port(1, "site9", ten) == 9700 + 11 + 1 + 9
    assert local_cluster.control_port(0, "site9", ten) == 9710
    assert clusters[0]["sites"]["s2"]["fault_exec"] == [
        "docker",
        "exec",
        "lets-e1-0-s2",
        "sh",
        "-c",
    ]
    with pytest.raises(RuntimeError, match="never became healthy"):
        local_cluster.wait_healthy(
            {
                "token": "tok",
                "clusters": [
                    {
                        "name": "x",
                        "sites": {
                            "s1": {"control_url": "http://127.0.0.1:9"},
                            "s2": {"control_url": "http://127.0.0.1:9"},
                            "s3": {"control_url": "http://127.0.0.1:9"},
                        },
                    }
                ],
            },
            timeout_s=0.5,
        )
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(local_cluster, "_compose", lambda work_dir, *args, **kw: calls.append(args))
    monkeypatch.setattr(local_cluster, "wait_healthy", lambda endpoints: None)
    assert local_cluster.main(["up", "--work-dir", str(tmp_path / "w"), "--clusters", "2"]) == 0
    assert (tmp_path / "w" / "compose.yaml").exists() and (
        tmp_path / "w" / "endpoints.json"
    ).exists()
    assert calls[-1] == ("up", "-d", "--remove-orphans", "--build")
    assert local_cluster.main(["up", "--work-dir", str(tmp_path / "w"), "--no-build"]) == 0
    assert calls[-1] == ("up", "-d", "--remove-orphans")
    assert (
        local_cluster.main(
            ["up", "--work-dir", str(tmp_path / "w"), "--no-build", "--sites", *SEVEN]
        )
        == 0
    )
    written = json.loads((tmp_path / "w" / "endpoints.json").read_text(encoding="utf-8"))
    assert written["sites"] == list(SEVEN) and len(written["clusters"]) == 3
    with pytest.raises(SystemExit, match="at least 3"):
        local_cluster.main(["up", "--work-dir", str(tmp_path), "--no-build", "--sites", "a", "b"])
    with pytest.raises(SystemExit, match="site alias"):
        local_cluster.main(
            ["up", "--work-dir", str(tmp_path), "--no-build", "--sites", "a", "b", "c-d"]
        )
    assert local_cluster.main(["down", "--work-dir", str(tmp_path / "w")]) == 0
    assert calls[-1][0] == "down"
    assert local_cluster.main(["down", "--work-dir", str(tmp_path / "missing")]) == 0
    with pytest.raises(SystemExit, match="between 1 and 20"):
        local_cluster.main(["up", "--work-dir", str(tmp_path), "--clusters", "0"])


def _build_event(
    run_id: str, system: str, site: str, offset_s: float, value: int, detail: str
) -> dict[str, str]:
    return {
        "run_id": run_id,
        "system": system,
        "site": site,
        "offset_ns": str(int(offset_s * 1e9)),
        "kind": "tree_build",
        "value": str(value),
        "detail": detail,
    }


def test_tree_builds_and_delegation_rows() -> None:
    tree = "lets-tree-d2-f2"
    events = [
        _build_event("r1", tree, "s1", 0.1, 7, "initial leases=7 leaves=4 us=45000"),
        _build_event("r1", tree, "s2", 0.1, 7, "initial leases=7 leaves=4 us=40000"),
        _build_event("r1", tree, "s3", 0.1, 7, "initial leases=7 leaves=4 us=41000"),
        _build_event("r1", tree, "s1", 8.0, 14, "in-1 leases=7 leaves=4 us=90000"),
        _build_event("r1", tree, "s2", 8.0, 14, "out-s1-1 leases=7 leaves=4 us=80000"),
        _build_event("r2", tree, "s1", 0.1, 7, "initial leases=7 leaves=4 us=47000"),
        _build_event("r2", tree, "s2", 0.1, 7, "initial leases=7 leaves=4 us=42000"),
        _build_event("r2", tree, "s3", 0.1, 7, "initial leases=7 leaves=4 us=43000"),
        _build_event("r2", tree, "s3", 9.0, 3, "out-s1-1 leases=0 leaves=0 us=20000"),
        _build_event("r1", "lets", "s1", 0.1, 1, "initial leases=1 leaves=1 us=7000"),
        _build_event("r1", "lets", "s1", 8.0, 2, "in-1 leases=1 leaves=1 us=14000"),
        _build_event("r9", tree, "s1", 0.1, 7, "initial leases=7 leaves=4 us=45000"),
        {**_build_event("r1", tree, "s1", 1.0, 1, "x"), "kind": "free"},
    ]
    parsed = tree_builds(events)
    assert len(parsed) == 12
    assert parsed[3].refresh and not parsed[0].refresh
    assert parsed[3].operations == 14 and parsed[3].leaves == 4 and parsed[3].seconds == 0.09
    assert parsed[3].offset_s == 8.0 and parsed[3].site == "s1"
    assert tree_builds([]) == []
    runs = [
        {
            "run_id": run_id,
            "topology": "split-s1",
            "load": "0.7",
            "theta": "1",
            "placement": "equal",
        }
        for run_id in ("r1", "r2")
    ]
    table = delegation_rows(events, runs)
    assert [row["system"] for row in table] == ["lets", tree]
    row = table[1]
    assert (row["depth"], row["fanout"], row["runs"]) == (2, 2, 2)
    assert row["leases_per_tree"] == 7.0 and row["leaves_per_tree"] == 4.0
    assert row["initial_ops_per_site"] == 7.0
    assert row["initial_ms_p50"] == 42.0
    assert row["refreshes_per_run"] == 1.5
    assert abs(row["refresh_ops_mean"] - 31 / 3) < 1e-9
    assert row["refresh_ms_p50"] == 80.0 and row["refresh_ms_p95"] == 90.0
    assert row["refresh_ms_max"] == 90.0
    assert row["lease_ops_per_run"] == (7 * 6 + 14 + 14 + 3) / 2
    assert abs(row["build_ms_per_run"] - 448 / 2) < 1e-9
    plain = table[0]
    assert (plain["depth"], plain["fanout"], plain["runs"]) == (0, 0, 1)
    assert plain["leases_per_tree"] == 1.0 and plain["refreshes_per_run"] == 1.0
    assert plain["refresh_ops_mean"] == 2.0 and plain["refresh_ms_p50"] == 14.0
    markdown = delegation_markdown(table, "Trees")
    assert markdown.startswith("# Trees")
    assert "| split-s1 | 0.7 | 1 | lets-tree-d2-f2 | 2 | 2 | 2 |" in markdown
    assert "| 80.0 / 90.0 / 90.0 |" in markdown
    assert delegation_rows(events, []) == []
    empty = delegation_rows(
        [_build_event("r1", tree, "s1", 0.1, 7, "initial leases=7 leaves=4 us=45000")], runs
    )
    assert empty[0]["refresh_ops_mean"] is None and empty[0]["refresh_ms_p50"] is None
    assert "| n/a |" not in delegation_markdown(empty, "T")
    assert "| — / — / — |" in delegation_markdown(empty, "T")
