"""Tests for benchmarks/fair_baselines/common.py and workload.py: system and topology catalogues,
Zipf placement arithmetic, run configuration validation, and the deterministic arrival plan.
"""

from __future__ import annotations

import pytest

from benchmarks.fair_baselines.common import (
    DEFAULT_SYSTEMS,
    LINKS,
    SITES,
    TOPOLOGIES,
    RunConfig,
    SystemSpec,
    integer,
    mapping,
    peer_mac,
    share_placement,
    site_list,
    string,
    zipf_weights,
)
from benchmarks.fair_baselines.workload import arrival_plan, site_demand


def _config(**overrides: object) -> RunConfig:
    payload: dict[str, object] = {
        "run_id": "unit",
        "topology": "split-s1",
        "load": 2.0,
        "theta": 1.0,
        "seed": 5,
        "placement": "equal",
        "envelope": 30,
        "systems": list(DEFAULT_SYSTEMS),
        "pre_s": 5.0,
        "partition_s": 30.0,
        "post_s": 15.0,
        "deadline_s": 20.0,
    }
    payload.update(overrides)
    return RunConfig.from_dict(payload)


def test_system_specs_parse_every_default_and_reject_unknown_names() -> None:
    kinds = {SystemSpec.parse(name).kind for name in DEFAULT_SYSTEMS}
    assert kinds == {"central", "static-quota", "raft-quorum", "lets"}
    noretry = SystemSpec.parse("central-noretry@s2")
    assert (noretry.retry, noretry.host) == (False, "s2")
    retry = SystemSpec.parse("central-retry@s3")
    assert (retry.retry, retry.host) == (True, "s3")
    assert SystemSpec.parse("lets").retry is True
    for bad in ("central-retry@s9", "central@s1", "raft", "", "lets@s1"):
        with pytest.raises(ValueError, match="unknown system"):
            SystemSpec.parse(bad)


def test_topologies_cut_the_documented_links_and_flap_on_a_period() -> None:
    assert TOPOLOGIES["split-s1"].cut_links == frozenset({LINKS[0], LINKS[1]})
    assert TOPOLOGIES["bridge-s3"].cut_links == frozenset({LINKS[0]})
    assert TOPOLOGIES["full-isolation"].cut_links == frozenset(LINKS)
    flapping = TOPOLOGIES["flapping-s1-s2"]
    assert flapping.flap_period_s == 3.0
    link = frozenset({"s1", "s2"})
    assert flapping.link_is_cut(link, 5.0, 5.0) is True
    assert flapping.link_is_cut(link, 8.5, 5.0) is False
    assert flapping.link_is_cut(link, 11.0, 5.0) is True
    assert flapping.link_is_cut(frozenset({"s2", "s3"}), 6.0, 5.0) is False
    assert TOPOLOGIES["bridge-s3"].link_is_cut(link, 100.0, 5.0) is True


def test_zipf_weights_and_share_placement() -> None:
    assert zipf_weights(0.0) == (1 / 3, 1 / 3, 1 / 3)
    skewed = zipf_weights(1.0)
    assert skewed[0] > skewed[1] > skewed[2]
    assert abs(sum(skewed) - 1.0) < 1e-12
    with pytest.raises(ValueError):
        zipf_weights(-0.5)
    assert share_placement("equal", 30, 1.0) == {"s1": 10, "s2": 10, "s3": 10}
    proportional = share_placement("proportional", 30, 1.0)
    assert sum(proportional.values()) == 30
    assert proportional["s1"] > proportional["s2"] > proportional["s3"] >= 1
    assert sum(share_placement("equal", 31, 0.0).values()) == 31
    with pytest.raises(ValueError, match="unknown placement"):
        share_placement("random", 30, 0.0)
    with pytest.raises(ValueError, match="at least one unit"):
        share_placement("equal", 2, 0.0)


def test_run_config_round_trips_and_validates() -> None:
    config = _config()
    assert config.arrival_window_s == 50.0
    assert config.shares == {"s1": 10, "s2": 10, "s3": 10}
    assert RunConfig.from_dict(config.to_dict()) == config
    with pytest.raises(ValueError, match="unknown topology"):
        _config(topology="ring")
    with pytest.raises(ValueError, match="unknown system"):
        _config(systems=["lets", "mystery"])
    with pytest.raises(ValueError, match="positive"):
        _config(load=0.0)
    with pytest.raises(ValueError, match="non-negative"):
        _config(pre_s=-1.0)
    with pytest.raises(ValueError, match="arrival window"):
        _config(pre_s=0.0, partition_s=0.0, post_s=0.0)


def test_payload_helpers_reject_wrong_shapes() -> None:
    assert mapping({"a": 1}, "x") == {"a": 1}
    with pytest.raises(ValueError, match="must be an object"):
        mapping([], "x")
    assert integer(3, "n") == 3
    for bad in (True, -1, "3"):
        with pytest.raises(ValueError, match="integer"):
            integer(bad, "n")
    assert string("ok", "s") == "ok"
    for bad in ("", "a\x00b", 7):
        with pytest.raises(ValueError, match="non-empty string"):
            string(bad, "s")
    assert site_list(["s1", "s3"], "sites") == ("s1", "s3")
    with pytest.raises(ValueError, match="unknown sites"):
        site_list(["s1", "s4"], "sites")
    with pytest.raises(ValueError, match="list of site"):
        site_list("s1", "sites")
    mac = peer_mac("token", "/peer/ping", "1", "n", "b", "s1")
    assert mac == peer_mac("token", "/peer/ping", "1", "n", "b", "s1")
    assert mac != peer_mac("token", "/peer/ping", "1", "n", "b", "s2")


def test_arrival_plan_is_deterministic_rate_matched_and_skewed() -> None:
    config = _config()
    plan = arrival_plan(config)
    assert plan == arrival_plan(config)
    assert plan != arrival_plan(_config(seed=6))
    assert all(0 <= arrival.offset_ns < 50_000_000_000 for arrival in plan)
    assert [arrival.index for arrival in plan] == list(range(len(plan)))
    assert plan[0].request_id == "r00000"
    assert all(arrival.site in SITES for arrival in plan)
    totals = dict.fromkeys(SITES, 0)
    count = 0
    for seed in range(1, 41):
        demand = site_demand(arrival_plan(_config(seed=seed)))
        count += sum(demand.values())
        for site in SITES:
            totals[site] += demand[site]
    assert 40 * 60 * 0.85 < count < 40 * 60 * 1.15
    assert 0.48 < totals["s1"] / count < 0.61
    assert 0.13 < totals["s3"] / count < 0.24
    uniform = site_demand(arrival_plan(_config(theta=0.0, load=0.7)))
    assert sum(uniform.values()) > 0
