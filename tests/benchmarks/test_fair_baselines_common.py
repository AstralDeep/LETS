"""Tests for benchmarks/fair_baselines/common.py and workload.py: the site roster and what derives
from it (links, parametric topologies, Zipf placement, shares) for the default three sites and a
seven-site roster, run configuration validation, and the deterministic arrival plan.
"""

from __future__ import annotations

import hashlib
import itertools

import pytest

from benchmarks.fair_baselines.common import (
    DEFAULT_SITES,
    DEFAULT_SYSTEMS,
    LEGACY_TOPOLOGIES,
    LINKS,
    SITES,
    TOPOLOGIES,
    RunConfig,
    SystemSpec,
    default_systems,
    default_topologies,
    integer,
    is_flapping,
    mapping,
    peer_mac,
    resolve_topology,
    share_placement,
    site_alias,
    site_links,
    site_list,
    site_roster,
    string,
    topology_catalogue,
    topology_order,
    validate_shares,
    zipf_weights,
)
from benchmarks.fair_baselines.workload import arrival_plan, site_demand

SEVEN = ("uk1", "uk2", "az1", "use2", "usw2", "euw2", "apse1")
GOLDEN_PLAN_SHA256 = "c5d541575e887f0358b2810c17a8cf797f44d3c34e32a78b3ca4cfd1ac9a0283"


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


def _seven_config(**overrides: object) -> RunConfig:
    payload: dict[str, object] = {
        "sites": list(SEVEN),
        "topology": "isolate-uk1",
        "systems": list(default_systems(SEVEN)),
    }
    payload.update(overrides)
    return _config(**payload)


def test_system_specs_parse_every_default_and_reject_unknown_names() -> None:
    kinds = {SystemSpec.parse(name).kind for name in DEFAULT_SYSTEMS}
    assert kinds == {"central", "static-quota", "raft-quorum", "lets"}
    noretry = SystemSpec.parse("central-noretry@s2")
    assert (noretry.retry, noretry.host) == (False, "s2")
    retry = SystemSpec.parse("central-retry@s3")
    assert (retry.retry, retry.host) == (True, "s3")
    assert SystemSpec.parse("lets").retry is True
    for bad in ("central-retry@s-9", "central@s1", "raft", "", "lets@s1", "central-retry@"):
        with pytest.raises(ValueError, match="unknown system"):
            SystemSpec.parse(bad)
    assert SystemSpec.parse("central-retry@use2", SEVEN).host == "use2"
    with pytest.raises(ValueError, match="unknown system"):
        SystemSpec.parse("central-retry@s1", SEVEN)
    assert default_systems(DEFAULT_SITES) == DEFAULT_SYSTEMS
    assert default_systems(SEVEN) == (
        "central-noretry@uk2",
        *(f"central-retry@{site}" for site in SEVEN),
        "static-quota",
        "raft-quorum",
        "lets",
    )


def test_site_roster_and_alias_validation() -> None:
    assert SITES == DEFAULT_SITES == ("s1", "s2", "s3")
    assert site_roster(list(SEVEN)) == SEVEN
    assert site_alias("aws_use2", "x") == "aws_use2"
    for bad in ("us-east-2", "", "a" * 33, "s 1", 7, "s1\n"):
        with pytest.raises(ValueError, match="site alias"):
            site_alias(bad, "x")
    with pytest.raises(ValueError, match="at least 3"):
        site_roster(["a", "b"])
    with pytest.raises(ValueError, match="repeats"):
        site_roster(["a", "b", "a"])
    with pytest.raises(ValueError, match="list of site"):
        site_roster("abc")
    with pytest.raises(ValueError, match="site alias"):
        site_roster(["a", "b", "c-d"])


def test_links_follow_the_roster() -> None:
    assert site_links(DEFAULT_SITES) == LINKS
    assert (frozenset({"s1", "s2"}), frozenset({"s1", "s3"}), frozenset({"s2", "s3"})) == LINKS
    seven = site_links(SEVEN)
    assert len(seven) == 21 and len(set(seven)) == 21
    assert all(len(link) == 2 and link <= set(SEVEN) for link in seven)
    assert len(site_links(("a", "b", "c", "d", "e"))) == 10


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
    assert tuple(TOPOLOGIES)[:4] == LEGACY_TOPOLOGIES == default_topologies(DEFAULT_SITES)
    assert TOPOLOGIES["isolate-s1"].cut_links == TOPOLOGIES["split-s1"].cut_links
    assert TOPOLOGIES["cut-s1-s2"].cut_links == TOPOLOGIES["bridge-s3"].cut_links
    assert TOPOLOGIES["halves"].cut_links == frozenset({LINKS[1], LINKS[2]})
    assert resolve_topology("cut-s2-s3").cut_links == frozenset({LINKS[2]})
    assert resolve_topology("flapping-s3-s1").cut_links == frozenset({LINKS[1]})


def test_parametric_topologies_for_seven_sites() -> None:
    links = set(site_links(SEVEN))
    isolate = resolve_topology("isolate-use2", SEVEN)
    assert len(isolate.cut_links) == 6 and all("use2" in link for link in isolate.cut_links)
    assert isolate.flap_period_s is None
    halves = resolve_topology("halves", SEVEN)
    head = {"uk1", "uk2", "az1", "use2"}
    assert len(halves.cut_links) == 12
    assert all(len(link & head) == 1 for link in halves.cut_links)
    assert resolve_topology("full-isolation", SEVEN).cut_links == frozenset(links)
    cut = resolve_topology("cut-uk1-apse1", SEVEN)
    assert cut.cut_links == frozenset({frozenset({"uk1", "apse1"})})
    flapping = resolve_topology("flapping-euw2-usw2", SEVEN)
    assert flapping.cut_links == frozenset({frozenset({"euw2", "usw2"})})
    assert flapping.flap_period_s == 3.0 and is_flapping("flapping-euw2-usw2")
    assert not is_flapping("isolate-uk1")
    assert (
        resolve_topology("split-az1", SEVEN).cut_links
        == resolve_topology("isolate-az1", SEVEN).cut_links
    )
    for bad in (
        "split-s1",
        "bridge-s3",
        "bridge-uk1",
        "isolate-nowhere",
        "cut-uk1-uk1",
        "cut-uk1",
        "flapping-uk1-s1",
        "ring",
        "",
    ):
        with pytest.raises(ValueError, match="unknown topology"):
            resolve_topology(bad, SEVEN)
    assert default_topologies(SEVEN) == (
        "isolate-uk1",
        "halves",
        "full-isolation",
        "flapping-uk1-uk2",
    )
    catalogue = topology_catalogue(SEVEN)
    assert list(catalogue)[:4] == list(default_topologies(SEVEN))
    assert {f"isolate-{site}" for site in SEVEN} <= set(catalogue)
    assert "cut-uk1-uk2" in catalogue
    assert topology_order(["full-isolation", "flapping-uk1-uk2", "halves", "isolate-uk1"]) == [
        "isolate-uk1",
        "halves",
        "full-isolation",
        "flapping-uk1-uk2",
    ]
    assert topology_order(["full-isolation", "bridge-s3", "split-s1", "split-s1"]) == [
        "split-s1",
        "bridge-s3",
        "full-isolation",
    ]


def test_zipf_weights_and_share_placement() -> None:
    assert zipf_weights(0.0) == (1 / 3, 1 / 3, 1 / 3)
    skewed = zipf_weights(1.0)
    assert skewed[0] > skewed[1] > skewed[2]
    assert abs(sum(skewed) - 1.0) < 1e-12
    with pytest.raises(ValueError):
        zipf_weights(-0.5)
    assert share_placement("equal", 30, 1.0) == {"s1": 10, "s2": 10, "s3": 10}
    proportional = share_placement("proportional", 30, 1.0)
    assert proportional == {"s1": 17, "s2": 8, "s3": 5}
    assert sum(share_placement("equal", 31, 0.0).values()) == 31
    with pytest.raises(ValueError, match="unknown placement"):
        share_placement("random", 30, 0.0)
    with pytest.raises(ValueError, match="at least one unit"):
        share_placement("equal", 2, 0.0)


def test_share_placement_for_seven_sites() -> None:
    seven = zipf_weights(1.0, 7)
    assert len(seven) == 7 and all(a > b for a, b in itertools.pairwise(seven))
    equal = share_placement("equal", 30, 1.0, SEVEN)
    assert list(equal) == list(SEVEN)
    assert list(equal.values()) == [5, 5, 4, 4, 4, 4, 4]
    assert list(share_placement("equal", 35, 0.0, SEVEN).values()) == [5] * 7
    proportional = share_placement("proportional", 30, 1.0, SEVEN)
    assert sum(proportional.values()) == 30
    assert proportional["uk1"] > proportional["uk2"] > proportional["apse1"] >= 1
    with pytest.raises(ValueError, match="at least one unit"):
        share_placement("equal", 6, 0.0, SEVEN)
    explicit = dict(zip(SEVEN, (9, 6, 3, 3, 3, 3, 3), strict=True))
    assert share_placement("explicit", 30, 0.0, SEVEN, explicit) == explicit
    assert validate_shares(explicit, SEVEN, 30) == explicit
    with pytest.raises(ValueError, match="needs a shares mapping"):
        share_placement("explicit", 30, 0.0, SEVEN)
    with pytest.raises(ValueError, match="exactly the sites"):
        validate_shares({**explicit, "extra": 1}, SEVEN, 31)
    with pytest.raises(ValueError, match="exactly the sites"):
        validate_shares({site: 5 for site in SEVEN[:-1]}, SEVEN, 30)
    with pytest.raises(ValueError, match="sum to the envelope"):
        validate_shares({**explicit, "uk1": 8}, SEVEN, 30)
    with pytest.raises(ValueError, match="integer >= 1"):
        validate_shares({**explicit, "uk1": 0}, SEVEN, 21)
    with pytest.raises(ValueError, match="must be an object"):
        validate_shares([1, 2, 3], SEVEN, 30)


def test_run_config_round_trips_and_validates() -> None:
    config = _config()
    assert config.arrival_window_s == 50.0
    assert config.sites == DEFAULT_SITES
    assert config.shares == {"s1": 10, "s2": 10, "s3": 10}
    assert config.resolved_topology() == TOPOLOGIES["split-s1"]
    assert config.to_dict()["sites"] == ["s1", "s2", "s3"]
    assert RunConfig.from_dict(config.to_dict()) == config
    with pytest.raises(ValueError, match="unknown topology"):
        _config(topology="ring")
    with pytest.raises(ValueError, match="unknown system"):
        _config(systems=["lets", "mystery"])
    with pytest.raises(ValueError, match="positive"):
        _config(load=0.0)
    with pytest.raises(ValueError, match="positive"):
        _config(envelope=0)
    with pytest.raises(ValueError, match="non-negative"):
        _config(pre_s=-1.0)
    with pytest.raises(ValueError, match="arrival window"):
        _config(pre_s=0.0, partition_s=0.0, post_s=0.0)
    with pytest.raises(ValueError, match="unknown placement"):
        _config(placement="random")
    with pytest.raises(ValueError, match="at least one unit"):
        _config(envelope=2)


def test_run_config_carries_a_seven_site_roster_and_explicit_shares() -> None:
    config = _seven_config()
    assert config.sites == SEVEN
    assert config.shares == dict(zip(SEVEN, (5, 5, 4, 4, 4, 4, 4), strict=True))
    assert config.resolved_topology().cut_links == resolve_topology("isolate-uk1", SEVEN).cut_links
    assert RunConfig.from_dict(config.to_dict()) == config
    explicit = dict(zip(SEVEN, (9, 6, 3, 3, 3, 3, 3), strict=True))
    chosen = _seven_config(placement="explicit", explicit_shares=explicit)
    assert chosen.shares == explicit and chosen.explicit_shares == explicit
    assert RunConfig.from_dict(chosen.to_dict()) == chosen
    with pytest.raises(ValueError, match="requires the explicit placement"):
        _seven_config(placement="equal", explicit_shares=explicit)
    with pytest.raises(ValueError, match="needs a shares mapping"):
        _seven_config(placement="explicit")
    with pytest.raises(ValueError, match="sum to the envelope"):
        _seven_config(placement="explicit", explicit_shares={**explicit, "uk1": 1})
    with pytest.raises(ValueError, match="unknown topology"):
        _seven_config(topology="split-s1")
    with pytest.raises(ValueError, match="unknown system"):
        _seven_config(systems=["central-retry@s1"])
    with pytest.raises(ValueError, match="at least 3"):
        _config(sites=["a", "b"], topology="full-isolation", systems=["lets"])
    with pytest.raises(ValueError, match="site alias"):
        _config(sites=["a", "b", "c-d"], topology="full-isolation", systems=["lets"])


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
    assert site_list(["use2", "uk1"], "sites", SEVEN) == ("use2", "uk1")
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
    digest = hashlib.sha256(
        "\n".join(f"{a.index},{a.site},{a.offset_ns}" for a in plan).encode()
    ).hexdigest()
    assert len(plan) == 54 and digest == GOLDEN_PLAN_SHA256
    assert site_demand(plan, SITES) == {"s1": 30, "s2": 11, "s3": 13}
    totals = dict.fromkeys(SITES, 0)
    count = 0
    for seed in range(1, 41):
        demand = site_demand(arrival_plan(_config(seed=seed)), SITES)
        count += sum(demand.values())
        for site in SITES:
            totals[site] += demand[site]
    assert 40 * 60 * 0.85 < count < 40 * 60 * 1.15
    assert 0.48 < totals["s1"] / count < 0.61
    assert 0.13 < totals["s3"] / count < 0.24
    uniform = site_demand(arrival_plan(_config(theta=0.0, load=0.7)), SITES)
    assert sum(uniform.values()) > 0


def test_arrival_plan_splits_seven_sites_in_roster_order() -> None:
    totals = dict.fromkeys(SEVEN, 0)
    count = 0
    for seed in range(1, 41):
        plan = arrival_plan(_seven_config(seed=seed))
        assert all(arrival.site in SEVEN for arrival in plan)
        demand = site_demand(plan, SEVEN)
        assert list(demand) == list(SEVEN)
        count += len(plan)
        for site in SEVEN:
            totals[site] += demand[site]
    assert 40 * 60 * 0.85 < count < 40 * 60 * 1.15
    expected = zipf_weights(1.0, 7)
    assert abs(totals["uk1"] / count - expected[0]) < 0.06
    assert abs(totals["apse1"] / count - expected[6]) < 0.04
    assert totals["uk1"] > totals["uk2"] > totals["apse1"] > 0
    flat = site_demand(arrival_plan(_seven_config(theta=0.0, seed=9)), SEVEN)
    assert set(flat) == set(SEVEN)
