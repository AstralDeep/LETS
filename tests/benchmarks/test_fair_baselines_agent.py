"""Tests for benchmarks/fair_baselines/site_agent.py: a three-agent loopback run through every
system with safety verification, the LETS delegation tree refreshing from mid-run transfers,
anchored LETS with scheduled stale restores, roster checks in the configure payload, the control
and peer API denials, and the CLI entry point.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
import urllib.request
from pathlib import Path

import pytest

from benchmarks.fair_baselines.common import SITES, peer_mac
from benchmarks.fair_baselines.controller import verify_safety
from benchmarks.fair_baselines.site_agent import AgentError, AgentState, anchor_settings, main
from tests.benchmarks.conftest import TOKEN, LoopbackCluster, short_config


def _assert_lets_conserved(snapshots: dict[str, dict], envelope: int, effects: int) -> None:
    transferred_in = sum(int(snapshot["transferred_in"]) for snapshot in snapshots.values())
    transferred_out = sum(int(snapshot["transferred_out"]) for snapshot in snapshots.values())
    in_flight = transferred_out - transferred_in
    held = sum(
        int(snapshot["free_pool"]) + int(snapshot["lease_residual"]) + int(snapshot["consumed"])
        for snapshot in snapshots.values()
    )
    assert in_flight >= 0
    if in_flight:
        assert sum(int(snapshot["outstanding_vouchers"]) for snapshot in snapshots.values()) >= 1
    assert held + in_flight == envelope
    assert sum(int(snapshot["consumed"]) for snapshot in snapshots.values()) == effects


def _run_to_completion(cluster: LoopbackCluster, config: dict[str, object]) -> dict[str, dict]:
    for site in SITES:
        status, payload = cluster.call(
            site, "POST", "/run/configure", cluster.configure_body(site, config)
        )
        assert status == 200, payload
        assert payload["configured"] is True
        assert payload["plan_size"] == sum(payload["site_demand"].values())
    deadline = time.monotonic() + 30
    while True:
        statuses = [cluster.call(site, "GET", "/run/status")[1] for site in SITES]
        if all(status["ready"] for status in statuses):
            break
        assert time.monotonic() < deadline, statuses
        time.sleep(0.1)
    start_at = time.time_ns() + 300_000_000
    for site in SITES:
        status, payload = cluster.call(site, "POST", "/run/start", {"start_at_epoch_ns": start_at})
        assert status == 200 and payload == {"started": True}
    status, payload = cluster.call("s1", "GET", "/run/results")
    assert status == 409 and "not done" in str(payload["error"])
    deadline = time.monotonic() + 60
    while True:
        statuses = [cluster.call(site, "GET", "/run/status")[1] for site in SITES]
        if all(status["status"] == "done" for status in statuses):
            break
        assert time.monotonic() < deadline, statuses
        time.sleep(0.2)
    results = {}
    for site in SITES:
        status, payload = cluster.call(site, "GET", "/run/results")
        assert status == 200
        results[site] = payload
    return results


def test_three_agents_run_every_system_within_the_envelope(
    loopback_cluster: LoopbackCluster,
) -> None:
    cluster = loopback_cluster
    config = short_config("agent-run")
    results = _run_to_completion(cluster, config)
    systems = set(config["systems"])  # type: ignore[arg-type]
    plan_size = results["s1"]["plan_size"]
    assert plan_size > 0
    total_records = sum(len(payload["records"]) for payload in results.values())
    assert total_records == plan_size * len(systems)
    for payload in results.values():
        assert set(payload["snapshots"]) == systems
        assert payload["end_offset_ns"] > 0
        for record in payload["records"]:
            assert record["outcome"] in {"authorized", "denied", "timeout"}
            assert record["attempts"] >= 1
            if record["outcome"] == "authorized":
                assert record["t_auth_ns"] >= 0
            else:
                assert record["t_auth_ns"] is None
        kinds = {event["kind"] for event in payload["events"]}
        assert {"waiting", "free"} <= kinds
    safety = verify_safety(int(config["envelope"]), results)  # type: ignore[arg-type]
    assert set(safety) == systems
    for system, verdict in safety.items():
        assert verdict["safety_ok"] is True, (system, verdict)
        assert verdict["effects"] == verdict["authorized_records"]
    lets = {site: payload["snapshots"]["lets"] for site, payload in results.items()}
    assert all(snapshot["healthy"] for snapshot in lets.values())
    _assert_lets_conserved(lets, int(config["envelope"]), safety["lets"]["effects"])  # type: ignore[arg-type]
    noretry = [
        record
        for payload in results.values()
        for record in payload["records"]
        if record["system"] == "central-noretry@s2"
    ]
    assert all(record["attempts"] == 1 for record in noretry)
    for site in SITES:
        status, payload = cluster.call(site, "POST", "/run/teardown")
        assert status == 200 and payload["torn_down"] is True
    status, payload = cluster.call("s1", "POST", "/run/teardown")
    assert status == 200 and payload == {"torn_down": False}


def test_control_api_denies_bad_tokens_paths_and_states(
    loopback_cluster: LoopbackCluster,
) -> None:
    cluster = loopback_cluster
    assert cluster.call("s1", "GET", "/health", token="nope")[0] == 401
    assert cluster.call("s1", "POST", "/run/teardown", token="nope")[0] == 401
    assert cluster.call("s1", "GET", "/nothing")[0] == 404
    assert cluster.call("s1", "POST", "/nothing", {})[0] == 404
    status, payload = cluster.call("s1", "GET", "/health")
    assert status == 200 and payload["site"] == "s1" and payload["run_id"] is None
    assert cluster.call("s1", "GET", "/run/status")[0] == 409
    assert cluster.call("s1", "POST", "/run/start", {"start_at_epoch_ns": 1})[0] == 400
    assert cluster.call("s1", "POST", "/probe/peer", {"target": "s2"})[0] == 400
    assert cluster.call("s1", "POST", "/probe/peer", {"target": "s1"})[0] == 400
    config = short_config("agent-deny", systems=["static-quota"])
    body = cluster.configure_body("s1", config)
    status, payload = cluster.call("s1", "POST", "/run/configure", body)
    assert status == 200, payload
    status, payload = cluster.call("s1", "POST", "/run/configure", body)
    assert status == 400 and "already configured" in payload["error"]
    status, payload = cluster.call("s1", "GET", "/health")
    assert payload["run_id"] == "agent-deny"
    status, payload = cluster.call("s1", "POST", "/probe/peer", {"target": "s2"})
    assert status == 200 and payload["reachable"] is True and payload["latency_ns"] > 0
    status, payload = cluster.call("s1", "POST", "/run/start", {"start_at_epoch_ns": "soon"})
    assert status == 400
    bad_peers = dict(body)
    bad_peers["peers"] = {"s2": body["peers"]["s2"]}  # type: ignore[index]
    cluster.call("s1", "POST", "/run/teardown")
    status, payload = cluster.call("s1", "POST", "/run/configure", bad_peers)
    assert status == 400 and "exactly the other sites" in payload["error"]
    foreign = dict(body)
    foreign["config"] = {**config, "sites": ["a1", "b2", "c3"], "topology": "isolate-a1"}
    status, payload = cluster.call("s1", "POST", "/run/configure", foreign)
    assert status == 400 and "not in the run's sites" in payload["error"]
    wider = dict(body)
    wider["config"] = {**config, "sites": ["s1", "s2", "s3", "s4"], "topology": "full-isolation"}
    status, payload = cluster.call("s1", "POST", "/run/configure", wider)
    assert status == 400 and "exactly the other sites" in payload["error"]
    bad_keys = dict(body)
    bad_keys["keys"] = {**body["keys"], "public_keys": {"s1": cluster.public_keys["s1"]}}  # type: ignore[dict-item]
    status, payload = cluster.call("s1", "POST", "/run/configure", bad_keys)
    assert status == 400 and "public_keys must name exactly" in payload["error"]
    bad_run = dict(body)
    bad_run["config"] = {**config, "run_id": "../escape"}
    status, payload = cluster.call("s1", "POST", "/run/configure", bad_run)
    assert status == 400 and "safe path" in payload["error"]
    bad_raft = dict(body)
    bad_raft["config"] = {**config, "systems": ["raft-quorum"]}
    bad_raft["raft"] = {}
    status, payload = cluster.call("s1", "POST", "/run/configure", bad_raft)
    assert status == 400 and "raft addresses" in payload["error"]
    request = urllib.request.Request(
        f"{cluster.control_url('s1')}/run/configure",
        data=b"{not json",
        method="POST",
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request, timeout=5)
    assert excinfo.value.code == 400


def _peer_post(
    cluster: LoopbackCluster,
    target: str,
    path: str,
    body: dict[str, object],
    *,
    alias: str = "s2",
    token: str = TOKEN,
    timestamp: str | None = None,
    nonce: str | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    timestamp = timestamp or str(int(time.time()))
    nonce = nonce or secrets.token_hex(32)
    digest = hashlib.sha256(raw).hexdigest()
    signature = peer_mac(token, path, timestamp, nonce, digest, alias)
    request = urllib.request.Request(
        f"{cluster.control_url(target)}{path}",
        data=raw,
        method="POST",
        headers={
            "Authorization": f"LETS-HMAC {signature}",
            "Content-Type": "application/json",
            "X-LETS-Peer-Alias": alias,
            "X-LETS-Timestamp": timestamp,
            "X-LETS-Nonce": nonce,
            "X-LETS-Body-SHA256": digest,
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_peer_api_verifies_hmac_timestamp_nonce_and_routes(
    loopback_cluster: LoopbackCluster,
) -> None:
    cluster = loopback_cluster
    status, payload = _peer_post(cluster, "s1", "/peer/ping", {})
    assert status == 200 and payload == {"pong": True, "site": "s1"}
    assert _peer_post(cluster, "s1", "/peer/ping", {}, token="other-token-0123")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, alias="s1")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, alias="s-9")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, alias="")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, timestamp="nope")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, timestamp="100")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, nonce="short")[0] == 401
    nonce = secrets.token_hex(32)
    assert _peer_post(cluster, "s1", "/peer/ping", {}, nonce=nonce)[0] == 200
    assert _peer_post(cluster, "s1", "/peer/ping", {}, nonce=nonce)[0] == 401
    assert (
        _peer_post(cluster, "s1", "/peer/ping", {}, headers={"Authorization": "Basic x"})[0] == 401
    )
    assert (
        _peer_post(cluster, "s1", "/peer/ping", {}, headers={"X-LETS-Body-SHA256": "0" * 64})[0]
        == 401
    )
    assert _peer_post(cluster, "s1", "/peer/central/x/take", {"request_id": "r"})[0] == 400
    config = short_config("agent-peer", systems=["central-retry@s1", "lets", "static-quota"])
    status, payload = cluster.call(
        "s1", "POST", "/run/configure", cluster.configure_body("s1", config)
    )
    assert status == 200, payload
    assert _peer_post(cluster, "s1", "/peer/ping", {}, alias="s9")[0] == 401
    assert _peer_post(cluster, "s1", "/peer/ping", {}, alias="s3")[0] == 200
    status, payload = _peer_post(
        cluster, "s1", "/peer/central/central-retry@s1/take", {"request_id": "r1"}
    )
    assert status == 200 and payload["authorized"] is True
    assert _peer_post(cluster, "s1", "/peer/central/lets/take", {"request_id": "r1"})[0] == 400
    assert _peer_post(cluster, "s1", "/peer/lets/lets/request-transfer", {"amount": 0})[0] == 400
    status, payload = _peer_post(cluster, "s1", "/peer/lets/lets/request-transfer", {"amount": 2})
    assert status == 200 and payload["granted"] == 2
    assert _peer_post(cluster, "s1", "/peer/lets/lets/finalize", {"ack": {}})[0] == 400
    assert _peer_post(cluster, "s1", "/peer/lets/static-quota/finalize", {"ack": {}})[0] == 400
    assert _peer_post(cluster, "s1", "/peer/other/lets/finalize", {})[0] == 400
    assert _peer_post(cluster, "s1", "/peer/lets", {})[0] == 400
    cluster.call("s1", "POST", "/run/teardown")


def test_agent_state_rejects_unknown_site_and_main_requires_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(AgentError, match="site alias"):
        AgentState("s-4", TOKEN, tmp_path)
    assert AgentState("apse1", TOKEN, tmp_path).site == "apse1"
    monkeypatch.delenv("LETS_E1_TOKEN", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["site_agent", "--site", "s1", "--port", "1", "--state-root", str(tmp_path)],
    )
    with pytest.raises(SystemExit, match="at least 16 characters"):
        main()
    monkeypatch.setenv("LETS_E1_TOKEN", TOKEN)
    monkeypatch.setattr(
        "sys.argv",
        ["site_agent", "--site", "us-east-2", "--port", "1", "--state-root", str(tmp_path)],
    )
    with pytest.raises(SystemExit):
        main()


def test_main_serves_until_shutdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from benchmarks.fair_baselines import site_agent

    monkeypatch.setenv("LETS_E1_TOKEN", TOKEN)
    monkeypatch.setattr(
        "sys.argv",
        ["site_agent", "--site", "s2", "--port", "0", "--state-root", str(tmp_path / "state")],
    )
    monkeypatch.setattr(site_agent.AgentServer, "serve_forever", lambda self, poll_interval: None)
    assert main() == 0
    assert (tmp_path / "state").is_dir()


def _tree_counters(results: dict[str, dict]) -> dict[str, tuple[int, int, int]]:
    return {
        site: (
            payload["snapshots"]["lets-tree-d2-f2"]["tree_builds"],
            payload["snapshots"]["lets-tree-d2-f2"]["transfers_in"],
            payload["snapshots"]["lets-tree-d2-f2"]["transfers_out"],
        )
        for site, payload in results.items()
    }


def _settled_results(cluster: LoopbackCluster, results: dict[str, dict]) -> dict[str, dict]:
    deadline = time.monotonic() + 30
    stable_since = time.monotonic()
    while True:
        time.sleep(0.3)
        again = {site: cluster.call(site, "GET", "/run/results")[1] for site in SITES}
        if _tree_counters(again) != _tree_counters(results):
            stable_since = time.monotonic()
            results = again
        elif time.monotonic() - stable_since >= 1.5:
            return again
        assert time.monotonic() < deadline, _tree_counters(again)


def test_three_agents_run_lets_with_and_without_delegation_trees(
    loopback_cluster: LoopbackCluster,
) -> None:
    cluster = loopback_cluster
    shares = {"s1": 1, "s2": 7, "s3": 1}
    config = short_config(
        "agent-tree",
        systems=["lets", "lets-tree-d2-f2"],
        placement="explicit",
        explicit_shares=shares,
    )
    results = _settled_results(cluster, _run_to_completion(cluster, config))
    envelope = int(config["envelope"])  # type: ignore[arg-type]
    safety = verify_safety(envelope, results)
    assert set(safety) == {"lets", "lets-tree-d2-f2"}
    for system, verdict in safety.items():
        assert verdict["safety_ok"] is True, (system, verdict)
        assert 1 <= verdict["effects"] == verdict["authorized_records"] <= envelope
    trees = {site: payload["snapshots"]["lets-tree-d2-f2"] for site, payload in results.items()}
    plain = {site: payload["snapshots"]["lets"] for site, payload in results.items()}
    reasons = {
        site: [
            event["detail"].split(" ", 1)[0]
            for event in payload["events"]
            if event["kind"] == "tree_build" and event["system"] == "lets-tree-d2-f2"
        ]
        for site, payload in results.items()
    }
    for site in SITES:
        assert trees[site]["healthy"] and plain[site]["healthy"]
        assert (trees[site]["tree_depth"], trees[site]["tree_fanout"]) == (2, 2)
        assert plain[site]["tree_depth"] == 0 and plain[site]["live_leases"] <= 1
        initial_leases = {1: 3, 7: 7}[shares[site]]
        assert trees[site]["lease_operations"] >= initial_leases + trees[site]["tree_builds"] - 1
        assert trees[site]["lease_operations"] >= trees[site]["live_leases"]
        assert plain[site]["lease_operations"] >= plain[site]["tree_builds"]
        assert reasons[site][0] == "initial" and len(reasons[site]) == trees[site]["tree_builds"]
        assert all(reason.startswith(("in-", "out-")) for reason in reasons[site][1:])
        assert (
            trees[site]["tree_builds"]
            == 1 + trees[site]["transfers_in"] + trees[site]["transfers_out"]
        )
    _assert_lets_conserved(trees, envelope, safety["lets-tree-d2-f2"]["effects"])
    _assert_lets_conserved(plain, envelope, safety["lets"]["effects"])
    builds = [
        event
        for payload in results.values()
        for event in payload["events"]
        if event["kind"] == "tree_build"
    ]
    assert {event["system"] for event in builds} == {"lets", "lets-tree-d2-f2"}
    for event in builds:
        assert event["value"] >= 1 and " us=" in event["detail"]
    holder = next(
        (
            site
            for site in SITES
            if trees[site]["remaining"] > 0 and trees[site]["outstanding_vouchers"] == 0
        ),
        None,
    )
    if holder is not None:
        requester = next(site for site in SITES if site != holder)
        deadline = time.monotonic() + 10
        before = trees[holder]
        while before["pending_acks"]:
            assert time.monotonic() < deadline, before
            time.sleep(0.2)
            before = cluster.call(holder, "GET", "/run/results")[1]["snapshots"]["lets-tree-d2-f2"]
        status, payload = _peer_post(
            cluster,
            holder,
            "/peer/lets/lets-tree-d2-f2/request-transfer",
            {"amount": 1},
            alias=requester,
        )
        assert status == 200 and payload["granted"] == 1
        assert isinstance(payload["voucher"], dict)
        _, after = cluster.call(holder, "GET", "/run/results")
        snapshot = after["snapshots"]["lets-tree-d2-f2"]
        assert snapshot["tree_builds"] == before["tree_builds"] + 1 and snapshot["healthy"]
        assert snapshot["remaining"] == before["remaining"] - 1
        assert snapshot["transfers_out"] == before["transfers_out"] + 1
        last = [
            event
            for event in after["events"]
            if event["kind"] == "tree_build" and event["system"] == "lets-tree-d2-f2"
        ][-1]
        assert last["detail"].startswith(f"out-{requester}-")
    for site in SITES:
        cluster.call(site, "POST", "/run/teardown")


def test_anchored_agents_refuse_a_stale_restore_that_unanchored_lets_accepts(
    anchored_cluster: LoopbackCluster, tmp_path: Path
) -> None:
    systems = ["lets-anchored", "lets-anchored-restore@s1", "lets-restore@s1"]
    config = short_config(
        "agent-anchored",
        systems=systems,
        envelope=30,
        placement="explicit",
        explicit_shares={"s1": 20, "s2": 5, "s3": 5},
        partition_s=3.0,
    )
    results = _run_to_completion(anchored_cluster, config)
    restores = {
        site: [
            (event["system"], event["kind"], event["detail"])
            for event in payload["events"]
            if event["kind"].startswith("restore_")
        ]
        for site, payload in results.items()
    }
    assert restores["s2"] == [] and restores["s3"] == []
    outcomes = {
        system: [(kind, detail) for name, kind, detail in restores["s1"] if name == system]
        for system in ("lets-anchored-restore@s1", "lets-restore@s1")
    }
    for system, events in outcomes.items():
        assert len(events) == 2 and events[0][0] == "restore_snapshot", (system, events)
    snapshots = results["s1"]["snapshots"]
    assert outcomes["lets-restore@s1"][1][0] == "restore_accepted"
    assert snapshots["lets-restore@s1"]["healthy"] is True
    kind, detail = outcomes["lets-anchored-restore@s1"][1]
    revisions = dict(token.split("=", 1) for token in detail.split()[:3])
    stale = int(revisions["revision_before"]) > int(revisions["snapshot_revision"])
    assert kind == ("restore_refused" if stale else "restore_accepted"), detail
    assert ("StorageError" in detail) is stale
    assert snapshots["lets-anchored-restore@s1"]["healthy"] is not stale
    assert snapshots["lets-anchored"]["anchored"] is True
    assert snapshots["lets-anchored"]["restore_refused"] is None
    safety = verify_safety(int(config["envelope"]), results)  # type: ignore[arg-type]
    assert safety["lets-anchored"]["safety_ok"] is True
    assert safety["lets-anchored-restore@s1"]["safety_ok"] is True
    late = [
        record
        for record in results["s1"]["records"]
        if record["system"] == "lets-anchored-restore@s1"
        and record["reason"] == "stale_state_refused"
    ]
    assert all(record["outcome"] == "denied" for record in late)
    anchors = sorted(path.name for path in (tmp_path / "anchors" / "s1").glob("*.anchor"))
    assert len(anchors) == 4


def test_anchored_systems_need_an_anchor_root(loopback_cluster: LoopbackCluster) -> None:
    config = short_config("agent-unanchored-host", systems=["lets-anchored"])
    status, payload = loopback_cluster.call(
        "s1", "POST", "/run/configure", loopback_cluster.configure_body("s1", config)
    )
    assert status == 400 and "--anchor-root" in str(payload["error"])


def test_anchor_settings_parse_the_helper_command(tmp_path: Path) -> None:
    assert anchor_settings(None, "", 5.0) is None
    with pytest.raises(SystemExit, match="--anchor-root"):
        anchor_settings(None, "sudo -n -u lets-anchor python", 5.0)
    settings = anchor_settings(tmp_path, "sudo -n -u 'lets anchor' python -m x", 2.5)
    assert settings is not None
    assert settings.helper == ("sudo", "-n", "-u", "lets anchor", "python", "-m", "x")
    assert (settings.root, settings.timeout_s) == (tmp_path, 2.5)
