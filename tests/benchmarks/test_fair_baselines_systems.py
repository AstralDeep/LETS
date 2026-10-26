"""Tests for benchmarks/fair_baselines/systems.py: the durable counter, static quotas, the
central counter's local and remote paths, the pysyncobj Raft counter, the LETS warden wrapper with
its transfer handlers, delegation trees, rollback anchors, and stale-snapshot restores, and the
actuator-side effect log.
"""

from __future__ import annotations

import base64
import os
import socket
import time
from pathlib import Path

import pytest

from benchmarks.fair_baselines.common import SITES
from benchmarks.fair_baselines.systems import (
    AnchorSettings,
    CentralCounterSystem,
    DurableCounter,
    EffectLog,
    LetsSystem,
    MessageCounter,
    PeerRejectedError,
    PeerTransport,
    PeerUnreachableError,
    RaftCounterSystem,
    StaticQuotaSystem,
    parse_peer_urls,
    public_key_table,
    split_allocation,
)
from lets.crypto import Ed25519Signer
from lets.errors import LETSError
from tests.benchmarks.conftest import free_port

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="the Linux lane covers this loopback multi-agent harness, which targets Linux hosts",
)


def _events() -> tuple[list[tuple[str, str, int, str]], object]:
    log: list[tuple[str, str, int, str]] = []

    def sink(system: str, kind: str, value: int, detail: str) -> None:
        log.append((system, kind, value, detail))

    return log, sink


def _unreachable_transport(alias: str = "s1") -> PeerTransport:
    port = free_port()
    return PeerTransport(
        alias, "token-0123456789abcdef", {site: f"http://127.0.0.1:{port}" for site in SITES}, 0.5
    )


def test_durable_counter_is_idempotent_and_exhausts(tmp_path: Path) -> None:
    counter = DurableCounter(tmp_path / "c.sqlite3", 2)
    assert counter.take("a", "s1") == (True, 1)
    assert counter.take("a", "s2") == (True, 1)
    assert counter.take("b", "s1") == (True, 0)
    assert counter.take("c", "s3") == (False, 0)
    assert counter.take("c", "s3") == (False, 0)
    assert (counter.remaining(), counter.consumed()) == (0, 2)
    counter.close()
    reopened = DurableCounter(tmp_path / "c.sqlite3", 2)
    assert reopened.remaining() == 0
    reopened.close()


def test_static_quota_denies_without_retry_and_reports(tmp_path: Path) -> None:
    log, sink = _events()
    system = StaticQuotaSystem("static-quota", "s2", tmp_path, 1, sink)
    first = system.take("r1")
    assert (first.authorized, first.reason, first.retryable, first.remaining) == (
        True,
        "authorized",
        False,
        0,
    )
    second = system.take("r2")
    assert (second.authorized, second.reason, second.retryable) == (False, "exhausted", False)
    assert system.usable_units() == 0
    assert system.snapshot()["consumed"] == 1
    assert log == [("static-quota", "free", 0, "s2"), ("static-quota", "free", 0, "s2")]
    system.start()
    system.close()


def test_central_counter_host_and_remote_paths(tmp_path: Path) -> None:
    log, sink = _events()
    transport = _unreachable_transport("s2")
    host = CentralCounterSystem("central-retry@s2", "s2", "s2", tmp_path, 2, transport, sink)
    assert host.hosts_pool is True
    assert host.take("r1").authorized is True
    served = host.serve_take("r2", "s1")
    assert served == {"authorized": True, "remaining": 0}
    assert host.serve_take("r3", "s3") == {"authorized": False, "remaining": 0}
    assert host.messages.value == 2
    assert host.usable_units() == 0
    assert host.snapshot()["consumed"] == 2
    assert ("central-retry@s2", "free", 0, "s1") in log
    remote = CentralCounterSystem("central-retry@s2", "s1", "s2", tmp_path, 2, transport, sink)
    assert remote.hosts_pool is False
    decision = remote.take("r9")
    assert (decision.authorized, decision.reason, decision.retryable, decision.messages) == (
        False,
        "unreachable",
        True,
        1,
    )
    assert remote.usable_units() is None
    assert remote.snapshot()["remaining"] is None
    with pytest.raises(ValueError, match="does not host"):
        remote.serve_take("x", "s3")
    host.start()
    host.close()
    remote.close()


def test_peer_transport_distinguishes_rejections_from_unreachable_peers(
    loopback_cluster: object,
) -> None:
    cluster = loopback_cluster
    transport = PeerTransport(
        "s1",
        "wrong-token-0123456789abcdef",
        {"s2": cluster.control_url("s2")},  # type: ignore[attr-defined]
        2.0,
    )
    with pytest.raises(PeerRejectedError, match="unauthorized_peer_mac"):
        transport.post("s2", "/peer/ping", {})
    with pytest.raises(PeerUnreachableError):
        _unreachable_transport().post("s2", "/peer/ping", {})


def test_raft_counter_reaches_quorum_and_is_idempotent(tmp_path: Path) -> None:
    ports = {site: free_port() for site in SITES}
    addresses = {site: f"127.0.0.1:{port}" for site, port in ports.items()}
    log, sink = _events()
    systems = {}
    for site in SITES:
        directory = tmp_path / site
        directory.mkdir()
        systems[site] = RaftCounterSystem(
            "raft-quorum",
            site,
            directory,
            2,
            addresses[site],
            {peer: addresses[peer] for peer in SITES if peer != site},
            3.0,
            sink,
        )
    deadline = time.monotonic() + 30
    while not all(system.ready() for system in systems.values()):
        assert time.monotonic() < deadline, "no leader elected"
        time.sleep(0.1)
    first = systems["s1"].take("r1")
    assert (first.authorized, first.remaining) == (True, 1)
    replay = systems["s2"].take("r1")
    assert (replay.authorized, replay.remaining) == (True, 1)
    assert systems["s3"].take("r2").authorized is True
    exhausted = systems["s1"].take("r3")
    assert (exhausted.authorized, exhausted.reason, exhausted.retryable) == (
        False,
        "exhausted",
        False,
    )
    snapshot = systems["s2"].snapshot()
    assert snapshot["remaining"] == 0 and snapshot["raft_has_quorum"] is True
    assert sum(system.messages.value for system in systems.values()) > 0
    assert any(kind == "raft_state" for _, kind, _, _ in log)
    systems["s1"].start()
    for system in systems.values():
        system.close()


def test_raft_counter_times_out_without_quorum(tmp_path: Path) -> None:
    _log, sink = _events()
    lonely = RaftCounterSystem(
        "raft-quorum",
        "s1",
        tmp_path,
        2,
        f"127.0.0.1:{free_port()}",
        {"s2": f"127.0.0.1:{free_port()}", "s3": f"127.0.0.1:{free_port()}"},
        0.3,
        sink,
    )
    try:
        decision = lonely.take("r1")
        assert decision.authorized is False and decision.retryable is True
        assert decision.reason.startswith("timeout") or decision.reason == "no_leader"
    finally:
        lonely.close()


def test_raft_counter_listens_on_every_interface_for_an_unbindable_advertised_address(
    tmp_path: Path,
) -> None:
    _log, sink = _events()
    port = free_port()
    advertised = RaftCounterSystem(
        "raft-quorum",
        "s3",
        tmp_path,
        2,
        f"203.0.113.10:{port}",
        {"s1": f"127.0.0.1:{free_port()}", "s2": f"127.0.0.1:{free_port()}"},
        0.3,
        sink,
    )
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
                break
            except OSError:
                assert time.monotonic() < deadline, "raft node never listened on 0.0.0.0"
                time.sleep(0.1)
    finally:
        advertised.close()


def _lets(  # type: ignore[no-untyped-def]
    tmp_path: Path,
    site: str,
    share: int,
    sink: object,
    transport: PeerTransport,
    name: str = "lets",
    depth: int = 0,
    fanout: int = 0,
    signers: dict[str, Ed25519Signer] | None = None,
    anchor: AnchorSettings | None = None,
):
    signers = signers or {alias: Ed25519Signer.generate(alias) for alias in SITES}
    public_keys = {
        alias: (signer.key_id, signer.public_key_bytes) for alias, signer in signers.items()
    }
    directory = tmp_path / site
    directory.mkdir(exist_ok=True)
    return LetsSystem(
        name,
        site,
        directory,
        30,
        share,
        signers[site].seed_bytes,
        public_keys,
        transport,
        sink,  # type: ignore[arg-type]
        depth=depth,
        fanout=fanout,
        anchor=anchor,
    ), signers


def test_lets_system_authorizes_locally_until_exhausted(tmp_path: Path) -> None:
    _log, sink = _events()
    system, _ = _lets(tmp_path, "s1", 2, sink, _unreachable_transport())
    try:
        assert system.usable_units() == 2
        first = system.take("r1")
        assert (first.authorized, first.reason, first.remaining) == (
            True,
            "authorized_and_claimed",
            1,
        )
        assert system.take("r2").authorized is True
        exhausted = system.take("r3")
        assert (exhausted.authorized, exhausted.reason, exhausted.retryable) == (
            False,
            "exhausted_local",
            True,
        )
        snapshot = system.snapshot()
        assert snapshot["consumed"] == 2 and snapshot["healthy"] is True
        assert snapshot["executor_claim_sequence"] == 2
        assert (snapshot["tree_depth"], snapshot["tree_fanout"]) == (0, 0)
        assert (snapshot["live_leases"], snapshot["live_leaves"]) == (1, 1)
        assert (snapshot["tree_builds"], snapshot["lease_operations"]) == (1, 1)
        assert snapshot["leaf_residuals"] == [0]
        assert system.serve_request_transfer("s2", 3) == {"voucher": None, "granted": 0}
        system.set_waiting(1)
        system.start()
        time.sleep(0.2)
    finally:
        system.close()


def test_lets_transfer_handshake_between_two_wardens(tmp_path: Path) -> None:
    log, sink = _events()
    transport = _unreachable_transport()
    (tmp_path / "s1").mkdir()
    (tmp_path / "s2").mkdir()
    signers = {alias: Ed25519Signer.generate(alias) for alias in SITES}
    public_keys = {
        alias: (signer.key_id, signer.public_key_bytes) for alias, signer in signers.items()
    }
    source = LetsSystem(
        "lets",
        "s2",
        tmp_path / "s2",
        30,
        10,
        signers["s2"].seed_bytes,
        public_keys,
        transport,
        sink,
    )
    target = LetsSystem(
        "lets", "s1", tmp_path / "s1", 30, 1, signers["s1"].seed_bytes, public_keys, transport, sink
    )
    try:
        assert target.take("r1").authorized is True
        assert target.take("r2").reason == "exhausted_local"
        granted = source.serve_request_transfer("s1", 4)
        assert granted["granted"] == 4
        voucher = granted["voucher"]
        assert isinstance(voucher, dict)
        assert source.serve_request_transfer("s1", 9)["voucher"] == voucher
        assert source.usable_units() == 6
        target._accept("s2", dict(voucher))
        assert target.usable_units() == 4
        assert target.snapshot()["pending_acks"] == 1
        assert target.take("r2").authorized is True
        ack = target._pending_acks["s2"]
        assert source.serve_finalize("s1", ack) == {"finalized": True}
        assert source.snapshot()["outstanding_vouchers"] == 0
        assert source.snapshot()["transferred_out"] == 4
        assert target.snapshot()["transferred_in"] == 4
        with pytest.raises(ValueError, match="unknown transfer target"):
            source.serve_request_transfer("s2", 1)
        kinds = {kind for _, kind, _, _ in log}
        assert {"transfer_out", "transfer_in", "free", "lease_reissue"} <= kinds
    finally:
        source.close()
        target.close()


def test_effect_log_counts_and_digests(tmp_path: Path) -> None:
    log = EffectLog(tmp_path / "effects.sqlite3", "s3")
    log.actuate("lets", "r2", 20)
    log.actuate("lets", "r1", 10)
    log.actuate("static-quota", "r1", 5)
    summary = log.summary()
    assert summary["lets"]["count"] == 2
    assert summary["lets"]["request_ids"] == ["r1", "r2"]
    assert len(str(summary["lets"]["sha256"])) == 64
    assert summary["static-quota"]["count"] == 1
    log.close()


def test_key_and_url_parsers() -> None:
    signers = {alias: Ed25519Signer.generate(alias) for alias in SITES}
    payload = {
        alias: {
            "key_id": signer.key_id,
            "public_key": base64.b64encode(signer.public_key_bytes).decode(),
        }
        for alias, signer in signers.items()
    }
    table = public_key_table(payload, SITES)
    assert set(table) == set(SITES)
    with pytest.raises(ValueError, match="exactly the run's sites"):
        public_key_table({"s1": payload["s1"]}, SITES)
    with pytest.raises(ValueError, match="exactly the run's sites"):
        public_key_table(payload, ("s1", "s2", "s3", "s4"))
    assert parse_peer_urls({"s2": "http://10.0.0.2:9701"}) == {"s2": "http://10.0.0.2:9701"}
    for bad in ("https://10.0.0.2:9701", "http://10.0.0.2", "http://10.0.0.2:9701/x"):
        with pytest.raises(ValueError, match="origin-only"):
            parse_peer_urls({"s2": bad})
    counter = MessageCounter()
    counter.add(2)
    counter.add()
    assert counter.value == 3


def _builds(log: list[tuple[str, str, int, str]]) -> list[tuple[int, str]]:
    return [(value, detail) for _, kind, value, detail in log if kind == "tree_build"]


def test_lets_tree_spawns_leaves_and_authorizes_round_robin(tmp_path: Path) -> None:
    log, sink = _events()
    system, _ = _lets(
        tmp_path, "s1", 10, sink, _unreachable_transport(), "lets-tree-d2-f2", depth=2, fanout=2
    )
    try:
        snapshot = system.snapshot()
        assert (snapshot["tree_depth"], snapshot["tree_fanout"]) == (2, 2)
        assert (snapshot["live_leases"], snapshot["live_leaves"]) == (7, 4)
        assert snapshot["leaf_residuals"] == [3, 2, 3, 2]
        assert (snapshot["tree_builds"], snapshot["lease_operations"]) == (1, 7)
        assert snapshot["tree_build_us"] > 0
        assert (snapshot["free_pool"], snapshot["lease_residual"]) == (0, 10)
        assert system.usable_units() == 10
        first = system.take("r1")
        assert (first.authorized, first.reason, first.remaining) == (
            True,
            "authorized_and_claimed",
            9,
        )
        assert system.snapshot()["leaf_residuals"] == [2, 2, 3, 2]
        assert system.take("r2").remaining == 8
        assert system.snapshot()["leaf_residuals"] == [2, 1, 3, 2]
        for index in range(3, 11):
            assert system.take(f"r{index}").authorized is True
        exhausted = system.take("r11")
        assert (exhausted.authorized, exhausted.reason, exhausted.retryable) == (
            False,
            "exhausted_local",
            True,
        )
        final = system.snapshot()
        assert final["consumed"] == 10 and final["healthy"] is True
        assert final["executor_claim_sequence"] == 10
        assert final["leaf_residuals"] == [0, 0, 0, 0]
        assert (final["live_leases"], final["lease_residual"], final["free_pool"]) == (7, 0, 0)
        builds = _builds(log)
        assert len(builds) == 1 and builds[0][0] == 7
        assert builds[0][1].startswith("initial leases=7 leaves=4 us=")
        assert sum(1 for _, kind, _, _ in log if kind == "free") == 10
    finally:
        system.close()


def test_lets_tree_prunes_children_the_share_cannot_fund(tmp_path: Path) -> None:
    _log, sink = _events()
    transport = _unreachable_transport()
    assert split_allocation(10, 4) == [3, 3, 2, 2]
    assert split_allocation(1, 2) == [1, 0]
    assert split_allocation(0, 2) == [0, 0]
    single, signers = _lets(
        tmp_path, "s2", 1, sink, transport, "lets-tree-d2-f2", depth=2, fanout=2
    )
    try:
        snapshot = single.snapshot()
        assert (snapshot["live_leases"], snapshot["live_leaves"]) == (3, 1)
        assert snapshot["leaf_residuals"] == [1] and snapshot["lease_operations"] == 3
        assert single.take("r1").authorized is True
        assert single.take("r2").reason == "exhausted_local"
        assert single.snapshot()["healthy"] is True
    finally:
        single.close()
    three, _ = _lets(
        tmp_path, "s3", 3, sink, transport, "lets-tree-d2-f2", depth=2, fanout=2, signers=signers
    )
    try:
        snapshot = three.snapshot()
        assert (snapshot["live_leases"], snapshot["live_leaves"]) == (6, 3)
        assert snapshot["leaf_residuals"] == [1, 1, 1]
    finally:
        three.close()
    wide, _ = _lets(
        tmp_path, "s1", 10, sink, transport, "lets-tree-d1-f4", depth=1, fanout=4, signers=signers
    )
    try:
        snapshot = wide.snapshot()
        assert (snapshot["live_leases"], snapshot["live_leaves"]) == (5, 4)
        assert snapshot["leaf_residuals"] == [3, 3, 2, 2]
    finally:
        wide.close()
    with pytest.raises(ValueError, match="delegation tree"):
        _lets(tmp_path, "s1", 10, sink, transport, "lets-tree-d1-f0", depth=1, fanout=0)
    with pytest.raises(ValueError, match="delegation tree"):
        _lets(tmp_path, "s1", 10, sink, transport, "bad", depth=-1, fanout=2)


def test_lets_tree_refreshes_from_a_transfer_after_exhaustion(tmp_path: Path) -> None:
    log, sink = _events()
    transport = _unreachable_transport()
    source, signers = _lets(
        tmp_path, "s2", 10, sink, transport, "lets-tree-d2-f2", depth=2, fanout=2
    )
    target, _ = _lets(
        tmp_path, "s1", 2, sink, transport, "lets-tree-d2-f2", depth=2, fanout=2, signers=signers
    )
    try:
        assert (target.snapshot()["live_leases"], target.snapshot()["live_leaves"]) == (5, 2)
        assert target.take("r1").authorized and target.take("r2").authorized
        assert target.take("r3").reason == "exhausted_local"
        assert target.usable_units() == 0
        granted = source.serve_request_transfer("s1", 4)
        assert granted["granted"] == 4
        voucher = granted["voucher"]
        assert isinstance(voucher, dict)
        after_out = source.snapshot()
        assert source.usable_units() == 6
        assert (after_out["tree_builds"], after_out["lease_operations"]) == (2, 21)
        assert after_out["leaf_residuals"] == [2, 1, 2, 1]
        assert after_out["healthy"] is True and after_out["outstanding_vouchers"] == 1
        assert source.serve_request_transfer("s1", 9)["voucher"] == voucher
        assert source.snapshot()["tree_builds"] == 2
        target._accept("s2", dict(voucher))
        after_in = target.snapshot()
        assert target.usable_units() == 4
        assert (after_in["tree_builds"], after_in["lease_operations"]) == (2, 17)
        assert (after_in["live_leases"], after_in["live_leaves"]) == (7, 4)
        assert after_in["leaf_residuals"] == [1, 1, 1, 1]
        assert after_in["transferred_in"] == 4 and after_in["healthy"] is True
        assert after_in["pending_acks"] == 1
        for index in range(3, 7):
            assert target.take(f"r{index}").authorized is True
        assert target.take("r7").reason == "exhausted_local"
        assert target.snapshot()["consumed"] == 6
        ack = target._pending_acks["s2"]
        assert source.serve_finalize("s1", ack) == {"finalized": True}
        assert source.snapshot()["transferred_out"] == 4
        assert source.snapshot()["outstanding_vouchers"] == 0
        reasons = [detail.split(" ", 1)[0] for _, detail in _builds(log)]
        assert reasons == ["initial", "initial", "out-s1-1", "in-1"]
        operations = [value for value, _ in _builds(log)]
        assert operations == [7, 5, 14, 12]
        assert all("leaves=" in detail and "us=" in detail for _, detail in _builds(log))
        kinds = {kind for _, kind, _, _ in log}
        assert {"transfer_out", "transfer_in", "free", "lease_reissue", "tree_build"} <= kinds
    finally:
        source.close()
        target.close()


def test_lets_tree_transfer_out_can_empty_a_site(tmp_path: Path) -> None:
    log, sink = _events()
    source, _ = _lets(
        tmp_path, "s3", 1, sink, _unreachable_transport(), "lets-tree-d2-f2", depth=2, fanout=2
    )
    try:
        assert source.serve_request_transfer("s1", 5)["granted"] == 1
        snapshot = source.snapshot()
        assert (snapshot["live_leases"], snapshot["live_leaves"]) == (0, 0)
        assert source.usable_units() == 0 and snapshot["healthy"] is True
        assert source.take("r1").reason == "exhausted_local"
        operations, detail = _builds(log)[-1]
        assert operations == 3 and detail.startswith("out-s1-1 leases=0 leaves=0 us=")
    finally:
        source.close()


def _anchor(tmp_path: Path) -> AnchorSettings:
    root = tmp_path / "anchors"
    root.mkdir(exist_ok=True)
    return AnchorSettings(root)


def test_anchored_lets_writes_anchors_and_authorizes(tmp_path: Path) -> None:
    _log, sink = _events()
    anchor = _anchor(tmp_path)
    system, _ = _lets(
        tmp_path, "s1", 2, sink, _unreachable_transport(), name="lets-anchored", anchor=anchor
    )
    try:
        assert system.anchored is True
        assert system.take("r1").authorized is True
        snapshot = system.snapshot()
        assert snapshot["anchored"] is True and snapshot["restore_refused"] is None
        assert snapshot["consumed"] == 1 and snapshot["healthy"] is True
        names = sorted(path.name for path in anchor.root.iterdir() if path.suffix == ".anchor")
        assert [name.rsplit("-", 1)[1] for name in names] == ["executor.anchor", "warden.anchor"]
    finally:
        system.close()


def test_anchored_lets_refuses_a_restored_stale_snapshot(tmp_path: Path) -> None:
    log, sink = _events()
    system, _ = _lets(
        tmp_path,
        "s1",
        4,
        sink,
        _unreachable_transport(),
        name="lets-anchored-restore@s1",
        anchor=_anchor(tmp_path),
    )
    try:
        with pytest.raises(RuntimeError, match="no snapshot"):
            system.restore_snapshot()
        assert system.take("r1").authorized is True
        assert system.take_snapshot() == "usable=3 revision=2 outstanding=0 pending_acks=0"
        assert system.take("r2").authorized is True
        assert system.take("r3").authorized is True
        accepted, detail = system.restore_snapshot()
        assert accepted is False
        assert detail.startswith(
            "usable_before=1 revision_before=4 snapshot_revision=2 StorageError"
        )
        refused = system.take("r4")
        assert (refused.authorized, refused.reason, refused.retryable, refused.remaining) == (
            False,
            "stale_state_refused",
            False,
            0,
        )
        assert system.usable_units() == 0
        snapshot = system.snapshot()
        assert snapshot["healthy"] is False and "StorageError" in str(snapshot["restore_refused"])
        assert system.serve_request_transfer("s2", 2) == {"voucher": None, "granted": 0}
        assert system.serve_finalize("s2", {}) == {"finalized": False}
        system._accept("s2", {"amount": [2]})
        assert log[-1] == ("lets-anchored-restore@s1", "voucher_lost", 2, "s2")
        with pytest.raises(RuntimeError, match="refused its restored state"):
            system.take_snapshot()
        system.set_waiting(1)
        system.start()
        time.sleep(0.2)
    finally:
        system.close()


def test_unanchored_restore_rewinds_the_budget_and_spends_it_again(tmp_path: Path) -> None:
    log, sink = _events()
    system, _ = _lets(
        tmp_path, "s1", 3, sink, _unreachable_transport(), name="lets-restore@s1", depth=1, fanout=2
    )
    try:
        assert system.anchored is False
        assert system.take("r1").authorized is True
        system.take_snapshot()
        assert system.take("r2").authorized is True
        assert system.take("r3").authorized is True
        assert system.take("r4").reason == "exhausted_local"
        accepted, detail = system.restore_snapshot()
        assert accepted is True
        assert detail.startswith("usable_before=0 revision_before=")
        assert detail.endswith(" usable_after=2")
        assert system.take("r5").authorized is True
        assert system.take("r6").authorized is True
        snapshot = system.snapshot()
        assert snapshot["consumed"] == 3 and snapshot["healthy"] is True
        assert snapshot["restore_refused"] is None and snapshot["live_leaves"] == 2
        system._accept("s2", {"amount": [1]})
        assert log[-1][:3] == ("lets-restore@s1", "voucher_rejected", 1)
        assert system.usable_units() == 0
    finally:
        system.close()


def test_anchored_lets_fails_closed_on_a_foreign_anchor(tmp_path: Path) -> None:
    _log, sink = _events()
    anchor = _anchor(tmp_path)
    (anchor.root / f"{tmp_path.name}.s1.lets-anchored-warden.anchor").write_text("{}")
    with pytest.raises(LETSError):
        _lets(
            tmp_path, "s1", 2, sink, _unreachable_transport(), name="lets-anchored", anchor=anchor
        )
