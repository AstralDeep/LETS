"""Tests for benchmarks/fair_baselines/systems.py: the durable counter, static quotas, the
central counter's local and remote paths, the pysyncobj Raft counter, the LETS warden wrapper with
its transfer handlers, and the actuator-side effect log.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path

import pytest

from benchmarks.fair_baselines.common import SITES
from benchmarks.fair_baselines.systems import (
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
)
from lets.crypto import Ed25519Signer
from tests.benchmarks.conftest import free_port


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


def _lets(tmp_path: Path, site: str, share: int, sink: object, transport: PeerTransport):  # type: ignore[no-untyped-def]
    signers = {alias: Ed25519Signer.generate(alias) for alias in SITES}
    public_keys = {
        alias: (signer.key_id, signer.public_key_bytes) for alias, signer in signers.items()
    }
    directory = tmp_path / site
    directory.mkdir(exist_ok=True)
    return LetsSystem(
        "lets",
        site,
        directory,
        30,
        share,
        signers[site].seed_bytes,
        public_keys,
        transport,
        sink,  # type: ignore[arg-type]
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
    table = public_key_table(payload)
    assert set(table) == set(SITES)
    with pytest.raises(ValueError, match="exactly s1, s2, and s3"):
        public_key_table({"s1": payload["s1"]})
    assert parse_peer_urls({"s2": "http://10.0.0.2:9701"}) == {"s2": "http://10.0.0.2:9701"}
    for bad in ("https://10.0.0.2:9701", "http://10.0.0.2", "http://10.0.0.2:9701/x"):
        with pytest.raises(ValueError, match="origin-only"):
            parse_peer_urls({"s2": bad})
    counter = MessageCounter()
    counter.add(2)
    counter.add()
    assert counter.value == 3
