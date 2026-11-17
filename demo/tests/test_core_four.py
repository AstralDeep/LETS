"""Runs the four claims of verify_core_four.py as asserts against a real warden started on loopback.

The warden is a `lets serve` subprocess on a port the test picks, built from `lets init` in a temp
directory, so the demo is proven against the LETS in this tree on every platform.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from demo.config import Settings
from demo.fleet import Fleet

COST_RESEARCH = [1, 500]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _lets(config: Path, *args: str) -> list[str]:
    return [sys.executable, "-m", "lets.cli", "--config", str(config), *args]


def _wait_ready(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"lets serve exited with {process.returncode}")
        try:
            if httpx.get(f"{base_url}/health/ready", timeout=2).json().get("status") == "ready":
                return
        except (httpx.HTTPError, ValueError):
            pass
        time.sleep(0.25)
    raise RuntimeError("the warden did not become ready")


@pytest.fixture(scope="module")
def fleet(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Fleet]:
    root = tmp_path_factory.mktemp("warden")
    config = root / ".lets" / "a" / "config.json"
    init = subprocess.run(
        _lets(
            config,
            "init",
            "--warden-id", "warden-a",
            "--tenant-id", "example",
            "--envelope-id", "agents",
            "--budget", "10000,1000000",
            "--local-share", "10000,1000000",
        ),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    token = json.loads(init.stdout)["bootstrap_token"]
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    server = subprocess.Popen(
        _lets(config, "serve", "--host", "127.0.0.1", "--port", str(port)),
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait_ready(base_url, server)
        host = Fleet(
            Settings(base_url=base_url, token=token),
            registry_path=root / "registry.json",
        )
        host.start()
        host.reset()
        yield host
        host.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def _lease(state: dict, subject: str) -> dict:
    return next(lease for lease in state["leases"] if lease["subject_id"] == subject)


def _delta(before: list[int], after: list[int]) -> list[int]:
    return [b - a for b, a in zip(before, after, strict=True)]


def test_core_four(fleet: Fleet) -> None:
    state = fleet.snapshot()
    assert state["ledger"]["balanced"]
    pool_before = state["ledger"]["free_pool"]

    event = fleet.provision_root()
    assert event.ok, event.detail or event.note
    state = fleet.snapshot()
    root = _lease(state, "agent-root")
    assert root["residual"] == root["allocation"]
    assert state["ledger"]["balanced"]
    assert _delta(pool_before, state["ledger"]["free_pool"]) == root["allocation"]
    root_id = root["lease_id"]

    escrow_before = _lease(state, "agent-root")["residual"]
    event = fleet.spawn_child(root_id)
    assert event.ok, event.detail or event.note
    state = fleet.snapshot()
    child = next(lease for lease in state["leases"] if lease["depth"] == 1)
    escrow_after = _lease(state, "agent-root")["residual"]
    assert _delta(escrow_before, escrow_after) == child["allocation"]
    assert state["ledger"]["balanced"]

    tree_before = [dict(lease) for lease in fleet.snapshot()["leases"]]
    event = fleet.spawn_oversized(root_id)
    assert not event.ok
    assert event.code == "policy_denied"
    assert event.ledger_unchanged is True
    state = fleet.snapshot()
    assert tree_before == [dict(lease) for lease in state["leases"]]
    assert state["ledger"]["balanced"]

    event = fleet.spawn_escalated(root_id)
    assert not event.ok
    assert "undeclared" not in (event.detail or "").lower()
    assert fleet.snapshot()["ledger"]["balanced"]

    before = _lease(fleet.snapshot(), "agent-root")
    consumed_before = fleet.snapshot()["ledger"]["consumed"]
    event = fleet.do_work(root_id, "research")
    assert event.ok, event.detail or event.note
    state = fleet.snapshot()
    after = _lease(state, "agent-root")
    assert _delta(before["residual"], after["residual"]) == COST_RESEARCH
    assert _delta(state["ledger"]["consumed"], consumed_before) == COST_RESEARCH
    assert after["sequence"] > before["sequence"]
    assert state["ledger"]["balanced"]

    events = fleet.drain(child["lease_id"], "research")
    assert any(e.ok for e in events)
    assert not events[-1].ok
    assert fleet.snapshot()["ledger"]["balanced"]

    assert fleet.reset().ok
    state = fleet.snapshot()
    assert state["leases"] == []
    assert state["ledger"]["balanced"]
