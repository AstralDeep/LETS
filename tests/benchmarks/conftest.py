"""Shared fixtures for the E1 fair-baseline tests: free loopback ports, in-process site agents
wired as a cluster over any site roster, and the endpoint description controller.py expects. The
agents bind port 0 and publish the port the kernel gave them, so no control port is ever guessed.
"""

from __future__ import annotations

import base64
import contextlib
import json
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest

from benchmarks.fair_baselines.common import DEFAULT_SITES
from benchmarks.fair_baselines.site_agent import AgentServer, serve
from benchmarks.fair_baselines.systems import AnchorSettings
from lets.crypto import Ed25519Signer

TOKEN = "test-token-not-a-secret-0123456789"
FIVE_SITES = ("uk1", "uk2", "az1", "use2", "apse1")


def free_ports(count: int) -> list[int]:
    with contextlib.ExitStack() as stack:
        sockets = [stack.enter_context(socket.socket()) for _ in range(count)]
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [int(sock.getsockname()[1]) for sock in sockets]


def free_port() -> int:
    return free_ports(1)[0]


class LoopbackCluster:
    def __init__(
        self, root: Path, sites: Sequence[str] = DEFAULT_SITES, anchor_root: Path | None = None
    ) -> None:
        self.token = TOKEN
        self.sites = tuple(sites)
        self.ports: dict[str, int] = {}
        self.servers: dict[str, AgentServer] = {}
        self._threads: dict[str, threading.Thread] = {}
        try:
            for site in self.sites:
                anchor = None
                if anchor_root is not None:
                    (anchor_root / site).mkdir(parents=True, exist_ok=True)
                    anchor = AnchorSettings(anchor_root / site)
                server = serve(site, "127.0.0.1", 0, TOKEN, root / site, anchor)
                self.servers[site] = server
                self.ports[site] = int(server.server_address[1])
                thread = threading.Thread(
                    target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
                )
                thread.start()
                self._threads[site] = thread
        except BaseException:
            self.close()
            raise
        self.raft_ports = dict(zip(self.sites, free_ports(len(self.sites)), strict=True))
        signers = {site: Ed25519Signer.generate(site) for site in self.sites}
        self.seeds = {
            site: base64.b64encode(signer.seed_bytes).decode() for site, signer in signers.items()
        }
        self.public_keys = {
            site: {
                "key_id": signer.key_id,
                "public_key": base64.b64encode(signer.public_key_bytes).decode(),
            }
            for site, signer in signers.items()
        }

    def control_url(self, site: str) -> str:
        return f"http://127.0.0.1:{self.ports[site]}"

    def call(
        self,
        site: str,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        *,
        token: str | None = None,
    ) -> tuple[int, dict[str, object]]:
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(
            f"{self.control_url(site)}{path}",
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {TOKEN if token is None else token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    def configure_body(self, site: str, config: dict[str, object]) -> dict[str, object]:
        return {
            "config": config,
            "peers": {
                peer: f"http://127.0.0.1:{self.ports[peer]}" for peer in self.sites if peer != site
            },
            "keys": {"seed": self.seeds[site], "public_keys": self.public_keys},
            "raft": {
                "self": f"127.0.0.1:{self.raft_ports[site]}",
                "peers": {
                    peer: f"127.0.0.1:{self.raft_ports[peer]}"
                    for peer in self.sites
                    if peer != site
                },
            },
        }

    def endpoints(self) -> dict[str, object]:
        return {
            "schema": "lets.fair-baselines-endpoints/v1",
            "token": TOKEN,
            "sites": list(self.sites),
            "clusters": [
                {
                    "name": "loopback",
                    "sites": {
                        site: {
                            "control_url": self.control_url(site),
                            "peer_ip": "127.0.0.1",
                            "peer_port": self.ports[site],
                            "raft_port": self.raft_ports[site],
                            "fault_exec": ["dry-run"],
                        }
                        for site in self.sites
                    },
                }
            ],
        }

    def close(self) -> None:
        with contextlib.ExitStack() as stack:
            for site, server in self.servers.items():
                stack.callback(self._close_server, site, server)

    def _close_server(self, site: str, server: AgentServer) -> None:
        try:
            if site in self._threads:
                server.shutdown()
                self._threads[site].join()
        finally:
            server.server_close()
            server.state.teardown()


@pytest.fixture
def loopback_cluster(tmp_path: Path) -> Iterator[LoopbackCluster]:
    cluster = LoopbackCluster(tmp_path / "agents")
    try:
        yield cluster
    finally:
        cluster.close()


@pytest.fixture
def anchored_cluster(tmp_path: Path) -> Iterator[LoopbackCluster]:
    cluster = LoopbackCluster(tmp_path / "agents", anchor_root=tmp_path / "anchors")
    try:
        yield cluster
    finally:
        cluster.close()


@pytest.fixture
def five_site_cluster(tmp_path: Path) -> Iterator[LoopbackCluster]:
    cluster = LoopbackCluster(tmp_path / "agents5", FIVE_SITES)
    try:
        yield cluster
    finally:
        cluster.close()


def short_config(run_id: str, **overrides: object) -> dict[str, object]:
    config: dict[str, object] = {
        "run_id": run_id,
        "topology": "bridge-s3",
        "load": 2.0,
        "theta": 1.0,
        "seed": 3,
        "placement": "equal",
        "envelope": 9,
        "systems": [
            "central-noretry@s2",
            "central-retry@s1",
            "static-quota",
            "raft-quorum",
            "lets",
        ],
        "pre_s": 0.5,
        "partition_s": 1.0,
        "post_s": 0.5,
        "deadline_s": 1.5,
        "retry_base_s": 0.05,
        "retry_cap_s": 0.2,
        "peer_timeout_s": 1.0,
        "raft_timeout_s": 1.0,
    }
    config.update(overrides)
    return config
