"""Shared fixtures for the E1 fair-baseline tests: free loopback ports, three in-process site
agents wired as a cluster, and the endpoint description controller.py expects for them.
"""

from __future__ import annotations

import base64
import json
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest

from benchmarks.fair_baselines.common import SITES
from benchmarks.fair_baselines.site_agent import AgentServer, serve
from lets.crypto import Ed25519Signer

TOKEN = "test-token-not-a-secret-0123456789"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LoopbackCluster:
    def __init__(self, root: Path) -> None:
        self.token = TOKEN
        self.ports = {site: free_port() for site in SITES}
        self.raft_ports = {site: free_port() for site in SITES}
        self.servers: dict[str, AgentServer] = {}
        for site in SITES:
            server = serve(site, "127.0.0.1", self.ports[site], TOKEN, root / site)
            threading.Thread(
                target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
            ).start()
            self.servers[site] = server
        signers = {site: Ed25519Signer.generate(site) for site in SITES}
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
                peer: f"http://127.0.0.1:{self.ports[peer]}" for peer in SITES if peer != site
            },
            "keys": {"seed": self.seeds[site], "public_keys": self.public_keys},
            "raft": {
                "self": f"127.0.0.1:{self.raft_ports[site]}",
                "peers": {
                    peer: f"127.0.0.1:{self.raft_ports[peer]}" for peer in SITES if peer != site
                },
            },
        }

    def endpoints(self) -> dict[str, object]:
        return {
            "schema": "lets.fair-baselines-endpoints/v1",
            "token": TOKEN,
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
                        for site in SITES
                    },
                }
            ],
        }

    def close(self) -> None:
        for server in self.servers.values():
            server.shutdown()
            server.server_close()
            server.state.teardown()


@pytest.fixture
def loopback_cluster(tmp_path: Path) -> Iterator[LoopbackCluster]:
    cluster = LoopbackCluster(tmp_path / "agents")
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
