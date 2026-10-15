"""Single-machine mode for E1: renders a Docker Compose project with N independent three-site
clusters (static IPs, NET_ADMIN, the docker/Dockerfile image), brings it up or down, and writes
the endpoints file controller.py consumes, with docker exec as the privileged fault command.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from pathlib import Path

from benchmarks.fair_baselines.common import SITES
from benchmarks.fair_baselines.faults import SiteEndpoint
from benchmarks.nsdi_strengthening.common import repository_root

PROJECT = "lets-e1"
AGENT_PORT = 9701
RAFT_PORT = 9801
SUBNET_PREFIX = "10.231"
SITE_HOST_OCTET = {"s1": 11, "s2": 12, "s3": 13}


def site_ip(cluster_index: int, site: str) -> str:
    return f"{SUBNET_PREFIX}.{cluster_index}.{SITE_HOST_OCTET[site]}"


def control_port(cluster_index: int, site: str) -> int:
    return 9700 + 10 * cluster_index + SITE_HOST_OCTET[site] - 10


def container_name(cluster_index: int, site: str) -> str:
    return f"{PROJECT}-{cluster_index}-{site}"


def compose_document(clusters: int, token: str, image: str) -> dict[str, object]:
    services: dict[str, object] = {}
    networks: dict[str, object] = {}
    for index in range(clusters):
        network = f"cluster{index}"
        networks[network] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": f"{SUBNET_PREFIX}.{index}.0/24"}]},
        }
        for site in SITES:
            services[container_name(index, site)] = {
                "image": image,
                "build": {
                    "context": str(repository_root()),
                    "dockerfile": "benchmarks/fair_baselines/docker/Dockerfile",
                },
                "container_name": container_name(index, site),
                "command": [
                    "--site",
                    site,
                    "--bind",
                    "0.0.0.0",
                    "--port",
                    str(AGENT_PORT),
                    "--state-root",
                    "/state",
                ],
                "environment": {"LETS_E1_TOKEN": token},
                "cap_add": ["NET_ADMIN"],
                "networks": {network: {"ipv4_address": site_ip(index, site)}},
                "ports": [f"127.0.0.1:{control_port(index, site)}:{AGENT_PORT}"],
                "tmpfs": ["/state:mode=700"],
                "stop_grace_period": "5s",
                "restart": "no",
            }
    return {"name": PROJECT, "services": services, "networks": networks}


def endpoints_document(clusters: int, token: str) -> dict[str, object]:
    return {
        "schema": "lets.fair-baselines-endpoints/v1",
        "token": token,
        "clusters": [
            {
                "name": f"local-{index}",
                "sites": {
                    site: SiteEndpoint(
                        site,
                        f"http://127.0.0.1:{control_port(index, site)}",
                        site_ip(index, site),
                        AGENT_PORT,
                        RAFT_PORT,
                        ("docker", "exec", container_name(index, site), "sh", "-c"),
                    ).to_dict()
                    for site in SITES
                },
            }
            for index in range(clusters)
        ],
    }


def _compose(work_dir: Path, *arguments: str, timeout_s: float = 900.0) -> None:
    command = ["docker", "compose", "-f", str(work_dir / "compose.yaml"), *arguments]
    subprocess.run(command, check=True, cwd=repository_root(), timeout=timeout_s)


def wait_healthy(endpoints: dict[str, object], timeout_s: float = 120.0) -> None:
    token = str(endpoints["token"])
    deadline = time.monotonic() + timeout_s
    clusters = endpoints["clusters"]
    assert isinstance(clusters, list)
    pending = [
        (cluster["name"], site, str(cluster["sites"][site]["control_url"]))
        for cluster in clusters
        for site in SITES
    ]
    while pending:
        name, site, url = pending[0]
        request = urllib.request.Request(
            f"{url}/health", headers={"Authorization": f"Bearer {token}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                payload = json.loads(response.read())
            if payload.get("site") == site:
                pending.pop(0)
                continue
        except (OSError, urllib.error.URLError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{name}/{site} at {url} never became healthy")
        time.sleep(0.5)


def up(
    work_dir: Path, clusters: int, *, build: bool = True, image: str = f"{PROJECT}:local"
) -> Path:
    work_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    compose_path = work_dir / "compose.yaml"
    compose_path.write_text(
        json.dumps(compose_document(clusters, token, image), indent=2) + "\n", encoding="utf-8"
    )
    endpoints = endpoints_document(clusters, token)
    endpoints_path = work_dir / "endpoints.json"
    endpoints_path.write_text(json.dumps(endpoints, indent=2) + "\n", encoding="utf-8")
    arguments = ["up", "-d", "--remove-orphans"]
    if build:
        arguments.append("--build")
    _compose(work_dir, *arguments)
    wait_healthy(endpoints)
    return endpoints_path


def down(work_dir: Path) -> None:
    if (work_dir / "compose.yaml").exists():
        _compose(work_dir, "down", "--remove-orphans", "--timeout", "5", timeout_s=300.0)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    up_parser = sub.add_parser("up")
    up_parser.add_argument("--work-dir", type=Path, required=True)
    up_parser.add_argument("--clusters", type=int, default=3)
    up_parser.add_argument("--no-build", action="store_true")
    down_parser = sub.add_parser("down")
    down_parser.add_argument("--work-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.command == "up":
        if arguments.clusters < 1 or arguments.clusters > 20:
            raise SystemExit("--clusters must be between 1 and 20")
        path = up(arguments.work_dir, arguments.clusters, build=not arguments.no_build)
        print(json.dumps({"endpoints": str(path), "clusters": arguments.clusters}))
        return 0
    down(arguments.work_dir)
    print(json.dumps({"down": True}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
