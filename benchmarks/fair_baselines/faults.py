"""Kernel-level fault injection for E1: builds the iptables cut/heal and tc netem commands for a
topology, runs them on each site through a per-site privileged command prefix (docker exec locally,
ssh+sudo on the three endpoints), and turns a topology plus phase timings into a timed schedule the
controller executes while a run is in flight.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from benchmarks.fair_baselines.common import LINKS, SITES, Topology

CHAIN = "LETS_E1"


@dataclass(frozen=True, slots=True)
class SiteEndpoint:
    site: str
    control_url: str
    peer_ip: str
    peer_port: int
    raft_port: int
    fault_exec: tuple[str, ...]
    interface: str = "eth0"

    @property
    def peer_url(self) -> str:
        return f"http://{self.peer_ip}:{self.peer_port}"

    @property
    def raft_address(self) -> str:
        return f"{self.peer_ip}:{self.raft_port}"

    @classmethod
    def from_dict(cls, site: str, payload: Mapping[str, object]) -> SiteEndpoint:
        if site not in SITES:
            raise ValueError(f"unknown site {site!r}")
        fault_exec = payload.get("fault_exec")
        if not isinstance(fault_exec, Sequence) or isinstance(fault_exec, str) or not fault_exec:
            raise ValueError(f"{site}: fault_exec must be a non-empty command prefix list")
        return cls(
            site=site,
            control_url=str(payload["control_url"]).rstrip("/"),
            peer_ip=str(payload["peer_ip"]),
            peer_port=int(payload["peer_port"]),  # type: ignore[call-overload]
            raft_port=int(payload["raft_port"]),  # type: ignore[call-overload]
            fault_exec=tuple(str(part) for part in fault_exec),
            interface=str(payload.get("interface", "eth0")),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "control_url": self.control_url,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "raft_port": self.raft_port,
            "fault_exec": list(self.fault_exec),
            "interface": self.interface,
        }


@dataclass(frozen=True, slots=True)
class CommandResult:
    site: str
    command: str
    returncode: int
    stdout: str
    stderr: str
    sent_wall_ns: int
    returned_wall_ns: int

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class FaultDriver(Protocol):
    def run(self, endpoint: SiteEndpoint, command: str) -> CommandResult: ...


class SubprocessFaultDriver:
    def __init__(self, timeout_s: float = 30.0) -> None:
        self.timeout_s = timeout_s

    def run(self, endpoint: SiteEndpoint, command: str) -> CommandResult:
        sent = time.time_ns()
        completed = subprocess.run(
            [*endpoint.fault_exec, command],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=self.timeout_s,
        )
        return CommandResult(
            endpoint.site,
            command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            sent,
            time.time_ns(),
        )


class DryRunFaultDriver:
    def __init__(self) -> None:
        self.commands: list[tuple[str, str]] = []

    def run(self, endpoint: SiteEndpoint, command: str) -> CommandResult:
        now = time.time_ns()
        self.commands.append((endpoint.site, command))
        return CommandResult(endpoint.site, command, 0, "", "", now, now)


def setup_commands() -> tuple[str, ...]:
    return (
        f"iptables -N {CHAIN} 2>/dev/null || true",
        f"iptables -F {CHAIN}",
        f"iptables -C INPUT -j {CHAIN} 2>/dev/null || iptables -I INPUT -j {CHAIN}",
        f"iptables -C OUTPUT -j {CHAIN} 2>/dev/null || iptables -I OUTPUT -j {CHAIN}",
    )


def cut_commands(peer_ip: str) -> tuple[str, ...]:
    ip = shlex.quote(peer_ip)
    return (f"iptables -A {CHAIN} -s {ip} -j DROP", f"iptables -A {CHAIN} -d {ip} -j DROP")


def heal_commands() -> tuple[str, ...]:
    return (f"iptables -F {CHAIN}",)


def counters_command() -> str:
    return f"iptables -L {CHAIN} -v -n -x"


def netem_commands(interface: str, one_way_ms: float, loss_pct: float) -> tuple[str, ...]:
    if one_way_ms < 0 or loss_pct < 0:
        raise ValueError("delay and loss must be non-negative")
    device = shlex.quote(interface)
    if one_way_ms == 0 and loss_pct == 0:
        return (f"tc qdisc del dev {device} root 2>/dev/null || true",)
    loss = f" loss {loss_pct:g}%" if loss_pct > 0 else ""
    return (f"tc qdisc replace dev {device} root netem delay {one_way_ms:g}ms{loss}",)


def cleanup_commands(interface: str) -> tuple[str, ...]:
    device = shlex.quote(interface)
    return (
        f"iptables -D INPUT -j {CHAIN} 2>/dev/null || true",
        f"iptables -D OUTPUT -j {CHAIN} 2>/dev/null || true",
        f"iptables -F {CHAIN} 2>/dev/null || true",
        f"iptables -X {CHAIN} 2>/dev/null || true",
        f"tc qdisc del dev {device} root 2>/dev/null || true",
    )


@dataclass(frozen=True, slots=True)
class ScheduledFault:
    offset_s: float
    kind: str
    links: frozenset[frozenset[str]]


def fault_schedule(
    topology: Topology, pre_s: float, partition_s: float
) -> tuple[ScheduledFault, ...]:
    if topology.flap_period_s is None:
        return (
            ScheduledFault(pre_s, "cut", topology.cut_links),
            ScheduledFault(pre_s + partition_s, "heal", topology.cut_links),
        )
    events: list[ScheduledFault] = []
    offset = pre_s
    cut = True
    while offset < pre_s + partition_s - 1e-9:
        events.append(ScheduledFault(offset, "cut" if cut else "heal", topology.cut_links))
        cut = not cut
        offset += topology.flap_period_s
    events.append(ScheduledFault(pre_s + partition_s, "heal", topology.cut_links))
    return tuple(events)


def link_label(link: frozenset[str]) -> str:
    return "-".join(sorted(link))


@dataclass
class FaultInjector:
    driver: FaultDriver
    endpoints: Mapping[str, SiteEndpoint]
    log: list[CommandResult] = field(default_factory=list)

    def _run(self, site: str, commands: Iterable[str]) -> list[CommandResult]:
        results = []
        for command in commands:
            result = self.driver.run(self.endpoints[site], command)
            self.log.append(result)
            results.append(result)
            if not result.ok:
                raise RuntimeError(
                    f"{site}: fault command failed ({result.returncode}): {command}: "
                    f"{result.stderr.strip()[:200]}"
                )
        return results

    def prepare(self, one_way_ms: float, loss_pct: float) -> None:
        for site, endpoint in self.endpoints.items():
            self._run(site, setup_commands())
            self._run(site, netem_commands(endpoint.interface, one_way_ms, loss_pct))

    def cut(self, links: Iterable[frozenset[str]]) -> list[CommandResult]:
        results = []
        for link in links:
            if link not in LINKS:
                raise ValueError(f"unknown link {sorted(link)}")
            left, right = sorted(link)
            results.extend(self._run(left, cut_commands(self.endpoints[right].peer_ip)))
            results.extend(self._run(right, cut_commands(self.endpoints[left].peer_ip)))
        return results

    def heal(self) -> list[CommandResult]:
        results = []
        for site in self.endpoints:
            results.extend(self._run(site, heal_commands()))
        return results

    def counters(self) -> dict[str, str]:
        output = {}
        for site in self.endpoints:
            result = self.driver.run(self.endpoints[site], counters_command())
            self.log.append(result)
            output[site] = result.stdout
        return output

    def cleanup(self) -> None:
        for endpoint in self.endpoints.values():
            for command in cleanup_commands(endpoint.interface):
                self.log.append(self.driver.run(endpoint, command))


def parse_drop_counters(output: str) -> list[dict[str, object]]:
    rows = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 9 or parts[2] != "DROP" or not parts[0].isdigit():
            continue
        rows.append(
            {
                "packets": int(parts[0]),
                "bytes": int(parts[1]),
                "source": parts[7],
                "destination": parts[8],
            }
        )
    return rows
