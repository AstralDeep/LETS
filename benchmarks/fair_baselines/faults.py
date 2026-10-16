"""Kernel-level fault injection for E1: builds the iptables cut/heal and tc netem commands for a
topology, runs them on each site through a per-site privileged command prefix (docker exec locally)
or a persistent sudo-over-SSH session (remote endpoints), and turns a topology plus phase timings
into a timed schedule the controller executes while a run is in flight.
"""

from __future__ import annotations

import contextlib
import shlex
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from benchmarks.fair_baselines.common import Topology, site_alias

CHAIN = "LETS_E1"


@dataclass(frozen=True, slots=True)
class SSHTarget:
    host: str
    user: str
    key_file: str
    port: int = 22
    prefix: tuple[str, ...] = ("sudo", "-n")

    @classmethod
    def from_dict(cls, site: str, payload: Mapping[str, object]) -> SSHTarget:
        for key in ("host", "user", "key_file"):
            if not isinstance(payload.get(key), str) or not payload[key]:
                raise ValueError(f"{site}: fault_ssh.{key} must be a non-empty string")
        prefix = payload.get("prefix", ("sudo", "-n"))
        if not isinstance(prefix, Sequence) or isinstance(prefix, str):
            raise ValueError(f"{site}: fault_ssh.prefix must be a command prefix list")
        return cls(
            host=str(payload["host"]),
            user=str(payload["user"]),
            key_file=str(payload["key_file"]),
            port=int(payload.get("port", 22)),  # type: ignore[call-overload]
            prefix=tuple(str(part) for part in prefix),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "user": self.user,
            "key_file": self.key_file,
            "port": self.port,
            "prefix": list(self.prefix),
        }

    def remote_command(self, command: str) -> str:
        return " ".join([*self.prefix, "sh", "-c", shlex.quote(command)])


@dataclass(frozen=True, slots=True)
class SiteEndpoint:
    site: str
    control_url: str
    peer_ip: str
    peer_port: int
    raft_port: int
    fault_exec: tuple[str, ...]
    interface: str = "eth0"
    fault_exec_quote: bool = False
    fault_ssh: SSHTarget | None = None

    @property
    def peer_url(self) -> str:
        return f"http://{self.peer_ip}:{self.peer_port}"

    @property
    def raft_address(self) -> str:
        return f"{self.peer_ip}:{self.raft_port}"

    @classmethod
    def from_dict(cls, site: str, payload: Mapping[str, object]) -> SiteEndpoint:
        site_alias(site, "site")
        ssh_payload = payload.get("fault_ssh")
        fault_ssh = None
        if ssh_payload is not None:
            if not isinstance(ssh_payload, Mapping):
                raise ValueError(f"{site}: fault_ssh must be a mapping")
            fault_ssh = SSHTarget.from_dict(site, ssh_payload)
        fault_exec = payload.get("fault_exec", ())
        if isinstance(fault_exec, str) or not isinstance(fault_exec, Sequence):
            raise ValueError(f"{site}: fault_exec must be a command prefix list")
        if not fault_exec and fault_ssh is None:
            raise ValueError(f"{site}: fault_exec must be a non-empty command prefix list")
        return cls(
            site=site,
            control_url=str(payload["control_url"]).rstrip("/"),
            peer_ip=str(payload["peer_ip"]),
            peer_port=int(payload["peer_port"]),  # type: ignore[call-overload]
            raft_port=int(payload["raft_port"]),  # type: ignore[call-overload]
            fault_exec=tuple(str(part) for part in fault_exec),
            interface=str(payload.get("interface", "eth0")),
            fault_exec_quote=bool(payload.get("fault_exec_quote", False)),
            fault_ssh=fault_ssh,
        )

    def to_dict(self) -> dict[str, object]:
        document: dict[str, object] = {
            "control_url": self.control_url,
            "peer_ip": self.peer_ip,
            "peer_port": self.peer_port,
            "raft_port": self.raft_port,
            "fault_exec": list(self.fault_exec),
            "interface": self.interface,
            "fault_exec_quote": self.fault_exec_quote,
        }
        if self.fault_ssh is not None:
            document["fault_ssh"] = self.fault_ssh.to_dict()
        return document


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
        argument = shlex.quote(command) if endpoint.fault_exec_quote else command
        completed = subprocess.run(
            [*endpoint.fault_exec, argument],
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


def _connect_ssh(target: SSHTarget) -> Any:
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        target.host,
        port=target.port,
        username=target.user,
        key_filename=target.key_file,
        timeout=20.0,
        banner_timeout=20.0,
        auth_timeout=20.0,
        look_for_keys=False,
        allow_agent=False,
    )
    client.get_transport().set_keepalive(15)
    return client


class SSHFaultDriver:
    def __init__(
        self,
        timeout_s: float = 30.0,
        client_factory: Callable[[SSHTarget], Any] = _connect_ssh,
    ) -> None:
        self.timeout_s = timeout_s
        self._client_factory = client_factory
        self._clients: dict[str, Any] = {}
        self._lock = threading.Lock()

    def _client(self, endpoint: SiteEndpoint) -> Any:
        client = self._clients.get(endpoint.site)
        transport = client.get_transport() if client is not None else None
        if transport is None or not transport.is_active():
            self._drop(endpoint.site)
            if endpoint.fault_ssh is None:
                raise ValueError(f"{endpoint.site}: endpoint has no fault_ssh target")
            client = self._client_factory(endpoint.fault_ssh)
            self._clients[endpoint.site] = client
        return client

    def _drop(self, site: str) -> None:
        client = self._clients.pop(site, None)
        if client is not None:
            with contextlib.suppress(Exception):
                client.close()

    def _execute(self, endpoint: SiteEndpoint, remote: str) -> tuple[int, str, str]:
        client = self._client(endpoint)
        _, stdout, stderr = client.exec_command(remote, timeout=self.timeout_s)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        return stdout.channel.recv_exit_status(), out, err

    def run(self, endpoint: SiteEndpoint, command: str) -> CommandResult:
        if endpoint.fault_ssh is None:
            raise ValueError(f"{endpoint.site}: endpoint has no fault_ssh target")
        remote = endpoint.fault_ssh.remote_command(command)
        sent = time.time_ns()
        with self._lock:
            try:
                returncode, out, err = self._execute(endpoint, remote)
            except Exception as first:
                self._drop(endpoint.site)
                try:
                    returncode, out, err = self._execute(endpoint, remote)
                except Exception as second:
                    self._drop(endpoint.site)
                    returncode, out, err = 255, "", f"ssh session failed twice: {first}; {second}"
        return CommandResult(endpoint.site, command, returncode, out, err, sent, time.time_ns())

    def close(self) -> None:
        with self._lock:
            for site in list(self._clients):
                self._drop(site)


class EndpointFaultDriver:
    def __init__(self, timeout_s: float = 30.0) -> None:
        self.subprocess = SubprocessFaultDriver(timeout_s)
        self.ssh = SSHFaultDriver(timeout_s)

    def run(self, endpoint: SiteEndpoint, command: str) -> CommandResult:
        if endpoint.fault_ssh is not None:
            return self.ssh.run(endpoint, command)
        return self.subprocess.run(endpoint, command)

    def close(self) -> None:
        self.ssh.close()


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
            if len(link) != 2 or not link <= set(self.endpoints):
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
