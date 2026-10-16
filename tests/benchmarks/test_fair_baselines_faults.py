"""Tests for benchmarks/fair_baselines/faults.py: command construction for iptables and netem,
the timed cut/heal schedule including flapping, the injector over a recording driver for three
and seven endpoints, the subprocess driver, and drop-counter parsing.
"""

from __future__ import annotations

import itertools
import shlex
import sys

import pytest

from benchmarks.fair_baselines.common import LINKS, TOPOLOGIES, resolve_topology
from benchmarks.fair_baselines.faults import (
    CHAIN,
    DryRunFaultDriver,
    EndpointFaultDriver,
    FaultInjector,
    SiteEndpoint,
    SSHFaultDriver,
    SSHTarget,
    SubprocessFaultDriver,
    cleanup_commands,
    counters_command,
    cut_commands,
    fault_schedule,
    heal_commands,
    link_label,
    netem_commands,
    parse_drop_counters,
    setup_commands,
)

SEVEN = ("uk1", "uk2", "az1", "use2", "usw2", "euw2", "apse1")


def _endpoints(sites: tuple[str, ...] = ("s1", "s2", "s3")) -> dict[str, SiteEndpoint]:
    return {
        site: SiteEndpoint(
            site, f"http://127.0.0.1:97{index:02d}", f"10.231.0.{10 + index}", 9701, 9801, ("dry",)
        )
        for index, site in enumerate(sites, start=1)
    }


def test_command_builders() -> None:
    assert f"iptables -N {CHAIN}" in setup_commands()[0]
    assert cut_commands("10.0.0.2") == (
        f"iptables -A {CHAIN} -s 10.0.0.2 -j DROP",
        f"iptables -A {CHAIN} -d 10.0.0.2 -j DROP",
    )
    assert "'" in cut_commands("10.0.0.2; rm -rf /")[0]
    assert heal_commands() == (f"iptables -F {CHAIN}",)
    assert counters_command().startswith(f"iptables -L {CHAIN}")
    assert netem_commands("eth0", 25, 0) == ("tc qdisc replace dev eth0 root netem delay 25ms",)
    assert netem_commands("eth0", 25, 1.5) == (
        "tc qdisc replace dev eth0 root netem delay 25ms loss 1.5%",
    )
    assert netem_commands("eth0", 0, 0)[0].startswith("tc qdisc del")
    with pytest.raises(ValueError):
        netem_commands("eth0", -1, 0)
    assert any("-X" in command for command in cleanup_commands("eth0"))
    assert link_label(frozenset({"s2", "s1"})) == "s1-s2"


def test_fault_schedule_static_and_flapping() -> None:
    static = fault_schedule(TOPOLOGIES["split-s1"], 5.0, 30.0)
    assert [(event.offset_s, event.kind) for event in static] == [(5.0, "cut"), (35.0, "heal")]
    assert static[0].links == TOPOLOGIES["split-s1"].cut_links
    flapping = fault_schedule(TOPOLOGIES["flapping-s1-s2"], 5.0, 30.0)
    kinds = [event.kind for event in flapping]
    assert kinds[0] == "cut" and kinds[-1] == "heal"
    assert len(flapping) == 11
    assert all(later.offset_s > earlier.offset_s for earlier, later in itertools.pairwise(flapping))
    assert flapping[-1].offset_s == 35.0
    seven = fault_schedule(resolve_topology("halves", SEVEN), 5.0, 30.0)
    assert [(event.offset_s, event.kind) for event in seven] == [(5.0, "cut"), (35.0, "heal")]
    assert len(seven[0].links) == 12


def test_injector_runs_setup_cut_heal_counters_and_cleanup() -> None:
    driver = DryRunFaultDriver()
    injector = FaultInjector(driver, _endpoints())
    injector.prepare(25, 0.0)
    assert all(site in {"s1", "s2", "s3"} for site, _ in driver.commands)
    assert sum(1 for _, command in driver.commands if "netem" in command) == 3
    results = injector.cut({LINKS[0]})
    assert [result.site for result in results] == ["s1", "s1", "s2", "s2"]
    assert "10.231.0.12" in results[0].command and "10.231.0.11" in results[2].command
    with pytest.raises(ValueError, match="unknown link"):
        injector.cut({frozenset({"s1", "s4"})})
    healed = injector.heal()
    assert [result.site for result in healed] == ["s1", "s2", "s3"]
    assert set(injector.counters()) == {"s1", "s2", "s3"}
    injector.cleanup()
    assert len(injector.log) == len(driver.commands)


def test_injector_cuts_every_link_of_a_seven_site_topology() -> None:
    driver = DryRunFaultDriver()
    endpoints = _endpoints(SEVEN)
    injector = FaultInjector(driver, endpoints)
    injector.prepare(0, 0.0)
    assert sum(1 for _, command in driver.commands if "qdisc del" in command) == 7
    isolate = injector.cut(resolve_topology("isolate-use2", SEVEN).cut_links)
    assert len(isolate) == 6 * 4
    assert {result.site for result in isolate} == set(SEVEN)
    assert sum(1 for result in isolate if result.site == "use2") == 12
    others = [result for result in isolate if result.site != "use2"]
    assert all(endpoints["use2"].peer_ip in result.command for result in others)
    full = injector.cut(resolve_topology("full-isolation", SEVEN).cut_links)
    assert len(full) == 21 * 4
    with pytest.raises(ValueError, match="unknown link"):
        injector.cut({frozenset({"uk1", "s1"})})
    with pytest.raises(ValueError, match="unknown link"):
        injector.cut({frozenset({"uk1"})})
    assert [result.site for result in injector.heal()] == list(SEVEN)


def test_injector_reports_failing_commands() -> None:
    class FailingDriver:
        def run(self, endpoint: SiteEndpoint, command: str):  # type: ignore[no-untyped-def]
            return (
                DryRunFaultDriver()
                .run(endpoint, command)
                .__class__(endpoint.site, command, 2, "", "iptables: not permitted", 0, 0)
            )

    injector = FaultInjector(FailingDriver(), _endpoints())
    with pytest.raises(RuntimeError, match="not permitted"):
        injector.heal()


def test_subprocess_driver_runs_prefix_plus_command() -> None:
    endpoint = SiteEndpoint(
        "s1",
        "http://127.0.0.1:1",
        "127.0.0.1",
        1,
        2,
        (sys.executable, "-c", "import sys; print(sys.argv[1]); sys.exit(int(sys.argv[1][-1]))"),
    )
    result = SubprocessFaultDriver().run(endpoint, "echo-0")
    assert result.ok and result.stdout.strip() == "echo-0"
    assert result.returned_wall_ns >= result.sent_wall_ns
    assert SubprocessFaultDriver().run(endpoint, "echo-3").returncode == 3


def test_subprocess_driver_quotes_the_command_for_a_remote_shell() -> None:
    prefix = (sys.executable, "-c", "import sys; print(sys.argv[1])")
    command = "iptables -N LETS_E1 2>/dev/null || true; iptables -F LETS_E1"
    raw = SiteEndpoint("s1", "http://127.0.0.1:1", "127.0.0.1", 1, 2, prefix)
    quoted = SiteEndpoint("s1", "http://127.0.0.1:1", "127.0.0.1", 1, 2, prefix, "eth0", True)
    assert SubprocessFaultDriver().run(raw, command).stdout.strip() == command
    assert SubprocessFaultDriver().run(quoted, command).stdout.strip() == shlex.quote(command)


class _FakeChannel:
    def __init__(self, status: int) -> None:
        self._status = status

    def recv_exit_status(self) -> int:
        return self._status


class _FakeStream:
    def __init__(self, text: str, status: int = 0) -> None:
        self._text = text.encode()
        self.channel = _FakeChannel(status)

    def read(self) -> bytes:
        return self._text


class _FakeTransport:
    def __init__(self) -> None:
        self.active = True

    def is_active(self) -> bool:
        return self.active


class _FakeSSHClient:
    def __init__(self, fail_times: int = 0) -> None:
        self.transport = _FakeTransport()
        self.commands: list[str] = []
        self.fail_times = fail_times
        self.closed = False

    def get_transport(self) -> _FakeTransport:
        return self.transport

    def exec_command(self, remote: str, timeout: float) -> tuple[None, _FakeStream, _FakeStream]:
        if self.fail_times:
            self.fail_times -= 1
            raise OSError("socket closed")
        self.commands.append(remote)
        return None, _FakeStream(remote, 0), _FakeStream("", 0)

    def close(self) -> None:
        self.closed = True


def _ssh_endpoint() -> SiteEndpoint:
    return SiteEndpoint.from_dict(
        "s1",
        {
            "control_url": "http://127.0.0.1:9711",
            "peer_ip": "203.0.113.11",
            "peer_port": 9701,
            "raft_port": 9801,
            "interface": "eno50",
            "fault_ssh": {"host": "203.0.113.11", "user": "sam", "key_file": "/keys/e1"},
        },
    )


def test_ssh_driver_reuses_one_session_and_quotes_through_sudo() -> None:
    clients: list[_FakeSSHClient] = []

    def factory(target: SSHTarget) -> _FakeSSHClient:
        assert (target.host, target.user, target.key_file, target.port) == (
            "203.0.113.11",
            "sam",
            "/keys/e1",
            22,
        )
        clients.append(_FakeSSHClient())
        return clients[-1]

    driver = SSHFaultDriver(client_factory=factory)
    endpoint = _ssh_endpoint()
    command = "iptables -N LETS_E1 2>/dev/null || true; iptables -F LETS_E1"
    first = driver.run(endpoint, command)
    second = driver.run(endpoint, "iptables -F LETS_E1")
    assert first.ok and second.ok and first.command == command
    assert first.stdout == "sudo -n sh -c " + shlex.quote(command)
    assert len(clients) == 1 and clients[0].commands[1] == "sudo -n sh -c 'iptables -F LETS_E1'"
    assert first.returned_wall_ns >= first.sent_wall_ns
    driver.close()
    assert clients[0].closed


def test_ssh_driver_reconnects_once_then_reports_failure() -> None:
    made: list[_FakeSSHClient] = []

    def flaky(_target: SSHTarget) -> _FakeSSHClient:
        made.append(_FakeSSHClient(fail_times=0 if made else 1))
        return made[-1]

    driver = SSHFaultDriver(client_factory=flaky)
    endpoint = _ssh_endpoint()
    assert driver.run(endpoint, "iptables -F LETS_E1").ok
    assert len(made) == 2 and made[0].closed and not made[1].closed

    def dead(_target: SSHTarget) -> _FakeSSHClient:
        return _FakeSSHClient(fail_times=5)

    broken = SSHFaultDriver(client_factory=dead)
    result = broken.run(endpoint, "iptables -F LETS_E1")
    assert result.returncode == 255 and "ssh session failed twice" in result.stderr
    with pytest.raises(ValueError, match="fault_ssh"):
        SSHFaultDriver(client_factory=dead).run(
            SiteEndpoint("s1", "http://127.0.0.1:1", "127.0.0.1", 1, 2, ("docker", "exec", "x")),
            "true",
        )


def test_endpoint_driver_routes_by_endpoint_kind() -> None:
    driver = EndpointFaultDriver()
    fake = _FakeSSHClient()
    driver.ssh = SSHFaultDriver(client_factory=lambda _target: fake)
    assert driver.run(_ssh_endpoint(), "iptables -F LETS_E1").ok
    assert fake.commands == ["sudo -n sh -c 'iptables -F LETS_E1'"]
    local = SiteEndpoint(
        "s2",
        "http://127.0.0.1:1",
        "127.0.0.1",
        1,
        2,
        (sys.executable, "-c", "import sys; print(sys.argv[1])"),
    )
    assert driver.run(local, "echo-0").stdout.strip() == "echo-0"
    driver.close()


def test_endpoint_parsing_and_drop_counter_parsing() -> None:
    endpoint = SiteEndpoint.from_dict(
        "s2",
        {
            "control_url": "http://127.0.0.1:9702/",
            "peer_ip": "10.231.0.12",
            "peer_port": 9701,
            "raft_port": 9801,
            "fault_exec": ["docker", "exec", "x", "sh", "-c"],
        },
    )
    assert endpoint.control_url == "http://127.0.0.1:9702"
    assert endpoint.peer_url == "http://10.231.0.12:9701"
    assert endpoint.raft_address == "10.231.0.12:9801"
    assert endpoint.to_dict()["fault_exec"] == ["docker", "exec", "x", "sh", "-c"]
    assert endpoint.fault_exec_quote is False
    assert endpoint.to_dict()["fault_exec_quote"] is False
    remote = SiteEndpoint.from_dict(
        "s3",
        {
            "control_url": "http://127.0.0.1:9713",
            "peer_ip": "203.0.113.10",
            "peer_port": 9701,
            "raft_port": 9801,
            "interface": "eno1",
            "fault_exec": ["ssh", "user@203.0.113.10", "sudo", "-n", "sh", "-c"],
            "fault_exec_quote": True,
        },
    )
    assert remote.fault_exec_quote is True and remote.interface == "eno1"
    assert remote.to_dict()["fault_exec_quote"] is True
    with pytest.raises(ValueError, match="site alias"):
        SiteEndpoint.from_dict("s-4", {})
    with pytest.raises(ValueError, match="fault_exec"):
        SiteEndpoint.from_dict("s4", {})
    over_ssh = SiteEndpoint.from_dict(
        "s4",
        {
            "control_url": "http://127.0.0.1:9714",
            "peer_ip": "203.0.113.14",
            "peer_port": 9701,
            "raft_port": 9801,
            "interface": "ens5",
            "fault_ssh": {"host": "203.0.113.14", "user": "ubuntu", "key_file": "/keys/e1"},
        },
    )
    assert over_ssh.fault_exec == () and over_ssh.fault_ssh is not None
    assert over_ssh.fault_ssh.prefix == ("sudo", "-n") and over_ssh.fault_ssh.port == 22
    assert over_ssh.to_dict()["fault_ssh"] == {
        "host": "203.0.113.14",
        "user": "ubuntu",
        "key_file": "/keys/e1",
        "port": 22,
        "prefix": ["sudo", "-n"],
    }
    assert over_ssh.fault_ssh.remote_command("tc qdisc del dev ens5 root") == (
        "sudo -n sh -c 'tc qdisc del dev ens5 root'"
    )
    with pytest.raises(ValueError, match=r"fault_ssh\.key_file"):
        SiteEndpoint.from_dict(
            "s4",
            {
                "control_url": "http://127.0.0.1:9714",
                "peer_ip": "203.0.113.14",
                "peer_port": 9701,
                "raft_port": 9801,
                "fault_ssh": {"host": "203.0.113.14", "user": "ubuntu"},
            },
        )
    with pytest.raises(ValueError, match="fault_exec"):
        SiteEndpoint.from_dict("s1", {"fault_exec": "docker"})
    output = (
        "Chain LETS_E1 (2 references)\n"
        "    pkts      bytes target     prot opt in     out     source               destination\n"
        "      72       5822 DROP       0    --  *      *       0.0.0.0/0            10.231.0.12\n"
        "       7       1210 DROP       0    --  *      *       10.231.0.12          0.0.0.0/0\n"
    )
    rows = parse_drop_counters(output)
    assert rows == [
        {"packets": 72, "bytes": 5822, "source": "0.0.0.0/0", "destination": "10.231.0.12"},
        {"packets": 7, "bytes": 1210, "source": "10.231.0.12", "destination": "0.0.0.0/0"},
    ]
    assert parse_drop_counters("") == []
