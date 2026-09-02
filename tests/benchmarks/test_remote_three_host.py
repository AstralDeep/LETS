from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.remote_three_host import (
    SCENARIOS,
    SCHEMA,
    PinnedFingerprintPolicy,
    RemoteExperimentError,
    _provision_runtime,
    failure_envelope,
    guarded_remote_child,
    main,
    per_site_timeline_svg,
    phase_end_csv,
    phase_end_markdown,
    phase_end_rows,
    report_markdown,
    reported_uv_version,
    timeline_csv,
    timeline_svg,
)
from benchmarks.nsdi_strengthening.remote_three_host_agent import (
    AgentConfig,
    AgentServer,
    Handler,
    LinkPartitionedError,
    NodeState,
    _peer_mac,
    _safe_endpoint,
)
from lets.crypto import Ed25519Signer


def _config(tmp_path: Path, *, token: str = "not-a-real-secret") -> tuple[Path, AgentConfig]:
    root = tmp_path / "run"
    root.mkdir()
    signers = {alias: Ed25519Signer.generate(alias) for alias in ("s1", "s2", "s3")}
    payload = {
        "alias": "s1",
        "warden_id": "s1",
        "port": 47180,
        "token": token,
        "run_root": str(root),
        "budget": 30,
        "initial_share": 10,
        "initial_lease": 5,
        "seed": base64.b64encode(signers["s1"].seed_bytes).decode(),
        "public_keys": {
            alias: {
                "key_id": signer.key_id,
                "public_key": base64.b64encode(signer.public_key_bytes).decode(),
            }
            for alias, signer in signers.items()
        },
    }
    path = root / "agent-config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, AgentConfig.load(path)


def test_guarded_remote_child_accepts_only_strict_home_children() -> None:
    assert guarded_remote_child("/home/alice", ".lets", "run-12345678") == (
        "/home/alice/.lets/run-12345678"
    )

    for parts in (("..",), ("a/b",), ("",), (".",), ("a\nb",)):
        with pytest.raises(ValueError, match="remote path"):
            guarded_remote_child("/home/alice", *parts)
    with pytest.raises(ValueError, match="absolute normalized"):
        guarded_remote_child("relative/home", "run")
    with pytest.raises(ValueError, match="absolute normalized"):
        guarded_remote_child("/home/alice/../alice", "run")
    with pytest.raises(ValueError, match="absolute normalized"):
        guarded_remote_child("/", "run")


def test_ssh_fingerprint_policy_rejects_before_accepting_unknown_key() -> None:
    class FakeKey:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def get_name(self) -> str:
            return "ssh-ed25519"

        def asbytes(self) -> bytes:
            return self.payload

    key = FakeKey(b"expected-key")
    expected = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()
    policy = PinnedFingerprintPolicy("ssh-ed25519", expected)

    policy.missing_host_key(None, "redacted", key)
    assert policy.verified is True
    with pytest.raises(RemoteExperimentError, match="pinned inventory"):
        PinnedFingerprintPolicy("ssh-ed25519", expected).missing_host_key(
            None, "redacted", FakeKey(b"different-key")
        )


def test_failure_envelope_exposes_stage_but_never_exception_text() -> None:
    payload = failure_envelope(
        RemoteExperimentError(
            "must-not-escape",
            stage="s1:installing pinned CPython",
            reason="remote_command_exit_1",
        )
    )

    assert payload["stage"] == "s1:installing pinned CPython"
    assert payload["reason"] == "remote_command_exit_1"
    assert "must-not-escape" not in json.dumps(payload)


def test_uv_version_parser_accepts_pinned_binary_build_metadata() -> None:
    assert reported_uv_version("uv 0.11.21 (x86_64-unknown-linux-gnu)\n") == "0.11.21"
    assert reported_uv_version("uv 0.11.21\n") == "0.11.21"
    with pytest.raises(RemoteExperimentError, match="malformed"):
        reported_uv_version("uv unknown")


def test_runtime_provision_retries_python_bootstrap_and_reports_attempts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeHost:
        run_root = "/home/tester/run-12345678"

        def __init__(self) -> None:
            self.install_calls = 0
            self.stages: list[str] = []

        def upload(self, _source: Path, _target: str) -> None:
            return

        def _guard(self, _target: str, _action: str, _stage: str) -> None:
            return

        def guard_write(self, _target: str) -> None:
            return

        def run(self, _command: str, *, timeout: float = 120) -> tuple[int, str, str]:
            assert timeout == 900
            self.install_calls += 1
            if self.install_calls == 1:
                return 1, "", "transient"
            return 0, "installed", ""

        def require_run(self, _command: str, stage: str, *, timeout: float = 120) -> str:
            self.stages.append(stage)
            if stage == "validating pinned uv version":
                return "uv 0.11.21 (x86_64-unknown-linux-gnu)"
            if stage == "probing the pinned runtime":
                return '{"python":"3.12.3","lets_agent":"1.0.11"}'
            return ""

    monkeypatch.setattr(
        "benchmarks.nsdi_strengthening.remote_three_host.time.sleep", lambda _: None
    )
    host = FakeHost()

    result = _provision_runtime(  # type: ignore[arg-type]
        host, tmp_path / "source.tgz", tmp_path / "uv.tgz", tmp_path / "agent.py"
    )

    assert result["python_install_attempts"] == 2
    assert host.install_calls == 2
    assert host.stages == [
        "extracting tracked LETS source",
        "extracting pinned uv archive",
        "validating pinned uv version",
        "creating the pinned virtual environment",
        "exporting the frozen dependency set",
        "installing frozen runtime dependencies",
        "installing tracked LETS source",
        "probing the pinned runtime",
    ]


def test_agent_config_must_be_inside_declared_run_root(tmp_path: Path) -> None:
    path, _config_value = _config(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["run_root"] = str(tmp_path / "different")
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="outside run_root"):
        AgentConfig.load(path)


def test_agent_config_binds_alias_to_warden_identity(tmp_path: Path) -> None:
    path, _config_value = _config(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["warden_id"] = "s2"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="same known host alias"):
        AgentConfig.load(path)


def test_peer_endpoint_is_strictly_loopback() -> None:
    assert _safe_endpoint("http://127.0.0.1:47180") == "http://127.0.0.1:47180"
    for endpoint in (
        "http://192.0.2.10:47180",
        "http://localhost:47180",
        "https://127.0.0.1:47180",
    ):
        with pytest.raises(ValueError, match=r"127\.0\.0\.1"):
            _safe_endpoint(endpoint)


def test_agent_uses_real_local_warden_and_executor_sqlite(tmp_path: Path) -> None:
    _path, config = _config(tmp_path)
    state = NodeState(config)
    try:
        outcome = state.authorize("test-authorize-0001")
        snapshot = state.snapshot()
    finally:
        state.close()

    assert outcome["authorized"] is True
    assert outcome["executor_claimed"] is True
    assert snapshot["consumed"] == 1
    assert snapshot["lease_residual"] == 4
    assert snapshot["local_executor_claim_sequence"] == 1
    assert snapshot["healthy"] is True
    assert (config.run_root / "state" / "warden.sqlite3").is_file()
    assert (config.run_root / "state" / "executor.sqlite3").is_file()


def test_peer_hmac_binds_request_and_rejects_nonce_replay(tmp_path: Path) -> None:
    _path, config = _config(tmp_path)
    state = NodeState(config)
    body = b'{"source_alias":"s2"}'
    path = "/peer/ping"
    timestamp = str(int(time.time()))
    nonce = "ab" * 32
    body_sha256 = hashlib.sha256(body).hexdigest()
    authorization = "LETS-HMAC " + _peer_mac(
        config.token, path, timestamp, nonce, body_sha256, "s2"
    )
    arguments = {
        "path": path,
        "source_alias": "s2",
        "timestamp": timestamp,
        "nonce": nonce,
        "body_sha256": body_sha256,
        "authorization": authorization,
        "body": body,
    }
    try:
        assert state.verify_peer_auth(**arguments) is True
        assert state.verify_peer_auth(**arguments) is False
        tampered = {**arguments, "nonce": "cd" * 32, "body": body + b" "}
        assert state.verify_peer_auth(**tampered) is False
    finally:
        state.close()


def test_hmac_http_peer_probe_and_real_transfer(tmp_path: Path) -> None:
    signers = {alias: Ed25519Signer.generate(alias) for alias in ("s1", "s2", "s3")}
    public_keys = {
        alias: (signer.key_id, signer.public_key_bytes) for alias, signer in signers.items()
    }
    states: list[NodeState] = []
    servers: list[AgentServer] = []
    threads: list[threading.Thread] = []
    token = "test-only-shared-hmac-key"
    try:
        for alias in ("s1", "s2"):
            root = tmp_path / alias
            root.mkdir()
            state = NodeState(
                AgentConfig(
                    alias=alias,
                    warden_id=alias,
                    port=47180,
                    token=token,
                    run_root=root,
                    budget=20,
                    initial_share=10,
                    initial_lease=5,
                    seed=signers[alias].seed_bytes,
                    public_keys=public_keys,
                )
            )
            server = AgentServer(("127.0.0.1", 0), Handler)
            server.state = state
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            states.append(state)
            servers.append(server)
            threads.append(thread)

        endpoint = f"http://127.0.0.1:{servers[1].server_address[1]}"
        probe = states[0].peer_ping("s2", endpoint)
        central = states[0].central_proxy("s2", endpoint, "central-integration-s1-0001")
        states[0].close_lease("transfer")
        transfer = states[0].transfer("s2", endpoint, 1, "integration-transfer-s1-s2")

        assert probe["delivered"] is True
        assert probe["transport"] == "peer_tcp_http_hmac"
        assert central["authorized"] is True
        assert central["consumed"] == 1
        assert transfer["delivered"] is True
        assert transfer["finalized"] is True
        assert states[1].snapshot()["transferred_in"] == 1
        states[0].set_link("s2", False)
        with pytest.raises(LinkPartitionedError):
            states[0].peer_ping("s2", endpoint)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        for state in states:
            state.close()


def test_matrix_is_full_factorial_equal_and_seventy_percent_skew() -> None:
    assert {(item.placement, item.workload) for item in SCENARIOS} == {
        ("equal", "equal"),
        ("equal", "70-percent-s1"),
        ("70-percent-s1", "equal"),
        ("70-percent-s1", "70-percent-s1"),
    }
    assert all(sum(item.shares) == 30 for item in SCENARIOS)
    skewed = [item for item in SCENARIOS if item.placement == "70-percent-s1"]
    assert all(item.shares[0] / sum(item.shares) == 0.7 for item in skewed)


def test_report_states_transport_and_host_limitations() -> None:
    result = {
        "status": "passed",
        "run_id": "run-12345678",
        "source": {"commit": "a" * 40, "archive_sha256": "b" * 64},
        "harness": {"sha256": "c" * 64},
        "scope": {
            "remote_write_boundary": "authenticated normalized home only",
            "peer_transport": "controller-mediated relay; not direct",
        },
        "host_evidence": {
            "distinct_address_hashes": 3,
            "distinct_ssh_host_keys": 3,
            "linux_boot_identity": [
                {"boot_id_sha256": character * 64} for character in ("1", "2", "3")
            ],
        },
        "scenarios": [
            {
                "placement": "70-percent-s1",
                "workload": "equal",
                "final_snapshots": [
                    {"authorized": 1, "denied": 0},
                    {"authorized": 1, "denied": 0},
                    {"authorized": 1, "denied": 0},
                ],
                "central_baseline_summary": {"authorized": 2, "denied": 1},
                "recovery": {"transfer": {"source": "s2", "target": "s1", "amount": 1}},
                "aggregate_final": {
                    "consumed": 3,
                    "conservation_holds": True,
                    "initial_share": 30,
                },
                "name": "skew70-placement-equal-workload",
                "timeline": [
                    {
                        "step": 0,
                        "phase": "normal",
                        "site": "s1",
                        "lets_authorized": True,
                        "central_authorized": True,
                        "actions_remaining_at_site": 9,
                        "stranded_on_blocked_peer": 0,
                    }
                ],
            }
        ],
        "assertions": {"failures": []},
    }

    report = report_markdown(result)

    assert "not prove physical-machine" in report
    assert "not a direct endpoint-to-endpoint route" in report
    assert "Inter-warden authentication" in report
    assert "HMAC-SHA256" in report
    assert "production rollback protection" in report
    assert report.startswith("# LETS three-endpoint development experiment")
    assert "## Endpoint and transport evidence" in report
    assert "## Partitioned local progress" in report
    assert (
        "| Initial placement | Demand | Partitioned wardens | Central counter | "
        "Post-heal transfer |" in report
    )
    assert "| 70% at s1 | Equal | 3/0 | 2/1 | s2→s1, 1 |" in report
    assert "Every row conserved its 30-unit envelope." in report
    assert "warden debit equaled the authorized count" in report
    assert "70-percent-s1" not in report
    assert "Full-factorial placement/workload matrix" not in report
    report_table = report.split("## Partitioned local progress\n\n", 1)[1].split("\n\n", 1)[0]
    assert "Consumed" not in report_table
    assert "Conservation" not in report_table
    assert "warden debit" not in report_table

    rendered_csv = timeline_csv(result)
    assert "placement,workload" in rendered_csv
    assert "skew70-placement-equal-workload,70-percent-s1,equal" in rendered_csv

    aggregate_svg = timeline_svg(result)
    aggregate_text = " ".join(ET.fromstring(aggregate_svg).itertext())
    assert "Cumulative authorized operations for four fixed schedules" in aggregate_text
    assert "(a) 70% s1 authority / equal demand" in aggregate_text
    assert "partitioned wardens" in aggregate_text
    assert "central counter" in aggregate_text
    assert "70-percent-s1" not in aggregate_text
    assert "LETS" not in aggregate_text


def _supplemental_result() -> dict[str, object]:
    combinations = (
        ("equal", "equal"),
        ("equal", "70-percent-s1"),
        ("70-percent-s1", "equal"),
        ("70-percent-s1", "70-percent-s1"),
    )
    scenarios: list[dict[str, object]] = []
    for index, (placement, workload) in enumerate(combinations):
        snapshots: dict[str, list[dict[str, object]]] = {}
        for phase, authorized, remaining in (
            ("normal", 1, 9),
            ("partition", 2, 8),
            ("recovery", 3, 7),
        ):
            snapshots[phase] = [
                {
                    "alias": alias,
                    "authorized": authorized,
                    "denied": 0,
                    "actions_remaining": remaining,
                    "stranded_on_blocked_peer": (
                        8 if phase == "partition" and alias in {"s1", "s2"} else 0
                    ),
                }
                for alias in ("s1", "s2", "s3")
            ]
        timeline = []
        for phase_index, phase in enumerate(("normal", "partition", "recovery")):
            for site_index, alias in enumerate(("s1", "s2", "s3")):
                timeline.append(
                    {
                        "step": phase_index * 3 + site_index,
                        "phase": phase,
                        "site": alias,
                        "lets_authorized": True,
                        "central_authorized": True,
                        "site_authorized_cumulative": phase_index + 1,
                        "site_denied_cumulative": 0,
                        "actions_remaining_at_site": 9 - phase_index,
                        "stranded_on_blocked_peer": (
                            8 if phase == "partition" and alias in {"s1", "s2"} else 0
                        ),
                    }
                )
        scenarios.append(
            {
                "name": f"scenario-{index}",
                "placement": placement,
                "workload": workload,
                "shares": {"s1": 10, "s2": 10, "s3": 10},
                "initial_snapshots": [
                    {
                        "alias": alias,
                        "authorized": 0,
                        "denied": 0,
                        "actions_remaining": 10,
                        "stranded_on_blocked_peer": 0,
                    }
                    for alias in ("s1", "s2", "s3")
                ],
                "normal": {"snapshots": snapshots["normal"]},
                "partition": {"snapshots": snapshots["partition"]},
                "recovery": {
                    "snapshots": snapshots["recovery"],
                    "transfer": {"source": "s2", "target": "s1", "amount": 1},
                },
                "timeline": timeline,
                "central_baseline_summary": {
                    "per_site": {
                        alias: {"authorized": 2, "denied": 1} for alias in ("s1", "s2", "s3")
                    }
                },
            }
        )
    return {"schema": SCHEMA, "scenarios": scenarios}


def test_supplemental_phase_end_renderers_are_explicit_and_deterministic() -> None:
    result = _supplemental_result()

    rows = phase_end_rows(result)
    rendered_csv = phase_end_csv(result)
    rendered_markdown = phase_end_markdown(result)

    assert len(rows) == 12
    assert rows[0] == {
        "scenario": "scenario-0",
        "placement": "equal",
        "workload": "equal",
        "site": "s1",
        "initial_share": 10,
        "central_authorized": 2,
        "central_denied": 1,
        "transfer_source": "s2",
        "transfer_target": "s1",
        "transfer_amount": 1,
        "normal_authorized": 1,
        "normal_denied": 0,
        "normal_actions_remaining": 9,
        "normal_stranded": 0,
        "partition_authorized": 2,
        "partition_denied": 0,
        "partition_actions_remaining": 8,
        "partition_stranded": 8,
        "recovery_authorized": 3,
        "recovery_denied": 0,
        "recovery_actions_remaining": 7,
        "recovery_stranded": 0,
    }
    assert rendered_csv.count("\n") == 13
    assert "normal_authorized" in rendered_csv
    assert "placement,workload" in rendered_csv
    assert "70-percent-s1" in rendered_csv
    assert rendered_markdown.startswith("# LETS three-endpoint per-site phase endpoints")
    assert (
        "| Initial placement | Demand | Site | Initial authority | Pre-gate A/D/R/S | "
        "Application-path gate A/D/R/S | Recovery A/D/R/S | Central counter A/D | "
        "Post-heal transfer |" in rendered_markdown
    )
    ordered_rows = (
        "| Equal | Equal | s1 |",
        "| Equal | 70% at s1 | s1 |",
        "| 70% at s1 | Equal | s1 |",
        "| 70% at s1 | 70% at s1 | s1 |",
    )
    assert [rendered_markdown.index(row) for row in ordered_rows] == sorted(
        rendered_markdown.index(row) for row in ordered_rows
    )
    assert rendered_markdown.count("| Equal | Equal | s1 |") == 1
    assert "s2→s1, 1" in rendered_markdown
    assert "70-percent-s1" not in rendered_markdown
    assert "Normal A/D/R/S" not in rendered_markdown
    assert "| Placement | Workload |" not in rendered_markdown
    assert phase_end_csv(result) == rendered_csv
    assert phase_end_markdown(result) == rendered_markdown


def test_per_site_timeline_is_four_by_three_and_exposes_all_four_metrics() -> None:
    svg = per_site_timeline_svg(_supplemental_result())

    visible_text = " ".join(ET.fromstring(svg).itertext())
    assert svg.count('<g class="site-panel"') == 12
    assert svg.count('class="partition-window"') == 12
    assert svg.count('data-metric="authorized"') == 12
    assert svg.count('data-metric="denied"') == 12
    assert svg.count('data-metric="remaining"') == 12
    assert svg.count('data-metric="stranded"') == 12
    assert "fixed y-axis 0-30" in svg
    assert "Per-site state over the retained three-endpoint experiment" in visible_text
    assert "Per-site warden state over time" in visible_text
    assert "equal authority / equal demand · s1" in visible_text
    assert "70% s1 authority / 70% s1 demand · s3" in visible_text
    assert "70-percent-s1" not in visible_text
    assert 'data-scenario="70-percent-s1 placement / equal workload"' in svg
    assert per_site_timeline_svg(_supplemental_result()) == svg


def test_aggregate_timeline_uses_paper_labels_in_canonical_order() -> None:
    svg = timeline_svg(_supplemental_result())
    visible_text = " ".join(ET.fromstring(svg).itertext())

    labels = (
        "(a) equal authority / equal demand",
        "(b) equal authority / 70% s1 demand",
        "(c) 70% s1 authority / equal demand",
        "(d) 70% s1 authority / 70% s1 demand",
    )
    assert [visible_text.index(label) for label in labels] == sorted(
        visible_text.index(label) for label in labels
    )
    assert visible_text.count("partitioned wardens") == 4
    assert visible_text.count("central counter") == 4
    assert "70-percent-s1" not in visible_text
    assert "placement /" not in visible_text
    assert "workload" not in visible_text
    assert "LETS" not in visible_text


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("placement", "unsupported placement display token"),
        ("workload", "unsupported demand display token"),
    ),
)
def test_human_renderers_reject_unknown_scenario_display_tokens(field: str, message: str) -> None:
    result = _supplemental_result()
    scenarios = result["scenarios"]
    assert isinstance(scenarios, list)
    assert isinstance(scenarios[0], dict)
    scenarios[0][field] = "unmapped"

    with pytest.raises(ValueError, match=message):
        phase_end_markdown(result)
    with pytest.raises(ValueError, match=message):
        per_site_timeline_svg(result)
    with pytest.raises(ValueError, match=message):
        timeline_svg(result)


def test_render_existing_mode_is_local_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    retained = tmp_path / "retained.json"
    output = tmp_path / "rendered"
    retained.write_text(json.dumps(_supplemental_result()), encoding="utf-8")

    def fail_if_remote_called(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("remote experiment must not run in retained-result mode")

    monkeypatch.setattr(
        "benchmarks.nsdi_strengthening.remote_three_host.run_experiment",
        fail_if_remote_called,
    )
    monkeypatch.setattr(
        "sys.argv",
        [
            "remote_three_host",
            "--render-existing",
            str(retained),
            "--output-dir",
            str(output),
        ],
    )

    assert main() == 0
    assert (output / "three-host-linux-per-site-timeline.svg").is_file()
    assert (output / "three-host-linux-phase-end.csv").is_file()
    assert (output / "three-host-linux-phase-end.md").is_file()
    assert not (output / "three-host-linux-result.json").exists()
