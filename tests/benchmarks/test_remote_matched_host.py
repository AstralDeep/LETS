from __future__ import annotations

import base64
import hashlib
import io
import json
import stat
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from benchmarks.nsdi_strengthening.matched_host_path import (
    EXPECTED_ASTRALDEEP_COMMIT,
    EXPECTED_COMPONENTS,
    OUTPUT_CSV,
    OUTPUT_JSON,
    OUTPUT_MARKDOWN,
)
from benchmarks.nsdi_strengthening.remote_cluster import Credential
from benchmarks.nsdi_strengthening.remote_matched_host import (
    EXPECTED_REPLACEMENT_SQLITE,
    UV_ARCHIVE_SHA256,
    PinnedFingerprintPolicy,
    RecoveryCandidate,
    RemoteMatchedHostError,
    RemoteSession,
    _load_recovery_candidate,
    _recovery_timing,
    _safe_recovery_roots,
    _write_retained,
    benchmark_command,
    guarded_remote_child,
    load_s1_inventory,
    sanitize_artifacts,
    select_latest_recovery_candidate,
    validate_benchmark_artifacts,
    verify_address_pin,
)


class _Key:
    def __init__(self, payload: bytes = b"pinned-key") -> None:
        self.payload = payload

    def asbytes(self) -> bytes:
        return self.payload

    def get_name(self) -> str:
        return "ssh-ed25519"


def _fingerprint(key: _Key) -> str:
    return base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii")


def _inventory(home: str = "/home/runner", key: _Key | None = None) -> dict[str, object]:
    selected_key = key or _Key()
    host = "192.0.2.10"
    return {
        "alias": "s1",
        "inventory_ok": True,
        "connected": True,
        "kernel": "Linux",
        "architecture": "x86_64",
        "home_absolute": True,
        "home_normalized": True,
        "home_owned": True,
        "login_matches_credential": True,
        "address_sha256": hashlib.sha256(host.encode()).hexdigest(),
        "host_key_type": "ssh-ed25519",
        "host_key_sha256": _fingerprint(selected_key),
        "home_path_sha256": hashlib.sha256(home.encode()).hexdigest(),
    }


def test_pinned_policy_accepts_only_the_exact_host_key() -> None:
    key = _Key()
    policy = PinnedFingerprintPolicy("ssh-ed25519", _fingerprint(key))

    policy.missing_host_key(None, "unretained-address", key)

    assert policy.verified is True
    with pytest.raises(RemoteMatchedHostError, match="host key"):
        PinnedFingerprintPolicy("ssh-ed25519", _fingerprint(key)).missing_host_key(
            None, "unretained-address", _Key(b"wrong")
        )


def test_address_pin_is_checked_without_exposing_the_address() -> None:
    credential = Credential("s1", "192.0.2.10", "runner", "secret")
    verify_address_pin(credential, _inventory())

    with pytest.raises(RemoteMatchedHostError, match="pinned inventory") as raised:
        verify_address_pin(Credential("s1", "192.0.2.11", "runner", "secret"), _inventory())
    assert "192.0.2" not in str(raised.value)


def test_inventory_loader_requires_a_safe_linux_s1_record(tmp_path: Path) -> None:
    payload = {
        "schema": "lets.remote-cluster-inventory/v1",
        "addresses_retained": False,
        "servers": [_inventory()],
    }
    inventory = tmp_path / "inventory.json"
    inventory.write_text(json.dumps(payload), encoding="utf-8")

    assert load_s1_inventory(inventory)["alias"] == "s1"

    payload["servers"][0]["home_owned"] = False
    inventory.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="home_owned"):
        load_s1_inventory(inventory)


class _Channel:
    def recv_exit_status(self) -> int:
        return 0


class _Stream:
    def __init__(self, payload: bytes = b"") -> None:
        self.payload = payload
        self.channel = _Channel()

    def read(self) -> bytes:
        return self.payload


class _SFTP:
    def normalize(self, path: str) -> str:
        return path

    def close(self) -> None:
        return None


class _Transport:
    def __init__(self, key: _Key) -> None:
        self.key = key

    def is_active(self) -> bool:
        return True

    def get_remote_server_key(self) -> _Key:
        return self.key


class _Client:
    def __init__(self, key: _Key, home: str) -> None:
        self.key = key
        self.home = home
        self.policy: PinnedFingerprintPolicy | None = None
        self.connect_values: dict[str, object] = {}

    def set_missing_host_key_policy(self, policy: PinnedFingerprintPolicy) -> None:
        self.policy = policy

    def connect(self, host: str, **values: object) -> None:
        self.connect_values = {"host": host, **values}
        assert self.policy is not None
        self.policy.missing_host_key(self, host, self.key)

    def get_transport(self) -> _Transport:
        return _Transport(self.key)

    def open_sftp(self) -> _SFTP:
        return _SFTP()

    def exec_command(self, _command: str, **_values: object) -> tuple[None, _Stream, _Stream]:
        record = {
            "home": self.home,
            "uid": 1000,
            "owned": True,
            "normalized": True,
            "pwd_home_matches": True,
        }
        return None, _Stream(json.dumps(record).encode()), _Stream()

    def close(self) -> None:
        return None


def test_connect_uses_pinned_policy_and_validates_normalized_owned_home() -> None:
    key = _Key()
    home = "/home/runner"
    client = _Client(key, home)
    paramiko = SimpleNamespace(SSHClient=lambda: client)
    session = RemoteSession(
        Credential("s1", "192.0.2.10", "runner", "secret"), _inventory(home, key)
    )

    session.connect(paramiko_module=paramiko)

    assert session.home == home
    assert session.uid == 1000
    assert client.connect_values["look_for_keys"] is False
    assert client.connect_values["allow_agent"] is False


def test_guarded_paths_and_environment_refuse_escape_and_scope_all_caches() -> None:
    assert guarded_remote_child("/home/runner/root", "cache", "uv") == (
        "/home/runner/root/cache/uv"
    )
    with pytest.raises(ValueError, match="safe POSIX basenames"):
        guarded_remote_child("/home/runner/root", "..")
    with pytest.raises(ValueError, match="safe POSIX basenames"):
        guarded_remote_child("/home/runner/root", "parent/child")

    session = RemoteSession(Credential("s1", "host", "user", "secret"), {})
    session.home = "/home/user"
    session.run_root = "/home/user/.lets-nsdi-matched-host/run-20260831-120000-deadbeef"
    environment = session.environment()

    for name in (
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "PYTHONPYCACHEPREFIX",
        "UV_PYTHON_INSTALL_DIR",
    ):
        assert f"{name}=" in environment
    assert session.run_root in environment
    assert "sudo" not in environment
    assert "docker" not in environment.lower()


def test_upload_uses_exclusive_writable_sftp_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UploadSFTP:
        mode = ""

        def file(self, _target: str, mode: str) -> io.BytesIO:
            self.mode = mode
            return io.BytesIO()

        def chmod(self, _target: str, _mode: int) -> None:
            return None

    source = tmp_path / "payload"
    source.write_bytes(b"payload")
    session = RemoteSession(Credential("s1", "host", "user", "secret"), {})
    sftp = UploadSFTP()
    session.sftp = sftp
    monkeypatch.setattr(RemoteSession, "guard_write", lambda _self, _target: None)
    monkeypatch.setattr(RemoteSession, "verify_regular_file", lambda _self, _target: 7)

    session.upload(source, "/guarded/run/payload")

    assert sftp.mode == "wx"


def test_benchmark_command_has_the_fixed_full_run_shape() -> None:
    command = benchmark_command(
        "/run/AstralDeep/.venv/bin/python",
        "/run/runner/matched_host_path.py",
        "/run/AstralDeep",
        "/run/storage",
        "/run/output",
    )

    assert "--astraldeep-root /run/AstralDeep" in command
    assert "--storage-root /run/storage" in command
    assert "--output /run/output" in command
    assert command.endswith("--trials 10 --operations 1000 --warmups 100")


def _artifacts() -> dict[str, bytes]:
    trials = [
        {
            "trial": index // 2,
            "mode": "off" if index % 2 == 0 else "enforce",
            "samples": [{}] * 1000,
        }
        for index in range(20)
    ]
    document = {
        "claim": "replacement-current-composition-not-historical-reproduction",
        "configuration": {"trials": 10, "operations": 1000, "warmups": 100},
        "environment": {
            "python": "3.12.3",
            "sqlite": EXPECTED_REPLACEMENT_SQLITE,
            "harness_repository": {
                "available": False,
                "reason": "standalone-source-upload",
                "benchmark_sha256": "a" * 64,
            },
            "instrumentation": {"benchmark_sha256": "a" * 64},
            "astraldeep": {"revision": EXPECTED_ASTRALDEEP_COMMIT},
            "components": {
                name: {"revision": revision} for name, revision in EXPECTED_COMPONENTS.items()
            },
        },
        "scope": {"historical_artifact_available": False},
        "trials": trials,
    }
    csv_payload = "header\n" + "row\n" * 20_000
    markdown = "This is not an exact reproduction of the missing `20260826T231656Z` artifact.\n"
    return {
        OUTPUT_JSON: json.dumps(document).encode(),
        OUTPUT_CSV: csv_payload.encode(),
        OUTPUT_MARKDOWN: markdown.encode(),
    }


def test_artifact_validation_requires_full_samples_pins_and_sqlite_diagnosis() -> None:
    artifacts = _artifacts()

    document = validate_benchmark_artifacts(artifacts, expected_benchmark_sha256="a" * 64)

    assert len(document["trials"]) == 20
    changed = json.loads(artifacts[OUTPUT_JSON])
    changed["environment"]["sqlite"] = "3.53.4"
    artifacts[OUTPUT_JSON] = json.dumps(changed).encode()
    with pytest.raises(RemoteMatchedHostError, match=r"SQLite 3\.45\.1"):
        validate_benchmark_artifacts(artifacts)


def test_sanitization_removes_address_user_home_secret_and_ip_literals() -> None:
    session = RemoteSession(Credential("s1", "192.0.2.10", "private-user", "private-secret"), {})
    session.home = "/home/private-user"
    session.run_root = f"{session.home}/.lets-nsdi-matched-host/run-20260831-120000-deadbeef"
    artifacts = {
        OUTPUT_JSON: json.dumps(
            {"path": f"{session.run_root}/output", "value": "private-secret 198.51.100.4"}
        ).encode(),
        OUTPUT_CSV: b"private-user,192.0.2.10\n",
        OUTPUT_MARKDOWN: b"/home/private-user/data\n",
    }

    retained = sanitize_artifacts(artifacts, session)
    text = b"".join(retained.values()).decode()

    assert "$RUN_ROOT" in text
    for forbidden in (
        "private-user",
        "private-secret",
        "192.0.2.10",
        "198.51.100.4",
        "/home/private-user",
    ):
        assert forbidden not in text


@pytest.mark.parametrize(
    ("host", "username", "password"),
    (
        ("address", "user", "secret"),
        ("HOME", "R", "ip"),
        ("$", "!", "#"),
    ),
)
def test_sanitization_tokens_never_reintroduce_short_credentials(
    host: str, username: str, password: str
) -> None:
    session = RemoteSession(Credential("s1", host, username, password), {})
    session.home = f"/owned/{username}"
    session.run_root = f"{session.home}/.lets-nsdi-matched-host/run-20260831-120000-deadbeef"
    artifacts = {
        OUTPUT_JSON: json.dumps(
            {
                "run": session.run_root,
                "home": session.home,
                "host": host,
                "username": username,
                "password": password,
                "ip": "203.0.113.7",
            }
        ).encode(),
        OUTPUT_CSV: f"{host},{username},{password}\n".encode(),
        OUTPUT_MARKDOWN: f"{session.home} {session.run_root}\n".encode(),
    }

    retained = sanitize_artifacts(artifacts, session)

    document = json.loads(retained[OUTPUT_JSON])
    retained_values = tuple(str(value) for value in document.values() if isinstance(value, str))
    assert all(
        forbidden not in value
        for value in retained_values
        for forbidden in (host, username, password, session.home)
    )
    assert all("203.0.113.7" not in value for value in retained_values)
    text_outputs = retained[OUTPUT_CSV] + retained[OUTPUT_MARKDOWN]
    assert all(
        forbidden.encode() not in text_outputs
        for forbidden in (host, username, password, session.home)
    )


def test_short_username_does_not_corrupt_sample_schema_or_prose() -> None:
    session = RemoteSession(Credential("s1", "host.example", "amp", "long-secret"), {})
    session.home = "/home/amp"
    session.run_root = f"{session.home}/.lets-nsdi-matched-host/run-20260831-120000-deadbeef"
    artifacts = {
        OUTPUT_JSON: json.dumps(
            {"samples": [{"sample_index": 1}], "storage": session.run_root}
        ).encode(),
        OUTPUT_CSV: b"sample_index,samples\n1,1\n",
        OUTPUT_MARKDOWN: b"The samples retain one row per measured sample.\n",
    }

    retained = sanitize_artifacts(artifacts, session)

    document = json.loads(retained[OUTPUT_JSON])
    assert document["samples"][0]["sample_index"] == 1
    assert retained[OUTPUT_CSV].startswith(b"sample_index,samples\n")
    assert b"samples retain one row per measured sample" in retained[OUTPUT_MARKDOWN]
    assert "amp" not in document["storage"]


def test_retained_outputs_refuse_silent_overwrite(tmp_path: Path) -> None:
    artifacts = {
        OUTPUT_JSON: b"{}\n",
        OUTPUT_CSV: b"header\n",
        OUTPUT_MARKDOWN: b"notes\n",
    }
    manifest = {"schema": "lets.remote-matched-host/v1"}
    output = tmp_path / "retained"

    paths = _write_retained(output, artifacts, manifest, overwrite=False)

    assert len(paths) == 4
    with pytest.raises(RemoteMatchedHostError, match="overwrite"):
        _write_retained(output, artifacts, manifest, overwrite=False)
    _write_retained(output, artifacts, manifest, overwrite=True)


def _recovery_candidate(run_id: str) -> RecoveryCandidate:
    timestamp = datetime.strptime(run_id[4:19], "%Y%m%d-%H%M%S").replace(tzinfo=UTC)
    return RecoveryCandidate(
        run_id=run_id,
        timestamp=timestamp,
        remote_root=f"/guarded/{run_id}",
        raw_artifacts={},
        document={},
        clone_identity={},
        uv_archive_sha256=UV_ARCHIVE_SHA256,
    )


def test_recovery_selection_uses_unique_latest_timestamp_and_rejects_ambiguity() -> None:
    older = _recovery_candidate("run-20260831-120000-aaaaaaaa")
    latest = _recovery_candidate("run-20260831-120001-bbbbbbbb")

    assert select_latest_recovery_candidate((latest, older)) is latest

    tied = _recovery_candidate("run-20260831-120001-cccccccc")
    with pytest.raises(RemoteMatchedHostError, match="share the latest timestamp"):
        select_latest_recovery_candidate((latest, tied))
    with pytest.raises(RemoteMatchedHostError, match="no completed remote run"):
        select_latest_recovery_candidate(())


def test_recovery_timing_does_not_infer_benchmark_start_from_environment_capture() -> None:
    candidate = _recovery_candidate("run-20260831-120001-bbbbbbbb")
    captured = "2026-08-31T12:45:00+00:00"
    recovered = "2026-08-31T13:00:00+00:00"

    timing = _recovery_timing(candidate, {"captured_at_utc": captured}, recovered)

    assert timing == {
        "started_at_utc": None,
        "completed_at_utc": recovered,
        "run_root_created_at_utc": "2026-08-31T12:00:01+00:00",
        "environment_captured_at_utc": captured,
        "recovered_at_utc": recovered,
    }


def test_recovery_root_scan_rejects_symlinks_and_unexpected_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ListingSFTP:
        def __init__(self, entries: list[SimpleNamespace]) -> None:
            self.entries = entries

        def listdir_attr(self, _path: str) -> list[SimpleNamespace]:
            return self.entries

        def normalize(self, path: str) -> str:
            return path

    session = RemoteSession(Credential("s1", "host", "user", "secret"), {})
    session.home = "/home/user"
    session.uid = 1000
    monkeypatch.setattr(RemoteSession, "_guard", lambda *_args: None)
    valid_name = "run-20260831-120001-bbbbbbbb"
    session.sftp = ListingSFTP(
        [SimpleNamespace(filename=valid_name, st_mode=stat.S_IFDIR | 0o700, st_uid=1000)]
    )
    assert _safe_recovery_roots(session) == [
        (valid_name, f"/home/user/.lets-nsdi-matched-host/{valid_name}")
    ]

    session.sftp = ListingSFTP(
        [SimpleNamespace(filename=valid_name, st_mode=stat.S_IFLNK | 0o700, st_uid=1000)]
    )
    with pytest.raises(RemoteMatchedHostError, match="unsafe run directory"):
        _safe_recovery_roots(session)

    session.sftp = ListingSFTP(
        [SimpleNamespace(filename="not-a-run", st_mode=stat.S_IFDIR | 0o700, st_uid=1000)]
    )
    with pytest.raises(RemoteMatchedHostError, match="unexpected entry"):
        _safe_recovery_roots(session)


def test_candidate_recovery_reads_only_and_validates_exact_remote_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = "run-20260831-120001-bbbbbbbb"
    root = f"/home/user/.lets-nsdi-matched-host/{run_id}"
    artifacts = _artifacts()
    document = json.loads(artifacts[OUTPUT_JSON])
    document["environment"]["storage"] = {"resolved_root": f"{root}/storage"}
    artifacts[OUTPUT_JSON] = json.dumps(document).encode()

    class CandidateSFTP:
        def lstat(self, _path: str) -> SimpleNamespace:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=1000)

        def normalize(self, path: str) -> str:
            return path

        def listdir_attr(self, _path: str) -> list[SimpleNamespace]:
            return [SimpleNamespace(filename=name) for name in artifacts]

    session = RemoteSession(Credential("s1", "host", "user", "secret"), {})
    session.home = "/home/user"
    session.uid = 1000
    session.sftp = CandidateSFTP()
    monkeypatch.setattr(RemoteSession, "verify_path", lambda *_args: None)
    monkeypatch.setattr(RemoteSession, "verify_regular_file", lambda *_args: 1)
    monkeypatch.setattr(
        RemoteSession,
        "download",
        lambda _self, path: artifacts[Path(path).name],
    )
    monkeypatch.setattr(
        "benchmarks.nsdi_strengthening.remote_matched_host._remote_sha256",
        lambda _session, path: UV_ARCHIVE_SHA256 if path.endswith(".tar.gz") else "a" * 64,
    )
    monkeypatch.setattr(
        "benchmarks.nsdi_strengthening.remote_matched_host._verify_clone",
        lambda _session, _deep: {"clean": True},
    )
    monkeypatch.setattr(
        RemoteSession,
        "guarded_command",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("remote write")),
    )
    monkeypatch.setattr(
        RemoteSession,
        "upload",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("remote write")),
    )

    candidate = _load_recovery_candidate(session, run_id, root, "a" * 64)

    assert candidate is not None
    assert candidate.run_id == run_id
    assert candidate.uv_archive_sha256 == UV_ARCHIVE_SHA256
