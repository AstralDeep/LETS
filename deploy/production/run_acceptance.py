"""Run and safely tear down the opt-in production-profile Docker acceptance."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
PROJECT = "lets-production-acceptance"
COMPOSE_FILE = ROOT / "deploy" / "production" / "acceptance-compose.yaml"
COMPOSE = (
    "docker",
    "compose",
    "--project-name",
    PROJECT,
    "--project-directory",
    str(ROOT),
    "--file",
    str(COMPOSE_FILE),
)
VOLUME_KEYS = {
    "trust",
    "client",
    "scenario",
    "executor-state",
    "executor-authority",
    *(
        f"warden-{letter}-{kind}"
        for letter in "abc"
        for kind in ("state", "config", "authority", "audit", "pki", "signer")
    ),
}
ALLOWED_VOLUMES = {f"{PROJECT}_{item}" for item in VOLUME_KEYS}
WARDENS = ("warden-a", "warden-b", "warden-c")
TOXIPROXY = "http://127.0.0.1:28474"
EVIDENCE = ROOT / "results" / "generated" / "production-profile-acceptance.json"
IMAGE_DIGEST = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def _source_tree_digest() -> tuple[str, int]:
    """Hash the exact tracked/untracked, non-ignored working tree used by Docker."""

    listed = _run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"])
    paths = sorted(item for item in listed.stdout.split("\0") if item)
    digest = sha256(b"lets-source-tree/v1\0")
    for relative in paths:
        candidate = ROOT / relative
        resolved = candidate.resolve()
        if not resolved.is_relative_to(ROOT):
            raise RuntimeError(f"Git returned a path outside the repository: {relative!r}")
        if candidate.is_symlink():
            kind = "symlink"
            payload = os.readlink(candidate).encode("utf-8")
        elif candidate.is_file():
            kind = "file"
            payload = candidate.read_bytes()
        elif not candidate.exists():
            kind = "missing"
            payload = b""
        else:
            raise RuntimeError(f"Git source path is not a file: {relative!r}")
        header = json.dumps(
            {"kind": kind, "path": relative.replace("\\", "/"), "size": len(payload)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest.update(len(header).to_bytes(8, "big"))
        digest.update(header)
        digest.update(payload)
    return f"sha256:{digest.hexdigest()}", len(paths)


def _run(
    arguments: list[str] | tuple[str, ...],
    *,
    check: bool = True,
    timeout: float = 600,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(arguments),
        cwd=ROOT,
        check=check,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _compose(*arguments: str, check: bool = True, timeout: float = 600) -> str:
    result = _run([*COMPOSE, *arguments], check=False, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Docker Compose failed ({result.returncode}): {' '.join(arguments)}\n"
            f"{result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


def _project_volumes() -> set[str]:
    output = _run(
        [
            "docker",
            "volume",
            "ls",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
            "--format",
            "{{.Name}}",
        ]
    ).stdout
    return {line.strip() for line in output.splitlines() if line.strip()}


def _checked_down() -> None:
    unexpected = _project_volumes() - ALLOWED_VOLUMES
    if unexpected:
        raise RuntimeError(f"refusing to remove unexpected project volumes: {sorted(unexpected)}")
    _compose("down", "--volumes", timeout=180)


def _proxy_request(method: str, path: str, body: object | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{TOXIPROXY}{path}",
        data=data,
        headers={"content-type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read())


def _wait_toxiproxy() -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            _proxy_request("GET", "/proxies")
            return
        except (OSError, urllib.error.URLError, json.JSONDecodeError):
            time.sleep(0.25)
    raise RuntimeError("Toxiproxy control API did not become ready")


def _configure_proxies() -> None:
    for payload in (
        {
            "enabled": True,
            "listen": "0.0.0.0:8666",
            "name": "a_to_b",
            "upstream": "warden-b:8443",
        },
        {
            "enabled": True,
            "listen": "0.0.0.0:8667",
            "name": "b_to_a",
            "upstream": "warden-a:8443",
        },
    ):
        _proxy_request("POST", "/proxies", payload)


def _set_partition(*, enabled: bool) -> None:
    for name in ("a_to_b", "b_to_a"):
        current = _proxy_request("GET", f"/proxies/{name}")
        current["enabled"] = enabled
        updated = _proxy_request("PATCH", f"/proxies/{name}", current)
        if bool(updated.get("enabled")) is not enabled:
            raise RuntimeError(f"Toxiproxy did not set {name} enabled={enabled}")


def _container(service: str) -> str:
    value = _compose("ps", "-q", service)
    if not value:
        raise RuntimeError(f"Compose service {service} has no container")
    return value


def _state(service: str) -> dict[str, Any]:
    value = json.loads(
        _run(["docker", "inspect", "--format", "{{json .State}}", _container(service)]).stdout
    )
    if not isinstance(value, dict):
        raise RuntimeError(f"Docker returned invalid state for {service}")
    return cast(dict[str, Any], value)


def _wait_healthy(service: str, *, timeout_s: float = 180) -> None:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _state(service)
        health = last.get("Health")
        if isinstance(health, dict) and health.get("Status") == "healthy":
            return
        if last.get("Status") == "exited":
            raise RuntimeError(f"{service} exited before becoming healthy: {last}")
        time.sleep(0.5)
    raise RuntimeError(f"{service} did not become healthy: {last}")


def _scenario(phase: str) -> dict[str, Any]:
    output = _compose(
        "run",
        "--rm",
        "--no-deps",
        "scenario",
        "python",
        "/app/deploy/production/acceptance/scenario.py",
        phase,
        timeout=240,
    )
    for line in reversed(output.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return cast(dict[str, Any], value)
    raise RuntimeError(f"scenario phase {phase} returned no JSON result: {output}")


def _hardening_evidence() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for service in WARDENS:
        document = json.loads(_run(["docker", "inspect", _container(service)]).stdout)[0]
        host = document["HostConfig"]
        security = host.get("SecurityOpt") or []
        capability_drops = {str(item).upper() for item in (host.get("CapDrop") or [])}
        if (
            document["Config"]["User"] != "10001:10001"
            or host.get("ReadonlyRootfs") is not True
            or "ALL" not in capability_drops
            or not any("no-new-privileges" in str(item) for item in security)
        ):
            raise RuntimeError(f"{service} is missing a required container hardening control")
        mounts = {
            item["Destination"]: item.get("Name") or item.get("Source")
            for item in document.get("Mounts", [])
        }
        mount_documents = {item["Destination"]: item for item in document.get("Mounts", [])}
        authority_domains = [
            mounts.get("/var/lib/lets"),
            mounts.get("/var/lib/lets-authority"),
            mounts.get("/var/lib/lets-audit"),
        ]
        if None in authority_domains or len(set(authority_domains)) != 3:
            raise RuntimeError(f"{service} does not use distinct state/anchor/audit volumes")
        for protected_mount in (
            "/etc/lets/trust",
            "/run/lets-pki",
            "/run/lets-signer",
        ):
            mounted = mount_documents.get(protected_mount)
            if not isinstance(mounted, dict) or mounted.get("RW") is not False:
                raise RuntimeError(f"{service} does not protect {protected_mount} read-only")
        if "/var/lib/lets-backup" in mounts:
            raise RuntimeError(f"{service} unexpectedly mounts the backup domain")
        tmp_options = str((host.get("Tmpfs") or {}).get("/tmp", ""))
        if not {"rw", "noexec", "nosuid", "nodev", "size=16m", "mode=1777"}.issubset(
            set(tmp_options.split(","))
        ):
            raise RuntimeError(f"{service} does not use the bounded hardened tmpfs")
        ulimits = {
            str(item.get("Name")): (item.get("Soft"), item.get("Hard"))
            for item in (host.get("Ulimits") or [])
        }
        log_config = host.get("LogConfig") or {}
        log_options = log_config.get("Config") or {}
        if (
            host.get("Memory") != 1024 * 1024 * 1024
            or host.get("MemorySwap") != 1024 * 1024 * 1024
            or host.get("NanoCpus") != 1_500_000_000
            or host.get("PidsLimit") != 256
            or host.get("Init") is not True
            or ulimits.get("nofile") != (4096, 4096)
            or log_config.get("Type") != "json-file"
            or log_options.get("max-size") != "10m"
            or log_options.get("max-file") != "5"
            or host.get("PortBindings") not in (None, {})
        ):
            raise RuntimeError(f"{service} does not match the bounded production resource profile")
        command = tuple(str(item) for item in (document.get("Config", {}).get("Cmd") or []))
        for required_argument in (
            "--production",
            "--tls-cert",
            "--tls-key",
            "--client-ca",
            "--peer-ca",
            "--peer-cert",
            "--peer-key",
            "--limit-concurrency",
            "--backlog",
            "--timeout-keep-alive",
            "--timeout-graceful-shutdown",
        ):
            if required_argument not in command:
                raise RuntimeError(f"{service} command omits {required_argument}")
        helper_records = int(
            _compose(
                "exec",
                "-T",
                service,
                "python",
                "-c",
                "from pathlib import Path; p=Path('/var/lib/lets-audit/signer-helper.jsonl'); "
                "print(len(p.read_text().splitlines()))",
            )
        )
        if helper_records < 1:
            raise RuntimeError(f"{service} has no external signer-helper evidence")
        archive = json.loads(
            _compose(
                "exec",
                "-T",
                service,
                "python",
                "-c",
                "import json, sqlite3; from pathlib import Path; "
                "p=Path('/var/lib/lets-audit/audit.sqlite3'); "
                "c=sqlite3.connect(f'file:{p}?mode=ro', uri=True, timeout=5); "
                "row=c.execute('SELECT COUNT(*), MAX(sequence) FROM audit_records').fetchone(); "
                "c.close(); size=sum(Path(f'{p}{suffix}').stat().st_size "
                "for suffix in ('', '-wal', '-shm') if Path(f'{p}{suffix}').exists()); "
                "print(json.dumps({'bytes': size, 'head_sequence': row[1], "
                "'records': row[0]}, sort_keys=True))",
            )
        )
        if (
            not isinstance(archive, dict)
            or not isinstance(archive.get("bytes"), int)
            or int(archive["bytes"]) <= 0
            or not isinstance(archive.get("head_sequence"), int)
            or not isinstance(archive.get("records"), int)
            or int(archive["records"]) <= 0
        ):
            raise RuntimeError(f"{service} returned invalid audit archive evidence: {archive!r}")
        config_mount = next(
            (
                item
                for item in document.get("Mounts", [])
                if item.get("Destination") == "/var/lib/lets/config.json"
            ),
            None,
        )
        if not isinstance(config_mount, dict) or config_mount.get("RW") is not False:
            raise RuntimeError(f"{service} does not use a distinct read-only config mount")
        config_probe = _compose(
            "exec",
            "-T",
            service,
            "python",
            "-c",
            "from pathlib import Path; p=Path('/var/lib/lets/config.json'); "
            "original=p.read_bytes(); failures=0; "
            "\nfor operation in (lambda: p.unlink(), lambda: p.write_bytes(b'unsafe')):\n"
            " try: operation()\n"
            " except OSError: failures += 1\n"
            "\nassert failures == 2 and p.read_bytes() == original; print('immutable')",
        )
        if config_probe != "immutable":
            raise RuntimeError(f"{service} immutable config probe returned {config_probe!r}")
        result[service] = {
            "audit_archive": archive,
            "external_signer_invocations": helper_records,
            "bounded_resources_and_logs": True,
            "nonroot": True,
            "no_backup_mount": True,
            "read_only_rootfs": True,
            "read_only_config": True,
            "read_only_trust_pki_signer": True,
            "separate_state_anchor_audit": True,
            "tmpfs_hardened": True,
        }
    return result


def main() -> int:
    started = datetime.now(UTC)
    source_commit = _run(["git", "rev-parse", "--verify", "HEAD"]).stdout.strip()
    source_dirty = bool(_run(["git", "status", "--porcelain=v1"]).stdout)
    source_tree_digest, source_file_count = _source_tree_digest()
    candidate_image = os.environ.get("LETS_PRODUCTION_ACCEPTANCE_IMAGE")
    if candidate_image is not None and IMAGE_DIGEST.fullmatch(candidate_image) is None:
        raise RuntimeError(
            "LETS_PRODUCTION_ACCEPTANCE_IMAGE must be an exact name@sha256:<digest> reference"
        )
    keep = os.environ.get("LETS_KEEP_PRODUCTION_ACCEPTANCE") == "1"
    failure_logs = ""
    try:
        _checked_down()
        if candidate_image is not None:
            _run(["docker", "pull", candidate_image], timeout=600)
        _compose("up", "-d", "--build", timeout=900)
        _wait_toxiproxy()
        _configure_proxies()
        for service in WARDENS:
            _wait_healthy(service)
        security = _scenario("security")
        executor = _scenario("executor")
        _set_partition(enabled=False)
        prepared = _scenario("prepare")
        prior_pid = int(_state("warden-a")["Pid"])
        _compose("kill", "--signal", "SIGKILL", "warden-a")
        _compose("up", "-d", "--no-deps", "warden-a")
        _wait_healthy("warden-a")
        restarted_pid = int(_state("warden-a")["Pid"])
        if restarted_pid == prior_pid:
            raise RuntimeError("warden-a restart did not replace the runtime process")
        _set_partition(enabled=True)
        converged = _scenario("converge")
        hardening = _hardening_evidence()
        container_documents = {
            service: json.loads(_run(["docker", "inspect", _container(service)]).stdout)[0]
            for service in WARDENS
        }
        image_ids = {document["Image"] for document in container_documents.values()}
        if len(image_ids) != 1 or not next(iter(image_ids)).startswith("sha256:"):
            raise RuntimeError("wardens did not run one content-addressed acceptance image")
        configured_images = {
            str(document["Config"]["Image"]) for document in container_documents.values()
        }
        if candidate_image is not None and configured_images != {candidate_image}:
            raise RuntimeError(
                "wardens did not run the requested published candidate digest: "
                f"{sorted(configured_images)}"
            )
        completed = datetime.now(UTC)
        evidence = {
            "completed_at": completed.isoformat().replace("+00:00", "Z"),
            "duration_seconds": round((completed - started).total_seconds(), 3),
            "executor": executor,
            "hardening": hardening,
            "partition": {"links": ["a_to_b", "b_to_a"], "prepared": prepared},
            "restart": {"process_replaced": True, "service": "warden-a"},
            "runtime_image_id": next(iter(image_ids)),
            "runtime_image_digest": candidate_image,
            "scenario": converged,
            "schema": "lets.production-profile-acceptance/v1",
            "security": security,
            "source": {
                "dirty": source_dirty,
                "file_count": source_file_count,
                "git_commit": source_commit,
                "tree_digest": source_tree_digest,
            },
            "started_at": started.isoformat().replace("+00:00", "Z"),
        }
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0
    except Exception:
        failure_logs = _compose("logs", "--no-color", "--tail", "200", check=False)
        raise
    finally:
        if failure_logs:
            print(failure_logs)
        if not keep:
            _checked_down()


if __name__ == "__main__":
    raise SystemExit(main())
