"""Inventory authorized SSH hosts without retaining addresses or credentials."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import utc_now, write_json

ALIASES = ("s1", "s2", "s3")


@dataclass(frozen=True, slots=True, repr=False)
class Credential:
    alias: str
    host: str
    username: str
    password: str

    def __repr__(self) -> str:
        return f"Credential(alias={self.alias!r}, host=<redacted>, username=<redacted>)"


def load_credentials(path: Path) -> tuple[Credential, ...]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        separator = "=" if "=" in line else ":" if ":" in line else None
        if separator is None:
            raise ValueError(f"credential line {number} has no '=' or ':' separator")
        key, value = line.split(separator, 1)
        checked_key = key.strip()
        checked_value = value.strip().strip('"').strip("'")
        if not checked_key or not checked_value:
            raise ValueError(f"credential line {number} has an empty key or value")
        if checked_key in values:
            raise ValueError(f"credential key {checked_key!r} is duplicated")
        values[checked_key] = checked_value

    expected = {
        *(alias for alias in ALIASES),
        *(f"{alias}_USERNAME" for alias in ALIASES),
        *(f"{alias}_PASS" for alias in ALIASES),
    }
    missing = expected - values.keys()
    unexpected = values.keys() - expected
    if missing or unexpected:
        raise ValueError(
            f"credential keys differ from the required schema; "
            f"missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )
    return tuple(
        Credential(
            alias=alias,
            host=values[alias],
            username=values[f"{alias}_USERNAME"],
            password=values[f"{alias}_PASS"],
        )
        for alias in ALIASES
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _run(client: Any, command: str, *, timeout: float = 30) -> tuple[int, str, str]:
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode("utf-8", errors="replace")
    error = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), output, error


def _inventory(credential: Credential) -> dict[str, object]:
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - environment diagnostic
        raise RuntimeError("install Paramiko in the runner environment") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            credential.host,
            username=credential.username,
            password=credential.password,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            banner_timeout=15,
            auth_timeout=15,
        )
        transport = client.get_transport()
        if transport is None or not transport.is_active():
            raise RuntimeError("SSH transport is not active")
        key = transport.get_remote_server_key()
        fingerprint = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode()

        commands = {
            "home": "printf '%s' \"$HOME\"",
            "login": "id -un",
            "home_checks": (
                'if [ -d "$HOME" ] && [ -O "$HOME" ]; then echo owned; else echo unsafe; fi'
            ),
            "kernel": "uname -s",
            "arch": "uname -m",
            "os": (
                "if [ -r /etc/os-release ]; then . /etc/os-release; "
                'printf \'%s|%s\' "${ID:-unknown}" "${VERSION_ID:-unknown}"; '
                "else printf 'unknown|unknown'; fi"
            ),
            "cpu": "getconf _NPROCESSORS_ONLN 2>/dev/null || printf unknown",
            "python": "python3 --version 2>&1 || true",
            "git": "git --version 2>&1 || true",
            "docker": "docker version --format '{{.Server.Version}}' 2>/dev/null || true",
            "home_fs": "df -PT \"$HOME\" | tail -1 | awk '{print $2}'",
            "home_capacity": "df -PB1 \"$HOME\" | tail -1 | awk '{print $2}'",
        }
        values: dict[str, str] = {}
        for name, command in commands.items():
            code, output, _error = _run(client, command)
            if code != 0:
                raise RuntimeError(f"read-only inventory command {name!r} failed")
            values[name] = output.strip()

        tools: dict[str, bool] = {}
        for tool in (
            "python3",
            "git",
            "uv",
            "docker",
            "podman",
            "curl",
            "tar",
            "rsync",
            "tc",
            "nft",
            "iptables",
        ):
            code, _output, _error = _run(client, f"command -v {tool} >/dev/null 2>&1", timeout=10)
            tools[tool] = code == 0

        sftp = client.open_sftp()
        try:
            normalized_home = sftp.normalize(values["home"])
        finally:
            sftp.close()
        os_id, _, os_version = values["os"].partition("|")
        return {
            "alias": credential.alias,
            "connected": True,
            "inventory_ok": True,
            "host_key_type": key.get_name(),
            "host_key_sha256": fingerprint,
            "address_sha256": _sha256(credential.host),
            "login_matches_credential": values["login"] == credential.username,
            "home_absolute": values["home"].startswith("/"),
            "home_owned": values["home_checks"] == "owned",
            "home_normalized": normalized_home == values["home"],
            "home_path_sha256": _sha256(values["home"]),
            "kernel": values["kernel"],
            "architecture": values["arch"],
            "os_id": os_id,
            "os_version": os_version,
            "cpu_count": values["cpu"],
            "python": values["python"] or None,
            "git": values["git"] or None,
            "docker_server": values["docker"] or None,
            "home_filesystem": values["home_fs"] or None,
            "home_capacity_bytes": values["home_capacity"] or None,
            "tools": tools,
        }
    except Exception as exc:
        return {
            "alias": credential.alias,
            "connected": False,
            "inventory_ok": False,
            "error_class": type(exc).__name__,
            "error": str(exc)[:200],
        }
    finally:
        client.close()


def inventory_cluster(credentials: tuple[Credential, ...]) -> dict[str, object]:
    with ThreadPoolExecutor(max_workers=len(credentials)) as executor:
        servers = list(executor.map(_inventory, credentials))
    return {
        "schema": "lets.remote-cluster-inventory/v1",
        "generated_at": utc_now(),
        "credential_schema_sha256": hashlib.sha256(
            "|".join(item.alias for item in credentials).encode("utf-8")
        ).hexdigest(),
        "secrets_retained": False,
        "addresses_retained": False,
        "usernames_retained": False,
        "servers": servers,
    }


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--credentials", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    result = inventory_cluster(load_credentials(arguments.credentials))
    write_json(arguments.output, result, overwrite=arguments.overwrite)
    passed = all(server.get("inventory_ok") is True for server in result["servers"])
    print(json.dumps({"status": "passed" if passed else "failed", "output": str(arguments.output)}))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
