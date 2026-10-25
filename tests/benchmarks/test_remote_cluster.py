"""Tests for benchmarks/nsdi_strengthening/remote_cluster.py: remote-cluster credential
loading accepts only the exact schema, with a password or a key file per host, and
rejects missing, unexpected, duplicate, or ambiguous keys.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.remote_cluster import Credential, load_credentials, ssh_auth


def test_load_credentials_accepts_exact_schema_without_exposing_repr(tmp_path: Path) -> None:
    path = tmp_path / "servers.txt"
    path.write_text(
        "\n".join(
            f"s{index}=host-{index}\ns{index}_USERNAME=user-{index}\ns{index}_PASS=secret-{index}"
            for index in range(1, 4)
        ),
        encoding="utf-8",
    )

    credentials = load_credentials(path)

    assert credentials == tuple(
        Credential(f"s{index}", f"host-{index}", f"user-{index}", f"secret-{index}")
        for index in range(1, 4)
    )
    assert "secret" not in repr(credentials)
    assert "host-" not in repr(credentials)
    assert "user-" not in repr(credentials)


def test_load_credentials_rejects_missing_and_unexpected_keys(tmp_path: Path) -> None:
    path = tmp_path / "servers.txt"
    path.write_text("s1=host\nunexpected=value\n", encoding="utf-8")

    with pytest.raises(ValueError, match="required schema"):
        load_credentials(path)


def test_load_credentials_rejects_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "servers.txt"
    path.write_text("s1=first\ns1=second\n", encoding="utf-8")

    with pytest.raises(ValueError, match="duplicated"):
        load_credentials(path)


def test_load_credentials_accepts_key_files_per_host(tmp_path: Path) -> None:
    path = tmp_path / "servers.txt"
    lines = ["s1=host-1", "s1_USERNAME=user-1", "s1_KEY=/keys/one"]
    for index in (2, 3):
        lines += [f"s{index}=host-{index}", f"s{index}_USERNAME=user-{index}"]
        lines.append(f"s{index}_PASS=secret-{index}")
    path.write_text("\n".join(lines), encoding="utf-8")

    first, second, _third = load_credentials(path)

    assert first == Credential("s1", "host-1", "user-1", "", "/keys/one")
    assert ssh_auth(first) == {"key_filename": "/keys/one"}
    assert ssh_auth(second) == {"password": "secret-2"}
    assert "/keys/one" not in repr(first)


@pytest.mark.parametrize("secrets", [(), ("s1_PASS=secret", "s1_KEY=/keys/one")])
def test_load_credentials_requires_exactly_one_secret_per_host(
    tmp_path: Path, secrets: tuple[str, ...]
) -> None:
    lines = ["s1=host-1", "s1_USERNAME=user-1", *secrets]
    for index in (2, 3):
        lines += [f"s{index}=host-{index}", f"s{index}_USERNAME=user-{index}"]
        lines.append(f"s{index}_PASS=secret-{index}")
    path = tmp_path / "servers.txt"
    path.write_text("\n".join(lines), encoding="utf-8")

    with pytest.raises(ValueError, match="exactly one of s1_PASS or s1_KEY"):
        load_credentials(path)
