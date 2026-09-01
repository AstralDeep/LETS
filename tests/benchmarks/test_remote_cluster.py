from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.nsdi_strengthening.remote_cluster import Credential, load_credentials


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
