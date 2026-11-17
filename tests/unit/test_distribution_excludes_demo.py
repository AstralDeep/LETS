"""Builds the wheel and sdist and proves neither ships demo/, which is its own build target."""

import subprocess
import tarfile
import zipfile
from pathlib import Path

REPOSITORY = Path(__file__).parents[2]


def test_wheel_and_sdist_contain_no_demo_path(tmp_path: Path) -> None:
    subprocess.run(
        ["uv", "build", "--wheel", "--sdist", "--out-dir", str(tmp_path), str(REPOSITORY)],
        check=True,
        capture_output=True,
    )
    wheel = next(tmp_path.glob("*.whl"))
    sdist = next(tmp_path.glob("*.tar.gz"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()

    assert any(name.startswith("lets/") for name in wheel_names)
    assert any(name.endswith("/src/lets/__init__.py") for name in sdist_names)
    for name in (*wheel_names, *sdist_names):
        parts = Path(name).parts
        assert "demo" not in parts, name
