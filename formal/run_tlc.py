"""Download a pinned TLC tool locally and reproduce the finite LETS check."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FORMAL_DIRECTORY = ROOT / "formal"
GENERATED_ROOT = ROOT / "results" / "generated" / "formal"
TOOL_MANIFEST = FORMAL_DIRECTORY / "tlc-tool.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _generated_path(value: Path, field: str) -> Path:
    candidate = (ROOT / value).resolve()
    generated = GENERATED_ROOT.resolve()
    if candidate == generated or not candidate.is_relative_to(generated):
        raise ValueError(f"{field} must be below results/generated/formal")
    return candidate


def _tool() -> dict[str, Any]:
    value = json.loads(TOOL_MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("formal/tlc-tool.json must contain an object")
    return value


def _verify_jar(path: Path, tool: dict[str, Any]) -> None:
    expected_hash = str(tool["sha256"])
    observed_hash = _sha256(path)
    if observed_hash != expected_hash:
        raise RuntimeError(f"tla2tools.jar SHA-256 mismatch: {observed_hash}")
    expected_size = int(tool["bytes"])
    if path.stat().st_size != expected_size:
        raise RuntimeError(
            f"tla2tools.jar size mismatch: {path.stat().st_size}, expected {expected_size}"
        )


def _local_jar(tool: dict[str, Any]) -> Path:
    tool_directory = ROOT / "tmp" / "tla"
    tool_directory.mkdir(parents=True, exist_ok=True)
    jar = tool_directory / "tla2tools.jar"
    if jar.exists():
        _verify_jar(jar, tool)
        return jar

    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            prefix="tla2tools-",
            suffix=".download",
            dir=tool_directory,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            with urllib.request.urlopen(str(tool["url"]), timeout=120) as response:
                shutil.copyfileobj(response, handle)
        _verify_jar(temporary, tool)
        try:
            os.link(temporary, jar)
        except FileExistsError:
            # Another runner won the no-clobber race; trust it only after verification.
            _verify_jar(jar, tool)
        return jar
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _parse_summary(output: str) -> dict[str, int | float | str | None]:
    states = re.search(
        r"(?m)^(?P<generated>[0-9]+) states generated, "
        r"(?P<distinct>[0-9]+) distinct states found, "
        r"(?P<left>[0-9]+) states left on queue\.$",
        output,
    )
    depth = re.search(
        r"The depth of the complete state graph search is (?P<depth>[0-9]+)\.",
        output,
    )
    version = re.search(r"(?m)^TLC2 Version (?P<version>.+)$", output)
    probability = re.search(r"calculated \(optimistic\):\s+val = (?P<value>[0-9.E+-]+)", output)
    if states is None or depth is None or version is None:
        raise RuntimeError("TLC succeeded but its summary could not be parsed")
    return {
        "states_generated": int(states.group("generated")),
        "distinct_states": int(states.group("distinct")),
        "states_left_on_queue": int(states.group("left")),
        "maximum_depth": int(depth.group("depth")),
        "tlc_version": version.group("version").strip(),
        "fingerprint_collision_probability_optimistic": (
            float(probability.group("value")) if probability is not None else None
        ),
    }


def run_tlc(
    *,
    meta_directory: Path,
    evidence_output: Path,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    if shutil.which("java") is None:
        raise RuntimeError(
            "Java 11 or newer is required; this runner does not install system software"
        )
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    resolved_meta = _generated_path(meta_directory, "meta_directory")
    resolved_evidence = _generated_path(evidence_output, "evidence_output")
    if resolved_meta.exists():
        raise FileExistsError(
            f"TLC metadir already exists; choose a new --meta-directory: {resolved_meta}"
        )
    resolved_evidence.parent.mkdir(parents=True, exist_ok=True)
    tool = _tool()
    _local_jar(tool)
    relative_jar = Path("..") / "tmp" / "tla" / "tla2tools.jar"
    relative_meta = Path("..") / meta_directory
    command = (
        "java",
        "-XX:+UseParallelGC",
        "-cp",
        relative_jar.as_posix(),
        "tlc2.TLC",
        "-workers",
        "auto",
        "-metadir",
        relative_meta.as_posix(),
        "-config",
        "LETS.cfg",
        "LETS.tla",
    )
    completed = subprocess.run(
        command,
        cwd=FORMAL_DIRECTORY,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    output = completed.stdout + completed.stderr
    log = resolved_evidence.with_suffix(".log")
    log.write_text(output, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"TLC failed with exit code {completed.returncode}; inspect {log}")
    summary = _parse_summary(output)
    runner_command = (
        "python -m formal.run_tlc "
        f"--meta-directory {meta_directory.as_posix()} "
        f"--evidence-output {evidence_output.as_posix()}"
    )
    evidence: dict[str, Any] = {
        "schema": "lets.tlc-model-check/v1",
        "checked_at": datetime.now(UTC).isoformat(),
        "runner_command": runner_command,
        "tlc_command": " ".join(command),
        "tlc_working_directory": "formal",
        "config_sha256": _sha256(FORMAL_DIRECTORY / "LETS.cfg"),
        "passed": True,
        "spec_sha256": _sha256(FORMAL_DIRECTORY / "LETS.tla"),
        "tla2tools_jar_bytes": int(tool["bytes"]),
        "tla2tools_jar_sha256": str(tool["sha256"]),
        "tla2tools_release": str(tool["release"]),
        "workers": os.cpu_count(),
        **summary,
    }
    resolved_evidence.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(output, end="" if output.endswith("\n") else "\n")
    print(json.dumps({"evidence": str(resolved_evidence), "log": str(log)}, sort_keys=True))
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--meta-directory",
        type=Path,
        default=Path("results/generated/formal/tlc-states"),
    )
    parser.add_argument(
        "--evidence-output",
        type=Path,
        default=Path("results/generated/formal/tlc-check.json"),
    )
    parser.add_argument("--timeout-seconds", type=int, default=300)
    arguments = parser.parse_args()
    try:
        run_tlc(
            meta_directory=arguments.meta_directory,
            evidence_output=arguments.evidence_output,
            timeout_seconds=arguments.timeout_seconds,
        )
    except (FileExistsError, RuntimeError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
