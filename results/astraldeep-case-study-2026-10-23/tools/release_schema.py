"""Runs the tracked capture_environment or the ungated summary with the tracked evidence
schema's v1.0.11 release constants replaced by the measured composition release; every
other schema rule and validation step in benchmarks/astraldeep is unchanged.
"""

from __future__ import annotations

import functools
import json
import sys
from pathlib import Path

from benchmarks.astraldeep import capture_environment as capture

TRACKED_RELEASE = "v1.0.11"


def release_schema(release: str, output: Path) -> Path:
    tracked = Path(capture.__file__).with_name("case-study-evidence.schema.json")
    text = tracked.read_bytes()
    needle = json.dumps({"const": TRACKED_RELEASE})[1:-1].encode("ascii")
    if text.count(needle) != 2:
        raise SystemExit("tracked evidence schema no longer has exactly two release constants")
    output.write_bytes(text.replace(needle, json.dumps({"const": release})[1:-1].encode("ascii")))
    return output


def install(release: str, output: Path) -> None:
    schema = release_schema(release, output)
    capture.validate_evidence_bundle = functools.partial(
        capture.validate_evidence_bundle, schema_path=schema
    )


if __name__ == "__main__":
    release, schema_output, tool, *arguments = sys.argv[1:]
    install(release, Path(schema_output))
    if tool == "capture":
        raise SystemExit(capture.main(arguments))
    if tool == "summary":
        sys.path.insert(0, str(Path(__file__).parent))
        import ungated_summary

        sys.argv = ["ungated_summary", *arguments]
        raise SystemExit(ungated_summary.main())
    raise SystemExit(f"unknown tool {tool!r}")
