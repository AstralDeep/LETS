"""Checks results/nsdi-evidence-scope-2026-09-28.json against the sealed NSDI bundles'
SOURCE-MANIFEST.json files and this repository's Git history, so every recorded digest,
drift commit, and behavior classification stays reproducible.
"""

from __future__ import annotations

import ast
import copy
import functools
import hashlib
import json
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
RECORD_PATH = ROOT / "results" / "nsdi-evidence-scope-2026-09-28.json"
SEALED_BUNDLES = {
    "results/nsdi-strengthening-2026-08-31",
    "results/nsdi-strengthening-2026-09-02",
}


@functools.cache
def _git(*arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(ROOT), *arguments], check=True, capture_output=True
    ).stdout


def _blob(commit: str, path: str) -> bytes:
    return _git("show", f"{commit}:{path}")


def _commits_touching(start: str, end: str, path: str) -> list[str]:
    return _git("log", "--reverse", "--format=%H", f"{start}..{end}", "--", path).decode().split()


def _executable_syntax(source: bytes) -> str:
    tree = ast.parse(source.decode("utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                node.body = body[1:] or [ast.Pass()]
    return ast.dump(tree)


def _record() -> dict[str, Any]:
    return json.loads(RECORD_PATH.read_text(encoding="utf-8"))


def _verify_manifest_coverage(record: dict[str, Any]) -> None:
    assert record["schema"] == "lets.nsdi-evidence-scope/v1"
    assert {section["bundle"] for section in record["source_drift"]} == SEALED_BUNDLES
    for section in record["source_drift"]:
        manifest_path = section["source_manifest_path"]
        assert manifest_path == f"{section['bundle']}/SOURCE-MANIFEST.json"
        manifest_bytes = (ROOT / manifest_path).read_bytes()
        assert hashlib.sha256(manifest_bytes).hexdigest() == section["source_manifest_sha256"]
        sealed = {entry["path"]: entry for entry in json.loads(manifest_bytes)["files"]}
        drifted = {entry["path"]: entry for entry in section["drifted"]}
        unchanged = set(section["unchanged"])
        assert len(drifted) == len(section["drifted"])
        assert len(unchanged) == len(section["unchanged"])
        assert not unchanged & set(drifted)
        assert unchanged | set(drifted) == set(sealed)
        for path, entry in sealed.items():
            content = _blob(section["recorded_bytes_commit"], path)
            assert hashlib.sha256(content).hexdigest() == entry["sha256"], path
            assert len(content) == entry["bytes"], path
        for path, entry in drifted.items():
            assert entry["recorded_sha256"] == sealed[path]["sha256"], path
            assert entry["recorded_bytes"] == sealed[path]["bytes"], path


def _verify_observed_history(record: dict[str, Any]) -> None:
    observed = record["observation"]["git_commit"]
    referenced: set[str] = set()
    for section in record["source_drift"]:
        recorded = section["recorded_bytes_commit"]
        for path in section["unchanged"]:
            assert _blob(observed, path) == _blob(recorded, path), path
            assert _commits_touching(recorded, observed, path) == [], path
        for entry in section["drifted"]:
            path = entry["path"]
            content = _blob(observed, path)
            assert hashlib.sha256(content).hexdigest() == entry["current_sha256"], path
            assert len(content) == entry["current_bytes"], path
            assert content != _blob(recorded, path), path
            commits = [change["commit"] for change in entry["changed_by"]]
            assert commits == _commits_touching(recorded, observed, path), path
            assert all(change["change"].strip() for change in entry["changed_by"]), path
            referenced.update(commits)
    assert set(record["commits"]) == referenced
    for commit, subject in record["commits"].items():
        assert _git("log", "-1", "--format=%s", commit).decode().strip() == subject, commit


def _verify_behavior(record: dict[str, Any]) -> None:
    observed = record["observation"]["git_commit"]
    for section in record["source_drift"]:
        for entry in section["drifted"]:
            path = entry["path"]
            assert isinstance(entry["behavior_changed"], bool), path
            if not path.endswith(".py"):
                assert entry["note"].strip(), path
                continue
            before = _blob(section["recorded_bytes_commit"], path)
            after = _blob(observed, path)
            syntax_changed = _executable_syntax(before) != _executable_syntax(after)
            assert entry["behavior_changed"] is syntax_changed, path
            help_from_docstring = b"description=__doc__" in after
            assert ("note" in entry) is (help_from_docstring and not syntax_changed), path


def _verify(record: dict[str, Any]) -> None:
    _verify_manifest_coverage(record)
    _verify_observed_history(record)
    _verify_behavior(record)


def test_scope_record_is_canonical_json() -> None:
    record = _record()
    assert RECORD_PATH.read_text(encoding="utf-8") == (
        json.dumps(record, indent=2, sort_keys=True) + "\n"
    )


def test_scope_record_matches_sealed_manifests_and_git_history() -> None:
    _verify(_record())


def test_sensitivity_frontier_drift_is_docstring_only() -> None:
    record = _record()
    entries = [
        entry
        for section in record["source_drift"]
        for entry in section["drifted"]
        if entry["path"] == "formal/sensitivity_frontier.py"
    ]
    assert len(entries) == 2
    for entry in entries:
        assert entry["recorded_sha256"].startswith("459e16c4")
        assert entry["current_sha256"].startswith("3bd838af")
        assert entry["behavior_changed"] is False
        assert [change["commit"][:7] for change in entry["changed_by"]] == ["0333cd6"]


def _first_drifted(record: dict[str, Any], suffix: str) -> dict[str, Any]:
    return next(
        entry
        for section in record["source_drift"]
        for entry in section["drifted"]
        if entry["path"].endswith(suffix)
    )


def _tamper_recorded_digest(record: dict[str, Any]) -> None:
    _first_drifted(record, "sensitivity_frontier.py")["recorded_sha256"] = "0" * 64


def _tamper_current_digest(record: dict[str, Any]) -> None:
    _first_drifted(record, "sensitivity_frontier.py")["current_sha256"] = "0" * 64


def _drop_sealed_path(record: dict[str, Any]) -> None:
    record["source_drift"][0]["drifted"].pop()


def _omit_drift_commit(record: dict[str, Any]) -> None:
    _first_drifted(record, "evidence_campaign.py")["changed_by"].pop(0)


def _hide_behavior_change(record: dict[str, Any]) -> None:
    _first_drifted(record, "evidence_campaign.py")["behavior_changed"] = False


def _claim_behavior_change(record: dict[str, Any]) -> None:
    _first_drifted(record, "sensitivity_frontier.py")["behavior_changed"] = True


def _relabel_commit(record: dict[str, Any]) -> None:
    first = next(iter(record["commits"]))
    record["commits"][first] = "a different subject"


@pytest.mark.parametrize(
    "tamper",
    [
        _tamper_recorded_digest,
        _tamper_current_digest,
        _drop_sealed_path,
        _omit_drift_commit,
        _hide_behavior_change,
        _claim_behavior_change,
        _relabel_commit,
    ],
)
def test_scope_record_verification_rejects_tampering(
    tamper: Callable[[dict[str, Any]], None],
) -> None:
    record = copy.deepcopy(_record())
    tamper(record)

    with pytest.raises(AssertionError):
        _verify(record)
