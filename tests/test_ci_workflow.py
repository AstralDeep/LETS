import re
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"

CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_UV_ACTION = "astral-sh/setup-uv@ae62891fec2bb8e7d6c99fc78c9fec3a63790f8d"
UPLOAD_ACTION = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
APPROVED_ACTIONS = {
    "actions/checkout": CHECKOUT_ACTION.partition("@")[2],
    "astral-sh/setup-uv": SETUP_UV_ACTION.partition("@")[2],
    "actions/upload-artifact": UPLOAD_ACTION.partition("@")[2],
}
EXPECTED_ACTIONS = Counter(
    {
        CHECKOUT_ACTION: 3,
        SETUP_UV_ACTION: 3,
        UPLOAD_ACTION: 1,
    }
)


def _assert_approved_actions(text: str) -> None:
    actions = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s*([^\s#]+)", text)
    assert actions
    for action in actions:
        repository, separator, sha = action.rpartition("@")
        assert separator and re.fullmatch(r"[0-9a-f]{40}", sha), action
        assert APPROVED_ACTIONS.get(repository) == sha, action
    assert Counter(actions) == EXPECTED_ACTIONS


def test_ci_uses_only_exact_approved_action_commits() -> None:
    _assert_approved_actions(WORKFLOW_PATH.read_text(encoding="utf-8"))


def test_ci_rejects_valid_shape_unapproved_action_commit() -> None:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    mutated = text.replace(SETUP_UV_ACTION, f"astral-sh/setup-uv@{'0' * 40}", 1)
    assert mutated != text

    with pytest.raises(AssertionError):
        _assert_approved_actions(mutated)
