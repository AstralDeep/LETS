from __future__ import annotations

from pathlib import Path

import pytest

import lets.cli as cli_module
from lets.errors import ValidationError


def test_config_publication_does_not_clobber_a_racing_creator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "config.json"
    original_link = cli_module.os.link

    def racer(source: str, target: Path) -> None:
        Path(target).write_text("competitor-owned\n", encoding="utf-8")
        original_link(source, target)

    monkeypatch.setattr(cli_module.os, "link", racer)
    with pytest.raises(ValidationError, match="appeared during initialization"):
        cli_module._atomic_json(destination, {"version": 1})

    assert destination.read_text(encoding="utf-8") == "competitor-owned\n"
    assert list(tmp_path.glob(".config.json.*.tmp")) == []
