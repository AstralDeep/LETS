from __future__ import annotations

import pytest
from lets.deadline_validator import DeadlineValidator

def test_valid_deadline_contract() -> None:
    data = {"deadline_at": "2025-12-31T23:59:59Z"}
    validated = DeadlineValidator.validate(data)
    assert validated.deadlineAt.year == 2025
    assert validated.deadline_at.year == 2025

def test_invalid_deadline_format() -> None:
    data = {"deadline_at": "not-a-date"}
    with pytest.raises(ValueError, match="Invalid deadline contract"):
        DeadlineValidator.validate(data)

def test_missing_deadline_field() -> None:
    data: dict[str, str] = {}
    with pytest.raises(ValueError, match="Invalid deadline contract"):
        DeadlineValidator.validate(data)

def test_rejects_extra_fields() -> None:
    data = {"deadline_at": "2025-12-31T23:59:59Z", "extra": "field"}
    with pytest.raises(ValueError, match="Invalid deadline contract"):
        DeadlineValidator.validate(data)
