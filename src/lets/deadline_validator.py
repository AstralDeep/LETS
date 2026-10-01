from __future__ import annotations

from typing import Any

from lets.models import ClientDeadline
from pydantic import ValidationError

class DeadlineValidator:
    @staticmethod
    def validate(data: dict[str, Any]) -> ClientDeadline:
        try:
            return ClientDeadline.model_validate(data)
        except ValidationError as e:
            raise ValueError(f"Invalid deadline contract: {e}") from e
