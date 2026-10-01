from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

class ClientDeadline(BaseModel):
    model_config = ConfigDict(
        populate_by_name=True,
        extra="forbid",
    )

    deadline_at: datetime = Field(alias="deadline_at")
    deadlineAt: datetime = Field(alias="deadline_at")

    @field_validator("deadline_at", "deadlineAt", mode="before")
    @classmethod
    def parse_deadline(cls, v: Any) -> Any:
        if isinstance(v, str):
            return datetime.fromisoformat(v.replace("Z", "+00:00"))
        return v
