"""Discovered endpoint model."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Endpoint(BaseModel):
    """A discovered endpoint/URL found during crawling."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    url: str
    method: str = 'GET'
    status_code: int | None = None
    content_type: str | None = None
    parameters: list[str] = Field(default_factory=list)
    discovered_by: str = ''
    created_at: datetime = Field(default_factory=datetime.utcnow)
