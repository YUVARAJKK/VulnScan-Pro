"""Pydantic vulnerability finding model."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


class Finding(BaseModel):
    """A single vulnerability finding produced by a detector."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    title: str
    description: str = ''
    severity: str = 'info'  # critical | high | medium | low | info
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cve_id: str | None = None
    affected_component: str = ''
    category: str = 'misconfig'
    endpoint: str | None = None
    parameter: str | None = None
    detected_by: str = ''
    confidence: str = 'medium'  # high | medium | low
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    remediation: str = ''
    references: str = ''
    evidence: dict[str, Any] = Field(default_factory=dict)
    raw_output: dict[str, Any] = Field(default_factory=dict)
    # ML classification result (from ml.classifier). None until classified —
    # never pretend a finding was classified when it was not.
    ml_classification: dict[str, Any] | None = None
    status: str = 'open'
    created_at: datetime = Field(default_factory=datetime.utcnow)
