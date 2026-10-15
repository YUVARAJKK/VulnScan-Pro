"""Complete scan result model."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from .finding import Finding
from .endpoint import Endpoint


class ScanMetadata(BaseModel):
    """Metadata about the scan execution itself."""

    model_config = ConfigDict(from_attributes=True)

    scan_id: UUID
    health_score: int = 100
    health_grade: str = 'A+'
    risk_score: int = 0
    total_endpoints: int = 0
    total_parameters: int = 0
    total_findings: int = 0
    scan_duration_ms: int = 0
    scanner_version: str = '3.0.0'
    score_breakdown: dict[str, Any] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=lambda: {
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
    })
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanResult(BaseModel):
    """Complete result of a vulnerability scan."""

    model_config = ConfigDict(from_attributes=True)

    scan_id: UUID
    target: str
    findings: list[Finding] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    metadata: ScanMetadata | None = None
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
