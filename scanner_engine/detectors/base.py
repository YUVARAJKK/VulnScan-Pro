"""Base detector abstract class with lifecycle hooks."""

from __future__ import annotations

import abc
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner_engine.core.http_client import HttpClient
    from scanner_engine.models.finding import Finding

logger = logging.getLogger(__name__)


class BaseDetector(abc.ABC):
    """Abstract base class for all vulnerability detectors.

    Subclasses must implement:
      - name: human-readable detector name
      - category: vulnerability category (headers, ssl, injection, etc.)
      - detect(target_url, http_client) -> list[Finding]
    """

    name: str = 'base'
    category: str = 'misconfig'

    @abc.abstractmethod
    async def detect(
        self,
        target_url: str,
        http_client: 'HttpClient',
        **kwargs,
    ) -> list['Finding']:
        """Run detection against a target URL and return findings."""
        ...

    def _make_finding(self, **kwargs) -> 'Finding':
        """Helper to create a Finding with detector defaults filled in."""
        from scanner_engine.models.finding import Finding
        return Finding(detected_by=self.name, category=self.category, **kwargs)
