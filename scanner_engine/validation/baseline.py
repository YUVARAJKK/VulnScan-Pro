"""Baseline response comparator for differential analysis."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Baseline:
    """Stores baseline response characteristics for comparison."""

    status_code: int = 200
    content_length: int = 0
    content_type: str = ''
    headers: dict | None = None
    body_hash: int = 0

    @classmethod
    def from_response(cls, status_code: int, body: str, headers: dict) -> 'Baseline':
        return cls(
            status_code=status_code,
            content_length=len(body),
            content_type=headers.get('content-type', ''),
            headers=dict(headers),
            body_hash=hash(body[:5000]),
        )

    def differs_significantly(
        self,
        status_code: int,
        body: str,
        length_threshold: float = 0.3,
    ) -> bool:
        """Check if a new response differs significantly from baseline."""
        # Status code change
        if status_code != self.status_code:
            return True

        # Significant length change
        if self.content_length > 0:
            length_change = abs(len(body) - self.content_length) / self.content_length
            if length_change > length_threshold:
                return True

        # Content hash change
        if hash(body[:5000]) != self.body_hash:
            return True

        return False
