"""SQLAlchemy PostgreSQL writer for direct database access.

The engine writes results straight into PostgreSQL using the same tables the
Node.js API reads from. Two scan kinds are supported:

  - internal: findings go to ``vulnerabilities`` (linked to ``scans``),
    endpoint/metadata tables are populated.
  - public:   findings go to ``public_vulnerabilities`` (linked to
    ``public_scans``); endpoint/metadata tables are skipped because public
    scans have no row in the internal ``scans`` table.

All custom-engine fields (endpoint, parameter, confidence, detector,
MITRE mapping, structured evidence) are persisted so the UI and reports can
display them.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

logger = logging.getLogger(__name__)

# scan-kind -> table names
_SCAN_TABLES = {
    'internal': 'scans',
    'public': 'public_scans',
}
_FINDINGS_TABLES = {
    'internal': 'vulnerabilities',
    'public': 'public_vulnerabilities',
}
# Column that links a finding to its scan row (differs between the two tables)
_SCAN_ID_COLUMNS = {
    'internal': 'scan_id',
    'public': 'public_scan_id',
}

# Columns shared by `vulnerabilities` and `public_vulnerabilities`.
_FINDINGS_COLUMNS = [
    'id', 'scan_id', 'title', 'description', 'severity', 'cvss_score',
    'cvss_vector', 'cve_id', 'affected_component', 'remediation', 'references',
    'category', 'raw_output', 'status', 'confidence', 'endpoint', 'parameter',
    'detected_by', 'mitre_technique', 'mitre_tactic', 'evidence',
    'ml_classification', 'ml_verification_status',
    'created_at', 'updated_at',
]


class DatabaseWriter:
    """Writes scan results directly to PostgreSQL using SQLAlchemy."""

    def __init__(self, db_url: str, scan_kind: str = 'internal'):
        if scan_kind not in _SCAN_TABLES:
            raise ValueError(f"Unknown scan_kind: {scan_kind!r} (use 'internal' or 'public')")
        self.scan_kind = scan_kind
        self.engine = create_engine(db_url, pool_size=5, max_overflow=10)
        self.SessionLocal = sessionmaker(bind=self.engine)

    # ─── helpers ────────────────────────────────────────────────────────────

    def _is_public(self) -> bool:
        return self.scan_kind == 'public'

    def _scan_table(self) -> str:
        return _SCAN_TABLES[self.scan_kind]

    def _findings_table(self) -> str:
        return _FINDINGS_TABLES[self.scan_kind]

    # ─── findings ───────────────────────────────────────────────────────────

    def write_findings(
        self,
        scan_id: str,
        findings: list[dict],
    ) -> int:
        """Bulk insert vulnerability findings. Returns count of inserted rows."""
        if not findings:
            return 0

        table = self._findings_table()
        # Double-quote every column: `references` is a reserved word in Postgres
        # and would otherwise make the INSERT statement a syntax error.
        # Only public scans use public_scan_id as the linking column — the
        # internal `vulnerabilities` table has a plain scan_id column.
        if self._is_public():
            columns = ['public_scan_id' if c == 'scan_id' else c for c in _FINDINGS_COLUMNS]
        else:
            columns = list(_FINDINGS_COLUMNS)
        cols = ', '.join(f'"{c}"' for c in columns)
        placeholders = ', '.join(f':{c}' for c in _FINDINGS_COLUMNS)
        now = datetime.utcnow()

        count = 0
        with self.SessionLocal() as session:
            try:
                for f in findings:
                    evidence = f.get('evidence') or {}
                    session.execute(
                        text(f"""
                            INSERT INTO {table} ({cols})
                            VALUES ({placeholders})
                        """),
                        {
                            'id': str(uuid.uuid4()),
                            'scan_id': str(scan_id),
                            'title': f.get('title', ''),
                            'description': f.get('description', ''),
                            'severity': f.get('severity', 'info'),
                            'cvss_score': f.get('cvss_score'),
                            'cvss_vector': f.get('cvss_vector'),
                            'cve_id': f.get('cve_id'),
                            'affected_component': f.get('affected_component', ''),
                            'remediation': f.get('remediation', ''),
                            'references': f.get('references', ''),
                            'category': f.get('category', 'misconfig'),
                            'raw_output': json.dumps(f.get('raw_output') or evidence),
                            'status': f.get('status', 'open'),
                            'confidence': f.get('confidence', 'medium'),
                            'endpoint': f.get('endpoint'),
                            'parameter': f.get('parameter'),
                            'detected_by': f.get('detected_by', ''),
                            'mitre_technique': f.get('mitre_technique'),
                            'mitre_tactic': f.get('mitre_tactic'),
                            'evidence': json.dumps(evidence),
                            'ml_classification': json.dumps(f.get('ml_classification')) if f.get('ml_classification') else None,
                            'ml_verification_status': (f.get('ml_classification') or {}).get('verification_status'),
                            'created_at': now,
                            'updated_at': now,
                        },
                    )
                    count += 1

                session.commit()
                logger.info(f'Wrote {count} findings for scan {scan_id} -> {table}')

            except Exception as e:
                session.rollback()
                logger.error(f'Failed to write findings: {e}')
                raise

        return count

    # ─── endpoints & metadata (internal scans only) ─────────────────────────

    def write_endpoints(
        self,
        scan_id: str,
        endpoints: list[dict],
    ) -> int:
        """Insert discovered endpoints. Returns count of inserted rows.

        Public scans have no row in the internal ``scans`` table and the
        ``discovered_endpoints.scan_id`` column references it, so this is only
        meaningful for internal scans.
        """
        if self._is_public() or not endpoints:
            return 0

        count = 0
        with self.SessionLocal() as session:
            try:
                for ep in endpoints:
                    session.execute(
                        text("""
                            INSERT INTO discovered_endpoints (
                                id, scan_id, url, method, status_code,
                                content_type, parameters, discovered_by, created_at
                            ) VALUES (
                                :id, :scan_id, :url, :method, :status_code,
                                :content_type, :parameters, :discovered_by, :created_at
                            )
                        """),
                        {
                            'id': str(uuid.uuid4()),
                            'scan_id': str(scan_id),
                            'url': ep.get('url', ''),
                            'method': ep.get('method', 'GET'),
                            'status_code': ep.get('status_code'),
                            'content_type': ep.get('content_type'),
                            'parameters': json.dumps(ep.get('parameters', [])),
                            'discovered_by': ep.get('discovered_by', ''),
                            'created_at': datetime.utcnow(),
                        },
                    )
                    count += 1

                session.commit()
                logger.info(f'Wrote {count} endpoints for scan {scan_id}')

            except Exception as e:
                session.rollback()
                logger.error(f'Failed to write endpoints: {e}')
                raise

        return count

    def write_scan_metadata(
        self,
        scan_id: str,
        metadata: dict,
    ) -> None:
        """Insert scan metadata (health score, risk score, etc.) — internal scans only."""
        if self._is_public():
            return

        with self.SessionLocal() as session:
            try:
                session.execute(
                    text("""
                        INSERT INTO scan_metadata (
                            id, scan_id, health_score, health_grade, risk_score,
                            total_endpoints, total_parameters, scan_duration_ms,
                            scanner_version, score_breakdown, created_at
                        ) VALUES (
                            :id, :scan_id, :health_score, :health_grade, :risk_score,
                            :total_endpoints, :total_parameters, :scan_duration_ms,
                            :scanner_version, :score_breakdown, :created_at
                        )
                    """),
                    {
                        'id': str(uuid.uuid4()),
                        'scan_id': str(scan_id),
                        'health_score': metadata.get('health_score', 100),
                        'health_grade': metadata.get('health_grade', 'A+'),
                        'risk_score': metadata.get('risk_score', 0),
                        'total_endpoints': metadata.get('total_endpoints', 0),
                        'total_parameters': metadata.get('total_parameters', 0),
                        'scan_duration_ms': metadata.get('scan_duration_ms', 0),
                        'scanner_version': metadata.get('scanner_version', '3.0.0'),
                        'score_breakdown': json.dumps(metadata.get('score_breakdown', {})),
                        'created_at': datetime.utcnow(),
                    },
                )
                session.commit()
                logger.info(f'Wrote scan metadata for scan {scan_id}')

            except Exception as e:
                session.rollback()
                logger.error(f'Failed to write scan metadata: {e}')
                raise

    # ─── scan status ────────────────────────────────────────────────────────

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        total_vulnerabilities: int = 0,
        error_message: str | None = None,
        progress: int | None = None,
    ) -> None:
        """Update scan status on the table matching this writer's scan kind."""
        with self.SessionLocal() as session:
            try:
                updates: dict[str, Any] = {
                    'status': status,
                    'total_vulnerabilities': total_vulnerabilities,
                    'updated_at': datetime.utcnow(),
                }
                if status == 'completed':
                    updates['completed_at'] = datetime.utcnow()
                if error_message:
                    updates['error_message'] = error_message
                if progress is not None:
                    updates['progress'] = progress

                set_clause = ', '.join(f'{k} = :{k}' for k in updates)
                updates['scan_id'] = str(scan_id)

                result = session.execute(
                    text(f"UPDATE {self._scan_table()} SET {set_clause} WHERE id = :scan_id"),
                    updates,
                )
                session.commit()
                if result.rowcount == 0:
                    logger.warning(
                        f'No row updated in {self._scan_table()} for scan {scan_id} '
                        f'(status={status}) — scan may not exist in this table'
                    )
                else:
                    logger.info(
                        f'Updated {self._scan_table()}.{scan_id} status to {status}'
                    )

            except Exception as e:
                session.rollback()
                logger.error(f'Failed to update scan status: {e}')
                raise

    def close(self) -> None:
        """Close the database engine."""
        self.engine.dispose()
