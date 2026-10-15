#!/usr/bin/env python3
"""
VulnScan Pro — Custom Python Vulnerability Scanner Engine
=========================================================
CLI entry point invoked by the Node.js BullMQ worker.

Usage:
    python main.py --target <url> --scan-id <uuid> --db-url <postgresql://...> [--scan-kind internal|public]

The scanner writes results directly to PostgreSQL and prints a JSON summary to stdout.

Scan kinds:
  - internal: findings written to `vulnerabilities` for an authenticated scan.
  - public:   findings written to `public_vulnerabilities` for an anonymous scan.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from urllib.parse import parse_qs, urlparse

# Allow BOTH import styles to work regardless of how the engine is launched:
#  - `python main.py` (script mode, sys.path[0] = engine dir → plain imports)
#  - package imports like `from scanner_engine.core...` used by some detectors
if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import ScannerConfig
from core.http_client import HttpClient
from core.ssrf_guard import validate_target
from core.url_utils import normalize_url, get_subdomain
from models.finding import Finding

# Detectors
from detectors.security_headers import SecurityHeadersDetector
from detectors.cookie_security import CookieSecurityDetector
from detectors.cors import CorsDetector
from detectors.http_methods import HttpMethodsDetector
from detectors.information_disclosure import InformationDisclosureDetector
from detectors.directory_exposure import DirectoryExposureDetector
from detectors.xss import XssDetector
from detectors.sqli import SqliDetector
from detectors.open_redirect import OpenRedirectDetector
from detectors.path_traversal import PathTraversalDetector

# Discovery
from discovery.crawler import Crawler
from discovery.robots_sitemap import fetch_robots_txt, fetch_sitemap_urls
from discovery.technology_detector import detect_technologies

# Validation
from validation.deduplication import deduplicate_findings

# Analysis
from analysis.severity import calculate_risk_score

# MITRE
from mitre.mapper import map_finding_to_mitre

# Remediation
from remediation.engine import generate_remediation

# ML Classification
from ml.classifier import get_classifier

# Storage
from storage.database import DatabaseWriter

SCANNER_VERSION = '3.2.0'

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    stream=sys.stderr,
)
logger = logging.getLogger('vulnscan')

# Candidate parameter names used when a discovered endpoint exposes no real
# parameters (standard black-box parameter fuzzing). Real parameters found in
# URLs and forms always take precedence.
CANDIDATE_PARAMS = ['id', 'q', 'search', 'page', 'name', 'user', 'item', 'cat', 'sort', 'redirect', 'callback']


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='VulnScan Pro — Python Scanner Engine')
    parser.add_argument('--target', required=True, help='Target URL or hostname to scan')
    parser.add_argument('--scan-id', required=True, help='Scan UUID (from Node.js)')
    parser.add_argument('--db-url', required=True, help='PostgreSQL connection URL')
    parser.add_argument('--scan-kind', default='internal', choices=['internal', 'public'],
                        help='Which scan record owns this job (internal scans vs public scans)')
    parser.add_argument('--timeout', type=int, default=15, help='HTTP timeout in seconds')
    parser.add_argument('--max-concurrent', type=int, default=50, help='Max concurrent requests')
    return parser.parse_args()


def params_for_url(url: str) -> list[str]:
    """Return real query-parameter names present in a URL."""
    return list(parse_qs(urlparse(url).query).keys())


async def run_scan(args: argparse.Namespace) -> dict:
    """Execute the full vulnerability scan pipeline."""
    start_time = time.time()
    scan_id = args.scan_id
    target = normalize_url(args.target)
    hostname = get_subdomain(target)

    logger.info(f'Starting {args.scan_kind} scan {scan_id} against {target}')

    # SSRF protection (defense in depth — Node.js also validates on submission)
    is_safe, reason = validate_target(target)
    if not is_safe:
        logger.error(f'SSRF check failed: {reason}')
        return {'success': False, 'error': reason}

    # Config
    config = ScannerConfig.from_env()
    config.timeout = args.timeout
    config.max_concurrent_requests = args.max_concurrent

    # Database writer (table selection depends on scan kind)
    db = DatabaseWriter(args.db_url, scan_kind=args.scan_kind)

    try:
        # Mark as running and report initial progress
        db.update_scan_status(scan_id, 'running', progress=5)

        # Phase 1: Discovery
        logger.info('Phase 1: Discovery — crawling, robots.txt, sitemap, technology detection')
        db.update_scan_status(scan_id, 'running', progress=15)
        async with HttpClient(config) as http_client:
            # Crawl
            crawler = Crawler(config)
            urls, forms = await crawler.crawl(target, http_client)
            logger.info(f'Discovered {len(urls)} URLs, {len(forms)} forms')

            # Robots.txt
            robots = await fetch_robots_txt(target, http_client)
            logger.info(f'robots.txt: {len(robots["disallowed"])} disallowed paths')

            # Sitemap
            sitemap_urls = await fetch_sitemap_urls(target, http_client)
            logger.info(f'Sitemap: {len(sitemap_urls)} URLs')

            # Technology detection
            technologies = await detect_technologies(target, http_client)
            logger.info(f'Technologies: {[t["name"] for t in technologies]}')

            # ── Build endpoint list for active detectors ──
            # Parameters come from real query keys / form fields when available;
            # candidate names are only used for endpoints with no parameters.
            endpoints: list[dict] = []
            for url in urls[: config.crawler_max_pages]:
                real_params = params_for_url(url)
                endpoints.append({
                    'url': url,
                    'method': 'GET',
                    'parameters': real_params or CANDIDATE_PARAMS[:4],
                    'discovered_by': 'crawler',
                })
            for form in forms:
                endpoints.append({
                    'url': form['url'],
                    'method': form.get('method', 'GET'),
                    'parameters': form.get('parameters', []) or CANDIDATE_PARAMS[:4],
                    'discovered_by': 'form',
                })
            for url in sitemap_urls[:50]:
                if url not in urls:
                    endpoints.append({
                        'url': url,
                        'method': 'GET',
                        'parameters': params_for_url(url) or CANDIDATE_PARAMS[:4],
                        'discovered_by': 'sitemap',
                    })

            # Persist discovered endpoints (internal scans only — table is keyed to `scans`)
            db.write_endpoints(scan_id, endpoints)

            # Phase 2: Passive detection
            logger.info('Phase 2: Passive detection — headers, cookies, CORS, info disclosure')
            db.update_scan_status(scan_id, 'running', progress=40)
            detectors = [
                SecurityHeadersDetector(),
                CookieSecurityDetector(),
                CorsDetector(),
                HttpMethodsDetector(),
                InformationDisclosureDetector(),
                DirectoryExposureDetector(),
            ]

            all_findings: list[Finding] = []
            for detector in detectors:
                try:
                    findings = await detector.detect(
                        target,
                        http_client,
                        scan_id=scan_id,
                        hostname=hostname,
                    )
                    all_findings.extend(findings)
                    logger.info(f'{detector.name}: {len(findings)} findings')
                except Exception as e:
                    logger.error(f'{detector.name} failed: {e}')

            # Phase 3: Active detection
            logger.info('Phase 3: Active detection — XSS, SQLi, open redirect, path traversal')
            db.update_scan_status(scan_id, 'running', progress=65)
            active_detectors = [
                XssDetector(),
                SqliDetector(),
                OpenRedirectDetector(),
                PathTraversalDetector(),
            ]

            for detector in active_detectors:
                try:
                    findings = await detector.detect(
                        target,
                        http_client,
                        scan_id=scan_id,
                        hostname=hostname,
                        endpoints=endpoints[:50],
                    )
                    all_findings.extend(findings)
                    logger.info(f'{detector.name}: {len(findings)} findings')
                except Exception as e:
                    logger.error(f'{detector.name} failed: {e}')

        # Phase 4: Post-processing
        logger.info('Phase 4: Post-processing — deduplication, MITRE mapping, remediation')
        db.update_scan_status(scan_id, 'running', progress=80)

        # Deduplicate
        all_findings = deduplicate_findings(all_findings)
        logger.info(f'After dedup: {len(all_findings)} findings')

        # Map MITRE and generate remediation
        for f in all_findings:
            # MITRE mapping
            if not f.mitre_technique:
                mitre = map_finding_to_mitre(f)
                if mitre['techniques']:
                    f.mitre_technique = mitre['primary'].get('id')
                    f.mitre_tactic = mitre['primary'].get('tactic')

            # Remediation
            if not f.remediation:
                f.remediation = generate_remediation(f)

        # Phase 4.5: ML classification — classify collected observations.
        # The scanner discovers candidates; the model classifies them. When no
        # trained model is available the classifier returns a transparent
        # rule-based fallback and flags every finding for manual review.
        logger.info('Phase 4.5: ML classification of findings')
        classifier = get_classifier()
        model_info = classifier.get_model_info()
        classification_results = classifier.classify_batch(
            [f.model_dump(mode='json') for f in all_findings]
        )
        for f, cls in zip(all_findings, classification_results):
            f.ml_classification = cls
        status_counts: dict[str, int] = {}
        for cls in classification_results:
            vs = cls.get('verification_status', 'inconclusive')
            status_counts[vs] = status_counts.get(vs, 0) + 1
        logger.info(
            f'Classification method: {model_info["classification_method"]} — '
            f'verification statuses: {status_counts}'
        )

        # Phase 5: Risk scoring
        logger.info('Phase 5: Risk scoring and health score calculation')
        risk_result = calculate_risk_score(all_findings)

        # Phase 6: Write to database
        logger.info('Phase 6: Writing results to database')
        findings_dicts = [f.model_dump(mode='json') for f in all_findings]
        db.write_findings(scan_id, findings_dicts)

        # Write scan metadata (internal scans only)
        duration_ms = int((time.time() - start_time) * 1000)
        db.write_scan_metadata(scan_id, {
            'health_score': risk_result['health_score'],
            'health_grade': risk_result['grade'],
            'risk_score': risk_result['risk_score'],
            'total_endpoints': len(endpoints),
            'total_parameters': sum(len(ep.get('parameters', [])) for ep in endpoints),
            'scan_duration_ms': duration_ms,
            'scanner_version': SCANNER_VERSION,
            'score_breakdown': risk_result['breakdown'],
            'classification_method': model_info['classification_method'],
            'ml_model_version': model_info['model_version'] or 'none',
            'verification_status_counts': status_counts,
        })

        # Complete
        db.update_scan_status(
            scan_id,
            'completed',
            total_vulnerabilities=len(all_findings),
            progress=100,
        )

        elapsed = time.time() - start_time
        logger.info(
            f'Scan {scan_id} completed in {elapsed:.1f}s — '
            f'{len(all_findings)} findings, '
            f'health: {risk_result["grade"]} ({risk_result["health_score"]}/100), '
            f'risk: {risk_result["risk_score"]}'
        )

        return {
            'success': True,
            'scan_id': scan_id,
            'scan_kind': args.scan_kind,
            'findings_count': len(all_findings),
            'risk_score': risk_result['risk_score'],
            'health_score': risk_result['health_score'],
            'health_grade': risk_result['grade'],
            'severity_counts': risk_result['severity_counts'],
            'verification_status_counts': status_counts,
            'classification_method': model_info['classification_method'],
            'ml_model_version': model_info['model_version'] or 'none',
            'duration_ms': duration_ms,
        }

    except Exception as e:
        logger.error(f'Scan {scan_id} failed: {e}', exc_info=True)
        try:
            db.update_scan_status(scan_id, 'failed', error_message=str(e))
        except Exception as db_err:
            logger.error(f'Could not update scan failure status: {db_err}')
        return {'success': False, 'error': str(e)}

    finally:
        db.close()


def main() -> None:
    args = parse_args()
    result = asyncio.run(run_scan(args))
    # Print JSON summary to stdout for the Node.js worker to read
    print(json.dumps(result))
    sys.exit(0 if result.get('success') else 1)


if __name__ == '__main__':
    main()
