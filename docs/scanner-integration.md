# Scanner Integration Design (Custom Python Engine)

> **Status note (v3.x):** the legacy multi-plugin architecture (Nmap/Nikto/
> OpenVAS/WPScan/SQLMap scanner plugins executed by the Node.js backend) has
> been removed. All scanning is performed by the **project-owned Python engine**
> in `scanner_engine/`, invoked by BullMQ workers through a single subprocess
> bridge. This document describes the current design.

## 1. Architecture

```
Node.js BullMQ Worker
        │  spawn: python main.py --target <url> --scan-id <uuid> \
        │         --db-url <postgres://...> --scan-kind internal|public
        ▼
Python engine (scanner_engine/)
  1. SSRF re-validation (defense in depth)
  2. Discovery      crawler (same-origin BFS, depth/page/rate caps),
                    robots.txt + sitemap parsing, form & query-parameter
                    extraction, technology detection
  3. Passive tests  security_headers, cookie_security, cors, http_methods,
                    information_disclosure, directory_exposure
  4. Active tests   xss (marker + context analysis), sqli (error-based +
                    differential), open_redirect, path_traversal
  5. Post-processing deduplication → MITRE ATT&CK mapping → remediation
  6. Analysis       severity-band risk + health score (canonical model)
  7. Persistence    findings/endpoints/metadata written straight to PostgreSQL
        │
        ▼
PostgreSQL ──► Node.js API ──► Dashboard / Scan Results / PDF·XML·JSON reports
```

Scan *kind* controls the destination tables:

| kind | scan record | findings |
|------|-------------|----------|
| `internal` | `scans` | `vulnerabilities` (+ `discovered_endpoints`, `scan_metadata`) |
| `public`   | `public_scans` | `public_vulnerabilities` |

## 2. Normalized Finding Schema

Every detector returns a pydantic `Finding` (see `scanner_engine/models/finding.py`),
which is persisted into the shared vulnerability columns:

```json
{
  "id": "uuid",
  "scan_id": "uuid",
  "title": "Missing Content-Security-Policy header",
  "description": "…",
  "severity": "medium",
  "cvss_score": 4.3,
  "cvss_vector": null,
  "cve_id": null,
  "category": "headers",
  "endpoint": "https://target/",
  "parameter": null,
  "confidence": "high",
  "detected_by": "security_headers",
  "mitre_technique": "T1190",
  "mitre_tactic": "Initial Access",
  "evidence": { "header": "Content-Security-Policy", "observed": "missing" },
  "remediation": "…",
  "references": "…",
  "status": "open"
}
```

`detected_by` names the custom detector that produced the finding (security_headers,
cookie_security, cors, http_methods, information_disclosure, directory_exposure,
xss, sqli, open_redirect, path_traversal). A future optional supplementary-tool
layer would record `supplementary_tool:<name>` here so **custom engine findings**
and **tool findings** remain distinguishable in the UI and reports.

## 3. Execution & Error Flow

1. Controller validates the target (Joi) and runs the Node SSRF guard.
2. Job is enqueued on BullMQ (`scan-queue` / `public-scan-queue`) with retries.
3. Worker (`scanWorker.js` / `publicScanWorker.js`, concurrency 3) sets status to
   `running`, then calls `PythonScanner.run()`.
4. `PythonScanner.js` spawns `main.py` with `shell: false` (no user-controlled
   shell input), a 10-minute kill timer, and forwards `--scan-kind`.
5. The engine updates progress on the scan row, writes results, prints a JSON
   summary to stdout; the worker parses it and updates health/notification data.
6. Engine or worker failures mark the scan `failed`; BullMQ retries with
   exponential backoff (3 attempts internal / 2 public).

## 4. Detector Lifecycle (evidence-first)

Each detector implements `BaseDetector.detect()`:

1. **Baseline request** — capture normal response (status, size, body).
2. **Controlled probe** — send a harmless unique marker / payload.
3. **Response analysis** — compare status/body/error signals against baseline.
4. **Evidence collection** — only observed signals are recorded.
5. **Confidence** — assigned from corroborating signals (never from reflection alone).
6. **Deduplication** — fingerprint (title + component + detector) keeps highest severity.

Rules enforced across the engine:

- XSS is reported only when a *marker* (no executable payload) is reflected
  unencoded in an executable/attribute context; plain unverified reflection is
  downgraded to informational with low confidence.
- SQLi uses error-pattern and differential signals only — no destructive or
  time-based payloads.
- Detectors never fabricate CVEs/CVSS vectors; MITRE mappings are conservative.
- Cookies/session values are never logged or persisted.

## 5. Optional Supplementary Tool Layer (future/designed)

An optional Docker-isolated layer (Nmap/Nikto/ZAP profiles) may be re-introduced
behind `scanner_engine/integration/tool_adapters.py`, with:

- strict target validation & SSRF guards identical to the custom path,
- fixed, non-user-constructed command templates,
- resource limits and timeouts,
- results normalized to the schema above and tagged
  `detected_by: supplementary_tool:<name>`,
- UI/report sections that clearly separate **Custom Findings** from
  **Supplementary Tool Findings**.

## 6. Adding a New Custom Detector

1. Create `scanner_engine/detectors/<name>.py` extending `BaseDetector`
   (implement `detect()`; set `name` + `category`).
2. Optionally add payloads to `scanner_engine/config.py`.
3. Register it in `scanner_engine/main.py` (passive or active list).
4. Add pytest cases under `scanner_engine/tests/` and run
   `python -m pytest tests/ -q` from `scanner_engine/`.
