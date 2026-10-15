# Phase 1 — Complete Project Audit & Technical Assessment

Project: **VulnScan Pro — Integrated Vulnerability Scanning and Reporting System for Web Security**
Date: September 3, 2026
Scope: Full repository inspection (backend, frontend, scanner_engine, docs, Docker, tests). No code was modified for this assessment.

---

## 1. Existing Architecture

Three-layer, self-hosted platform with **two scan pipelines**:

```
React + Vite frontend
        │
        ▼
Node.js + Express API (backend/src)
        │  JWT auth + RBAC + Joi validation + SSRF checks
        ▼
BullMQ queue (Redis)  ── 'scan-queue' (authenticated) / 'public-scan-queue' (public landing page)
        │
        ▼
BullMQ workers → PythonScanner bridge → spawns `python3 scanner_engine/main.py`
        │
        ▼
Custom Python engine (discovery → detectors → validation → analysis → MITRE → remediation)
        │  writes directly to PostgreSQL (SQLAlchemy raw SQL)
        ▼
PostgreSQL (Sequelize models) → Dashboard / Scan Results / PDF·XML·JSON reports
```

- **Frontend** (`frontend/src`): React 18 + Vite + Tailwind; 13 pages, a shared "console" UI library (`components/console.jsx`), auth via `AuthContext`, axios client in `services/api.js`.
- **Backend** (`backend/src`): Express; routes → controllers → models; BullMQ workers; a PythonScanner subprocess bridge; ReportGenerator (PDFKit) for authenticated reports.
- **Python engine** (`scanner_engine`): async (httpx) crawler + technology detection + robots/sitemap; 10 detectors; confidence + dedup + evidence validation; severity/health scoring; MITRE mapper; remediation engine; direct DB writer.
- **Docker**: compose stack with postgres, redis, backend, worker, public-worker (2 replicas), frontend.

Two user paths:
1. **Authenticated scans** — user registers/login, creates/uses assets, scans target URLs (`/api/v1/scans`).
2. **Public scans** — landing-page form (email + URL) → `public_scans` record → results accessed by a long random bearer token embedded in the emailed link (`/api/v1/public/scan/:token`).

## 2. Technology Stack

| Layer | Technology | Status |
|---|---|---|
| Frontend | React 18, Vite 5, Tailwind 3, Chart.js, axios, react-router 6 | Working |
| Backend | Node 18+, Express 4 | Working |
| DB | PostgreSQL 15 + Sequelize 6 (models), raw SQLAlchemy from Python | Working |
| Queue | Redis + BullMQ | Working |
| Python engine | Python 3.10, httpx, pydantic v2, SQLAlchemy, tldextract | Working — 37/37 tests pass |
| Auth | JWT + bcryptjs + RBAC + TOTP MFA (otplib) + email verification | Working |
| Reporting | PDFKit + Handlebars (backend), PDF/XML/JSON exports on public reports | Working |
| Misc deps | helmet, cors, express-rate-limit, morgan, winston, node-cron, joi, nodemailer, xml2js, uuid | Installed |
| Optional AI | `@anthropic-ai/sdk` — AI remediation endpoint w/ rule-based fallback | Installed, key optional |

## 3. Scan Workflow (as implemented)

1. Validate input (Joi), ownership checks, rate limits (10 scans/email/24h, 50/IP/24h public; 10/user/24h internal).
2. SSRF validation (Node `utils/ssrfProtection.js`): blocks private/reserved IPv4/IPv6 ranges, mapped IPv6, metadata hosts; DNS-resolves hostnames.
3. Create scan record → enqueue BullMQ job (retries 2–3, exponential backoff).
4. Worker (`scanWorker.js` / `publicScanWorker.js`, concurrency 3 each) → `PythonScanner.run()` spawns the engine:
   - `main.py`: re-validates target (defense in depth), updates `scans` status, crawls (≤200 pages, depth 3), robots.txt + sitemap + tech detection, runs passive detectors then active detectors against discovered endpoints/params, deduplicates, maps MITRE, generates remediation, computes risk/health, writes findings + metadata straight to Postgres, prints JSON summary.
5. Worker reads summary, updates health/grade on the asset (internal) or PublicScan (public), sends email notifications.

## 4. Database Architecture

Tables (Sequelize): `users`, `assets`, `scans`, `scan_policies`, `vulnerabilities`, `reports`, `audit_logs`, `public_scans`, `public_vulnerabilities`. Plus raw tables `discovered_endpoints` and `scan_metadata` (created by migration only — **not** Sequelize models). No migration runner; schema maintained via `sequelize.sync` (`db:sync`) + one hand-written migration file. Enum columns for status/severity/role; JSONB for parameters/evidence/output.

## 5. Scanner Integrations

Only **one** scanner remains: the custom Python engine (`scanners/PythonScanner.js` → `scanner_engine`). All third-party tool containers (Nmap, Nikto, OpenVAS, WPScan, SQLMap, ZAP) were removed earlier. **But the README, several docs, and the public XML/JSON export endpoints still claim those tools are used** — stale text that must be corrected (see §13).

## 6. Queue Architecture

- Two BullMQ queues: `scan-queue` (internal, 3 attempts) and `public-scan-queue` (2 attempts) with exponential backoff.
- In-process workers started by `app.js` when Redis is up and `WORKER_MODE !== true`; in Docker, dedicated worker containers run them (WORKER_MODE=true on API container) to avoid double-processing.
- Scan scheduler (node-cron) for recurring scans; cleanup scheduler for expired tokens/old data. Concurrency caps exist (3 per worker). Redis absence is tolerated gracefully (queue features disabled; scan rows marked failed with a clear message).

## 7. Reusable Components (keep)

- Python: `core/http_client.py` (rate limiting + retries + semaphore), `core/ssrf_guard.py`, `core/url_utils.py`, `models/finding.py` (pydantic), `validation/*` (confidence, dedup), `mitre/mapper.py`, `remediation/engine.py`, `analysis/severity.py`.
- Node: `utils/ssrfProtection.js` (thorough IPv4/IPv6 logic), `middleware/auth.js`, `rbac.js`, ownership-scoped controllers, `reports/ReportGenerator.js`, migration file for engine columns.
- Frontend: `components/console.jsx` UI kit, `ScanReportView.jsx` report renderer, `services/api.js`, `store/AuthContext.jsx`.

## 8–12. Redundant / Duplicate / Dead / Broken Items

### Redundant or duplicate implementations
- **Risk/health scoring exists in 4 places with 3 different weights/thresholds:**
  - `scanner_engine/analysis/severity.py` — weights 10/7/4/2/0, risk = Σ×2 (cap 100), A+ ≥ 90.
  - `scanner_engine/analysis/health_score.py` — duplicate of severity's inline grade logic (kept only for its own test).
  - `backend/src/utils/riskScoring.js` — weights 25/12/5/2/0 + CVSS bonus, A+ ≥ 95.
  - `frontend/src/components/ScanReportView.jsx` — mirrors riskScoring.js client-side.
  Same vulnerability set can therefore render *different* scores/grades in different surfaces. Needs one documented model.
- **MITRE mapping implemented twice**: `scanner_engine/mitre/mapper.py` and `backend/src/utils/mitreMapping.js` (both live; outputs not cross-checked).
- **Remediation generated twice per finding**: Python engine writes remediation at scan time; `backend/utils/aiRemediationEngine.js` (Anthropic w/ rule fallback, 738 lines) powers an on-demand endpoint for the same data.
- **Email helpers overlap**: `emailService.js` (415 lines) and `notificationService.js` (122 lines); both are actually used but duplicate templates/logic (`sendScanComplete` in both).

### Dead code
- `scanner_engine/analysis/cvss.py` — not imported anywhere (no tests either).
- `scanner_engine/detectors/sqli.py` — `TIME_PAYLOADS` defined but never used (time-based claims unsupported by code).
- `config/redis.js` (ioredis client) — created but not imported by any consumer (BullMQ builds its own connections).
- `scan_metadata` / `discovered_endpoints` tables are written (only `scan_metadata` — `write_endpoints` is never called) and never read by any API/UI.
- `ScanPolicy` model/table: no policy endpoints or UI; only an optional `policyId` FK on scans.
- `migrations/20240101_add_scanner_engine_fields.js`: the columns it adds exist in models, but the migration file is not executed by any runner (`db:sync` uses `sync({alter})` only).
- Frontend: none confirmed dead (console.jsx is the active UI kit).

### Scratch / debug / junk files (safe deletion candidates — must re-verify with grep before deleting)
- `backend/` root: `get-token.js`, `get-token-clean.js`, `get-users.js`, `fix-roles.js`, `check-scans.js`, `test-api.js`, `test-scanner.js`, `test-joi.js`, `test-ssrf.js`, `test-dns.js`, `test-all-scanners.js` + `latest-token.txt`, `clean-token.txt`, `users.txt`, `error_log.txt`, `error_log2.txt`, `startup_log.txt` (contain credentials/tokens).
- `backend/src/controllers/logs/*.log` — logs written inside the source tree (logger misconfiguration).
- `scanner_engine/.pytest_cache/`, `__pycache__/` + `*.pyc` build artifacts.
- Root `report.pdf`, `logs/` (empty), `backend/reports/*.pdf`, `backend/error_log*`.
- No `.git` repository exists; `.gitignore` may be ineffective for the junk above.

### Broken features (confirmed by inspection)
1. **Public scan results never reach the public UI (critical).** The Python engine writes findings/status into the internal `vulnerabilities` + `scans` tables keyed by the *public* scan UUID (a row in `public_scans`). `public_vulnerabilities` rows are **never created anywhere** (its only reference is a `destroy` in `cleanupScheduler.js`). Consequences: (a) with FK constraints enabled, inserting a `vulnerabilities` row whose `scan_id` doesn't exist in `scans` fails → public scan marked `failed`; (b) even without FKs, `GET /public/scan/:token` joins an empty `public_vulnerabilities` table → summary counts ≠ listed findings, exports/PDF show counts but no findings.
2. **Engine DB writer discards custom-engine fields.** `storage/database.py` inserts only id/scan_id/title/description/severity/cvss_score/cve_id/affected_component/remediation/references/category/raw_output/status — dropping `confidence`, `endpoint`, `parameter`, `detected_by`, `mitre_technique`, `mitre_tactic`, and structured `evidence` (evidence is shoved into `raw_output`). The engine's core value (per-finding evidence, endpoint/parameter, confidence, source, MITRE) is lost at write time, and the UI/PDFs cannot show it.
3. **`write_endpoints` is never invoked** — discovered endpoints are counted (`total_endpoints`) but never persisted.
4. **Backend Jest suite is broken/stale**: 2 failing tests ("Scanner Plugin System") require `src/scanners/BaseScanner` (deleted) and expect 8 registered scanners (only `custom` exists). Much of the suite is tautological (re-implements the logic under test instead of exercising real modules).
5. **Stale vendor claims in exports & docs**: public XML/JSON exports and README/docs list Nmap, Nikto, SSLyze, OWASP ZAP, SQLMap, WPScan, OpenVAS as used scanners — false; only the custom engine runs. Violates the project's own "do not claim without evidence" rule and undermines the custom-engine story.

## 13. Security Issues (audit of implemented controls)

Good controls present: helmet, CORS allow-list, rate limits, JWT + per-resource ownership checks (scans/reports/vulns are IDOR-safe in code), report download path-traversal guard + sanitized filenames, bcrypt, TOTP MFA, audit log middleware, SSRF guard covering private IPv4/IPv6/mapped-IPv6/metadata/DNS rebinding at submission.

Issues to fix:
1. **Public per-IP limits are spoofable** — `req.ip || x-forwarded-for || connection.remoteAddress` trusts a client-supplied `X-Forwarded-For` (behind `trust proxy=1`, any direct client can set it). Spoofing bypasses the per-IP scan cap and pollutes stored IPs.
2. **Redirect destinations are not re-validated.** The engine follows redirects (`follow_redirects=True`) without re-checking scope/SSRF; a validated public target can redirect the scanner to internal/private hosts or metadata endpoints. Crawler should enforce same-origin scope and both layers should re-validate redirect hops (DNS rebinding surface).
3. **XSS detector over-claims**: marker reflection inside a raw `<script>`/event-handler context is reported `high` even though markers are benign strings and no encoding-bypass or executable-context proof is demonstrated; `html.escape` handling can produce contradictory low/medium signals. Needs conservative context+encoding scoring (the “don’t report on reflection alone” rule).
4. **SQLi `TIME_PAYLOADS` are defined but never executed** — no timing analysis despite config claiming it.
5. **Session-less public token**: fine (long random tokens, 7-day expiry, cleanup scheduler), but token is delivered in the initial HTTP response and email; acceptable for the model, keep expiry enforcement (present in controller).
6. **Secrets hygiene**: junk files at `backend/` root contain live tokens (from earlier testing); `config/index.js` ships `fallback-dev-secret` JWT default and compose uses fixed dev secrets — must be clearly dev-only; verify `.env` is gitignored.
7. `users.txt`/`clean-token.txt` etc. — remove before any submission/commit (above).

## 14. Performance Issues

- Python engine inserts findings **row-by-row in one session/transaction** — fine for typical scans; could batch for 100s of findings.
- `Vulnerability.findAll` per scan in worker (full fetch) to recompute health in Node — redundant given the engine already computed and stored a summary.
- Duplicate per-scan severity queries in `scanController` are batched via a single grouped query (already fixed) — OK.
- Crawler caps exist (200 pages / depth 3 / semaphore 50 / rate 20 rps / 120s) — acceptable, no runaway found.
- One engine subprocess per scan (no reuse) — acceptable for BullMQ model; memory bounded by concurrency cap.

## 15. Recommended Refactoring Strategy (priority order)

1. **Fix the public scan pipeline end-to-end** (highest value): make the Python writer target the correct tables for public scans (update `public_scans`, insert into `public_vulnerabilities`) — requires adding the engine columns to `public_vulnerabilities` via migration/model and passing scan-kind from the worker; then verify token report shows real findings.
2. **Persist full engine output**: extend DB writer to store endpoint/parameter/confidence/detected_by/mitre/evidence columns (and `write_endpoints` call) so UI + PDFs reflect engine work.
3. **Correct false vendor claims**: exports, README, docs → "Custom Python Engine" as the only scanner; reintroduce an optional supplementary-tool adapter layer *if* desired, otherwise remove all references.
4. **Unify risk/health model**: single documented algorithm computed once in the engine, consumed by API/reports (delete Node + frontend divergent mirrors or align exactly).
5. **Backend tests overhaul**: replace tautological/stale suites with real unit tests of ssrfProtection, ownership middleware, validation, report controller; keep only accurate scanner-registry tests.
6. **Phase-2 cleanup** (grep-verified): remove scratch files, logs inside src, pycache artifacts, dead modules (`analysis/cvss.py`, unused redis client, unused TIME payloads or implement timing), align `.gitignore`.
7. **Security hardening**: trusted-proxy IP handling, redirect re-validation in engine + crawler scope enforcement, conservative XSS reporting.
8. **Docs/README refresh** + final Phase-27 verification table + viva/IEEE deliverables.

## Verification baseline (recorded before changes)

- Python engine: **37 passed** (`scanner_engine` pytest, Python 3.10).
- Backend Jest: **19 passed / 2 failed** (stale Scanner Plugin System tests) — 21 total.
- Frontend: no Vitest tests present; build not yet verified.
- Environment: Node 24 + Python 3.10/3.12 present; Docker CLI present but **daemon not running** (Postgres/Redis unavailable → end-to-end scan verification blocked until Docker Desktop is started).
