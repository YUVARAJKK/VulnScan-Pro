# VulnScan Pro — Integrated Vulnerability Scanning and Reporting System

![Version](https://img.shields.io/badge/version-3.1.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Node](https://img.shields.io/badge/node-18%2B-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%2B-brightgreen)

A self-hosted vulnerability scanning and security reporting platform built around a **project-owned, custom Python web vulnerability scanning engine** (discovery → detection → evidence validation → confidence scoring → risk/health scoring → MITRE ATT&CK mapping → remediation → reporting). The Node.js API, Redis/BullMQ queue, PostgreSQL store and React dashboard orchestrate and present the engine's output.

> **Architecture principle:** the primary contribution is the custom Python engine (`scanner_engine/`). Established third-party tools (Nmap, Nikto, OWASP ZAP, ...) are **not** bundled or emulated — findings are produced and attributed only to the custom engine. An optional Docker-isolated supplementary-tool layer is designed for but not enabled.

## 🚀 Features

- **Custom Python scanning engine** — same-origin crawler, robots.txt/sitemap parsing, form & parameter discovery, technology detection
- **Custom detectors** — security headers, cookie flags, CORS policy, HTTP methods, information disclosure, directory exposure, reflected XSS (marker + context analysis), SQL injection (error-based + differential), open redirect, path traversal
- **Evidence validation & false-positive reduction** — baseline comparison, controlled verification, context-aware analysis, confidence scoring (high/medium/low), fingerprint deduplication
- **Analysis** — explainable severity-band risk model, 0–100 security health score with grade, per-finding CVSS + OWASP + MITRE ATT&CK mapping, specific remediation guidance
- **AI/ML classification** — locally-trainable scikit-learn Random Forest classifies findings as likely genuine vs. likely false positive (evidence-based features, versioned model + schema, configurable threshold); a transparent rule-based fallback runs when no trained model exists, and every fallback classification is flagged for manual review. See `docs/machine-learning.md`
- **Two scan flows** — authenticated scans (assets) and public scans (email-gated, token-protected report links)
- **Background processing** — Redis + BullMQ queues, retries, progress tracking, concurrency caps, failure handling
- **Reporting** — professional PDF / HTML reports plus PDF / XML / JSON exports with executive summary, severity distribution, detailed findings, MITRE attack map, remediation roadmap
- **RBAC + audit** — admin/analyst/viewer roles, per-resource ownership checks, JWT auth with TOTP MFA option, full audit trail
- **SSRF-safe** — target validation in Node.js *and* Python blocks private/reserved IPs, IPv4-mapped IPv6, metadata endpoints and DNS-rebinding surfaces; redirect hops are re-validated during scans
- **Docker ready** — one-command deployment (PostgreSQL, Redis, API, workers, frontend)

## 📁 Project Structure

```
├── scanner_engine/           # ★ CUSTOM PYTHON SCANNING ENGINE (primary contribution)
│   ├── main.py               # CLI entry (invoked by BullMQ workers)
│   ├── config.py
│   ├── core/                 # http client (rate limit/retries), SSRF guard, URL utils
│   ├── discovery/            # crawler, robots.txt/sitemap, technology detection
│   ├── detectors/            # 10 custom detectors (headers, xss, sqli, cors, ...)
│   ├── validation/           # baseline, evidence, confidence, deduplication
│   ├── analysis/             # severity/health scoring (canonical model)
│   ├── mitre/                # ATT&CK mapping
│   ├── remediation/          # remediation engine
│   ├── models/               # finding/scan-result pydantic models
│   ├── storage/              # PostgreSQL writer (internal + public scans)
│   └── tests/                # pytest suite (37 tests)
├── backend/
│   └── src/
│       ├── config/           # app/database config
│       ├── controllers/      # auth, assets, scans, reports, dashboard, public scans
│       ├── middleware/       # JWT auth, RBAC, error handling, audit
│       ├── models/           # Sequelize models (users … scan_metadata, endpoints)
│       ├── routes/v1/        # versioned Express routes
│       ├── scanners/         # PythonScanner subprocess bridge
│       ├── workers/          # BullMQ scan workers + schedulers
│       ├── reports/          # PDF/HTML report generator
│       └── utils/            # SSRF protection, risk scoring mirror, email, logger
├── frontend/
│   └── src/                  # React 18 + Vite + Tailwind (13 pages)
├── docs/                     # project documentation
├── docker-compose.yml        # full stack
├── Dockerfile.scanner        # worker image (Node + Python engine)
└── openapi.yaml              # OpenAPI 3.0 spec
```

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Scanner engine | **Python 3.10+, httpx (async), pydantic v2, SQLAlchemy** |
| Frontend | React 18, Vite, Tailwind CSS, Chart.js |
| Backend | Node.js 18+, Express.js |
| Database | PostgreSQL 15 (Sequelize ORM + engine writes) |
| Job queue | Redis + BullMQ |
| Auth | JWT + bcrypt + RBAC (+ TOTP MFA) |
| Reports | PDFKit + Handlebars |

## ⚡ Quick Start

### Prerequisites
- Docker Desktop (recommended), or Node.js 18+, Python 3.10+, PostgreSQL 15+, Redis 7+

### Docker Compose (recommended)

```bash
docker compose up -d --build

# Frontend:  http://localhost:3001   (nginx proxies /api to the backend)
# Backend:   http://localhost:3001/api/v1/health
# Postgres:  localhost:5433   Redis: localhost:6379
```

Then create the schema once:

```bash
docker compose exec backend npm run db:sync
docker compose exec backend npm run db:seed
```

> A fresh Postgres volume is initialized automatically; `db:sync` is only
> required when upgrading an existing database. Workers run in dedicated
> containers (`worker`, `public-worker`) — the API container skips in-process
> worker startup (`WORKER_MODE=true`).

### Local Development

```bash
# 1. Backend
cd backend && cp .env.example .env && npm install && npm run db:sync && npm run db:seed
npm run dev                    # API on http://localhost:5000

# 2. Worker (terminal 2) — requires Redis
node src/workers/scanWorker.js

# 3. Python scanner deps
cd ../scanner_engine && pip install -r requirements.txt

# 4. Frontend (terminal 3)
cd ../frontend && npm install && npm run dev   # http://localhost:3000
```

### Default Credentials

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@vulnscan.com | Admin@123 |
| Analyst | analyst@vulnscan.com | Analyst@123 |

Only scan systems you own or have explicit permission to test.

## 🔎 Running a scan

- **Public scan**: landing page → email + URL → results link emailed / shown on completion (token-protected for 7 days).
- **Authenticated scan**: Assets → New Scan → target URL → BullMQ queue → Python engine writes findings to PostgreSQL → Scan detail shows the full report (findings, evidence, confidence, MITRE mapping, remediation) with PDF/CSV/JSON export.

## 🧪 Testing

```bash
cd backend && npm test                  # Jest — 23 tests
cd scanner_engine && python -m pytest   # pytest — 53 tests
cd frontend && npm run build            # production build check
```

### Train the ML classifier (optional)

```bash
cd scanner_engine
python -m ml.train_model --dataset path/to/labelled.csv   # real data
python -m ml.train_model --synthetic                      # pipeline test only
```

Without a trained model the engine uses a clearly-labelled rule-based fallback —
no fabricated accuracy, no silent pretend-ML. Details: `docs/machine-learning.md`.

## 📚 Documentation

See `docs/` — in particular `docs/technical-assessment.md` (Phase-1 audit) and
`docs/architecture.md`. Detailed API surface: `openapi.yaml`.

## 📄 License

Developed as a final-year academic project.
