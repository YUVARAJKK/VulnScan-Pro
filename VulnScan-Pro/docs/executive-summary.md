# Executive Summary

> **v3 status note:** written for the early multi-tool design. The shipped system's core is a **project-owned custom Python scanning engine** (see `README.md`); third-party scanners are not part of the deliverable.

## Project Title
**VulnScan Pro — Integrated Vulnerability Scanning and Reporting System**

## Problem Statement
Organizations face increasing cybersecurity threats but lack centralized, affordable tools to manage vulnerability scanning across their digital assets. Existing enterprise solutions (Tenable, Qualys, HostedScan) are expensive and complex. Small-to-medium businesses and security teams need an integrated, self-hosted platform that unifies multiple scanning tools under a single dashboard with automated reporting.

## Objectives
1. Build a **web-based platform** that integrates multiple open-source vulnerability scanners (Nmap, OpenVAS, Nikto, WPScan, SQLMap) into a unified interface.
2. Provide **asset management** to track targets (IPs, domains, subnets) across an organization.
3. Automate **scan scheduling**, execution, and result aggregation with risk scoring.
4. Generate **professional PDF/HTML reports** for compliance and stakeholder communication.
5. Implement **role-based access control** (Admin, Analyst, Viewer) with secure authentication.
6. Deliver a **production-ready** system with Docker deployment, CI/CD, and comprehensive testing.

## Methodology
- **Agile development** with iterative sprints
- **Modular architecture** — each scanner integrated via a plugin system
- **Security-first design** — OWASP Top 10 protections built into every layer

## Tech Stack Summary
| Component | Technology |
|-----------|-----------|
| Frontend | React 18, Vite, Tailwind CSS, Chart.js |
| Backend | Node.js, Express.js |
| Database | PostgreSQL (Sequelize ORM) |
| Job Queue | Redis + BullMQ |
| Auth | JWT + bcrypt + RBAC |
| Reports | PDFKit + Handlebars |
| DevOps | Docker Compose, GitHub Actions |

## Expected Outcomes
- Fully functional vulnerability scanning platform with 6+ scanner integrations
- Role-based multi-user system with real-time scan monitoring
- Automated PDF/HTML report generation with severity visualization
- Containerized deployment with one-command setup via Docker Compose
- Comprehensive documentation suitable for a final-year project submission

## Target Users
- **Security Analysts** — run and review vulnerability scans
- **IT Administrators** — manage assets, users, and system configuration
- **Management** — view dashboards, download compliance reports
- **Developers** — integrate via REST API for CI/CD security checks

## Project Timeline
| Phase | Duration | Deliverables |
|-------|----------|-------------|
| Research & Planning | Week 1-2 | Requirements, architecture design |
| Backend Development | Week 3-6 | API, database, scanner integrations |
| Frontend Development | Week 5-8 | UI pages, dashboards, charts |
| Integration & Testing | Week 9-10 | End-to-end testing, bug fixes |
| Documentation & Deployment | Week 11-12 | Reports, Docker setup, final docs |
