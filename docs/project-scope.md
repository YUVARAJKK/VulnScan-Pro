# Project Scope

> **v3 status note:** scope history. Final scope centres on the custom Python scanning engine (`scanner_engine/`) with a single `custom` scanner type; Nmap/Nikto/OpenVAS/WPScan/SQLMap integrations were removed.

## 1. Functional Requirements

### 1.1 User Management
| ID | Requirement | Priority |
|----|------------|----------|
| FR-01 | User registration with email verification | High |
| FR-02 | Login with JWT-based authentication | High |
| FR-03 | Multi-Factor Authentication (MFA) via TOTP | Medium |
| FR-04 | Role-Based Access Control (Admin, Analyst, Viewer) | High |
| FR-05 | Profile management (update name, password, avatar) | Medium |
| FR-06 | Admin user management (list, create, deactivate users) | High |

### 1.2 Asset & Target Management
| ID | Requirement | Priority |
|----|------------|----------|
| FR-07 | Add/edit/delete targets (IP addresses) | High |
| FR-08 | Add/edit/delete targets (domain names) | High |
| FR-09 | Add/edit/delete targets (CIDR subnets) | Medium |
| FR-10 | Group assets by organization or project | Medium |
| FR-11 | Validate target format before saving | High |
| FR-12 | Ownership scoping — users see only their assets | High |

### 1.3 Vulnerability Scanning
| ID | Requirement | Priority |
|----|------------|----------|
| FR-13 | Launch on-demand scans against selected targets | High |
| FR-14 | Select scanner type (Nmap, Nikto, OpenVAS, etc.) | High |
| FR-15 | Configure scan policies (port range, intensity) | Medium |
| FR-16 | Schedule recurring scans (cron-based) | Medium |
| FR-17 | View real-time scan status (queued, running, completed, failed) | High |
| FR-18 | Cancel running scans | Medium |
| FR-19 | Retry failed scans | Medium |

### 1.4 Results & Risk Scoring
| ID | Requirement | Priority |
|----|------------|----------|
| FR-20 | View vulnerability findings per scan | High |
| FR-21 | Severity categorization (Critical, High, Medium, Low, Info) | High |
| FR-22 | CVSS-based risk scoring | Medium |
| FR-23 | Search and filter vulnerabilities | Medium |
| FR-24 | Vulnerability detail view (description, remediation, references) | High |

### 1.5 Reporting
| ID | Requirement | Priority |
|----|------------|----------|
| FR-25 | Generate PDF reports with executive summary | High |
| FR-26 | Generate HTML reports | Medium |
| FR-27 | Include severity distribution charts in reports | High |
| FR-28 | Export vulnerability data as CSV | Low |
| FR-29 | Custom report templates | Low |

### 1.6 Notifications
| ID | Requirement | Priority |
|----|------------|----------|
| FR-30 | Email notifications on scan completion | Medium |
| FR-31 | Webhook notifications for 3rd-party integration | Medium |
| FR-32 | In-app notification feed | Low |

### 1.7 Dashboard
| ID | Requirement | Priority |
|----|------------|----------|
| FR-33 | User dashboard with scan summary statistics | High |
| FR-34 | Severity distribution pie/doughnut chart | High |
| FR-35 | Scan trend line chart (scans over time) | Medium |
| FR-36 | Recent scans table | High |
| FR-37 | Admin dashboard with system-wide statistics | Medium |

### 1.8 API
| ID | Requirement | Priority |
|----|------------|----------|
| FR-38 | RESTful API for all core operations | High |
| FR-39 | API versioning (v1) | High |
| FR-40 | API documentation via OpenAPI/Swagger | High |

## 2. Non-Functional Requirements

| ID | Requirement | Category |
|----|------------|----------|
| NFR-01 | Response time < 500ms for API endpoints | Performance |
| NFR-02 | Support 50+ concurrent scans via job queue | Scalability |
| NFR-03 | 99.9% uptime for web interface | Availability |
| NFR-04 | All passwords hashed with bcrypt (cost factor 12) | Security |
| NFR-05 | All API endpoints authenticated except public routes | Security |
| NFR-06 | Input validation on all user inputs | Security |
| NFR-07 | HTTPS enforcement in production | Security |
| NFR-08 | Responsive UI (desktop + tablet) | Usability |
| NFR-09 | Structured logging with Winston | Maintainability |
| NFR-10 | Dockerized deployment | Portability |

## 3. In Scope
- Web application (frontend + backend + database)
- Integration with Nmap, Nikto, OpenVAS, WPScan, SQLMap
- Custom lightweight scanner modules
- PDF and HTML report generation
- Docker Compose deployment
- GitHub Actions CI/CD
- Unit and integration tests
- Complete project documentation

## 4. Out of Scope
- Mobile application (iOS/Android)
- Real-time WebSocket push (polling used instead)
- Kubernetes orchestration (documented but not implemented)
- Commercial scanner integrations (Nessus, Burp Suite Pro)
- SOC/SIEM integration
- Compliance framework mapping (PCI-DSS, HIPAA)

## 5. Constraints
- Final year project timeline: ~12 weeks
- Single developer
- Open-source tools only (no paid scanner licenses)
- Local/self-hosted deployment (no cloud costs)

## 6. Assumptions
- Target machines are authorized for scanning (ethical use)
- Scanner CLI tools are pre-installed on the host or container
- PostgreSQL and Redis are available (via Docker or local install)
- Node.js 18+ runtime available
