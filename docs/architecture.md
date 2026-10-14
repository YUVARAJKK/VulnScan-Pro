# System Architecture

## 1. High-Level Architecture

The system follows a **modular monolith** architecture with clear separation between frontend, backend API, background workers, and data stores.

```mermaid
graph TB
    subgraph Client["Frontend (React + Vite)"]
        UI[Web Browser]
    end

    subgraph Backend["Backend (Node.js + Express)"]
        API[REST API Server]
        AUTH[Auth Middleware]
        RBAC[RBAC Middleware]
        ROUTES[Route Handlers]
        SERVICES[Business Logic Services]
    end

    subgraph Workers["Background Workers"]
        QUEUE[BullMQ Job Queue]
        W1[Scan Worker 1]
        W2[Scan Worker 2]
        W3[Scan Worker N]
    end

    subgraph Scanners["Scanner Plugins"]
        NMAP[Nmap Scanner]
        NIKTO[Nikto Scanner]
        OPENVAS[OpenVAS Scanner]
        WPSCAN[WPScan Scanner]
        SQLMAP[SQLMap Scanner]
        CUSTOM[Custom Scanner]
    end

    subgraph DataStores["Data Stores"]
        PG[(PostgreSQL)]
        REDIS[(Redis)]
    end

    UI -->|HTTP/HTTPS| API
    API --> AUTH --> RBAC --> ROUTES --> SERVICES
    SERVICES -->|Read/Write| PG
    SERVICES -->|Enqueue Jobs| REDIS
    REDIS -->|Dequeue| QUEUE
    QUEUE --> W1 & W2 & W3
    W1 & W2 & W3 --> NMAP & NIKTO & OPENVAS & WPSCAN & SQLMAP & CUSTOM
    W1 & W2 & W3 -->|Store Results| PG
```

## 2. Component Diagram

```mermaid
graph LR
    subgraph Frontend
        PAGES[Pages]
        COMPONENTS[Components]
        HOOKS[Custom Hooks]
        APISERVICE[API Service Layer]
        STORE[Context Store]
    end

    subgraph Backend
        direction TB
        subgraph Middleware
            HELMET[Helmet]
            CORS[CORS]
            RATELIMIT[Rate Limiter]
            JWTAUTH[JWT Auth]
            ROLECHECK[Role Check]
            ERRORHANDLER[Error Handler]
        end

        subgraph Modules
            AUTH_MOD[Auth Module]
            ASSET_MOD[Asset Module]
            SCAN_MOD[Scan Module]
            REPORT_MOD[Report Module]
            NOTIFY_MOD[Notification Module]
            ADMIN_MOD[Admin Module]
        end

        subgraph ScanEngine
            PLUGIN_MGR[Plugin Manager]
            BASE_SCANNER[Base Scanner Class]
            RESULT_NORM[Result Normalizer]
        end
    end
```

## 3. Data Flow — Scan Execution

```mermaid
sequenceDiagram
    participant U as User
    participant A as API Server
    participant DB as PostgreSQL
    participant R as Redis/BullMQ
    participant W as Scan Worker
    participant S as Scanner (e.g. Nmap)

    U->>A: POST /api/v1/scans (target, scanner, policy)
    A->>DB: Create Scan record (status: queued)
    A->>R: Enqueue scan job
    A-->>U: 201 { scanId, status: "queued" }

    R->>W: Dequeue job
    W->>DB: Update Scan status → "running"
    W->>S: Execute scanner CLI
    S-->>W: Raw output (XML/JSON)
    W->>W: Parse & normalize results
    W->>DB: Insert Vulnerability records
    W->>DB: Update Scan status → "completed"

    U->>A: GET /api/v1/scans/:id
    A->>DB: Fetch scan + vulnerabilities
    A-->>U: 200 { scan, vulnerabilities }
```

## 4. Authentication & Authorization Flow

```mermaid
sequenceDiagram
    participant U as User
    participant A as API Server
    participant DB as PostgreSQL

    U->>A: POST /api/v1/auth/login { email, password }
    A->>DB: Find user by email
    A->>A: Verify bcrypt hash
    A->>A: Generate JWT (userId, role, exp)
    A-->>U: 200 { token, user }

    U->>A: GET /api/v1/assets (Authorization: Bearer <token>)
    A->>A: JWT Middleware — verify & decode token
    A->>A: RBAC Middleware — check role >= analyst
    A->>DB: Fetch user's assets
    A-->>U: 200 { assets[] }
```

## 5. Deployment Topology

```mermaid
graph TB
    subgraph DockerCompose["Docker Compose Stack"]
        FE[Frontend Container<br>Nginx + React Build<br>Port 3000]
        BE[Backend Container<br>Node.js + Express<br>Port 5000]
        WK[Worker Container<br>BullMQ Workers<br>+ Scanner CLIs]
        PG[(PostgreSQL<br>Port 5432)]
        RD[(Redis<br>Port 6379)]
    end

    BROWSER[User Browser] -->|:3000| FE
    FE -->|Proxy /api| BE
    BE --> PG
    BE --> RD
    WK --> PG
    WK --> RD

    style FE fill:#61dafb
    style BE fill:#68a063
    style WK fill:#ff6b6b
    style PG fill:#336791
    style RD fill:#dc382d
```

## 6. Security Architecture

### Layered Security Model
1. **Network Layer**: HTTPS enforcement, Helmet headers, CORS whitelist
2. **Application Layer**: JWT authentication, RBAC authorization, input validation (Joi)
3. **Data Layer**: Bcrypt password hashing, parameterized queries (Sequelize ORM), encrypted sensitive fields
4. **Infrastructure Layer**: Docker container isolation, non-root users, secret management via environment variables

### RBAC Role Matrix

| Resource | Admin | Analyst | Viewer |
|----------|-------|---------|--------|
| Manage Users | ✅ | ❌ | ❌ |
| Create/Edit Assets | ✅ | ✅ | ❌ |
| Launch Scans | ✅ | ✅ | ❌ |
| View Results | ✅ | ✅ | ✅ |
| Generate Reports | ✅ | ✅ | ✅ |
| System Settings | ✅ | ❌ | ❌ |

## 7. Logging & Monitoring

- **Application Logs**: Winston logger → console + file rotation
- **Request Logs**: Morgan HTTP request logging
- **Audit Trail**: Database table logging all user actions with timestamps
- **Error Tracking**: Centralized error handler with stack traces in dev, sanitized messages in production
- **Health Check**: `GET /api/v1/health` endpoint for uptime monitoring
