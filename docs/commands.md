# VulnScan Pro — Commands Reference

> **v3 status note:** Nmap/Nikto CLI prerequisites in the table below are no longer required — scanning runs on the bundled custom Python engine. Docker service ports: frontend `3001`, API via the frontend proxy (`/api`), Postgres `5433`, Redis `6379`.

A complete guide to all the commands needed to set up, run, and manage the application.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Running with Docker (Recommended)](#running-with-docker-recommended)
3. [Running Locally (Without Docker)](#running-locally-without-docker)
4. [Backend Commands](#backend-commands)
5. [Frontend Commands](#frontend-commands)
6. [Database Commands](#database-commands)
7. [Testing Commands](#testing-commands)
8. [Environment Variables](#environment-variables)

---

## Prerequisites

| Tool       | Version  | Purpose                         |
|------------|----------|---------------------------------|
| Node.js    | ≥ 18     | Backend & Frontend runtime      |
| npm        | ≥ 9      | Package manager                 |
| Docker     | ≥ 20     | Container runtime               |
| Docker Compose | ≥ 2  | Multi-container orchestration   |
| PostgreSQL | 15       | Database (if running locally)   |
| Redis      | 7        | Queue & caching (if running locally) |
| Nmap       | latest   | Network scanning (if running locally) |
| Nikto      | latest   | Web server scanning (if running locally) |

---

## Running with Docker (Recommended)

This is the easiest way to get the entire stack running. Docker Compose manages PostgreSQL, Redis, the backend API, the scan worker, and the frontend.

### Start All Services

```bash
docker-compose up --build
```

### Start in Detached Mode (Background)

```bash
docker-compose up --build -d
```

### Stop All Services

```bash
docker-compose down
```

### Stop and Remove All Data (Volumes)

```bash
docker-compose down -v
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f frontend
docker-compose logs -f worker
docker-compose logs -f postgres
docker-compose logs -f redis
```

### Restart a Single Service

```bash
docker-compose restart backend
```

### Service Ports (Docker)

| Service    | URL                        |
|------------|----------------------------|
| Frontend   | http://localhost:3000       |
| Backend API| http://localhost:5000       |
| PostgreSQL | localhost:5432              |
| Redis      | localhost:6379              |

---

## Running Locally (Without Docker)

If you prefer running without Docker, you need PostgreSQL and Redis running on your machine first.

### 1. Install Dependencies

```bash
# Backend
cd backend
npm install

# Frontend
cd ../frontend
npm install
```

### 2. Set Up Environment Variables

Create a `.env` file in the `backend/` directory:

```env
NODE_ENV=development
PORT=5000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnscan_dev
DB_USER=postgres
DB_PASSWORD=postgres

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379

# JWT
JWT_SECRET=your-secret-key-here
JWT_EXPIRES_IN=24h

# CORS
CORS_ORIGIN=http://localhost:3000

# SMTP (Optional — for email notifications)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your-email@example.com
SMTP_PASS=your-email-password
SMTP_FROM=noreply@vulnscan-pro.local

# Logging
LOG_LEVEL=info
LOG_DIR=./logs

# Reports
REPORTS_DIR=./reports
```

### 3. Set Up the Database

```bash
cd backend
npm run db:sync
npm run db:seed    # (Optional) Seed with sample data
```

### 4. Start the Backend

```bash
cd backend
npm run dev
```

The API will be available at **http://localhost:5000**.

### 5. Start the Scan Worker

Open a **separate terminal**:

```bash
cd backend
node src/workers/scanWorker.js
```

### 6. Start the Frontend

Open another **separate terminal**:

```bash
cd frontend
npm run dev
```

The frontend will be available at **http://localhost:3000**.

---

## Backend Commands

Run from the `backend/` directory:

| Command                | Description                            |
|------------------------|----------------------------------------|
| `npm start`            | Start the server (production mode)     |
| `npm run dev`          | Start with hot-reload (development)    |
| `npm run lint`         | Run ESLint on source files             |
| `npm run db:sync`      | Sync database schema (create tables)   |
| `npm run db:seed`      | Seed database with sample data         |

---

## Frontend Commands

Run from the `frontend/` directory:

| Command                | Description                            |
|------------------------|----------------------------------------|
| `npm run dev`          | Start Vite dev server with HMR         |
| `npm run build`        | Build for production (outputs to `dist/`) |
| `npm run preview`      | Preview the production build locally   |

---

## Database Commands

### Using psql (Direct Access)

```bash
# Connect to the database
psql -h localhost -U postgres -d vulnscan_dev

# Via Docker
docker exec -it vulnscan-postgres psql -U postgres -d vulnscan_dev
```

### Reset Database

```bash
# Drop and recreate via Docker
docker-compose down -v
docker-compose up --build -d
```

---

## Testing Commands

### Backend Tests

Run from the `backend/` directory:

```bash
# Run all tests
npm test

# Run tests with coverage report
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Frontend Tests

Run from the `frontend/` directory:

```bash
# Run all tests
npm test

# Run tests with coverage report
npm run test:coverage
```

---

## Environment Variables

Full list of environment variables used by the backend:

| Variable         | Default                          | Description                     |
|------------------|----------------------------------|---------------------------------|
| `NODE_ENV`       | `development`                    | Environment mode                |
| `PORT`           | `5000`                           | Backend server port             |
| `DB_HOST`        | `localhost`                      | PostgreSQL host                 |
| `DB_PORT`        | `5432`                           | PostgreSQL port                 |
| `DB_NAME`        | `vulnscan_dev`                   | Database name                   |
| `DB_USER`        | `postgres`                       | Database user                   |
| `DB_PASSWORD`    | `postgres`                       | Database password               |
| `DB_DIALECT`     | `postgres`                       | Sequelize dialect               |
| `REDIS_HOST`     | `localhost`                      | Redis host                      |
| `REDIS_PORT`     | `6379`                           | Redis port                      |
| `JWT_SECRET`     | `fallback-dev-secret`            | Secret for signing JWTs         |
| `JWT_EXPIRES_IN` | `24h`                            | JWT token expiry duration       |
| `CORS_ORIGIN`    | `http://localhost:3000`          | Allowed CORS origin             |
| `SMTP_HOST`      | —                                | SMTP server host                |
| `SMTP_PORT`      | `587`                            | SMTP server port                |
| `SMTP_USER`      | —                                | SMTP username                   |
| `SMTP_PASS`      | —                                | SMTP password                   |
| `SMTP_FROM`      | `noreply@vulnscan-pro.local`     | Email sender address            |
| `LOG_LEVEL`      | `info`                           | Winston log level               |
| `LOG_DIR`        | `./logs`                         | Directory for log files         |
| `REPORTS_DIR`    | `./reports`                      | Directory for generated reports |
