# Anomaly Aegis

**AI-Powered Security Operations Center — Multi-Agent Anomaly Detection & Threat Prevention**

Aegis is an enterprise-grade, full-stack Security Operations Center (SOC) platform that combines real-time statistical anomaly detection, hybrid machine-learning analysis, autonomous AI agent mitigation, and a RAG-powered Security Copilot into a single unified dashboard. It operates in two modes — **Demo** for evaluators and academic demonstrations, and **Organization** for real-world enterprise deployments with live database connectors.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Development](#local-development)
  - [Docker Deployment](#docker-deployment)
- [Environment Configuration](#environment-configuration)
- [Operating Modes](#operating-modes)
- [Dashboard](#dashboard)
- [Hybrid Detection Engine](#hybrid-detection-engine)
- [Enterprise Security Copilot](#enterprise-security-copilot)
- [Responsible AI & Security Boundaries](#responsible-ai--security-boundaries)
- [Disaster Recovery](#disaster-recovery)
- [Health Monitoring](#health-monitoring)
- [API Reference](#api-reference)
- [Default Credentials](#default-credentials)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

### Core Detection & Response
- **Hybrid Anomaly Detection** — Three-layer engine: Z-Score (fast univariate spikes), Isolation Forest (multivariate deep analysis), and EWMA (adaptive trend tracking), all fused into a unified severity classifier
- **Real-Time Telemetry** — Sub-second event ingestion with sliding-window statistical analysis and live timeline visualization
- **Autonomous AI Agent** — ReAct (Reason + Act) loop that queries SQLite via MCP tools, classifies threats, applies source throttling, and dispatches Discord alerts
- **Gemini AI Explanations** — Google Gemini 2.5 Flash generates natural-language incident summaries with full chain-of-thought reasoning
- **Threat Classification** — Automated pattern matching for DDoS, brute force, data exfiltration, insider threats, and service failures
- **Incident Auto-Creation** — Every anomaly automatically generates a linked incident record with root cause, AI diagnosis, and recommended actions

### Enterprise Capabilities
- **Multi-Tenant Architecture** — Organization-isolated data with per-tenant Qdrant collections, PostgreSQL schemas, and RBAC enforcement
- **Role-Based Access Control** — Seven roles: `super_admin`, `org_admin`, `soc_analyst`, `executive_viewer`, `demo_admin`, `demo_analyst`, `demo_viewer`
- **JWT Authentication** — Dual-token system (access + refresh) with bcrypt password hashing and audit-logged sessions
- **Database Connectors** — Connect to PostgreSQL, MySQL, SQLite, SQL Server, and MongoDB with schema discovery and field mapping
- **Live Data Ingestion** — Pull real-time events from connected databases with configurable polling intervals
- **Audit Logging** — Every user action, setting change, AI interaction, and approval decision is immutably recorded
- **PII Masking & Secret Encryption** — Sensitive fields encrypted at rest; PII masked in API responses and audit exports

### Security Copilot (RAG-Powered)
- **4 AI Assistants** — Analyst, Audit, Documentation, and Incident Intelligence, each with specialized system prompts and collection scoping
- **Retrieval-Augmented Generation** — LangChain pipeline: document chunking → Gemini embeddings → Qdrant indexing → semantic retrieval → context-injected Gemini generation
- **4 Qdrant Collections** — `knowledge_base`, `alert_rules`, `incidents`, `logs` with tenant-isolated search
- **MinIO Document Storage** — Upload, retrieve, and index PDFs, Markdown, JSON, and text files into the knowledge base
- **Prompt Registry** — Version-controlled prompt templates with governance review and rollback support

### Responsible AI Governance
- **10 Hard Security Boundaries** — AI can never automatically block IPs, isolate endpoints, disable accounts, alter thresholds, execute mitigations, override RBAC, access cross-tenant data, expose secrets, fabricate evidence, or provide unsupported answers
- **Human-in-the-Loop** — All high-impact recommendations enter `PENDING_APPROVAL` state requiring explicit analyst authorization
- **Hallucination Detection** — Confidence scoring with automatic safe-fallback when evidence is insufficient
- **Safe Failure Protocol** — When Gemini/Qdrant is unavailable or confidence is low: notify user, avoid speculation, recommend human escalation
- **PII Masking** — SSN, email, IP addresses, API keys, and secrets automatically masked in AI responses

### Operational Resilience
- **Disaster Recovery** — Automated backups for PostgreSQL (daily, 30-day retention), Qdrant (daily snapshots, 14-day), MinIO (weekly mirror, 30-day), SQLite (daily, 7-day)
- **Recovery Objectives** — RPO: 1 hour, RTO: 4 hours
- **Health Monitoring** — Automated connectivity checks every 15 seconds for PostgreSQL, Qdrant, MinIO, Gemini, Python Copilot, and SQLite
- **Graceful Degradation** — 6 strategies: SQLite fallback, cached responses, upload disabled, safe fallback, local processing, read-only mode
- **Discord Webhook Integration** — Real-time alert dispatch with configurable webhook URL and test transmission

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Browser (React SPA)                         │
│  Landing → Auth → Connector Setup → Schema Mapping → Dashboard      │
│  12 Tabs: Overview, Incidents, Cases, Copilot, Governance, MITRE,   │
│           Health, Replay, Connectors, Users, Reports, DR            │
└────────────────────────────┬─────────────────────────────────────────┘
                             │ REST API (JWT-authenticated)
┌────────────────────────────▼─────────────────────────────────────────┐
│                    Express Server (Node.js :3000)                     │
│                                                                       │
│  Auth │ Metrics │ Anomalies │ Incidents │ Cases │ Connectors │ Demo  │
│  Governance │ Prompt Registry │ Observability │ Threat Intel │ DR    │
│  Health Monitor │ AI Boundary Middleware │ Evaluation Framework      │
│                                                                       │
│  Hybrid Detector (Z-Score + Isolation Forest + EWMA)                 │
│  ReAct Agent Loop (MCP Tools → Gemini AI → Discord Alerts)          │
└──────┬──────────────┬──────────────┬──────────────┬──────────────────┘
       │              │              │              │
  ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐   ┌─────▼─────┐
  │ SQLite  │   │ PostgreSQL │  │ Qdrant  │   │   MinIO   │
  │ Events  │   │ Enterprise │  │ Vector  │   │  Object   │
  │  (WAL)  │   │  Metadata  │  │  Store  │   │  Storage  │
  └─────────┘   └────────────┘  └─────────┘   └───────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│              Python Copilot FastAPI Service (:8100)                   │
│                                                                       │
│  Chat Engine (4 Assistants) │ RAG Pipeline │ Vector Store Manager    │
│  Responsible AI Engine │ Audit Logger │ Storage Service              │
│  LangChain + Gemini Embeddings + RecursiveCharacterTextSplitter      │
└──────────────────────────────────────────────────────────────────────┘
                             │
              ┌──────────────▼──────────────┐
              │    Streamlit Dashboard (:8501)│
              │    Analytics & Visualization  │
              └─────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 19, TypeScript 5.8, Tailwind CSS 4, Recharts, Lucide React, Motion (Framer) |
| **Backend** | Express 4 (Node.js), Helmet, express-rate-limit, bcryptjs, jsonwebtoken |
| **Primary DB** | SQLite 3 (WAL mode) — events, anomalies, incidents, audit logs |
| **Enterprise DB** | PostgreSQL 16 — multi-tenant metadata, case management, prompt registry |
| **Vector Store** | Qdrant v1.9.7 — RAG embeddings, semantic search, 4 enterprise collections |
| **Object Storage** | MinIO — document upload, knowledge base files, bucket mirroring |
| **AI / LLM** | Google Gemini 2.5 Flash — chat, embeddings, explanations, threat analysis |
| **RAG Pipeline** | LangChain, Gemini text-embedding-004, RecursiveCharacterTextSplitter |
| **Python Services** | FastAPI, Uvicorn, sentence-transformers (fallback embeddings), Pydantic |
| **Analytics** | Streamlit, Pandas |
| **Streaming** | Apache Kafka (producer/consumer), JSON event format |
| **Detection** | Pure TypeScript Isolation Forest, Z-Score, EWMA — no external ML libs |
| **Containerization** | Docker (multi-stage build), Docker Compose (6 services) |
| **Build** | Vite 6 (frontend), esbuild (server bundling), TypeScript strict mode |

---

## Getting Started

### Prerequisites

- **Node.js** 20+
- **Python** 3.10+
- **Docker & Docker Compose** (recommended for full-stack deployment)
- **Google Gemini API Key** (optional — enables AI copilot and explanations)
- **Discord Webhook URL** (optional — enables real-time alert notifications)

### Local Development

```bash
# Clone the repository
git clone <repository-url>
cd Aegis

# Install Node.js dependencies
npm install

# Install Python dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your API keys and settings

# Set operating mode (required)
# MODE=demo     — for demonstrations with sample data
# MODE=organization — for real enterprise deployment

# Start all services
npm run dev          # Express server with Vite HMR on :3000

# In separate terminals:
python -m copilot.server                     # Copilot FastAPI on :8100
streamlit run dashboard/dashboard.py         # Streamlit dashboard on :8501
```

### Docker Deployment

```bash
# Copy and configure environment
cp .env.example .env

# Start the full stack (production)
docker compose up -d

# Or with development profile (hot-reload)
docker compose --profile development up -d
```

This starts all 6 services:
- **Aegis Platform** — :3000 (main dashboard)
- **Qdrant** — :6333 (vector database)
- **PostgreSQL** — :5432 (enterprise metadata)
- **MinIO** — :9000 (object storage), :9001 (console)
- **Python Copilot** — :8100 (RAG + chat service)
- **Streamlit Dashboard** — :8501 (analytics)

### Production Build

```bash
npm run build    # Build frontend (Vite) + server bundle (esbuild)
npm start        # Run production server from dist/server.cjs
```

---

## Environment Configuration

All settings are managed via `.env` (see `.env.example` for reference):

| Variable | Description | Default |
|----------|-------------|---------|
| `MODE` | Operating mode: `demo` or `organization` | **Required** |
| `GEMINI_API_KEY` | Google Gemini API key for AI features | Empty (fallback mode) |
| `JWT_SECRET` | Secret for JWT access token signing | `aegis-enterprise-secret-key-change-in-production` |
| `JWT_REFRESH_SECRET` | Secret for JWT refresh token signing | `aegis-refresh-secret-change-in-production` |
| `DISCORD_WEBHOOK_URL` | Discord webhook for real-time alerts | Empty |
| `EVENT_INTERVAL` | Event feed interval (seconds) | `0.2` |
| `WINDOW_SIZE` | Sliding window size (seconds) | `60` |
| `Z_SCORE_THRESHOLD` | Z-Score breach threshold | `3.0` |
| `POSTGRES_HOST` | PostgreSQL host | `localhost` |
| `POSTGRES_PORT` | PostgreSQL port | `5432` |
| `POSTGRES_DB` | PostgreSQL database name | `aegis_enterprise` |
| `QDRANT_HOST` | Qdrant host | `localhost` |
| `QDRANT_PORT` | Qdrant port | `6333` |
| `MINIO_ENDPOINT` | MinIO endpoint | `localhost:9000` |
| `RAG_CHUNK_SIZE` | RAG document chunk size | `1000` |
| `RAG_TOP_K` | Number of RAG results to retrieve | `5` |
| `RAG_CONFIDENCE_THRESHOLD` | Minimum confidence for AI response | `0.55` |
| `DR_BACKUP_ENABLED` | Enable automated backups | `true` |
| `HEALTH_MONITOR_ENABLED` | Enable health monitoring | `true` |
| `VIRUSTOTAL_API_KEY` | VirusTotal API for threat intel | Empty |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API for threat intel | Empty |

---

## Operating Modes

### Demo Mode
Designed for judges, evaluators, and academic demonstrations. Uses sample datasets and simulated telemetry.

- Pre-seeded demo users (`demo_admin`, `demo_analyst`, `demo_viewer`)
- Sample data replay engine (7 scenario files: brute force, DDoS, exfiltration, insider threat, mixed, etc.)
- JSON upload for custom event scenarios
- Simulated connectors (firewall, auth, VPN, Kafka, syslog)
- Auto-reset on restart when `DEMO_RESET=true`

### Organization Mode
Real-world enterprise deployment connecting to production databases.

- Organization self-registration with admin account creation
- Database connector wizard (PostgreSQL, MySQL, SQLite, SQL Server, MongoDB)
- Schema discovery and field mapping UI
- Live data ingestion from connected databases
- Multi-tenant data isolation
- Full RBAC enforcement

---

## Dashboard

The main dashboard provides 12 specialized tabs:

| Tab | Description |
|-----|-------------|
| **Overview** | Real-time telemetry, live event timeline chart, anomaly feed, hybrid detection metrics, engine controls |
| **Incidents** | Auto-generated incident records with root cause, AI diagnosis, Gemini summaries, severity classification |
| **Cases** | Enterprise case management with SLA tracking, timeline events, analyst assignment, runbook suggestions |
| **Copilot** | RAG-powered AI chat with 4 assistants, source attribution, confidence scores, governance metadata |
| **Governance** | Responsible AI status, audit log, pending approvals, boundary enforcement, evaluation reports |
| **MITRE ATT&CK** | Threat intelligence mapping with 14 tactics and technique database, anomaly-to-MITRE correlation |
| **Health** | Service health monitoring for all 6 infrastructure components with alert management |
| **Replay** | Demo scenario replay engine with speed control (1x-10x) and sample file selection |
| **Connectors** | Database connector management, connection testing, schema discovery, field mapping |
| **Users** | User management with role assignment, organization scoping, PII-masked display |
| **Reports** | JSON/CSV export for anomalies, incidents, and audit logs |
| **Disaster Recovery** | Backup status, RPO/RTO objectives, backup schedules, recent backup history (admin only) |

---

## Hybrid Detection Engine

The three-layer detection engine runs entirely in TypeScript with zero external ML dependencies:

### Layer 1: Z-Score (Fast Statistical)
- Sliding window mean and standard deviation
- Configurable threshold (default: 3.0 standard deviations)
- Sub-millisecond per-event evaluation

### Layer 2: Isolation Forest (Multivariate)
- Pure TypeScript implementation — 50 trees, 128 sample size, depth 8
- Anomaly score: s(x,n) = 2^(-E(h(x))/c(n))
- Trained on historical feature vectors (Z-Score, event count, entropy, burst ratio)
- Scores in [0, 1] range — higher values indicate more anomalous behavior

### Layer 3: EWMA (Adaptive Trend)
- Exponentially Weighted Moving Average with configurable alpha (default: 0.15)
- Tracks rolling mean, variance, standard deviation, and Z-Score
- Adapts to shifting baselines without manual recalibration

### Fusion & Severity Classification
- Weighted combination: `hybrid_score = 0.4 * z_score_norm + 0.35 * iforest_score + 0.25 * ewma_score`
- Source entropy analysis for source concentration detection
- Burst ratio for traffic spike identification
- Severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

## Enterprise Security Copilot

The RAG-powered copilot runs as a Python FastAPI microservice with 4 specialized assistants:

### Assistant Personas

| Assistant | Purpose | Collections Searched |
|-----------|---------|---------------------|
| **Analyst** | Anomaly explanation, severity decisions, mitigation guidance | alerts, incidents, knowledge_base |
| **Audit** | Audit findings, OWASP compliance, risk assessment | incidents, logs, knowledge_base |
| **Documentation** | Architecture, workflows, setup assistance | knowledge_base |
| **Incident Intel** | Similar incidents, investigation summaries, lessons learned | incidents, alerts, logs |

### RAG Pipeline

1. **Document Loading** — Recursively loads `.md`, `.txt`, `.json`, `.pdf` from knowledge base directories
2. **Chunking** — `RecursiveCharacterTextSplitter` (1000 chars, 200 overlap)
3. **Embedding** — Gemini `text-embedding-004` (768-dim) with sentence-transformers fallback
4. **Indexing** — Qdrant vector store with tenant-isolated payloads
5. **Retrieval** — Cosine similarity search, top-5 results, configurable confidence threshold
6. **Generation** — Context-injected Gemini prompt with Responsible AI guardrails
7. **Attribution** — Full source citations with relevance scores and collection names

### Knowledge Base Directories

```
knowledge_base/
├── alert_rules/         # Severity logic, threat classification rules
├── incidents/           # Historical incident reports
├── logs/                # Investigation annotations
└── architecture.md      # System architecture documentation
```

---

## Responsible AI & Security Boundaries

### 10 Hard-Coded Security Boundaries

The AI is **hard-blocked** from:

| # | Boundary | Enforcement |
|---|----------|-------------|
| 1 | Automatically blocking IP addresses | Regex + hard block |
| 2 | Automatically isolating endpoints | Regex + hard block |
| 3 | Automatically disabling accounts | Regex + hard block |
| 4 | Automatically altering detection thresholds | Regex + hard block |
| 5 | Automatically executing mitigation commands | Regex + hard block |
| 6 | Overriding RBAC permissions | Regex + hard block |
| 7 | Accessing cross-tenant data | Tenant isolation filter |
| 8 | Exposing secrets or credentials | Pattern detection + masking |
| 9 | Fabricating evidence or citations | Confidence validation |
| 10 | Providing unsupported claims | Safe fallback enforcement |

### Enforcement Architecture

- **Pre-Request Validation** — Prohibited prompts blocked with HTTP 403 before AI processing
- **Post-Response Enforcement** — Regex pattern matching on AI responses; violating content replaced with safe fallback
- **AI Boundary Middleware** — Express middleware attaches `X-AI-Boundary-Notice` header to all copilot requests
- **Governance Evaluation** — Every response passes through confidence scoring, hallucination detection, PII masking, and policy violation checks
- **Audit Trail** — All boundary violations logged with full context (prompt, response, tenant, user, timestamp)

### Safe Failure Protocol

When the system cannot answer confidently:
1. Returns the exact message: *"I could not find sufficient evidence in the indexed knowledge base to answer this confidently."*
2. Notifies the user of the limitation
3. Recommends escalation to a human analyst
4. Records the event in audit logs

---

## Disaster Recovery

### Backup Strategy

| Component | Frequency | Retention | Method |
|-----------|-----------|-----------|--------|
| **PostgreSQL** | Daily | 30 days | `pg_dump` with gzip compression |
| **Qdrant** | Daily | 14 days | Collection snapshots via REST API |
| **MinIO** | Weekly | 30 days | Bucket mirror via `mc` client |
| **SQLite** | Daily | 7 days | WAL-aware file copy (`.db` + `-wal`) |

### Recovery Objectives

- **RPO (Recovery Point Objective):** 1 hour — maximum acceptable data loss window
- **RTO (Recovery Time Objective):** 4 hours — maximum time to restore full service

### Recovery Plans

Each component includes step-by-step recovery procedures with:
- Prerequisites and tooling requirements
- Ordered recovery steps with exact commands
- Rollback commands for each step
- Estimated duration

Accessible via the API at `GET /api/dr/recovery-plans`.

### Automated Backups

When `DR_BACKUP_ENABLED=true`, the scheduler:
- Runs PostgreSQL, Qdrant, and SQLite backups daily at startup + interval
- Runs MinIO mirror weekly
- Enforces retention policy automatically
- Records all backup history with status, size, and verification

---

## Health Monitoring

### Monitored Services

| Service | Check Method | Interval | Failure Threshold |
|---------|-------------|----------|-------------------|
| PostgreSQL | TCP socket connection | 15s | 3 consecutive |
| Qdrant | HTTP `GET /readyz` | 15s | 3 consecutive |
| MinIO | HTTP `GET /minio/health/live` | 15s | 3 consecutive |
| Gemini | API connectivity test | 15s | 3 consecutive |
| Python Copilot | HTTP `GET /health` | 15s | 3 consecutive |
| SQLite | File existence + WAL check | 15s | 3 consecutive |

### Degradation Strategies

| Service Down | Strategy | Behavior |
|-------------|----------|----------|
| PostgreSQL | `SQLITE_FALLBACK` | Core operations via SQLite; enterprise features paused |
| Qdrant | `CACHED_RESPONSES` | RAG disabled; safe fallback responses served |
| MinIO | `UPLOAD_DISABLED` | Document upload disabled; existing content remains queryable |
| Gemini | `SAFE_FALLBACK` | AI explanations disabled; retrieved knowledge only |
| Python Copilot | `LOCAL_PROCESSING` | Copilot returns maintenance notice; cached responses served |
| SQLite | `READ_ONLY` | Dashboard viewable; no new data written |

---

## API Reference

All endpoints are prefixed with `/api/` and require JWT authentication unless noted.

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate and receive JWT tokens |
| POST | `/api/auth/refresh` | Refresh access token |
| GET | `/api/auth/me` | Current user profile |
| POST | `/api/auth/register-org` | Register new organization (public) |

### Core Telemetry
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/metrics` | Real-time telemetry metrics and hybrid detection state |
| GET | `/api/history` | 120-second event timeline |
| GET | `/api/anomalies` | Recent anomaly records (last 25) |
| GET | `/api/alerts/pending` | Real-time pending anomaly alerts |
| GET | `/api/incidents` | Incident records with joined anomaly data |

### Copilot & Governance
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/copilot/chat` | Send message to AI copilot (proxied to Python service) |
| GET | `/api/copilot/governance/status` | Responsible AI governance status |
| GET | `/api/copilot/governance/audit` | Governance audit log |
| GET | `/api/copilot/governance/approvals` | Pending approval requests |
| GET | `/api/copilot/boundaries` | AI security boundary notice |
| GET | `/api/copilot/prompts` | Prompt registry (all prompts) |
| GET | `/api/copilot/evaluation/report` | AI evaluation report |

### Enterprise Features
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/cases` | List investigation cases |
| POST | `/api/cases` | Create new case |
| GET | `/api/threat-intel/mitre/techniques` | MITRE ATT&CK techniques |
| POST | `/api/threat-intel/mitre/map` | Map anomaly to MITRE technique |
| POST | `/api/threat-intel/lookup` | IOC lookup (VirusTotal, AbuseIPDB, AlienVault) |
| GET | `/api/connectors` | Database connector list |
| POST | `/api/connectors/:id/test` | Test connector connection |

### Infrastructure
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health-monitor/status` | All service health status |
| GET | `/api/health-monitor/alerts` | Health alerts |
| GET | `/api/dr/status` | Disaster recovery status and schedules |
| POST | `/api/dr/backup/all` | Trigger all backups |
| GET | `/api/dr/recovery-plans` | Recovery plan documentation |
| GET | `/api/reports/export/json` | Export report as JSON |
| GET | `/api/reports/export/csv` | Export report as CSV |
| GET | `/api/public/health` | Public health check (no auth) |

---

## Default Credentials

### Demo Mode

| Username | Password | Role | Access |
|----------|----------|------|--------|
| `demo_admin` | `demo123` | Demo Admin | Full demo control |
| `demo_analyst` | `demo123` | Demo Analyst | Investigate & replay |
| `demo_viewer` | `demo123` | Demo Viewer | View dashboards only |

### Organization Mode

| Username | Password | Role | Access |
|----------|----------|------|--------|
| `superadmin` | `admin123` | Super Admin | Full platform control |
| `admin` | `admin123` | Org Admin | Organization management |
| `analyst` | `analyst123` | SOC Analyst | Incident investigation |
| `viewer` | `viewer123` | Executive Viewer | Dashboards & reports |

> **Important:** Change all default passwords before deploying to production.

---

## Project Structure

```
Aegis/
├── server.ts                    # Express server (2400+ lines, 80+ API routes)
├── src/
│   ├── App.tsx                  # React SPA (700+ lines, 12 dashboard tabs)
│   ├── auth.ts                  # JWT auth, RBAC, PII masking, encryption
│   ├── server_db.ts             # SQLite database layer (WAL mode)
│   ├── server_agent.ts          # TypeScript ReAct agent loop (MCP tools)
│   ├── hybrid_detector.ts       # Isolation Forest + EWMA + Z-Score engine
│   ├── discord_alert.ts         # Discord webhook integration
│   └── copilot/
│       ├── governance_service.ts    # Responsible AI governance + 10 boundaries
│       ├── ai_boundary_middleware.ts  # Request/response boundary enforcement
│       ├── health_monitor.ts        # Service health monitoring (6 services)
│       ├── disaster_recovery.ts     # Backup/recovery (PostgreSQL, Qdrant, MinIO, SQLite)
│       ├── case_manager.ts          # Enterprise case management + SLA
│       ├── threat_intel.ts          # MITRE ATT&CK + IOC lookup
│       ├── evaluation.ts            # AI evaluation framework
│       ├── prompt_registry.ts       # Version-controlled prompt templates
│       └── observability.ts         # Cost monitoring + metrics
├── copilot/                     # Python FastAPI microservice
│   ├── server.py                # FastAPI endpoints (chat, ingest, approve)
│   ├── chat_engine.py           # Chat orchestration (4 assistants)
│   ├── rag_pipeline.py          # LangChain RAG pipeline
│   ├── vector_store.py          # Qdrant vector store manager
│   ├── responsible_ai.py        # RAI engine (HITL, hallucination guard)
│   ├── storage_service.py       # MinIO document storage
│   └── config.py                # Environment configuration
├── ai/
│   ├── agent_loop.py            # Python ReAct agent loop
│   └── gemini_explainer.py      # Gemini incident explanations
├── detection/
│   └── consumer.py              # Kafka consumer
├── stream/
│   └── producer.py              # Kafka producer
├── generators/
│   └── scenario_engine.py       # Demo scenario generator
├── detections/
│   └── threat_classifier.py     # Python threat classification
├── alerts/
│   └── discord_alert.py         # Python Discord alerts
├── dashboard/
│   └── dashboard.py             # Streamlit analytics dashboard
├── knowledge_base/              # RAG knowledge sources
│   ├── alert_rules/             # Severity logic, threat classification
│   ├── incidents/               # Historical incident reports
│   └── logs/                    # Investigation annotations
├── sample_data/                 # Demo replay scenarios
│   ├── bruteforce_sample.json
│   ├── ddos_sample.json
│   ├── exfiltration_sample.json
│   ├── insider_sample.json
│   ├── mixed_sample.json
│   ├── normal_sample.json
│   └── service_failure_sample.json
├── storage/                     # SQLite databases (WAL mode)
├── docker-compose.yml           # 6-service orchestration
├── Dockerfile                   # Multi-stage build (Node + Python)
├── package.json                 # Node.js dependencies
├── requirements.txt             # Python dependencies
├── vite.config.ts               # Vite configuration
├── tsconfig.json                # TypeScript strict configuration
└── .env.example                 # Environment variable reference
```

---

## License

This project is developed for academic demonstration and enterprise evaluation purposes.
