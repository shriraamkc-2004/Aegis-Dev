# PROJECT_ANALYSIS.md — Anomaly Aegis Enterprise Gap Analysis

## 1. WHAT ALREADY EXISTS (Fully Functional)

### Core Architecture
| Component | File(s) | Status | Notes |
|---|---|---|---|
| Event Producer (Python) | `stream/producer.py` | ✅ Complete | 5% spike injection, configurable interval |
| Event Producer (Node.js) | `server.ts` (startProducerLoop) | ✅ Complete | Inline in Express server |
| Z-Score Detector (Python) | `detection/consumer.py` | ✅ Complete | Sliding window, cooldown, subprocess spawn |
| Z-Score Detector (Node.js) | `server.ts` (startDetectorLoop) | ✅ Complete | Inline statistical engine |
| SQLite DB Layer (Python) | `storage/db.py` | ✅ Complete | WAL mode, thread-local connections |
| SQLite DB Layer (TypeScript) | `src/server_db.ts` | ✅ Complete | Promise wrappers, WAL mode |
| ReAct AI Agent (Python) | `ai/agent_loop.py` | ✅ Complete | Gemini + deterministic fallback |
| ReAct AI Agent (TypeScript) | `src/server_agent.ts` | ✅ Complete | @google/genai SDK + fallback |
| MCP Server (Python) | `mcp_server.py` | ✅ Complete | 4 tools exposed |
| MCP Tools (TypeScript) | `src/server_agent.ts` (callLocalMCPTool) | ✅ Complete | 4 inline tools |
| Discord Alerting | `alerts/discord_alert.py` | ✅ Complete | Rich embed support |
| React Dashboard | `src/App.tsx` | ✅ Complete | Dark theme, charts, metrics, traces |
| Express REST API | `server.ts` | ✅ Complete | 7 endpoints |
| Streamlit Dashboard | `dashboard/dashboard.py` | ✅ Complete | Alternative Python dashboard |
| Test Suite | `test_cases/test_anomaly.py` | ✅ Complete | 5 test cases |
| Sample Data | `sample_data/*.json` | ✅ Partial | normal + anomaly samples |
| Configuration | `config.py`, `.env.example` | ✅ Complete | dotenv based |

### Existing Database Schema
- `events` — order transaction records
- `anomalies` — detected Z-Score breaches
- `agent_logs` — ReAct reasoning step traces

### Existing API Endpoints
- `GET /api/metrics` — live telemetry
- `GET /api/history` — chart timeline data
- `GET /api/anomalies` — anomaly ledger
- `GET /api/traces/:id` — agent reasoning logs
- `GET /api/settings` — engine configuration
- `POST /api/settings` — live config updates
- `POST /api/trigger-spike` — manual surge injection

### Existing MCP Tools (4 of 8)
1. `query_database()` — read-only SQL
2. `read_system_logs()` — backend log inspection
3. `mitigate_anomaly()` — source throttling + Z-Score adjustment
4. `trigger_discord_alert()` — webhook notifications

---

## 2. WHAT IS PARTIALLY IMPLEMENTED

| Feature | Current State | Gap |
|---|---|---|
| **Authentication** | Client-side hardcoded credentials (admin/admin123, org/org123) stored in localStorage | No JWT, no bcrypt, no backend validation, trivially bypassable |
| **RBAC** | 2 UI roles (admin, organization) with basic UI hiding | Only 2 of 4 required roles, no server-side enforcement |
| **Configuration** | Python config.py + inline Node.js engineSettings | No unified cross-runtime config system |
| **Sample Data** | normal_sample.json + anomaly_sample.json | Missing mixed_sample.json for Demo Mode |

---

## 3. WHAT IS MISSING

### Critical Enterprise Features
- [ ] **Isolation Forest Anomaly Detection** — only Z-Score exists
- [ ] **Incident Management** — no status workflow (OPEN→INVESTIGATING→MITIGATED→CLOSED), no severity levels
- [ ] **JWT Authentication** — no real auth, no token management, no password hashing
- [ ] **Server-side RBAC** — no middleware enforcement, no role-based API access control
- [ ] **Multi-Tenant / Organization Support** — single-tenant only
- [ ] **Database Connector Framework** — no PostgreSQL/MySQL/MongoDB/SQL Server support
- [ ] **Demo Mode** — no sample data upload/replay capability
- [ ] **Audit Logging** — no user action tracking
- [ ] **Security Headers** — no CSP, HSTS, X-Frame-Options, etc.
- [ ] **Rate Limiting** — API endpoints fully open
- [ ] **Input Validation** — no sanitization on API inputs
- [ ] **CSRF/XSS Protection** — none implemented

### Missing MCP Tools (4 of 8)
- [ ] `generate_incident_report()`
- [ ] `calculate_risk_score()`
- [ ] `search_attack_patterns()`
- [ ] `get_threat_statistics()`

### Missing Dashboard Sections
- [ ] Incident Management panel
- [ ] User Management panel
- [ ] Organization Management panel
- [ ] System Health monitor
- [ ] Executive Analytics / trend charts
- [ ] Reports generation/export

### Missing Infrastructure
- [ ] Docker / Docker Compose
- [ ] CI/CD pipeline
- [ ] Environment profiles (dev/staging/prod)
- [ ] Reporting system (PDF/CSV/JSON export)
- [ ] Email alerting channel
- [ ] Mobile application (React Native)

### Missing Database Tables
- `users` — user accounts with hashed passwords
- `organizations` — multi-tenant org records
- `incidents` — incident management records
- `audit_logs` — user action tracking
- `notifications` — alert dispatch history
- `connectors` — database connector configurations

---

## 4. SECURITY ISSUES

| Severity | Issue | Location |
|---|---|---|
| **CRITICAL** | Hardcoded plaintext credentials | `src/App.tsx` lines 112-121 |
| **CRITICAL** | No server-side authentication | All API endpoints |
| **CRITICAL** | No password hashing (bcrypt) | Entire project |
| **HIGH** | No JWT token management | Auth flow |
| **HIGH** | SQL injection surface in MCP query_database | `mcp_server.py` line 71 (only checks `starts with SELECT`) |
| **HIGH** | No rate limiting on any endpoint | `server.ts` |
| **HIGH** | No security headers | `server.ts` |
| **HIGH** | No input validation on POST endpoints | `server.ts` lines 148-162, 165-183 |
| **MEDIUM** | No CSRF protection | React forms |
| **MEDIUM** | No XSS sanitization | User-facing content |
| **MEDIUM** | No audit trail for user actions | Entire project |
| **LOW** | Secrets in .env not encrypted at rest | `.env` file |

---

## 5. SCALABILITY ISSUES

- SQLite only — no production RDBMS support
- Single-node architecture — no horizontal scaling
- No message queue (Redis/Kafka) for event buffering
- Synchronous event processing
- In-memory state for engine settings (lost on restart)
- No connection pooling for Node.js SQLite

---

## 6. TECHNICAL DEBT

- **Dual Runtime Duplication** — Python and Node.js implement same logic independently
- **Streamlit dashboard** overlaps with React dashboard
- **No ORM** — raw SQL scattered across codebase
- **No TypeScript strict mode** — `strict: true` not set in tsconfig
- **No linting config** — no ESLint/Prettier
- **Agent loop coupling** — MCP tool dispatch is inline switch statements

---

## 7. REUSABLE MODULES (Do NOT rewrite)

These are well-implemented and should be preserved/refactored:

1. `storage/db.py` — Thread-safe SQLite connection manager
2. `src/server_db.ts` — Promise-based SQLite wrappers
3. `detection/consumer.py` — Statistical detection formulas
4. `mcp_server.py` — MCP tool architecture pattern
5. `ai/agent_loop.py` — ReAct loop structure + Gemini integration
6. `src/server_agent.ts` — TypeScript ReAct implementation
7. `alerts/discord_alert.py` — Rich embed alert formatting
8. `stream/producer.py` — Event generation + spike injection
9. `config.py` — Centralized Python configuration
10. `test_cases/test_anomaly.py` — Test patterns and fixtures
11. `src/App.tsx` — Dashboard UI components and layout

---

## 8. IMPLEMENTATION ROADMAP

### Phase 2 — Security & Auth Foundation
1. Install `jsonwebtoken`, `bcryptjs`, `helmet`, `express-rate-limit`
2. Expand DB schema: users, organizations, incidents, audit_logs, notifications, connectors
3. Implement JWT auth API (register, login, verify middleware)
4. Implement server-side RBAC middleware with 4 roles
5. Add security headers (helmet) and rate limiting
6. Replace client-side auth with real JWT flow

### Phase 3 — Core Enterprise Features
7. Implement Isolation Forest detection (Python sklearn integration)
8. Build incident management CRUD API + status workflow
9. Add 4 new MCP tools
10. Input validation and CSRF protection

### Phase 4 — Dashboard & Demo Mode
11. Add new dashboard sections (incidents, user mgmt, reports, health)
12. Implement Demo Mode with sample data upload/replay
13. Build reporting/export system (CSV/JSON)
14. Create mixed_sample.json

### Phase 5 — Infrastructure & Polish
15. Alert architecture expansion (email-ready)
16. Expanded test suite
17. Docker + Docker Compose
18. Documentation updates
