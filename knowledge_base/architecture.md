# Aegis — Platform Architecture Overview

## System Overview

Aegis is a real-time streaming anomaly detection platform designed for Security Operations Centers (SOCs). It ingests event telemetry, detects anomalies using hybrid statistical and machine learning methods, classifies threats, and alerts analysts via Discord and the dashboard.

## Architecture Components

### Event Stream Layer
- **Producer** (`stream/producer.py`): Generates synthetic or live event telemetry at configurable intervals.
- **Consumer** (`detection/consumer.py`): Consumes events from the stream and feeds them into the detection pipeline.

### Detection Engine
- **Hybrid Detector** (`src/hybrid_detector.ts`): Combines Z-score statistical analysis with Isolation Forest ML and EWMA (Exponentially Weighted Moving Average) for robust anomaly detection.
- **Threat Classifier** (`detections/threat_classifier.py`): Classifies detected anomalies into threat categories (brute force, DDoS, exfiltration, insider threat, etc.) with confidence scores.

### AI Agent Layer
- **Agent Loop** (`ai/agent_loop.py`): Multi-step reasoning agent that investigates anomalies using MCP tools.
- **Gemini Explainer** (`ai/gemini_explainer.py`): Uses Google Gemini 2.5 Flash to generate human-readable explanations of anomalies and incidents.
- **MCP Server** (`mcp_server.py`): Model Context Protocol server exposing 8 tools for database queries, risk scoring, incident reporting, log reading, and threat intelligence.

### Storage Layer
- **SQLite** (`storage/db.py`): Primary event store using WAL mode for concurrent reads/writes.
- **PostgreSQL** (new): Enterprise metadata store for users, chat sessions, documents, alerts, and audit logs.
- **Qdrant** (new): Vector database for RAG-powered semantic search across knowledge documents.
- **MinIO** (new): S3-compatible object storage for uploaded documents, PDFs, and investigation artifacts.

### Frontend
- **React Dashboard** (`src/App.tsx`): Single-page application with real-time charts, incident management, user management, and system health monitoring.
- **Streamlit Dashboard** (`dashboard/dashboard.py`): Alternative Python-based analytics dashboard.

### Backend
- **Express Server** (`server.ts`): Node.js API server handling authentication, event ingestion, anomaly detection orchestration, and REST endpoints.
- **Copilot FastAPI** (`copilot/server.py`): Python microservice for RAG-powered security chatbot.

## Data Flow
1. Events are produced at configurable intervals (default 200ms).
2. The hybrid detector analyzes each window (default 60s) using Z-score, iForest, and EWMA.
3. Anomalies trigger the AI agent loop which investigates using MCP tools.
4. Threat classification assigns categories and confidence scores.
5. Incidents are auto-created with AI diagnoses and recommendations.
6. Discord alerts fire for high-severity events.
7. The dashboard displays real-time metrics, charts, and incident details.

## Dual Runtime
The platform operates with both Node.js (TypeScript) and Python runtimes:
- Node.js handles the Express API server, real-time detection, and frontend build.
- Python handles the AI agent loop, threat classification, MCP server, and copilot service.
