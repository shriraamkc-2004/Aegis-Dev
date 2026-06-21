# Aegis — Setup & Deployment Guide

## Prerequisites
- Node.js 18+ and npm
- Python 3.10+
- Docker & Docker Compose (for containerized deployment)

## Local Development

### 1. Install Dependencies
```bash
npm install
pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and set your `GEMINI_API_KEY`.

### 3. Start the Platform
```bash
# Terminal 1: Express server
npx tsx server.ts

# Terminal 2: Python producer (if running locally)
python stream/producer.py
```

### 4. Access the Dashboard
Open `http://localhost:3000` in your browser.

## Docker Deployment

### Build and Run
```bash
docker compose up --build -d
```

### Services
| Service    | Port(s)          | Description                      |
|------------|------------------|----------------------------------|
| aegis-app  | 3000, 8100, 8501 | Main app (API + Copilot + Dash)  |
| qdrant     | 6333, 6334       | Vector database                  |
| postgres   | 5432             | Enterprise metadata database     |
| minio      | 9000, 9001       | Object storage (API + Console)   |

## Environment Variables
See `.env.example` for all configuration options. Key variables:
- `GEMINI_API_KEY` — Required for AI features
- `JWT_SECRET` — Authentication token signing
- `DISCORD_WEBHOOK_URL` — Alert notifications
- `QDRANT_HOST` / `QDRANT_PORT` — Vector store connection
- `POSTGRES_*` — PostgreSQL connection settings
- `MINIO_*` — Object storage settings

## Demo Mode vs Organization Mode
- **Demo Mode**: Uses sample datasets, pre-configured users, no external DB required.
- **Organization Mode**: Connect to real databases via the Connector Wizard.
