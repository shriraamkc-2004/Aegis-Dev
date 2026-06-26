# Multi-stage build for Aegis Copilot Python Service
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y build-essential && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# ── Production stage ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS production

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy copilot code and config
COPY config.py ./config.py
COPY copilot/ ./copilot
COPY knowledge_base/ ./knowledge_base

# Create non-root system user
RUN groupadd -g 10002 copilot && \
    useradd -u 10002 -g copilot -m -s /bin/bash copilot

RUN mkdir -p storage && chown -R copilot:copilot /app /opt/venv

USER copilot

EXPOSE 8100

CMD ["python", "-m", "copilot.server"]
