# Multi-stage build for Aegis Enterprise SOC Platform + Security Copilot
FROM node:20-slim AS base

# Install Python and build tools for virtual environment setup
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv build-essential && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Set up virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install python dependencies inside the venv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (dev needed for build)
RUN npm ci --production=false

# Copy source code
COPY . .

# Build for production
RUN npm run build

# ── Production stage ──────────────────────────────────────────────────────────
FROM node:20-slim AS production

# Install Python and runtime utilities (wget for health checks)
RUN apt-get update && apt-get install -y python3 python3-venv wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy python virtual environment from base
COPY --from=base /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy built artifacts and runtime dependencies from base
COPY --from=base /app/node_modules   ./node_modules
COPY --from=base /app/dist           ./dist
COPY --from=base /app/package.json   ./package.json
COPY --from=base /app/requirements.txt ./requirements.txt

# Python source modules
COPY --from=base /app/config.py      ./config.py
COPY --from=base /app/mcp_server.py  ./mcp_server.py
COPY --from=base /app/server.ts      ./server.ts
COPY --from=base /app/src            ./src
COPY --from=base /app/ai             ./ai
COPY --from=base /app/alerts         ./alerts
COPY --from=base /app/dashboard      ./dashboard
COPY --from=base /app/detection      ./detection
COPY --from=base /app/detections     ./detections
COPY --from=base /app/generators     ./generators
COPY --from=base /app/datasets       ./datasets
COPY --from=base /app/sample_data    ./sample_data
COPY --from=base /app/stream         ./stream
COPY --from=base /app/storage        ./storage
COPY --from=base /app/test_cases     ./test_cases

# Enterprise Copilot modules
COPY --from=base /app/copilot        ./copilot
COPY --from=base /app/knowledge_base ./knowledge_base

# Remove dev-only npm packages to shrink image
RUN npm prune --production

# Create a non-root system group and user
RUN groupadd -g 10001 aegis && \
    useradd -u 10001 -g aegis -m -s /bin/bash aegis

# Ensure runtime directories exist and set proper permissions
RUN mkdir -p storage sandbox && \
    chown -R aegis:aegis /app /opt/venv

EXPOSE 3000 8100 8501

ENV NODE_ENV=production

# Switch to the non-root user
USER aegis

# Start Node server, Copilot FastAPI service, and Streamlit dashboard
CMD ["sh", "-c", "node dist/server.cjs & python3 -m copilot.server & streamlit run dashboard/dashboard.py --server.port 8501 --server.address 0.0.0.0 --server.headless true & wait"]
