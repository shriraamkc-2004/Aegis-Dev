# Multi-stage build for Aegis Enterprise SOC Platform
FROM node:20-slim AS base

# Install Python for dual-runtime support
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package.json package-lock.json ./

# Install all dependencies (dev needed for build)
RUN npm ci --production=false

# Install Python dependencies
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy source code
COPY . .

# Build for production
RUN npm run build

# ── Production stage ──────────────────────────────────────────────────────────
FROM node:20-slim AS production

RUN apt-get update && apt-get install -y python3 python3-pip python3-venv wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built artifacts and runtime dependencies from base
COPY --from=base /app/node_modules   ./node_modules
COPY --from=base /app/dist           ./dist
COPY --from=base /app/package.json   ./package.json
COPY --from=base /app/requirements.txt ./requirements.txt

# Python source modules
COPY --from=base /app/config.py      ./config.py
COPY --from=base /app/mcp_server.py  ./mcp_server.py
COPY --from=base /app/server.ts      ./server.ts
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

# Remove dev-only npm packages to shrink image
RUN npm prune --production

# Install Python dependencies in production stage
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Ensure runtime directories exist
RUN mkdir -p storage sandbox

EXPOSE 3000 8501

ENV NODE_ENV=production

# Start both Node server and Streamlit dashboard
CMD ["sh", "-c", "node dist/server.cjs & streamlit run dashboard/dashboard.py --server.port 8501 --server.address 0.0.0.0 --server.headless true & wait"]
