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


# Generate Prisma client
RUN npx prisma generate


# Build for production
RUN npm run build:backend


# ── Production stage ──────────────────────────────────────────────────────────
FROM node:20-slim AS production

# Install Python and runtime utilities (wget, curl for health checks)
RUN apt-get update && apt-get install -y python3 python3-venv wget curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy python virtual environment from base
COPY --from=base /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy built artifacts and runtime dependencies from base
COPY --from=base /app/node_modules   ./node_modules
COPY --from=base /app/dist           ./dist
COPY --from=base /app/package.json   ./package.json
COPY --from=base /app/requirements.txt ./requirements.txt

# Application source modules
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
COPY --from=base /app/copilot        ./copilot
COPY --from=base /app/knowledge_base ./knowledge_base
COPY --from=base /app/prisma         ./prisma

# Ensure runtime directories exist
RUN mkdir -p storage sandbox storage/backups

EXPOSE 3000

ENV NODE_ENV=production

# Start Node backend
CMD ["node", "dist/server.cjs"]
