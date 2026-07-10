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


# Install Python and runtime utilities (wget for health checks)
RUN apt-get update && apt-get install -y python3 python3-venv wget && rm -rf /var/lib/apt/lists/*
