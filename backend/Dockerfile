# ============================================================================
# HoneyGuard Backend - Production Docker Image
# ============================================================================
# Multi-stage build for optimized production deployment
# Python 3.10 with security hardening and performance optimizations

# ============================================================================
# Stage 1: Build Dependencies
# ============================================================================
FROM python:3.10-slim-bullseye as builder

# Set build arguments
ARG DEBIAN_FRONTEND=noninteractive
ARG PIP_NO_CACHE_DIR=1
ARG PIP_DISABLE_PIP_VERSION_CHECK=1

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# ============================================================================
# Stage 2: Production Runtime
# ============================================================================
FROM python:3.10-slim-bullseye as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH" \
    FLASK_ENV=production \
    GUNICORN_ENVIRONMENT=production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r honeyguard && \
    useradd -r -g honeyguard -d /app -s /bin/bash honeyguard

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=honeyguard:honeyguard . /app/

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/uploads && \
    chown -R honeyguard:honeyguard /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/logs /app/uploads

# Switch to non-root user
USER honeyguard

# Expose port (configurable via environment)
EXPOSE 5000

# Add labels for better container management
LABEL maintainer="HoneyGuard Team" \
      version="1.0" \
      description="HoneyGuard Backend - Honeypot Security System" \
      org.opencontainers.image.source="https://github.com/your-org/honeyguard" \
      org.opencontainers.image.title="HoneyGuard Backend" \
      org.opencontainers.image.description="Production-ready honeypot backend service"

# Default command - uses gunicorn with the existing configuration
CMD ["gunicorn", "-c", "gunicorn.conf.py", "main:app"]

# ============================================================================
# Build Instructions:
# ============================================================================
# docker build -t honeyguard-backend:latest .
# docker run -d --name honeyguard-backend \
#   --env-file .env \
#   -p 5000:5000 \
#   -v $(pwd)/logs:/app/logs \
#   -v $(pwd)/uploads:/app/uploads \
#   honeyguard-backend:latest
# ============================================================================