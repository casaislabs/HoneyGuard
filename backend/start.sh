#!/bin/bash

# HoneyGuard Backend - Secure Start
# Uses existing .env configuration with isolated network and persistent volumes

set -e

echo "🍯 Starting HoneyGuard Backend..."

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ Error: .env file not found"
    echo "💡 Copy .env.example to .env and configure the variables"
    exit 1
fi

# Convert Windows line endings to Unix and load .env variables
sed -i 's/\r$//' .env 2>/dev/null || true
source .env

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Error: Docker is not installed"
    exit 1
fi

# Create network if not exists
docker network inspect honeyguard-net >/dev/null 2>&1 || \
  docker network create honeyguard-net

# Create volumes if not exists
docker volume inspect honeyguard-logs >/dev/null 2>&1 || \
  docker volume create honeyguard-logs
docker volume inspect honeyguard-uploads >/dev/null 2>&1 || \
  docker volume create honeyguard-uploads

# Stop existing container if running
echo "🔄 Stopping existing container..."
docker stop honeyguard-backend 2>/dev/null || true
docker rm honeyguard-backend 2>/dev/null || true

# Build image
echo "🔨 Building image..."
docker build -t honeyguard-backend .

# Run container securely
echo "🚀 Starting container..."
docker run -d \
  --name honeyguard-backend \
  --env-file .env \
  -p ${FLASK_PORT:-5000}:${FLASK_PORT:-5000} \
  --network honeyguard-net \
  -v honeyguard-logs:/app/logs \
  -v honeyguard-uploads:/app/uploads \
  --memory="512m" \
  --cpus="1" \
  --restart unless-stopped \
  honeyguard-backend

echo "✅ HoneyGuard Backend started successfully!"
echo "📍 Available at: http://localhost:${FLASK_PORT:-5000}"
echo "📊 View logs: docker logs -f honeyguard-backend"
echo "🛑 Stop: docker stop honeyguard-backend"
