#!/bin/bash

# HoneyGuard Backend - Simple Start
# This script uses the existing .env configuration

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

# Stop existing container if running
echo "🔄 Stopping existing container..."
docker stop honeyguard-backend 2>/dev/null || true
docker rm honeyguard-backend 2>/dev/null || true

# Build image
echo "🔨 Building image..."
docker build -t honeyguard-backend .

# Run container
echo "🚀 Starting container..."
docker run -d \
  --name honeyguard-backend \
  --env-file .env \
  -p ${FLASK_PORT:-5000}:${FLASK_PORT:-5000} \
  --restart unless-stopped \
  honeyguard-backend

echo "✅ HoneyGuard Backend started successfully!"
echo "📍 Available at: http://localhost:${FLASK_PORT:-5000}"
echo "📊 View logs: docker logs -f honeyguard-backend"
echo "🛑 Stop: docker stop honeyguard-backend"