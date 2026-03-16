#!/bin/bash

# AUT_SOC Setup Script
set -e

echo "🚀 AUT_SOC Setup Script"
echo "======================="

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

echo "✅ Prerequisites OK"

# Create .env file
echo "⚙️  Configuring environment..."
if [ ! -f .env ]; then
    cp config/env.example .env
    echo "✅ Created .env (update with your credentials)"
else
    echo "✅ .env already exists"
fi

# Create directories
echo "📁 Creating directories..."
mkdir -p logs backups data config/backups
echo "✅ Directories created"

# Install dependencies
echo "🐍 Installing Python dependencies..."
pip install -q -r requirements.txt
echo "✅ Installed"

# Docker setup
echo "🐳 Starting Docker services..."
docker-compose up -d --build
echo "✅ Services started"

# Download models
echo "🤖 Downloading LLM models..."
docker exec soc_ollama ollama pull qwen2.5:14b &
docker exec soc_ollama ollama pull deepseek-r1:14b &
wait

echo "✅ Models downloaded"

echo ""
echo "✅ Setup completed!"
echo "📖 Next steps:"
echo "1. Update .env with your credentials"
echo "2. Access n8n at: http://192.168.118.64:5678"
echo "3. Configure APIs in n8n credentials"
echo "4. Test the workflow"
echo ""
