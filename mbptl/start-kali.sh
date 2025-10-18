#!/bin/bash

# MBPTL Kali Linux Container - Quick Start Script
# This script helps users quickly set up and access the Kali attack container

echo "================================================"
echo "  MBPTL Kali Container - Quick Start"
echo "================================================"
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Error: Docker is not running!"
    echo "Please start Docker Desktop and try again."
    exit 1
fi

echo "✅ Docker is running"
echo ""

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: docker-compose.yml not found!"
    echo "Please run this script from the mbptl/ directory."
    exit 1
fi

echo "📁 Found docker-compose.yml"
echo ""

# Build the Kali container
echo "🔨 Building the Kali attack container..."
echo "This may take a few minutes on first run..."
docker-compose build attacker-kali

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Build failed! Please check the error messages above."
    exit 1
fi

echo ""
echo "✅ Build completed successfully!"
echo ""

# Start all containers
echo "🚀 Starting all lab containers..."
docker-compose up -d

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Failed to start containers! Please check the error messages above."
    exit 1
fi

echo ""
echo "✅ All containers are running!"
echo ""

# Wait a moment for services to initialize
echo "⏳ Waiting for services to initialize..."
sleep 3

# Show container status
echo ""
echo "📊 Container Status:"
docker-compose ps

echo ""
echo "================================================"
echo "  Setup Complete! 🎉"
echo "================================================"
echo ""
echo "Next Steps:"
echo ""
echo "1. Access the Kali attack container:"
echo "   docker exec -it attacker-kali bash"
echo ""
echo "2. Switch to kali user (if needed):"
echo "   su - kali"
echo ""
echo "3. Start the lab following the writeup:"
echo "   ../writeup/README.md"
echo ""
echo "Target URLs:"
echo "  - Main App: http://localhost:80"
echo "  - Admin Panel: http://localhost:8080/administrator/"
echo "  - Internal services accessible from Kali container"
echo ""
echo "Helpful Commands:"
echo "  - View quick reference: cat ~/tools/../quickref.sh"
echo "  - List all tools: ls -la ~/tools/"
echo "  - Check targets: nmap mbptl-main"
echo ""
echo "================================================"
echo ""
