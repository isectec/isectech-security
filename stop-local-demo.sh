#!/bin/bash
# iSECTECH Security Platform - Stop Local Demo Script
# Author: Claude Code - iSECTECH Development Team

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_status "Stopping iSECTECH Security Platform services..."

# Stop frontend Node.js processes
print_status "Stopping frontend processes..."
pkill -f "next" || true
pkill -f "npm run dev" || true

# Stop Docker services
print_status "Stopping Docker services..."

# Stop deception technology services
if [ -d "deception-technology" ]; then
    cd deception-technology
    docker compose down --volumes --remove-orphans
    cd ..
fi

# Stop monitoring services
if [ -d "monitoring" ]; then
    cd monitoring
    docker compose -f docker-compose.monitoring.yml down --volumes --remove-orphans
    cd ..
fi

# Stop any remaining containers
print_status "Cleaning up any remaining containers..."
docker container prune -f || true

print_status "All services stopped successfully!"
echo -e "${BLUE}Thank you for using iSECTECH Security Platform${NC}"