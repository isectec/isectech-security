#!/bin/bash
set -euo pipefail

# Trust Scoring Engine Production Startup Script
# Initializes and starts the real-time trust scoring engine with production configuration

echo "========================================"
echo "Trust Scoring Engine Production Startup"
echo "========================================"

# Configuration
export TRUST_SCORING_ENV=${TRUST_SCORING_ENV:-production}
export LOG_LEVEL=${LOG_LEVEL:-INFO}
export WORKERS=${WORKERS:-4}
export PORT=${PORT:-8080}
export HOST=${HOST:-0.0.0.0}

# Health check configuration
export HEALTH_CHECK_INTERVAL=${HEALTH_CHECK_INTERVAL:-30}
export HEALTH_CHECK_TIMEOUT=${HEALTH_CHECK_TIMEOUT:-10}

# Performance tuning
export MAX_REQUESTS=${MAX_REQUESTS:-10000}
export MAX_REQUESTS_JITTER=${MAX_REQUESTS_JITTER:-1000}
export KEEPALIVE=${KEEPALIVE:-5}
export TIMEOUT=${TIMEOUT:-30}

# Cache configuration
export REDIS_URL=${REDIS_URL:-redis://localhost:6379/4}
export CACHE_TTL_SECONDS=${CACHE_TTL_SECONDS:-300}

# Database configuration
export DATABASE_URL=${DATABASE_URL:-postgresql://localhost/trust_scoring}
export DB_POOL_SIZE=${DB_POOL_SIZE:-20}
export DB_MAX_OVERFLOW=${DB_MAX_OVERFLOW:-30}

# Trust scoring configuration
export TENANT_ID=${TENANT_ID:-production}
export MAX_CONCURRENT_CALCULATIONS=${MAX_CONCURRENT_CALCULATIONS:-100}
export TRUST_BASE_SCORE=${TRUST_BASE_SCORE:-0.5}

# Monitoring configuration
export PROMETHEUS_PORT=${PROMETHEUS_PORT:-9090}
export ENABLE_METRICS=${ENABLE_METRICS:-true}

echo "Environment: $TRUST_SCORING_ENV"
echo "Workers: $WORKERS"
echo "Port: $PORT"
echo "Max concurrent calculations: $MAX_CONCURRENT_CALCULATIONS"

# Validate required environment variables
validate_env_vars() {
    local required_vars=(
        "REDIS_URL"
        "DATABASE_URL"
    )
    
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        echo "ERROR: Missing required environment variables:"
        printf "  - %s\n" "${missing_vars[@]}"
        exit 1
    fi
}

# Pre-flight health checks
preflight_checks() {
    echo "Running pre-flight checks..."
    
    # Check Redis connectivity
    echo "Checking Redis connectivity..."
    python -c "
import redis
import sys
from urllib.parse import urlparse

try:
    url = urlparse('$REDIS_URL')
    r = redis.Redis(host=url.hostname, port=url.port or 6379, db=url.path.lstrip('/') or 0)
    r.ping()
    print('✓ Redis connection successful')
except Exception as e:
    print(f'✗ Redis connection failed: {e}')
    sys.exit(1)
" || exit 1
    
    # Check database connectivity
    echo "Checking database connectivity..."
    python -c "
import asyncio
import asyncpg
import sys
from urllib.parse import urlparse

async def check_db():
    try:
        conn = await asyncpg.connect('$DATABASE_URL')
        await conn.execute('SELECT 1')
        await conn.close()
        print('✓ Database connection successful')
    except Exception as e:
        print(f'✗ Database connection failed: {e}')
        sys.exit(1)

asyncio.run(check_db())
" || exit 1
    
    echo "✓ All pre-flight checks passed"
}

# Initialize logging
setup_logging() {
    echo "Setting up logging..."
    
    # Create log directory if it doesn't exist
    mkdir -p /var/log/trust-scoring
    
    # Set proper permissions
    if [[ $EUID -eq 0 ]]; then
        chown trustscoring:trustscoring /var/log/trust-scoring
    fi
    
    # Configure log rotation
    cat > /etc/logrotate.d/trust-scoring << EOF
/var/log/trust-scoring/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    postrotate
        systemctl reload trust-scoring || true
    endscript
}
EOF

    echo "✓ Logging configured"
}

# Initialize monitoring
setup_monitoring() {
    if [[ "$ENABLE_METRICS" == "true" ]]; then
        echo "Setting up monitoring..."
        
        # Start Prometheus metrics endpoint
        python -c "
from prometheus_client import start_http_server, Counter, Histogram, Gauge
import time
import threading

# Start metrics server
start_http_server($PROMETHEUS_PORT)
print('✓ Prometheus metrics endpoint started on port $PROMETHEUS_PORT')
" &
        
        echo "✓ Monitoring configured"
    fi
}

# Performance tuning
performance_tuning() {
    echo "Applying performance tuning..."
    
    # Set system limits
    if [[ $EUID -eq 0 ]]; then
        # Increase file descriptor limits
        echo "fs.file-max = 65535" >> /etc/sysctl.conf
        echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
        
        # Apply changes
        sysctl -p
        
        # Set ulimits
        ulimit -n 65535
        ulimit -u 32768
    fi
    
    # Python optimizations
    export PYTHONUNBUFFERED=1
    export PYTHONOPTIMIZE=1
    export PYTHONDONTWRITEBYTECODE=1
    
    # Disable Python garbage collection for better performance (be careful with memory)
    export PYTHONGC=0
    
    echo "✓ Performance tuning applied"
}

# Cache warmup
cache_warmup() {
    echo "Starting cache warmup..."
    
    python -c "
import asyncio
import aiohttp
import json
from urllib.parse import urljoin

async def warmup_cache():
    base_url = 'http://$HOST:$PORT'
    
    # Wait for service to be ready
    await asyncio.sleep(5)
    
    try:
        async with aiohttp.ClientSession() as session:
            # Check health
            async with session.get(f'{base_url}/api/health') as resp:
                if resp.status != 200:
                    print('Service not ready for warmup')
                    return
            
            # Warmup common entities
            warmup_entities = [
                f'warmup_user_{i}' for i in range(100)
            ]
            
            for entity_id in warmup_entities:
                try:
                    request_data = {
                        'entity_id': entity_id,
                        'entity_type': 'user',
                        'force_refresh': False
                    }
                    
                    async with session.post(
                        f'{base_url}/api/trust-score/calculate',
                        json=request_data
                    ) as resp:
                        if resp.status == 200:
                            print(f'Warmed up cache for {entity_id}')
                        await asyncio.sleep(0.1)  # Rate limiting
                        
                except Exception as e:
                    print(f'Warmup failed for {entity_id}: {e}')
            
            print('✓ Cache warmup completed')
    
    except Exception as e:
        print(f'Cache warmup error: {e}')

asyncio.run(warmup_cache())
" &
}

# Signal handlers for graceful shutdown
setup_signal_handlers() {
    trap 'echo "Shutting down gracefully..."; kill $(jobs -p); wait; exit 0' SIGTERM SIGINT
}

# Health monitoring daemon
start_health_monitor() {
    echo "Starting health monitoring daemon..."
    
    python -c "
import asyncio
import aiohttp
import time
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('health_monitor')

async def health_check():
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('http://$HOST:$PORT/api/health', timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        logger.info(f'Health check OK: {data.get(\"status\", \"unknown\")}')
                    else:
                        logger.warning(f'Health check failed: HTTP {resp.status}')
        except Exception as e:
            logger.error(f'Health check error: {e}')
        
        await asyncio.sleep($HEALTH_CHECK_INTERVAL)

asyncio.run(health_check())
" &
    
    echo "✓ Health monitor started"
}

# Main startup sequence
main() {
    echo "Starting Trust Scoring Engine..."
    
    # Validate environment
    validate_env_vars
    
    # Run pre-flight checks
    preflight_checks
    
    # Setup components
    setup_logging
    setup_monitoring
    performance_tuning
    setup_signal_handlers
    
    # Start health monitor
    start_health_monitor
    
    echo "Starting FastAPI application..."
    
    # Start the application with gunicorn for production
    if command -v gunicorn &> /dev/null; then
        echo "Using Gunicorn ASGI server"
        exec gunicorn \
            --worker-class uvicorn.workers.UvicornWorker \
            --workers $WORKERS \
            --bind $HOST:$PORT \
            --max-requests $MAX_REQUESTS \
            --max-requests-jitter $MAX_REQUESTS_JITTER \
            --timeout $TIMEOUT \
            --keepalive $KEEPALIVE \
            --access-logfile /var/log/trust-scoring/access.log \
            --error-logfile /var/log/trust-scoring/error.log \
            --log-level $LOG_LEVEL \
            --preload \
            --enable-stdio-inheritance \
            api.trust_scoring_engine:app
    else
        echo "Using Uvicorn server"
        exec uvicorn \
            api.trust_scoring_engine:app \
            --host $HOST \
            --port $PORT \
            --workers $WORKERS \
            --log-level $(echo $LOG_LEVEL | tr '[:upper:]' '[:lower:]') \
            --access-log \
            --loop uvloop \
            --http httptools
    fi
    
    # Start cache warmup in background
    cache_warmup
}

# Execute main function
main "$@"