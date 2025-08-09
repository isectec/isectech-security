# Multi-stage build for production decoy services
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Production stage
FROM node:18-alpine AS production

# Create non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S deception -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Install security and monitoring tools
RUN apk add --no-cache \
    dumb-init \
    curl \
    tini \
    && rm -rf /var/cache/apk/*

# Copy dependencies from builder stage
COPY --from=builder --chown=deception:nodejs /app/node_modules ./node_modules

# Copy application code
COPY --chown=deception:nodejs . .

# Create necessary directories
RUN mkdir -p logs tokens config && \
    chown -R deception:nodejs logs tokens config

# Set up health check script
COPY --chown=deception:nodejs scripts/health-check.sh ./health-check.sh
RUN chmod +x health-check.sh

# Create package.json for the decoy services
RUN cat > package.json << 'EOF'
{
  "name": "isectech-deception-services",
  "version": "1.0.0",
  "description": "Decoy services and canary token management for iSECTECH security platform",
  "main": "services/decoy-service-manager.js",
  "scripts": {
    "start": "node services/decoy-service-manager.js",
    "start:canary": "node services/canary-token-manager.js",
    "deploy-tokens": "node scripts/deploy-canary-tokens.js",
    "health": "./health-check.sh",
    "dev": "nodemon services/decoy-service-manager.js",
    "test": "jest",
    "lint": "eslint .",
    "logs": "tail -f logs/*.log"
  },
  "dependencies": {
    "express": "^4.18.2",
    "pg": "^8.11.3",
    "redis": "^4.6.10",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "@faker-js/faker": "^8.3.1",
    "winston": "^3.11.0",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "rate-limiter-flexible": "^3.0.8",
    "express-validator": "^7.0.1",
    "uuid": "^9.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "eslint": "^8.55.0"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "author": "iSECTECH Security Team",
  "license": "PROPRIETARY"
}
EOF

# Install Node.js dependencies
RUN npm install --production --no-optional && \
    npm cache clean --force

# Create startup script
RUN cat > start.sh << 'EOF'
#!/bin/sh
set -e

# Wait for database connection
echo "Waiting for database connection..."
until pg_isready -h ${DECOY_DATABASE_HOST:-postgres-service} -p ${DECOY_DATABASE_PORT:-5432} -U ${DECOY_DATABASE_USER:-postgres}; do
  echo "Database not ready, waiting..."
  sleep 2
done

echo "Database connection established"

# Wait for Redis connection  
echo "Waiting for Redis connection..."
until redis-cli -h ${REDIS_HOST:-redis-service} -p ${REDIS_PORT:-6379} ping > /dev/null 2>&1; do
  echo "Redis not ready, waiting..."
  sleep 2
done

echo "Redis connection established"

# Start the appropriate service based on SERVICE_TYPE
case "${SERVICE_TYPE:-decoy}" in
  "canary")
    echo "Starting Canary Token Manager..."
    exec node services/canary-token-manager.js
    ;;
  "deploy")
    echo "Deploying Canary Tokens..."
    exec node scripts/deploy-canary-tokens.js
    ;;
  *)
    echo "Starting Decoy Service Manager..."
    exec node services/decoy-service-manager.js
    ;;
esac
EOF

RUN chmod +x start.sh

# Create health check script
RUN cat > health-check.sh << 'EOF'
#!/bin/sh
set -e

# Check if main service is running
SERVICE_PORT=${PORT:-3001}
HEALTH_ENDPOINT="http://localhost:${SERVICE_PORT}/health"

# Perform health check
if curl -f -s -o /dev/null -w "%{http_code}" "$HEALTH_ENDPOINT" | grep -q "200"; then
    echo "Service health check: OK"
    exit 0
else
    echo "Service health check: FAILED"
    exit 1
fi
EOF

RUN chmod +x health-check.sh

# Create configuration file
RUN cat > config/default.json << 'EOF'
{
  "server": {
    "port": 3001,
    "host": "0.0.0.0",
    "trustProxy": true
  },
  "database": {
    "host": "postgres-service",
    "port": 5432,
    "database": "deception",
    "ssl": false,
    "pool": {
      "min": 2,
      "max": 10,
      "idleTimeoutMillis": 30000
    }
  },
  "redis": {
    "host": "redis-service",
    "port": 6379,
    "password": null,
    "db": 0,
    "retryDelayOnFailover": 100,
    "maxRetriesPerRequest": 3
  },
  "security": {
    "rateLimiting": {
      "windowMs": 900000,
      "max": 100,
      "message": "Too many requests from this IP"
    },
    "cors": {
      "origin": ["https://canary-dashboard.isectech.com"],
      "methods": ["GET", "POST", "PUT", "DELETE"],
      "allowedHeaders": ["Content-Type", "Authorization"],
      "credentials": true
    },
    "helmet": {
      "contentSecurityPolicy": {
        "directives": {
          "defaultSrc": ["'self'"],
          "scriptSrc": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
          "styleSrc": ["'self'", "'unsafe-inline'"],
          "imgSrc": ["'self'", "data:", "https:"],
          "connectSrc": ["'self'"]
        }
      }
    }
  },
  "monitoring": {
    "metrics": {
      "enabled": true,
      "port": 9090,
      "path": "/metrics"
    },
    "logging": {
      "level": "info",
      "format": "json",
      "transports": ["console", "file"]
    }
  },
  "deception": {
    "alertWebhook": "https://soc.isectech.com/webhooks/deception-alert",
    "tokenDomain": "canary.isectech.internal",
    "responseDelay": {
      "min": 100,
      "max": 300
    },
    "services": {
      "customerPortal": true,
      "internalApi": true,
      "adminDashboard": true,
      "fileServer": true,
      "databaseApi": true,
      "analyticsService": true,
      "backupService": true
    }
  }
}
EOF

# Set environment variables
ENV NODE_ENV=production \
    PORT=3001 \
    SERVICE_TYPE=decoy \
    DECOY_DATABASE_HOST=postgres-service \
    DECOY_DATABASE_PORT=5432 \
    DECOY_DATABASE_NAME=deception \
    REDIS_HOST=redis-service \
    REDIS_PORT=6379

# Expose ports
EXPOSE 3001 9090

# Add labels for container metadata
LABEL maintainer="security@isectech.com" \
      name="isectech-deception-services" \
      version="1.0.0" \
      description="Decoy services and canary token management" \
      org.opencontainers.image.title="iSECTECH Deception Services" \
      org.opencontainers.image.description="Production decoy services with canary token management" \
      org.opencontainers.image.version="1.0.0" \
      org.opencontainers.image.vendor="iSECTECH" \
      org.opencontainers.image.url="https://github.com/isectech/deception-services" \
      org.opencontainers.image.source="https://github.com/isectech/deception-services" \
      org.opencontainers.image.licenses="PROPRIETARY"

# Switch to non-root user
USER deception

# Set working directory permissions
RUN whoami && ls -la

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ./health-check.sh

# Use tini as init system for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

# Start the service
CMD ["./start.sh"]