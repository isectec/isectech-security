# iSECTECH SIEM ML Anomaly Detection Service
# Production-grade Docker container for ML service deployment
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Create non-root user for security
RUN groupadd -r mlservice && useradd -r -g mlservice mlservice

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libc6-dev \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create application directories
RUN mkdir -p /opt/siem/ml-service \
    /opt/siem/models \
    /opt/siem/config \
    /opt/siem/logs \
    /var/log/siem \
    && chown -R mlservice:mlservice /opt/siem /var/log/siem

# Set working directory
WORKDIR /opt/siem/ml-service

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY ml_service.py .
COPY ../anomaly_detection_engine.py ./anomaly_detection_engine.py
COPY ../ml_training_pipeline.py ./ml_training_pipeline.py
COPY ../config/ml_config.yaml /opt/siem/config/

# Copy health check script
COPY healthcheck.py .

# Create startup script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Wait for dependencies\n\
echo "Waiting for dependencies..."\n\
\n\
# Wait for PostgreSQL\n\
until pg_isready -h ${POSTGRES_HOST:-localhost} -p ${POSTGRES_PORT:-5432} -U ${POSTGRES_USER:-ml_user}; do\n\
  echo "Waiting for PostgreSQL..."\n\
  sleep 2\n\
done\n\
\n\
# Wait for Redis\n\
until redis-cli -h ${REDIS_HOST:-localhost} -p ${REDIS_PORT:-6379} ping; do\n\
  echo "Waiting for Redis..."\n\
  sleep 2\n\
done\n\
\n\
# Wait for Kafka\n\
until nc -z ${KAFKA_HOST:-localhost} ${KAFKA_PORT:-9092}; do\n\
  echo "Waiting for Kafka..."\n\
  sleep 2\n\
done\n\
\n\
echo "Dependencies are ready. Starting ML service..."\n\
\n\
# Start the ML service\n\
exec python ml_service.py\n\
' > /opt/siem/ml-service/start.sh

RUN chmod +x /opt/siem/ml-service/start.sh

# Switch to non-root user
USER mlservice

# Expose ports
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD python healthcheck.py

# Set default command
CMD ["/opt/siem/ml-service/start.sh"]

# Labels for metadata
LABEL maintainer="iSECTECH Security Team <security@isectech.com>"
LABEL version="1.0.0"
LABEL description="iSECTECH SIEM ML Anomaly Detection Service"
LABEL org.opencontainers.image.title="iSECTECH SIEM ML Service"
LABEL org.opencontainers.image.description="Production ML anomaly detection service for SIEM"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="iSECTECH"
LABEL org.opencontainers.image.licenses="Proprietary"