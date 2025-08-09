# SOC Automation - Incident Response Orchestration
# Production Docker container

FROM python:3.11-slim

# Set metadata
LABEL maintainer="SOC Team <soc-team@isectech.com>"
LABEL description="SOC Automation Incident Response Orchestration System"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create app user
RUN groupadd -r soc && useradd -r -g soc soc

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        wget \
        gnupg \
        ca-certificates \
        gcc \
        g++ \
        libc6-dev \
        libffi-dev \
        libssl-dev \
        libyaml-dev \
        procps \
        net-tools \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install forensic tools (optional - remove if not needed)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        sleuthkit \
        binwalk \
        hexedit \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p \
    /evidence \
    /tmp/evidence \
    /evidence/backup \
    /etc/soc-automation \
    /var/log/soc-automation \
    && chown -R soc:soc /app /evidence /tmp/evidence /var/log/soc-automation

# Copy default configuration
COPY config/incident-response.yaml /etc/soc-automation/

# Set permissions
RUN chmod +x scripts/*.sh && \
    chown -R soc:soc /etc/soc-automation

# Switch to non-root user
USER soc

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/metrics || exit 1

# Expose ports
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["python", "-m", "incident_response_service"]

# Default command
CMD ["/etc/soc-automation/incident-response.yaml"]