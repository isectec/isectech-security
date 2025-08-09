# Multi-stage build for production-ready SOC Alert Ingestion Service
FROM python:3.11-slim as builder

WORKDIR /build

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Create non-root user for security
RUN groupadd -r socuser && useradd -r -g socuser socuser

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder stage
COPY --from=builder /root/.local /home/socuser/.local

# Set PATH to include user packages
ENV PATH=/home/socuser/.local/bin:$PATH

# Set work directory
WORKDIR /app

# Copy application code
COPY alert-ingestion/ ./alert-ingestion/
COPY requirements.txt .

# Create necessary directories and set permissions
RUN mkdir -p logs data config \
    && chown -R socuser:socuser /app

# Switch to non-root user
USER socuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Expose port
EXPOSE 8001

# Set environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "-m", "uvicorn", "alert-ingestion.main:app", "--host", "0.0.0.0", "--port", "8001"]