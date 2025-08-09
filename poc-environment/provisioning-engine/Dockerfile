# iSECTECH POC Provisioning Engine - Docker Configuration
# Production-Grade Multi-Stage Container Build
# Version: 1.0

# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies and Terraform
RUN apk add --no-cache git ca-certificates tzdata curl unzip && \
    curl -fsSL https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip -o terraform.zip && \
    unzip terraform.zip && \
    mv terraform /usr/local/bin/ && \
    rm terraform.zip

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags '-extldflags "-static" -w -s' \
    -o main .

# Final stage
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl && \
    adduser -D -s /bin/sh appuser

# Install Terraform
RUN curl -fsSL https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip -o terraform.zip && \
    unzip terraform.zip && \
    mv terraform /usr/local/bin/ && \
    rm terraform.zip && \
    chmod +x /usr/local/bin/terraform

# Install Google Cloud CLI
RUN curl -sSL https://sdk.cloud.google.com | bash
ENV PATH $PATH:/root/google-cloud-sdk/bin

# Create necessary directories
RUN mkdir -p /app/terraform-workspaces && \
    chown -R appuser:appuser /app

# Copy the binary
COPY --from=builder /app/main /app/main

# Copy Terraform modules
COPY --from=builder /app/../architecture/terraform /app/terraform-modules

# Set working directory
WORKDIR /app

# Expose port
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/api/v1/health || exit 1

# Set user
USER appuser

# Set environment variables
ENV PORT=8081
ENV TZ=UTC
ENV TERRAFORM_BINARY=/usr/local/bin/terraform
ENV TERRAFORM_WORKSPACE_DIR=/app/terraform-workspaces

# Run the application
ENTRYPOINT ["/app/main"]