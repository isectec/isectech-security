# Build stage
FROM golang:1.21-alpine AS builder

# Install required packages
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build arguments for version information
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build \
  -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
  -o auth-service \
  ./cmd/auth-service

# Final stage
FROM alpine:3.18

# Install required packages
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -g 1000 -S isectech && \
  adduser -u 1000 -S isectech -G isectech

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/auth-service .

# Copy configuration files
COPY --from=builder /app/config.example.yaml ./config.yaml
COPY --from=builder /app/infrastructure/database/migrations ./migrations

# Create directories for templates and logs
RUN mkdir -p ./templates/email ./logs ./models

# Change ownership to non-root user
RUN chown -R isectech:isectech /app

# Switch to non-root user
USER isectech

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["./auth-service"]
CMD ["-config", "config.yaml"]