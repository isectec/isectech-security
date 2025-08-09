# iSECTECH Platform Backend Makefile

.PHONY: help install build test clean docker deps-update security-check lint format

# Default target
help:
	@echo "iSECTECH Platform Backend - Available Commands:"
	@echo "  help            Show this help message"
	@echo "  install         Install all dependencies"
	@echo "  build           Build all services"
	@echo "  test            Run all tests with coverage"
	@echo "  clean           Clean build artifacts and caches"
	@echo "  docker          Build Docker images for all services"
	@echo "  deps-update     Update dependencies"
	@echo "  security-check  Run security vulnerability checks"
	@echo "  lint            Run code linting"
	@echo "  format          Format code with gofmt"
	@echo "  proto           Generate protobuf code"
	@echo "  dev             Start development environment"

# Install all dependencies
install:
	@echo "Installing dependencies..."
	go mod download
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Installing dependencies for $$service..."; \
		cd services/$$service && go mod tidy && cd ../..; \
	done
	@echo "Dependencies installed successfully!"

# Build all services
build:
	@echo "Building all services..."
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Building $$service..."; \
		cd services/$$service && go build -o ../../bin/$$service ./cmd/$$service && cd ../..; \
	done
	@echo "Build completed successfully!"

# Run tests with coverage
test:
	@echo "Running tests with coverage..."
	@mkdir -p coverage
	go test -race -coverprofile=coverage/coverage.out -covermode=atomic ./...
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Testing $$service..."; \
		cd services/$$service && go test -race -coverprofile=../../coverage/$$service.out -covermode=atomic ./... && cd ../..; \
	done
	@echo "Combining coverage reports..."
	@echo "mode: atomic" > coverage/combined.out
	@for file in coverage/*.out; do \
		if [ "$$file" != "coverage/combined.out" ]; then \
			tail -n +2 "$$file" >> coverage/combined.out; \
		fi; \
	done
	go tool cover -html=coverage/combined.out -o coverage/coverage.html
	@echo "Tests completed! Coverage report: coverage/coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf coverage/
	go clean -cache
	go clean -testcache
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		cd services/$$service && go clean && cd ../..; \
	done
	@echo "Clean completed!"

# Build Docker images
docker:
	@echo "Building Docker images..."
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Building Docker image for $$service..."; \
		docker build -t isectech/$$service:latest -f services/$$service/Dockerfile .; \
	done
	@echo "Docker images built successfully!"

# Update dependencies
deps-update:
	@echo "Checking for dependency updates..."
	go list -u -m all
	@echo "Updating patch versions..."
	go get -u=patch ./...
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Updating dependencies for $$service..."; \
		cd services/$$service && go get -u=patch ./... && go mod tidy && cd ../..; \
	done
	@echo "Dependencies updated!"

# Security vulnerability check
security-check:
	@echo "Running security checks..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	else \
		echo "govulncheck not installed. Installing..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest; \
		govulncheck ./...; \
	fi
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "gosec not installed. Installing..."; \
		go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest; \
		gosec ./...; \
	fi

# Lint code
lint:
	@echo "Running linters..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed. Installing..."; \
		go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest; \
		golangci-lint run ./...; \
	fi
	go vet ./...

# Format code
format:
	@echo "Formatting code..."
	gofmt -s -w .
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	else \
		echo "goimports not installed. Installing..."; \
		go install golang.org/x/tools/cmd/goimports@latest; \
		goimports -w .; \
	fi

# Generate protobuf code
proto:
	@echo "Generating protobuf code..."
	@if command -v protoc >/dev/null 2>&1; then \
		protoc --go_out=. --go_opt=paths=source_relative \
			--go-grpc_out=. --go-grpc_opt=paths=source_relative \
			shared/proto/*.proto; \
	else \
		echo "protoc not installed. Please install Protocol Buffers compiler."; \
		echo "macOS: brew install protobuf"; \
		echo "Ubuntu: apt install protobuf-compiler"; \
	fi

# Development environment setup
dev:
	@echo "Starting development environment..."
	@echo "Starting local dependencies with Docker Compose..."
	docker-compose -f docker-compose.dev.yml up -d
	@echo "Development environment ready!"
	@echo "Services available at:"
	@echo "  - MongoDB: localhost:27017"
	@echo "  - Redis: localhost:6379"
	@echo "  - Kafka: localhost:9092"
	@echo "  - Consul: localhost:8500"
	@echo "  - Prometheus: localhost:9090"
	@echo "  - Jaeger: localhost:16686"

# Install development tools
dev-tools:
	@echo "Installing development tools..."
	go install golang.org/x/tools/gopls@latest
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@echo "Development tools installed!"

# Service-specific targets
build-event-processor:
	cd services/event-processor && go build -o ../../bin/event-processor ./cmd/event-processor

build-asset-discovery:
	cd services/asset-discovery && go build -o ../../bin/asset-discovery ./cmd/asset-discovery

build-threat-detection:
	cd services/threat-detection && go build -o ../../bin/threat-detection ./cmd/threat-detection

build-api-gateway:
	cd services/api-gateway && go build -o ../../bin/api-gateway ./cmd/api-gateway

test-event-processor:
	cd services/event-processor && go test -race -cover ./...

test-asset-discovery:
	cd services/asset-discovery && go test -race -cover ./...

test-threat-detection:
	cd services/threat-detection && go test -race -cover ./...

test-api-gateway:
	cd services/api-gateway && go test -race -cover ./...

# Run specific service
run-event-processor: build-event-processor
	./bin/event-processor

run-asset-discovery: build-asset-discovery
	./bin/asset-discovery

run-threat-detection: build-threat-detection
	./bin/threat-detection

run-api-gateway: build-api-gateway
	./bin/api-gateway

# Performance testing
benchmark:
	@echo "Running benchmarks..."
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Benchmarking $$service..."; \
		cd services/$$service && go test -bench=. -benchmem ./... && cd ../..; \
	done

# Check Go version compatibility
check-go-version:
	@go_version=$$(go version | cut -d' ' -f3 | cut -d'o' -f2); \
	required_version="1.21"; \
	if [ "$$(printf '%s\n' "$$required_version" "$$go_version" | sort -V | head -n1)" = "$$required_version" ]; then \
		echo "✓ Go version $$go_version meets minimum requirement ($$required_version)"; \
	else \
		echo "✗ Go version $$go_version does not meet minimum requirement ($$required_version)"; \
		exit 1; \
	fi

# Validate all modules
validate:
	@echo "Validating all modules..."
	go mod verify
	@for service in event-processor asset-discovery threat-detection api-gateway; do \
		echo "Validating $$service module..."; \
		cd services/$$service && go mod verify && cd ../..; \
	done
	@echo "All modules validated successfully!"