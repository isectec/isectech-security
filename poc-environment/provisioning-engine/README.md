# iSECTECH POC Environment Provisioning Engine

## Production-Grade Terraform-based Infrastructure Provisioning Service

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/isectech/poc-provisioning-engine)
[![Go Version](https://img.shields.io/badge/go-1.21-00ADD8.svg)](https://golang.org)
[![Terraform](https://img.shields.io/badge/terraform-1.6.0-623CE4.svg)](https://terraform.io)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## Overview

The iSECTECH POC Environment Provisioning Engine is a production-grade microservice that automatically provisions complete cybersecurity POC environments using Terraform and Google Cloud Platform. It processes provisioning requests from the POC signup system and manages the entire lifecycle of infrastructure deployment, monitoring, and cleanup.

### Key Features

🚀 **Automated Infrastructure Provisioning**: Complete GCP infrastructure deployment using Terraform  
⚡ **Concurrent Processing**: Multi-worker architecture for parallel provisioning  
🔒 **Secure Workspaces**: Isolated Terraform workspaces with state management  
📊 **Progress Tracking**: Real-time status updates and progress monitoring  
🎯 **Tier-Based Resources**: Automatic resource allocation based on POC tier  
🔄 **Retry Logic**: Robust error handling with automatic retry mechanisms  
📈 **Scalable Architecture**: Kubernetes-ready with horizontal pod auto-scaling  
🏗️ **Complete Lifecycle Management**: Automated cleanup and resource termination  

---

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   POC Signup    │────│  Provisioning   │────│   Terraform     │
│   Backend API   │    │    Engine       │    │   Workspaces    │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   PostgreSQL    │    │   Worker Pool   │    │   Google Cloud  │
│   (Job Queue)   │    │   (Concurrent)  │    │   Platform      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Core Components

**Provisioning Engine API**
- RESTful API for provisioning requests
- Job queue management and status tracking
- Health monitoring and metrics collection
- Integration with POC signup backend

**Worker Pool**
- Concurrent processing of provisioning jobs
- Terraform workspace management
- Resource lifecycle management
- Error handling and retry logic

**Terraform Integration**
- Dynamic workspace creation
- Variable generation from POC requirements
- State management with GCS backend
- Output extraction and credential generation

**Database Layer**
- Job tracking and status management
- Progress monitoring and audit logging
- Resource metadata storage
- Cleanup scheduling and lifecycle management

---

## Technology Stack

**Backend Service**
- Go 1.21 with Gin framework
- GORM for database operations
- Concurrent worker pool architecture
- Comprehensive error handling and logging

**Infrastructure as Code**
- Terraform 1.6.0 for resource provisioning
- Google Cloud Platform provider
- Modular Terraform architecture
- Remote state management with GCS

**Database**
- PostgreSQL 15+ for job tracking
- JSONB for flexible metadata storage
- Comprehensive indexing for performance
- Database migrations and schema management

**Containerization & Orchestration**
- Docker multi-stage builds
- Kubernetes deployment manifests
- Horizontal pod auto-scaling
- Network policies and security contexts

---

## Project Structure

```
provisioning-engine/
├── main.go                      # Main application entry point
├── go.mod                       # Go module dependencies
├── Dockerfile                   # Container configuration
├── k8s/                         # Kubernetes deployment manifests
│   └── deployment.yaml          # Complete K8s configuration
├── integration/                 # Client integration libraries
│   └── provisioning-client.go   # Go client for backend integration
├── terraform-workspaces/        # Dynamic Terraform workspaces
│   └── [tenant-slug]/           # Per-tenant workspace directories
├── docs/                        # Documentation
│   └── api-documentation.md     # API reference documentation
└── README.md                    # This file
```

---

## Quick Start

### Prerequisites

- **Go 1.21+**
- **Terraform 1.6.0+**
- **Docker** and Docker Compose
- **PostgreSQL 15+**
- **Google Cloud CLI** (gcloud)
- **Kubernetes CLI** (kubectl)

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/isectech/poc-provisioning-engine.git
   cd poc-provisioning-engine
   ```

2. **Setup environment variables**
   ```bash
   cp .env.template .env
   # Edit .env with your configuration
   
   export DATABASE_URL="postgres://user:pass@localhost:5432/isectech_poc?sslmode=disable"
   export GCP_PROJECT="isectech-poc-platform"
   export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account-key.json"
   ```

3. **Install dependencies**
   ```bash
   go mod download
   ```

4. **Setup database**
   ```bash
   # The application will auto-migrate the schema on startup
   # Ensure PostgreSQL is running and accessible
   ```

5. **Run the provisioning engine**
   ```bash
   go run main.go
   ```

6. **Verify the service**
   ```bash
   curl http://localhost:8081/api/v1/health
   ```

---

## Production Deployment

### Google Cloud Platform Setup

1. **Create service account**
   ```bash
   gcloud iam service-accounts create poc-provisioning-engine \
     --display-name="POC Provisioning Engine"
   
   gcloud projects add-iam-policy-binding $GCP_PROJECT \
     --member="serviceAccount:poc-provisioning-engine@$GCP_PROJECT.iam.gserviceaccount.com" \
     --role="roles/compute.admin" \
     --role="roles/container.admin" \
     --role="roles/cloudsql.admin" \
     --role="roles/storage.admin"
   ```

2. **Create Kubernetes secret**
   ```bash
   kubectl create secret generic gcp-service-account-key \
     --from-file=key.json=/path/to/service-account-key.json \
     -n poc-provisioning
   ```

### Kubernetes Deployment

1. **Deploy the provisioning engine**
   ```bash
   kubectl apply -f k8s/deployment.yaml
   ```

2. **Verify the deployment**
   ```bash
   kubectl get pods -n poc-provisioning
   kubectl logs -f deployment/poc-provisioning-engine -n poc-provisioning
   ```

3. **Check service health**
   ```bash
   kubectl port-forward svc/poc-provisioning-service 8081:80 -n poc-provisioning
   curl http://localhost:8081/api/v1/health
   ```

---

## API Reference

### Base URL
- **Development**: `http://localhost:8081/api/v1`
- **Production**: `http://poc-provisioning-service.poc-provisioning.svc.cluster.local/api/v1`

### Core Endpoints

#### POST `/provisioning/provision`
Submit a new provisioning request.

**Request Body:**
```json
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_slug": "acme-cybersecurity-inc-a1b2c3d4",
  "company_info": {
    "company_name": "ACME Cybersecurity Inc.",
    "industry_vertical": "financial_services",
    "company_size": "enterprise",
    "headquarters_country": "US",
    "contact_email": "john.smith@acmecyber.com",
    "contact_name": "John Smith"
  },
  "poc_config": {
    "poc_tier": "enterprise",
    "poc_duration_days": 30,
    "expires_at": "2024-02-15T10:30:00Z",
    "enabled_features": [
      "threat_detection",
      "vulnerability_management",
      "email_security"
    ],
    "resource_allocation": {
      "cpu_cores": 16,
      "memory_gb": 64,
      "storage_gb": 1000,
      "max_users": 100
    }
  },
  "security_config": {
    "security_clearance": "unclassified",
    "data_residency_region": "us",
    "compliance_frameworks": ["soc2", "iso27001"],
    "network_isolation_level": "high",
    "encryption_required": true
  },
  "integration_config": {
    "main_platform_integration": true,
    "allowed_data_connectors": ["splunk", "qradar"],
    "crm_integration_enabled": true
  },
  "monitoring_config": {
    "enabled": true,
    "detailed_monitoring": true,
    "alerting_enabled": true,
    "retention_days": 90
  },
  "priority": "standard"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Provisioning job queued successfully",
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "queued",
  "estimated_duration": "30m0s",
  "progress_tracking_url": "/api/v1/provisioning/status/123e4567-e89b-12d3-a456-426614174000"
}
```

#### GET `/provisioning/status/{job_id}`
Get the status of a provisioning job.

**Response:**
```json
{
  "success": true,
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "status": "completed",
  "message": "Infrastructure provisioning completed successfully",
  "provisioned_resources": {
    "gke_cluster": "poc-cluster-acme-cybersecurity-inc-a1b2c3d4",
    "database_instance": "poc-db-acme-cybersecurity-inc-a1b2c3d4",
    "vpc_network": "poc-vpc-acme-cybersecurity-inc-a1b2c3d4"
  },
  "service_endpoints": {
    "api_endpoint": "https://api.acme-cybersecurity-inc-a1b2c3d4.poc.isectech.com",
    "web_interface": "https://acme-cybersecurity-inc-a1b2c3d4.poc.isectech.com",
    "monitoring_dashboard": "https://monitoring.acme-cybersecurity-inc-a1b2c3d4.poc.isectech.com"
  }
}
```

#### GET `/health`
Check service health status.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "queue": "healthy",
  "workers": 5,
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

## Provisioning Process

### Job Lifecycle

1. **Request Submission**
   - Validate provisioning request
   - Generate unique job ID and request ID
   - Queue job with appropriate priority

2. **Workspace Creation**
   - Create isolated Terraform workspace
   - Copy Terraform modules to workspace
   - Generate tenant-specific variables

3. **Infrastructure Planning**
   - Run `terraform init` with remote state
   - Generate `terraform plan` with resources
   - Store plan output in database

4. **Infrastructure Provisioning**
   - Execute `terraform apply` with plan
   - Monitor provisioning progress
   - Handle errors and retry failed operations

5. **Resource Configuration**
   - Extract Terraform outputs
   - Generate access credentials
   - Configure service endpoints

6. **Completion Notification**
   - Update tenant status to active
   - Send completion notifications
   - Schedule automatic cleanup

### Job Status Flow

```
pending → queued → provisioning → completed
                                ↓
                              failed
```

### Error Handling

- **Retry Logic**: Automatic retry for transient failures (up to 3 attempts)
- **Timeout Management**: Configurable timeouts for long-running operations
- **Rollback Support**: Automatic cleanup of partially provisioned resources
- **Error Reporting**: Detailed error messages and troubleshooting information

---

## Worker Pool Architecture

### Concurrent Processing

The provisioning engine uses a worker pool pattern for concurrent job processing:

```go
type WorkerPool struct {
    workers    []*Worker
    jobQueue   chan *ProvisioningJob
    maxWorkers int
}
```

**Configuration Options:**
- `MAX_CONCURRENT_PROVISIONS`: Maximum number of concurrent provisioning jobs (default: 5)
- `PROVISIONING_TIMEOUT`: Maximum time for a single provisioning job (default: 45m)
- `WORKER_RETRY_ATTEMPTS`: Number of retry attempts for failed jobs (default: 3)

### Worker Responsibilities

Each worker handles:
- Terraform workspace management
- Infrastructure provisioning
- Progress tracking and status updates
- Error handling and retry logic
- Resource cleanup and lifecycle management

---

## Database Schema

### Provisioning Jobs Table

```sql
CREATE TABLE provisioning_jobs (
    job_id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL,
    tenant_slug         VARCHAR(63) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    priority            VARCHAR(20) NOT NULL DEFAULT 'standard',
    
    -- Request tracking
    request_id          VARCHAR(255) NOT NULL UNIQUE,
    requested_by        UUID,
    request_payload     JSONB,
    
    -- Terraform workspace
    terraform_workspace VARCHAR(255),
    terraform_plan      TEXT,
    terraform_state     TEXT,
    
    -- Progress tracking
    current_step        VARCHAR(100),
    total_steps         INTEGER DEFAULT 0,
    completed_steps     INTEGER DEFAULT 0,
    progress_percent    INTEGER DEFAULT 0,
    
    -- Results
    provisioned_resources JSONB,
    access_credentials    JSONB,
    service_endpoints     JSONB,
    
    -- Timing
    queued_at           TIMESTAMP WITH TIME ZONE,
    started_at          TIMESTAMP WITH TIME ZONE,
    completed_at        TIMESTAMP WITH TIME ZONE,
    estimated_duration  INTERVAL,
    actual_duration     INTERVAL,
    
    -- Error handling
    error_message       TEXT,
    error_details       JSONB,
    retry_count         INTEGER DEFAULT 0,
    max_retries         INTEGER DEFAULT 3,
    
    -- Lifecycle
    expires_at          TIMESTAMP WITH TIME ZONE NOT NULL,
    cleanup_scheduled   BOOLEAN DEFAULT FALSE,
    auto_cleanup        BOOLEAN DEFAULT TRUE,
    
    -- Metadata
    tags                JSONB,
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Indexes for Performance

```sql
CREATE INDEX idx_provisioning_jobs_status ON provisioning_jobs(status, created_at);
CREATE INDEX idx_provisioning_jobs_tenant ON provisioning_jobs(tenant_id, status);
CREATE INDEX idx_provisioning_jobs_priority ON provisioning_jobs(priority, status, created_at);
CREATE INDEX idx_provisioning_jobs_cleanup ON provisioning_jobs(expires_at, auto_cleanup) WHERE status = 'completed';
```

---

## Integration with Backend API

### Client Library Usage

```go
import "isectech-poc-provisioning-engine/integration"

// Create provisioning client
client := integration.NewProvisioningClient(&integration.ProvisioningClientConfig{
    BaseURL: "http://poc-provisioning-service.poc-provisioning.svc.cluster.local/api/v1",
    Timeout: 60 * time.Second,
})

// Convert signup data to provisioning request
request := integration.ConvertSignupToProvisioningRequest(
    signupData, tenantID, tenantSlug)

// Submit provisioning request
response, err := client.SubmitProvisioningRequest(ctx, request)
if err != nil {
    log.Printf("Provisioning request failed: %v", err)
    return
}

// Track provisioning progress
for {
    status, err := client.GetProvisioningStatus(ctx, response.JobID)
    if err != nil {
        log.Printf("Failed to get provisioning status: %v", err)
        break
    }
    
    if status.Status == "completed" {
        log.Printf("Provisioning completed successfully")
        break
    }
    
    if status.Status == "failed" {
        log.Printf("Provisioning failed: %s", status.ErrorMessage)
        break
    }
    
    time.Sleep(30 * time.Second)
}
```

### Integration Points

**POC Signup Backend → Provisioning Engine**
- Async provisioning request submission
- Progress tracking and status updates
- Error handling and failure notifications

**Provisioning Engine → Terraform Modules**
- Dynamic workspace creation
- Variable generation and injection
- State management and output extraction

**Provisioning Engine → Database**
- Job tracking and progress updates
- Resource metadata storage
- Audit logging and lifecycle management

---

## Monitoring & Observability

### Metrics Collection

**Application Metrics:**
- Provisioning job success/failure rates
- Average provisioning duration by POC tier
- Worker pool utilization and queue depth
- Error rates and retry statistics

**Infrastructure Metrics:**
- CPU and memory utilization
- Terraform execution times
- GCS state bucket operations
- Database connection pool status

### Logging

**Structured Logging:**
```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "component": "worker",
  "worker_id": 1,
  "job_id": "123e4567-e89b-12d3-a456-426614174000",
  "tenant_slug": "acme-cybersecurity-inc-a1b2c3d4",
  "step": "terraform_apply",
  "progress": "75%",
  "message": "Terraform apply in progress",
  "request_id": "req-abc123"
}
```

### Health Checks

**Kubernetes Health Probes:**
- Liveness probe: `/api/v1/health`
- Readiness probe: `/api/v1/health`
- Custom health indicators for database and queue status

**Monitoring Dashboards:**
- Provisioning pipeline overview
- Worker pool performance metrics
- Error tracking and alerting
- Resource utilization by POC tier

---

## Security Considerations

### Infrastructure Security

**Terraform State Management:**
- Remote state storage in Google Cloud Storage
- State file encryption at rest
- Access control with IAM policies
- State locking to prevent concurrent modifications

**Workspace Isolation:**
- Separate Terraform workspace per tenant
- Isolated resource naming and tagging
- Network isolation with VPC and firewall rules
- Service account permissions with least privilege

### Application Security

**Authentication & Authorization:**
- Service-to-service authentication with JWT
- API key validation for external integrations
- Role-based access control for administrative functions
- Audit logging for all provisioning operations

**Data Protection:**
- Encryption of sensitive data in database
- Secure credential generation and storage
- PII scrubbing in logs and metrics
- Secure inter-service communication with TLS

### Kubernetes Security

**Pod Security:**
- Non-root container execution
- Read-only root filesystem (where possible)
- Security contexts with dropped capabilities
- Network policies for traffic isolation

**RBAC Configuration:**
- Minimal ClusterRole permissions
- Service account with specific resource access
- Namespace isolation and resource quotas
- Secrets management with encryption at rest

---

## Performance Optimization

### Concurrent Processing

**Worker Pool Tuning:**
- Optimal worker count based on resource availability
- Dynamic scaling based on queue depth
- Priority-based job scheduling
- Batch processing for bulk operations

**Resource Management:**
- Connection pooling for database operations
- Terraform workspace cleanup and reuse
- Memory-efficient JSON processing
- Async operations with context cancellation

### Database Optimization

**Query Performance:**
- Proper indexing for frequent queries
- Pagination for large result sets
- Connection pooling and prepared statements
- Query timeout and resource limits

**Storage Efficiency:**
- JSONB compression for large payloads
- Partitioning for historical data
- Automated cleanup of expired jobs
- Archive storage for compliance retention

---

## Troubleshooting

### Common Issues

1. **Terraform Execution Failures**
   ```bash
   # Check Terraform logs in job details
   kubectl logs -f deployment/poc-provisioning-engine -n poc-provisioning
   
   # Verify GCP credentials and permissions
   kubectl exec -it deployment/poc-provisioning-engine -n poc-provisioning -- \
     gcloud auth application-default print-access-token
   
   # Check Terraform state bucket access
   kubectl exec -it deployment/poc-provisioning-engine -n poc-provisioning -- \
     gsutil ls gs://isectech-terraform-state-poc/
   ```

2. **Database Connection Issues**
   ```bash
   # Check database connectivity
   kubectl exec -it deployment/poc-provisioning-engine -n poc-provisioning -- \
     pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER
   
   # Verify database schema
   kubectl exec -it deployment/poc-provisioning-engine -n poc-provisioning -- \
     psql $DATABASE_URL -c "\dt"
   ```

3. **Worker Pool Performance**
   ```bash
   # Check worker utilization
   curl -s http://localhost:8081/api/v1/health | jq .
   
   # Monitor job queue depth
   kubectl exec -it deployment/poc-provisioning-engine -n poc-provisioning -- \
     curl -s localhost:8081/api/v1/metrics | grep job_queue
   ```

### Debug Mode

Enable debug logging:
```bash
kubectl set env deployment/poc-provisioning-engine LOG_LEVEL=debug -n poc-provisioning
```

---

## Contributing

### Development Guidelines

1. **Code Quality**
   - Follow Go best practices and conventions
   - Write comprehensive unit and integration tests
   - Use proper error handling and logging
   - Document public APIs and complex logic

2. **Terraform Modules**
   - Follow Terraform best practices
   - Use proper variable validation
   - Include comprehensive outputs
   - Test modules with different configurations

3. **Testing**
   ```bash
   # Unit tests
   go test ./... -v -cover
   
   # Integration tests
   go test -tags=integration ./... -v
   
   # Terraform validation
   terraform validate
   terraform plan -var-file=test.tfvars
   ```

### Contribution Process

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Run quality checks
5. Submit pull request with documentation

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

### Technical Support
- **Email**: poc-support@isectech.org
- **Documentation**: https://docs.isectech.org/provisioning
- **GitHub Issues**: https://github.com/isectech/poc-provisioning-engine/issues

### Monitoring & Status
- **Status Page**: https://status.isectech.org
- **Metrics Dashboard**: https://monitoring.isectech.org/provisioning
- **Logging**: https://logs.isectech.org/provisioning

---

**Built with ⚡ by the iSECTECH Platform Engineering Team**