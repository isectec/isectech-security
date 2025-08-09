# iSECTECH POC Signup Portal

## Production-Grade Self-Service POC Environment Provisioning System

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/isectech/poc-signup-portal)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.21-00ADD8.svg)](https://golang.org)
[![React Version](https://img.shields.io/badge/react-18.0-61DAFB.svg)](https://reactjs.org)
[![TypeScript](https://img.shields.io/badge/typescript-5.0-3178C6.svg)](https://typescriptlang.org)

---

## Overview

The iSECTECH POC Signup Portal is a comprehensive, enterprise-grade system that enables cybersecurity professionals to self-service provision proof-of-concept environments. Built with modern technologies and security best practices, it provides a seamless experience from initial signup through complete infrastructure deployment.

### Key Features

🚀 **Self-Service Registration**: Complete POC environment setup with guided wizard  
🏢 **Multi-Tenant Architecture**: Isolated environments with enterprise-grade security  
⚡ **Automated Provisioning**: Terraform-based infrastructure deployment on Google Cloud  
🔒 **Security Clearance Support**: Unclassified through Top Secret clearance levels  
📊 **Compliance Framework Integration**: SOC2, ISO27001, HIPAA, GDPR, FedRAMP, and more  
🎯 **Industry-Specific Configurations**: Tailored security tools and scenarios  
📈 **Business Context Capture**: Decision makers, budget, timeline, competitive analysis  
🔗 **CRM Integration**: Automated sales pipeline management and lead scoring

---

## Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│   React Frontend│────│   Go Backend    │────│  PostgreSQL DB  │
│   (TypeScript)  │    │   (REST API)    │    │  (Multi-tenant) │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│  Kubernetes     │    │   Terraform     │    │   Google Cloud  │
│  (GKE)          │    │   (IaC)         │    │   Platform      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Technology Stack

**Frontend**
- React 18 with TypeScript
- Zod for form validation
- Tailwind CSS for styling
- React Hook Form for form management
- Axios for API communication

**Backend**
- Go 1.21 with Gin framework
- GORM for database ORM
- PostgreSQL 15+ for data persistence
- JWT for authentication
- Comprehensive input validation

**Infrastructure**
- Google Kubernetes Engine (GKE)
- Cloud SQL (PostgreSQL)
- Cloud Storage
- Cloud KMS for encryption
- Terraform for Infrastructure as Code

**Security & Compliance**
- Row Level Security (RLS) for multi-tenancy
- Workload Identity for GKE
- Binary Authorization for containers
- Comprehensive audit logging
- GDPR/HIPAA/SOC2 compliance ready

---

## Project Structure

```
poc-environment/signup-portal/
├── frontend/                    # React TypeScript frontend
│   ├── POCSignupPortal.tsx     # Main signup component
│   ├── components/             # Reusable UI components
│   ├── types/                  # TypeScript type definitions
│   └── utils/                  # Utility functions
├── backend/                     # Go REST API backend
│   ├── main.go                 # Main application entry point
│   ├── go.mod                  # Go module dependencies
│   ├── Dockerfile              # Container configuration
│   ├── k8s/                    # Kubernetes manifests
│   └── docs/                   # API documentation
├── integration/                 # Frontend-backend integration
│   └── api-client.ts           # TypeScript API client
├── architecture/               # Infrastructure architecture
│   ├── docs/                   # Architecture documentation
│   ├── terraform/              # Terraform modules
│   └── backend/database/       # Database schema
└── README.md                   # This file
```

---

## Quick Start

### Prerequisites

- **Node.js 18+** and npm/yarn
- **Go 1.21+**
- **Docker** and Docker Compose
- **Terraform 1.5+**
- **Google Cloud CLI** (gcloud)
- **Kubernetes CLI** (kubectl)

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/isectech/poc-signup-portal.git
   cd poc-signup-portal
   ```

2. **Setup Database**
   ```bash
   # Start PostgreSQL with Docker
   docker run -d \
     --name poc-postgres \
     -e POSTGRES_DB=isectech_poc \
     -e POSTGRES_USER=poc_user \
     -e POSTGRES_PASSWORD=poc_password \
     -p 5432:5432 \
     postgres:15

   # Apply database schema
   psql -h localhost -U poc_user -d isectech_poc -f architecture/backend/database/schema.sql
   ```

3. **Setup Backend**
   ```bash
   cd backend
   
   # Copy environment template
   cp .env.template .env
   # Edit .env with your configuration
   
   # Install dependencies
   go mod download
   
   # Run the backend
   go run main.go
   ```

4. **Setup Frontend**
   ```bash
   cd frontend
   
   # Install dependencies
   npm install
   
   # Start development server
   npm run dev
   ```

5. **Access the Application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8080
   - API Documentation: http://localhost:8080/docs

---

## Production Deployment

### Google Cloud Platform Setup

1. **Create GCP Project**
   ```bash
   gcloud projects create isectech-poc-platform
   gcloud config set project isectech-poc-platform
   ```

2. **Enable Required APIs**
   ```bash
   gcloud services enable \
     compute.googleapis.com \
     container.googleapis.com \
     sql.googleapis.com \
     secretmanager.googleapis.com \
     monitoring.googleapis.com \
     logging.googleapis.com
   ```

3. **Setup Terraform State Backend**
   ```bash
   gsutil mb gs://isectech-terraform-state-poc
   gsutil versioning set on gs://isectech-terraform-state-poc
   ```

### Infrastructure Deployment

1. **Deploy Base Infrastructure**
   ```bash
   cd architecture/terraform
   
   # Initialize Terraform
   terraform init
   
   # Plan deployment
   terraform plan \
     -var="project_id=isectech-poc-platform" \
     -var="tenant_id=example-tenant" \
     -var="tenant_display_name=Example Company" \
     -var="company_info={...}"
   
   # Apply infrastructure
   terraform apply
   ```

2. **Deploy Application to Kubernetes**
   ```bash
   # Get GKE credentials
   gcloud container clusters get-credentials poc-cluster --region=us-central1
   
   # Deploy backend
   kubectl apply -f backend/k8s/deployment.yaml
   
   # Deploy frontend (separate deployment)
   kubectl apply -f frontend/k8s/deployment.yaml
   ```

### Monitoring and Observability

```bash
# View application logs
kubectl logs -f deployment/poc-signup-backend -n poc-signup-portal

# Check application health
curl https://api.poc.isectech.com/api/v1/health

# Monitor metrics
kubectl port-forward svc/poc-signup-backend-service 9090:9090 -n poc-signup-portal
```

---

## API Reference

### Base URL
- **Development**: `http://localhost:8080/api/v1`
- **Production**: `https://api.poc.isectech.com/api/v1`

### Authentication
All requests require the following headers:
```http
Content-Type: application/json
Accept: application/json
X-Request-ID: unique-request-identifier
```

### Core Endpoints

#### POST `/poc/signup`
Submit a new POC environment request.

**Request Body:**
```json
{
  "company_name": "ACME Cybersecurity Inc.",
  "industry_vertical": "financial_services",
  "company_size": "enterprise",
  "contact_name": "John Smith",
  "contact_email": "john.smith@acmecyber.com",
  "poc_tier": "enterprise",
  "poc_duration_days": 30,
  "security_clearance": "unclassified",
  "data_residency_region": "us",
  "compliance_frameworks": ["soc2", "iso27001"],
  "terms_accepted": true,
  "privacy_policy_accepted": true,
  "nda_accepted": true
}
```

**Response:**
```json
{
  "success": true,
  "message": "POC environment creation initiated successfully",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_slug": "acme-cybersecurity-inc-a1b2c3d4",
  "provisioning_id": "prov-550e8400-e29b-41d4-a716-446655440000",
  "estimated_ready_at": "2024-01-15T11:00:00Z"
}
```

#### GET `/health`
Check service health status.

**Response:**
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

For complete API documentation, see [API Documentation](backend/docs/api-documentation.md).

---

## Database Schema

### Core Tables

- **`poc_tenants`**: Primary tenant information and configuration
- **`poc_users`**: User accounts with role-based access control
- **`poc_environments`**: Infrastructure environment instances
- **`poc_feature_usage`**: Detailed feature usage analytics
- **`poc_evaluation_metrics`**: Business metrics and ROI tracking
- **`poc_sales_pipeline`**: CRM integration and conversion tracking
- **`poc_event_log`**: Comprehensive audit logging

### Multi-Tenant Security

- Row Level Security (RLS) policies for tenant isolation
- Encrypted sensitive data with Google Cloud KMS
- Comprehensive audit logging for compliance
- GDPR-compliant data retention policies

---

## POC Tier Specifications

### Standard Tier
- **Resources**: 8 CPU cores, 32GB RAM, 500GB storage
- **Users**: Up to 25 concurrent users
- **Duration**: 7-60 days
- **Features**: Core threat detection, vulnerability management, compliance reporting
- **Provisioning Time**: ~15 minutes

### Enterprise Tier
- **Resources**: 16 CPU cores, 64GB RAM, 1TB storage
- **Users**: Up to 100 concurrent users
- **Duration**: 7-90 days
- **Features**: All Standard + email security, network monitoring, identity analytics
- **Provisioning Time**: ~30 minutes

### Premium Tier
- **Resources**: 32 CPU cores, 128GB RAM, 2TB storage
- **Users**: Up to 500 concurrent users
- **Duration**: 7-180 days
- **Features**: All Enterprise + SOAR automation, AI/ML analytics, custom integrations
- **Provisioning Time**: ~45 minutes

---

## Security Considerations

### Data Protection
- **Encryption**: All data encrypted at rest and in transit (TLS 1.3+)
- **Key Management**: Google Cloud KMS with automatic rotation
- **PII Handling**: Automated PII detection and scrubbing
- **Access Control**: Role-based access with principle of least privilege

### Network Security
- **VPC Isolation**: Each tenant gets isolated network resources
- **Firewall Rules**: Restrictive ingress/egress policies
- **DDoS Protection**: Google Cloud Armor integration
- **Certificate Management**: Automated SSL/TLS certificate provisioning

### Compliance
- **Frameworks Supported**: SOC2, ISO27001, HIPAA, GDPR, FedRAMP, FISMA
- **Data Residency**: Region-specific data storage options
- **Audit Logging**: Comprehensive audit trail for all operations
- **Retention Policies**: Automated data lifecycle management

---

## Monitoring & Observability

### Metrics Collection
- **Application Metrics**: Response time, throughput, error rates
- **Infrastructure Metrics**: CPU, memory, storage utilization
- **Business Metrics**: POC conversion rates, feature adoption
- **Security Metrics**: Failed authentications, suspicious activities

### Logging
- **Structured Logging**: JSON format with correlation IDs
- **Log Aggregation**: Google Cloud Logging with retention policies
- **Security Logs**: Comprehensive security event logging
- **Audit Logs**: Compliance-ready audit trail

### Alerting
- **High Priority**: Service outages, security incidents
- **Medium Priority**: Performance degradation, resource limits
- **Low Priority**: Maintenance notifications, usage reports

---

## Development Guidelines

### Code Quality
- **Go**: Follow standard Go conventions and use `golangci-lint`
- **TypeScript**: Strict TypeScript configuration with ESLint
- **Testing**: Comprehensive unit and integration tests
- **Documentation**: Inline code documentation and API docs

### Git Workflow
- **Branching**: Feature branches with pull request reviews
- **Commits**: Conventional commit messages
- **CI/CD**: Automated testing and deployment pipelines
- **Security**: Pre-commit hooks for secret scanning

### Performance
- **Database**: Proper indexing and query optimization
- **Caching**: Redis for session and response caching
- **API**: Request/response compression and rate limiting
- **Frontend**: Code splitting and lazy loading

---

## Testing

### Backend Testing
```bash
cd backend
go test ./... -v -cover
go test -race ./...
```

### Frontend Testing
```bash
cd frontend
npm run test
npm run test:coverage
npm run test:e2e
```

### Integration Testing
```bash
# Start test environment
docker-compose -f docker-compose.test.yml up -d

# Run integration tests
npm run test:integration

# Cleanup
docker-compose -f docker-compose.test.yml down
```

---

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   ```bash
   # Check PostgreSQL status
   kubectl get pods -n postgres
   
   # Check connection string
   echo $DATABASE_URL
   
   # Test connection
   psql $DATABASE_URL -c "SELECT version();"
   ```

2. **Terraform Apply Failed**
   ```bash
   # Check API enablement
   gcloud services list --enabled
   
   # Verify credentials
   gcloud auth application-default print-access-token
   
   # Check state lock
   terraform force-unlock LOCK_ID
   ```

3. **Pod CrashLoopBackOff**
   ```bash
   # Check pod logs
   kubectl logs -f pod/poc-signup-backend-xxx
   
   # Describe pod
   kubectl describe pod poc-signup-backend-xxx
   
   # Check resource limits
   kubectl top pods -n poc-signup-portal
   ```

### Debug Mode

Enable debug logging in development:
```bash
export LOG_LEVEL=debug
export ENABLE_DEBUG_LOGGING=true
export GIN_MODE=debug
```

---

## Contributing

### Development Setup
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Create a Pull Request

### Code Standards
- Follow Go best practices and conventions
- Use TypeScript strict mode
- Write comprehensive tests
- Update documentation
- Follow semantic versioning

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Support

### Technical Support
- **Email**: poc-support@isectech.org
- **Documentation**: https://docs.isectech.org
- **Status Page**: https://status.isectech.org
- **GitHub Issues**: https://github.com/isectech/poc-signup-portal/issues

### Business Inquiries
- **Sales**: sales@isectech.org
- **Partnerships**: partnerships@isectech.org
- **General**: info@isectech.org

---

## Changelog

### Version 1.0.0 (Current)
- ✅ Complete self-service POC registration system
- ✅ Multi-tier POC environment support (Standard/Enterprise/Premium)
- ✅ Terraform-based infrastructure provisioning on GCP
- ✅ Comprehensive business context capture and CRM integration
- ✅ Security clearance and compliance framework integration
- ✅ Production-grade PostgreSQL schema with multi-tenant RLS
- ✅ React TypeScript frontend with comprehensive form validation
- ✅ Go backend API with enterprise security features
- ✅ Kubernetes deployment manifests with auto-scaling
- ✅ Comprehensive monitoring, logging, and alerting

### Upcoming Features (Future Releases)
- 🔄 Advanced sample data generation and population (Task 60.4)
- 🔄 POC environment provisioning engine integration (Task 60.3)
- 🔄 Real-time POC status dashboard
- 🔄 Advanced analytics and reporting
- 🔄 Mobile-responsive design improvements
- 🔄 Integration with additional cloud providers (AWS, Azure)

---

**Built with ❤️ by the iSECTECH Platform Engineering Team**