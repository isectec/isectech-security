# iSECTECH POC Signup Portal - API Documentation

## Version: 1.0.0
## Base URL: `https://api.app.isectech.org/api/v1`

---

## Overview

The iSECTECH POC Signup Portal API provides a comprehensive self-service interface for cybersecurity professionals to request and provision proof-of-concept environments. This production-grade API handles the complete lifecycle of POC environment creation, from initial signup through infrastructure provisioning.

### Key Features

- **Self-Service POC Registration**: Complete company and contact information capture
- **Multi-Tier POC Environments**: Standard, Enterprise, and Premium tiers with different resource allocations
- **Security Clearance Integration**: Support for unclassified through top secret clearance levels
- **Compliance Framework Support**: SOC2, ISO27001, HIPAA, GDPR, FedRAMP, FISMA, and more
- **Automated Infrastructure Provisioning**: Terraform-based GCP infrastructure deployment
- **Industry-Specific Configurations**: Tailored security tools and scenarios by industry vertical
- **Advanced Business Context Capture**: Decision makers, budget, timeline, and competitive analysis
- **CRM Integration**: Automated sales pipeline management and lead scoring

---

## Authentication & Security

### Request Headers

All requests must include the following headers:

```http
Content-Type: application/json
Accept: application/json
X-Request-ID: unique-request-identifier
```

### Security Features

- **Rate Limiting**: 100 requests per second per IP address
- **Input Validation**: Comprehensive request validation using Go validator
- **SQL Injection Protection**: Parameterized queries with GORM
- **CORS Protection**: Configurable allowed origins
- **Request Size Limits**: Maximum 10MB request body
- **Multi-Tenant Isolation**: Database-level row security policies

---

## Error Handling

### Standard Error Response Format

```json
{
  "error": "error_code",
  "message": "Human-readable error description",
  "details": {
    "validation_errors": "Specific field validation failures"
  },
  "request_id": "unique-request-identifier",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request successful |
| 201 | Created | Resource created successfully |
| 400 | Bad Request | Invalid request format or validation error |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Access denied |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 413 | Payload Too Large | Request body exceeds size limit |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Server Error | Server error occurred |
| 503 | Service Unavailable | Service temporarily unavailable |

---

## API Endpoints

### Health Check

#### GET `/health`

Check the health status of the API service and its dependencies.

**Response Example:**
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "1.0.0",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

---

### POC Signup

#### POST `/poc/signup`

Create a new POC environment registration and initiate infrastructure provisioning.

**Request Body Schema:**

```json
{
  "company_name": "ACME Cybersecurity Inc.", // required, 2-255 chars
  "industry_vertical": "financial_services", // required, predefined values
  "company_size": "enterprise", // required: startup|small|medium|large|enterprise
  "employee_count": 5000, // optional, min 1
  "annual_revenue": 500000000, // optional, min 0
  "headquarters_country": "US", // required, ISO 3166-1 alpha-2
  "website_url": "https://www.acmecyber.com", // optional, valid URL
  
  "contact_name": "John Smith", // required, 2-200 chars
  "contact_email": "john.smith@acmecyber.com", // required, valid email
  "contact_phone": "+1-555-123-4567", // optional, max 50 chars
  "job_title": "CISO", // optional, max 150 chars
  "department": "Information Security", // optional, max 100 chars
  
  "poc_tier": "enterprise", // required: standard|enterprise|premium
  "poc_duration_days": 30, // required, 7-180 days
  "security_clearance": "unclassified", // required: unclassified|confidential|secret|top_secret
  "data_residency_region": "us", // required: us|eu|uk|ca|au|jp|in|sg|global
  "compliance_frameworks": ["soc2", "iso27001"], // required, min 1
  
  "current_security_tools": {
    "siem": "Splunk Enterprise",
    "endpoint_protection": "CrowdStrike Falcon",
    "vulnerability_scanner": "Nessus",
    "email_security": "Proofpoint"
  },
  "security_maturity_level": 3, // optional, 1-5
  "primary_security_challenges": [
    "Advanced persistent threats",
    "Insider threat detection",
    "Cloud security visibility"
  ],
  "evaluation_objectives": [
    "Improve threat detection accuracy",
    "Reduce false positive rates",
    "Streamline incident response"
  ],
  "success_criteria": {
    "detection_improvement": "25% increase in true positive rate",
    "response_time": "50% reduction in mean time to response",
    "cost_efficiency": "20% reduction in security operations cost"
  },
  
  "decision_makers": [
    {
      "name": "Jane Doe",
      "title": "CTO",
      "email": "jane.doe@acmecyber.com",
      "role": "technical_decision_maker",
      "influence_level": "high"
    },
    {
      "name": "Bob Johnson",
      "title": "CFO", 
      "email": "bob.johnson@acmecyber.com",
      "role": "budget_approval",
      "influence_level": "high"
    }
  ],
  "budget_range": "$100k-500k", // optional
  "timeline_to_decision": "3-6 months", // optional
  "competitive_alternatives": [
    "Splunk SOAR",
    "IBM QRadar", 
    "Microsoft Sentinel"
  ],
  
  "integration_requirements": {
    "existing_siem": "Splunk Enterprise",
    "authentication": "Active Directory",
    "ticketing_system": "ServiceNow",
    "required_apis": ["SIEM", "ITSM", "Identity"]
  },
  "compliance_requirements": {
    "regulatory_frameworks": ["SOX", "PCI-DSS"],
    "audit_requirements": "Real-time compliance monitoring",
    "data_retention": "7 years"
  },
  "scalability_requirements": {
    "expected_data_volume": "10TB/day",
    "concurrent_users": 50,
    "geographic_regions": ["US", "EU"],
    "availability_requirement": "99.9%"
  },
  
  "source_campaign": "cybersec-conference-2024", // optional
  
  "terms_accepted": true, // required, must be true
  "privacy_policy_accepted": true, // required, must be true
  "nda_accepted": true, // required, must be true
  "marketing_opt_in": false // optional
}
```

**Industry Vertical Options:**
- `financial_services`
- `healthcare`
- `government`
- `education`
- `retail`
- `manufacturing`
- `technology`
- `energy`
- `telecommunications`
- `media_entertainment`
- `transportation`
- `real_estate`
- `other`

**Compliance Framework Options:**
- `soc2` - SOC 2 Type II
- `iso27001` - ISO 27001
- `hipaa` - HIPAA
- `gdpr` - GDPR
- `fedramp` - FedRAMP
- `fisma` - FISMA
- `pci_dss` - PCI DSS
- `ccpa` - CCPA
- `nist` - NIST Cybersecurity Framework
- `cis` - CIS Controls

**Success Response (201 Created):**

```json
{
  "success": true,
  "message": "POC environment creation initiated successfully",
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_slug": "acme-cybersecurity-inc-a1b2c3d4",
  "provisioning_id": "prov-550e8400-e29b-41d4-a716-446655440000",
  "estimated_ready_at": "2024-01-15T11:00:00Z",
  "access_instructions": "You will receive an email at john.smith@acmecyber.com with access instructions once your POC environment is ready.",
  "support_contact": "poc-support@isectech.com"
}
```

**Error Responses:**

```json
// Validation Error (400)
{
  "error": "validation_error",
  "message": "Invalid request format or missing required fields",
  "details": {
    "validation_errors": "Key: 'POCSignupRequest.CompanyName' Error:Field validation for 'CompanyName' failed on the 'required' tag"
  },
  "request_id": "req-123456789",
  "timestamp": "2024-01-15T10:30:00Z"
}

// Duplicate Registration (409)
{
  "error": "duplicate_registration",
  "message": "A POC environment already exists for this company or email address",
  "request_id": "req-123456789",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

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
- **Features**: All Standard features + email security, network monitoring, identity analytics
- **Provisioning Time**: ~30 minutes

### Premium Tier
- **Resources**: 32 CPU cores, 128GB RAM, 2TB storage
- **Users**: Up to 500 concurrent users
- **Duration**: 7-180 days
- **Features**: All Enterprise features + SOAR automation, AI/ML analytics, custom integrations
- **Provisioning Time**: ~45 minutes

---

## Infrastructure Architecture

### Google Cloud Platform Components

**Kubernetes Engine (GKE)**
- Private cluster with workload identity
- Node auto-scaling and multi-zone deployment
- Pod security policies and network policies
- Binary authorization for container security

**Cloud SQL (PostgreSQL)**
- Multi-tenant database with row-level security
- Automated backups and high availability
- Connection pooling and query optimization
- Encryption at rest and in transit

**Cloud Storage**
- Sample data storage and backup retention
- Lifecycle management and compliance controls
- Regional replication for data residency

**Cloud KMS**
- Key management for encryption
- Automatic key rotation (90 days for database, 30 days for secrets)
- HSM-backed keys for premium tier

**Monitoring & Logging**
- Cloud Monitoring with custom metrics
- Cloud Logging with structured logs
- Error Reporting and APM integration
- Custom dashboards for POC analytics

---

## Database Schema Overview

### Core Tables

**poc_tenants**
- Primary tenant information and configuration
- Company details and business context
- POC tier and resource allocation
- Security clearance and compliance requirements

**poc_users**
- User accounts within each tenant
- Role-based access control
- Multi-factor authentication support
- Activity tracking and audit logging

**poc_environments**
- Infrastructure environment instances
- Resource usage and health monitoring
- Cost tracking and budget management
- Automated lifecycle management

**poc_feature_usage**
- Detailed feature usage analytics
- Performance metrics and user engagement
- Business value demonstration tracking
- ROI calculation support

**poc_evaluation_metrics**
- Success criteria tracking
- Business impact measurement
- Comparative analysis with baselines
- Conversion probability scoring

---

## Security Considerations

### Data Protection
- **Encryption**: All data encrypted at rest and in transit
- **PII Handling**: Automatic PII detection and scrubbing
- **Access Control**: Role-based access with principle of least privilege
- **Audit Logging**: Comprehensive audit trail for all operations

### Network Security
- **VPC Isolation**: Each tenant gets isolated network resources
- **Firewall Rules**: Restrictive ingress/egress policies
- **TLS Enforcement**: TLS 1.3 minimum for all communications
- **DDoS Protection**: Google Cloud Armor integration

### Compliance
- **Data Residency**: Region-specific data storage
- **Retention Policies**: Automated data lifecycle management
- **Audit Reports**: Automated compliance reporting
- **Certification**: SOC 2 Type II, ISO 27001 compliant infrastructure

---

## Monitoring & Observability

### Metrics
- **API Performance**: Response time, throughput, error rates
- **Infrastructure**: CPU, memory, storage utilization
- **Business**: POC conversion rates, feature adoption
- **Security**: Failed authentication attempts, suspicious activities

### Alerting
- **High Priority**: Service outages, security incidents, data breaches
- **Medium Priority**: Performance degradation, resource exhaustion
- **Low Priority**: Maintenance notifications, usage reports

### Dashboards
- **Operations**: System health and performance metrics
- **Business**: POC pipeline and conversion analytics
- **Security**: Threat detection and compliance status

---

## Rate Limiting & Quotas

### API Rate Limits
- **General**: 100 requests per second per IP
- **Signup**: 5 POC signups per hour per IP
- **Bulk Operations**: 10 requests per minute

### Resource Quotas
- **Standard**: 1 POC per company per month
- **Enterprise**: 2 POCs per company per month
- **Premium**: 3 POCs per company per month

---

## Support & Contact Information

### Technical Support
- **Email**: poc-support@isectech.org
- **Documentation**: https://docs.isectech.org
- **Status Page**: https://status.isectech.org

### Business Inquiries
- **Sales**: sales@isectech.org
- **Partnerships**: partnerships@isectech.org
- **General**: info@isectech.org

---

## Changelog

### Version 1.0.0 (Current)
- Initial release of POC Signup Portal API
- Complete self-service POC registration
- Multi-tier POC environment support
- Terraform-based infrastructure provisioning
- Comprehensive business context capture
- Security clearance and compliance framework integration