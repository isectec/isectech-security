# iSECTECH Google Cloud Infrastructure as Code

This repository contains production-grade Terraform configurations for deploying the iSECTECH security platform on Google Cloud Platform (GCP).

## Architecture Overview

The infrastructure includes:

- **VPC Network**: Secure, segmented networking with private subnets
- **GKE Cluster**: Production-ready Kubernetes cluster with security hardening
- **Cloud SQL**: Managed PostgreSQL database with encryption and backups
- **Redis Memorystore**: In-memory cache with high availability options
- **Cloud KMS**: Encryption key management for data-at-rest protection
- **Cloud Monitoring**: Comprehensive observability and alerting
- **Cloud Armor**: Web application firewall and DDoS protection
- **Secret Manager**: Secure storage for application secrets
- **Workload Identity**: IAM integration for Kubernetes workloads

## Prerequisites

### Required Tools

1. **Terraform** >= 1.6.0
   ```bash
   # Install via Homebrew (macOS)
   brew install terraform
   
   # Install via apt (Ubuntu/Debian)
   sudo apt-get install terraform
   ```

2. **Google Cloud SDK** >= 400.0.0
   ```bash
   # Install gcloud CLI
   curl https://sdk.cloud.google.com | bash
   source ~/.bashrc
   gcloud init
   ```

3. **kubectl** (for cluster access)
   ```bash
   # Install via gcloud
   gcloud components install kubectl
   ```

### GCP Setup

1. **Create or select a Google Cloud Project**
   ```bash
   # Create new project
   gcloud projects create PROJECT_ID --name="iSECTECH Security Platform"
   
   # Set as default project
   gcloud config set project PROJECT_ID
   ```

2. **Enable billing**
   ```bash
   # Link billing account to project
   gcloud billing projects link PROJECT_ID --billing-account=BILLING_ACCOUNT_ID
   ```

3. **Enable required APIs**
   ```bash
   gcloud services enable \
     container.googleapis.com \
     compute.googleapis.com \
     sqladmin.googleapis.com \
     cloudkms.googleapis.com \
     redis.googleapis.com \
     monitoring.googleapis.com \
     logging.googleapis.com \
     secretmanager.googleapis.com \
     cloudbilling.googleapis.com
   ```

4. **Set up authentication**
   ```bash
   # Create service account for Terraform
   gcloud iam service-accounts create terraform-sa --display-name="Terraform Service Account"
   
   # Grant necessary permissions
   gcloud projects add-iam-policy-binding PROJECT_ID \
     --member="serviceAccount:terraform-sa@PROJECT_ID.iam.gserviceaccount.com" \
     --role="roles/editor"
   
   # Generate and download key
   gcloud iam service-accounts keys create terraform-sa-key.json \
     --iam-account=terraform-sa@PROJECT_ID.iam.gserviceaccount.com
   
   # Set environment variable
   export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/terraform-sa-key.json"
   ```

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd infrastructure/terraform
```

### 2. Configure Backend

Create a Google Cloud Storage bucket for Terraform state:

```bash
# Create state bucket
gsutil mb gs://YOUR_PROJECT_ID-terraform-state

# Enable versioning
gsutil versioning set on gs://YOUR_PROJECT_ID-terraform-state
```

### 3. Create Environment Configuration

Create environment-specific `.tfvars` files:

```bash
# Copy example configuration
cp terraform.tfvars.example terraform.tfvars

# Edit with your values
vim terraform.tfvars
```

### 4. Initialize and Deploy

```bash
# Initialize Terraform
terraform init

# Plan deployment
terraform plan -var-file="terraform.tfvars"

# Apply configuration
terraform apply -var-file="terraform.tfvars"
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account key file | Yes |
| `GOOGLE_PROJECT` | Google Cloud Project ID | Yes |
| `GOOGLE_REGION` | Default region for resources | No |

### Terraform Variables

#### Core Configuration

```hcl
# terraform.tfvars
project_id                = "isectech-prod-12345"
environment              = "production"
region                   = "us-central1"
zone                     = "us-central1-a"
terraform_state_bucket   = "isectech-prod-12345-terraform-state"
```

#### Network Configuration

```hcl
vpc_cidr            = "10.0.0.0/16"
subnet_cidr         = "10.0.1.0/24"
pods_cidr_range     = "10.1.0.0/16"
services_cidr_range = "10.2.0.0/16"
```

#### Security Configuration

```hcl
enable_workload_identity     = true
enable_network_policy        = true
enable_shielded_nodes       = true
enable_private_nodes        = true
enable_envelope_encryption  = true

authorized_networks = [
  {
    cidr_block   = "203.0.113.0/24"
    display_name = "Office Network"
  }
]
```

#### Database Configuration

```hcl
database_version        = "POSTGRES_15"
database_tier          = "db-custom-2-4096"
database_disk_size     = 100
database_disk_type     = "PD_SSD"
database_backup_enabled = true
enable_database_high_availability = true
```

### Environment-Specific Configurations

#### Production Environment
```hcl
# production.tfvars
environment = "production"

# High-performance cluster
node_machine_type     = "e2-standard-4"
initial_node_count   = 3
max_node_count       = 20
enable_autoscaling   = true

# High availability database
database_tier = "db-custom-4-8192"
enable_database_high_availability = true

# Enhanced security
enable_binary_authorization = true
enable_audit_logging       = true
enable_backup              = true

# Monitoring
notification_email = "alerts@isectech.com"
enable_slo_monitoring = true
```

#### Staging Environment
```hcl
# staging.tfvars
environment = "staging"

# Medium-performance cluster
node_machine_type     = "e2-standard-2"
initial_node_count   = 2
max_node_count       = 10
enable_preemptible_nodes = true

# Standard database
database_tier = "db-custom-2-4096"
enable_database_high_availability = false

# Basic monitoring
notification_email = "dev-alerts@isectech.com"
```

#### Development Environment
```hcl
# development.tfvars
environment = "development"

# Cost-optimized cluster
node_machine_type     = "e2-medium"
initial_node_count   = 1
max_node_count       = 4
enable_preemptible_nodes = true

# Minimal database
database_tier = "db-f1-micro"
database_disk_size = 20
enable_database_high_availability = false

# Basic monitoring
notification_email = "dev-team@isectech.com"
```

## Deployment Workflows

### Environment Deployment

```bash
# Development
terraform workspace new development
terraform apply -var-file="development.tfvars"

# Staging  
terraform workspace new staging
terraform apply -var-file="staging.tfvars"

# Production
terraform workspace new production
terraform apply -var-file="production.tfvars"
```

### Rolling Updates

```bash
# Update cluster
terraform plan -var-file="production.tfvars" -target=module.gke
terraform apply -var-file="production.tfvars" -target=module.gke

# Update database
terraform plan -var-file="production.tfvars" -target=module.cloud_sql
terraform apply -var-file="production.tfvars" -target=module.cloud_sql
```

### Disaster Recovery

```bash
# Backup current state
terraform state pull > terraform.tfstate.backup

# Restore from backup
terraform state push terraform.tfstate.backup

# Emergency rollback
terraform apply -var-file="production.tfvars" -replace=module.gke
```

## Post-Deployment Setup

### 1. Configure kubectl

```bash
# Get cluster credentials
gcloud container clusters get-credentials CLUSTER_NAME \
  --region REGION --project PROJECT_ID

# Verify access
kubectl cluster-info
kubectl get nodes
```

### 2. Verify Services

```bash
# Check GKE cluster
kubectl get nodes
kubectl get pods --all-namespaces

# Check Cloud SQL
gcloud sql instances list

# Check Redis
gcloud redis instances list --region=REGION
```

### 3. Access Secrets

```bash
# List secrets
gcloud secrets list

# Access database connection
gcloud secrets versions access latest --secret="CLUSTER_NAME-database-connection"

# Access Redis connection  
gcloud secrets versions access latest --secret="CLUSTER_NAME-redis-connection"
```

## Module Documentation

### VPC Module (`modules/vpc`)

Creates a secure VPC network with:
- Private subnets for workloads
- Secondary ranges for pods and services
- NAT gateway for outbound internet access
- VPC Flow Logs for security monitoring

**Usage:**
```hcl
module "vpc" {
  source = "./modules/vpc"
  
  project_id    = var.project_id
  region        = var.region
  environment   = var.environment
  cluster_name  = "isectech-prod"
  
  vpc_cidr            = "10.0.0.0/16"
  subnet_cidr         = "10.0.1.0/24"
  pods_cidr_range     = "10.1.0.0/16"
  services_cidr_range = "10.2.0.0/16"
}
```

### GKE Module (`modules/gke`)

Deploys a production-ready GKE cluster with:
- Private nodes and optional private control plane
- Workload Identity for secure GCP integration
- Network policies for traffic control
- Shielded nodes for enhanced security
- Auto-scaling and auto-repair

**Usage:**
```hcl
module "gke" {
  source = "./modules/gke"
  
  project_id   = var.project_id
  region       = var.region
  cluster_name = "isectech-prod"
  
  network_name = module.vpc.network_name
  subnet_name  = module.vpc.subnet_name
  
  node_count     = 3
  machine_type   = "e2-standard-4"
  enable_autoscaling = true
}
```

### Cloud SQL Module (`modules/cloud-sql`)

Creates a managed PostgreSQL instance with:
- Private IP connectivity
- Automated backups and point-in-time recovery
- High availability (optional)
- Encryption at rest with customer-managed keys
- Database flags for security and performance

### KMS Module (`modules/kms`)

Sets up Cloud KMS for encryption:
- Keyring for organizing keys
- Dedicated keys for different services (GKE, Cloud SQL, backups)
- Automatic key rotation
- IAM policies for key access

### Redis Module (`modules/redis`)

Deploys Redis Memorystore with:
- Private IP connectivity  
- AUTH enabled for security
- Transit encryption
- High availability (optional)
- Maintenance windows

### Monitoring Module (`modules/monitoring`)

Comprehensive monitoring setup:
- Alert policies for infrastructure and applications
- Notification channels (email, Slack, PagerDuty)
- SLO definitions for service reliability
- Custom dashboards
- Log-based metrics

## Security Best Practices

### Network Security

1. **Private Clusters**: Use private nodes and optionally private control plane
2. **Network Policies**: Implement Kubernetes network policies for traffic control
3. **Authorized Networks**: Restrict API server access to specific IP ranges
4. **VPC Flow Logs**: Enable for network traffic monitoring

### Identity and Access Management

1. **Workload Identity**: Enable for secure pod-to-GCP service authentication
2. **Least Privilege**: Use minimal IAM roles for service accounts
3. **Service Account Keys**: Avoid downloading keys; use Workload Identity instead
4. **Audit Logging**: Enable for all API calls and data access

### Data Protection

1. **Encryption at Rest**: Use Cloud KMS for envelope encryption
2. **Encryption in Transit**: Enable TLS for all communications
3. **Secret Management**: Store sensitive data in Secret Manager
4. **Backup Encryption**: Encrypt backups with customer-managed keys

### Container Security

1. **Shielded Nodes**: Enable for additional security features
2. **Binary Authorization**: Require signed container images (production)
3. **Vulnerability Scanning**: Enable for container image analysis
4. **Pod Security Policies**: Implement security constraints

## Monitoring and Alerting

### Key Metrics

- **Cluster Health**: Node status, pod failures, resource utilization
- **Application Performance**: Request latency, error rates, throughput
- **Database Performance**: Connection count, query latency, replication lag
- **Security Events**: Failed authentication, network policy violations

### Alert Policies

- High CPU/memory utilization (>80%)
- Disk space usage (>85%)
- Database connection failures
- Application error rate (>5%)
- Security audit events

### Dashboards

- Infrastructure overview
- Application performance
- Security monitoring
- Cost optimization

## Cost Optimization

### Strategies

1. **Right-sizing**: Use appropriate machine types for workloads
2. **Preemptible Nodes**: Use for non-critical workloads (60-90% savings)
3. **Auto-scaling**: Scale resources based on demand
4. **Reserved Instances**: Commit to usage for discounts
5. **Resource Quotas**: Prevent over-provisioning

### Cost Monitoring

- Set up billing budgets with alerts
- Monitor spending by service and label
- Regular cost optimization reviews
- Identify unused resources

## Troubleshooting

### Common Issues

#### Terraform State Lock

```bash
# If state is locked
terraform force-unlock LOCK_ID

# Alternative: import existing resources
terraform import google_container_cluster.primary projects/PROJECT_ID/locations/REGION/clusters/CLUSTER_NAME
```

#### GKE Access Issues

```bash
# Update kubeconfig
gcloud container clusters get-credentials CLUSTER_NAME --region REGION

# Check IAM permissions
gcloud projects get-iam-policy PROJECT_ID

# Verify network connectivity
gcloud compute ssh INSTANCE_NAME --zone ZONE
```

#### Database Connection Issues

```bash
# Check Cloud SQL instance status
gcloud sql instances describe INSTANCE_NAME

# Test connectivity from GKE
kubectl run debug --image=postgres:13 --rm -it -- bash
psql -h PRIVATE_IP -U USERNAME -d DATABASE_NAME
```

### Debugging Commands

```bash
# Terraform debugging
export TF_LOG=DEBUG
terraform apply -var-file="terraform.tfvars"

# GCP resource debugging
gcloud logging read "resource.type=gke_cluster" --limit=50

# Kubernetes debugging
kubectl describe nodes
kubectl get events --sort-by=.metadata.creationTimestamp
```

## Contributing

### Development Workflow

1. Create feature branch
2. Make changes to Terraform configurations
3. Test with `terraform plan`
4. Update documentation
5. Submit pull request

### Testing

```bash
# Validate syntax
terraform validate

# Format code
terraform fmt -recursive

# Security scanning
terraform-compliance --compliance-path tests/

# Integration testing  
terratest tests/
```

## Support

For support and questions:

- **Documentation**: [Internal Wiki](wiki-url)
- **Issues**: [GitHub Issues](issues-url)
- **Chat**: #infrastructure Slack channel
- **On-call**: PagerDuty escalation policy

## License

Internal use only - iSECTECH Security Platform