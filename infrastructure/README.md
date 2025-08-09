# iSECTECH Infrastructure Setup

## 🚀 Deployment Order

Run these scripts in order to set up the complete infrastructure:

### 1. Enable APIs
```bash
./enable-apis.sh
```
**What it does:** Enables 24+ GCP APIs required for the microservices platform

### 2. Set up Domain
```bash  
./setup-domain.sh
```
**What it does:** Configures Cloud DNS for app.isectech.org domain
**Note:** Update your domain registrar with the provided name servers

### 3. Set up Load Balancer
```bash
./setup-load-balancer.sh  
```
**What it does:** Creates global HTTPS load balancer with SSL certificate
**Result:** https://app.isectech.org will be live

### 4. Prepare Multi-Region
```bash
./prepare-multi-region.sh
```
**What it does:** Sets up infrastructure for US, Europe, and Asia regions

## 📋 Current Status

### ✅ Completed Infrastructure
- **Project:** isectech-protech-project (553374734381)
- **Cloud Run:** Live application service
- **Database:** PostgreSQL 15 with VPC connection
- **VPC:** Basic networking (isectech-vpc)
- **Security:** Service accounts, Secret Manager, SSL/TLS
- **Monitoring:** Basic uptime monitoring and logging
- **Storage:** Cloud Storage buckets

### 🔄 Ready to Deploy
- **APIs:** 24+ microservices platform APIs
- **Domain:** app.isectech.org with Cloud DNS
- **Load Balancer:** Global HTTPS with SSL certificate
- **Multi-Region:** US/EU/Asia infrastructure foundation

## 🌍 Multi-Region Architecture

| Region | Subnet | Purpose |
|--------|--------|---------|
| us-central1 | 10.0.0.0/24 | Primary (existing) |
| europe-west1 | 10.1.0.0/24 | EU compliance |
| asia-southeast1 | 10.2.0.0/24 | APAC expansion |

## 🔐 Security Features

- **Private Database:** No public IP, VPC-only access
- **SSL/TLS:** Enforced encryption everywhere
- **Service Accounts:** Least-privilege IAM
- **Secret Manager:** Centralized secret storage
- **VPC Isolation:** Network-level security

## 📊 Next Steps

After running all scripts:
1. Deploy Next.js application to Cloud Run
2. Set up GKE clusters for microservices
3. Configure Kafka for event streaming
4. Deploy security monitoring services

## 🛠️ Project Structure

```
infrastructure/
├── enable-apis.sh           # API enablement
├── setup-domain.sh          # DNS configuration  
├── setup-load-balancer.sh   # Global load balancer
├── prepare-multi-region.sh  # Multi-region setup
├── multi-region-db-config.yaml # DB configuration
└── README.md               # This file
```