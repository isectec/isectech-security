#!/bin/bash

# Enable Missing APIs for iSECTECH Microservices Platform
# Project: isectech-protech-project

set -e

# Add gcloud to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo "🚀 Enabling APIs for iSECTECH Platform..."

# Set project context
gcloud config set project isectech-protech-project

# Core Kubernetes and Container APIs
echo "📦 Enabling Kubernetes and Container APIs..."
gcloud services enable container.googleapis.com           # Google Kubernetes Engine
gcloud services enable servicemesh.googleapis.com         # Istio Service Mesh
gcloud services enable gkehub.googleapis.com             # Anthos/GKE Hub
gcloud services enable anthos.googleapis.com             # Anthos Service Mesh

# Networking and Load Balancing
echo "🌐 Enabling Networking APIs..."
gcloud services enable dns.googleapis.com                # Cloud DNS
gcloud services enable networkservices.googleapis.com    # Network Services
gcloud services enable certificatemanager.googleapis.com # Certificate Manager
gcloud services enable networkmanagement.googleapis.com  # Network Management

# Security and Encryption
echo "🔐 Enabling Security APIs..."
gcloud services enable cloudkms.googleapis.com           # Cloud Key Management
gcloud services enable binaryauthorization.googleapis.com # Binary Authorization
gcloud services enable securitycenter.googleapis.com     # Security Command Center
gcloud services enable accesscontextmanager.googleapis.com # VPC Service Controls

# Data and Analytics
echo "📊 Enabling Data APIs..."
gcloud services enable bigquery.googleapis.com           # BigQuery for analytics
gcloud services enable bigtable.googleapis.com          # Cloud Bigtable
gcloud services enable spanner.googleapis.com           # Cloud Spanner
gcloud services enable redis.googleapis.com             # Redis for caching

# Messaging and Events
echo "📨 Enabling Messaging APIs..."
gcloud services enable pubsub.googleapis.com            # Cloud Pub/Sub
gcloud services enable eventarc.googleapis.com          # Eventarc
gcloud services enable workflows.googleapis.com         # Workflows

# Monitoring and Observability
echo "📈 Enabling Monitoring APIs..."
gcloud services enable monitoring.googleapis.com        # Cloud Monitoring
gcloud services enable logging.googleapis.com           # Cloud Logging
gcloud services enable cloudtrace.googleapis.com        # Cloud Trace
gcloud services enable cloudprofiler.googleapis.com     # Cloud Profiler

# AI/ML for Security Analytics
echo "🤖 Enabling AI/ML APIs..."
gcloud services enable aiplatform.googleapis.com        # Vertex AI
gcloud services enable ml.googleapis.com                # Machine Learning APIs
gcloud services enable automl.googleapis.com            # AutoML

# Additional Platform Services
echo "⚙️ Enabling Platform APIs..."
gcloud services enable cloudbuild.googleapis.com        # Cloud Build for CI/CD
gcloud services enable artifactregistry.googleapis.com  # Artifact Registry
gcloud services enable cloudscheduler.googleapis.com    # Cloud Scheduler
gcloud services enable cloudfunctions.googleapis.com    # Cloud Functions

echo "✅ All APIs enabled successfully!"
echo "📋 Next: Configure app.isectech.org domain"