#!/bin/bash

# Enable Available APIs for iSECTECH Microservices Platform
# Project: isectech-protech-project

set -e

# Add gcloud to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo "🚀 Enabling APIs for iSECTECH Platform..."

# Set project context
gcloud config set project isectech-protech-project

# Function to enable API with error handling
enable_api() {
    local api=$1
    local description=$2
    echo "  Enabling $description ($api)..."
    if gcloud services enable "$api" 2>/dev/null; then
        echo "  ✅ $description enabled"
    else
        echo "  ⚠️  $description not available or already enabled"
    fi
}

# Core Kubernetes and Container APIs
echo "📦 Enabling Kubernetes and Container APIs..."
enable_api "container.googleapis.com" "Google Kubernetes Engine"
enable_api "gkehub.googleapis.com" "Anthos/GKE Hub"
enable_api "anthos.googleapis.com" "Anthos Service Mesh"

# Networking and Load Balancing
echo "🌐 Enabling Networking APIs..."
enable_api "dns.googleapis.com" "Cloud DNS"
enable_api "networkservices.googleapis.com" "Network Services"
enable_api "certificatemanager.googleapis.com" "Certificate Manager"
enable_api "networkmanagement.googleapis.com" "Network Management"

# Security and Encryption
echo "🔐 Enabling Security APIs..."
enable_api "cloudkms.googleapis.com" "Cloud Key Management"
enable_api "binaryauthorization.googleapis.com" "Binary Authorization"
enable_api "securitycenter.googleapis.com" "Security Command Center"
enable_api "accesscontextmanager.googleapis.com" "VPC Service Controls"

# Data and Analytics
echo "📊 Enabling Data APIs..."
enable_api "bigquery.googleapis.com" "BigQuery for analytics"
enable_api "bigtable.googleapis.com" "Cloud Bigtable"
enable_api "spanner.googleapis.com" "Cloud Spanner"
enable_api "redis.googleapis.com" "Redis for caching"

# Messaging and Events
echo "📨 Enabling Messaging APIs..."
enable_api "pubsub.googleapis.com" "Cloud Pub/Sub"
enable_api "eventarc.googleapis.com" "Eventarc"
enable_api "workflows.googleapis.com" "Workflows"

# Monitoring and Observability
echo "📈 Enabling Monitoring APIs..."
enable_api "monitoring.googleapis.com" "Cloud Monitoring"
enable_api "logging.googleapis.com" "Cloud Logging"
enable_api "cloudtrace.googleapis.com" "Cloud Trace"
enable_api "cloudprofiler.googleapis.com" "Cloud Profiler"

# AI/ML for Security Analytics
echo "🤖 Enabling AI/ML APIs..."
enable_api "aiplatform.googleapis.com" "Vertex AI"
enable_api "ml.googleapis.com" "Machine Learning APIs"
enable_api "automl.googleapis.com" "AutoML"

# Additional Platform Services
echo "⚙️ Enabling Platform APIs..."
enable_api "cloudbuild.googleapis.com" "Cloud Build for CI/CD"
enable_api "artifactregistry.googleapis.com" "Artifact Registry"
enable_api "cloudscheduler.googleapis.com" "Cloud Scheduler"
enable_api "cloudfunctions.googleapis.com" "Cloud Functions"

echo "✅ API enablement process completed!"
echo "📋 Some APIs may require additional setup or permissions"
echo "📋 Next: Configure app.isectech.org domain"