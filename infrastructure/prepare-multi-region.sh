#!/bin/bash

# Prepare for Multi-Region Expansion
# Project: isectech-protech-project
# Regions: us-central1 (existing), europe-west1, asia-southeast1

set -e

# Add gcloud to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo "🌍 Preparing multi-region infrastructure..."

# Set project context
gcloud config set project isectech-protech-project

# Define regions
REGIONS=("us-central1" "europe-west1" "asia-southeast1")
PRIMARY_REGION="us-central1"

echo "📋 Target regions: ${REGIONS[*]}"

# Enable required regional services
echo "⚙️ Enabling regional services..."
for region in "${REGIONS[@]}"; do
    echo "  🌐 Preparing region: $region"
    
    # Enable regional APIs if needed
    gcloud services enable compute.googleapis.com
    gcloud services enable container.googleapis.com
    gcloud services enable sqladmin.googleapis.com
done

# Create regional VPC subnets for expansion
echo "🔗 Creating regional VPC subnets..."

# Europe West 1 subnet
gcloud compute networks subnets create isectech-subnet-eu \
    --network=isectech-vpc \
    --range=10.1.0.0/24 \
    --region=europe-west1 \
    --enable-private-ip-google-access || echo "Subnet may already exist"

# Asia Southeast 1 subnet  
gcloud compute networks subnets create isectech-subnet-asia \
    --network=isectech-vpc \
    --range=10.2.0.0/24 \
    --region=asia-southeast1 \
    --enable-private-ip-google-access || echo "Subnet may already exist"

# Create VPC connectors for Cloud Run in each region
echo "🔌 Creating VPC connectors..."

# Europe VPC connector
gcloud compute networks vpc-access connectors create isectech-connector-eu \
    --region=europe-west1 \
    --subnet=isectech-subnet-eu \
    --subnet-project=isectech-protech-project \
    --min-instances=2 \
    --max-instances=10 || echo "EU connector may already exist"

# Asia VPC connector
gcloud compute networks vpc-access connectors create isectech-connector-asia \
    --region=asia-southeast1 \
    --subnet=isectech-subnet-asia \
    --subnet-project=isectech-protech-project \
    --min-instances=2 \
    --max-instances=10 || echo "Asia connector may already exist"

# Reserve regional IP addresses for future load balancers
echo "📍 Reserving regional IP addresses..."

gcloud compute addresses create isectech-ip-eu \
    --region=europe-west1 || echo "EU IP may already exist"

gcloud compute addresses create isectech-ip-asia \
    --region=asia-southeast1 || echo "Asia IP may already exist"

# Create firewall rules for cross-region communication
echo "🔥 Creating cross-region firewall rules..."

gcloud compute firewall-rules create allow-cross-region-internal \
    --network=isectech-vpc \
    --allow=tcp,udp,icmp \
    --source-ranges=10.0.0.0/16,10.1.0.0/24,10.2.0.0/24 \
    --description="Allow internal communication between regions" || echo "Firewall rule may already exist"

# Prepare Cloud SQL regional instances configuration
echo "🗄️ Preparing database replication configuration..."
cat > multi-region-db-config.yaml << EOF
# Multi-region database configuration
primary_region: us-central1
replica_regions:
  - europe-west1
  - asia-southeast1

database_configuration:
  tier: db-custom-2-8192
  availability_type: REGIONAL
  backup_enabled: true
  binary_log_enabled: true
  point_in_time_recovery_enabled: true
  
network_configuration:
  ipv4_enabled: false
  private_network: projects/isectech-protech-project/global/networks/isectech-vpc
  
maintenance_window:
  day: 7  # Sunday
  hour: 3 # 3 AM UTC
EOF

# Create Cloud Storage buckets for each region
echo "🪣 Creating regional storage buckets..."

gsutil mb -p isectech-protech-project -c STANDARD -l us-central1 gs://isectech-storage-us || echo "US bucket may already exist"
gsutil mb -p isectech-protech-project -c STANDARD -l europe-west1 gs://isectech-storage-eu || echo "EU bucket may already exist"  
gsutil mb -p isectech-protech-project -c STANDARD -l asia-southeast1 gs://isectech-storage-asia || echo "Asia bucket may already exist"

# Set up Cross-Region Load Balancer health checks
echo "🏥 Creating health check configurations..."
gcloud compute health-checks create http isectech-health-check \
    --port=8080 \
    --request-path=/health \
    --check-interval=30 \
    --timeout=10 \
    --unhealthy-threshold=3 \
    --healthy-threshold=2 || echo "Health check may already exist"

echo "✅ Multi-region preparation complete!"
echo ""
echo "🌍 Prepared regions:"
echo "  • US Central 1 (Primary): 10.0.0.0/24"
echo "  • Europe West 1: 10.1.0.0/24" 
echo "  • Asia Southeast 1: 10.2.0.0/24"
echo ""
echo "📋 Next steps ready:"
echo "  • Deploy Cloud SQL read replicas"
echo "  • Set up GKE clusters in each region"
echo "  • Configure cross-region load balancing"
echo ""
echo "📄 Configuration saved to: multi-region-db-config.yaml"