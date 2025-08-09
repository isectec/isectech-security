#!/bin/bash

# Prepare for Multi-Region Expansion (Fixed)
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

# Function to create resource with error handling
create_resource() {
    local command="$1"
    local resource_name="$2"
    local description="$3"
    
    echo "  $description..."
    if eval "$command" 2>/dev/null; then
        echo "  ✅ $resource_name created"
    else
        echo "  ⚠️  $resource_name already exists or creation failed"
    fi
}

# Create regional VPC subnets for expansion (with /28 subnets for VPC connectors)
echo "🔗 Creating regional VPC subnets..."

# Europe West 1 subnets
create_resource "gcloud compute networks subnets create isectech-subnet-eu --network=isectech-vpc --range=10.1.0.0/24 --region=europe-west1 --enable-private-ip-google-access" "EU Main Subnet" "Creating EU main subnet"

create_resource "gcloud compute networks subnets create isectech-connector-subnet-eu --network=isectech-vpc --range=10.1.1.0/28 --region=europe-west1 --enable-private-ip-google-access" "EU Connector Subnet" "Creating EU connector subnet"

# Asia Southeast 1 subnets  
create_resource "gcloud compute networks subnets create isectech-subnet-asia --network=isectech-vpc --range=10.2.0.0/24 --region=asia-southeast1 --enable-private-ip-google-access" "Asia Main Subnet" "Creating Asia main subnet"

create_resource "gcloud compute networks subnets create isectech-connector-subnet-asia --network=isectech-vpc --range=10.2.1.0/28 --region=asia-southeast1 --enable-private-ip-google-access" "Asia Connector Subnet" "Creating Asia connector subnet"

# Create VPC connectors for Cloud Run in each region
echo "🔌 Creating VPC connectors..."

# Europe VPC connector (using /28 subnet)
create_resource "gcloud compute networks vpc-access connectors create isectech-connector-eu --region=europe-west1 --subnet=isectech-connector-subnet-eu --subnet-project=isectech-protech-project --min-instances=2 --max-instances=10" "EU VPC Connector" "Creating EU VPC connector"

# Asia VPC connector (using /28 subnet)
create_resource "gcloud compute networks vpc-access connectors create isectech-connector-asia --region=asia-southeast1 --subnet=isectech-connector-subnet-asia --subnet-project=isectech-protech-project --min-instances=2 --max-instances=10" "Asia VPC Connector" "Creating Asia VPC connector"

# Reserve regional IP addresses for future load balancers
echo "📍 Reserving regional IP addresses..."

create_resource "gcloud compute addresses create isectech-ip-eu --region=europe-west1" "EU Regional IP" "Reserving EU IP"

create_resource "gcloud compute addresses create isectech-ip-asia --region=asia-southeast1" "Asia Regional IP" "Reserving Asia IP"

# Create firewall rules for cross-region communication
echo "🔥 Creating cross-region firewall rules..."

create_resource "gcloud compute firewall-rules create allow-cross-region-internal --network=isectech-vpc --allow=tcp,udp,icmp --source-ranges=10.0.0.0/16,10.1.0.0/24,10.1.1.0/28,10.2.0.0/24,10.2.1.0/28 --description='Allow internal communication between regions'" "Cross-region Firewall" "Creating cross-region firewall rules"

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

create_resource "gsutil mb -p isectech-protech-project -c STANDARD -l us-central1 gs://isectech-storage-us" "US Storage Bucket" "Creating US storage bucket"
create_resource "gsutil mb -p isectech-protech-project -c STANDARD -l europe-west1 gs://isectech-storage-eu" "EU Storage Bucket" "Creating EU storage bucket"
create_resource "gsutil mb -p isectech-protech-project -c STANDARD -l asia-southeast1 gs://isectech-storage-asia" "Asia Storage Bucket" "Creating Asia storage bucket"

# Set up Cross-Region Load Balancer health checks
echo "🏥 Creating health check configurations..."
create_resource "gcloud compute health-checks create http isectech-health-check --port=8080 --request-path=/health --check-interval=30 --timeout=10 --unhealthy-threshold=3 --healthy-threshold=2" "Health Check" "Creating health check"

echo "✅ Multi-region preparation complete!"
echo ""
echo "🌍 Prepared regions:"
echo "  • US Central 1 (Primary): 10.0.0.0/24"
echo "  • Europe West 1: 10.1.0.0/24 (connector: 10.1.1.0/28)" 
echo "  • Asia Southeast 1: 10.2.0.0/24 (connector: 10.2.1.0/28)"
echo ""
echo "📋 Next steps ready:"
echo "  • Deploy Cloud SQL read replicas"
echo "  • Set up GKE clusters in each region"
echo "  • Configure cross-region load balancing"
echo ""
echo "📄 Configuration saved to: multi-region-db-config.yaml"