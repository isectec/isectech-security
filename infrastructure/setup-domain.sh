#!/bin/bash

# Configure app.isectech.org domain with Cloud DNS
# Project: isectech-protech-project

set -e

# Add gcloud to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo "🌐 Setting up app.isectech.org domain..."

# Set project context
gcloud config set project isectech-protech-project

# Create Cloud DNS managed zone for isectech.org
echo "📝 Creating DNS managed zone..."
gcloud dns managed-zones create isectech-zone \
    --description="DNS zone for iSECTECH platform" \
    --dns-name="isectech.org." \
    --visibility=public

# Get the name servers for the zone
echo "📋 Getting name servers..."
gcloud dns managed-zones describe isectech-zone \
    --format="value(nameServers)" > nameservers.txt

echo "🔍 Your name servers:"
cat nameservers.txt

# Create A record for app.isectech.org pointing to load balancer
# Note: IP will be updated after load balancer creation
echo "📌 Creating temporary A record..."
gcloud dns record-sets create app.isectech.org. \
    --zone=isectech-zone \
    --type=A \
    --ttl=300 \
    --rrdatas=34.102.136.180

# Create CNAME for www.app.isectech.org
echo "🔗 Creating CNAME record..."
gcloud dns record-sets create www.app.isectech.org. \
    --zone=isectech-zone \
    --type=CNAME \
    --ttl=300 \
    --rrdatas=app.isectech.org.

# Create MX records for email (optional)
echo "📧 Creating MX records..."
gcloud dns record-sets create isectech.org. \
    --zone=isectech-zone \
    --type=MX \
    --ttl=3600 \
    --rrdatas="10 mail.isectech.org."

echo "✅ DNS zone created successfully!"
echo ""
echo "🚨 IMPORTANT: Update your domain registrar with these name servers:"
echo "================================================"
cat nameservers.txt
echo "================================================"
echo ""
echo "📋 Next: Set up Global Load Balancer"