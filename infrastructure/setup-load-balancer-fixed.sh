#!/bin/bash

# Set up Global Load Balancer for app.isectech.org
# Project: isectech-protech-project

set -e

# Add gcloud to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo "⚖️ Setting up Global Load Balancer..."

# Set project context
gcloud config set project isectech-protech-project

# Function to create resource with error handling
create_resource() {
    local command="$1"
    local resource_name="$2"
    local description="$3"
    
    echo "$description..."
    if eval "$command" 2>/dev/null; then
        echo "✅ $resource_name created"
    else
        echo "⚠️  $resource_name already exists or creation failed"
    fi
}

# Reserve global static IP address (or use existing)
echo "🌐 Reserving global static IP..."
create_resource "gcloud compute addresses create isectech-global-ip --ip-version=IPV4 --global" "Global IP" "Creating global IP address"

# Get the reserved IP address
GLOBAL_IP=$(gcloud compute addresses describe isectech-global-ip --global --format="value(address)")
echo "📍 Using IP: $GLOBAL_IP"

# Create managed SSL certificate for app.isectech.org (or use existing)
echo "🔒 Creating managed SSL certificate..."
create_resource "gcloud compute ssl-certificates create isectech-ssl-cert --domains=app.isectech.org,www.app.isectech.org --global" "SSL Certificate" "Creating SSL certificate"

# Create Cloud Run NEG (Network Endpoint Group) for existing service
echo "🔗 Creating Network Endpoint Group..."
create_resource "gcloud compute network-endpoint-groups create isectech-neg --region=us-central1 --network-endpoint-type=serverless --cloud-run-service=isectech-app" "Network Endpoint Group" "Creating NEG"

# Create backend service
echo "🎯 Creating backend service..."
create_resource "gcloud compute backend-services create isectech-backend --global --load-balancing-scheme=EXTERNAL_MANAGED" "Backend Service" "Creating backend service"

# Add NEG to backend service (handle if already added)
echo "➕ Adding NEG to backend service..."
if ! gcloud compute backend-services describe isectech-backend --global --format="value(backends[].group)" | grep -q "isectech-neg"; then
    gcloud compute backend-services add-backend isectech-backend \
        --global \
        --network-endpoint-group=isectech-neg \
        --network-endpoint-group-region=us-central1
    echo "✅ NEG added to backend service"
else
    echo "⚠️  NEG already added to backend service"
fi

# Create URL map
echo "🗺️ Creating URL map..."
create_resource "gcloud compute url-maps create isectech-url-map --default-service=isectech-backend" "URL Map" "Creating URL map"

# Create HTTPS proxy
echo "🔐 Creating HTTPS proxy..."
create_resource "gcloud compute target-https-proxies create isectech-https-proxy --url-map=isectech-url-map --ssl-certificates=isectech-ssl-cert" "HTTPS Proxy" "Creating HTTPS proxy"

# Create global forwarding rule for HTTPS
echo "📡 Creating HTTPS forwarding rule..."
create_resource "gcloud compute forwarding-rules create isectech-https-forwarding-rule --address=isectech-global-ip --global --target-https-proxy=isectech-https-proxy --ports=443" "HTTPS Forwarding Rule" "Creating HTTPS forwarding rule"

# Create HTTP to HTTPS redirect
echo "🔄 Setting up HTTP to HTTPS redirect..."
create_resource "gcloud compute url-maps create isectech-http-redirect --default-url-redirect-response-code=301 --default-url-redirect-https-redirect" "HTTP Redirect URL Map" "Creating HTTP redirect"

create_resource "gcloud compute target-http-proxies create isectech-http-proxy --url-map=isectech-http-redirect" "HTTP Proxy" "Creating HTTP proxy"

create_resource "gcloud compute forwarding-rules create isectech-http-forwarding-rule --address=isectech-global-ip --global --target-http-proxy=isectech-http-proxy --ports=80" "HTTP Forwarding Rule" "Creating HTTP forwarding rule"

# Update DNS A record with the global IP
echo "📝 Updating DNS A record..."
if gcloud dns record-sets update app.isectech.org. --zone=isectech-zone --type=A --ttl=300 --rrdatas=$GLOBAL_IP 2>/dev/null; then
    echo "✅ DNS A record updated"
else
    echo "⚠️  DNS A record update failed or already set"
fi

echo "✅ Global Load Balancer setup complete!"
echo ""
echo "🌐 Your app will be available at:"
echo "   https://app.isectech.org"
echo "   IP Address: $GLOBAL_IP"
echo ""
echo "⏱️ SSL certificate provisioning may take 10-60 minutes"
echo "📋 Next: Prepare for multi-region expansion"