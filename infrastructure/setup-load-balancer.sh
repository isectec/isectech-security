#!/bin/bash

# Set up Global Load Balancer for app.isectech.org
# Project: isectech-protech-project

set -e

# Add gcloud to PATH
export PATH="$HOME/google-cloud-sdk/bin:$PATH"

echo "⚖️ Setting up Global Load Balancer..."

# Set project context
gcloud config set project isectech-protech-project

# Reserve global static IP address
echo "🌐 Reserving global static IP..."
gcloud compute addresses create isectech-global-ip \
    --ip-version=IPV4 \
    --global

# Get the reserved IP address
GLOBAL_IP=$(gcloud compute addresses describe isectech-global-ip --global --format="value(address)")
echo "📍 Reserved IP: $GLOBAL_IP"

# Create managed SSL certificate for app.isectech.org
echo "🔒 Creating managed SSL certificate..."
gcloud compute ssl-certificates create isectech-ssl-cert \
    --domains=app.isectech.org,www.app.isectech.org \
    --global

# Create Cloud Run NEG (Network Endpoint Group) for existing service
echo "🔗 Creating Network Endpoint Group..."
gcloud compute network-endpoint-groups create isectech-neg \
    --region=us-central1 \
    --network-endpoint-type=serverless \
    --cloud-run-service=isectech-app

# Create backend service
echo "🎯 Creating backend service..."
gcloud compute backend-services create isectech-backend \
    --global \
    --load-balancing-scheme=EXTERNAL_MANAGED

# Add NEG to backend service
echo "➕ Adding NEG to backend service..."
gcloud compute backend-services add-backend isectech-backend \
    --global \
    --network-endpoint-group=isectech-neg \
    --network-endpoint-group-region=us-central1

# Create URL map
echo "🗺️ Creating URL map..."
gcloud compute url-maps create isectech-url-map \
    --default-service=isectech-backend

# Create HTTPS proxy
echo "🔐 Creating HTTPS proxy..."
gcloud compute target-https-proxies create isectech-https-proxy \
    --url-map=isectech-url-map \
    --ssl-certificates=isectech-ssl-cert

# Create global forwarding rule for HTTPS
echo "📡 Creating HTTPS forwarding rule..."
gcloud compute forwarding-rules create isectech-https-forwarding-rule \
    --address=isectech-global-ip \
    --global \
    --target-https-proxy=isectech-https-proxy \
    --ports=443

# Create HTTP to HTTPS redirect
echo "🔄 Setting up HTTP to HTTPS redirect..."
gcloud compute url-maps create isectech-http-redirect \
    --default-url-redirect-response-code=301 \
    --default-url-redirect-https-redirect

gcloud compute target-http-proxies create isectech-http-proxy \
    --url-map=isectech-http-redirect

gcloud compute forwarding-rules create isectech-http-forwarding-rule \
    --address=isectech-global-ip \
    --global \
    --target-http-proxy=isectech-http-proxy \
    --ports=80

# Update DNS A record with the global IP
echo "📝 Updating DNS A record..."
gcloud dns record-sets update app.isectech.org. \
    --zone=isectech-zone \
    --type=A \
    --ttl=300 \
    --rrdatas=$GLOBAL_IP

echo "✅ Global Load Balancer setup complete!"
echo ""
echo "🌐 Your app will be available at:"
echo "   https://app.isectech.org"
echo "   IP Address: $GLOBAL_IP"
echo ""
echo "⏱️ SSL certificate provisioning may take 10-60 minutes"
echo "📋 Next: Prepare for multi-region expansion"