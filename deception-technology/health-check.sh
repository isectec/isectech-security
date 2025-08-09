#!/bin/bash
# Health check script for deception technology services

# Check if the main service is responding
if [ "$SERVICE_TYPE" = "decoy" ]; then
    curl -sf http://localhost:${PORT:-3001}/health > /dev/null
elif [ "$SERVICE_TYPE" = "canary" ]; then
    curl -sf http://localhost:${PORT:-3002}/health > /dev/null
else
    # Default health check
    curl -sf http://localhost:${PORT:-3000}/health > /dev/null
fi

exit $?