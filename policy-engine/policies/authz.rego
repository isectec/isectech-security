package authz

import future.keywords.if
import future.keywords.in

# Default deny policy
default allow := false

# Main authorization decision
allow if {
    # Verify user authentication
    valid_user
    
    # Check trust score threshold
    trust_score_valid
    
    # Verify RBAC permissions
    has_permission
    
    # Additional context-based checks
    context_valid
}

# User authentication validation
valid_user if {
    input.user.id != ""
    input.user.authenticated == true
    not user_blocked
}

# Check if user is blocked or suspended
user_blocked if {
    input.user.status in ["blocked", "suspended", "disabled"]
}

# Trust score validation
trust_score_valid if {
    trust_score := get_trust_score(input.user.id, input.context)
    resource_threshold := get_resource_threshold(input.resource)
    trust_score >= resource_threshold
}

# Get trust score from external service
get_trust_score(user_id, context) := score if {
    response := http.send({
        "method": "GET",
        "url": sprintf("http://trust-score-service:8080/api/trust-score/%s", [user_id]),
        "headers": {
            "Authorization": sprintf("Bearer %s", [opa.env.TRUST_SCORE_API_TOKEN]),
            "Content-Type": "application/json"
        },
        "timeout": "5s"
    })
    response.status_code == 200
    score := response.body.trust_score
}

# Get trust score from cache or use default
get_trust_score(user_id, context) := 50 if {
    not http.send({
        "method": "GET",
        "url": sprintf("http://trust-score-service:8080/api/trust-score/%s", [user_id]),
        "timeout": "5s"
    })
}

# Resource-specific trust score thresholds
get_resource_threshold(resource) := threshold if {
    resource_thresholds := {
        "/api/admin": 90,
        "/api/user-management": 80,
        "/api/compliance": 85,
        "/api/analytics": 70,
        "/api/notifications": 60,
        "/api/health": 50
    }
    threshold := resource_thresholds[resource]
}

# Default threshold for unlisted resources
get_resource_threshold(resource) := 60 if {
    resource_thresholds := {
        "/api/admin": 90,
        "/api/user-management": 80,
        "/api/compliance": 85,
        "/api/analytics": 70,
        "/api/notifications": 60,
        "/api/health": 50
    }
    not resource_thresholds[resource]
}

# RBAC permission validation
has_permission if {
    rbac_check(input.user.id, input.resource, input.action, input.tenant_id)
}

# Check RBAC permissions via external service
rbac_check(user_id, resource, action, tenant_id) if {
    response := http.send({
        "method": "POST",
        "url": "http://rbac-service:8080/api/check-permission",
        "headers": {
            "Authorization": sprintf("Bearer %s", [opa.env.RBAC_API_TOKEN]),
            "Content-Type": "application/json"
        },
        "body": json.marshal({
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "tenant_id": tenant_id
        }),
        "timeout": "3s"
    })
    response.status_code == 200
    response.body.allowed == true
}

# Context-based validation
context_valid if {
    # IP address validation
    ip_allowed
    
    # Time-based access control
    time_window_allowed
    
    # Device validation
    device_trusted
    
    # Geolocation checks
    location_allowed
}

# IP address allowlist validation
ip_allowed if {
    # Allow all IPs for now - can be extended with specific rules
    true
}

# Time-based access control
time_window_allowed if {
    current_hour := time.hour_of_day(time.now_ns())
    # Business hours: 6 AM to 10 PM UTC
    current_hour >= 6
    current_hour <= 22
}

# Allow access outside business hours for emergency roles
time_window_allowed if {
    input.user.roles[_] in ["emergency_admin", "security_admin", "oncall_engineer"]
}

# Device trust validation
device_trusted if {
    input.device.id != ""
    input.device.registered == true
    not device_compromised
}

# Check if device is marked as compromised
device_compromised if {
    input.device.status in ["compromised", "suspicious", "quarantined"]
}

# Geolocation validation
location_allowed if {
    # Allow all locations for now - can be extended with geo-fencing
    true
}

# Additional security rules for high-privilege operations
admin_operations_allowed if {
    allow
    input.resource in ["/api/admin", "/api/user-management"]
    trust_score := get_trust_score(input.user.id, input.context)
    trust_score >= 95  # Higher threshold for admin operations
    mfa_verified
}

# Multi-factor authentication verification
mfa_verified if {
    input.user.mfa.verified == true
    mfa_session_valid
}

# Check MFA session validity (within last 10 minutes)
mfa_session_valid if {
    mfa_timestamp := time.parse_duration_ns(input.user.mfa.timestamp)
    current_time := time.now_ns()
    session_age := current_time - mfa_timestamp
    session_age <= 600000000000  # 10 minutes in nanoseconds
}

# Rate limiting context (for integration with rate limiter)
rate_limit_context := {
    "user_id": input.user.id,
    "tenant_id": input.tenant_id,
    "resource": input.resource,
    "action": input.action,
    "ip_address": input.context.ip_address
}

# Audit logging context
audit_context := {
    "decision": allow,
    "user_id": input.user.id,
    "tenant_id": input.tenant_id,
    "resource": input.resource,
    "action": input.action,
    "trust_score": get_trust_score(input.user.id, input.context),
    "context": input.context,
    "timestamp": time.now_ns(),
    "policy_version": "1.0.0"
}