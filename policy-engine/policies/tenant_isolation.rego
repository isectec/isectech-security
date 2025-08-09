package tenant_isolation

import future.keywords.if
import future.keywords.in

# Tenant isolation policy
# Ensures users can only access resources within their tenant boundaries

default tenant_access_allowed := false

# Main tenant access control
tenant_access_allowed if {
    # User must have valid tenant association
    user_tenant_valid
    
    # Request must be for user's tenant or cross-tenant access is explicitly allowed
    tenant_boundary_respected
    
    # Multi-tenant operations must be explicitly authorized
    multi_tenant_operation_allowed
}

# Validate user-tenant association
user_tenant_valid if {
    input.user.tenant_id != ""
    input.user.tenant_id == input.tenant_id
}

# Cross-tenant access validation for admin users
user_tenant_valid if {
    input.user.roles[_] in ["super_admin", "cross_tenant_admin"]
    cross_tenant_access_justified
}

# Tenant boundary enforcement
tenant_boundary_respected if {
    # Same tenant access
    input.user.tenant_id == input.tenant_id
}

# Cross-tenant access for authorized operations
tenant_boundary_respected if {
    input.user.roles[_] in ["super_admin", "cross_tenant_admin"]
    cross_tenant_operations[input.action]
}

# Cross-tenant operations that are allowed for authorized users
cross_tenant_operations := {
    "audit",
    "compliance_check",
    "security_scan",
    "health_check",
    "billing_management"
}

# Justify cross-tenant access with audit trail
cross_tenant_access_justified if {
    input.context.justification != ""
    input.context.audit_reference != ""
    emergency_access_or_scheduled_maintenance
}

# Emergency access or scheduled maintenance window
emergency_access_or_scheduled_maintenance if {
    input.context.access_type in ["emergency", "scheduled_maintenance"]
}

# Multi-tenant operation authorization
multi_tenant_operation_allowed if {
    # Single tenant operation - always allowed
    not is_multi_tenant_operation
}

multi_tenant_operation_allowed if {
    # Multi-tenant operation with proper authorization
    is_multi_tenant_operation
    input.user.roles[_] in ["super_admin", "cross_tenant_admin"]
    multi_tenant_request_valid
}

# Detect multi-tenant operations
is_multi_tenant_operation if {
    # Check if request affects multiple tenants
    count(input.affected_tenants) > 1
}

is_multi_tenant_operation if {
    # Check if request is for tenant management
    startswith(input.resource, "/api/tenants")
}

# Validate multi-tenant requests
multi_tenant_request_valid if {
    # All affected tenants must be explicitly listed
    count(input.affected_tenants) > 0
    
    # Request must include proper justification
    input.context.multi_tenant_justification != ""
    
    # Audit trail must be present
    input.context.audit_trail != ""
}

# Data residency compliance
data_residency_compliant if {
    tenant_region := get_tenant_region(input.tenant_id)
    request_region := input.context.region
    tenant_region == request_region
}

# Cross-region access for disaster recovery
data_residency_compliant if {
    input.context.access_type == "disaster_recovery"
    dr_region_authorized(input.context.region, input.tenant_id)
}

# Get tenant's primary region
get_tenant_region(tenant_id) := region if {
    # This would typically call an external service
    tenant_config := data.tenants[tenant_id]
    region := tenant_config.region
}

# Default region fallback
get_tenant_region(tenant_id) := "us-east-1" if {
    not data.tenants[tenant_id]
}

# Validate disaster recovery region authorization
dr_region_authorized(region, tenant_id) if {
    tenant_config := data.tenants[tenant_id]
    region in tenant_config.authorized_dr_regions
}

# Tenant resource quotas validation
resource_quota_compliant if {
    tenant_quotas := get_tenant_quotas(input.tenant_id)
    current_usage := get_current_usage(input.tenant_id, input.resource_type)
    requested_amount := input.context.requested_amount
    
    (current_usage + requested_amount) <= tenant_quotas[input.resource_type]
}

# Always allow non-quota-impacting operations
resource_quota_compliant if {
    input.action in ["read", "list", "describe", "health_check"]
}

# Get tenant resource quotas
get_tenant_quotas(tenant_id) := quotas if {
    quotas := data.tenant_quotas[tenant_id]
}

# Default quotas for new tenants
get_tenant_quotas(tenant_id) := {
    "api_calls": 10000,
    "storage_gb": 100,
    "users": 50,
    "integrations": 10
} if {
    not data.tenant_quotas[tenant_id]
}

# Get current resource usage
get_current_usage(tenant_id, resource_type) := usage if {
    # This would typically call a metrics service
    response := http.send({
        "method": "GET",
        "url": sprintf("http://metrics-service:8080/api/usage/%s/%s", [tenant_id, resource_type]),
        "headers": {
            "Authorization": sprintf("Bearer %s", [opa.env.METRICS_API_TOKEN])
        },
        "timeout": "2s"
    })
    response.status_code == 200
    usage := response.body.current_usage
}

# Default usage when metrics service is unavailable
get_current_usage(tenant_id, resource_type) := 0 if {
    not http.send({
        "method": "GET",
        "url": sprintf("http://metrics-service:8080/api/usage/%s/%s", [tenant_id, resource_type]),
        "timeout": "2s"
    })
}

# Tenant status validation
tenant_active if {
    tenant_status := get_tenant_status(input.tenant_id)
    tenant_status in ["active", "trial"]
}

# Get tenant status
get_tenant_status(tenant_id) := status if {
    tenant_info := data.tenants[tenant_id]
    status := tenant_info.status
}

# Default status for unknown tenants
get_tenant_status(tenant_id) := "inactive" if {
    not data.tenants[tenant_id]
}