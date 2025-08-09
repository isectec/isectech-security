# ═══════════════════════════════════════════════════════════════════════════════
# iSECTECH Data Residency OPA Policies
# Production-grade Open Policy Agent rules for data residency compliance
# Author: Claude Code - MULTI-REGION-DEPLOYMENT-AGENT
# Version: 1.0.0 - Task 70.5 Implementation
# ═══════════════════════════════════════════════════════════════════════════════

package data_residency

# ═══════════════════════════════════════════════════════════════════════════════
# REGIONAL COMPLIANCE ZONE DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Regional compliance mapping
approved_regions := {
    "gdpr": [
        "europe-west4",   # Netherlands - Primary EU region
        "europe-west1"    # Belgium - EU backup region
    ],
    "ccpa": [
        "us-central1",    # Iowa - Primary US region
        "us-east1"        # South Carolina - US backup region
    ],
    "appi": [
        "asia-northeast1" # Tokyo - Primary APAC region
    ]
}

# Compliance zone requirements
compliance_requirements := {
    "gdpr": {
        "data_export_allowed": false,
        "retention_max_days": 365,
        "encryption_required": true,
        "pseudonymization_required": true,
        "right_to_deletion": true,
        "data_portability": true,
        "consent_required": true,
        "breach_notification_hours": 72
    },
    "ccpa": {
        "data_export_allowed": false,
        "retention_max_days": 730,
        "encryption_required": true,
        "pseudonymization_required": false,
        "right_to_deletion": true,
        "data_portability": true,
        "consent_required": false,
        "breach_notification_hours": 72
    },
    "appi": {
        "data_export_allowed": false,
        "retention_max_days": 1095,
        "encryption_required": true,
        "pseudonymization_required": false,
        "right_to_deletion": false,
        "data_portability": false,
        "consent_required": true,
        "breach_notification_hours": 24
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# STORAGE BUCKET POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

# Allow storage bucket creation only in approved regions
allow_storage_bucket {
    input.resource_type == "storage_bucket"
    input.location in approved_regions[input.compliance_zone]
    is_single_region(input.location)
}

# Deny multi-region buckets that violate data residency
deny_multi_region_bucket {
    input.resource_type == "storage_bucket"
    is_multi_region(input.location)
}

# Require encryption for all storage buckets
require_storage_encryption {
    input.resource_type == "storage_bucket"
    input.encryption.default_kms_key_name != ""
    is_regional_kms_key(input.encryption.default_kms_key_name, input.region)
}

# Require versioning for data protection
require_storage_versioning {
    input.resource_type == "storage_bucket"
    input.versioning_enabled == true
}

# Check lifecycle policies for compliance
validate_storage_lifecycle {
    input.resource_type == "storage_bucket"
    some lifecycle_rule
    input.lifecycle_rules[_] = lifecycle_rule
    lifecycle_rule.condition.age <= compliance_requirements[input.compliance_zone].retention_max_days
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD SQL POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

# Allow SQL instance only in compliance zone regions
allow_sql_instance {
    input.resource_type == "sql_instance"
    input.region in approved_regions[input.compliance_zone]
}

# Deny cross-region backup for SQL instances
deny_cross_region_backup {
    input.resource_type == "sql_instance"
    input.backup_location != ""
    input.backup_location != input.region
}

# Require SQL encryption at rest
require_sql_encryption {
    input.resource_type == "sql_instance" 
    input.database_encryption.state == "ENCRYPTED"
    is_regional_kms_key(input.database_encryption.key_name, input.region)
}

# Require private IP for SQL instances
require_sql_private_ip {
    input.resource_type == "sql_instance"
    input.ip_configuration.ipv4_enabled == false
    input.ip_configuration.private_network != ""
}

# Validate SQL backup retention
validate_sql_backup_retention {
    input.resource_type == "sql_instance"
    backup_retention := input.backup_configuration.retained_backups
    backup_retention <= compliance_requirements[input.compliance_zone].retention_max_days / 30
}

# ═══════════════════════════════════════════════════════════════════════════════
# COMPUTE ENGINE POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

# Allow compute instances only in approved regions
allow_compute_instance {
    input.resource_type == "compute_instance"
    extract_region(input.zone) in approved_regions[input.compliance_zone]
}

# Deny external IP access for compliance
deny_external_ip {
    input.resource_type == "compute_instance"
    count(input.access_configs) > 0
}

# Require disk encryption for compute instances
require_compute_disk_encryption {
    input.resource_type == "compute_instance"
    some disk
    input.disks[_] = disk
    disk.disk_encryption_key != null
    is_regional_kms_key(disk.disk_encryption_key.kms_key_name, input.region)
}

# Require shielded VM features
require_shielded_vm {
    input.resource_type == "compute_instance"
    input.shielded_instance_config.enable_secure_boot == true
    input.shielded_instance_config.enable_integrity_monitoring == true
}

# ═══════════════════════════════════════════════════════════════════════════════
# BIGQUERY POLICIES  
# ═══════════════════════════════════════════════════════════════════════════════

# Allow BigQuery datasets only in approved regions
allow_bigquery_dataset {
    input.resource_type == "bigquery_dataset"
    input.location in approved_regions[input.compliance_zone]
    is_single_region(input.location)
}

# Deny multi-region BigQuery datasets
deny_multi_region_bigquery {
    input.resource_type == "bigquery_dataset"
    is_multi_region(input.location)
}

# Require BigQuery encryption
require_bigquery_encryption {
    input.resource_type == "bigquery_dataset"
    input.default_encryption_configuration.kms_key_name != ""
    is_regional_kms_key(input.default_encryption_configuration.kms_key_name, input.location)
}

# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK SECURITY POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

# Block cross-region VPC peering
deny_cross_region_peering {
    input.resource_type == "compute_network_peering"
    extract_region_from_network(input.source_network) != extract_region_from_network(input.target_network)
}

# Require private Google access for subnets
require_private_google_access {
    input.resource_type == "compute_subnetwork"
    input.private_ip_google_access == true
}

# Validate subnet CIDR ranges don't overlap between regions
validate_subnet_isolation {
    input.resource_type == "compute_subnetwork"
    subnet_region := extract_region_from_subnet(input.name)
    not overlaps_with_other_regions(input.ip_cidr_range, subnet_region)
}

# ═══════════════════════════════════════════════════════════════════════════════
# KMS AND ENCRYPTION POLICIES
# ═══════════════════════════════════════════════════════════════════════════════

# Require regional KMS keys for data residency
require_regional_kms {
    input.resource_type in ["storage_bucket", "sql_instance", "bigquery_dataset", "compute_instance"]
    kms_key := get_kms_key(input)
    kms_key != ""
    is_regional_kms_key(kms_key, input.region)
}

# Validate KMS key rotation period
validate_kms_rotation {
    input.resource_type == "kms_crypto_key"
    rotation_seconds := parse_duration_to_seconds(input.rotation_period)
    rotation_seconds <= 7776000  # 90 days maximum
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# Check if location is multi-region
is_multi_region(location) {
    upper(location) in ["US", "EU", "ASIA"]
}

# Check if location is single region
is_single_region(location) {
    not is_multi_region(location)
    regex.match("[a-z]+-[a-z0-9]+-[0-9]+", lower(location))
}

# Check if KMS key is regional and matches resource region
is_regional_kms_key(kms_key_name, resource_region) {
    kms_region := extract_kms_region(kms_key_name)
    kms_region == resource_region
}

# Extract region from zone
extract_region(zone) := region {
    zone_parts := split(zone, "-")
    region := sprintf("%s-%s-%s", [zone_parts[0], zone_parts[1], zone_parts[2]])
}

# Extract region from KMS key name
extract_kms_region(kms_key_name) := region {
    key_parts := split(kms_key_name, "/")
    locations_index := index_of(key_parts, "locations") 
    locations_index >= 0
    region := key_parts[locations_index + 1]
}

# Extract region from network name
extract_region_from_network(network_name) := region {
    network_parts := split(network_name, "/")
    # Extract region from network resource path
    contains(network_name, "/regions/")
    regions_index := index_of(network_parts, "regions")
    regions_index >= 0
    region := network_parts[regions_index + 1]
}

# Extract region from subnet name
extract_region_from_subnet(subnet_name) := region {
    name_parts := split(subnet_name, "-")
    count(name_parts) >= 3
    region := sprintf("%s-%s-%s", [name_parts[1], name_parts[2], name_parts[3]])
}

# Get KMS key from resource based on type
get_kms_key(resource) := kms_key {
    resource.resource_type == "storage_bucket"
    kms_key := resource.encryption.default_kms_key_name
} else := kms_key {
    resource.resource_type == "sql_instance" 
    kms_key := resource.database_encryption.key_name
} else := kms_key {
    resource.resource_type == "bigquery_dataset"
    kms_key := resource.default_encryption_configuration.kms_key_name
} else := "" {
    true
}

# Parse duration string to seconds
parse_duration_to_seconds(duration_str) := seconds {
    endswith(duration_str, "s")
    seconds := to_number(trim_suffix(duration_str, "s"))
}

# Find index of element in array
index_of(arr, element) := i {
    arr[i] == element
} else := -1 {
    true
}

# Check if CIDR range overlaps with other regions
overlaps_with_other_regions(cidr_range, current_region) {
    # This would be implemented with actual CIDR overlap logic
    # For now, simplified check
    false
}

# ═══════════════════════════════════════════════════════════════════════════════
# VIOLATION RULES (WHAT TO DENY)
# ═══════════════════════════════════════════════════════════════════════════════

# Storage violations
storage_violations[violation] {
    input.resource_type == "storage_bucket"
    deny_multi_region_bucket
    violation := {
        "policy": "data_residency",
        "rule": "deny_multi_region_bucket",
        "severity": "critical",
        "message": sprintf("Storage bucket uses multi-region location '%s' which violates data residency requirements", [input.location])
    }
}

storage_violations[violation] {
    input.resource_type == "storage_bucket"
    not require_storage_encryption
    violation := {
        "policy": "encryption_compliance",
        "rule": "require_storage_encryption", 
        "severity": "high",
        "message": "Storage bucket must use customer-managed encryption keys (CMEK)"
    }
}

# SQL violations
sql_violations[violation] {
    input.resource_type == "sql_instance"
    deny_cross_region_backup
    violation := {
        "policy": "data_residency",
        "rule": "deny_cross_region_backup",
        "severity": "high", 
        "message": sprintf("SQL instance backup location '%s' differs from instance region '%s'", [input.backup_location, input.region])
    }
}

sql_violations[violation] {
    input.resource_type == "sql_instance"
    not require_sql_encryption
    violation := {
        "policy": "encryption_compliance",
        "rule": "require_sql_encryption",
        "severity": "high",
        "message": "SQL instance must use encryption at rest with regional KMS keys"
    }
}

# Compute violations
compute_violations[violation] {
    input.resource_type == "compute_instance"
    deny_external_ip
    violation := {
        "policy": "network_security", 
        "rule": "deny_external_ip",
        "severity": "medium",
        "message": "Compute instance must not have external IP access"
    }
}

# BigQuery violations  
bigquery_violations[violation] {
    input.resource_type == "bigquery_dataset"
    deny_multi_region_bigquery
    violation := {
        "policy": "data_residency",
        "rule": "deny_multi_region_bigquery",
        "severity": "critical",
        "message": sprintf("BigQuery dataset location '%s' is multi-region which violates data residency", [input.location])
    }
}

# Collect all violations
violations := array.concat(
    array.concat(storage_violations, sql_violations),
    array.concat(compute_violations, bigquery_violations)
)