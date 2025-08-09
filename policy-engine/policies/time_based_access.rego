package time_based_access

import future.keywords.if
import future.keywords.in

# Time-based access control policies
# Implements temporal access restrictions and emergency access

default time_access_allowed := false

# Main time-based access control
time_access_allowed if {
    # Standard business hours access
    business_hours_access
}

time_access_allowed if {
    # Emergency access override
    emergency_access_valid
}

time_access_allowed if {
    # Scheduled maintenance window
    maintenance_window_access
}

time_access_allowed if {
    # 24/7 access for critical roles
    always_on_role_access
}

# Business hours access control
business_hours_access if {
    current_time := time.now_ns()
    current_hour := time.hour_of_day(current_time)
    current_weekday := time.weekday(current_time)
    
    # Monday to Friday (0 = Sunday, 1 = Monday, ..., 6 = Saturday)
    current_weekday in [1, 2, 3, 4, 5]
    
    # Business hours: 6 AM to 10 PM
    current_hour >= 6
    current_hour <= 22
    
    # Not during maintenance windows
    not maintenance_window_active
}

# Weekend access for authorized roles
business_hours_access if {
    current_time := time.now_ns()
    current_weekday := time.weekday(current_time)
    
    # Weekend (Saturday or Sunday)
    current_weekday in [0, 6]
    
    # User has weekend access role
    input.user.roles[_] in ["weekend_admin", "security_admin", "oncall_engineer"]
    
    # Reasonable hours even on weekends (8 AM to 8 PM)
    current_hour := time.hour_of_day(current_time)
    current_hour >= 8
    current_hour <= 20
}

# Emergency access validation
emergency_access_valid if {
    # Emergency declared
    input.context.access_type == "emergency"
    
    # User has emergency access role
    input.user.roles[_] in ["emergency_admin", "security_admin", "incident_responder"]
    
    # Emergency ticket or incident ID provided
    input.context.emergency_reference != ""
    
    # Emergency access time limit not exceeded
    emergency_time_limit_valid
}

# Emergency access time validation (max 4 hours)
emergency_time_limit_valid if {
    emergency_start := time.parse_duration_ns(input.context.emergency_start_time)
    current_time := time.now_ns()
    emergency_duration := current_time - emergency_start
    emergency_duration <= 14400000000000  # 4 hours in nanoseconds
}

# Maintenance window access
maintenance_window_access if {
    maintenance_window_active
    input.user.roles[_] in ["maintenance_admin", "system_admin", "devops_engineer"]
    input.context.maintenance_ticket != ""
}

# Check if maintenance window is active
maintenance_window_active if {
    current_time := time.now_ns()
    maintenance_windows := data.maintenance_windows
    
    some window
    maintenance_windows[window]
    
    window_start := time.parse_duration_ns(maintenance_windows[window].start_time)
    window_end := time.parse_duration_ns(maintenance_windows[window].end_time)
    
    current_time >= window_start
    current_time <= window_end
}

# Always-on access for critical roles
always_on_role_access if {
    input.user.roles[_] in ["super_admin", "security_ops", "monitoring_service"]
    
    # Even always-on access should have reasonable restrictions
    not high_risk_time_period
}

# High-risk time periods (e.g., during known attack patterns)
high_risk_time_period if {
    # Block access during known high-risk periods
    # This could be dynamically updated based on threat intelligence
    current_hour := time.hour_of_day(time.now_ns())
    
    # Example: Block 2 AM to 4 AM unless explicitly authorized
    current_hour >= 2
    current_hour <= 4
    
    not input.context.high_risk_authorized
}

# Session time limits based on role and context
session_time_limit_valid if {
    session_start := time.parse_duration_ns(input.user.session.start_time)
    current_time := time.now_ns()
    session_duration := current_time - session_start
    
    max_session_duration := get_max_session_duration(input.user.roles[_])
    session_duration <= max_session_duration
}

# Get maximum session duration based on highest privilege role
get_max_session_duration(role) := duration if {
    session_limits := {
        "super_admin": 7200000000000,        # 2 hours
        "security_admin": 10800000000000,    # 3 hours
        "tenant_admin": 14400000000000,      # 4 hours
        "user": 28800000000000,              # 8 hours
        "readonly": 43200000000000           # 12 hours
    }
    duration := session_limits[role]
}

# Default session duration for unknown roles
get_max_session_duration(role) := 3600000000000 if {  # 1 hour
    session_limits := {
        "super_admin": 7200000000000,
        "security_admin": 10800000000000,
        "tenant_admin": 14400000000000,
        "user": 28800000000000,
        "readonly": 43200000000000
    }
    not session_limits[role]
}

# Idle timeout validation
idle_timeout_valid if {
    last_activity := time.parse_duration_ns(input.user.session.last_activity)
    current_time := time.now_ns()
    idle_duration := current_time - last_activity
    
    max_idle_duration := get_max_idle_duration(input.user.roles[_])
    idle_duration <= max_idle_duration
}

# Get maximum idle duration based on role
get_max_idle_duration(role) := duration if {
    idle_limits := {
        "super_admin": 1800000000000,        # 30 minutes
        "security_admin": 2700000000000,     # 45 minutes
        "tenant_admin": 3600000000000,       # 1 hour
        "user": 7200000000000,               # 2 hours
        "readonly": 14400000000000           # 4 hours
    }
    duration := idle_limits[role]
}

# Default idle timeout for unknown roles
get_max_idle_duration(role) := 1800000000000 if {  # 30 minutes
    idle_limits := {
        "super_admin": 1800000000000,
        "security_admin": 2700000000000,
        "tenant_admin": 3600000000000,
        "user": 7200000000000,
        "readonly": 14400000000000
    }
    not idle_limits[role]
}

# Timezone-aware access control
timezone_access_valid if {
    user_timezone := input.user.profile.timezone
    user_local_time := time.add_date(time.now_ns(), 0, 0, 0)
    user_local_hour := time.hour_of_day(user_local_time)
    
    # Apply business hours based on user's timezone
    user_local_hour >= 6
    user_local_hour <= 22
}

# Holiday access control
holiday_access_valid if {
    current_date := time.date(time.now_ns())
    
    # Allow access if not a holiday
    not is_holiday(current_date)
}

# Holiday access for authorized users
holiday_access_valid if {
    current_date := time.date(time.now_ns())
    is_holiday(current_date)
    
    # User has holiday access authorization
    input.user.roles[_] in ["holiday_admin", "security_admin", "emergency_admin"]
}

# Check if current date is a holiday
is_holiday(date) if {
    holidays := data.holidays
    date in holidays
}

# Audit context for time-based decisions
time_audit_context := {
    "decision": time_access_allowed,
    "current_time": time.now_ns(),
    "business_hours": business_hours_access,
    "emergency_access": emergency_access_valid,
    "maintenance_window": maintenance_window_access,
    "session_valid": session_time_limit_valid,
    "idle_timeout_valid": idle_timeout_valid,
    "user_timezone": input.user.profile.timezone,
    "access_context": input.context
}