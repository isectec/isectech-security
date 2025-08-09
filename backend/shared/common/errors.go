package common

import (
	"errors"
	"fmt"
	"net/http"
	"runtime"
)

// ErrorCode represents different types of application errors
type ErrorCode string

const (
	// General errors
	ErrCodeInternal        ErrorCode = "INTERNAL_ERROR"
	ErrCodeInvalidInput    ErrorCode = "INVALID_INPUT"
	ErrCodeNotFound        ErrorCode = "NOT_FOUND"
	ErrCodeAlreadyExists   ErrorCode = "ALREADY_EXISTS"
	ErrCodeUnauthorized    ErrorCode = "UNAUTHORIZED"
	ErrCodeForbidden       ErrorCode = "FORBIDDEN"
	ErrCodeTimeout         ErrorCode = "TIMEOUT"
	ErrCodeServiceUnavailable ErrorCode = "SERVICE_UNAVAILABLE"
	
	// Authentication errors
	ErrCodeInvalidCredentials ErrorCode = "INVALID_CREDENTIALS"
	ErrCodeTokenExpired       ErrorCode = "TOKEN_EXPIRED"
	ErrCodeTokenInvalid       ErrorCode = "TOKEN_INVALID"
	ErrCodeAccountLocked      ErrorCode = "ACCOUNT_LOCKED"
	ErrCodeAccountDisabled    ErrorCode = "ACCOUNT_DISABLED"
	
	// Authorization errors
	ErrCodeInsufficientPermissions ErrorCode = "INSUFFICIENT_PERMISSIONS"
	ErrCodeResourceAccessDenied     ErrorCode = "RESOURCE_ACCESS_DENIED"
	ErrCodeTenantMismatch          ErrorCode = "TENANT_MISMATCH"
	
	// Validation errors
	ErrCodeValidationFailed   ErrorCode = "VALIDATION_FAILED"
	ErrCodeInvalidFormat      ErrorCode = "INVALID_FORMAT"
	ErrCodeMissingRequired    ErrorCode = "MISSING_REQUIRED"
	ErrCodeOutOfRange         ErrorCode = "OUT_OF_RANGE"
	
	// Database errors
	ErrCodeDatabaseConnection ErrorCode = "DATABASE_CONNECTION"
	ErrCodeDatabaseQuery      ErrorCode = "DATABASE_QUERY"
	ErrCodeDatabaseConstraint ErrorCode = "DATABASE_CONSTRAINT"
	ErrCodeDatabaseTransaction ErrorCode = "DATABASE_TRANSACTION"
	
	// External service errors
	ErrCodeExternalService    ErrorCode = "EXTERNAL_SERVICE"
	ErrCodeNetworkError       ErrorCode = "NETWORK_ERROR"
	ErrCodeRateLimited        ErrorCode = "RATE_LIMITED"
	
	// Business logic errors
	ErrCodeBusinessRuleViolation ErrorCode = "BUSINESS_RULE_VIOLATION"
	ErrCodeInvalidState          ErrorCode = "INVALID_STATE"
	ErrCodeOperationNotAllowed   ErrorCode = "OPERATION_NOT_ALLOWED"
	
	// Security errors
	ErrCodeSecurityViolation     ErrorCode = "SECURITY_VIOLATION"
	ErrCodeSuspiciousActivity    ErrorCode = "SUSPICIOUS_ACTIVITY"
	ErrCodeEncryptionFailed      ErrorCode = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed      ErrorCode = "DECRYPTION_FAILED"
)

// AppError represents a structured application error
type AppError struct {
	Code       ErrorCode              `json:"code"`
	Message    string                 `json:"message"`
	Details    string                 `json:"details,omitempty"`
	Cause      error                  `json:"-"`
	StatusCode int                    `json:"-"`
	Context    map[string]interface{} `json:"context,omitempty"`
	Stack      string                 `json:"-"`
	RequestID  string                 `json:"request_id,omitempty"`
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error
func (e *AppError) Unwrap() error {
	return e.Cause
}

// WithContext adds context to the error
func (e *AppError) WithContext(key string, value interface{}) *AppError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithRequestID adds request ID to the error
func (e *AppError) WithRequestID(requestID string) *AppError {
	e.RequestID = requestID
	return e
}

// WithCause sets the underlying cause
func (e *AppError) WithCause(cause error) *AppError {
	e.Cause = cause
	return e
}

// NewAppError creates a new application error
func NewAppError(code ErrorCode, message string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		StatusCode: getHTTPStatusCode(code),
		Stack:      getStackTrace(),
	}
}

// NewAppErrorWithDetails creates a new application error with details
func NewAppErrorWithDetails(code ErrorCode, message, details string) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Details:    details,
		StatusCode: getHTTPStatusCode(code),
		Stack:      getStackTrace(),
	}
}

// NewAppErrorWithCause creates a new application error with an underlying cause
func NewAppErrorWithCause(code ErrorCode, message string, cause error) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		Cause:      cause,
		StatusCode: getHTTPStatusCode(code),
		Stack:      getStackTrace(),
	}
}

// WrapError wraps an existing error with application error context
func WrapError(err error, code ErrorCode, message string) *AppError {
	if err == nil {
		return nil
	}
	
	// If it's already an AppError, preserve it
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}
	
	return &AppError{
		Code:       code,
		Message:    message,
		Cause:      err,
		StatusCode: getHTTPStatusCode(code),
		Stack:      getStackTrace(),
	}
}

// getHTTPStatusCode maps error codes to HTTP status codes
func getHTTPStatusCode(code ErrorCode) int {
	switch code {
	case ErrCodeNotFound:
		return http.StatusNotFound
	case ErrCodeAlreadyExists:
		return http.StatusConflict
	case ErrCodeInvalidInput, ErrCodeValidationFailed, ErrCodeInvalidFormat, 
		 ErrCodeMissingRequired, ErrCodeOutOfRange:
		return http.StatusBadRequest
	case ErrCodeUnauthorized, ErrCodeInvalidCredentials, ErrCodeTokenExpired, 
		 ErrCodeTokenInvalid:
		return http.StatusUnauthorized
	case ErrCodeForbidden, ErrCodeInsufficientPermissions, ErrCodeResourceAccessDenied,
		 ErrCodeTenantMismatch, ErrCodeAccountLocked, ErrCodeAccountDisabled:
		return http.StatusForbidden
	case ErrCodeTimeout:
		return http.StatusRequestTimeout
	case ErrCodeRateLimited:
		return http.StatusTooManyRequests
	case ErrCodeServiceUnavailable, ErrCodeDatabaseConnection, ErrCodeExternalService:
		return http.StatusServiceUnavailable
	case ErrCodeBusinessRuleViolation, ErrCodeInvalidState, ErrCodeOperationNotAllowed:
		return http.StatusUnprocessableEntity
	case ErrCodeSecurityViolation, ErrCodeSuspiciousActivity:
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// getStackTrace captures the current stack trace
func getStackTrace() string {
	buf := make([]byte, 1024)
	for {
		n := runtime.Stack(buf, false)
		if n < len(buf) {
			return string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

// IsAppError checks if an error is an AppError
func IsAppError(err error) bool {
	_, ok := err.(*AppError)
	return ok
}

// GetAppError extracts AppError from error chain
func GetAppError(err error) *AppError {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr
	}
	return nil
}

// HasErrorCode checks if the error has a specific error code
func HasErrorCode(err error, code ErrorCode) bool {
	if appErr := GetAppError(err); appErr != nil {
		return appErr.Code == code
	}
	return false
}

// Common error constructors for frequently used errors

// ErrNotFound creates a not found error
func ErrNotFound(resource string) *AppError {
	return NewAppError(ErrCodeNotFound, fmt.Sprintf("%s not found", resource))
}

// ErrAlreadyExists creates an already exists error
func ErrAlreadyExists(resource string) *AppError {
	return NewAppError(ErrCodeAlreadyExists, fmt.Sprintf("%s already exists", resource))
}

// ErrInvalidInput creates an invalid input error
func ErrInvalidInput(field string) *AppError {
	return NewAppError(ErrCodeInvalidInput, fmt.Sprintf("invalid input for field: %s", field))
}

// ErrUnauthorized creates an unauthorized error
func ErrUnauthorized(message string) *AppError {
	if message == "" {
		message = "unauthorized access"
	}
	return NewAppError(ErrCodeUnauthorized, message)
}

// ErrForbidden creates a forbidden error
func ErrForbidden(message string) *AppError {
	if message == "" {
		message = "access forbidden"
	}
	return NewAppError(ErrCodeForbidden, message)
}

// ErrValidationFailed creates a validation failed error
func ErrValidationFailed(details string) *AppError {
	return NewAppErrorWithDetails(ErrCodeValidationFailed, "validation failed", details)
}

// ErrDatabaseConnection creates a database connection error
func ErrDatabaseConnection(cause error) *AppError {
	return NewAppErrorWithCause(ErrCodeDatabaseConnection, "database connection failed", cause)
}

// ErrExternalService creates an external service error
func ErrExternalService(service string, cause error) *AppError {
	return NewAppErrorWithCause(ErrCodeExternalService, 
		fmt.Sprintf("external service error: %s", service), cause)
}

// ErrTimeout creates a timeout error
func ErrTimeout(operation string) *AppError {
	return NewAppError(ErrCodeTimeout, fmt.Sprintf("operation timeout: %s", operation))
}

// ErrInternal creates an internal error
func ErrInternal(message string) *AppError {
	if message == "" {
		message = "internal server error"
	}
	return NewAppError(ErrCodeInternal, message)
}

// ErrBusinessRule creates a business rule violation error
func ErrBusinessRule(rule string) *AppError {
	return NewAppError(ErrCodeBusinessRuleViolation, 
		fmt.Sprintf("business rule violation: %s", rule))
}

// ErrInvalidState creates an invalid state error
func ErrInvalidState(current, expected string) *AppError {
	return NewAppErrorWithDetails(ErrCodeInvalidState, "invalid state", 
		fmt.Sprintf("current: %s, expected: %s", current, expected))
}

// ErrTenantMismatch creates a tenant mismatch error
func ErrTenantMismatch() *AppError {
	return NewAppError(ErrCodeTenantMismatch, "resource does not belong to the specified tenant")
}

// ErrInsufficientPermissions creates an insufficient permissions error
func ErrInsufficientPermissions(permission string) *AppError {
	return NewAppError(ErrCodeInsufficientPermissions, 
		fmt.Sprintf("insufficient permissions: %s required", permission))
}

// ErrRateLimited creates a rate limited error
func ErrRateLimited() *AppError {
	return NewAppError(ErrCodeRateLimited, "rate limit exceeded")
}

// ErrSecurityViolation creates a security violation error
func ErrSecurityViolation(details string) *AppError {
	return NewAppErrorWithDetails(ErrCodeSecurityViolation, "security violation detected", details)
}

// ErrorHandler is a middleware function type for handling errors
type ErrorHandler func(error) *AppError

// RecoverHandler handles panics and converts them to errors
func RecoverHandler() *AppError {
	if r := recover(); r != nil {
		switch v := r.(type) {
		case error:
			return WrapError(v, ErrCodeInternal, "panic occurred")
		case string:
			return NewAppError(ErrCodeInternal, v)
		default:
			return NewAppError(ErrCodeInternal, fmt.Sprintf("panic occurred: %v", v))
		}
	}
	return nil
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   interface{} `json:"value,omitempty"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

// Error implements the error interface for ValidationErrors
func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}
	
	if len(ve) == 1 {
		return fmt.Sprintf("validation failed: %s %s", ve[0].Field, ve[0].Message)
	}
	
	return fmt.Sprintf("validation failed with %d errors", len(ve))
}

// ToAppError converts ValidationErrors to AppError
func (ve ValidationErrors) ToAppError() *AppError {
	if len(ve) == 0 {
		return nil
	}
	
	appErr := NewAppError(ErrCodeValidationFailed, "validation failed")
	appErr.WithContext("validation_errors", ve)
	
	return appErr
}

// Add adds a validation error
func (ve *ValidationErrors) Add(field, message string, value interface{}) {
	*ve = append(*ve, ValidationError{
		Field:   field,
		Message: message,
		Value:   value,
	})
}

// HasErrors returns true if there are validation errors
func (ve ValidationErrors) HasErrors() bool {
	return len(ve) > 0
}