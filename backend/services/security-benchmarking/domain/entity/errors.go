package entity

import (
	"fmt"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// NewValidationError creates a new validation error
func NewValidationError(message string) *ValidationError {
	return &ValidationError{
		Message: message,
	}
}

// BusinessLogicError represents a business logic error
type BusinessLogicError struct {
	Operation string
	Reason    string
}

func (e *BusinessLogicError) Error() string {
	return fmt.Sprintf("business logic error in operation '%s': %s", e.Operation, e.Reason)
}

// NewBusinessLogicError creates a new business logic error
func NewBusinessLogicError(operation, reason string) *BusinessLogicError {
	return &BusinessLogicError{
		Operation: operation,
		Reason:    reason,
	}
}