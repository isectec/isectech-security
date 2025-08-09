package usecase

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"isectech/auth-service/domain/entity"
	"isectech/auth-service/domain/service"
	"isectech/auth-service/infrastructure/database/postgres"
)

// PasswordServiceImpl implements password management operations
type PasswordServiceImpl struct {
	userRepo        *postgres.UserRepository
	auditRepo       *postgres.AuditRepository
	emailService    EmailService
	authService     *AuthenticationServiceImpl
	config          *PasswordConfig
	commonPasswords map[string]bool
	passwordHistory PasswordHistoryStore
}

// PasswordConfig holds password policy configuration
type PasswordConfig struct {
	// Length requirements
	MinLength int `yaml:"min_length" default:"12"`
	MaxLength int `yaml:"max_length" default:"128"`

	// Character requirements
	RequireUppercase    bool `yaml:"require_uppercase" default:"true"`
	RequireLowercase    bool `yaml:"require_lowercase" default:"true"`
	RequireNumbers      bool `yaml:"require_numbers" default:"true"`
	RequireSpecialChars bool `yaml:"require_special_chars" default:"true"`

	// Security requirements
	ForbidCommonPasswords bool `yaml:"forbid_common_passwords" default:"true"`
	ForbidUserInfo        bool `yaml:"forbid_user_info" default:"true"`
	ForbidRepeating       bool `yaml:"forbid_repeating" default:"true"`
	MaxRepeatingChars     int  `yaml:"max_repeating_chars" default:"3"`

	// History and expiration
	PasswordHistoryCount int           `yaml:"password_history_count" default:"12"`
	PasswordMaxAge       time.Duration `yaml:"password_max_age" default:"90d"`
	PasswordMinAge       time.Duration `yaml:"password_min_age" default:"24h"`

	// Reset tokens
	ResetTokenTTL    time.Duration `yaml:"reset_token_ttl" default:"1h"`
	MaxResetAttempts int           `yaml:"max_reset_attempts" default:"3"`

	// Notifications
	NotifyPasswordChange bool `yaml:"notify_password_change" default:"true"`
	NotifyPasswordReset  bool `yaml:"notify_password_reset" default:"true"`
	WarnBeforeExpiry     bool `yaml:"warn_before_expiry" default:"true"`
	WarningDays          int  `yaml:"warning_days" default:"7"`
}

// PasswordHistoryStore interface for password history management
type PasswordHistoryStore interface {
	AddPasswordHash(ctx context.Context, userID, tenantID uuid.UUID, passwordHash string) error
	CheckPasswordHistory(ctx context.Context, userID, tenantID uuid.UUID, passwordHash string, count int) (bool, error)
	CleanupOldHistory(ctx context.Context, userID, tenantID uuid.UUID, keepCount int) error
}

// PasswordValidationResult contains password validation results
type PasswordValidationResult struct {
	Valid       bool
	Score       int
	Violations  []string
	Suggestions []string
}

// PasswordStrengthScore represents password strength levels
type PasswordStrengthScore int

const (
	PasswordWeak PasswordStrengthScore = iota
	PasswordFair
	PasswordGood
	PasswordStrong
	PasswordVeryStrong
)

// NewPasswordService creates a new password service
func NewPasswordService(
	userRepo *postgres.UserRepository,
	auditRepo *postgres.AuditRepository,
	emailService EmailService,
	authService *AuthenticationServiceImpl,
	passwordHistory PasswordHistoryStore,
	config *PasswordConfig,
) *PasswordServiceImpl {
	ps := &PasswordServiceImpl{
		userRepo:        userRepo,
		auditRepo:       auditRepo,
		emailService:    emailService,
		authService:     authService,
		passwordHistory: passwordHistory,
		config:          config,
		commonPasswords: make(map[string]bool),
	}

	// Load common passwords list
	ps.loadCommonPasswords()

	return ps
}

// ChangePassword implements secure password change with validation
func (p *PasswordServiceImpl) ChangePassword(ctx context.Context, req *service.PasswordChangeRequest) error {
	// Step 1: Validate current password
	user, err := p.userRepo.GetByID(ctx, req.UserID, req.TenantID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if !user.IsActive() {
		return fmt.Errorf("user account is not active")
	}

	// Verify current password
	valid, err := p.authService.verifyPassword(req.CurrentPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("password verification failed: %w", err)
	}
	if !valid {
		p.logPasswordChangeAttempt(ctx, user, false, "Invalid current password")
		return fmt.Errorf("current password is incorrect")
	}

	// Step 2: Check minimum password age
	if p.config.PasswordMinAge > 0 {
		timeSinceChange := time.Since(user.PasswordChangedAt)
		if timeSinceChange < p.config.PasswordMinAge {
			return fmt.Errorf("password can only be changed once every %v", p.config.PasswordMinAge)
		}
	}

	// Step 3: Validate new password
	validation := p.ValidatePasswordStrength(ctx, req.NewPassword, user)
	if !validation.Valid {
		p.logPasswordChangeAttempt(ctx, user, false, strings.Join(validation.Violations, "; "))
		return fmt.Errorf("password validation failed: %v", strings.Join(validation.Violations, ", "))
	}

	// Step 4: Check password history
	if p.config.PasswordHistoryCount > 0 {
		newHash, err := p.authService.hashPassword(req.NewPassword)
		if err != nil {
			return fmt.Errorf("password hashing failed: %w", err)
		}

		inHistory, err := p.passwordHistory.CheckPasswordHistory(ctx, user.ID, user.TenantID, newHash, p.config.PasswordHistoryCount)
		if err != nil {
			return fmt.Errorf("password history check failed: %w", err)
		}
		if inHistory {
			p.logPasswordChangeAttempt(ctx, user, false, "Password was used recently")
			return fmt.Errorf("password was used recently, please choose a different password")
		}
	}

	// Step 5: Update password
	newHash, err := p.authService.hashPassword(req.NewPassword)
	if err != nil {
		return fmt.Errorf("password hashing failed: %w", err)
	}

	err = p.userRepo.UpdatePasswordHash(ctx, user.ID, user.TenantID, newHash)
	if err != nil {
		return fmt.Errorf("password update failed: %w", err)
	}

	// Step 6: Add to password history
	if p.config.PasswordHistoryCount > 0 {
		err = p.passwordHistory.AddPasswordHash(ctx, user.ID, user.TenantID, user.PasswordHash)
		if err != nil {
			// Log error but don't fail the operation
			p.logPasswordChangeAttempt(ctx, user, true, "Password updated but history update failed")
		}

		// Cleanup old history
		p.passwordHistory.CleanupOldHistory(ctx, user.ID, user.TenantID, p.config.PasswordHistoryCount)
	}

	// Step 7: Invalidate all sessions (force re-login)
	err = p.authService.LogoutAll(ctx, user.ID, user.TenantID)
	if err != nil {
		// Log error but don't fail the operation
		p.logPasswordChangeAttempt(ctx, user, true, "Password updated but session cleanup failed")
	}

	// Step 8: Log successful password change
	p.logPasswordChangeAttempt(ctx, user, true, "Password changed successfully")

	// Step 9: Send notification
	if p.config.NotifyPasswordChange {
		go p.emailService.SendPasswordChangeNotification(ctx, user)
	}

	return nil
}

// ValidatePasswordStrength validates password against security policies
func (p *PasswordServiceImpl) ValidatePasswordStrength(ctx context.Context, password string, user *entity.User) *PasswordValidationResult {
	result := &PasswordValidationResult{
		Valid:       true,
		Score:       0,
		Violations:  make([]string, 0),
		Suggestions: make([]string, 0),
	}

	// Check length requirements
	if len(password) < p.config.MinLength {
		result.Valid = false
		result.Violations = append(result.Violations, fmt.Sprintf("Password must be at least %d characters long", p.config.MinLength))
		result.Suggestions = append(result.Suggestions, "Use a longer password")
	} else {
		result.Score += 10
	}

	if len(password) > p.config.MaxLength {
		result.Valid = false
		result.Violations = append(result.Violations, fmt.Sprintf("Password must not exceed %d characters", p.config.MaxLength))
	}

	// Check character requirements
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)

	if p.config.RequireUppercase && !hasUpper {
		result.Valid = false
		result.Violations = append(result.Violations, "Password must contain uppercase letters")
		result.Suggestions = append(result.Suggestions, "Add uppercase letters")
	} else if hasUpper {
		result.Score += 10
	}

	if p.config.RequireLowercase && !hasLower {
		result.Valid = false
		result.Violations = append(result.Violations, "Password must contain lowercase letters")
		result.Suggestions = append(result.Suggestions, "Add lowercase letters")
	} else if hasLower {
		result.Score += 10
	}

	if p.config.RequireNumbers && !hasNumber {
		result.Valid = false
		result.Violations = append(result.Violations, "Password must contain numbers")
		result.Suggestions = append(result.Suggestions, "Add numbers")
	} else if hasNumber {
		result.Score += 10
	}

	if p.config.RequireSpecialChars && !hasSpecial {
		result.Valid = false
		result.Violations = append(result.Violations, "Password must contain special characters")
		result.Suggestions = append(result.Suggestions, "Add special characters (!@#$%^&*)")
	} else if hasSpecial {
		result.Score += 15
	}

	// Check for common passwords
	if p.config.ForbidCommonPasswords && p.isCommonPassword(password) {
		result.Valid = false
		result.Violations = append(result.Violations, "Password is too common")
		result.Suggestions = append(result.Suggestions, "Choose a more unique password")
	} else {
		result.Score += 15
	}

	// Check for user information
	if p.config.ForbidUserInfo && user != nil {
		if p.containsUserInfo(password, user) {
			result.Valid = false
			result.Violations = append(result.Violations, "Password must not contain personal information")
			result.Suggestions = append(result.Suggestions, "Avoid using your name, email, or username")
		} else {
			result.Score += 10
		}
	}

	// Check for repeating characters
	if p.config.ForbidRepeating && p.hasRepeatingCharacters(password, p.config.MaxRepeatingChars) {
		result.Valid = false
		result.Violations = append(result.Violations, fmt.Sprintf("Password must not have more than %d repeating characters", p.config.MaxRepeatingChars))
		result.Suggestions = append(result.Suggestions, "Avoid repeating characters")
	} else {
		result.Score += 5
	}

	// Additional strength scoring
	if len(password) >= 16 {
		result.Score += 10
	}
	if len(password) >= 20 {
		result.Score += 5
	}

	// Entropy-based scoring
	entropy := p.calculateEntropy(password)
	if entropy >= 60 {
		result.Score += 15
	} else if entropy >= 40 {
		result.Score += 10
	} else if entropy >= 30 {
		result.Score += 5
	}

	// Adjust score based on violations
	if len(result.Violations) > 0 {
		result.Score = max(0, result.Score-len(result.Violations)*10)
	}

	return result
}

// ResetPassword initiates password reset process
func (p *PasswordServiceImpl) ResetPassword(ctx context.Context, email string, tenantID uuid.UUID) error {
	// Find user by email
	user, err := p.userRepo.GetByEmail(ctx, email, tenantID)
	if err != nil {
		// Don't reveal if email exists for security
		p.logPasswordResetAttempt(ctx, nil, email, false, "Email not found")
		return nil // Return success to prevent email enumeration
	}

	if !user.IsActive() {
		p.logPasswordResetAttempt(ctx, user, email, false, "Account inactive")
		return fmt.Errorf("account is not active")
	}

	// Generate reset token
	token, err := p.generateResetToken()
	if err != nil {
		return fmt.Errorf("token generation failed: %w", err)
	}

	// Store reset token (implementation depends on token storage strategy)
	err = p.storeResetToken(ctx, user.ID, user.TenantID, token)
	if err != nil {
		return fmt.Errorf("token storage failed: %w", err)
	}

	// Send reset email
	if p.config.NotifyPasswordReset {
		err = p.emailService.SendPasswordResetEmail(ctx, user, token)
		if err != nil {
			p.logPasswordResetAttempt(ctx, user, email, false, "Email sending failed")
			return fmt.Errorf("failed to send reset email: %w", err)
		}
	}

	p.logPasswordResetAttempt(ctx, user, email, true, "Reset token sent")
	return nil
}

// CompletePasswordReset completes the password reset process
func (p *PasswordServiceImpl) CompletePasswordReset(ctx context.Context, token, newPassword string) error {
	// Validate and consume reset token
	userID, tenantID, err := p.validateAndConsumeResetToken(ctx, token)
	if err != nil {
		return fmt.Errorf("invalid or expired token: %w", err)
	}

	// Get user
	user, err := p.userRepo.GetByID(ctx, userID, tenantID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Validate new password
	validation := p.ValidatePasswordStrength(ctx, newPassword, user)
	if !validation.Valid {
		return fmt.Errorf("password validation failed: %v", strings.Join(validation.Violations, ", "))
	}

	// Update password
	newHash, err := p.authService.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("password hashing failed: %w", err)
	}

	err = p.userRepo.UpdatePasswordHash(ctx, user.ID, user.TenantID, newHash)
	if err != nil {
		return fmt.Errorf("password update failed: %w", err)
	}

	// Reset failed attempts
	err = p.userRepo.ResetFailedAttempts(ctx, user.ID, user.TenantID)
	if err != nil {
		// Log but don't fail
		p.logPasswordResetCompletion(ctx, user, false, "Password reset but failed attempts not cleared")
	}

	// Invalidate all sessions
	p.authService.LogoutAll(ctx, user.ID, user.TenantID)

	// Log successful reset
	p.logPasswordResetCompletion(ctx, user, true, "Password reset completed")

	return nil
}

// Helper methods

func (p *PasswordServiceImpl) isCommonPassword(password string) bool {
	return p.commonPasswords[strings.ToLower(password)]
}

func (p *PasswordServiceImpl) containsUserInfo(password string, user *entity.User) bool {
	password = strings.ToLower(password)

	// Check against username
	if strings.Contains(password, strings.ToLower(user.Username)) {
		return true
	}

	// Check against email parts
	emailParts := strings.Split(strings.ToLower(user.Email), "@")
	if len(emailParts) > 0 && strings.Contains(password, emailParts[0]) {
		return true
	}

	// Check against first name
	if strings.Contains(password, strings.ToLower(user.FirstName)) {
		return true
	}

	// Check against last name
	if strings.Contains(password, strings.ToLower(user.LastName)) {
		return true
	}

	return false
}

func (p *PasswordServiceImpl) hasRepeatingCharacters(password string, maxRepeating int) bool {
	if maxRepeating <= 0 {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count > maxRepeating {
				return true
			}
		} else {
			count = 1
		}
	}

	return false
}

func (p *PasswordServiceImpl) calculateEntropy(password string) float64 {
	// Character set sizes
	var charsetSize float64

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigits := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password)

	if hasLower {
		charsetSize += 26
	}
	if hasUpper {
		charsetSize += 26
	}
	if hasDigits {
		charsetSize += 10
	}
	if hasSpecial {
		charsetSize += 32 // Common special characters
	}

	if charsetSize == 0 {
		return 0
	}

	// Calculate entropy: log2(charset^length)
	return float64(len(password)) * log2(charsetSize)
}

func log2(x float64) float64 {
	return math.Log(x) / math.Log(2)
}

func (p *PasswordServiceImpl) generateResetToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (p *PasswordServiceImpl) loadCommonPasswords() {
	// Load common passwords from a list
	// This would typically be loaded from a file or database
	commonList := []string{
		"password", "123456", "123456789", "12345678", "12345",
		"qwerty", "abc123", "password123", "admin", "letmein",
		"welcome", "monkey", "1234567890", "dragon", "princess",
		// Add more common passwords...
	}

	for _, pwd := range commonList {
		p.commonPasswords[pwd] = true
	}
}

// Placeholder implementations for token management and logging
func (p *PasswordServiceImpl) storeResetToken(ctx context.Context, userID, tenantID uuid.UUID, token string) error {
	// Implementation would store token in database with expiration
	return nil
}

func (p *PasswordServiceImpl) validateAndConsumeResetToken(ctx context.Context, token string) (uuid.UUID, uuid.UUID, error) {
	// Implementation would validate token and mark as used
	return uuid.New(), uuid.New(), nil
}

func (p *PasswordServiceImpl) logPasswordChangeAttempt(ctx context.Context, user *entity.User, success bool, details string) {
	// Implementation for audit logging
}

func (p *PasswordServiceImpl) logPasswordResetAttempt(ctx context.Context, user *entity.User, email string, success bool, details string) {
	// Implementation for audit logging
}

func (p *PasswordServiceImpl) logPasswordResetCompletion(ctx context.Context, user *entity.User, success bool, details string) {
	// Implementation for audit logging
}

// Additional email service methods needed
type EmailServiceExtended interface {
	EmailService
	SendPasswordChangeNotification(ctx context.Context, user *entity.User) error
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
