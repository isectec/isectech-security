package common

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// StringUtils provides string utility functions
type StringUtils struct{}

// IsEmpty checks if a string is empty or contains only whitespace
func (StringUtils) IsEmpty(s string) bool {
	return strings.TrimSpace(s) == ""
}

// IsNotEmpty checks if a string is not empty
func (StringUtils) IsNotEmpty(s string) bool {
	return strings.TrimSpace(s) != ""
}

// Truncate truncates a string to a maximum length
func (StringUtils) Truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// ToCamelCase converts a string to camelCase
func (StringUtils) ToCamelCase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	
	words := strings.FieldsFunc(s, func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c)
	})
	
	if len(words) == 0 {
		return ""
	}
	
	result := strings.ToLower(words[0])
	for i := 1; i < len(words); i++ {
		if len(words[i]) > 0 {
			result += strings.ToUpper(words[i][:1]) + strings.ToLower(words[i][1:])
		}
	}
	
	return result
}

// ToSnakeCase converts a string to snake_case
func (StringUtils) ToSnakeCase(s string) string {
	var result strings.Builder
	
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			result.WriteRune('_')
		}
		result.WriteRune(unicode.ToLower(r))
	}
	
	return result.String()
}

// ToKebabCase converts a string to kebab-case
func (StringUtils) ToKebabCase(s string) string {
	return strings.ReplaceAll(StringUtils{}.ToSnakeCase(s), "_", "-")
}

// Contains checks if a slice contains a string (case-sensitive)
func (StringUtils) Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// ContainsIgnoreCase checks if a slice contains a string (case-insensitive)
func (StringUtils) ContainsIgnoreCase(slice []string, item string) bool {
	item = strings.ToLower(item)
	for _, s := range slice {
		if strings.ToLower(s) == item {
			return true
		}
	}
	return false
}

// RemoveDuplicates removes duplicate strings from a slice
func (StringUtils) RemoveDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// Reverse reverses a string
func (StringUtils) Reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

// NumberUtils provides number utility functions
type NumberUtils struct{}

// ToInt converts various types to int
func (NumberUtils) ToInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int8:
		return int(v), nil
	case int16:
		return int(v), nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case uint:
		return int(v), nil
	case uint8:
		return int(v), nil
	case uint16:
		return int(v), nil
	case uint32:
		return int(v), nil
	case uint64:
		return int(v), nil
	case float32:
		return int(v), nil
	case float64:
		return int(v), nil
	case string:
		return strconv.Atoi(v)
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// ToFloat64 converts various types to float64
func (NumberUtils) ToFloat64(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case float32:
		return float64(v), nil
	case int:
		return float64(v), nil
	case int8:
		return float64(v), nil
	case int16:
		return float64(v), nil
	case int32:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case uint:
		return float64(v), nil
	case uint8:
		return float64(v), nil
	case uint16:
		return float64(v), nil
	case uint32:
		return float64(v), nil
	case uint64:
		return float64(v), nil
	case string:
		return strconv.ParseFloat(v, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to float64", value)
	}
}

// Round rounds a float64 to the specified decimal places
func (NumberUtils) Round(value float64, decimals int) float64 {
	ratio := math.Pow(10, float64(decimals))
	return math.Round(value*ratio) / ratio
}

// Min returns the minimum of two integers
func (NumberUtils) Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Max returns the maximum of two integers
func (NumberUtils) Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Clamp clamps a value between min and max
func (NumberUtils) Clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// TimeUtils provides time utility functions
type TimeUtils struct{}

// Now returns the current UTC time
func (TimeUtils) Now() time.Time {
	return time.Now().UTC()
}

// ToISO8601 formats time as ISO 8601 string
func (TimeUtils) ToISO8601(t time.Time) string {
	return t.Format(time.RFC3339)
}

// FromISO8601 parses ISO 8601 string to time
func (TimeUtils) FromISO8601(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// StartOfDay returns the start of the day for the given time
func (TimeUtils) StartOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// EndOfDay returns the end of the day for the given time
func (TimeUtils) EndOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 999999999, t.Location())
}

// DaysAgo returns a time that is the specified number of days ago
func (TimeUtils) DaysAgo(days int) time.Time {
	return TimeUtils{}.Now().AddDate(0, 0, -days)
}

// DaysFromNow returns a time that is the specified number of days from now
func (TimeUtils) DaysFromNow(days int) time.Time {
	return TimeUtils{}.Now().AddDate(0, 0, days)
}

// FormatDuration formats a duration in a human-readable way
func (TimeUtils) FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

// CryptoUtils provides cryptographic utility functions
type CryptoUtils struct{}

// GenerateRandomString generates a random string of the specified length
func (CryptoUtils) GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateRandomBytes generates random bytes
func (CryptoUtils) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// HashSHA256 generates SHA256 hash of input
func (CryptoUtils) HashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// HashSHA256Bytes generates SHA256 hash of byte input
func (CryptoUtils) HashSHA256Bytes(input []byte) string {
	hash := sha256.Sum256(input)
	return hex.EncodeToString(hash[:])
}

// GenerateUUID generates a new UUID
func (CryptoUtils) GenerateUUID() string {
	return uuid.New().String()
}

// ValidateUUID validates a UUID string
func (CryptoUtils) ValidateUUID(uuidStr string) bool {
	_, err := uuid.Parse(uuidStr)
	return err == nil
}

// JSONUtils provides JSON utility functions
type JSONUtils struct{}

// Marshal marshals an object to JSON string
func (JSONUtils) Marshal(v interface{}) (string, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// MarshalIndent marshals an object to indented JSON string
func (JSONUtils) MarshalIndent(v interface{}) (string, error) {
	bytes, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Unmarshal unmarshals JSON string to object
func (JSONUtils) Unmarshal(jsonStr string, v interface{}) error {
	return json.Unmarshal([]byte(jsonStr), v)
}

// IsValidJSON checks if a string is valid JSON
func (JSONUtils) IsValidJSON(jsonStr string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(jsonStr), &js) == nil
}

// ToMap converts a struct to map[string]interface{}
func (JSONUtils) ToMap(v interface{}) (map[string]interface{}, error) {
	jsonStr, err := JSONUtils{}.Marshal(v)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	err = JSONUtils{}.Unmarshal(jsonStr, &result)
	return result, err
}

// FromMap converts map[string]interface{} to struct
func (JSONUtils) FromMap(m map[string]interface{}, v interface{}) error {
	jsonStr, err := JSONUtils{}.Marshal(m)
	if err != nil {
		return err
	}
	return JSONUtils{}.Unmarshal(jsonStr, v)
}

// ValidationUtils provides validation utility functions
type ValidationUtils struct{}

// IsValidEmail validates email format
func (ValidationUtils) IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// IsValidIP validates IP address format
func (ValidationUtils) IsValidIP(ip string) bool {
	ipRegex := regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	return ipRegex.MatchString(ip)
}

// IsValidURL validates URL format
func (ValidationUtils) IsValidURL(url string) bool {
	urlRegex := regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)
	return urlRegex.MatchString(url)
}

// IsValidPhone validates phone number format (basic)
func (ValidationUtils) IsValidPhone(phone string) bool {
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	return phoneRegex.MatchString(phone)
}

// IsStrongPassword validates password strength
func (ValidationUtils) IsStrongPassword(password string) bool {
	if len(password) < 8 {
		return false
	}
	
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	
	return hasUpper && hasLower && hasDigit && hasSpecial
}

// SliceUtils provides slice utility functions
type SliceUtils struct{}

// Contains checks if a slice contains an element
func (SliceUtils) Contains(slice interface{}, item interface{}) bool {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		return false
	}
	
	for i := 0; i < s.Len(); i++ {
		if reflect.DeepEqual(s.Index(i).Interface(), item) {
			return true
		}
	}
	
	return false
}

// Unique removes duplicates from a slice
func (SliceUtils) Unique(slice interface{}) interface{} {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		return slice
	}
	
	uniqueMap := make(map[interface{}]bool)
	result := reflect.MakeSlice(s.Type(), 0, s.Len())
	
	for i := 0; i < s.Len(); i++ {
		item := s.Index(i).Interface()
		if !uniqueMap[item] {
			uniqueMap[item] = true
			result = reflect.Append(result, s.Index(i))
		}
	}
	
	return result.Interface()
}

// Chunk splits a slice into chunks of the specified size
func (SliceUtils) Chunk(slice interface{}, size int) interface{} {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice || size <= 0 {
		return slice
	}
	
	length := s.Len()
	chunksCount := (length + size - 1) / size
	chunkType := reflect.SliceOf(s.Type())
	chunks := reflect.MakeSlice(chunkType, 0, chunksCount)
	
	for i := 0; i < length; i += size {
		end := i + size
		if end > length {
			end = length
		}
		chunk := s.Slice(i, end)
		chunks = reflect.Append(chunks, chunk)
	}
	
	return chunks.Interface()
}

// Global utility instances for easy access
var (
	Strings    = StringUtils{}
	Numbers    = NumberUtils{}
	Times      = TimeUtils{}
	Crypto     = CryptoUtils{}
	JSON       = JSONUtils{}
	Validation = ValidationUtils{}
	Slices     = SliceUtils{}
)

// Pointer utility functions

// StringPtr returns a pointer to a string
func StringPtr(s string) *string {
	return &s
}

// IntPtr returns a pointer to an int
func IntPtr(i int) *int {
	return &i
}

// BoolPtr returns a pointer to a bool
func BoolPtr(b bool) *bool {
	return &b
}

// TimePtr returns a pointer to a time
func TimePtr(t time.Time) *time.Time {
	return &t
}

// StringValue returns the value of a string pointer or empty string if nil
func StringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// IntValue returns the value of an int pointer or 0 if nil
func IntValue(i *int) int {
	if i == nil {
		return 0
	}
	return *i
}

// BoolValue returns the value of a bool pointer or false if nil
func BoolValue(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// TimeValue returns the value of a time pointer or zero time if nil
func TimeValue(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// Conditional returns one of two values based on a condition
func Conditional[T any](condition bool, trueValue, falseValue T) T {
	if condition {
		return trueValue
	}
	return falseValue
}

// Coalesce returns the first non-zero value
func Coalesce[T comparable](values ...T) T {
	var zero T
	for _, v := range values {
		if v != zero {
			return v
		}
	}
	return zero
}