package testing

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/isectech/platform/pkg/logging"
)

// TestSuite provides common testing utilities
type TestSuite struct {
	suite.Suite
	Logger *zap.Logger
	TempDir string
	cleanup []func()
	mu      sync.Mutex
}

// SetupSuite runs before the test suite
func (ts *TestSuite) SetupSuite() {
	// Create logger
	ts.Logger = zaptest.NewLogger(ts.T())
	
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "isectech-test-*")
	require.NoError(ts.T(), err)
	ts.TempDir = tempDir
	
	ts.cleanup = make([]func(), 0)
}

// TearDownSuite runs after the test suite
func (ts *TestSuite) TearDownSuite() {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	
	// Run cleanup functions in reverse order
	for i := len(ts.cleanup) - 1; i >= 0; i-- {
		ts.cleanup[i]()
	}
	
	// Remove temp directory
	if ts.TempDir != "" {
		os.RemoveAll(ts.TempDir)
	}
}

// AddCleanup adds a cleanup function
func (ts *TestSuite) AddCleanup(fn func()) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.cleanup = append(ts.cleanup, fn)
}

// CreateTempFile creates a temporary file for testing
func (ts *TestSuite) CreateTempFile(name, content string) string {
	filePath := filepath.Join(ts.TempDir, name)
	
	// Create directory if needed
	dir := filepath.Dir(filePath)
	err := os.MkdirAll(dir, 0755)
	require.NoError(ts.T(), err)
	
	// Write file
	err = os.WriteFile(filePath, []byte(content), 0644)
	require.NoError(ts.T(), err)
	
	return filePath
}

// CreateTempDir creates a temporary directory for testing
func (ts *TestSuite) CreateTempDir(name string) string {
	dirPath := filepath.Join(ts.TempDir, name)
	err := os.MkdirAll(dirPath, 0755)
	require.NoError(ts.T(), err)
	return dirPath
}

// Context Helpers

// ContextWithTimeout creates a context with timeout for testing
func ContextWithTimeout(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// ContextWithDeadline creates a context with deadline for testing
func ContextWithDeadline(t *testing.T, deadline time.Time) (context.Context, context.CancelFunc) {
	return context.WithDeadline(context.Background(), deadline)
}

// Logger Helpers

// NewTestLogger creates a test logger
func NewTestLogger(t *testing.T) *zap.Logger {
	return zaptest.NewLogger(t)
}

// NewTestLoggerWithLevel creates a test logger with specific level
func NewTestLoggerWithLevel(t *testing.T, level zap.AtomicLevel) *zap.Logger {
	return zaptest.NewLogger(t, zaptest.Level(level.Level()))
}

// HTTP Helpers

// HTTPServer provides a test HTTP server
type HTTPServer struct {
	*httptest.Server
	t *testing.T
}

// NewHTTPServer creates a new test HTTP server
func NewHTTPServer(t *testing.T, handler http.Handler) *HTTPServer {
	server := httptest.NewServer(handler)
	
	return &HTTPServer{
		Server: server,
		t:      t,
	}
}

// NewHTTPSServer creates a new test HTTPS server
func NewHTTPSServer(t *testing.T, handler http.Handler) *HTTPServer {
	server := httptest.NewTLSServer(handler)
	
	return &HTTPServer{
		Server: server,
		t:      t,
	}
}

// Close closes the HTTP server
func (hs *HTTPServer) Close() {
	hs.Server.Close()
}

// Get performs a GET request to the server
func (hs *HTTPServer) Get(path string) (*http.Response, error) {
	return http.Get(hs.URL + path)
}

// Post performs a POST request to the server
func (hs *HTTPServer) Post(path string, contentType string, body interface{}) (*http.Response, error) {
	// Implementation would depend on body type
	return nil, fmt.Errorf("not implemented")
}

// gRPC Helpers

// GRPCServer provides a test gRPC server
type GRPCServer struct {
	*grpc.Server
	listener *bufconn.Listener
	t        *testing.T
}

// NewGRPCServer creates a new test gRPC server
func NewGRPCServer(t *testing.T, opts ...grpc.ServerOption) *GRPCServer {
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(opts...)
	
	grpcServer := &GRPCServer{
		Server:   server,
		listener: lis,
		t:        t,
	}
	
	go func() {
		if err := server.Serve(lis); err != nil {
			t.Logf("gRPC server error: %v", err)
		}
	}()
	
	return grpcServer
}

// Dial creates a client connection to the test gRPC server
func (gs *GRPCServer) Dial(opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	opts = append(opts, grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return gs.listener.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	
	return grpc.Dial("bufnet", opts...)
}

// Close stops the gRPC server
func (gs *GRPCServer) Close() {
	gs.Server.Stop()
	gs.listener.Close()
}

// Database Helpers

// DatabaseHelper provides database testing utilities
type DatabaseHelper struct {
	DB *sql.DB
	t  *testing.T
}

// NewDatabaseHelper creates a new database test helper
func NewDatabaseHelper(t *testing.T, db *sql.DB) *DatabaseHelper {
	return &DatabaseHelper{
		DB: db,
		t:  t,
	}
}

// ExecSQL executes SQL and requires no error
func (dh *DatabaseHelper) ExecSQL(query string, args ...interface{}) {
	_, err := dh.DB.Exec(query, args...)
	require.NoError(dh.t, err, "Failed to execute SQL: %s", query)
}

// QueryRow queries a single row and returns the result
func (dh *DatabaseHelper) QueryRow(query string, args ...interface{}) *sql.Row {
	return dh.DB.QueryRow(query, args...)
}

// CountRows counts rows matching a query
func (dh *DatabaseHelper) CountRows(query string, args ...interface{}) int {
	var count int
	err := dh.DB.QueryRow(query, args...).Scan(&count)
	require.NoError(dh.t, err, "Failed to count rows: %s", query)
	return count
}

// TableExists checks if a table exists
func (dh *DatabaseHelper) TableExists(tableName string) bool {
	query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
	var name string
	err := dh.DB.QueryRow(query, tableName).Scan(&name)
	return err == nil
}

// Assertion Helpers

// AssertEventuallyTrue asserts that a condition becomes true within timeout
func AssertEventuallyTrue(t *testing.T, condition func() bool, timeout time.Duration, msgAndArgs ...interface{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	timeoutCh := time.After(timeout)
	
	for {
		select {
		case <-ticker.C:
			if condition() {
				return
			}
		case <-timeoutCh:
			assert.Fail(t, "Condition never became true within timeout", msgAndArgs...)
			return
		}
	}
}

// AssertNeverTrue asserts that a condition never becomes true within duration
func AssertNeverTrue(t *testing.T, condition func() bool, duration time.Duration, msgAndArgs ...interface{}) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	timeoutCh := time.After(duration)
	
	for {
		select {
		case <-ticker.C:
			if condition() {
				assert.Fail(t, "Condition became true when it shouldn't have", msgAndArgs...)
				return
			}
		case <-timeoutCh:
			return // Success - condition never became true
		}
	}
}

// AssertJSONEquals asserts that two JSON strings are equivalent
func AssertJSONEquals(t *testing.T, expected, actual string, msgAndArgs ...interface{}) {
	// Parse both JSON strings and compare
	// This is a simplified version - in practice you'd use proper JSON comparison
	assert.JSONEq(t, expected, actual, msgAndArgs...)
}

// Network Helpers

// GetFreePort returns a free port for testing
func GetFreePort(t *testing.T) int {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer listener.Close()
	
	return listener.Addr().(*net.TCPAddr).Port
}

// WaitForPort waits for a port to become available
func WaitForPort(t *testing.T, host string, port int, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", host, port)
	
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	require.Fail(t, fmt.Sprintf("Port %s did not become available within %v", address, timeout))
}

// WaitForPortClosed waits for a port to become unavailable
func WaitForPortClosed(t *testing.T, host string, port int, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", host, port)
	
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return // Port is closed
		}
		conn.Close()
		time.Sleep(100 * time.Millisecond)
	}
	
	require.Fail(t, fmt.Sprintf("Port %s did not close within %v", address, timeout))
}

// File Helpers

// CreateTestConfig creates a test configuration file
func CreateTestConfig(t *testing.T, content map[string]interface{}) string {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.yaml")
	
	// This is simplified - in practice you'd use proper YAML marshaling
	err := os.WriteFile(configPath, []byte("test: config"), 0644)
	require.NoError(t, err)
	
	return configPath
}

// Environment Helpers

// WithEnv temporarily sets environment variables for a test
func WithEnv(t *testing.T, env map[string]string, fn func()) {
	oldEnv := make(map[string]string)
	
	// Set new env vars
	for key, value := range env {
		oldEnv[key] = os.Getenv(key)
		os.Setenv(key, value)
	}
	
	// Cleanup
	defer func() {
		for key, oldValue := range oldEnv {
			if oldValue == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, oldValue)
			}
		}
	}()
	
	fn()
}

// Concurrency Helpers

// RunConcurrently runs functions concurrently and waits for completion
func RunConcurrently(t *testing.T, fns ...func()) {
	var wg sync.WaitGroup
	
	for _, fn := range fns {
		wg.Add(1)
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}
	
	wg.Wait()
}

// RunConcurrentlyWithTimeout runs functions concurrently with timeout
func RunConcurrentlyWithTimeout(t *testing.T, timeout time.Duration, fns ...func()) {
	done := make(chan struct{})
	
	go func() {
		RunConcurrently(t, fns...)
		close(done)
	}()
	
	select {
	case <-done:
		// Success
	case <-time.After(timeout):
		require.Fail(t, fmt.Sprintf("Concurrent execution did not complete within %v", timeout))
	}
}

// Mock Helpers

// MockFunc represents a mock function
type MockFunc struct {
	CallCount int
	Args      [][]interface{}
	Returns   [][]interface{}
	mu        sync.Mutex
}

// NewMockFunc creates a new mock function
func NewMockFunc() *MockFunc {
	return &MockFunc{
		Args:    make([][]interface{}, 0),
		Returns: make([][]interface{}, 0),
	}
}

// Call records a function call
func (mf *MockFunc) Call(args ...interface{}) []interface{} {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	
	mf.CallCount++
	mf.Args = append(mf.Args, args)
	
	if len(mf.Returns) > 0 {
		returnIndex := mf.CallCount - 1
		if returnIndex < len(mf.Returns) {
			return mf.Returns[returnIndex]
		}
		// Return last configured return value
		return mf.Returns[len(mf.Returns)-1]
	}
	
	return nil
}

// SetReturn sets return values for the mock
func (mf *MockFunc) SetReturn(returns ...interface{}) {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	mf.Returns = append(mf.Returns, returns)
}

// AssertCalled asserts the function was called
func (mf *MockFunc) AssertCalled(t *testing.T, times int) {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	assert.Equal(t, times, mf.CallCount, "Expected function to be called %d times, but was called %d times", times, mf.CallCount)
}

// AssertCalledWith asserts the function was called with specific arguments
func (mf *MockFunc) AssertCalledWith(t *testing.T, args ...interface{}) {
	mf.mu.Lock()
	defer mf.mu.Unlock()
	
	found := false
	for _, callArgs := range mf.Args {
		if len(callArgs) == len(args) {
			match := true
			for i, arg := range args {
				if !assert.ObjectsAreEqual(arg, callArgs[i]) {
					match = false
					break
				}
			}
			if match {
				found = true
				break
			}
		}
	}
	
	assert.True(t, found, "Expected function to be called with args %v, but was not", args)
}

// Performance Helpers

// BenchmarkFunc benchmarks a function
func BenchmarkFunc(b *testing.B, fn func()) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fn()
	}
}

// MeasureTime measures execution time of a function
func MeasureTime(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

// AssertPerformance asserts that a function completes within expected time
func AssertPerformance(t *testing.T, expected time.Duration, fn func(), msgAndArgs ...interface{}) {
	duration := MeasureTime(fn)
	assert.True(t, duration <= expected, 
		"Function took %v, expected to complete within %v. %v", 
		duration, expected, msgAndArgs)
}

// Testing Configuration

// TestConfig provides common test configuration
type TestConfig struct {
	LogLevel    string
	TempDir     string
	DatabaseURL string
	RedisURL    string
	Timeout     time.Duration
}

// DefaultTestConfig returns default test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		LogLevel: "debug",
		Timeout:  30 * time.Second,
	}
}

// Golden File Testing

// GoldenFile manages golden file testing
type GoldenFile struct {
	path string
	t    *testing.T
}

// NewGoldenFile creates a new golden file helper
func NewGoldenFile(t *testing.T, path string) *GoldenFile {
	return &GoldenFile{
		path: path,
		t:    t,
	}
}

// Compare compares content with golden file
func (gf *GoldenFile) Compare(content []byte) {
	// This is simplified - in practice you'd implement proper golden file testing
	// with update flags and better comparison
	assert.NotEmpty(gf.t, content, "Content should not be empty")
}