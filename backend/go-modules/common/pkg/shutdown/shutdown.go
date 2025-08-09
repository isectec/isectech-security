package shutdown

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// GracefulShutdown manages graceful shutdown of services
type GracefulShutdown struct {
	timeout   time.Duration
	logger    *zap.Logger
	hooks     []Hook
	done      chan struct{}
	mu        sync.RWMutex
	shutdown  bool
	wg        sync.WaitGroup
}

// Hook represents a function to be called during shutdown
type Hook struct {
	Name     string
	Priority int // Lower numbers run first
	Timeout  time.Duration
	Fn       func(context.Context) error
}

// Config represents graceful shutdown configuration
type Config struct {
	Timeout time.Duration `yaml:"timeout" json:"timeout"`
	Signals []os.Signal   `yaml:"-" json:"-"` // Not serializable
}

// New creates a new graceful shutdown manager
func New(config *Config, logger *zap.Logger) *GracefulShutdown {
	if config == nil {
		config = &Config{
			Timeout: 30 * time.Second,
			Signals: []os.Signal{syscall.SIGTERM, syscall.SIGINT},
		}
	}
	
	if logger == nil {
		logger = zap.NewNop()
	}

	return &GracefulShutdown{
		timeout: config.Timeout,
		logger:  logger,
		hooks:   make([]Hook, 0),
		done:    make(chan struct{}),
	}
}

// AddHook adds a shutdown hook with priority and timeout
func (gs *GracefulShutdown) AddHook(hook Hook) {
	gs.mu.Lock()
	defer gs.mu.Unlock()

	if hook.Timeout == 0 {
		hook.Timeout = gs.timeout
	}

	// Insert hook in priority order (lower priority runs first)
	inserted := false
	for i, h := range gs.hooks {
		if hook.Priority < h.Priority {
			gs.hooks = append(gs.hooks[:i], append([]Hook{hook}, gs.hooks[i:]...)...)
			inserted = true
			break
		}
	}
	
	if !inserted {
		gs.hooks = append(gs.hooks, hook)
	}

	gs.logger.Debug("Shutdown hook added",
		zap.String("name", hook.Name),
		zap.Int("priority", hook.Priority),
		zap.Duration("timeout", hook.Timeout),
	)
}

// AddHooks adds multiple shutdown hooks
func (gs *GracefulShutdown) AddHooks(hooks ...Hook) {
	for _, hook := range hooks {
		gs.AddHook(hook)
	}
}

// Listen starts listening for shutdown signals
func (gs *GracefulShutdown) Listen(signals ...os.Signal) {
	if len(signals) == 0 {
		signals = []os.Signal{syscall.SIGTERM, syscall.SIGINT}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, signals...)

	gs.wg.Add(1)
	go func() {
		defer gs.wg.Done()
		
		sig := <-c
		gs.logger.Info("Shutdown signal received", zap.String("signal", sig.String()))
		
		gs.mu.Lock()
		if gs.shutdown {
			gs.mu.Unlock()
			gs.logger.Warn("Shutdown already in progress")
			return
		}
		gs.shutdown = true
		gs.mu.Unlock()

		gs.executeShutdown()
	}()
}

// Shutdown triggers graceful shutdown programmatically
func (gs *GracefulShutdown) Shutdown() {
	gs.mu.Lock()
	if gs.shutdown {
		gs.mu.Unlock()
		return
	}
	gs.shutdown = true
	gs.mu.Unlock()

	gs.logger.Info("Programmatic shutdown initiated")
	gs.executeShutdown()
}

// executeShutdown executes all shutdown hooks
func (gs *GracefulShutdown) executeShutdown() {
	defer close(gs.done)

	ctx, cancel := context.WithTimeout(context.Background(), gs.timeout)
	defer cancel()

	gs.logger.Info("Starting graceful shutdown", 
		zap.Duration("timeout", gs.timeout),
		zap.Int("hooks", len(gs.hooks)),
	)

	start := time.Now()
	for _, hook := range gs.hooks {
		gs.executeHook(ctx, hook)
	}

	gs.logger.Info("Graceful shutdown completed", 
		zap.Duration("duration", time.Since(start)),
	)
}

// executeHook executes a single shutdown hook
func (gs *GracefulShutdown) executeHook(ctx context.Context, hook Hook) {
	hookCtx, cancel := context.WithTimeout(ctx, hook.Timeout)
	defer cancel()

	start := time.Now()
	gs.logger.Info("Executing shutdown hook", 
		zap.String("name", hook.Name),
		zap.Duration("timeout", hook.Timeout),
	)

	done := make(chan error, 1)
	go func() {
		done <- hook.Fn(hookCtx)
	}()

	select {
	case err := <-done:
		duration := time.Since(start)
		if err != nil {
			gs.logger.Error("Shutdown hook failed",
				zap.String("name", hook.Name),
				zap.Duration("duration", duration),
				zap.Error(err),
			)
		} else {
			gs.logger.Info("Shutdown hook completed",
				zap.String("name", hook.Name),
				zap.Duration("duration", duration),
			)
		}
	case <-hookCtx.Done():
		gs.logger.Warn("Shutdown hook timed out",
			zap.String("name", hook.Name),
			zap.Duration("timeout", hook.Timeout),
		)
	}
}

// Wait waits for shutdown to complete
func (gs *GracefulShutdown) Wait() {
	<-gs.done
}

// WaitWithTimeout waits for shutdown to complete with a timeout
func (gs *GracefulShutdown) WaitWithTimeout(timeout time.Duration) error {
	select {
	case <-gs.done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("shutdown wait timeout after %v", timeout)
	}
}

// IsShuttingDown returns true if shutdown is in progress
func (gs *GracefulShutdown) IsShuttingDown() bool {
	gs.mu.RLock()
	defer gs.mu.RUnlock()
	return gs.shutdown
}

// Done returns a channel that closes when shutdown is complete
func (gs *GracefulShutdown) Done() <-chan struct{} {
	return gs.done
}

// Stop stops listening for signals and waits for current operations
func (gs *GracefulShutdown) Stop() {
	signal.Stop(make(chan os.Signal, 1))
	gs.wg.Wait()
}

// Manager is a global shutdown manager
var globalManager *GracefulShutdown
var globalOnce sync.Once

// InitGlobal initializes the global shutdown manager
func InitGlobal(config *Config, logger *zap.Logger) {
	globalOnce.Do(func() {
		globalManager = New(config, logger)
	})
}

// GetGlobal returns the global shutdown manager
func GetGlobal() *GracefulShutdown {
	if globalManager == nil {
		InitGlobal(nil, nil)
	}
	return globalManager
}

// Common Hook Factories

// HTTPServerHook creates a shutdown hook for HTTP servers
func HTTPServerHook(name string, server interface{ Shutdown(context.Context) error }) Hook {
	return Hook{
		Name:     name,
		Priority: 10, // HTTP servers should shutdown early
		Timeout:  30 * time.Second,
		Fn: func(ctx context.Context) error {
			return server.Shutdown(ctx)
		},
	}
}

// GRPCServerHook creates a shutdown hook for gRPC servers
func GRPCServerHook(name string, server interface{ GracefulStop() }) Hook {
	return Hook{
		Name:     name,
		Priority: 10, // gRPC servers should shutdown early
		Timeout:  30 * time.Second,
		Fn: func(ctx context.Context) error {
			done := make(chan struct{})
			go func() {
				server.GracefulStop()
				close(done)
			}()
			
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	}
}

// DatabaseHook creates a shutdown hook for database connections
func DatabaseHook(name string, closer interface{ Close() error }) Hook {
	return Hook{
		Name:     name,
		Priority: 20, // Databases should close after servers
		Timeout:  10 * time.Second,
		Fn: func(ctx context.Context) error {
			return closer.Close()
		},
	}
}

// BackgroundTaskHook creates a shutdown hook for background tasks
func BackgroundTaskHook(name string, canceller context.CancelFunc, wg *sync.WaitGroup) Hook {
	return Hook{
		Name:     name,
		Priority: 5, // Background tasks should stop first
		Timeout:  15 * time.Second,
		Fn: func(ctx context.Context) error {
			canceller()
			
			done := make(chan struct{})
			go func() {
				wg.Wait()
				close(done)
			}()
			
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return fmt.Errorf("background tasks did not finish in time")
			}
		},
	}
}

// MetricsHook creates a shutdown hook for metrics collection
func MetricsHook(name string, metricsManager interface{ Stop(context.Context) error }) Hook {
	return Hook{
		Name:     name,
		Priority: 30, // Metrics should shutdown last to capture final stats
		Timeout:  5 * time.Second,
		Fn: func(ctx context.Context) error {
			return metricsManager.Stop(ctx)
		},
	}
}

// TracingHook creates a shutdown hook for tracing
func TracingHook(name string, tracer interface{ Shutdown(context.Context) error }) Hook {
	return Hook{
		Name:     name,
		Priority: 30, // Tracing should shutdown last
		Timeout:  5 * time.Second,
		Fn: func(ctx context.Context) error {
			return tracer.Shutdown(ctx)
		},
	}
}

// LoggerHook creates a shutdown hook for logger syncing
func LoggerHook(name string, logger interface{ Sync() error }) Hook {
	return Hook{
		Name:     name,
		Priority: 40, // Logger should sync last
		Timeout:  2 * time.Second,
		Fn: func(ctx context.Context) error {
			return logger.Sync()
		},
	}
}

// GenericHook creates a generic shutdown hook
func GenericHook(name string, priority int, timeout time.Duration, fn func(context.Context) error) Hook {
	return Hook{
		Name:     name,
		Priority: priority,
		Timeout:  timeout,
		Fn:       fn,
	}
}

// WithTimeout wraps a function with a timeout
func WithTimeout(fn func() error, timeout time.Duration) func(context.Context) error {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		
		done := make(chan error, 1)
		go func() {
			done <- fn()
		}()
		
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// DefaultConfig returns a default shutdown configuration
func DefaultConfig() *Config {
	return &Config{
		Timeout: 30 * time.Second,
		Signals: []os.Signal{syscall.SIGTERM, syscall.SIGINT},
	}
}