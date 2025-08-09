package logging

import (
	"context"
	"fmt"
	"path"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCServerInterceptors returns gRPC server interceptors for logging
func GRPCServerInterceptors(logger *zap.Logger) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	l := &Logger{Logger: logger, config: DefaultConfig()}
	return l.UnaryServerInterceptor(), l.StreamServerInterceptor()
}

// GRPCClientInterceptors returns gRPC client interceptors for logging
func GRPCClientInterceptors(logger *zap.Logger) (grpc.UnaryClientInterceptor, grpc.StreamClientInterceptor) {
	l := &Logger{Logger: logger, config: DefaultConfig()}
	return l.UnaryClientInterceptor(), l.StreamClientInterceptor()
}

// UnaryServerInterceptor returns a gRPC unary server interceptor for logging
func (l *Logger) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		
		// Extract metadata and create enriched context
		ctx = l.enrichContextFromMetadata(ctx)
		
		// Create request-specific logger
		requestLogger := l.WithContext(ctx)
		
		// Log request start
		requestLogger.Info("gRPC request started",
			zap.String("method", info.FullMethod),
			zap.String("service", path.Dir(info.FullMethod)[1:]),
			zap.String("operation", path.Base(info.FullMethod)),
			zap.String("type", "unary"),
		)
		
		// Call the handler
		resp, err := handler(ctx, req)
		
		// Calculate duration
		duration := time.Since(start)
		
		// Determine log level and status
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}
		
		// Log response
		fields := []zap.Field{
			zap.String("method", info.FullMethod),
			zap.String("service", path.Dir(info.FullMethod)[1:]),
			zap.String("operation", path.Base(info.FullMethod)),
			zap.String("type", "unary"),
			zap.Duration("duration", duration),
			zap.String("status", code.String()),
			zap.Int("status_code", int(code)),
		}
		
		if err != nil {
			fields = append(fields, zap.Error(err))
			requestLogger.Error("gRPC request failed", fields...)
		} else {
			requestLogger.Info("gRPC request completed", fields...)
		}
		
		// Log performance metric
		requestLogger.LogPerformance(info.FullMethod, duration,
			zap.String("status", code.String()),
			zap.Bool("success", err == nil),
		)
		
		return resp, err
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor for logging
func (l *Logger) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()
		
		// Extract metadata and create enriched context
		ctx := l.enrichContextFromMetadata(stream.Context())
		
		// Create request-specific logger
		requestLogger := l.WithContext(ctx)
		
		// Create wrapped stream with enriched context
		wrappedStream := &serverStreamWrapper{
			ServerStream: stream,
			ctx:          ctx,
			logger:       requestLogger,
			method:       info.FullMethod,
		}
		
		// Log stream start
		requestLogger.Info("gRPC stream started",
			zap.String("method", info.FullMethod),
			zap.String("service", path.Dir(info.FullMethod)[1:]),
			zap.String("operation", path.Base(info.FullMethod)),
			zap.String("type", "stream"),
			zap.Bool("client_stream", info.IsClientStream),
			zap.Bool("server_stream", info.IsServerStream),
		)
		
		// Call the handler
		err := handler(srv, wrappedStream)
		
		// Calculate duration
		duration := time.Since(start)
		
		// Determine status
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}
		
		// Log stream completion
		fields := []zap.Field{
			zap.String("method", info.FullMethod),
			zap.String("service", path.Dir(info.FullMethod)[1:]),
			zap.String("operation", path.Base(info.FullMethod)),
			zap.String("type", "stream"),
			zap.Duration("duration", duration),
			zap.String("status", code.String()),
			zap.Int("status_code", int(code)),
			zap.Bool("client_stream", info.IsClientStream),
			zap.Bool("server_stream", info.IsServerStream),
		}
		
		if err != nil {
			fields = append(fields, zap.Error(err))
			requestLogger.Error("gRPC stream failed", fields...)
		} else {
			requestLogger.Info("gRPC stream completed", fields...)
		}
		
		return err
	}
}

// UnaryClientInterceptor returns a gRPC unary client interceptor for logging
func (l *Logger) UnaryClientInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		start := time.Now()
		
		// Inject context into metadata
		ctx = l.injectContextIntoMetadata(ctx)
		
		// Create request-specific logger
		requestLogger := l.WithContext(ctx)
		
		// Log request start
		requestLogger.Debug("gRPC client request started",
			zap.String("method", method),
			zap.String("service", path.Dir(method)[1:]),
			zap.String("operation", path.Base(method)),
			zap.String("type", "unary"),
			zap.String("target", cc.Target()),
		)
		
		// Make the call
		err := invoker(ctx, method, req, reply, cc, opts...)
		
		// Calculate duration
		duration := time.Since(start)
		
		// Determine status
		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}
		
		// Log response
		fields := []zap.Field{
			zap.String("method", method),
			zap.String("service", path.Dir(method)[1:]),
			zap.String("operation", path.Base(method)),
			zap.String("type", "unary"),
			zap.String("target", cc.Target()),
			zap.Duration("duration", duration),
			zap.String("status", code.String()),
			zap.Int("status_code", int(code)),
		}
		
		if err != nil {
			fields = append(fields, zap.Error(err))
			requestLogger.Error("gRPC client request failed", fields...)
		} else {
			requestLogger.Debug("gRPC client request completed", fields...)
		}
		
		return err
	}
}

// StreamClientInterceptor returns a gRPC stream client interceptor for logging
func (l *Logger) StreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		start := time.Now()
		
		// Inject context into metadata
		ctx = l.injectContextIntoMetadata(ctx)
		
		// Create request-specific logger
		requestLogger := l.WithContext(ctx)
		
		// Log stream start
		requestLogger.Debug("gRPC client stream started",
			zap.String("method", method),
			zap.String("service", path.Dir(method)[1:]),
			zap.String("operation", path.Base(method)),
			zap.String("type", "stream"),
			zap.String("target", cc.Target()),
			zap.Bool("client_stream", desc.ClientStreams),
			zap.Bool("server_stream", desc.ServerStreams),
		)
		
		// Create the stream
		stream, err := streamer(ctx, desc, cc, method, opts...)
		
		if err != nil {
			duration := time.Since(start)
			code := status.Code(err)
			
			requestLogger.Error("gRPC client stream failed to start",
				zap.String("method", method),
				zap.String("target", cc.Target()),
				zap.Duration("duration", duration),
				zap.String("status", code.String()),
				zap.Error(err),
			)
			
			return nil, err
		}
		
		// Wrap the stream for logging
		wrappedStream := &clientStreamWrapper{
			ClientStream: stream,
			logger:       requestLogger,
			method:       method,
			target:       cc.Target(),
			startTime:    start,
		}
		
		return wrappedStream, nil
	}
}

// enrichContextFromMetadata extracts logging context from gRPC metadata
func (l *Logger) enrichContextFromMetadata(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		// Ensure basic context if no metadata
		ctx, _ = EnsureCorrelationID(ctx)
		ctx, _ = EnsureRequestID(ctx)
		return ctx
	}
	
	// Extract correlation ID
	if values := md.Get("correlation-id"); len(values) > 0 {
		ctx = WithCorrelationID(ctx, values[0])
	} else if values := md.Get("x-correlation-id"); len(values) > 0 {
		ctx = WithCorrelationID(ctx, values[0])
	} else {
		ctx, _ = EnsureCorrelationID(ctx)
	}
	
	// Extract request ID
	if values := md.Get("request-id"); len(values) > 0 {
		ctx = WithRequestID(ctx, values[0])
	} else if values := md.Get("x-request-id"); len(values) > 0 {
		ctx = WithRequestID(ctx, values[0])
	} else {
		ctx, _ = EnsureRequestID(ctx)
	}
	
	// Extract trace context
	if values := md.Get("trace-id"); len(values) > 0 {
		ctx = WithTraceID(ctx, values[0])
	}
	if values := md.Get("span-id"); len(values) > 0 {
		ctx = WithSpanID(ctx, values[0])
	}
	
	// Extract user context
	if values := md.Get("user-id"); len(values) > 0 {
		ctx = WithUserID(ctx, values[0])
	}
	if values := md.Get("tenant-id"); len(values) > 0 {
		ctx = WithTenantID(ctx, values[0])
	}
	
	return ctx
}

// injectContextIntoMetadata injects logging context into gRPC metadata
func (l *Logger) injectContextIntoMetadata(ctx context.Context) context.Context {
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		md = metadata.New(nil)
	}
	
	// Inject correlation ID
	if correlationID := GetCorrelationID(ctx); correlationID != "" {
		md.Set("correlation-id", correlationID)
	}
	
	// Inject request ID
	if requestID := GetRequestID(ctx); requestID != "" {
		md.Set("request-id", requestID)
	}
	
	// Inject trace context
	if traceID := GetTraceID(ctx); traceID != "" {
		md.Set("trace-id", traceID)
	}
	if spanID := GetSpanID(ctx); spanID != "" {
		md.Set("span-id", spanID)
	}
	
	// Inject user context
	if userID := GetUserID(ctx); userID != "" {
		md.Set("user-id", userID)
	}
	if tenantID := GetTenantID(ctx); tenantID != "" {
		md.Set("tenant-id", tenantID)
	}
	
	return metadata.NewOutgoingContext(ctx, md)
}

// serverStreamWrapper wraps grpc.ServerStream with enriched context
type serverStreamWrapper struct {
	grpc.ServerStream
	ctx    context.Context
	logger *Logger
	method string
}

func (w *serverStreamWrapper) Context() context.Context {
	return w.ctx
}

func (w *serverStreamWrapper) SendMsg(m interface{}) error {
	err := w.ServerStream.SendMsg(m)
	if err != nil {
		w.logger.Debug("gRPC stream send failed",
			zap.String("method", w.method),
			zap.Error(err),
		)
	}
	return err
}

func (w *serverStreamWrapper) RecvMsg(m interface{}) error {
	err := w.ServerStream.RecvMsg(m)
	if err != nil {
		w.logger.Debug("gRPC stream receive failed",
			zap.String("method", w.method),
			zap.Error(err),
		)
	}
	return err
}

// clientStreamWrapper wraps grpc.ClientStream for logging
type clientStreamWrapper struct {
	grpc.ClientStream
	logger    *Logger
	method    string
	target    string
	startTime time.Time
}

func (w *clientStreamWrapper) SendMsg(m interface{}) error {
	err := w.ClientStream.SendMsg(m)
	if err != nil {
		w.logger.Debug("gRPC client stream send failed",
			zap.String("method", w.method),
			zap.String("target", w.target),
			zap.Error(err),
		)
	}
	return err
}

func (w *clientStreamWrapper) RecvMsg(m interface{}) error {
	err := w.ClientStream.RecvMsg(m)
	if err != nil {
		w.logger.Debug("gRPC client stream receive failed",
			zap.String("method", w.method),
			zap.String("target", w.target),
			zap.Error(err),
		)
	}
	return err
}

func (w *clientStreamWrapper) CloseSend() error {
	err := w.ClientStream.CloseSend()
	duration := time.Since(w.startTime)
	
	w.logger.Debug("gRPC client stream closed",
		zap.String("method", w.method),
		zap.String("target", w.target),
		zap.Duration("total_duration", duration),
		zap.Bool("close_send_error", err != nil),
	)
	
	return err
}