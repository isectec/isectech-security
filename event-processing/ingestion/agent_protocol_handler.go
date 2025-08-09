package ingestion

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// AgentProtocolHandler manages custom binary protocol communication with iSECTECH security agents
type AgentProtocolHandler struct {
	config        *AgentProtocolConfig
	logger        *zap.Logger
	listener      net.Listener
	connections   map[string]*AgentConnection
	connMutex     sync.RWMutex
	ingestionSvc  IngestionService
	
	// State management
	isRunning     int32
	shutdownCh    chan struct{}
	wg            sync.WaitGroup
	
	// Metrics
	metrics       *AgentProtocolMetrics
	lastReport    time.Time
}

// AgentProtocolConfig defines configuration for agent protocol communication
type AgentProtocolConfig struct {
	// Network Configuration
	ListenAddress        string        `json:"listen_address" validate:"required"`     // 0.0.0.0:8443
	Port                 int           `json:"port" validate:"required"`              // 8443
	
	// Security Configuration
	TLSConfig            *TLSServerConfig `json:"tls_config" validate:"required"`
	AuthenticationKey    string        `json:"authentication_key" validate:"required"`
	EncryptionKey        string        `json:"encryption_key" validate:"required"`
	
	// Protocol Settings
	ProtocolVersion      uint8         `json:"protocol_version"`                      // Default: 1
	MaxMessageSize       int           `json:"max_message_size"`                      // Default: 10MB
	HeartbeatInterval    time.Duration `json:"heartbeat_interval"`                    // Default: 30s
	ConnectionTimeout    time.Duration `json:"connection_timeout"`                    // Default: 5m
	ReadTimeout          time.Duration `json:"read_timeout"`                          // Default: 30s
	WriteTimeout         time.Duration `json:"write_timeout"`                         // Default: 30s
	
	// Connection Management
	MaxConnections       int           `json:"max_connections"`                       // Default: 10000
	MaxConnectionsPerIP  int           `json:"max_connections_per_ip"`                // Default: 100
	ConnectionQueueSize  int           `json:"connection_queue_size"`                 // Default: 1000
	
	// Performance Settings
	BufferSize           int           `json:"buffer_size"`                           // Default: 64KB
	BatchSize            int           `json:"batch_size"`                            // Default: 100
	FlushInterval        time.Duration `json:"flush_interval"`                        // Default: 1s
	
	// Rate Limiting
	RateLimit            *AgentRateLimitConfig `json:"rate_limit,omitempty"`
	
	// Compression
	EnableCompression    bool          `json:"enable_compression"`                    // Default: true
	CompressionLevel     int           `json:"compression_level"`                     // Default: 6
	CompressionThreshold int           `json:"compression_threshold"`                 // Default: 1KB
}

// TLSServerConfig defines TLS configuration for agent connections
type TLSServerConfig struct {
	CertFile             string   `json:"cert_file" validate:"required"`
	KeyFile              string   `json:"key_file" validate:"required"`
	CAFile               string   `json:"ca_file,omitempty"`
	ClientAuth           string   `json:"client_auth"`                               // none, request, require, verify
	CipherSuites         []string `json:"cipher_suites,omitempty"`
	MinVersion           string   `json:"min_version"`                               // TLS1.2, TLS1.3
	MaxVersion           string   `json:"max_version"`
}

// AgentRateLimitConfig defines rate limiting for agent connections
type AgentRateLimitConfig struct {
	EventsPerSecond      int64         `json:"events_per_second"`                     // Default: 1000
	BurstSize            int64         `json:"burst_size"`                            // Default: 100
	ConnectionsPerSecond int           `json:"connections_per_second"`                // Default: 10
}

// AgentConnection represents a connected security agent
type AgentConnection struct {
	ID               string                 `json:"id"`
	AgentInfo        *AgentInfo             `json:"agent_info"`
	Conn             net.Conn               `json:"-"`
	TenantID         string                 `json:"tenant_id"`
	ConnectedAt      time.Time              `json:"connected_at"`
	LastActivity     time.Time              `json:"last_activity"`
	LastHeartbeat    time.Time              `json:"last_heartbeat"`
	
	// Protocol state
	ProtocolVersion  uint8                  `json:"protocol_version"`
	Authenticated    bool                   `json:"authenticated"`
	CompressionEnabled bool                 `json:"compression_enabled"`
	
	// Buffers and channels
	sendCh           chan []byte
	receiveCh        chan []byte
	errorCh          chan error
	
	// Metrics
	MessagesSent     int64                  `json:"messages_sent"`
	MessagesReceived int64                  `json:"messages_received"`
	BytesSent        int64                  `json:"bytes_sent"`
	BytesReceived    int64                  `json:"bytes_received"`
	ErrorCount       int64                  `json:"error_count"`
	
	// Connection state
	isConnected      bool
	mutex            sync.RWMutex
}

// AgentProtocolMetrics tracks protocol performance and health
type AgentProtocolMetrics struct {
	ActiveConnections     int64                  `json:"active_connections"`
	TotalConnections      int64                  `json:"total_connections"`
	ConnectionsPerSecond  float64                `json:"connections_per_second"`
	
	MessagesPerSecond     float64                `json:"messages_per_second"`
	BytesPerSecond        float64                `json:"bytes_per_second"`
	
	AvgMessageSize        float64                `json:"avg_message_size"`
	CompressionRatio      float64                `json:"compression_ratio"`
	
	ErrorRate             float64                `json:"error_rate"`
	TimeoutRate           float64                `json:"timeout_rate"`
	
	AgentVersions         map[string]int         `json:"agent_versions"`
	TenantConnections     map[string]int         `json:"tenant_connections"`
	
	mutex                 sync.RWMutex
	lastUpdate            time.Time
}

// IngestionService interface for forwarding events
type IngestionService interface {
	IngestEvent(ctx context.Context, event *SecurityEvent) error
	IngestBatch(ctx context.Context, batch *EventBatch) error
}

// Protocol message types
const (
	MessageTypeHandshake     uint8 = 0x01
	MessageTypeAuth          uint8 = 0x02
	MessageTypeHeartbeat     uint8 = 0x03
	MessageTypeEvent         uint8 = 0x04
	MessageTypeBatch         uint8 = 0x05
	MessageTypeAck           uint8 = 0x06
	MessageTypeError         uint8 = 0x07
	MessageTypeConfig        uint8 = 0x08
	MessageTypeDisconnect    uint8 = 0x09
)

// Protocol message structure
type ProtocolMessage struct {
	Version      uint8                  `json:"version"`
	Type         uint8                  `json:"type"`
	Sequence     uint32                 `json:"sequence"`
	Timestamp    uint64                 `json:"timestamp"`
	PayloadSize  uint32                 `json:"payload_size"`
	Checksum     uint32                 `json:"checksum"`
	Compressed   bool                   `json:"compressed"`
	Encrypted    bool                   `json:"encrypted"`
	Payload      []byte                 `json:"payload"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Authentication message payload
type AuthMessage struct {
	AgentID          string    `json:"agent_id"`
	TenantID         string    `json:"tenant_id"`
	AuthToken        string    `json:"auth_token"`
	AgentVersion     string    `json:"agent_version"`
	Platform         string    `json:"platform"`
	Hostname         string    `json:"hostname"`
	Capabilities     []string  `json:"capabilities"`
	ConfigVersion    string    `json:"config_version"`
	LastSyncTime     time.Time `json:"last_sync_time"`
}

// Heartbeat message payload
type HeartbeatMessage struct {
	AgentID          string                 `json:"agent_id"`
	Timestamp        time.Time              `json:"timestamp"`
	Health           *AgentHealth           `json:"health"`
	EventQueueDepth  int                    `json:"event_queue_depth"`
	Stats            map[string]interface{} `json:"stats,omitempty"`
}

// Configuration message payload
type ConfigMessage struct {
	Version          string                 `json:"version"`
	UpdatedAt        time.Time              `json:"updated_at"`
	Configuration    map[string]interface{} `json:"configuration"`
	ForceRestart     bool                   `json:"force_restart"`
}

// NewAgentProtocolHandler creates a new agent protocol handler
func NewAgentProtocolHandler(config *AgentProtocolConfig, ingestionSvc IngestionService, logger *zap.Logger) (*AgentProtocolHandler, error) {
	if err := validateAgentProtocolConfig(config); err != nil {
		return nil, fmt.Errorf("invalid agent protocol configuration: %w", err)
	}
	
	setAgentProtocolDefaults(config)
	
	return &AgentProtocolHandler{
		config:       config,
		logger:       logger,
		connections:  make(map[string]*AgentConnection),
		ingestionSvc: ingestionSvc,
		shutdownCh:   make(chan struct{}),
		metrics:      NewAgentProtocolMetrics(),
		lastReport:   time.Now(),
	}, nil
}

// Start initializes and starts the agent protocol handler
func (h *AgentProtocolHandler) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&h.isRunning, 0, 1) {
		return fmt.Errorf("agent protocol handler is already running")
	}
	
	h.logger.Info("Starting agent protocol handler",
		zap.String("listen_address", h.config.ListenAddress),
		zap.Int("port", h.config.Port))
	
	// Create TLS configuration
	tlsConfig, err := h.createTLSConfig()
	if err != nil {
		return fmt.Errorf("failed to create TLS configuration: %w", err)
	}
	
	// Create listener
	listener, err := tls.Listen("tcp", fmt.Sprintf("%s:%d", h.config.ListenAddress, h.config.Port), tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to create TLS listener: %w", err)
	}
	h.listener = listener
	
	// Start background routines
	h.wg.Add(3)
	go h.acceptConnections()
	go h.manageConnections()
	go h.reportMetrics()
	
	h.logger.Info("Agent protocol handler started successfully")
	return nil
}

// Stop gracefully shuts down the agent protocol handler
func (h *AgentProtocolHandler) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&h.isRunning, 1, 0) {
		return fmt.Errorf("agent protocol handler is not running")
	}
	
	h.logger.Info("Stopping agent protocol handler")
	
	// Signal shutdown
	close(h.shutdownCh)
	
	// Close listener
	if h.listener != nil {
		h.listener.Close()
	}
	
	// Close all connections
	h.closeAllConnections()
	
	// Wait for background routines
	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		h.logger.Info("Agent protocol handler stopped successfully")
		return nil
	case <-ctx.Done():
		h.logger.Warn("Agent protocol handler shutdown timed out")
		return ctx.Err()
	}
}

// GetMetrics returns current protocol metrics
func (h *AgentProtocolHandler) GetMetrics() *AgentProtocolMetrics {
	h.metrics.mutex.RLock()
	defer h.metrics.mutex.RUnlock()
	
	// Create a copy
	metrics := *h.metrics
	metrics.AgentVersions = make(map[string]int)
	metrics.TenantConnections = make(map[string]int)
	
	for version, count := range h.metrics.AgentVersions {
		metrics.AgentVersions[version] = count
	}
	for tenant, count := range h.metrics.TenantConnections {
		metrics.TenantConnections[tenant] = count
	}
	
	return &metrics
}

// GetActiveConnections returns list of active agent connections
func (h *AgentProtocolHandler) GetActiveConnections() []*AgentConnection {
	h.connMutex.RLock()
	defer h.connMutex.RUnlock()
	
	connections := make([]*AgentConnection, 0, len(h.connections))
	for _, conn := range h.connections {
		// Create a copy for safety
		connCopy := *conn
		connections = append(connections, &connCopy)
	}
	
	return connections
}

// Private methods

func (h *AgentProtocolHandler) acceptConnections() {
	defer h.wg.Done()
	
	for {
		select {
		case <-h.shutdownCh:
			return
		default:
			// Set accept timeout
			if tcpListener, ok := h.listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(time.Second))
			}
			
			conn, err := h.listener.Accept()
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue // Timeout is expected for graceful shutdown
				}
				if atomic.LoadInt32(&h.isRunning) == 1 {
					h.logger.Error("Failed to accept connection", zap.Error(err))
				}
				continue
			}
			
			// Check connection limits
			if h.getActiveConnectionCount() >= h.config.MaxConnections {
				h.logger.Warn("Maximum connections reached, rejecting connection",
					zap.String("remote_addr", conn.RemoteAddr().String()))
				conn.Close()
				continue
			}
			
			// Handle connection in goroutine
			go h.handleConnection(conn)
		}
	}
}

func (h *AgentProtocolHandler) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	// Set initial timeouts
	conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout))
	conn.SetWriteDeadline(time.Now().Add(h.config.WriteTimeout))
	
	// Create agent connection
	agentConn := &AgentConnection{
		ID:           generateConnectionID(),
		Conn:         conn,
		ConnectedAt:  time.Now(),
		LastActivity: time.Now(),
		sendCh:       make(chan []byte, 100),
		receiveCh:    make(chan []byte, 100),
		errorCh:      make(chan error, 10),
		isConnected:  true,
	}
	
	h.logger.Info("New agent connection",
		zap.String("connection_id", agentConn.ID),
		zap.String("remote_addr", conn.RemoteAddr().String()))
	
	// Start connection handlers
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	go h.connectionReader(ctx, agentConn)
	go h.connectionWriter(ctx, agentConn)
	go h.connectionProcessor(ctx, agentConn)
	
	// Wait for authentication or timeout
	authTimeout := time.NewTimer(30 * time.Second)
	defer authTimeout.Stop()
	
	select {
	case <-authTimeout.C:
		h.logger.Warn("Authentication timeout",
			zap.String("connection_id", agentConn.ID))
		return
	case err := <-agentConn.errorCh:
		h.logger.Error("Connection error during authentication",
			zap.String("connection_id", agentConn.ID),
			zap.Error(err))
		return
	case <-ctx.Done():
		return
	}
	
	// If we reach here, authentication was successful
	h.addConnection(agentConn)
	defer h.removeConnection(agentConn.ID)
	
	// Connection maintenance loop
	ticker := time.NewTicker(h.config.HeartbeatInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			if !h.isConnectionHealthy(agentConn) {
				h.logger.Warn("Unhealthy connection detected",
					zap.String("connection_id", agentConn.ID),
					zap.String("agent_id", agentConn.AgentInfo.ID))
				return
			}
		case err := <-agentConn.errorCh:
			h.logger.Error("Connection error",
				zap.String("connection_id", agentConn.ID),
				zap.Error(err))
			return
		case <-ctx.Done():
			return
		case <-h.shutdownCh:
			return
		}
	}
}

func (h *AgentProtocolHandler) connectionReader(ctx context.Context, conn *AgentConnection) {
	reader := bufio.NewReader(conn.Conn)
	buffer := make([]byte, h.config.BufferSize)
	
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Set read deadline
			conn.Conn.SetReadDeadline(time.Now().Add(h.config.ReadTimeout))
			
			// Read message header (fixed size)
			header := make([]byte, 24) // Version(1) + Type(1) + Sequence(4) + Timestamp(8) + PayloadSize(4) + Checksum(4) + Flags(2)
			_, err := reader.Read(header)
			if err != nil {
				conn.errorCh <- fmt.Errorf("failed to read message header: %w", err)
				return
			}
			
			// Parse header
			msg, err := h.parseMessageHeader(header)
			if err != nil {
				conn.errorCh <- fmt.Errorf("failed to parse message header: %w", err)
				return
			}
			
			// Validate payload size
			if msg.PayloadSize > uint32(h.config.MaxMessageSize) {
				conn.errorCh <- fmt.Errorf("message payload too large: %d bytes", msg.PayloadSize)
				return
			}
			
			// Read payload if present
			if msg.PayloadSize > 0 {
				payload := make([]byte, msg.PayloadSize)
				_, err := reader.Read(payload)
				if err != nil {
					conn.errorCh <- fmt.Errorf("failed to read message payload: %w", err)
					return
				}
				
				// Verify checksum
				if !h.verifyChecksum(payload, msg.Checksum) {
					conn.errorCh <- fmt.Errorf("message checksum verification failed")
					return
				}
				
				msg.Payload = payload
			}
			
			// Update connection metrics
			atomic.AddInt64(&conn.MessagesReceived, 1)
			atomic.AddInt64(&conn.BytesReceived, int64(len(header)+len(msg.Payload)))
			conn.LastActivity = time.Now()
			
			// Send to processor
			select {
			case conn.receiveCh <- h.serializeMessage(msg):
			case <-ctx.Done():
				return
			}
		}
	}
}

func (h *AgentProtocolHandler) connectionWriter(ctx context.Context, conn *AgentConnection) {
	for {
		select {
		case data := <-conn.sendCh:
			// Set write deadline
			conn.Conn.SetWriteDeadline(time.Now().Add(h.config.WriteTimeout))
			
			// Write data
			_, err := conn.Conn.Write(data)
			if err != nil {
				conn.errorCh <- fmt.Errorf("failed to write data: %w", err)
				return
			}
			
			// Update metrics
			atomic.AddInt64(&conn.MessagesSent, 1)
			atomic.AddInt64(&conn.BytesSent, int64(len(data)))
			conn.LastActivity = time.Now()
			
		case <-ctx.Done():
			return
		}
	}
}

func (h *AgentProtocolHandler) connectionProcessor(ctx context.Context, conn *AgentConnection) {
	for {
		select {
		case data := <-conn.receiveCh:
			// Deserialize message
			msg, err := h.deserializeMessage(data)
			if err != nil {
				h.logger.Error("Failed to deserialize message", zap.Error(err))
				continue
			}
			
			// Process message based on type
			if err := h.processMessage(ctx, conn, msg); err != nil {
				h.logger.Error("Failed to process message",
					zap.String("connection_id", conn.ID),
					zap.Uint8("message_type", msg.Type),
					zap.Error(err))
			}
			
		case <-ctx.Done():
			return
		}
	}
}

func (h *AgentProtocolHandler) processMessage(ctx context.Context, conn *AgentConnection, msg *ProtocolMessage) error {
	switch msg.Type {
	case MessageTypeHandshake:
		return h.handleHandshake(conn, msg)
	case MessageTypeAuth:
		return h.handleAuthentication(conn, msg)
	case MessageTypeHeartbeat:
		return h.handleHeartbeat(conn, msg)
	case MessageTypeEvent:
		return h.handleEvent(ctx, conn, msg)
	case MessageTypeBatch:
		return h.handleBatch(ctx, conn, msg)
	case MessageTypeDisconnect:
		return h.handleDisconnect(conn, msg)
	default:
		return fmt.Errorf("unknown message type: %d", msg.Type)
	}
}

func (h *AgentProtocolHandler) handleHandshake(conn *AgentConnection, msg *ProtocolMessage) error {
	// Process handshake and respond with protocol capabilities
	conn.ProtocolVersion = msg.Version
	
	// Send handshake response
	response := &ProtocolMessage{
		Version:     h.config.ProtocolVersion,
		Type:        MessageTypeHandshake,
		Sequence:    msg.Sequence + 1,
		Timestamp:   uint64(time.Now().UnixNano()),
		PayloadSize: 0,
	}
	
	return h.sendMessage(conn, response)
}

func (h *AgentProtocolHandler) handleAuthentication(conn *AgentConnection, msg *ProtocolMessage) error {
	// Parse authentication message
	var authMsg AuthMessage
	if err := json.Unmarshal(msg.Payload, &authMsg); err != nil {
		return fmt.Errorf("failed to parse authentication message: %w", err)
	}
	
	// Validate authentication token
	if !h.validateAuthToken(authMsg.AuthToken, authMsg.AgentID, authMsg.TenantID) {
		return fmt.Errorf("authentication failed for agent %s", authMsg.AgentID)
	}
	
	// Update connection with agent information
	conn.TenantID = authMsg.TenantID
	conn.AgentInfo = &AgentInfo{
		ID:           authMsg.AgentID,
		Version:      authMsg.AgentVersion,
		Platform:     authMsg.Platform,
		Hostname:     authMsg.Hostname,
		Capabilities: authMsg.Capabilities,
		LastSeen:     time.Now(),
	}
	conn.Authenticated = true
	
	h.logger.Info("Agent authenticated successfully",
		zap.String("agent_id", authMsg.AgentID),
		zap.String("tenant_id", authMsg.TenantID),
		zap.String("version", authMsg.AgentVersion),
		zap.String("platform", authMsg.Platform))
	
	// Send authentication response
	response := &ProtocolMessage{
		Version:     h.config.ProtocolVersion,
		Type:        MessageTypeAuth,
		Sequence:    msg.Sequence + 1,
		Timestamp:   uint64(time.Now().UnixNano()),
		PayloadSize: 0,
	}
	
	return h.sendMessage(conn, response)
}

func (h *AgentProtocolHandler) handleHeartbeat(conn *AgentConnection, msg *ProtocolMessage) error {
	// Parse heartbeat message
	var heartbeat HeartbeatMessage
	if err := json.Unmarshal(msg.Payload, &heartbeat); err != nil {
		return fmt.Errorf("failed to parse heartbeat message: %w", err)
	}
	
	// Update agent health information
	if conn.AgentInfo != nil {
		conn.AgentInfo.Health = heartbeat.Health
		conn.AgentInfo.LastSeen = heartbeat.Timestamp
	}
	conn.LastHeartbeat = time.Now()
	
	// Send heartbeat acknowledgment
	response := &ProtocolMessage{
		Version:     h.config.ProtocolVersion,
		Type:        MessageTypeAck,
		Sequence:    msg.Sequence + 1,
		Timestamp:   uint64(time.Now().UnixNano()),
		PayloadSize: 0,
	}
	
	return h.sendMessage(conn, response)
}

func (h *AgentProtocolHandler) handleEvent(ctx context.Context, conn *AgentConnection, msg *ProtocolMessage) error {
	if !conn.Authenticated {
		return fmt.Errorf("connection not authenticated")
	}
	
	// Parse security event
	event, err := FromJSON(msg.Payload)
	if err != nil {
		return fmt.Errorf("failed to parse security event: %w", err)
	}
	
	// Set tenant ID from connection
	event.TenantID = conn.TenantID
	
	// Set agent information
	if conn.AgentInfo != nil {
		event.Agent = conn.AgentInfo
	}
	
	// Forward to ingestion service
	if err := h.ingestionSvc.IngestEvent(ctx, event); err != nil {
		return fmt.Errorf("failed to ingest event: %w", err)
	}
	
	// Send acknowledgment
	response := &ProtocolMessage{
		Version:     h.config.ProtocolVersion,
		Type:        MessageTypeAck,
		Sequence:    msg.Sequence + 1,
		Timestamp:   uint64(time.Now().UnixNano()),
		PayloadSize: 0,
	}
	
	return h.sendMessage(conn, response)
}

func (h *AgentProtocolHandler) handleBatch(ctx context.Context, conn *AgentConnection, msg *ProtocolMessage) error {
	if !conn.Authenticated {
		return fmt.Errorf("connection not authenticated")
	}
	
	// Parse event batch
	var batch EventBatch
	if err := json.Unmarshal(msg.Payload, &batch); err != nil {
		return fmt.Errorf("failed to parse event batch: %w", err)
	}
	
	// Set tenant ID for all events
	for _, event := range batch.Events {
		event.TenantID = conn.TenantID
		if conn.AgentInfo != nil {
			event.Agent = conn.AgentInfo
		}
	}
	
	// Forward to ingestion service
	if err := h.ingestionSvc.IngestBatch(ctx, &batch); err != nil {
		return fmt.Errorf("failed to ingest batch: %w", err)
	}
	
	// Send acknowledgment
	response := &ProtocolMessage{
		Version:     h.config.ProtocolVersion,
		Type:        MessageTypeAck,
		Sequence:    msg.Sequence + 1,
		Timestamp:   uint64(time.Now().UnixNano()),
		PayloadSize: 0,
	}
	
	return h.sendMessage(conn, response)
}

func (h *AgentProtocolHandler) handleDisconnect(conn *AgentConnection, msg *ProtocolMessage) error {
	h.logger.Info("Agent disconnecting",
		zap.String("connection_id", conn.ID),
		zap.String("agent_id", conn.AgentInfo.ID))
	
	conn.isConnected = false
	return nil
}

// Helper methods

func (h *AgentProtocolHandler) createTLSConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(h.config.TLSConfig.CertFile, h.config.TLSConfig.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificates: %w", err)
	}
	
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	
	// Configure client authentication if CA file is provided
	if h.config.TLSConfig.CAFile != "" {
		// Load CA certificate for client authentication
		// Implementation would load and configure CA
	}
	
	return config, nil
}

func (h *AgentProtocolHandler) parseMessageHeader(header []byte) (*ProtocolMessage, error) {
	if len(header) < 24 {
		return nil, fmt.Errorf("header too short: %d bytes", len(header))
	}
	
	msg := &ProtocolMessage{
		Version:     header[0],
		Type:        header[1],
		Sequence:    binary.BigEndian.Uint32(header[2:6]),
		Timestamp:   binary.BigEndian.Uint64(header[6:14]),
		PayloadSize: binary.BigEndian.Uint32(header[14:18]),
		Checksum:    binary.BigEndian.Uint32(header[18:22]),
	}
	
	// Parse flags
	flags := binary.BigEndian.Uint16(header[22:24])
	msg.Compressed = (flags & 0x01) != 0
	msg.Encrypted = (flags & 0x02) != 0
	
	return msg, nil
}

func (h *AgentProtocolHandler) serializeMessage(msg *ProtocolMessage) []byte {
	// Implementation would serialize the message
	data, _ := json.Marshal(msg)
	return data
}

func (h *AgentProtocolHandler) deserializeMessage(data []byte) (*ProtocolMessage, error) {
	var msg ProtocolMessage
	err := json.Unmarshal(data, &msg)
	return &msg, err
}

func (h *AgentProtocolHandler) sendMessage(conn *AgentConnection, msg *ProtocolMessage) error {
	data := h.serializeMessage(msg)
	
	select {
	case conn.sendCh <- data:
		return nil
	case <-time.After(time.Second):
		return fmt.Errorf("send timeout")
	}
}

func (h *AgentProtocolHandler) verifyChecksum(payload []byte, checksum uint32) bool {
	// Implementation would verify checksum
	return true // Placeholder
}

func (h *AgentProtocolHandler) validateAuthToken(token, agentID, tenantID string) bool {
	// Implementation would validate authentication token
	return true // Placeholder
}

func (h *AgentProtocolHandler) addConnection(conn *AgentConnection) {
	h.connMutex.Lock()
	defer h.connMutex.Unlock()
	
	h.connections[conn.ID] = conn
	atomic.AddInt64(&h.metrics.ActiveConnections, 1)
	atomic.AddInt64(&h.metrics.TotalConnections, 1)
}

func (h *AgentProtocolHandler) removeConnection(connID string) {
	h.connMutex.Lock()
	defer h.connMutex.Unlock()
	
	if _, exists := h.connections[connID]; exists {
		delete(h.connections, connID)
		atomic.AddInt64(&h.metrics.ActiveConnections, -1)
	}
}

func (h *AgentProtocolHandler) getActiveConnectionCount() int {
	h.connMutex.RLock()
	defer h.connMutex.RUnlock()
	return len(h.connections)
}

func (h *AgentProtocolHandler) isConnectionHealthy(conn *AgentConnection) bool {
	// Check if connection has been inactive for too long
	if time.Since(conn.LastActivity) > h.config.ConnectionTimeout {
		return false
	}
	
	// Check if heartbeat is overdue
	if time.Since(conn.LastHeartbeat) > 2*h.config.HeartbeatInterval {
		return false
	}
	
	return conn.isConnected
}

func (h *AgentProtocolHandler) closeAllConnections() {
	h.connMutex.Lock()
	defer h.connMutex.Unlock()
	
	for _, conn := range h.connections {
		conn.Conn.Close()
		conn.isConnected = false
	}
}

func (h *AgentProtocolHandler) manageConnections() {
	defer h.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			h.cleanupStaleConnections()
		case <-h.shutdownCh:
			return
		}
	}
}

func (h *AgentProtocolHandler) cleanupStaleConnections() {
	h.connMutex.Lock()
	defer h.connMutex.Unlock()
	
	var staleConnections []string
	
	for connID, conn := range h.connections {
		if !h.isConnectionHealthy(conn) {
			staleConnections = append(staleConnections, connID)
		}
	}
	
	for _, connID := range staleConnections {
		if conn, exists := h.connections[connID]; exists {
			h.logger.Info("Cleaning up stale connection",
				zap.String("connection_id", connID),
				zap.String("agent_id", conn.AgentInfo.ID))
			
			conn.Conn.Close()
			delete(h.connections, connID)
			atomic.AddInt64(&h.metrics.ActiveConnections, -1)
		}
	}
}

func (h *AgentProtocolHandler) reportMetrics() {
	defer h.wg.Done()
	
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			h.updateMetrics()
		case <-h.shutdownCh:
			return
		}
	}
}

func (h *AgentProtocolHandler) updateMetrics() {
	h.metrics.mutex.Lock()
	defer h.metrics.mutex.Unlock()
	
	now := time.Now()
	duration := now.Sub(h.metrics.lastUpdate)
	
	// Update connection metrics
	h.connMutex.RLock()
	h.metrics.ActiveConnections = int64(len(h.connections))
	
	// Update tenant and version distributions
	h.metrics.AgentVersions = make(map[string]int)
	h.metrics.TenantConnections = make(map[string]int)
	
	for _, conn := range h.connections {
		if conn.AgentInfo != nil {
			h.metrics.AgentVersions[conn.AgentInfo.Version]++
		}
		h.metrics.TenantConnections[conn.TenantID]++
	}
	h.connMutex.RUnlock()
	
	h.metrics.lastUpdate = now
	
	h.logger.Debug("Agent protocol metrics updated",
		zap.Int64("active_connections", h.metrics.ActiveConnections),
		zap.Int("agent_versions", len(h.metrics.AgentVersions)),
		zap.Int("tenant_connections", len(h.metrics.TenantConnections)))
}

// Utility functions

func validateAgentProtocolConfig(config *AgentProtocolConfig) error {
	if config.ListenAddress == "" {
		return fmt.Errorf("listen address is required")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return fmt.Errorf("invalid port: %d", config.Port)
	}
	if config.TLSConfig == nil {
		return fmt.Errorf("TLS configuration is required")
	}
	if config.TLSConfig.CertFile == "" || config.TLSConfig.KeyFile == "" {
		return fmt.Errorf("TLS certificate and key files are required")
	}
	return nil
}

func setAgentProtocolDefaults(config *AgentProtocolConfig) {
	if config.ProtocolVersion == 0 {
		config.ProtocolVersion = 1
	}
	if config.MaxMessageSize == 0 {
		config.MaxMessageSize = 10 * 1024 * 1024 // 10MB
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 30 * time.Second
	}
	if config.ConnectionTimeout == 0 {
		config.ConnectionTimeout = 5 * time.Minute
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = 30 * time.Second
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = 30 * time.Second
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 10000
	}
	if config.MaxConnectionsPerIP == 0 {
		config.MaxConnectionsPerIP = 100
	}
	if config.BufferSize == 0 {
		config.BufferSize = 64 * 1024 // 64KB
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = time.Second
	}
}

func generateConnectionID() string {
	return fmt.Sprintf("conn_%d", time.Now().UnixNano())
}

func NewAgentProtocolMetrics() *AgentProtocolMetrics {
	return &AgentProtocolMetrics{
		AgentVersions:     make(map[string]int),
		TenantConnections: make(map[string]int),
		lastUpdate:       time.Now(),
	}
}