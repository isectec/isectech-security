package elasticsearch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"go.uber.org/zap"
)

// CCRManager handles Cross-Cluster Replication for iSECTECH
type CCRManager struct {
	client *Client
	config *Config
	logger *zap.Logger
}

// FollowerStats represents statistics for a follower index
type FollowerStats struct {
	Index                    string    `json:"index"`
	RemoteCluster           string    `json:"remote_cluster"`
	LeaderIndex             string    `json:"leader_index"`
	Status                  string    `json:"status"`
	ParametersStatus        string    `json:"parameters_status"`
	OutstandingReadRequests int       `json:"outstanding_read_requests"`
	OutstandingWriteRequests int      `json:"outstanding_write_requests"`
	WriteBufferOperationCount int     `json:"write_buffer_operation_count"`
	FollowerGlobalCheckpoint int64    `json:"follower_global_checkpoint"`
	LeaderGlobalCheckpoint  int64     `json:"leader_global_checkpoint"`
	FollowerMaxSeqNo        int64     `json:"follower_max_seq_no"`
	LeaderMaxSeqNo          int64     `json:"leader_max_seq_no"`
	LastRequestedSeqNo      int64     `json:"last_requested_seq_no"`
	NumberOfFailedFollowAttempts int  `json:"number_of_failed_follow_attempts"`
	TotalReadTimeMillis     int       `json:"total_read_time_millis"`
	TotalReadRemoteExecTimeMillis int `json:"total_read_remote_exec_time_millis"`
	SuccessfulReadRequests  int       `json:"successful_read_requests"`
	FailedReadRequests      int       `json:"failed_read_requests"`
	OperationsRetrieved     int       `json:"operations_retrieved"`
	BytesRead               int64     `json:"bytes_read"`
	TotalWriteTimeMillis    int       `json:"total_write_time_millis"`
	SuccessfulWriteRequests int       `json:"successful_write_requests"`
	FailedWriteRequests     int       `json:"failed_write_requests"`
	OperationsIndexed       int       `json:"operations_indexed"`
	SinceLastAutoFollowFetch time.Time `json:"since_last_auto_follow_fetch"`
}

// RemoteClusterInfo represents information about a remote cluster
type RemoteClusterInfo struct {
	Name                string   `json:"name"`
	Seeds               []string `json:"seeds"`
	Connected           bool     `json:"connected"`
	Mode                string   `json:"mode"`
	SkipUnavailable     bool     `json:"skip_unavailable"`
	MaxConnectionsPerCluster int `json:"max_connections_per_cluster"`
	InitialConnectTimeout string `json:"initial_connect_timeout"`
	NumNodesConnected   int      `json:"num_nodes_connected"`
	MaxConnections      int      `json:"max_connections"`
}

// AutoFollowPattern represents an auto-follow pattern
type AutoFollowPattern struct {
	RemoteCluster          string   `json:"remote_cluster"`
	LeaderIndexPatterns    []string `json:"leader_index_patterns"`
	FollowIndexPattern     string   `json:"follow_index_pattern"`
	MaxReadRequestOpCount  int      `json:"max_read_request_operation_count"`
	MaxOutstandingReadRequests int  `json:"max_outstanding_read_requests"`
	MaxReadRequestSize     string   `json:"max_read_request_size"`
	MaxWriteRequestOpCount int      `json:"max_write_request_operation_count"`
	MaxOutstandingWriteRequests int `json:"max_outstanding_write_requests"`
	MaxWriteRequestSize    string   `json:"max_write_request_size"`
	MaxWriteBufferCount    int      `json:"max_write_buffer_count"`
	MaxWriteBufferSize     string   `json:"max_write_buffer_size"`
	MaxRetryDelay          string   `json:"max_retry_delay"`
	ReadPollTimeout        string   `json:"read_poll_timeout"`
}

// NewCCRManager creates a new CCR manager
func NewCCRManager(client *Client, config *Config, logger *zap.Logger) (*CCRManager, error) {
	return &CCRManager{
		client: client,
		config: config,
		logger: logger,
	}, nil
}

// SetupRemoteClusters configures remote clusters for CCR
func (ccr *CCRManager) SetupRemoteClusters(ctx context.Context) error {
	if !ccr.config.CCR.Enabled {
		ccr.logger.Info("CCR is disabled, skipping remote cluster setup")
		return nil
	}

	ccr.logger.Info("Setting up remote clusters for CCR")

	for clusterName, clusterConfig := range ccr.config.CCR.RemoteClusters {
		if err := ccr.AddRemoteCluster(ctx, clusterName, clusterConfig); err != nil {
			return fmt.Errorf("failed to add remote cluster %s: %w", clusterName, err)
		}

		ccr.logger.Info("Remote cluster configured",
			zap.String("cluster", clusterName),
			zap.String("mode", clusterConfig.Mode))
	}

	return nil
}

// AddRemoteCluster adds a remote cluster configuration
func (ccr *CCRManager) AddRemoteCluster(ctx context.Context, clusterName string, cluster RemoteCluster) error {
	settings := make(map[string]interface{})

	if cluster.Mode == "proxy" {
		settings[fmt.Sprintf("cluster.remote.%s.mode", clusterName)] = "proxy"
		settings[fmt.Sprintf("cluster.remote.%s.proxy_address", clusterName)] = cluster.ProxyAddress
		if cluster.ServerName != "" {
			settings[fmt.Sprintf("cluster.remote.%s.server_name", clusterName)] = cluster.ServerName
		}
		if cluster.ProxySocketConnections > 0 {
			settings[fmt.Sprintf("cluster.remote.%s.proxy_socket_connections", clusterName)] = cluster.ProxySocketConnections
		}
	} else {
		// Default to sniff mode
		settings[fmt.Sprintf("cluster.remote.%s.seeds", clusterName)] = cluster.Seeds
		settings[fmt.Sprintf("cluster.remote.%s.mode", clusterName)] = "sniff"
	}

	// Apply settings
	settingsPayload := map[string]interface{}{
		"persistent": settings,
	}

	settingsBytes, err := json.Marshal(settingsPayload)
	if err != nil {
		return fmt.Errorf("failed to serialize cluster settings: %w", err)
	}

	req := esapi.ClusterPutSettingsRequest{
		Body: bytes.NewReader(settingsBytes),
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to add remote cluster: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("add remote cluster failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// RemoveRemoteCluster removes a remote cluster configuration
func (ccr *CCRManager) RemoveRemoteCluster(ctx context.Context, clusterName string) error {
	settings := map[string]interface{}{
		"persistent": map[string]interface{}{
			fmt.Sprintf("cluster.remote.%s.*", clusterName): nil,
		},
	}

	settingsBytes, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to serialize cluster settings: %w", err)
	}

	req := esapi.ClusterPutSettingsRequest{
		Body: bytes.NewReader(settingsBytes),
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to remove remote cluster: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("remove remote cluster failed with status %s: %s", res.Status(), string(body))
	}

	return nil
}

// GetRemoteClusters retrieves information about remote clusters
func (ccr *CCRManager) GetRemoteClusters(ctx context.Context) ([]RemoteClusterInfo, error) {
	req := esapi.ClusterRemoteInfoRequest{}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote clusters: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get remote clusters failed with status %s: %s", res.Status(), string(body))
	}

	var response map[string]struct {
		Seeds               []string `json:"seeds"`
		Connected           bool     `json:"connected"`
		Mode                string   `json:"mode"`
		SkipUnavailable     bool     `json:"skip_unavailable"`
		MaxConnectionsPerCluster int `json:"max_connections_per_cluster"`
		InitialConnectTimeout string `json:"initial_connect_timeout"`
		NumNodesConnected   int      `json:"num_nodes_connected"`
		MaxConnections      int      `json:"max_connections"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse remote clusters response: %w", err)
	}

	var clusters []RemoteClusterInfo
	for clusterName, clusterData := range response {
		cluster := RemoteClusterInfo{
			Name:                     clusterName,
			Seeds:                    clusterData.Seeds,
			Connected:                clusterData.Connected,
			Mode:                     clusterData.Mode,
			SkipUnavailable:          clusterData.SkipUnavailable,
			MaxConnectionsPerCluster: clusterData.MaxConnectionsPerCluster,
			InitialConnectTimeout:    clusterData.InitialConnectTimeout,
			NumNodesConnected:        clusterData.NumNodesConnected,
			MaxConnections:           clusterData.MaxConnections,
		}
		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

// CreateFollowerIndex creates a follower index
func (ccr *CCRManager) CreateFollowerIndex(ctx context.Context, followerIndex string, config FollowerIndex) error {
	followerConfig := map[string]interface{}{
		"remote_cluster":                    config.RemoteCluster,
		"leader_index":                      config.LeaderIndex,
		"max_read_request_operation_count":  config.MaxReadRequestOpCount,
		"max_outstanding_read_requests":     config.MaxOutstandingReadRequests,
		"max_read_request_size":             config.MaxReadRequestSize,
		"max_write_request_operation_count": config.MaxWriteRequestOpCount,
		"max_outstanding_write_requests":    config.MaxOutstandingWriteRequests,
		"max_write_request_size":            config.MaxWriteRequestSize,
		"max_write_buffer_count":            config.MaxWriteBufferCount,
		"max_write_buffer_size":             config.MaxWriteBufferSize,
		"max_retry_delay":                   config.MaxRetryDelay.String(),
		"read_poll_timeout":                 config.ReadPollTimeout.String(),
	}

	configBytes, err := json.Marshal(followerConfig)
	if err != nil {
		return fmt.Errorf("failed to serialize follower config: %w", err)
	}

	req := esapi.CCRFollowRequest{
		Index: followerIndex,
		Body:  bytes.NewReader(configBytes),
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to create follower index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create follower index failed with status %s: %s", res.Status(), string(body))
	}

	ccr.logger.Info("Follower index created",
		zap.String("follower_index", followerIndex),
		zap.String("leader_index", config.LeaderIndex),
		zap.String("remote_cluster", config.RemoteCluster))

	return nil
}

// SetupFollowerIndices creates all configured follower indices
func (ccr *CCRManager) SetupFollowerIndices(ctx context.Context) error {
	if !ccr.config.CCR.Enabled {
		return nil
	}

	ccr.logger.Info("Setting up follower indices")

	for followerIndex, config := range ccr.config.CCR.FollowerIndices {
		if err := ccr.CreateFollowerIndex(ctx, followerIndex, config); err != nil {
			return fmt.Errorf("failed to create follower index %s: %w", followerIndex, err)
		}
	}

	return nil
}

// UnfollowIndex stops following a leader index
func (ccr *CCRManager) UnfollowIndex(ctx context.Context, followerIndex string) error {
	req := esapi.CCRUnfollowRequest{
		Index: followerIndex,
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to unfollow index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("unfollow index failed with status %s: %s", res.Status(), string(body))
	}

	ccr.logger.Info("Index unfollowed", zap.String("index", followerIndex))
	return nil
}

// PauseFollowerIndex pauses replication for a follower index
func (ccr *CCRManager) PauseFollowerIndex(ctx context.Context, followerIndex string) error {
	req := esapi.CCRPauseFollowRequest{
		Index: followerIndex,
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to pause follower index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("pause follower index failed with status %s: %s", res.Status(), string(body))
	}

	ccr.logger.Info("Follower index paused", zap.String("index", followerIndex))
	return nil
}

// ResumeFollowerIndex resumes replication for a follower index
func (ccr *CCRManager) ResumeFollowerIndex(ctx context.Context, followerIndex string) error {
	req := esapi.CCRResumeFollowRequest{
		Index: followerIndex,
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to resume follower index: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("resume follower index failed with status %s: %s", res.Status(), string(body))
	}

	ccr.logger.Info("Follower index resumed", zap.String("index", followerIndex))
	return nil
}

// GetFollowerStats retrieves statistics for follower indices
func (ccr *CCRManager) GetFollowerStats(ctx context.Context, indices ...string) ([]FollowerStats, error) {
	var indexNames []string
	if len(indices) > 0 {
		indexNames = indices
	} else {
		indexNames = []string{"*"}
	}

	req := esapi.CCRFollowStatsRequest{
		Index: indexNames,
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return nil, fmt.Errorf("failed to get follower stats: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("get follower stats failed with status %s: %s", res.Status(), string(body))
	}

	var response struct {
		Indices []struct {
			Index                        string    `json:"index"`
			RemoteCluster               string    `json:"remote_cluster"`
			LeaderIndex                 string    `json:"leader_index"`
			Status                      string    `json:"status"`
			ParametersStatus            string    `json:"parameters_status"`
			OutstandingReadRequests     int       `json:"outstanding_read_requests"`
			OutstandingWriteRequests    int       `json:"outstanding_write_requests"`
			WriteBufferOperationCount   int       `json:"write_buffer_operation_count"`
			FollowerGlobalCheckpoint    int64     `json:"follower_global_checkpoint"`
			LeaderGlobalCheckpoint      int64     `json:"leader_global_checkpoint"`
			FollowerMaxSeqNo            int64     `json:"follower_max_seq_no"`
			LeaderMaxSeqNo              int64     `json:"leader_max_seq_no"`
			LastRequestedSeqNo          int64     `json:"last_requested_seq_no"`
			NumberOfFailedFollowAttempts int      `json:"number_of_failed_follow_attempts"`
			TotalReadTimeMillis         int       `json:"total_read_time_millis"`
			TotalReadRemoteExecTimeMillis int     `json:"total_read_remote_exec_time_millis"`
			SuccessfulReadRequests      int       `json:"successful_read_requests"`
			FailedReadRequests          int       `json:"failed_read_requests"`
			OperationsRetrieved         int       `json:"operations_retrieved"`
			BytesRead                   int64     `json:"bytes_read"`
			TotalWriteTimeMillis        int       `json:"total_write_time_millis"`
			SuccessfulWriteRequests     int       `json:"successful_write_requests"`
			FailedWriteRequests         int       `json:"failed_write_requests"`
			OperationsIndexed           int       `json:"operations_indexed"`
			SinceLastAutoFollowFetch    string    `json:"since_last_auto_follow_fetch"`
		} `json:"indices"`
	}

	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to parse follower stats response: %w", err)
	}

	var stats []FollowerStats
	for _, indexData := range response.Indices {
		lastFetch, _ := time.Parse(time.RFC3339, indexData.SinceLastAutoFollowFetch)

		stat := FollowerStats{
			Index:                         indexData.Index,
			RemoteCluster:                indexData.RemoteCluster,
			LeaderIndex:                  indexData.LeaderIndex,
			Status:                       indexData.Status,
			ParametersStatus:             indexData.ParametersStatus,
			OutstandingReadRequests:      indexData.OutstandingReadRequests,
			OutstandingWriteRequests:     indexData.OutstandingWriteRequests,
			WriteBufferOperationCount:    indexData.WriteBufferOperationCount,
			FollowerGlobalCheckpoint:     indexData.FollowerGlobalCheckpoint,
			LeaderGlobalCheckpoint:       indexData.LeaderGlobalCheckpoint,
			FollowerMaxSeqNo:             indexData.FollowerMaxSeqNo,
			LeaderMaxSeqNo:               indexData.LeaderMaxSeqNo,
			LastRequestedSeqNo:           indexData.LastRequestedSeqNo,
			NumberOfFailedFollowAttempts: indexData.NumberOfFailedFollowAttempts,
			TotalReadTimeMillis:          indexData.TotalReadTimeMillis,
			TotalReadRemoteExecTimeMillis: indexData.TotalReadRemoteExecTimeMillis,
			SuccessfulReadRequests:       indexData.SuccessfulReadRequests,
			FailedReadRequests:           indexData.FailedReadRequests,
			OperationsRetrieved:          indexData.OperationsRetrieved,
			BytesRead:                    indexData.BytesRead,
			TotalWriteTimeMillis:         indexData.TotalWriteTimeMillis,
			SuccessfulWriteRequests:      indexData.SuccessfulWriteRequests,
			FailedWriteRequests:          indexData.FailedWriteRequests,
			OperationsIndexed:            indexData.OperationsIndexed,
			SinceLastAutoFollowFetch:     lastFetch,
		}

		stats = append(stats, stat)
	}

	return stats, nil
}

// CreateAutoFollowPattern creates an auto-follow pattern
func (ccr *CCRManager) CreateAutoFollowPattern(ctx context.Context, patternName string, pattern AutoFollowPattern) error {
	patternBytes, err := json.Marshal(pattern)
	if err != nil {
		return fmt.Errorf("failed to serialize auto-follow pattern: %w", err)
	}

	req := esapi.CCRPutAutoFollowPatternRequest{
		Name: patternName,
		Body: bytes.NewReader(patternBytes),
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to create auto-follow pattern: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("create auto-follow pattern failed with status %s: %s", res.Status(), string(body))
	}

	ccr.logger.Info("Auto-follow pattern created",
		zap.String("pattern", patternName))

	return nil
}

// DeleteAutoFollowPattern deletes an auto-follow pattern
func (ccr *CCRManager) DeleteAutoFollowPattern(ctx context.Context, patternName string) error {
	req := esapi.CCRDeleteAutoFollowPatternRequest{
		Name: patternName,
	}

	res, err := req.Do(ctx, ccr.client.client)
	if err != nil {
		return fmt.Errorf("failed to delete auto-follow pattern: %w", err)
	}
	defer res.Body.Close()

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("delete auto-follow pattern failed with status %s: %s", res.Status(), string(body))
	}

	ccr.logger.Info("Auto-follow pattern deleted",
		zap.String("pattern", patternName))

	return nil
}

// MonitorReplication monitors CCR replication status
func (ccr *CCRManager) MonitorReplication(ctx context.Context) error {
	if !ccr.config.CCR.Enabled {
		return nil
	}

	// Get follower statistics
	stats, err := ccr.GetFollowerStats(ctx)
	if err != nil {
		return fmt.Errorf("failed to get follower stats: %w", err)
	}

	for _, stat := range stats {
		lag := stat.LeaderGlobalCheckpoint - stat.FollowerGlobalCheckpoint
		
		ccr.logger.Info("CCR replication status",
			zap.String("follower_index", stat.Index),
			zap.String("leader_index", stat.LeaderIndex),
			zap.String("remote_cluster", stat.RemoteCluster),
			zap.String("status", stat.Status),
			zap.Int64("replication_lag", lag),
			zap.Int("failed_read_requests", stat.FailedReadRequests),
			zap.Int("failed_write_requests", stat.FailedWriteRequests),
			zap.Int("failed_follow_attempts", stat.NumberOfFailedFollowAttempts))

		// Alert on high lag or failures
		if lag > 1000 {
			ccr.logger.Warn("High replication lag detected",
				zap.String("follower_index", stat.Index),
				zap.Int64("lag", lag))
		}

		if stat.FailedReadRequests > 0 || stat.FailedWriteRequests > 0 {
			ccr.logger.Warn("CCR failures detected",
				zap.String("follower_index", stat.Index),
				zap.Int("failed_reads", stat.FailedReadRequests),
				zap.Int("failed_writes", stat.FailedWriteRequests))
		}
	}

	// Check remote cluster connectivity
	clusters, err := ccr.GetRemoteClusters(ctx)
	if err != nil {
		return fmt.Errorf("failed to get remote clusters: %w", err)
	}

	for _, cluster := range clusters {
		ccr.logger.Info("Remote cluster status",
			zap.String("cluster", cluster.Name),
			zap.Bool("connected", cluster.Connected),
			zap.Int("nodes_connected", cluster.NumNodesConnected))

		if !cluster.Connected {
			ccr.logger.Error("Remote cluster disconnected",
				zap.String("cluster", cluster.Name))
		}
	}

	return nil
}

// ValidateConfiguration validates CCR configuration
func (ccr *CCRManager) ValidateConfiguration(ctx context.Context) error {
	if !ccr.config.CCR.Enabled {
		return nil
	}

	ccr.logger.Info("Validating CCR configuration")

	// Check remote clusters
	clusters, err := ccr.GetRemoteClusters(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate remote clusters: %w", err)
	}

	for _, cluster := range clusters {
		if !cluster.Connected {
			return fmt.Errorf("remote cluster not connected: %s", cluster.Name)
		}
	}

	// Check follower indices
	stats, err := ccr.GetFollowerStats(ctx)
	if err != nil {
		return fmt.Errorf("failed to validate follower indices: %w", err)
	}

	for _, stat := range stats {
		if stat.Status != "active" {
			ccr.logger.Warn("Follower index not active",
				zap.String("index", stat.Index),
				zap.String("status", stat.Status))
		}
	}

	ccr.logger.Info("CCR configuration validated successfully")
	return nil
}