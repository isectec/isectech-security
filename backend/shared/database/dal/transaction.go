package dal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// TransactionCoordinator manages distributed transactions across multiple databases
type TransactionCoordinator struct {
	config          TransactionConfig
	logger          *zap.Logger
	activeTransactions map[string]*DistributedTransaction
	transactionHistory []TransactionRecord
	mu              sync.RWMutex
	nextTxnID       int64
	closed          bool
}

// DistributedTransaction represents a distributed transaction across multiple databases
type DistributedTransaction struct {
	ID            string
	TenantID      string
	StartTime     time.Time
	Timeout       time.Duration
	Status        TransactionStatus
	Participants  []*TransactionParticipant
	Operations    []TransactionOperation
	IsolationLevel string
	RetryCount    int
	mu            sync.RWMutex
}

// TransactionParticipant represents a database participating in a distributed transaction
type TransactionParticipant struct {
	Database    string
	TransactionID interface{} // Database-specific transaction ID
	Status      ParticipantStatus
	PreparedAt  *time.Time
	CommittedAt *time.Time
	RolledBackAt *time.Time
	LastError   string
}

// TransactionOperation represents an operation within a transaction
type TransactionOperation struct {
	ID          string
	Database    string
	Operation   string
	Query       string
	Parameters  []interface{}
	ExecutedAt  time.Time
	Duration    time.Duration
	Success     bool
	Error       string
	Retryable   bool
}

// TransactionRecord represents a completed transaction record
type TransactionRecord struct {
	ID              string
	TenantID        string
	StartTime       time.Time
	EndTime         time.Time
	Duration        time.Duration
	Status          TransactionStatus
	ParticipantCount int
	OperationCount  int
	RetryCount      int
	ErrorMessage    string
}

// TransactionStatus represents the status of a transaction
type TransactionStatus string

const (
	TxnStatusActive    TransactionStatus = "active"
	TxnStatusPreparing TransactionStatus = "preparing"
	TxnStatusPrepared  TransactionStatus = "prepared"
	TxnStatusCommitting TransactionStatus = "committing"
	TxnStatusCommitted TransactionStatus = "committed"
	TxnStatusAborting  TransactionStatus = "aborting"
	TxnStatusAborted   TransactionStatus = "aborted"
	TxnStatusFailed    TransactionStatus = "failed"
	TxnStatusTimedOut  TransactionStatus = "timed_out"
)

// ParticipantStatus represents the status of a transaction participant
type ParticipantStatus string

const (
	ParticipantStatusActive     ParticipantStatus = "active"
	ParticipantStatusPreparing  ParticipantStatus = "preparing"
	ParticipantStatusPrepared   ParticipantStatus = "prepared"
	ParticipantStatusCommitting ParticipantStatus = "committing"
	ParticipantStatusCommitted  ParticipantStatus = "committed"
	ParticipantStatusAborting   ParticipantStatus = "aborting"
	ParticipantStatusAborted    ParticipantStatus = "aborted"
	ParticipantStatusFailed     ParticipantStatus = "failed"
)

// TransactionOptions represents options for creating a transaction
type TransactionOptions struct {
	TenantID       string
	IsolationLevel string
	Timeout        time.Duration
	ReadOnly       bool
	Participants   []string // List of databases that will participate
	MaxRetries     int
}

// NewTransactionCoordinator creates a new transaction coordinator
func NewTransactionCoordinator(config TransactionConfig, logger *zap.Logger) (*TransactionCoordinator, error) {
	tc := &TransactionCoordinator{
		config:             config,
		logger:             logger,
		activeTransactions: make(map[string]*DistributedTransaction),
		transactionHistory: make([]TransactionRecord, 0),
		nextTxnID:          1,
	}

	logger.Info("Transaction coordinator initialized",
		zap.Bool("enabled", config.Enabled),
		zap.Bool("distributed_enabled", config.EnableDistributed),
		zap.Duration("default_timeout", config.TransactionTimeout))

	return tc, nil
}

// BeginTransaction starts a new distributed transaction
func (tc *TransactionCoordinator) BeginTransaction(ctx context.Context, opts *TransactionOptions) (*DistributedTransaction, error) {
	if !tc.config.Enabled {
		return nil, fmt.Errorf("transactions are disabled")
	}

	tc.mu.Lock()
	if tc.closed {
		tc.mu.Unlock()
		return nil, fmt.Errorf("transaction coordinator is closed")
	}

	// Generate transaction ID
	txnID := fmt.Sprintf("txn_%d_%d", time.Now().Unix(), tc.nextTxnID)
	tc.nextTxnID++
	tc.mu.Unlock()

	// Set defaults
	if opts == nil {
		opts = &TransactionOptions{}
	}
	if opts.IsolationLevel == "" {
		opts.IsolationLevel = tc.config.DefaultIsolationLevel
	}
	if opts.Timeout == 0 {
		opts.Timeout = tc.config.TransactionTimeout
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = tc.config.MaxRetries
	}

	// Create transaction
	txn := &DistributedTransaction{
		ID:             txnID,
		TenantID:       opts.TenantID,
		StartTime:      time.Now(),
		Timeout:        opts.Timeout,
		Status:         TxnStatusActive,
		Participants:   make([]*TransactionParticipant, 0),
		Operations:     make([]TransactionOperation, 0),
		IsolationLevel: opts.IsolationLevel,
		RetryCount:     0,
	}

	// Initialize participants
	for _, database := range opts.Participants {
		participant := &TransactionParticipant{
			Database: database,
			Status:   ParticipantStatusActive,
		}
		txn.Participants = append(txn.Participants, participant)
	}

	// Store transaction
	tc.mu.Lock()
	tc.activeTransactions[txnID] = txn
	tc.mu.Unlock()

	tc.logger.Info("Transaction started",
		zap.String("txn_id", txnID),
		zap.String("tenant_id", opts.TenantID),
		zap.Duration("timeout", opts.Timeout),
		zap.Strings("participants", opts.Participants))

	// Set timeout context
	go tc.handleTransactionTimeout(ctx, txn)

	return txn, nil
}

// AddOperation adds an operation to a transaction
func (tc *TransactionCoordinator) AddOperation(txnID string, database, operation, query string, parameters []interface{}) error {
	tc.mu.RLock()
	txn, exists := tc.activeTransactions[txnID]
	tc.mu.RUnlock()

	if !exists {
		return fmt.Errorf("transaction %s not found", txnID)
	}

	if txn.Status != TxnStatusActive {
		return fmt.Errorf("transaction %s is not active (status: %s)", txnID, txn.Status)
	}

	txn.mu.Lock()
	defer txn.mu.Unlock()

	opID := fmt.Sprintf("%s_op_%d", txnID, len(txn.Operations)+1)
	op := TransactionOperation{
		ID:         opID,
		Database:   database,
		Operation:  operation,
		Query:      query,
		Parameters: parameters,
		ExecutedAt: time.Now(),
		Retryable:  tc.isRetryableOperation(operation),
	}

	txn.Operations = append(txn.Operations, op)

	tc.logger.Debug("Operation added to transaction",
		zap.String("txn_id", txnID),
		zap.String("op_id", opID),
		zap.String("database", database),
		zap.String("operation", operation))

	return nil
}

// CommitTransaction commits a distributed transaction using 2PC
func (tc *TransactionCoordinator) CommitTransaction(ctx context.Context, txnID string) error {
	tc.mu.RLock()
	txn, exists := tc.activeTransactions[txnID]
	tc.mu.RUnlock()

	if !exists {
		return fmt.Errorf("transaction %s not found", txnID)
	}

	if txn.Status != TxnStatusActive {
		return fmt.Errorf("transaction %s is not active (status: %s)", txnID, txn.Status)
	}

	if !tc.config.EnableDistributed && len(txn.Participants) > 1 {
		return fmt.Errorf("distributed transactions are disabled but transaction has %d participants", len(txn.Participants))
	}

	tc.logger.Info("Committing transaction", zap.String("txn_id", txnID))

	// Single database transaction
	if len(txn.Participants) <= 1 {
		return tc.commitSingleDatabase(ctx, txn)
	}

	// Two-phase commit for distributed transaction
	return tc.commitTwoPhase(ctx, txn)
}

// AbortTransaction aborts a transaction
func (tc *TransactionCoordinator) AbortTransaction(ctx context.Context, txnID string, reason string) error {
	tc.mu.RLock()
	txn, exists := tc.activeTransactions[txnID]
	tc.mu.RUnlock()

	if !exists {
		return fmt.Errorf("transaction %s not found", txnID)
	}

	tc.logger.Info("Aborting transaction",
		zap.String("txn_id", txnID),
		zap.String("reason", reason))

	txn.mu.Lock()
	txn.Status = TxnStatusAborting
	txn.mu.Unlock()

	// Rollback all participants
	for _, participant := range txn.Participants {
		if err := tc.rollbackParticipant(ctx, txn, participant); err != nil {
			tc.logger.Error("Failed to rollback participant",
				zap.String("txn_id", txnID),
				zap.String("database", participant.Database),
				zap.Error(err))
		}
	}

	// Update status
	txn.mu.Lock()
	txn.Status = TxnStatusAborted
	txn.mu.Unlock()

	// Record transaction
	tc.recordTransaction(txn, reason)

	// Remove from active transactions
	tc.mu.Lock()
	delete(tc.activeTransactions, txnID)
	tc.mu.Unlock()

	return nil
}

// commitSingleDatabase commits a single database transaction
func (tc *TransactionCoordinator) commitSingleDatabase(ctx context.Context, txn *DistributedTransaction) error {
	txn.mu.Lock()
	txn.Status = TxnStatusCommitting
	txn.mu.Unlock()

	if len(txn.Participants) == 1 {
		participant := txn.Participants[0]
		if err := tc.commitParticipant(ctx, txn, participant); err != nil {
			// Rollback on failure
			tc.rollbackParticipant(ctx, txn, participant)
			
			txn.mu.Lock()
			txn.Status = TxnStatusFailed
			txn.mu.Unlock()
			
			tc.recordTransaction(txn, err.Error())
			return err
		}
	}

	txn.mu.Lock()
	txn.Status = TxnStatusCommitted
	txn.mu.Unlock()

	tc.recordTransaction(txn, "")
	
	// Remove from active transactions
	tc.mu.Lock()
	delete(tc.activeTransactions, txn.ID)
	tc.mu.Unlock()

	tc.logger.Info("Transaction committed", zap.String("txn_id", txn.ID))
	return nil
}

// commitTwoPhase commits a distributed transaction using two-phase commit
func (tc *TransactionCoordinator) commitTwoPhase(ctx context.Context, txn *DistributedTransaction) error {
	// Phase 1: Prepare
	txn.mu.Lock()
	txn.Status = TxnStatusPreparing
	txn.mu.Unlock()

	tc.logger.Info("Starting 2PC Phase 1 (Prepare)", zap.String("txn_id", txn.ID))

	for _, participant := range txn.Participants {
		if err := tc.prepareParticipant(ctx, txn, participant); err != nil {
			tc.logger.Error("Prepare phase failed",
				zap.String("txn_id", txn.ID),
				zap.String("database", participant.Database),
				zap.Error(err))
			
			// Abort transaction
			return tc.AbortTransaction(ctx, txn.ID, fmt.Sprintf("prepare failed: %v", err))
		}
	}

	txn.mu.Lock()
	txn.Status = TxnStatusPrepared
	txn.mu.Unlock()

	// Phase 2: Commit
	tc.logger.Info("Starting 2PC Phase 2 (Commit)", zap.String("txn_id", txn.ID))

	txn.mu.Lock()
	txn.Status = TxnStatusCommitting
	txn.mu.Unlock()

	var commitErrors []error
	for _, participant := range txn.Participants {
		if err := tc.commitParticipant(ctx, txn, participant); err != nil {
			tc.logger.Error("Commit phase failed",
				zap.String("txn_id", txn.ID),
				zap.String("database", participant.Database),
				zap.Error(err))
			commitErrors = append(commitErrors, err)
		}
	}

	if len(commitErrors) > 0 {
		txn.mu.Lock()
		txn.Status = TxnStatusFailed
		txn.mu.Unlock()
		
		tc.recordTransaction(txn, fmt.Sprintf("commit failed: %v", commitErrors))
		return fmt.Errorf("commit phase failed: %v", commitErrors)
	}

	txn.mu.Lock()
	txn.Status = TxnStatusCommitted
	txn.mu.Unlock()

	tc.recordTransaction(txn, "")
	
	// Remove from active transactions
	tc.mu.Lock()
	delete(tc.activeTransactions, txn.ID)
	tc.mu.Unlock()

	tc.logger.Info("2PC transaction committed", zap.String("txn_id", txn.ID))
	return nil
}

// prepareParticipant prepares a participant for commit
func (tc *TransactionCoordinator) prepareParticipant(ctx context.Context, txn *DistributedTransaction, participant *TransactionParticipant) error {
	participant.Status = ParticipantStatusPreparing
	
	// In a real implementation, this would call the database-specific prepare method
	// For now, we'll simulate the prepare phase
	time.Sleep(10 * time.Millisecond) // Simulate database prepare time
	
	now := time.Now()
	participant.PreparedAt = &now
	participant.Status = ParticipantStatusPrepared
	
	tc.logger.Debug("Participant prepared",
		zap.String("txn_id", txn.ID),
		zap.String("database", participant.Database))
	
	return nil
}

// commitParticipant commits a participant
func (tc *TransactionCoordinator) commitParticipant(ctx context.Context, txn *DistributedTransaction, participant *TransactionParticipant) error {
	participant.Status = ParticipantStatusCommitting
	
	// In a real implementation, this would call the database-specific commit method
	// For now, we'll simulate the commit
	time.Sleep(10 * time.Millisecond) // Simulate database commit time
	
	now := time.Now()
	participant.CommittedAt = &now
	participant.Status = ParticipantStatusCommitted
	
	tc.logger.Debug("Participant committed",
		zap.String("txn_id", txn.ID),
		zap.String("database", participant.Database))
	
	return nil
}

// rollbackParticipant rolls back a participant
func (tc *TransactionCoordinator) rollbackParticipant(ctx context.Context, txn *DistributedTransaction, participant *TransactionParticipant) error {
	participant.Status = ParticipantStatusAborting
	
	// In a real implementation, this would call the database-specific rollback method
	// For now, we'll simulate the rollback
	time.Sleep(10 * time.Millisecond) // Simulate database rollback time
	
	now := time.Now()
	participant.RolledBackAt = &now
	participant.Status = ParticipantStatusAborted
	
	tc.logger.Debug("Participant rolled back",
		zap.String("txn_id", txn.ID),
		zap.String("database", participant.Database))
	
	return nil
}

// handleTransactionTimeout handles transaction timeouts
func (tc *TransactionCoordinator) handleTransactionTimeout(ctx context.Context, txn *DistributedTransaction) {
	timer := time.NewTimer(txn.Timeout)
	defer timer.Stop()

	select {
	case <-timer.C:
		// Transaction timed out
		tc.logger.Warn("Transaction timed out", zap.String("txn_id", txn.ID))
		
		txn.mu.Lock()
		if txn.Status == TxnStatusActive || txn.Status == TxnStatusPreparing {
			txn.Status = TxnStatusTimedOut
			txn.mu.Unlock()
			tc.AbortTransaction(ctx, txn.ID, "timeout")
		} else {
			txn.mu.Unlock()
		}
	case <-ctx.Done():
		// Context cancelled
		return
	}
}

// isRetryableOperation determines if an operation is retryable
func (tc *TransactionCoordinator) isRetryableOperation(operation string) bool {
	// Define which operations are retryable
	retryableOps := map[string]bool{
		"select": true,
		"insert": false, // Generally not retryable due to uniqueness constraints
		"update": false, // Generally not retryable due to state changes
		"delete": false, // Generally not retryable due to state changes
	}
	
	return retryableOps[operation]
}

// recordTransaction records a completed transaction
func (tc *TransactionCoordinator) recordTransaction(txn *DistributedTransaction, errorMsg string) {
	record := TransactionRecord{
		ID:               txn.ID,
		TenantID:         txn.TenantID,
		StartTime:        txn.StartTime,
		EndTime:          time.Now(),
		Duration:         time.Since(txn.StartTime),
		Status:           txn.Status,
		ParticipantCount: len(txn.Participants),
		OperationCount:   len(txn.Operations),
		RetryCount:       txn.RetryCount,
		ErrorMessage:     errorMsg,
	}

	tc.mu.Lock()
	tc.transactionHistory = append(tc.transactionHistory, record)
	
	// Keep only last 1000 records
	if len(tc.transactionHistory) > 1000 {
		tc.transactionHistory = tc.transactionHistory[len(tc.transactionHistory)-1000:]
	}
	tc.mu.Unlock()

	tc.logger.Info("Transaction recorded",
		zap.String("txn_id", txn.ID),
		zap.String("status", string(txn.Status)),
		zap.Duration("duration", record.Duration))
}

// GetTransaction returns information about a transaction
func (tc *TransactionCoordinator) GetTransaction(txnID string) (*DistributedTransaction, error) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	txn, exists := tc.activeTransactions[txnID]
	if !exists {
		return nil, fmt.Errorf("transaction %s not found", txnID)
	}

	return txn, nil
}

// GetActiveTransactions returns all active transactions
func (tc *TransactionCoordinator) GetActiveTransactions() []*DistributedTransaction {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	transactions := make([]*DistributedTransaction, 0, len(tc.activeTransactions))
	for _, txn := range tc.activeTransactions {
		transactions = append(transactions, txn)
	}

	return transactions
}

// GetTransactionHistory returns transaction history
func (tc *TransactionCoordinator) GetTransactionHistory(limit int) []TransactionRecord {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	if limit <= 0 || limit > len(tc.transactionHistory) {
		limit = len(tc.transactionHistory)
	}

	history := make([]TransactionRecord, limit)
	startIdx := len(tc.transactionHistory) - limit
	copy(history, tc.transactionHistory[startIdx:])

	return history
}

// GetStats returns transaction coordinator statistics
func (tc *TransactionCoordinator) GetStats() map[string]interface{} {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	activeCount := len(tc.activeTransactions)
	totalCount := len(tc.transactionHistory)
	
	// Calculate success rate from history
	var successCount int
	for _, record := range tc.transactionHistory {
		if record.Status == TxnStatusCommitted {
			successCount++
		}
	}
	
	var successRate float64
	if totalCount > 0 {
		successRate = float64(successCount) / float64(totalCount)
	}

	return map[string]interface{}{
		"enabled":                tc.config.Enabled,
		"distributed_enabled":    tc.config.EnableDistributed,
		"active_transactions":    activeCount,
		"total_transactions":     totalCount,
		"success_rate":          successRate,
		"default_timeout":       tc.config.TransactionTimeout,
		"max_retries":           tc.config.MaxRetries,
	}
}

// Close closes the transaction coordinator
func (tc *TransactionCoordinator) Close() error {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if tc.closed {
		return nil
	}

	// Abort all active transactions
	for txnID, txn := range tc.activeTransactions {
		ctx := context.Background()
		tc.AbortTransaction(ctx, txnID, "coordinator shutdown")
		tc.logger.Warn("Aborted transaction due to shutdown", zap.String("txn_id", txn.ID))
	}

	tc.closed = true
	tc.logger.Info("Transaction coordinator closed")
	return nil
}