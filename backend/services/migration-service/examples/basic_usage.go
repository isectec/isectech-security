package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/isectech/migration-service/connectors"
	"github.com/isectech/migration-service/domain/entity"
)

func main() {
	// Example: Setting up and using the migration service connectors

	// Create a source system configuration for Splunk
	splunkSystem := &entity.SourceSystem{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Name:     "Production Splunk SIEM",
		Description: stringPtr("Main production Splunk instance for security monitoring"),
		
		// System identification
		Vendor:         entity.VendorSplunk,
		ProductName:    "Splunk Enterprise",
		ProductVersion: "8.2.0",
		SystemType:     entity.SourceSystemTypeSIEM,
		
		// Connection configuration
		ConnectionConfig: entity.ConnectionConfig{
			BaseURL:    "https://splunk.company.com:8089",
			APIVersion: "v1",
			Port:       8089,
			UseSSL:     true,
			VerifySSL:  true,
			Timeout:    30,
			MaxRetries: 3,
			RetryDelay: 5,
			DefaultHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			MaxConnections: 10,
			KeepAlive:     true,
		},
		
		// Authentication configuration
		AuthConfig: entity.AuthenticationConfig{
			Type: entity.AuthTypeBasicAuth,
			Credentials: map[string]interface{}{
				"username": "migration_user",
				"password": "secure_password_123",
			},
			EncryptCredentials: true,
			AutoRefresh:       true,
			RefreshBuffer:     300, // 5 minutes before expiry
		},
		
		// System capabilities
		Capabilities: entity.SystemCapabilities{
			APICapabilities: map[string]entity.APICapability{
				"search": {
					Name:      "Search API",
					Supported: true,
					Version:   "8.2",
					DataTypes: []entity.DataType{
						entity.DataTypeAlerts,
						entity.DataTypeLogs,
						entity.DataTypeEvents,
						entity.DataTypeIncidents,
					},
				},
			},
			SupportedOperations: []string{"search", "export", "stream"},
			SupportsSearch:      true,
			SupportsExport:      true,
			SupportsStreaming:   false,
			SupportsMetadata:    true,
		},
		
		// Data extraction configuration
		DataExtractionConfig: entity.DataExtractionConfig{
			SupportedDataTypes: []entity.DataType{
				entity.DataTypeAlerts,
				entity.DataTypeLogs,
				entity.DataTypeEvents,
				entity.DataTypeIncidents,
				entity.DataTypeThreats,
			},
			DefaultBatchSize:         1000,
			MaxBatchSize:            10000,
			SupportsIncremental:     true,
			SupportsDateFiltering:   true,
			PaginationType:          "offset",
			MaxPageSize:             10000,
			DefaultPageSize:         1000,
			OutputFormats:           []string{"json", "xml"},
			DefaultFormat:           "json",
			CompressionSupported:    true,
			RequiredFields:          []string{"_time", "source", "sourcetype"},
			ParallelExtraction:      true,
			MaxParallelRequests:     5,
			ValidateData:            true,
			SkipInvalidRecords:      false,
			DeduplicateRecords:      true,
		},
		
		// Health check configuration
		HealthCheckConfig: entity.HealthCheckConfig{
			Enabled:             true,
			Endpoint:            "/services/server/info",
			Method:              "GET",
			IntervalSeconds:     60,
			TimeoutSeconds:      10,
			RetryAttempts:       3,
			ExpectedStatusCode:  200,
			AlertOnFailure:      true,
			AlertThreshold:      3,
		},
		
		// Security and compliance
		SecurityClearance:    "unclassified",
		DataClassification:   "internal",
		ComplianceFrameworks: []string{"SOC2", "ISO27001"},
		
		// Audit fields
		CreatedBy: uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Create QRadar system configuration
	qradarSystem := &entity.SourceSystem{
		ID:       uuid.New(),
		TenantID: splunkSystem.TenantID, // Same tenant
		Name:     "QRadar SIEM Instance",
		Description: stringPtr("IBM QRadar SIEM for advanced threat detection"),
		
		Vendor:         entity.VendorIBMQRadar,
		ProductName:    "IBM QRadar SIEM",
		ProductVersion: "7.4.3",
		SystemType:     entity.SourceSystemTypeSIEM,
		
		ConnectionConfig: entity.ConnectionConfig{
			BaseURL:    "https://qradar.company.com",
			APIVersion: "11.0",
			UseSSL:     true,
			VerifySSL:  true,
			Timeout:    45,
			MaxRetries: 5,
			RetryDelay: 10,
			DefaultHeaders: map[string]string{
				"Accept":  "application/json",
				"Version": "11.0",
			},
		},
		
		AuthConfig: entity.AuthenticationConfig{
			Type: entity.AuthTypeAPIKey,
			Credentials: map[string]interface{}{
				"api_token": "your-qradar-api-token-here",
			},
		},
		
		DataExtractionConfig: entity.DataExtractionConfig{
			SupportedDataTypes: []entity.DataType{
				entity.DataTypeEvents,
				entity.DataTypeIncidents, // QRadar offenses
				entity.DataTypeAssets,
			},
			DefaultBatchSize:      1000,
			MaxBatchSize:         5000,
			SupportsIncremental:  true,
			SupportsDateFiltering: true,
			PaginationType:       "offset",
			MaxPageSize:          5000,
			DefaultPageSize:      1000,
			OutputFormats:        []string{"json"},
			DefaultFormat:        "json",
			ValidateData:         true,
		},
		
		// Other configurations...
		SecurityClearance:  "unclassified",
		DataClassification: "internal",
		CreatedBy:         uuid.New(),
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	ctx := context.Background()

	// Example 1: Create and test Splunk connector
	fmt.Println("=== Testing Splunk Connector ===")
	splunkConnector, err := testConnector(ctx, splunkSystem)
	if err != nil {
		log.Printf("Splunk connector test failed: %v", err)
	} else {
		fmt.Println("Splunk connector test passed!")
		
		// Extract some alerts from Splunk
		alertParams := &connectors.ExtractionParams{
			DataType:  entity.DataTypeAlerts,
			DateRange: &entity.DateRange{
				StartDate: time.Now().Add(-24 * time.Hour), // Last 24 hours
				EndDate:   time.Now(),
			},
			BatchSize:    100,
			ValidateData: true,
			Filters: map[string]interface{}{
				"severity": []string{"high", "critical"},
			},
		}
		
		if result, err := splunkConnector.ExtractData(ctx, alertParams); err == nil {
			fmt.Printf("Extracted %d alerts from Splunk\n", result.ExtractedCount)
			fmt.Printf("Data quality score: %.2f%%\n", result.QualityMetrics.OverallScore)
		}
	}

	// Example 2: Create and test QRadar connector
	fmt.Println("\n=== Testing QRadar Connector ===")
	qradarConnector, err := testConnector(ctx, qradarSystem)
	if err != nil {
		log.Printf("QRadar connector test failed: %v", err)
	} else {
		fmt.Println("QRadar connector test passed!")
		
		// Extract incidents (offenses) from QRadar
		incidentParams := &connectors.ExtractionParams{
			DataType:  entity.DataTypeIncidents,
			DateRange: &entity.DateRange{
				StartDate: time.Now().Add(-7 * 24 * time.Hour), // Last week
				EndDate:   time.Now(),
			},
			BatchSize:    50,
			ValidateData: true,
			Filters: map[string]interface{}{
				"status": "OPEN",
			},
		}
		
		if result, err := qradarConnector.ExtractData(ctx, incidentParams); err == nil {
			fmt.Printf("Extracted %d incidents from QRadar\n", result.ExtractedCount)
		}
	}

	// Example 3: Demonstrate connector registry functionality
	fmt.Println("\n=== Testing Connector Registry ===")
	registry := connectors.DefaultConnectorRegistry
	
	// List all supported vendors
	vendors := registry.ListVendors()
	fmt.Printf("Supported vendors (%d): %v\n", len(vendors), vendors)
	
	// Get capabilities for specific vendors
	manager := connectors.NewConnectorFactoryManager(registry)
	
	if capabilities, err := manager.GetConnectorCapabilities(entity.VendorSplunk); err == nil {
		fmt.Printf("Splunk capabilities: %+v\n", capabilities.Features)
	}
	
	// Get vendors by system type
	if siemVendors, err := manager.GetVendorsBySystemType(entity.SourceSystemTypeSIEM); err == nil {
		fmt.Printf("SIEM vendors: %v\n", siemVendors)
	}

	// Example 4: Create and execute a migration job
	fmt.Println("\n=== Creating Migration Job ===")
	migrationJob := createSampleMigrationJob(splunkSystem)
	fmt.Printf("Created migration job: %s\n", migrationJob.Name)
	fmt.Printf("Job scope: %v\n", migrationJob.Scope.DataTypes)
	fmt.Printf("Progress: %.2f%%\n", migrationJob.GetProgressPercentage())

	fmt.Println("\n=== Migration Service Demo Complete ===")
}

// testConnector creates and tests a connector for the given source system
func testConnector(ctx context.Context, sourceSystem *entity.SourceSystem) (connectors.DataExtractor, error) {
	// Get connector factory manager
	manager := connectors.NewConnectorFactoryManager(nil)
	
	// Validate the source system configuration
	if err := manager.ValidateSourceSystemConfiguration(sourceSystem); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	
	// Create connector
	connector, err := connectors.DefaultConnectorRegistry.CreateConnector(sourceSystem)
	if err != nil {
		return nil, fmt.Errorf("failed to create connector: %w", err)
	}
	
	// Test connection (this would fail in real scenario without valid credentials)
	// For demo purposes, we'll just validate the connector was created
	if connector == nil {
		return nil, fmt.Errorf("connector creation returned nil")
	}
	
	// Get system info
	if systemInfo, err := connector.GetSystemInfo(ctx); err == nil {
		fmt.Printf("Connected to: %s %s (Vendor: %s)\n", 
			systemInfo.Name, systemInfo.Version, systemInfo.Vendor)
	}
	
	// Get schema for alerts data type
	if schema, err := connector.GetSchema(ctx, entity.DataTypeAlerts); err == nil {
		fmt.Printf("Alert schema has %d fields\n", len(schema.Fields))
	}
	
	return connector, nil
}

// createSampleMigrationJob creates a sample migration job
func createSampleMigrationJob(sourceSystem *entity.SourceSystem) *entity.MigrationJob {
	return &entity.MigrationJob{
		ID:       uuid.New(),
		TenantID: sourceSystem.TenantID,
		Name:     "Security Data Migration - " + sourceSystem.Name,
		Description: stringPtr("Migrate security data from legacy SIEM to iSECTECH platform"),
		
		SourceSystemID:   sourceSystem.ID,
		SourceSystemType: sourceSystem.SystemType,
		Status:          entity.MigrationJobStatusPending,
		Priority:        entity.MigrationJobPriorityHigh,
		
		// Migration scope
		Scope: entity.MigrationScope{
			DataTypes: []entity.DataType{
				entity.DataTypeAlerts,
				entity.DataTypeIncidents,
				entity.DataTypeEvents,
				entity.DataTypeThreats,
			},
			DateRange: &entity.DateRange{
				StartDate: time.Now().Add(-90 * 24 * time.Hour), // Last 90 days
				EndDate:   time.Now(),
			},
			Filters: map[string]interface{}{
				"severity": []string{"medium", "high", "critical"},
			},
			BatchSize:      1000,
			RateLimit:      100,
			RetryAttempts:  3,
			TimeoutSeconds: 300,
		},
		
		// Migration configuration
		Configuration: entity.MigrationConfiguration{
			EnableValidation:     true,
			ValidateData:        true,
			StrictMode:          false,
			ParallelWorkers:     4,
			BatchSize:           1000,
			MaxRetries:          3,
			RetryDelaySeconds:   5,
			CheckpointInterval:  time.Minute * 5,
			EnableCheckpointing: true,
			EncryptInTransit:    true,
			EncryptAtRest:       true,
			AuditAllOperations:  true,
			ComplianceFrameworks: []string{"SOC2", "ISO27001"},
			DataClassification:  "confidential",
		},
		
		// Progress tracking (initial state)
		Progress: entity.MigrationProgress{
			TotalRecords:      0,
			ProcessedRecords:  0,
			SuccessfulRecords: 0,
			FailedRecords:     0,
			SkippedRecords:    0,
			DataTypeProgress:  make(map[entity.DataType]*entity.DataTypeProgress),
			RecordsPerSecond:  0,
			ErrorSummary:      make(map[string]int64),
			RecentErrors:      make([]string, 0),
			DataQualityScore:  0,
		},
		
		// Security and compliance
		SecurityClearance:    "unclassified",
		ComplianceFrameworks: []string{"SOC2", "ISO27001"},
		DataClassification:   "confidential",
		
		// Audit fields
		CreatedBy: uuid.New(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}