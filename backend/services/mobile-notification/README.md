# Mobile Notification Service

A comprehensive, enterprise-grade mobile notification system designed for iSECTECH's security platform. This service provides intelligent notification delivery with advanced batching, priority management, and delivery tracking capabilities.

## Overview

The Mobile Notification Service is a production-ready microservice that handles push notifications across multiple platforms (FCM, APNS, Web Push) with sophisticated features including:

- **Intelligent Priority Management**: Critical, warning, and informational notification levels with automatic escalation
- **Smart Batching**: Reduces notification fatigue while ensuring critical alerts are delivered immediately  
- **Comprehensive Tracking**: End-to-end delivery receipts and read confirmation tracking
- **Multi-Platform Support**: Firebase Cloud Messaging (Android), Apple Push Notification Service (iOS), and Web Push
- **Anti-Fatigue Protection**: Prevents user overwhelm with configurable daily limits and quiet hours
- **Multi-Tenant Architecture**: Secure tenant isolation with row-level security policies
- **Enterprise Security**: HMAC signature validation, IP filtering, and comprehensive audit logging

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────────┐
│                    Mobile Notification Service                  │
├─────────────────────────────────────────────────────────────────┤
│  HTTP API Layer                                                │
│  ├── Notification Management     ├── Device Registration       │
│  ├── Delivery Tracking          ├── Analytics & Reporting      │
│  └── Webhook Handlers           └── Health & Metrics           │
├─────────────────────────────────────────────────────────────────┤
│  Business Logic Layer                                          │
│  ├── Priority Service           ├── Batching Service          │
│  ├── Template Service           ├── Tracking Service          │
│  └── Preferences Service        └── Push Service              │
├─────────────────────────────────────────────────────────────────┤
│  Infrastructure Layer                                          │
│  ├── Push Providers             ├── Database Layer            │
│  │   ├── FCM Service            │   ├── Notification Repo     │
│  │   ├── APNS Service           │   ├── Device Repo           │
│  │   └── Unified Push Service   │   ├── Template Repo         │
│  │                              │   └── Receipt Repo          │
│  ├── Caching Layer (Redis)      └── Configuration Management  │
│  └── Background Processing                                     │
└─────────────────────────────────────────────────────────────────┘
```

### Database Schema

The service uses PostgreSQL with the following core entities:

- **notifications**: Core notification data with status tracking
- **device_registrations**: User device information for push delivery
- **notification_templates**: Reusable notification templates with localization
- **notification_preferences**: User-specific notification settings
- **notification_batches**: Batch processing metadata
- **notification_delivery_receipts**: Delivery and read tracking data

## Features

### 🚨 Intelligent Priority Management

- **Three Priority Levels**: Critical (immediate), Warning (5-minute batches), Informational (1-hour batches)
- **Automatic Escalation**: Aging notifications automatically escalate priority
- **Smart Scoring**: Multi-factor scoring system considers urgency, user preferences, content type, and timing
- **Duplicate Suppression**: Prevents spam with configurable deduplication windows

### 📦 Smart Batching System

- **Anti-Fatigue Protection**: Prevents notification overload with daily limits (default: 20/day)
- **Quiet Hours Support**: Extended batch intervals during user-defined quiet periods
- **Dynamic Batch Sizing**: Adjusts batch sizes based on priority and user engagement
- **Batch Summarization**: Creates intelligent summaries for multiple notifications

### 📊 Comprehensive Tracking

- **Delivery Receipts**: Real-time tracking of notification delivery status
- **Read Confirmations**: Track user interactions (opened, clicked, dismissed)
- **Webhook Integration**: Supports webhooks from FCM, APNS, and custom services
- **Analytics Dashboard**: Delivery rates, read rates, failure analysis, and trends

### 🌍 Multi-Platform Support

- **Firebase Cloud Messaging (FCM)**: Android and web push notifications
- **Apple Push Notification Service (APNS)**: iOS push notifications with rich content
- **Web Push**: Browser-based notifications with service worker support
- **Platform-Specific Features**: Rich notifications, action buttons, images, and sounds

### 🔒 Enterprise Security

- **Multi-Tenant Isolation**: Row-level security with tenant-based data isolation
- **Webhook Security**: HMAC-SHA256 signature validation and IP filtering
- **API Authentication**: Bearer token authentication with configurable API keys
- **Audit Logging**: Comprehensive logging of all notification activities

## Quick Start

### Prerequisites

- Go 1.21 or later
- PostgreSQL 13 or later
- Redis 6 or later
- Docker and Docker Compose (for development)

### Development Setup

1. **Clone the repository**:
```bash
git clone <repository-url>
cd mobile-notification
```

2. **Start dependencies with Docker Compose**:
```bash
docker-compose up -d postgres redis
```

3. **Set up environment variables**:
```bash
export DB_HOST=localhost
export DB_PASSWORD=notifications123
export FCM_PROJECT_ID=your-project-id
export FCM_CREDENTIALS_JSON='{"type":"service_account",...}'
export APNS_TOPIC=com.isectech.app
export APNS_CERTIFICATE_FILE=path/to/cert.p12
```

4. **Run database migrations**:
```bash
# Migrations run automatically on startup, or manually:
psql -h localhost -U notifications -d mobile_notifications -f infrastructure/database/migrations/001_initial_schema.sql
```

5. **Build and run the service**:
```bash
go build -o mobile-notification ./cmd/mobile-notification
./mobile-notification --config config/development.yaml
```

### Production Deployment

Use the included Docker setup for production deployment:

```bash
# Build production image
docker build -t mobile-notification:latest .

# Deploy with docker-compose
docker-compose -f docker-compose.yml up -d

# Or deploy to Kubernetes/Cloud Run
kubectl apply -f k8s/
```

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `DB_HOST` | PostgreSQL host | Yes | - |
| `DB_PASSWORD` | PostgreSQL password | Yes | - |
| `FCM_PROJECT_ID` | Firebase project ID | No* | - |
| `FCM_CREDENTIALS_JSON` | FCM service account JSON | No* | - |
| `APNS_TOPIC` | iOS app bundle ID | No* | - |
| `APNS_CERTIFICATE_FILE` | APNS certificate path | No* | - |
| `REDIS_HOST` | Redis host | No | localhost |
| `LOG_LEVEL` | Logging level | No | info |

*At least one push service (FCM or APNS) must be configured.

### Configuration File

Create a `config.yaml` file for advanced configuration:

```yaml
server:
  port: 8080
  host: "0.0.0.0"

database:
  host: localhost
  port: 5432
  username: notifications
  database: mobile_notifications
  ssl_mode: disable

push:
  fcm:
    project_id: "your-project-id"
    credentials_file: "path/to/service-account.json"
    batch_size: 500
    max_retries: 3
  apns:
    auth_type: "certificate"
    certificate_file: "path/to/cert.p12" 
    topic: "com.isectech.app"
    production: false

batching:
  enable_batching: true
  critical_batch_interval: 0      # Immediate
  warning_batch_interval: 300     # 5 minutes
  informational_batch_interval: 3600  # 1 hour
  max_notifications_per_user: 20
  respect_quiet_hours: true

priority:
  enable_escalation: true
  warning_escalation_time: 1800   # 30 minutes
  enable_suppression: true
  duplicate_window: 300           # 5 minutes
```

## API Documentation

### Send Notification

```bash
POST /api/v1/notifications
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
  "user_id": "123e4567-e89b-12d3-a456-426614174001", 
  "title": "Critical Security Alert",
  "body": "Suspicious login detected from unknown location",
  "priority": "critical",
  "platform": "fcm",
  "device_token": "device-token-here",
  "data": {
    "alert_type": "login_anomaly",
    "severity": "high"
  },
  "action_url": "https://app.isectech.com/alerts/12345"
}
```

### Register Device

```bash
POST /api/v1/devices
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "tenant_id": "123e4567-e89b-12d3-a456-426614174000",
  "user_id": "123e4567-e89b-12d3-a456-426614174001",
  "device_token": "device-token-here",
  "platform": "fcm",
  "app_version": "1.2.3",
  "os_version": "Android 12",
  "language": "en",
  "timezone": "America/New_York"
}
```

### Track Read Status

```bash
POST /api/v1/notifications/{id}/read
Content-Type: application/json
Authorization: Bearer <api-key>

{
  "user_id": "123e4567-e89b-12d3-a456-426614174001",
  "device_token": "device-token-here", 
  "interaction_type": "opened",
  "metadata": {
    "source": "notification_tray"
  }
}
```

### Get Delivery Analytics

```bash
GET /api/v1/analytics?tenant_id={tenant_id}&from={from_date}&to={to_date}
Authorization: Bearer <api-key>
```

## Client SDK Usage

### Go Client

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "mobile-notification/client"
    "github.com/google/uuid"
)

func main() {
    // Create client
    config := client.ClientConfig{
        BaseURL: "https://notifications.isectech.com",
        APIKey:  "your-api-key",
        Timeout: 30 * time.Second,
    }
    
    client := client.NewNotificationClient(config)
    
    // Send critical notification
    tenantID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
    userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")
    
    notification := client.NewCriticalNotification(
        tenantID, 
        userID,
        "device-token-here",
        "Security Alert",
        "Suspicious activity detected",
    )
    
    resp, err := client.SendNotification(context.Background(), notification)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Notification sent: %s\n", resp.ID)
    
    // Register device
    device := client.NewDeviceRegistration(
        tenantID,
        userID, 
        "device-token-here",
        "fcm",
    )
    
    _, err = client.RegisterDevice(context.Background(), device)
    if err != nil {
        panic(err)
    }
    
    // Confirm read
    read := client.NewReadConfirmation(
        resp.ID,
        userID,
        "device-token-here", 
        "opened",
    )
    
    err = client.ConfirmRead(context.Background(), read)
    if err != nil {
        panic(err)
    }
}
```

## Monitoring and Observability

### Health Checks

- **Health**: `GET /health` - Basic service health
- **Readiness**: `GET /ready` - Service readiness including dependencies
- **Metrics**: `GET /metrics` - Prometheus metrics endpoint

### Key Metrics

- **Notification Throughput**: `notifications_sent_total`, `notifications_delivered_total`
- **Delivery Rates**: `notification_delivery_rate`, `notification_read_rate`
- **Queue Sizes**: `notification_queue_size_by_priority`
- **Error Rates**: `notification_errors_total`, `push_service_errors_total`
- **Latency**: `notification_processing_duration`, `push_delivery_duration`

### Logging

Structured JSON logging with configurable levels:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "info",
  "message": "Notification sent successfully",
  "notification_id": "123e4567-e89b-12d3-a456-426614174000",
  "user_id": "123e4567-e89b-12d3-a456-426614174001",
  "platform": "fcm",
  "priority": "critical",
  "delivery_time_ms": 150
}
```

## Performance Characteristics

### Throughput

- **Critical Notifications**: 1,000+ per minute per instance
- **Batch Processing**: 10,000+ notifications per batch
- **Database Operations**: Optimized with proper indexing and connection pooling

### Latency

- **Critical Notifications**: < 500ms end-to-end
- **API Response Times**: < 100ms for registration/status calls
- **Push Delivery**: Depends on platform (FCM: ~200ms, APNS: ~300ms)

### Resource Usage

- **Memory**: ~100MB base + ~1KB per active notification
- **CPU**: Low baseline, spikes during batch processing
- **Database Connections**: Configurable pool (default: 25 max, 5 idle)

## Security Considerations

### Data Protection

- **Encryption in Transit**: TLS 1.2+ for all HTTP communications
- **Credential Management**: Secure storage of push service credentials
- **Token Validation**: Regular validation of device tokens
- **Data Retention**: Configurable cleanup of old notifications and receipts

### Access Control

- **Multi-Tenant Isolation**: Row-level security policies enforce tenant boundaries
- **API Authentication**: Bearer token authentication with role-based access
- **Webhook Security**: HMAC signature validation and IP allowlisting
- **Audit Logging**: Complete audit trail of all notification activities

## Troubleshooting

### Common Issues

1. **FCM Authentication Errors**
   - Verify `FCM_CREDENTIALS_JSON` is valid service account JSON
   - Check Firebase project permissions
   - Ensure project ID matches credentials

2. **APNS Certificate Issues**
   - Verify certificate is not expired
   - Check certificate matches app bundle ID
   - Ensure production/development environment matches

3. **Database Connection Issues**
   - Check PostgreSQL is running and accessible
   - Verify connection pool settings
   - Review SSL/TLS configuration

4. **High Memory Usage**
   - Check active delivery tracking cleanup
   - Review batch sizes and processing intervals
   - Monitor for memory leaks in long-running processes

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
export LOG_LEVEL=debug
./mobile-notification
```

## Contributing

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make changes and add tests
4. Run tests: `go test ./...`
5. Submit a pull request

### Code Standards

- Follow Go best practices and style guidelines
- Include comprehensive tests for new features
- Update documentation for API changes
- Use structured logging with appropriate levels

## License

Copyright (c) 2024 iSECTECH. All rights reserved.

---

## Support

For technical support or questions:
- Create an issue in the repository
- Contact the platform team at platform@isectech.com
- Review the troubleshooting section above

For security issues, please email security@isectech.com directly.