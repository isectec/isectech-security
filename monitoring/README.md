# iSECTECH Monitoring and Observability Stack

This directory contains the complete monitoring and observability infrastructure for the iSECTECH cybersecurity platform. The stack provides comprehensive metrics collection, log aggregation, distributed tracing, alerting, and visualization capabilities.

## Architecture Overview

The monitoring stack consists of the following components:

### Core Infrastructure
- **Prometheus** - Metrics collection and storage
- **Grafana** - Visualization and dashboards
- **Alertmanager** - Alert management and routing
- **Elasticsearch** - Log storage and search
- **Kibana** - Log visualization
- **Logstash** - Log processing and transformation
- **Jaeger** - Distributed tracing
- **OpenTelemetry Collector** - Telemetry data collection

### Exporters and Collectors
- **Node Exporter** - System metrics
- **cAdvisor** - Container metrics
- **Blackbox Exporter** - Endpoint monitoring
- **Postgres Exporter** - Database metrics
- **Redis Exporter** - Cache metrics
- **Nginx Exporter** - Web server metrics

### Notification Systems
- **Slack Integration** - Real-time alerts and incident management
- **PagerDuty Integration** - On-call rotation and escalation
- **Email Notifications** - Critical alert emails
- **Webhook Support** - Custom integrations

## Quick Start

### Prerequisites
- Docker and Docker Compose
- At least 4GB RAM and 20GB free disk space
- Network access for pulling container images

### 1. Environment Setup

Create a `.env` file in the monitoring directory:

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your configuration
vim .env
```

Required environment variables:
```env
# Slack Configuration
SLACK_BOT_TOKEN=your_slack_bot_token
SLACK_API_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# SMTP Configuration
SMTP_PASSWORD=your_smtp_password

# PagerDuty Integration Keys
PAGERDUTY_ROUTING_KEY_CRITICAL=your_critical_key
PAGERDUTY_ROUTING_KEY_SECURITY=your_security_key

# Elasticsearch
ELASTICSEARCH_PASSWORD=your_elasticsearch_password
```

### 2. Start the Monitoring Stack

```bash
# Start all services
./scripts/start-monitoring.sh

# Or start specific components
docker-compose -f docker-compose.monitoring.yml up -d prometheus grafana
docker-compose -f docker-compose.elk.yml up -d elasticsearch kibana logstash
```

### 3. Access the Services

Once started, the following services will be available:

- **Prometheus**: http://localhost:9090
- **Grafana**: http://localhost:3001 (admin/isectech_admin_2024)
- **Alertmanager**: http://localhost:9093
- **Elasticsearch**: http://localhost:9200
- **Kibana**: http://localhost:5601
- **Jaeger**: http://localhost:16686

## Application Integration

### Frontend (Next.js)

```typescript
import { initTracing } from './lib/tracing';
import { initSentry } from './lib/sentry';

// Initialize OpenTelemetry tracing
initTracing();

// Initialize Sentry error tracking
initSentry();
```

### Backend (Go)

```go
import (
    "github.com/your-org/isectech/backend/monitoring"
    "github.com/your-org/isectech/backend/tracing"
)

func main() {
    // Initialize tracing
    tracer := tracing.InitTracer()
    defer tracer.Shutdown()
    
    // Initialize Sentry
    monitoring.InitSentry()
}
```

### AI Services (Python)

```python
from ai_services.tracing import init_tracer
from ai_services.monitoring import init_sentry

# Initialize monitoring
init_tracer()
init_sentry()
```

## Configuration Files

### Prometheus (`prometheus/prometheus.yml`)
Main metrics collection configuration with scrape targets for all services.

### Alertmanager (`alertmanager/alertmanager.yml`)
Alert routing rules and notification channels configuration.

### Grafana (`grafana/provisioning/`)
Dashboard and datasource provisioning for automatic setup.

### ELK Stack
- `elasticsearch/elasticsearch.yml` - Search and analytics engine
- `logstash/pipeline/` - Log processing pipelines
- `kibana/kibana.yml` - Log visualization interface

### Jaeger (`jaeger/jaeger-production.yml`)
Distributed tracing configuration with Elasticsearch backend.

## Alert Rules

The system includes predefined alert rules for:

### Infrastructure Alerts
- High CPU usage
- High memory usage
- Disk space low
- Service down
- Database connection issues

### Security Alerts
- Suspicious login attempts
- Failed authentication spikes
- Unusual network traffic
- Vulnerability scan detection

### Application Alerts
- High error rates
- Slow response times
- AI model failures
- Queue backlog

### Business Alerts
- User registration anomalies
- Payment processing issues
- Feature usage patterns

## Notification Channels

### Slack Integration
- **#alerts-critical** - Critical infrastructure issues
- **#alerts-security** - Security incidents
- **#alerts-warnings** - Warning-level alerts
- **#team-performance** - Performance-related issues
- **#incident-response** - Incident management

### PagerDuty Escalation
1. **Primary On-Call** - Immediate notification
2. **Secondary On-Call** - Escalation after 15 minutes
3. **Manager Escalation** - Escalation after 30 minutes
4. **Executive Escalation** - Critical issues after 1 hour

### Email Notifications
- Critical alerts to ops team
- Security incidents to security team
- Business alerts to stakeholders

## Health Monitoring

The health monitoring system provides:

### Service Health Checks
- Frontend application endpoints
- Backend API endpoints
- Database connectivity
- Cache availability
- External service dependencies

### Custom Health Metrics
```typescript
import { healthMonitor } from './monitoring/health-checks/health-monitor';

// Add custom health check
healthMonitor.addCheck({
  name: 'custom-service',
  url: 'https://api.isectech.com/custom/health',
  critical: true,
  interval: 30000
});
```

## Dashboards

### System Overview
- Infrastructure metrics
- Service status
- Resource utilization
- Network performance

### Application Performance
- Response times
- Error rates
- Throughput
- User activity

### Security Monitoring
- Threat detection
- Access patterns
- Vulnerability status
- Incident timeline

### Business Intelligence
- User engagement
- Feature adoption
- Performance trends
- Cost optimization

## Maintenance and Operations

### Log Rotation
Logs are automatically rotated based on:
- Size limits (1GB per file)
- Time retention (30 days)
- Index lifecycle management

### Data Retention
- Metrics: 30 days in Prometheus
- Logs: 30 days in Elasticsearch
- Traces: 7 days in Jaeger
- Long-term storage in S3 (optional)

### Backup Strategy
- Grafana dashboards exported to Git
- Prometheus rules version controlled
- Elasticsearch snapshots to S3
- Configuration files in repository

### Scaling Considerations
- Prometheus federation for multi-cluster
- Elasticsearch cluster expansion
- Load balancing for high availability
- Resource monitoring and alerting

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check service logs
docker-compose logs [service-name]

# Check system resources
docker system df
free -h

# Restart specific service
docker-compose restart [service-name]
```

#### Missing Metrics
```bash
# Check Prometheus targets
curl http://localhost:9090/api/v1/targets

# Verify exporter endpoints
curl http://localhost:9100/metrics
```

#### Alert Not Firing
```bash
# Check Prometheus rules
curl http://localhost:9090/api/v1/rules

# Test Alertmanager config
docker exec isectech-alertmanager amtool config show
```

### Performance Tuning

#### Prometheus Optimization
- Adjust scrape intervals
- Configure recording rules
- Implement federation
- Optimize storage settings

#### Elasticsearch Tuning
- Configure heap size
- Optimize index settings
- Implement index lifecycle
- Monitor cluster health

#### Grafana Performance
- Use caching plugins
- Optimize queries
- Implement alert folders
- Configure database

## Security Considerations

### Access Control
- Grafana RBAC configuration
- Prometheus federation security
- Elasticsearch authentication
- Network segmentation

### Data Protection
- TLS encryption in transit
- Data masking in logs
- Secrets management
- Audit logging

### Compliance
- Data retention policies
- Access audit trails
- Change management
- Security monitoring

## Development and Testing

### Local Development
```bash
# Start minimal stack for development
docker-compose -f docker-compose.dev.yml up -d

# Run specific monitoring services
docker-compose up -d prometheus grafana
```

### Testing Alert Rules
```bash
# Test Prometheus rules
promtool test rules prometheus/tests/*.yml

# Test Alertmanager config
amtool config check alertmanager/alertmanager.yml
```

### Adding New Dashboards
1. Create dashboard in Grafana UI
2. Export JSON definition
3. Add to `grafana/dashboards/`
4. Update provisioning configuration

## Support and Documentation

For additional support:
- Check service logs: `docker-compose logs [service]`
- Review configuration files
- Consult component documentation
- Contact the DevOps team

## License

This monitoring configuration is part of the iSECTECH project and follows the same licensing terms.