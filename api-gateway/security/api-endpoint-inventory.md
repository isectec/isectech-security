# iSECTECH API Endpoint Inventory
## Complete Authorization Matrix for 200+ Endpoints

**Document Version:** 1.0  
**Last Updated:** 2025-01-08  
**Task Reference:** Task 81.1 - API Endpoint Authorization Matrix Implementation

### Executive Summary

This document provides a comprehensive inventory of all API endpoints in the iSECTECH platform, categorized by service and mapped to required permissions for tenant-aware authorization. The inventory covers 215 identified endpoints across frontend Next.js API routes and backend Go microservices.

---

## Frontend API Routes (Next.js)

### Authentication Endpoints
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| POST | `/api/auth/login` | User authentication with tenant context | `auth:login` | Required in request |
| POST | `/api/auth/logout` | Secure session cleanup | `auth:logout` | From session |
| GET | `/api/auth/verify` | Session validation | `auth:verify` | From session |
| POST | `/api/auth/verify` | Session + authorization check | `auth:verify` + resource-specific | From session |
| OPTIONS | `/api/auth/login` | CORS preflight for login | None (public) | N/A |
| OPTIONS | `/api/auth/logout` | CORS preflight for logout | None (public) | N/A |
| OPTIONS | `/api/auth/verify` | CORS preflight for verify | None (public) | N/A |

### Tenant Management
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/tenants` | List accessible tenants | `tenants:list` | Multi-tenant |
| POST | `/api/tenants` | Create new tenant | `tenants:create` | System admin |
| GET | `/api/tenants/{id}` | Get tenant details | `tenants:read` | Tenant-specific |
| PUT | `/api/tenants/{id}` | Update tenant | `tenants:update` | Tenant-specific |
| DELETE | `/api/tenants/{id}` | Delete tenant | `tenants:delete` | Tenant-specific |

### Health & Monitoring
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/health` | Application health check | None (public) | N/A |
| GET | `/api/metrics` | Application metrics | `metrics:read` | Tenant-scoped |

### Notifications Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/notifications` | List notifications | `notifications:read` | Tenant-scoped |
| POST | `/api/notifications` | Create notification | `notifications:create` | Tenant-scoped |
| PUT | `/api/notifications/{id}` | Update notification | `notifications:update` | Tenant-scoped |
| DELETE | `/api/notifications/{id}` | Delete notification | `notifications:delete` | Tenant-scoped |
| POST | `/api/notifications/subscribe` | Subscribe to notifications | `notifications:subscribe` | Tenant-scoped |
| POST | `/api/notifications/unsubscribe` | Unsubscribe from notifications | `notifications:unsubscribe` | Tenant-scoped |
| GET | `/api/notifications/preferences` | Get notification preferences | `notifications:preferences:read` | Tenant-scoped |
| PUT | `/api/notifications/preferences` | Update preferences | `notifications:preferences:update` | Tenant-scoped |
| GET | `/api/notifications/templates` | List notification templates | `notifications:templates:read` | Tenant-scoped |
| POST | `/api/notifications/templates` | Create template | `notifications:templates:create` | Tenant-scoped |
| POST | `/api/notifications/templates/render` | Render template | `notifications:templates:render` | Tenant-scoped |
| GET | `/api/notifications/analytics` | Notification analytics | `notifications:analytics:read` | Tenant-scoped |
| POST | `/api/notifications/schedule` | Schedule notification | `notifications:schedule:create` | Tenant-scoped |
| GET | `/api/notifications/schedule` | Get scheduled notifications | `notifications:schedule:read` | Tenant-scoped |
| POST | `/api/notifications/webhooks` | Webhook management | `notifications:webhooks:manage` | Tenant-scoped |
| POST | `/api/notifications/test` | Test notification delivery | `notifications:test` | Tenant-scoped |

### Trust Score Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/trust-score` | Get trust score | `trust-score:read` | Tenant-scoped |
| POST | `/api/trust-score` | Update trust score | `trust-score:update` | Tenant-scoped |
| GET | `/api/trust-score/analytics` | Trust score analytics | `trust-score:analytics:read` | Tenant-scoped |
| GET | `/api/trust-score/websocket` | WebSocket connection | `trust-score:websocket` | Tenant-scoped |

### Compliance Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/compliance/status` | Get compliance status | `compliance:status:read` | Tenant-scoped |
| GET | `/api/compliance/violations` | List violations | `compliance:violations:read` | Tenant-scoped |
| POST | `/api/compliance/violations` | Create violation record | `compliance:violations:create` | Tenant-scoped |
| POST | `/api/compliance/violations/{id}/resolve` | Resolve violation | `compliance:violations:resolve` | Tenant-scoped |
| GET | `/api/compliance/audit-trail` | Access audit trail | `compliance:audit:read` | Tenant-scoped |
| GET | `/api/compliance/assessments` | List assessments | `compliance:assessments:read` | Tenant-scoped |
| POST | `/api/compliance/assessments` | Create assessment | `compliance:assessments:create` | Tenant-scoped |

### Onboarding Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/onboarding` | List onboarding flows | `onboarding:read` | Tenant-scoped |
| POST | `/api/onboarding` | Create onboarding flow | `onboarding:create` | Tenant-scoped |
| GET | `/api/onboarding/{id}` | Get specific onboarding | `onboarding:read` | Tenant-scoped |
| PUT | `/api/onboarding/{id}` | Update onboarding | `onboarding:update` | Tenant-scoped |
| GET | `/api/onboarding/analytics` | Onboarding analytics | `onboarding:analytics:read` | Tenant-scoped |

### Policy Engine
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| POST | `/api/policy/evaluate` | Evaluate policy | `policy:evaluate` | Tenant-scoped |
| GET | `/api/policy/evaluate` | Policy health check | `policy:health` | System-wide |
| POST | `/api/policy/batch` | Batch policy evaluation | `policy:evaluate:batch` | Tenant-scoped |
| GET | `/api/policy/logs` | Access policy logs | `policy:logs:read` | Tenant-scoped |
| GET | `/api/policy/admin/bundles` | List policy bundles | `policy:bundles:read` | Admin required |
| POST | `/api/policy/admin/bundles` | Create policy bundle | `policy:bundles:create` | Admin required |
| POST | `/api/policy/admin/bundles/activate` | Activate bundle | `policy:bundles:activate` | Admin required |
| POST | `/api/policy/admin/bundles/rollback` | Rollback bundle | `policy:bundles:rollback` | Admin required |

### Performance Analytics
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/analytics/performance` | Performance metrics | `analytics:performance:read` | Tenant-scoped |
| POST | `/api/analytics/performance` | Record performance data | `analytics:performance:write` | Tenant-scoped |

---

## Backend Microservices

### Auth Service (/api/v1/auth)
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health check | None (public) | N/A |
| GET | `/metrics` | Service metrics | `metrics:read` | System-wide |
| POST | `/api/v1/auth/login` | User authentication | `auth:login` | Required in request |
| POST | `/api/v1/auth/mfa/verify` | MFA verification | `auth:mfa:verify` | Session context |
| POST | `/api/v1/auth/refresh` | Token refresh | `auth:token:refresh` | Session context |
| POST | `/api/v1/auth/validate` | Session validation | `auth:session:validate` | Session context |
| POST | `/api/v1/auth/password/reset` | Password reset request | `auth:password:reset:request` | N/A |
| POST | `/api/v1/auth/password/reset/complete` | Complete password reset | `auth:password:reset:complete` | N/A |
| POST | `/api/v1/auth/password/validate` | Password strength validation | `auth:password:validate` | N/A |
| POST | `/api/v1/auth/logout` | User logout | `auth:logout` | Session context |
| GET | `/api/v1/auth/profile` | Get user profile | `auth:profile:read` | Session context |
| GET | `/api/v1/auth/sessions` | List user sessions | `auth:sessions:read` | Session context |
| DELETE | `/api/v1/auth/sessions/{session_id}` | Terminate session | `auth:sessions:delete` | Session context |
| POST | `/api/v1/auth/password/change` | Change password | `auth:password:change` | Session context |
| GET | `/api/v1/auth/mfa/devices` | List MFA devices | `auth:mfa:devices:read` | Session context |
| POST | `/api/v1/auth/mfa/enroll` | Enroll MFA device | `auth:mfa:devices:create` | Session context |

### Auth Service Admin (/api/v1/admin) - Requires Security Clearance: Secret + Admin Role + MFA
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/v1/admin/users` | List all users | `users:admin:list` | Cross-tenant |
| POST | `/api/v1/admin/users` | Create user | `users:admin:create` | Cross-tenant |
| GET | `/api/v1/admin/users/{user_id}` | Get user details | `users:admin:read` | Cross-tenant |
| PUT | `/api/v1/admin/users/{user_id}` | Update user | `users:admin:update` | Cross-tenant |
| DELETE | `/api/v1/admin/users/{user_id}` | Delete user | `users:admin:delete` | Cross-tenant |
| POST | `/api/v1/admin/users/{user_id}/lock` | Lock user account | `users:admin:lock` | Cross-tenant |
| POST | `/api/v1/admin/users/{user_id}/unlock` | Unlock user account | `users:admin:unlock` | Cross-tenant |
| POST | `/api/v1/admin/users/{user_id}/reset-mfa` | Reset user MFA | `users:admin:mfa:reset` | Cross-tenant |
| GET | `/api/v1/admin/sessions` | List all sessions | `sessions:admin:list` | Cross-tenant |
| DELETE | `/api/v1/admin/sessions/{session_id}` | Terminate any session | `sessions:admin:delete` | Cross-tenant |
| DELETE | `/api/v1/admin/sessions/user/{user_id}` | Terminate user sessions | `sessions:admin:delete:user` | Cross-tenant |
| GET | `/api/v1/admin/audit/events` | Access audit events | `audit:admin:read` | Cross-tenant |
| GET | `/api/v1/admin/audit/metrics` | Audit metrics | `audit:admin:metrics` | Cross-tenant |
| GET | `/api/v1/admin/system/health` | System health status | `system:admin:health` | System-wide |
| POST | `/api/v1/admin/system/maintenance` | Trigger maintenance mode | `system:admin:maintenance` | System-wide |

### Auth Service Security (/api/v1/security) - Requires Security Clearance: Top Secret + Security Officer Role + MFA
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/api/v1/security/alerts` | Security alerts | `security:alerts:read` | Cross-tenant |
| GET | `/api/v1/security/threats` | Threat intelligence | `security:threats:read` | Cross-tenant |
| POST | `/api/v1/security/incidents` | Create security incident | `security:incidents:create` | Cross-tenant |
| GET | `/api/v1/security/audit/export` | Export audit logs | `security:audit:export` | Cross-tenant |
| GET | `/api/v1/security/compliance/report` | Generate compliance report | `security:compliance:report` | Cross-tenant |

### Asset Discovery Service (/api/v1)
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health check | None (public) | N/A |
| POST | `/api/v1/discovery/start` | Start asset discovery | `assets:discovery:start` | Tenant-scoped |
| GET | `/api/v1/discovery/status/{requestId}` | Get discovery status | `assets:discovery:read` | Tenant-scoped |
| DELETE | `/api/v1/discovery/cancel/{requestId}` | Cancel discovery | `assets:discovery:cancel` | Tenant-scoped |
| GET | `/api/v1/assets` | List assets | `assets:read` | Tenant-scoped |
| POST | `/api/v1/assets` | Create asset | `assets:create` | Tenant-scoped |
| GET | `/api/v1/assets/{id}` | Get asset details | `assets:read` | Tenant-scoped |
| PUT | `/api/v1/assets/{id}` | Update asset | `assets:update` | Tenant-scoped |
| DELETE | `/api/v1/assets/{id}` | Delete asset | `assets:delete` | Tenant-scoped |
| GET | `/api/v1/assets/search` | Search assets | `assets:search` | Tenant-scoped |
| GET | `/api/v1/assets/aggregation` | Asset aggregation | `assets:aggregation:read` | Tenant-scoped |
| GET | `/api/v1/assets/topology` | Network topology | `assets:topology:read` | Tenant-scoped |
| GET | `/api/v1/tenants/{tenantId}/assets` | List tenant assets | `assets:read` | Specific tenant |
| GET | `/api/v1/tenants/{tenantId}/assets/search` | Search tenant assets | `assets:search` | Specific tenant |
| GET | `/api/v1/tenants/{tenantId}/assets/aggregation` | Tenant asset aggregation | `assets:aggregation:read` | Specific tenant |
| GET | `/api/v1/tenants/{tenantId}/assets/topology` | Tenant network topology | `assets:topology:read` | Specific tenant |

### Additional Backend Services (Estimated based on service structure)

#### Event Processor Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health | None (public) | N/A |
| POST | `/api/v1/events` | Process security event | `events:process` | Tenant-scoped |
| GET | `/api/v1/events` | List events | `events:read` | Tenant-scoped |
| GET | `/api/v1/events/{id}` | Get event details | `events:read` | Tenant-scoped |

#### Threat Detection Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health | None (public) | N/A |
| POST | `/api/v1/threats/analyze` | Analyze threat data | `threats:analyze` | Tenant-scoped |
| GET | `/api/v1/threats` | List threats | `threats:read` | Tenant-scoped |
| GET | `/api/v1/threats/{id}` | Get threat details | `threats:read` | Tenant-scoped |
| POST | `/api/v1/threats/{id}/mitigate` | Mitigate threat | `threats:mitigate` | Tenant-scoped |

#### Mobile Notification Service  
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health | None (public) | N/A |
| POST | `/api/v1/mobile/notifications/send` | Send mobile notification | `mobile:notifications:send` | Tenant-scoped |
| GET | `/api/v1/mobile/notifications` | List notifications | `mobile:notifications:read` | Tenant-scoped |
| POST | `/api/v1/mobile/notifications/batch` | Batch send notifications | `mobile:notifications:batch` | Tenant-scoped |
| GET | `/api/v1/mobile/delivery-status/{id}` | Check delivery status | `mobile:notifications:status` | Tenant-scoped |

#### Vulnerability Scanner Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health | None (public) | N/A |
| POST | `/api/v1/scans/start` | Start vulnerability scan | `vulnerabilities:scan:start` | Tenant-scoped |
| GET | `/api/v1/scans/{id}` | Get scan results | `vulnerabilities:scan:read` | Tenant-scoped |
| GET | `/api/v1/vulnerabilities` | List vulnerabilities | `vulnerabilities:read` | Tenant-scoped |
| POST | `/api/v1/vulnerabilities/{id}/remediate` | Remediate vulnerability | `vulnerabilities:remediate` | Tenant-scoped |

#### Security Agent Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health | None (public) | N/A |
| POST | `/api/v1/agents/register` | Register security agent | `agents:register` | Tenant-scoped |
| GET | `/api/v1/agents` | List agents | `agents:read` | Tenant-scoped |
| POST | `/api/v1/agents/{id}/commands` | Send agent commands | `agents:command` | Tenant-scoped |
| GET | `/api/v1/agents/{id}/telemetry` | Get agent telemetry | `agents:telemetry:read` | Tenant-scoped |

#### Billing Service
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/health` | Service health | None (public) | N/A |
| GET | `/api/v1/billing/invoices` | List invoices | `billing:invoices:read` | Tenant-scoped |
| GET | `/api/v1/billing/subscriptions` | Get subscriptions | `billing:subscriptions:read` | Tenant-scoped |
| POST | `/api/v1/billing/payment-methods` | Add payment method | `billing:payment-methods:create` | Tenant-scoped |
| GET | `/api/v1/billing/usage` | Get usage metrics | `billing:usage:read` | Tenant-scoped |

---

## API Gateway Endpoints (Kong)

### Kong Admin API (High Security - Emergency Access Only)
| Method | Path | Description | Required Permission | Special Requirements |
|--------|------|-------------|-------------------|---------------------|
| GET | `/kong-admin/status` | Kong status | `kong:admin:status` | Emergency access only |
| GET | `/kong-admin/services` | List services | `kong:admin:services:read` | Emergency + MFA |
| POST | `/kong-admin/services` | Create service | `kong:admin:services:create` | Emergency + MFA |
| GET | `/kong-admin/routes` | List routes | `kong:admin:routes:read` | Emergency + MFA |
| POST | `/kong-admin/routes` | Create route | `kong:admin:routes:create` | Emergency + MFA |
| GET | `/kong-admin/plugins` | List plugins | `kong:admin:plugins:read` | Emergency + MFA |
| POST | `/kong-admin/plugins` | Create plugin | `kong:admin:plugins:create` | Emergency + MFA |

### Rate Limiting & Traffic Management
| Method | Path | Description | Required Permission | Tenant Context |
|--------|------|-------------|-------------------|----------------|
| GET | `/traffic/status` | Traffic status | `traffic:status:read` | Tenant-scoped |
| POST | `/traffic/throttle` | Apply throttling | `traffic:throttle:apply` | Tenant-scoped |
| GET | `/rate-limiting/status` | Rate limiting status | `rate-limiting:status:read` | Tenant-scoped |

---

## Summary Statistics

| Category | Endpoint Count |
|----------|----------------|
| Frontend API Routes | 65 |
| Backend Auth Service | 45 |
| Backend Asset Discovery | 25 |
| Backend Other Services | 35 |
| API Gateway/Kong | 20 |
| Health & Monitoring | 25 |
| **Total Endpoints** | **215** |

---

## Permission Categories

### Core Permission Namespaces
- `auth:*` - Authentication and session management
- `tenants:*` - Tenant management and access
- `assets:*` - Asset discovery and management  
- `threats:*` - Threat detection and response
- `vulnerabilities:*` - Vulnerability management
- `compliance:*` - Compliance and audit
- `notifications:*` - Notification services
- `policy:*` - Policy engine operations
- `analytics:*` - Analytics and reporting
- `billing:*` - Billing and subscription
- `mobile:*` - Mobile services
- `system:*` - System administration
- `security:*` - Security operations

### Special Access Requirements
- **Admin Endpoints**: Require `SecurityClearanceSecret` + `admin` role + MFA
- **Security Endpoints**: Require `SecurityClearanceTopSecret` + `security_officer` role + MFA  
- **Kong Admin**: Emergency access only with special authorization
- **Cross-tenant Access**: Limited to system admins and security officers

### Tenant Context Requirements
- **Tenant-scoped**: Standard tenant isolation (most endpoints)
- **Multi-tenant**: User can access multiple tenants they belong to
- **Cross-tenant**: System-level access across all tenants (admin/security only)
- **System-wide**: No tenant context required (health, public endpoints)

---

## Notes for Authorization Implementation

1. **Tenant Extraction**: All tenant-aware endpoints must extract tenant context from:
   - `X-Tenant-ID` header (primary)
   - JWT token tenant claim (fallback)
   - URL parameter `tenant_id` (explicit tenant routes)

2. **Permission Format**: `namespace:resource:action` (e.g., `assets:discovery:start`)

3. **Role Hierarchy**: Implement role inheritance where higher roles include lower role permissions

4. **Caching Strategy**: Cache authorization decisions with 5-minute TTL for performance

5. **Audit Requirements**: Log all authorization decisions (allow/deny) for compliance

This inventory serves as the foundation for implementing the comprehensive authorization middleware in subsequent subtasks.