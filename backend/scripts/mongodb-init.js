// MongoDB initialization script for iSECTECH platform

// Create application database
db = db.getSiblingDB('isectech');

// Create application user
db.createUser({
  user: 'isectech_app',
  pwd: 'app_password',
  roles: [
    {
      role: 'readWrite',
      db: 'isectech',
    },
  ],
});

// Create collections with indexes

// Assets collection
db.createCollection('assets');
db.assets.createIndex({ asset_id: 1 }, { unique: true });
db.assets.createIndex({ tenant_id: 1 });
db.assets.createIndex({ asset_type: 1 });
db.assets.createIndex({ ip_address: 1 });
db.assets.createIndex({ discovered_at: 1 });
db.assets.createIndex({ last_seen: 1 });

// Threats collection
db.createCollection('threats');
db.threats.createIndex({ threat_id: 1 }, { unique: true });
db.threats.createIndex({ tenant_id: 1 });
db.threats.createIndex({ severity: 1 });
db.threats.createIndex({ status: 1 });
db.threats.createIndex({ detected_at: 1 });
db.threats.createIndex({ source_ip: 1 });
db.threats.createIndex({ target_ip: 1 });

// Events collection (for high-volume security events)
db.createCollection('events');
db.events.createIndex({ event_id: 1 }, { unique: true });
db.events.createIndex({ tenant_id: 1 });
db.events.createIndex({ event_type: 1 });
db.events.createIndex({ timestamp: 1 });
db.events.createIndex({ source_service: 1 });
db.events.createIndex({ correlation_id: 1 });

// Vulnerabilities collection
db.createCollection('vulnerabilities');
db.vulnerabilities.createIndex({ vulnerability_id: 1 }, { unique: true });
db.vulnerabilities.createIndex({ tenant_id: 1 });
db.vulnerabilities.createIndex({ cve_id: 1 });
db.vulnerabilities.createIndex({ severity: 1 });
db.vulnerabilities.createIndex({ asset_id: 1 });
db.vulnerabilities.createIndex({ discovered_at: 1 });

// Compliance scans collection
db.createCollection('compliance_scans');
db.compliance_scans.createIndex({ scan_id: 1 }, { unique: true });
db.compliance_scans.createIndex({ tenant_id: 1 });
db.compliance_scans.createIndex({ framework: 1 });
db.compliance_scans.createIndex({ status: 1 });
db.compliance_scans.createIndex({ started_at: 1 });

// Audit logs collection
db.createCollection('audit_logs');
db.audit_logs.createIndex({ log_id: 1 }, { unique: true });
db.audit_logs.createIndex({ tenant_id: 1 });
db.audit_logs.createIndex({ user_id: 1 });
db.audit_logs.createIndex({ action: 1 });
db.audit_logs.createIndex({ timestamp: 1 });
db.audit_logs.createIndex({ ip_address: 1 });

// Create TTL index for events (90 days retention)
db.events.createIndex(
  { timestamp: 1 },
  { expireAfterSeconds: 7776000 } // 90 days
);

// Create TTL index for audit logs (7 years retention for compliance)
db.audit_logs.createIndex(
  { timestamp: 1 },
  { expireAfterSeconds: 220752000 } // 7 years
);

print('MongoDB initialization completed for iSECTECH platform');
