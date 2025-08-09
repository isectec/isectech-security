-- Mobile Notification System Database Schema
-- Version: 001
-- Description: Initial schema for mobile notification system

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable row-level security
SET row_security = on;

-- Create enum types
CREATE TYPE notification_priority AS ENUM ('critical', 'warning', 'informational');
CREATE TYPE notification_status AS ENUM ('pending', 'sent', 'delivered', 'read', 'failed');
CREATE TYPE notification_platform AS ENUM ('fcm', 'apns', 'web');

-- Notifications table
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    priority notification_priority NOT NULL DEFAULT 'informational',
    status notification_status NOT NULL DEFAULT 'pending',
    platform notification_platform NOT NULL,
    device_token VARCHAR(512) NOT NULL,
    data JSONB DEFAULT '{}',
    image_url VARCHAR(512),
    action_url VARCHAR(512),
    ttl INTEGER DEFAULT 3600, -- Time to live in seconds
    batch_id UUID,
    scheduled_for TIMESTAMP WITH TIME ZONE,
    sent_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    read_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Device registrations table
CREATE TABLE device_registrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL,
    device_token VARCHAR(512) NOT NULL UNIQUE,
    platform notification_platform NOT NULL,
    app_version VARCHAR(50),
    os_version VARCHAR(50),
    device_model VARCHAR(100),
    language VARCHAR(10) DEFAULT 'en',
    timezone VARCHAR(50) DEFAULT 'UTC',
    is_active BOOLEAN DEFAULT TRUE,
    last_seen_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Notification templates table
CREATE TABLE notification_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    priority notification_priority NOT NULL DEFAULT 'informational',
    data JSONB DEFAULT '{}',
    variables TEXT[], -- Array of template variable names
    platforms notification_platform[] DEFAULT '{fcm,apns,web}',
    localization JSONB DEFAULT '{}', -- Localized content by language code
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User notification preferences table
CREATE TABLE notification_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    user_id UUID NOT NULL UNIQUE,
    security_alerts BOOLEAN DEFAULT TRUE,
    system_notifications BOOLEAN DEFAULT TRUE,
    marketing_notifications BOOLEAN DEFAULT FALSE,
    quiet_hours JSONB, -- {enabled: bool, start_time: "HH:MM", end_time: "HH:MM", timezone: "UTC"}
    categories JSONB DEFAULT '{}', -- Category-specific preferences
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Notification batches table
CREATE TABLE notification_batches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL,
    user_id UUID,
    count INTEGER DEFAULT 0,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    platform notification_platform NOT NULL,
    status notification_status NOT NULL DEFAULT 'pending',
    scheduled_for TIMESTAMP WITH TIME ZONE NOT NULL,
    sent_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Delivery receipts table
CREATE TABLE notification_delivery_receipts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    notification_id UUID NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
    device_token VARCHAR(512) NOT NULL,
    platform notification_platform NOT NULL,
    status VARCHAR(50) NOT NULL, -- success, failed, invalid_token, etc.
    error_code VARCHAR(50),
    error_message TEXT,
    attempt_count INTEGER DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_notifications_tenant_id ON notifications(tenant_id);
CREATE INDEX idx_notifications_user_id ON notifications(user_id);
CREATE INDEX idx_notifications_status ON notifications(status);
CREATE INDEX idx_notifications_priority ON notifications(priority);
CREATE INDEX idx_notifications_platform ON notifications(platform);
CREATE INDEX idx_notifications_scheduled_for ON notifications(scheduled_for);
CREATE INDEX idx_notifications_created_at ON notifications(created_at);
CREATE INDEX idx_notifications_tenant_created ON notifications(tenant_id, created_at DESC);
CREATE INDEX idx_notifications_user_created ON notifications(user_id, created_at DESC);
CREATE INDEX idx_notifications_status_priority ON notifications(status, priority DESC);

CREATE INDEX idx_device_registrations_tenant_id ON device_registrations(tenant_id);
CREATE INDEX idx_device_registrations_user_id ON device_registrations(user_id);
CREATE INDEX idx_device_registrations_device_token ON device_registrations(device_token);
CREATE INDEX idx_device_registrations_platform ON device_registrations(platform);
CREATE INDEX idx_device_registrations_is_active ON device_registrations(is_active);
CREATE INDEX idx_device_registrations_last_seen ON device_registrations(last_seen_at);

CREATE INDEX idx_notification_templates_tenant_id ON notification_templates(tenant_id);
CREATE INDEX idx_notification_templates_type ON notification_templates(type);
CREATE INDEX idx_notification_templates_is_active ON notification_templates(is_active);

CREATE INDEX idx_notification_preferences_tenant_id ON notification_preferences(tenant_id);
CREATE INDEX idx_notification_preferences_user_id ON notification_preferences(user_id);

CREATE INDEX idx_notification_batches_tenant_id ON notification_batches(tenant_id);
CREATE INDEX idx_notification_batches_status ON notification_batches(status);
CREATE INDEX idx_notification_batches_scheduled_for ON notification_batches(scheduled_for);

CREATE INDEX idx_delivery_receipts_notification_id ON notification_delivery_receipts(notification_id);
CREATE INDEX idx_delivery_receipts_device_token ON notification_delivery_receipts(device_token);
CREATE INDEX idx_delivery_receipts_status ON notification_delivery_receipts(status);

-- Row Level Security (RLS) policies for multi-tenancy
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_delivery_receipts ENABLE ROW LEVEL SECURITY;

-- RLS policies for notifications table
CREATE POLICY tenant_isolation_notifications ON notifications
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_device_registrations ON device_registrations
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_notification_templates ON notification_templates
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_notification_preferences ON notification_preferences
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

CREATE POLICY tenant_isolation_notification_batches ON notification_batches
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);

-- Delivery receipts inherit tenant isolation from notifications
CREATE POLICY tenant_isolation_delivery_receipts ON notification_delivery_receipts
    USING (notification_id IN (
        SELECT id FROM notifications 
        WHERE tenant_id = current_setting('app.current_tenant_id')::UUID
    ));

-- Functions and triggers
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_notifications_updated_at 
    BEFORE UPDATE ON notifications 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_device_registrations_updated_at 
    BEFORE UPDATE ON device_registrations 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_templates_updated_at 
    BEFORE UPDATE ON notification_templates 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_preferences_updated_at 
    BEFORE UPDATE ON notification_preferences 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_batches_updated_at 
    BEFORE UPDATE ON notification_batches 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_delivery_receipts_updated_at 
    BEFORE UPDATE ON notification_delivery_receipts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to clean up expired notifications
CREATE OR REPLACE FUNCTION cleanup_expired_notifications()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM notifications 
    WHERE status != 'pending' 
    AND created_at < NOW() - INTERVAL '30 days';
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean up inactive device registrations
CREATE OR REPLACE FUNCTION cleanup_inactive_devices(inactive_days INTEGER DEFAULT 90)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    UPDATE device_registrations 
    SET is_active = FALSE 
    WHERE last_seen_at < NOW() - (inactive_days || ' days')::INTERVAL
    AND is_active = TRUE;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get notification analytics
CREATE OR REPLACE FUNCTION get_notification_analytics(
    p_tenant_id UUID,
    p_from_date TIMESTAMP WITH TIME ZONE,
    p_to_date TIMESTAMP WITH TIME ZONE
)
RETURNS TABLE (
    total_sent BIGINT,
    total_delivered BIGINT,
    total_read BIGINT,
    total_failed BIGINT,
    delivery_rate NUMERIC,
    read_rate NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) as total_sent,
        COUNT(CASE WHEN status IN ('delivered', 'read') THEN 1 END) as total_delivered,
        COUNT(CASE WHEN status = 'read' THEN 1 END) as total_read,
        COUNT(CASE WHEN status = 'failed' THEN 1 END) as total_failed,
        CASE 
            WHEN COUNT(*) > 0 THEN 
                ROUND((COUNT(CASE WHEN status IN ('delivered', 'read') THEN 1 END) * 100.0) / COUNT(*), 2)
            ELSE 0 
        END as delivery_rate,
        CASE 
            WHEN COUNT(CASE WHEN status IN ('delivered', 'read') THEN 1 END) > 0 THEN 
                ROUND((COUNT(CASE WHEN status = 'read' THEN 1 END) * 100.0) / COUNT(CASE WHEN status IN ('delivered', 'read') THEN 1 END), 2)
            ELSE 0 
        END as read_rate
    FROM notifications
    WHERE tenant_id = p_tenant_id
    AND created_at BETWEEN p_from_date AND p_to_date;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Comments for documentation
COMMENT ON TABLE notifications IS 'Stores all push notifications sent to users';
COMMENT ON TABLE device_registrations IS 'Stores registered devices for push notifications';
COMMENT ON TABLE notification_templates IS 'Stores reusable notification templates';
COMMENT ON TABLE notification_preferences IS 'Stores user notification preferences';
COMMENT ON TABLE notification_batches IS 'Stores notification batches for efficient delivery';
COMMENT ON TABLE notification_delivery_receipts IS 'Stores delivery receipts and status from push services';

COMMENT ON COLUMN notifications.data IS 'Additional payload data as JSON';
COMMENT ON COLUMN notifications.ttl IS 'Time to live in seconds for the notification';
COMMENT ON COLUMN notifications.batch_id IS 'Reference to notification batch if applicable';

COMMENT ON FUNCTION cleanup_expired_notifications() IS 'Removes old notifications beyond retention period';
COMMENT ON FUNCTION cleanup_inactive_devices(INTEGER) IS 'Marks devices as inactive if not seen for specified days';
COMMENT ON FUNCTION get_notification_analytics(UUID, TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE) IS 'Returns notification analytics for a tenant within date range';