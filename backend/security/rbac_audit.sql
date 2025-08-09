BEGIN;

SET search_path = public;

-- Ensure audit table exists
CREATE TABLE IF NOT EXISTS security_audit_log (
  id BIGSERIAL PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  severity VARCHAR(16) NOT NULL,
  table_name VARCHAR(64) NOT NULL,
  operation_type VARCHAR(16) NOT NULL,
  user_tenant_id UUID NOT NULL,
  resource_tenant_id UUID,
  violation_context JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  context JSONB
);

-- Role-Permission change audit
CREATE OR REPLACE FUNCTION audit_role_permission_change() RETURNS TRIGGER AS $$
DECLARE v_tenant UUID; v_ctx JSONB; BEGIN
  IF (TG_OP = 'INSERT') THEN
    v_tenant := NEW.tenant_id;
    v_ctx := jsonb_build_object(
      'actor', current_user,
      'new', to_jsonb(NEW),
      'search_path', current_setting('search_path', true)
    );
    INSERT INTO security_audit_log(event_type,severity,table_name,operation_type,user_tenant_id,resource_tenant_id,violation_context,context)
    VALUES('RBAC_PERMISSION_CHANGE','info','role_permissions','INSERT',v_tenant,v_tenant, NULL, v_ctx);
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    v_tenant := OLD.tenant_id;
    v_ctx := jsonb_build_object(
      'actor', current_user,
      'old', to_jsonb(OLD),
      'search_path', current_setting('search_path', true)
    );
    INSERT INTO security_audit_log(event_type,severity,table_name,operation_type,user_tenant_id,resource_tenant_id,violation_context,context)
    VALUES('RBAC_PERMISSION_CHANGE','warning','role_permissions','DELETE',v_tenant,v_tenant, NULL, v_ctx);
    RETURN OLD;
  ELSE
    v_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);
    v_ctx := jsonb_build_object(
      'actor', current_user,
      'old', to_jsonb(OLD),
      'new', to_jsonb(NEW)
    );
    INSERT INTO security_audit_log(event_type,severity,table_name,operation_type,user_tenant_id,resource_tenant_id,violation_context,context)
    VALUES('RBAC_PERMISSION_CHANGE','info','role_permissions','UPDATE',v_tenant,v_tenant, NULL, v_ctx);
    RETURN NEW;
  END IF;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- User-Role change audit
CREATE OR REPLACE FUNCTION audit_user_role_change() RETURNS TRIGGER AS $$
DECLARE v_tenant UUID; v_ctx JSONB; BEGIN
  IF (TG_OP = 'INSERT') THEN
    v_tenant := NEW.tenant_id;
    v_ctx := jsonb_build_object('actor', current_user, 'new', to_jsonb(NEW));
    INSERT INTO security_audit_log(event_type,severity,table_name,operation_type,user_tenant_id,resource_tenant_id,violation_context,context)
    VALUES('RBAC_USER_ROLE_CHANGE','info','user_roles','INSERT',v_tenant,v_tenant, NULL, v_ctx);
    RETURN NEW;
  ELSIF (TG_OP = 'DELETE') THEN
    v_tenant := OLD.tenant_id;
    v_ctx := jsonb_build_object('actor', current_user, 'old', to_jsonb(OLD));
    INSERT INTO security_audit_log(event_type,severity,table_name,operation_type,user_tenant_id,resource_tenant_id,violation_context,context)
    VALUES('RBAC_USER_ROLE_CHANGE','warning','user_roles','DELETE',v_tenant,v_tenant, NULL, v_ctx);
    RETURN OLD;
  ELSE
    v_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);
    v_ctx := jsonb_build_object('actor', current_user, 'old', to_jsonb(OLD), 'new', to_jsonb(NEW));
    INSERT INTO security_audit_log(event_type,severity,table_name,operation_type,user_tenant_id,resource_tenant_id,violation_context,context)
    VALUES('RBAC_USER_ROLE_CHANGE','info','user_roles','UPDATE',v_tenant,v_tenant, NULL, v_ctx);
    RETURN NEW;
  END IF;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Triggers
DROP TRIGGER IF EXISTS trg_audit_role_permissions ON role_permissions;
CREATE TRIGGER trg_audit_role_permissions
AFTER INSERT OR UPDATE OR DELETE ON role_permissions
FOR EACH ROW EXECUTE FUNCTION audit_role_permission_change();

DROP TRIGGER IF EXISTS trg_audit_user_roles ON user_roles;
CREATE TRIGGER trg_audit_user_roles
AFTER INSERT OR UPDATE OR DELETE ON user_roles
FOR EACH ROW EXECUTE FUNCTION audit_user_role_change();

COMMIT;


