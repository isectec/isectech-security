-- iSECTECH RBAC Management Procedures (tenant-aware, production-grade)
-- Requires prior schema from rbac_schema.sql

BEGIN;

-- Restrict search_path for SECURITY DEFINER functions
SET search_path = public;

-- Validate role belongs to tenant
CREATE OR REPLACE FUNCTION validate_tenant_role(p_tenant UUID, p_role UUID)
RETURNS VOID AS $$
DECLARE v_count INT; BEGIN
  SELECT 1 INTO v_count FROM roles r WHERE r.id = p_role AND r.tenant_id = p_tenant;
  IF NOT FOUND THEN RAISE EXCEPTION 'Role % does not belong to tenant %', p_role, p_tenant;
  END IF;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Get or create permission id
CREATE OR REPLACE FUNCTION get_or_create_permission(
  p_namespace TEXT, p_resource TEXT, p_action TEXT, p_description TEXT DEFAULT NULL
) RETURNS UUID AS $$
DECLARE v_id UUID; BEGIN
  SELECT id INTO v_id FROM permissions
  WHERE resource_namespace = p_namespace AND resource = p_resource AND action = p_action;
  IF v_id IS NULL THEN
    INSERT INTO permissions(id, resource_namespace, resource, action, description)
    VALUES (gen_random_uuid(), p_namespace, p_resource, p_action, p_description)
    ON CONFLICT (resource_namespace, resource, action) DO UPDATE SET description = COALESCE(EXCLUDED.description, permissions.description)
    RETURNING id INTO v_id;
  END IF;
  RETURN v_id;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permission to role (by ids)
CREATE OR REPLACE FUNCTION grant_permission_to_role(
  p_tenant UUID, p_role UUID, p_permission UUID, p_constraints JSONB DEFAULT '{}'::JSONB
) RETURNS VOID AS $$
BEGIN
  PERFORM validate_tenant_role(p_tenant, p_role);
  INSERT INTO role_permissions(tenant_id, role_id, permission_id, constraint_attributes)
  VALUES (p_tenant, p_role, p_permission, COALESCE(p_constraints, '{}'::JSONB))
  ON CONFLICT (tenant_id, role_id, permission_id) DO UPDATE
    SET constraint_attributes = EXCLUDED.constraint_attributes,
        updated_at = NOW();
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grant permission to role (by names)
CREATE OR REPLACE FUNCTION grant_permission_to_role_by_name(
  p_tenant UUID, p_role UUID,
  p_namespace TEXT, p_resource TEXT, p_action TEXT,
  p_description TEXT DEFAULT NULL,
  p_constraints JSONB DEFAULT '{}'::JSONB
) RETURNS VOID AS $$
DECLARE v_perm UUID; BEGIN
  v_perm := get_or_create_permission(p_namespace, p_resource, p_action, p_description);
  PERFORM grant_permission_to_role(p_tenant, p_role, v_perm, p_constraints);
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Revoke permission from role
CREATE OR REPLACE FUNCTION revoke_permission_from_role(
  p_tenant UUID, p_role UUID, p_permission UUID
) RETURNS BOOLEAN AS $$
DECLARE v_count INT; BEGIN
  PERFORM validate_tenant_role(p_tenant, p_role);
  DELETE FROM role_permissions
  WHERE tenant_id = p_tenant AND role_id = p_role AND permission_id = p_permission;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count > 0;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Assign role to user
CREATE OR REPLACE FUNCTION assign_role_to_user(
  p_tenant UUID, p_user UUID, p_role UUID
) RETURNS VOID AS $$
BEGIN
  PERFORM validate_tenant_role(p_tenant, p_role);
  INSERT INTO user_roles(tenant_id, user_id, role_id)
  VALUES (p_tenant, p_user, p_role)
  ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Revoke role from user
CREATE OR REPLACE FUNCTION revoke_role_from_user(
  p_tenant UUID, p_user UUID, p_role UUID
) RETURNS BOOLEAN AS $$
DECLARE v_count INT; BEGIN
  PERFORM validate_tenant_role(p_tenant, p_role);
  DELETE FROM user_roles WHERE tenant_id = p_tenant AND user_id = p_user AND role_id = p_role;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count > 0;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- List effective permissions for a user (resolves inheritance)
CREATE OR REPLACE FUNCTION list_effective_permissions_for_user(
  p_tenant UUID, p_user UUID
) RETURNS TABLE(resource_namespace TEXT, resource TEXT, action TEXT) AS $$
BEGIN
  RETURN QUERY
  SELECT p.resource_namespace, p.resource, p.action
  FROM user_roles ur
  JOIN (
    SELECT tenant_id, role_id FROM v_effective_roles
    UNION
    SELECT tenant_id, role_id FROM user_roles
  ) er ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
  JOIN role_permissions rp ON rp.tenant_id = ur.tenant_id AND (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
  JOIN permissions p ON p.id = rp.permission_id
  WHERE ur.tenant_id = p_tenant AND ur.user_id = p_user;
END; $$ LANGUAGE plpgsql SECURITY DEFINER;

-- Grants for application role
GRANT EXECUTE ON FUNCTION validate_tenant_role(UUID,UUID) TO application_role;
GRANT EXECUTE ON FUNCTION get_or_create_permission(TEXT,TEXT,TEXT,TEXT) TO application_role;
GRANT EXECUTE ON FUNCTION grant_permission_to_role(UUID,UUID,UUID,JSONB) TO application_role;
GRANT EXECUTE ON FUNCTION grant_permission_to_role_by_name(UUID,UUID,TEXT,TEXT,TEXT,TEXT,JSONB) TO application_role;
GRANT EXECUTE ON FUNCTION revoke_permission_from_role(UUID,UUID,UUID) TO application_role;
GRANT EXECUTE ON FUNCTION assign_role_to_user(UUID,UUID,UUID) TO application_role;
GRANT EXECUTE ON FUNCTION revoke_role_from_user(UUID,UUID,UUID) TO application_role;
GRANT EXECUTE ON FUNCTION list_effective_permissions_for_user(UUID,UUID) TO application_role;

COMMIT;


