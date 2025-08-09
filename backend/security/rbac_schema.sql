-- iSECTECH Centralized RBAC Schema (tenant-scoped)
-- Production-grade: RLS-ready, indexes, constraints, audit columns

BEGIN;

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Users (reference to core user directory)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email CITEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Roles are tenant-scoped and hierarchical
CREATE TABLE IF NOT EXISTS roles (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, name)
);

-- Role hierarchy (parent -> child inheritance)
CREATE TABLE IF NOT EXISTS role_hierarchy (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  parent_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  child_role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, parent_role_id, child_role_id),
  CONSTRAINT no_self_inheritance CHECK (parent_role_id <> child_role_id)
);

-- Permission resources are namespaced and typed
CREATE TABLE IF NOT EXISTS permissions (
  id UUID PRIMARY KEY,
  resource_namespace TEXT NOT NULL,
  resource TEXT NOT NULL,
  action TEXT NOT NULL,
  description TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (resource_namespace, resource, action)
);

-- Role to permission mapping (tenant-scoped grant)
CREATE TABLE IF NOT EXISTS role_permissions (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  constraint_attributes JSONB NOT NULL DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, role_id, permission_id)
);

-- User role assignments (tenant-scoped)
CREATE TABLE IF NOT EXISTS user_roles (
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, user_id, role_id)
);

-- Optional attribute constraints (ABAC-style enrichments)
CREATE TABLE IF NOT EXISTS permission_attributes (
  permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  allowed_values TEXT[] NOT NULL,
  PRIMARY KEY (permission_id, key)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_roles_tenant ON roles(tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_hierarchy_tenant ON role_hierarchy(tenant_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_tenant ON role_permissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_tenant_user ON user_roles(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource ON permissions(resource_namespace, resource, action);

-- RLS enablement for tenant-scoped tables
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_hierarchy ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;

-- Expect application to SET app.current_tenant_id for session context
-- Policies
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = current_schema AND tablename = 'roles' AND policyname = 'tenant_isolation_roles'
  ) THEN
    CREATE POLICY tenant_isolation_roles ON roles
      USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = current_schema AND tablename = 'role_hierarchy' AND policyname = 'tenant_isolation_role_hierarchy'
  ) THEN
    CREATE POLICY tenant_isolation_role_hierarchy ON role_hierarchy
      USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = current_schema AND tablename = 'role_permissions' AND policyname = 'tenant_isolation_role_permissions'
  ) THEN
    CREATE POLICY tenant_isolation_role_permissions ON role_permissions
      USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE schemaname = current_schema AND tablename = 'user_roles' AND policyname = 'tenant_isolation_user_roles'
  ) THEN
    CREATE POLICY tenant_isolation_user_roles ON user_roles
      USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
  END IF;
END $$;

-- Helper view to expand role hierarchy (for fast permission resolution)
CREATE OR REPLACE VIEW v_effective_roles AS
WITH RECURSIVE inh(tenant_id, role_id, parent_role_id) AS (
  SELECT tenant_id, child_role_id, parent_role_id FROM role_hierarchy
  UNION ALL
  SELECT ih.tenant_id, ih.parent_role_id, rh.parent_role_id
  FROM inh ih JOIN role_hierarchy rh
    ON ih.tenant_id = rh.tenant_id AND ih.parent_role_id = rh.child_role_id
)
SELECT DISTINCT tenant_id, role_id FROM inh;

-- Function to check permission (lightweight; PDP remains source of truth)
CREATE OR REPLACE FUNCTION has_permission(p_tenant UUID, p_user UUID,
  p_namespace TEXT, p_resource TEXT, p_action TEXT)
RETURNS BOOLEAN LANGUAGE SQL STABLE AS $$
  SELECT EXISTS (
    SELECT 1
    FROM user_roles ur
    LEFT JOIN v_effective_roles er
      ON er.tenant_id = ur.tenant_id AND er.role_id = ur.role_id
    JOIN role_permissions rp
      ON rp.tenant_id = ur.tenant_id AND (rp.role_id = ur.role_id OR rp.role_id = er.role_id)
    JOIN permissions p
      ON p.id = rp.permission_id
    WHERE ur.tenant_id = p_tenant AND ur.user_id = p_user
      AND p.resource_namespace = p_namespace
      AND p.resource = p_resource
      AND p.action = p_action
  );
$$;

COMMIT;


