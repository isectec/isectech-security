from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras


@dataclass
class ModelRegistryConfig:
    postgres_dsn: str


class ModelRegistry:
    """DB-backed model registry with stage promotion and rollback.

    Tables used:
      - behavioral_models (existing): raw model artifacts/metrics
      - model_deployments (new): maps (tenant_id, model_type) -> deployed model id + stage
    """

    def __init__(self, config: ModelRegistryConfig):
        self.config = config
        self._pg_conn = psycopg2.connect(self.config.postgres_dsn)
        self._pg_conn.autocommit = True
        self._ensure_schema()

    def close(self) -> None:
        try:
            self._pg_conn.close()
        except Exception:
            pass

    def _ensure_schema(self) -> None:
        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS model_deployments (
                  id BIGSERIAL PRIMARY KEY,
                  tenant_id UUID NULL,
                  model_type TEXT NOT NULL,
                  model_id BIGINT NOT NULL,
                  stage TEXT NOT NULL CHECK (stage IN ('staging','production')),
                  promoted_by TEXT NULL,
                  promoted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE UNIQUE INDEX IF NOT EXISTS uq_model_deployments_active
                  ON model_deployments(tenant_id, model_type, stage);
                """
            )

    def promote(self, *, tenant_id: Optional[str], model_type: str, model_id: int, stage: str, promoted_by: Optional[str] = None) -> Dict[str, Any]:
        with self._pg_conn.cursor() as cur:
            # Upsert deployment for stage
            cur.execute(
                """
                DELETE FROM model_deployments
                 WHERE (tenant_id IS NOT DISTINCT FROM %s::uuid)
                   AND model_type = %s
                   AND stage = %s;
                INSERT INTO model_deployments (tenant_id, model_type, model_id, stage, promoted_by)
                VALUES (%s, %s, %s, %s, %s);
                """,
                (tenant_id, model_type, stage, tenant_id, model_type, model_id, stage, promoted_by),
            )
        return {"status": "promoted", "model_id": model_id, "stage": stage}

    def current(self, *, tenant_id: Optional[str], model_type: str, stage: str = 'production') -> Optional[Dict[str, Any]]:
        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT md.model_id, bm.params, bm.metrics, bm.artifact, bm.created_at
                  FROM model_deployments md
                  JOIN behavioral_models bm ON bm.id = md.model_id
                 WHERE (md.tenant_id IS NOT DISTINCT FROM %s::uuid)
                   AND md.model_type = %s
                   AND md.stage = %s
                 ORDER BY md.promoted_at DESC
                 LIMIT 1
                """,
                (tenant_id, model_type, stage),
            )
            row = cur.fetchone()
        if not row:
            return None
        return dict(row)

    def history(self, *, tenant_id: Optional[str], model_type: str) -> list[Dict[str, Any]]:
        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT md.id, md.model_id, md.stage, md.promoted_by, md.promoted_at
                  FROM model_deployments md
                 WHERE (md.tenant_id IS NOT DISTINCT FROM %s::uuid)
                   AND md.model_type = %s
                 ORDER BY md.promoted_at DESC
                """,
                (tenant_id, model_type),
            )
            rows = cur.fetchall() or []
        return [dict(r) for r in rows]


