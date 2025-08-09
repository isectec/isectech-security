from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional, Dict, Any, List

import pandas as pd
import psycopg2
import psycopg2.extras
import redis

from .feature_engineering import BehavioralFeatures


@dataclass
class FeatureStoreConfig:
    postgres_dsn: str
    redis_url: Optional[str] = None
    cache_ttl_seconds: int = 900


class FeatureStore:
    """Production-grade feature store with Postgres (source of truth),
    Redis cache for hot features, and Parquet export for training datasets.
    """

    def __init__(self, config: FeatureStoreConfig):
        self.config = config
        self._pg_conn = None
        self._redis = None

    def connect(self) -> None:
        if not self._pg_conn:
            self._pg_conn = psycopg2.connect(self.config.postgres_dsn)
            self._pg_conn.autocommit = True
            self._ensure_schema()
        if self.config.redis_url and not self._redis:
            self._redis = redis.Redis.from_url(self.config.redis_url, decode_responses=True)

    def close(self) -> None:
        try:
            if self._pg_conn:
                self._pg_conn.close()
        finally:
            self._pg_conn = None

    def _ensure_schema(self) -> None:
        """Create features table if not exists (tenant-aware, RLS-ready)."""
        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS behavioral_features (
                  id BIGSERIAL PRIMARY KEY,
                  tenant_id UUID NULL,
                  entity_id TEXT NOT NULL,
                  entity_type TEXT NOT NULL,
                  time_window_minutes INT NOT NULL,
                  features JSONB NOT NULL,
                  metadata JSONB NOT NULL,
                  extracted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_behavioral_features_tenant_entity
                  ON behavioral_features(tenant_id, entity_id);
                CREATE INDEX IF NOT EXISTS idx_behavioral_features_extracted_at
                  ON behavioral_features(extracted_at);
                """
            )

    def save_features(
        self,
        entity_id: str,
        behavioral: BehavioralFeatures,
        tenant_id: Optional[str] = None,
    ) -> None:
        self.connect()
        payload_features: Dict[str, Any] = behavioral.features
        payload_metadata: Dict[str, Any] = behavioral.metadata

        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO behavioral_features (
                  tenant_id, entity_id, entity_type, time_window_minutes, features, metadata, extracted_at
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s::jsonb, NOW())
                """,
                (
                    tenant_id,
                    entity_id,
                    behavioral.entity_type,
                    int(behavioral.time_window.total_seconds() // 60),
                    json.dumps(payload_features),
                    json.dumps(payload_metadata),
                ),
            )

        # Cache hot features if Redis enabled
        if self._redis:
            cache_key = self._build_cache_key(tenant_id, entity_id)
            self._redis.setex(cache_key, self.config.cache_ttl_seconds, json.dumps(payload_features))

    def get_cached_features(self, tenant_id: Optional[str], entity_id: str) -> Optional[Dict[str, Any]]:
        if not self._redis:
            return None
        cache_key = self._build_cache_key(tenant_id, entity_id)
        raw = self._redis.get(cache_key)
        return json.loads(raw) if raw else None

    def export_to_parquet(self, rows: List[BehavioralFeatures], path: str) -> None:
        """Export a list of features to Parquet for offline training."""
        records = []
        for r in rows:
            rec = {"entity_id": r.entity_id, "entity_type": r.entity_type, "time_window_minutes": int(r.time_window.total_seconds() // 60)}
            # Flatten features into top-level columns
            rec.update(r.features)
            records.append(rec)
        df = pd.DataFrame(records)
        # Ensure directory exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        df.to_parquet(path, index=False)

    @staticmethod
    def _build_cache_key(tenant_id: Optional[str], entity_id: str) -> str:
        tenant_part = tenant_id or "_"
        return f"behfeat:{tenant_part}:{entity_id}"

    def load_features_df(self, entity_id: str, tenant_id: Optional[str] = None,
                         since_hours: int = 720) -> pd.DataFrame:
        """Load persisted features for an entity within a recent time window.
        Returns a flat DataFrame with feature columns.
        """
        self.connect()
        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT time_window_minutes, features, metadata, extracted_at
                FROM behavioral_features
                WHERE entity_id = %s
                  AND (%s::uuid IS NULL OR tenant_id = %s::uuid)
                  AND extracted_at >= NOW() - (%s || ' hours')::interval
                ORDER BY extracted_at DESC
                LIMIT 10000
                """,
                (entity_id, tenant_id, tenant_id, str(since_hours))
            )
            rows = cur.fetchall()
        if not rows:
            return pd.DataFrame()
        records = []
        for r in rows:
            rec = {
                "time_window_minutes": r["time_window_minutes"],
                "extracted_at": r["extracted_at"],
            }
            rec.update(r["features"] or {})
            records.append(rec)
        return pd.DataFrame(records)


