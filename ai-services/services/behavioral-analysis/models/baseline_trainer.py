from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

import numpy as np
import pandas as pd
import psycopg2
import psycopg2.extras
from sklearn.ensemble import IsolationForest

try:
    import tensorflow as tf
    _TF_AVAILABLE = True
except Exception:  # pragma: no cover
    _TF_AVAILABLE = False

from .feature_store import FeatureStore


@dataclass
class BaselineTrainerConfig:
    postgres_dsn: str
    model_dir: str = "/var/lib/isectech/models"
    contamination: float = 0.03
    min_samples: int = 200
    train_window_hours: int = 24 * 14  # last 14 days


class BaselineTrainer:
    """Trains unsupervised baseline models per entity using feature store data."""

    def __init__(self, feature_store: FeatureStore, config: BaselineTrainerConfig):
        self.feature_store = feature_store
        self.config = config
        self._pg_conn = psycopg2.connect(self.config.postgres_dsn)
        self._pg_conn.autocommit = True
        self._ensure_schema()
        os.makedirs(self.config.model_dir, exist_ok=True)

    def close(self):
        if self._pg_conn:
            self._pg_conn.close()

    def _ensure_schema(self) -> None:
        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS behavioral_models (
                  id BIGSERIAL PRIMARY KEY,
                  tenant_id UUID NULL,
                  entity_id TEXT NOT NULL,
                  model_type TEXT NOT NULL,
                  framework TEXT NOT NULL,
                  version TEXT NOT NULL,
                  params JSONB NOT NULL,
                  metrics JSONB NOT NULL,
                  artifact_path TEXT NULL,
                  artifact BYTEA NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_behavioral_models_entity
                  ON behavioral_models(tenant_id, entity_id, model_type);
                """
            )

    def _prepare_matrix(self, df: pd.DataFrame) -> np.ndarray:
        # Use only numeric columns
        df_num = df.select_dtypes(include=[np.number]).copy()
        # Drop trivially constant columns
        nunique = df_num.nunique()
        keep_cols = nunique[nunique > 1].index.tolist()
        if not keep_cols:
            return np.array([])
        X = df_num[keep_cols].to_numpy(dtype=np.float32)
        return X

    def train_isolation_forest(self, entity_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        df = self.feature_store.load_features_df(entity_id, tenant_id, since_hours=self.config.train_window_hours)
        if df.empty or len(df) < self.config.min_samples:
            return {"status": "skipped", "reason": "insufficient_data", "samples": int(len(df))}

        X = self._prepare_matrix(df)
        if X.size == 0 or X.shape[0] < self.config.min_samples:
            return {"status": "skipped", "reason": "insufficient_numeric_features", "samples": int(X.shape[0])}

        model = IsolationForest(
            contamination=self.config.contamination,
            n_estimators=200,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X)

        # Metrics: proportion flagged as anomalies under training
        scores = model.decision_function(X)
        scores_norm = (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        anomaly_rate = float((1 - scores_norm > 0.8).mean())

        params = {"contamination": self.config.contamination, "n_estimators": 200}
        metrics = {"samples": int(X.shape[0]), "features": int(X.shape[1]), "train_anomaly_rate": anomaly_rate}

        # Persist artifact (pickle)
        import pickle
        artifact_bytes = pickle.dumps(model)
        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO behavioral_models (
                  tenant_id, entity_id, model_type, framework, version, params, metrics, artifact
                ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
                """,
                (
                    tenant_id, entity_id, "isolation_forest", "sklearn", "1.0",
                    json.dumps(params), json.dumps(metrics), artifact_bytes
                ),
            )

        return {"status": "trained", "metrics": metrics}

    def train_autoencoder(self, entity_id: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        if not _TF_AVAILABLE:
            return {"status": "skipped", "reason": "tensorflow_unavailable"}
        df = self.feature_store.load_features_df(entity_id, tenant_id, since_hours=self.config.train_window_hours)
        if df.empty or len(df) < self.config.min_samples:
            return {"status": "skipped", "reason": "insufficient_data", "samples": int(len(df))}

        X = self._prepare_matrix(df)
        if X.size == 0 or X.shape[0] < self.config.min_samples:
            return {"status": "skipped", "reason": "insufficient_numeric_features", "samples": int(X.shape[0])}

        input_dim = X.shape[1]
        encoder_input = tf.keras.Input(shape=(input_dim,))
        x = tf.keras.layers.Dense(128, activation='relu')(encoder_input)
        x = tf.keras.layers.Dropout(0.1)(x)
        x = tf.keras.layers.Dense(64, activation='relu')(x)
        latent = tf.keras.layers.Dense(32, activation='relu')(x)
        x = tf.keras.layers.Dense(64, activation='relu')(latent)
        x = tf.keras.layers.Dense(128, activation='relu')(x)
        decoded = tf.keras.layers.Dense(input_dim, activation='linear')(x)
        autoencoder = tf.keras.Model(encoder_input, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        hist = autoencoder.fit(X, X, epochs=25, batch_size=64, shuffle=True, verbose=0, validation_split=0.1)

        # Metrics
        metrics = {
            "samples": int(X.shape[0]),
            "features": int(X.shape[1]),
            "train_loss": float(hist.history.get("loss", [0])[-1]),
            "val_loss": float(hist.history.get("val_loss", [0])[-1]),
        }

        # Save model to filesystem and record path
        model_path = os.path.join(self.config.model_dir, f"ae_{tenant_id or 'global'}_{entity_id}_{int(datetime.utcnow().timestamp())}")
        autoencoder.save(model_path)
        params = {"architecture": [input_dim, 128, 64, 32]}

        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO behavioral_models (
                  tenant_id, entity_id, model_type, framework, version, params, metrics, artifact_path
                ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
                """,
                (
                    tenant_id, entity_id, "autoencoder", "tensorflow", "1.0",
                    json.dumps(params), json.dumps(metrics), model_path
                ),
            )

        return {"status": "trained", "metrics": metrics}

    def train_all_recent(self, tenant_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Train baselines for recent entities observed in the feature store."""
        # discover recent distinct entities from behavioral_features
        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT DISTINCT entity_id
                FROM behavioral_features
                WHERE (%s::uuid IS NULL OR tenant_id = %s::uuid)
                  AND extracted_at >= NOW() - interval '14 days'
                ORDER BY entity_id DESC
                LIMIT %s
                """,
                (tenant_id, tenant_id, limit)
            )
            rows = cur.fetchall()
        results: Dict[str, Any] = {"trained": [], "skipped": []}
        for r in rows:
            entity_id = r["entity_id"]
            res_if = self.train_isolation_forest(entity_id, tenant_id)
            results[("trained" if res_if.get("status") == "trained" else "skipped")].append({
                "entity_id": entity_id,
                "model": "isolation_forest",
                "details": res_if
            })
            # Autoencoder optional
            if _TF_AVAILABLE:
                res_ae = self.train_autoencoder(entity_id, tenant_id)
                results[("trained" if res_ae.get("status") == "trained" else "skipped")].append({
                    "entity_id": entity_id,
                    "model": "autoencoder",
                    "details": res_ae
                })
        return results


