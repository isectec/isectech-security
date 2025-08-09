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
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    accuracy_score,
)
from sklearn.model_selection import train_test_split

from .feature_store import FeatureStore
from .model_registry import ModelRegistry, ModelRegistryConfig


@dataclass
class SupervisedTrainerConfig:
    postgres_dsn: str
    model_dir: str = "/var/lib/isectech/models"
    min_samples: int = 500
    train_window_hours: int = 24 * 30  # last 30 days
    test_size: float = 0.2


class SupervisedTrainer:
    """Trains supervised detection models for known attack detection per tenant."""

    def __init__(self, feature_store: FeatureStore, config: SupervisedTrainerConfig):
        self.feature_store = feature_store
        self.config = config
        self._pg_conn = psycopg2.connect(self.config.postgres_dsn)
        self._pg_conn.autocommit = True
        self._ensure_schema()
        os.makedirs(self.config.model_dir, exist_ok=True)
        self._registry = ModelRegistry(ModelRegistryConfig(postgres_dsn=self.config.postgres_dsn))

    def close(self):
        if self._pg_conn:
            self._pg_conn.close()

    def _ensure_schema(self) -> None:
        with self._pg_conn.cursor() as cur:
            # Attack labels table: label windows for entities
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_labels (
                  id BIGSERIAL PRIMARY KEY,
                  tenant_id UUID NULL,
                  entity_id TEXT NOT NULL,
                  start_ts TIMESTAMPTZ NOT NULL,
                  end_ts TIMESTAMPTZ NOT NULL,
                  label SMALLINT NOT NULL CHECK (label IN (0,1)),
                  tactic TEXT NULL,
                  technique TEXT NULL,
                  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_attack_labels_tenant_entity
                  ON attack_labels(tenant_id, entity_id, start_ts, end_ts);
                
                -- Model registry table reused from baseline trainer
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

    def _load_labeled_dataset(self, tenant_id: Optional[str]) -> pd.DataFrame:
        """Join feature rows with label windows to produce a labeled dataset."""
        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT bf.entity_id,
                       bf.features,
                       bf.extracted_at,
                       al.label
                FROM behavioral_features bf
                JOIN attack_labels al
                  ON al.entity_id = bf.entity_id
                 AND (al.tenant_id IS NULL OR al.tenant_id = bf.tenant_id)
                 AND bf.extracted_at BETWEEN al.start_ts AND al.end_ts
                WHERE (%s::uuid IS NULL OR bf.tenant_id = %s::uuid)
                  AND bf.extracted_at >= NOW() - (%s || ' hours')::interval
                LIMIT 500000
                """,
                (tenant_id, tenant_id, str(self.config.train_window_hours)),
            )
            rows = cur.fetchall()

        if not rows:
            return pd.DataFrame()

        records = []
        for r in rows:
            rec = {"entity_id": r["entity_id"], "extracted_at": r["extracted_at"], "label": int(r["label"]) }
            rec.update(r["features"] or {})
            records.append(rec)
        df = pd.DataFrame(records)
        return df

    def _prepare_matrix(self, df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list]:
        df_num = df.select_dtypes(include=[np.number]).copy()
        if "label" not in df_num.columns:
            return np.array([]), np.array([]), []
        y = df_num.pop("label").to_numpy(dtype=np.int32)
        # drop trivially constant columns
        nunique = df_num.nunique()
        keep_cols = [c for c in df_num.columns if nunique[c] > 1]
        if not keep_cols:
            return np.array([]), np.array([]), []
        X = df_num[keep_cols].to_numpy(dtype=np.float32)
        return X, y, keep_cols

    def train_for_tenant(self, tenant_id: Optional[str]) -> Dict[str, Any]:
        df = self._load_labeled_dataset(tenant_id)
        if df.empty or len(df) < self.config.min_samples:
            return {"status": "skipped", "reason": "insufficient_labeled_data", "samples": int(len(df))}

        X, y, feature_names = self._prepare_matrix(df)
        if X.size == 0 or X.shape[0] < self.config.min_samples:
            return {"status": "skipped", "reason": "insufficient_numeric_labeled_features", "samples": int(X.shape[0])}

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=self.config.test_size, random_state=42, stratify=y)

        # Two-model ensemble: LogisticRegression + RandomForest with class weights
        lr = LogisticRegression(max_iter=1000, class_weight="balanced")
        rf = RandomForestClassifier(n_estimators=300, class_weight="balanced_subsample", random_state=42, n_jobs=-1)
        lr.fit(X_train, y_train)
        rf.fit(X_train, y_train)

        # Evaluate
        def evaluate(model) -> Dict[str, float]:
            y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(X_test)
            y_pred = (y_prob >= 0.5).astype(int)
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average="binary", zero_division=0)
            auc = roc_auc_score(y_test, y_prob)
            acc = accuracy_score(y_test, y_pred)
            return {"precision": float(precision), "recall": float(recall), "f1": float(f1), "roc_auc": float(auc), "accuracy": float(acc)}

        metrics_lr = evaluate(lr)
        metrics_rf = evaluate(rf)

        # Persist the better model artifact
        best_model, best_name, best_metrics = (rf, "random_forest", metrics_rf) if metrics_rf["f1"] >= metrics_lr["f1"] else (lr, "logistic_regression", metrics_lr)
        import pickle
        artifact_bytes = pickle.dumps(best_model)

        with self._pg_conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO behavioral_models (
                  tenant_id, entity_id, model_type, framework, version, params, metrics, artifact
                ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s)
                """,
                (
                    tenant_id, "_global_", "supervised_detector", "sklearn", "1.0",
                    json.dumps({"model": best_name, "features": feature_names}),
                    json.dumps(best_metrics),
                    artifact_bytes
                ),
            )

        # Retrieve id for the inserted model
        model_id: Optional[int] = None
        with self._pg_conn.cursor() as cur2:
            cur2.execute("SELECT currval(pg_get_serial_sequence('behavioral_models','id'))")
            row = cur2.fetchone()
            if row:
                model_id = int(row[0])

        # Auto-promote trained model to staging
        if model_id is not None:
            try:
                self._registry.promote(tenant_id=tenant_id, model_type="supervised_detector", model_id=model_id, stage="staging", promoted_by="trainer")
            except Exception:
                pass

        return {
            "status": "trained",
            "model": best_name,
            "metrics": best_metrics,
            "samples": int(X.shape[0]),
            "features": len(feature_names),
            "model_id": model_id,
            "promoted": "staging" if model_id is not None else None,
        }

    def load_best_model(self, tenant_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """Load the most recent supervised model artifact for a tenant (or global)."""
        with self._pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, params, metrics, artifact, created_at
                  FROM behavioral_models
                 WHERE model_type = 'supervised_detector'
                   AND (%s::uuid IS NULL OR tenant_id = %s::uuid)
                 ORDER BY created_at DESC
                 LIMIT 1
                """,
                (tenant_id, tenant_id),
            )
            row = cur.fetchone()
        if not row:
            return None
        import pickle
        model = pickle.loads(row["artifact"]) if row.get("artifact") else None
        params = row.get("params") or {}
        return {"model": model, "params": params, "metrics": row.get("metrics"), "created_at": row.get("created_at")}

    def predict_proba(self, tenant_id: Optional[str], features: Dict[str, Any]) -> Optional[float]:
        """Score a single feature dict using the latest supervised model.

        Returns probability for the positive class (attack) or None if unavailable.
        """
        # Prefer production-deployed model, fallback to latest artifact
        try:
            current = self._registry.current(tenant_id=tenant_id, model_type="supervised_detector", stage="production")
        except Exception:
            current = None
        if current and current.get("artifact"):
            import pickle
            model = pickle.loads(current["artifact"])  # type: ignore
            params = current.get("params") or {}
        else:
            loaded = self.load_best_model(tenant_id)
            if not loaded or not loaded.get("model"):
                return None
            model = loaded["model"]
            params = loaded.get("params") or {}
        feature_names = params.get("features") or []
        if not feature_names:
            return None
        # Build feature vector in the correct order
        vector = []
        for name in feature_names:
            value = features.get(name, 0)
            try:
                vector.append(float(value))
            except Exception:
                vector.append(0.0)
        X = np.array([vector], dtype=np.float32)
        if hasattr(model, "predict_proba"):
            return float(model.predict_proba(X)[:, 1][0])
        # Fallback
        scores = model.decision_function(X)
        # Map decision_function to [0,1] via logistic
        return float(1 / (1 + np.exp(-scores[0])))


