from __future__ import annotations

"""
Behavioral Analysis Model Training, Validation, and Evaluation Pipeline

Implements coordinated training and evaluation for supervised and unsupervised
models with metrics logging and optional MLflow integration.

Task 85.6: Implement Model Training, Validation, and Evaluation Pipeline
"""

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

import numpy as np
import pandas as pd

try:
    import mlflow
    _MLFLOW_AVAILABLE = True
except Exception:
    _MLFLOW_AVAILABLE = False

from .feature_store import FeatureStore
from .baseline_trainer import BaselineTrainer, BaselineTrainerConfig
from .supervised_trainer import SupervisedTrainer, SupervisedTrainerConfig


@dataclass
class TrainingPipelineConfig:
    postgres_dsn: str
    model_dir: str = "/var/lib/isectech/models"
    use_mlflow: bool = True
    mlflow_tracking_uri: Optional[str] = None
    baseline_window_hours: int = 24 * 14
    baseline_min_samples: int = 200
    supervised_window_hours: int = 24 * 30
    supervised_min_samples: int = 500
    supervised_test_size: float = 0.2


class TrainingPipeline:
    """Coordinates training and evaluation across model families."""

    def __init__(self, feature_store: FeatureStore, config: TrainingPipelineConfig):
        self.feature_store = feature_store
        self.config = config
        self._init_mlflow()

        # Initialize trainers
        self.baseline_trainer = BaselineTrainer(
            feature_store,
            BaselineTrainerConfig(
                postgres_dsn=config.postgres_dsn,
                model_dir=config.model_dir,
                contamination=float(os.getenv("BASELINE_IF_CONTAMINATION", "0.03")),
                min_samples=config.baseline_min_samples,
                train_window_hours=config.baseline_window_hours,
            ),
        )
        self.supervised_trainer = SupervisedTrainer(
            feature_store,
            SupervisedTrainerConfig(
                postgres_dsn=config.postgres_dsn,
                model_dir=config.model_dir,
                min_samples=config.supervised_min_samples,
                train_window_hours=config.supervised_window_hours,
                test_size=config.supervised_test_size,
            ),
        )

    def _init_mlflow(self) -> None:
        if not self.config.use_mlflow or not _MLFLOW_AVAILABLE:
            return
        if self.config.mlflow_tracking_uri:
            mlflow.set_tracking_uri(self.config.mlflow_tracking_uri)
        mlflow.set_experiment("behavioral-analysis")

    def train_baseline(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Train/refresh baselines for recent entities."""
        result = self.baseline_trainer.train_all_recent(tenant_id=tenant_id, limit=int(os.getenv("BASELINE_TRAIN_ENTITY_LIMIT", "200")))
        if _MLFLOW_AVAILABLE and self.config.use_mlflow:
            with mlflow.start_run(run_name=f"baseline_training_{tenant_id or 'global'}"):
                mlflow.log_param("tenant_id", tenant_id or "_global_")
                mlflow.log_param("window_hours", self.config.baseline_window_hours)
                mlflow.log_metric("trained_count", len(result.get("trained", [])))
                mlflow.log_metric("skipped_count", len(result.get("skipped", [])))
        return result

    def train_supervised(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Train supervised detector for a tenant (or global)."""
        result = self.supervised_trainer.train_for_tenant(tenant_id)
        metrics = result.get("metrics") or {}
        if _MLFLOW_AVAILABLE and self.config.use_mlflow and result.get("status") == "trained":
            with mlflow.start_run(run_name=f"supervised_training_{tenant_id or 'global'}"):
                mlflow.log_param("tenant_id", tenant_id or "_global_")
                for k, v in metrics.items():
                    try:
                        mlflow.log_metric(k, float(v))
                    except Exception:
                        pass
                mlflow.log_metric("samples", float(result.get("samples", 0)))
                mlflow.log_metric("features", float(result.get("features", 0)))
        return result

    def evaluate_supervised(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Evaluate current supervised model on a recent holdout set (approx)."""
        # Build a simple holdout from labeled dataset
        df = self.supervised_trainer._load_labeled_dataset(tenant_id)  # noqa: SLF001 (intentional internal reuse)
        if df.empty or len(df) < max(200, self.config.supervised_min_samples):
            return {"status": "skipped", "reason": "insufficient_labeled_data", "samples": int(len(df))}
        # Random split
        df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
        split = int(len(df) * 0.2)
        test_df = df.iloc[:split]
        # Load model and score
        loaded = self.supervised_trainer.load_best_model(tenant_id)
        if not loaded or not loaded.get("model"):
            return {"status": "skipped", "reason": "no_model"}
        feature_names = loaded.get("params", {}).get("features", [])
        if not feature_names:
            return {"status": "skipped", "reason": "no_feature_list"}
        # Prepare matrix
        y_true = test_df["label"].to_numpy()
        X_list = []
        for _, row in test_df.iterrows():
            fv = []
            feats = {**row.drop(labels=["entity_id", "extracted_at", "label"]).to_dict()}
            for name in feature_names:
                v = feats.get(name, 0)
                try:
                    fv.append(float(v))
                except Exception:
                    fv.append(0.0)
            X_list.append(fv)
        X = np.array(X_list, dtype=np.float32)
        model = loaded["model"]
        y_prob = model.predict_proba(X)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(X)
        y_pred = (y_prob >= 0.5).astype(int)
        # Metrics
        from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, accuracy_score
        precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
        auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
        acc = accuracy_score(y_true, y_pred)
        eval_metrics = {"precision": float(precision), "recall": float(recall), "f1": float(f1), "roc_auc": float(auc), "accuracy": float(acc), "samples": int(len(test_df))}
        if _MLFLOW_AVAILABLE and self.config.use_mlflow:
            with mlflow.start_run(run_name=f"supervised_eval_{tenant_id or 'global'}"):
                mlflow.log_param("tenant_id", tenant_id or "_global_")
                for k, v in eval_metrics.items():
                    try:
                        mlflow.log_metric(k, float(v))
                    except Exception:
                        pass
        return {"status": "evaluated", "metrics": eval_metrics}


