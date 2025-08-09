"""
Feedback Loop for Continuous Model Improvement

This module implements mechanisms to collect feedback from detection outcomes,
user responses, and incident investigations to refine ML models and reduce false positives.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import hashlib

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
import redis
from sklearn.metrics import precision_score, recall_score, f1_score

logger = logging.getLogger(__name__)


class FeedbackType(str, Enum):
    """Types of feedback that can be collected"""
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_POSITIVE = "true_positive"
    TRUE_NEGATIVE = "true_negative"
    INCIDENT_OUTCOME = "incident_outcome"
    USER_ANNOTATION = "user_annotation"
    AUTOMATED_VALIDATION = "automated_validation"


class FeedbackPriority(str, Enum):
    """Priority levels for feedback processing"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FeedbackRecord(BaseModel):
    """Schema for feedback records"""
    feedback_id: str = Field(description="Unique feedback identifier")
    entity_id: str = Field(description="Entity (user/device) identifier")
    tenant_id: str = Field(description="Tenant identifier")
    prediction_id: str = Field(description="Original prediction/alert ID")
    feedback_type: FeedbackType
    priority: FeedbackPriority = FeedbackPriority.MEDIUM
    original_score: float = Field(ge=0, le=1)
    original_prediction: bool
    corrected_label: bool
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(description="Source of feedback (user, soc, automated)")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1, default=1.0)


class FeedbackLoopConfig(BaseModel):
    """Configuration for feedback loop system"""
    database_dsn: str
    redis_url: str = "redis://localhost:6379"
    feedback_table: str = "behavioral_feedback"
    performance_table: str = "model_performance_metrics"
    retraining_threshold: float = 0.1
    min_feedback_samples: int = 100
    feedback_window_hours: int = 168
    batch_size: int = 1000
    cache_ttl: int = 3600


class FeedbackLoop:
    """Main feedback loop implementation"""
    
    def __init__(self, config: FeedbackLoopConfig):
        self.config = config
        self.engine = create_engine(config.database_dsn)
        self.redis_client = redis.from_url(config.redis_url)
        self._initialize_tables()
        
    def _initialize_tables(self):
        """Create feedback and metrics tables if they don't exist"""
        # PostgreSQL compatible table creation
        create_feedback_table = f"""
        CREATE TABLE IF NOT EXISTS {self.config.feedback_table} (
            feedback_id VARCHAR(64) PRIMARY KEY,
            entity_id VARCHAR(255) NOT NULL,
            tenant_id VARCHAR(255) NOT NULL,
            prediction_id VARCHAR(64) NOT NULL,
            feedback_type VARCHAR(50) NOT NULL,
            priority VARCHAR(20) NOT NULL,
            original_score FLOAT NOT NULL,
            original_prediction BOOLEAN NOT NULL,
            corrected_label BOOLEAN NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            source VARCHAR(100) NOT NULL,
            metadata JSONB,
            confidence FLOAT NOT NULL,
            processed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        create_metrics_table = f"""
        CREATE TABLE IF NOT EXISTS {self.config.performance_table} (
            id SERIAL PRIMARY KEY,
            tenant_id VARCHAR(255) NOT NULL,
            model_type VARCHAR(100) NOT NULL,
            precision FLOAT NOT NULL,
            recall FLOAT NOT NULL,
            f1_score FLOAT NOT NULL,
            false_positive_rate FLOAT NOT NULL,
            false_negative_rate FLOAT NOT NULL,
            accuracy FLOAT NOT NULL,
            sample_count INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        # Create indexes
        create_indexes = [
            f"CREATE INDEX IF NOT EXISTS idx_{self.config.feedback_table}_tenant_entity ON {self.config.feedback_table} (tenant_id, entity_id)",
            f"CREATE INDEX IF NOT EXISTS idx_{self.config.feedback_table}_timestamp ON {self.config.feedback_table} (timestamp)",
            f"CREATE INDEX IF NOT EXISTS idx_{self.config.feedback_table}_processed ON {self.config.feedback_table} (processed)",
            f"CREATE INDEX IF NOT EXISTS idx_{self.config.performance_table}_tenant_model ON {self.config.performance_table} (tenant_id, model_type)",
            f"CREATE INDEX IF NOT EXISTS idx_{self.config.performance_table}_timestamp ON {self.config.performance_table} (timestamp)"
        ]
        
        with self.engine.connect() as conn:
            conn.execute(text(create_feedback_table))
            conn.execute(text(create_metrics_table))
            for idx_query in create_indexes:
                conn.execute(text(idx_query))
            conn.commit()
    
    async def collect_feedback(
        self,
        entity_id: str,
        tenant_id: str,
        prediction_id: str,
        feedback_type: FeedbackType,
        original_score: float,
        original_prediction: bool,
        corrected_label: bool,
        source: str = "user",
        metadata: Optional[Dict] = None,
        confidence: float = 1.0
    ) -> str:
        """Collect and store feedback for a specific prediction"""
        # Generate unique feedback ID
        feedback_id = hashlib.sha256(
            f"{prediction_id}_{entity_id}_{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Determine priority
        priority = self._determine_priority(feedback_type, original_score)
        
        # Create feedback record
        feedback = FeedbackRecord(
            feedback_id=feedback_id,
            entity_id=entity_id,
            tenant_id=tenant_id,
            prediction_id=prediction_id,
            feedback_type=feedback_type,
            priority=priority,
            original_score=original_score,
            original_prediction=original_prediction,
            corrected_label=corrected_label,
            source=source,
            metadata=metadata or {},
            confidence=confidence
        )
        
        # Store in database
        await self._store_feedback(feedback)
        
        # Update cache
        await self._update_feedback_cache(tenant_id, feedback)
        
        # Check retraining trigger
        if await self._should_trigger_retraining(tenant_id):
            await self._trigger_retraining(tenant_id)
        
        logger.info(f"Feedback collected: {feedback_id} for entity {entity_id}")
        return feedback_id
    
    def _determine_priority(self, feedback_type: FeedbackType, score: float) -> FeedbackPriority:
        """Determine feedback priority"""
        if feedback_type == FeedbackType.FALSE_NEGATIVE:
            return FeedbackPriority.CRITICAL
        elif feedback_type == FeedbackType.FALSE_POSITIVE and score > 0.8:
            return FeedbackPriority.HIGH
        elif feedback_type in [FeedbackType.FALSE_POSITIVE, FeedbackType.INCIDENT_OUTCOME]:
            return FeedbackPriority.MEDIUM
        else:
            return FeedbackPriority.LOW
    
    async def _store_feedback(self, feedback: FeedbackRecord):
        """Store feedback in database"""
        insert_query = f"""
        INSERT INTO {self.config.feedback_table} (
            feedback_id, entity_id, tenant_id, prediction_id,
            feedback_type, priority, original_score, original_prediction,
            corrected_label, timestamp, source, metadata, confidence
        ) VALUES (
            :feedback_id, :entity_id, :tenant_id, :prediction_id,
            :feedback_type, :priority, :original_score, :original_prediction,
            :corrected_label, :timestamp, :source, :metadata, :confidence
        )
        """
        
        with self.engine.connect() as conn:
            feedback_dict = feedback.dict()
            feedback_dict['metadata'] = json.dumps(feedback.metadata)
            conn.execute(text(insert_query), feedback_dict)
            conn.commit()
    
    async def _update_feedback_cache(self, tenant_id: str, feedback: FeedbackRecord):
        """Update Redis cache with feedback metrics"""
        cache_key = f"feedback_metrics:{tenant_id}"
        
        # Use pipeline for atomic operations
        pipeline = self.redis_client.pipeline()
        pipeline.hincrby(cache_key, f"{feedback.feedback_type}_count", 1)
        pipeline.hincrby(cache_key, "total_count", 1)
        pipeline.hset(cache_key, "last_feedback", feedback.timestamp.isoformat())
        pipeline.expire(cache_key, self.config.cache_ttl)
        
        pipeline.execute()
    
    async def _should_trigger_retraining(self, tenant_id: str) -> bool:
        """Check if retraining should be triggered"""
        cache_key = f"feedback_metrics:{tenant_id}"
        metrics = self.redis_client.hgetall(cache_key)
        
        if not metrics:
            return False
        
        total_count = int(metrics.get(b'total_count', 0))
        
        if total_count < self.config.min_feedback_samples:
            return False
        
        fp_count = int(metrics.get(b'false_positive_count', 0))
        fn_count = int(metrics.get(b'false_negative_count', 0))
        
        error_rate = (fp_count + fn_count) / total_count
        
        return error_rate > self.config.retraining_threshold
    
    async def _trigger_retraining(self, tenant_id: str):
        """Trigger model retraining"""
        logger.info(f"Triggering model retraining for tenant {tenant_id}")
        
        self.redis_client.publish(
            f"model_retraining:{tenant_id}",
            json.dumps({
                "tenant_id": tenant_id,
                "trigger_time": datetime.utcnow().isoformat(),
                "reason": "performance_degradation"
            })
        )
    
    async def process_feedback_batch(self, tenant_id: str) -> Dict[str, Any]:
        """Process unprocessed feedback batch"""
        query = f"""
        SELECT * FROM {self.config.feedback_table}
        WHERE tenant_id = :tenant_id
        AND processed = FALSE
        AND timestamp > :cutoff_time
        ORDER BY priority DESC, timestamp DESC
        LIMIT :batch_size
        """
        
        cutoff_time = datetime.utcnow() - timedelta(hours=self.config.feedback_window_hours)
        
        with self.engine.connect() as conn:
            result = conn.execute(text(query), {
                'tenant_id': tenant_id,
                'cutoff_time': cutoff_time,
                'batch_size': self.config.batch_size
            })
            feedback_records = result.fetchall()
        
        if not feedback_records:
            return {"processed_count": 0, "training_data": None}
        
        # Process feedback
        df = pd.DataFrame(feedback_records)
        training_data = self._generate_training_data(df)
        
        # Mark as processed
        feedback_ids = df['feedback_id'].tolist()
        await self._mark_feedback_processed(feedback_ids)
        
        return {
            "processed_count": len(feedback_records),
            "training_data": training_data
        }
    
    def _generate_training_data(self, feedback_df: pd.DataFrame) -> pd.DataFrame:
        """Generate training data from feedback"""
        training_data = []
        
        for _, row in feedback_df.iterrows():
            sample = {
                'entity_id': row['entity_id'],
                'features': json.loads(row.get('metadata', '{}')).get('features', {}),
                'label': row['corrected_label'],
                'weight': row['confidence'],
                'feedback_type': row['feedback_type']
            }
            training_data.append(sample)
            
            # Generate synthetic variations for critical feedback
            if row['priority'] in ['critical', 'high']:
                for _ in range(3):
                    varied_sample = sample.copy()
                    varied_sample['weight'] *= 0.8
                    varied_sample['feedback_type'] = 'synthetic'
                    training_data.append(varied_sample)
        
        return pd.DataFrame(training_data)
    
    async def _mark_feedback_processed(self, feedback_ids: List[str]):
        """Mark feedback as processed"""
        if not feedback_ids:
            return
            
        update_query = f"""
        UPDATE {self.config.feedback_table}
        SET processed = TRUE
        WHERE feedback_id = ANY(:feedback_ids)
        """
        
        with self.engine.connect() as conn:
            conn.execute(text(update_query), {'feedback_ids': feedback_ids})
            conn.commit()
    
    async def generate_feedback_report(self, tenant_id: str) -> Dict[str, Any]:
        """Generate comprehensive feedback report"""
        stats_query = f"""
        SELECT 
            feedback_type,
            priority,
            COUNT(*) as count,
            AVG(confidence) as avg_confidence,
            AVG(original_score) as avg_score
        FROM {self.config.feedback_table}
        WHERE tenant_id = :tenant_id
        AND timestamp > :cutoff_time
        GROUP BY feedback_type, priority
        """
        
        cutoff_time = datetime.utcnow() - timedelta(hours=self.config.feedback_window_hours)
        
        with self.engine.connect() as conn:
            stats_result = conn.execute(text(stats_query), {
                'tenant_id': tenant_id,
                'cutoff_time': cutoff_time
            })
            
            stats = []
            for row in stats_result:
                stats.append({
                    'feedback_type': row['feedback_type'],
                    'priority': row['priority'],
                    'count': row['count'],
                    'avg_confidence': float(row['avg_confidence']),
                    'avg_score': float(row['avg_score'])
                })
        
        return {
            'tenant_id': tenant_id,
            'report_timestamp': datetime.utcnow().isoformat(),
            'feedback_statistics': stats,
            'recommendations': self._generate_recommendations(stats)
        }
    
    def _generate_recommendations(self, stats: List[Dict]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        total_feedback = sum(s['count'] for s in stats)
        if total_feedback > 0:
            fp_ratio = sum(s['count'] for s in stats if s['feedback_type'] == 'false_positive') / total_feedback
            fn_ratio = sum(s['count'] for s in stats if s['feedback_type'] == 'false_negative') / total_feedback
            
            if fp_ratio > 0.3:
                recommendations.append("High false positive rate. Adjust thresholds or retrain.")
            
            if fn_ratio > 0.1:
                recommendations.append("Significant false negatives. Enhance feature engineering.")
        
        critical_count = sum(s['count'] for s in stats if s['priority'] == 'critical')
        if critical_count > 5:
            recommendations.append(f"{critical_count} critical items need immediate attention.")
        
        if not recommendations:
            recommendations.append("Model performance is stable.")
        
        return recommendations


# Export classes
__all__ = [
    'FeedbackLoop',
    'FeedbackLoopConfig',
    'FeedbackRecord',
    'FeedbackType',
    'FeedbackPriority'
]
EOF < /dev/null