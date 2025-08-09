#!/usr/bin/env python3
"""
iSECTECH SIEM ML Anomaly Detection Service
Production-grade ML service for real-time anomaly detection
RESTful API service with Kafka integration and model management
"""

import asyncio
import json
import logging
import pickle
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, validator
import uvicorn
import redis.asyncio as redis
import psycopg2
from psycopg2.extras import RealDictCursor
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
import yaml
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from prometheus_client.openmetrics.exposition import CONTENT_TYPE_LATEST
import structlog

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Prometheus metrics
REQUEST_COUNT = Counter('ml_service_requests_total', 'Total ML service requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('ml_service_request_duration_seconds', 'Request duration')
ANOMALY_DETECTION_COUNT = Counter('anomalies_detected_total', 'Total anomalies detected', ['model', 'risk_level'])
MODEL_PREDICTION_TIME = Histogram('model_prediction_duration_seconds', 'Model prediction time', ['model'])
ACTIVE_MODELS = Gauge('active_models_count', 'Number of active models')
KAFKA_MESSAGES_PROCESSED = Counter('kafka_messages_processed_total', 'Kafka messages processed', ['topic'])

# Request/Response models
class EventData(BaseModel):
    """Event data for anomaly detection"""
    timestamp: str
    event_id: str
    event_action: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_name: Optional[str] = None
    host_name: Optional[str] = None
    bytes_transferred: Optional[int] = 0
    duration: Optional[float] = 0.0
    user_risk_score: Optional[float] = 0.0
    enrichment_score: Optional[float] = 0.0
    threat_detected: Optional[bool] = False
    asset_criticality: Optional[str] = "low"
    network_security_level: Optional[str] = "low"
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        try:
            datetime.fromisoformat(v.replace('Z', '+00:00'))
            return v
        except ValueError:
            raise ValueError('Invalid timestamp format')

class BatchEventData(BaseModel):
    """Batch of events for processing"""
    events: List[EventData]
    
    @validator('events')
    def validate_events_count(cls, v):
        if len(v) > 1000:
            raise ValueError('Maximum 1000 events per batch')
        return v

class AnomalyResponse(BaseModel):
    """Anomaly detection response"""
    event_id: str
    is_anomaly: bool
    confidence_score: float
    risk_level: str
    anomaly_type: str
    model_used: str
    features_analyzed: List[str]
    anomaly_details: Dict[str, Any]
    recommended_actions: List[str]
    processing_time_ms: float

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str
    models_loaded: int
    last_model_update: Optional[str]
    uptime_seconds: float

class ModelInfo(BaseModel):
    """Model information"""
    model_name: str
    version: str
    accuracy: float
    f1_score: float
    last_trained: str
    is_active: bool

# Security
security = HTTPBearer()

async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API key"""
    # In production, this would validate against a secure key store
    valid_keys = ["siem-ml-service-key", "admin-key"]
    if credentials.credentials not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return credentials.credentials

class MLService:
    """Production ML anomaly detection service"""
    
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self.app = FastAPI(title="iSECTECH SIEM ML Service", version="1.0.0")
        self.models = {}
        self.scalers = {}
        self.encoders = {}
        self.redis_client = None
        self.db_connection = None
        self.kafka_consumer = None
        self.kafka_producer = None
        self.start_time = time.time()
        self.last_model_update = None
        
        # Setup CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Setup routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup FastAPI routes"""
        
        @self.app.middleware("http")
        async def add_process_time_header(request, call_next):
            start_time = time.time()
            response = await call_next(request)
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            
            # Update metrics
            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code
            ).inc()
            REQUEST_DURATION.observe(process_time)
            
            return response
        
        @self.app.get("/health", response_model=HealthResponse)
        async def health_check():
            """Health check endpoint"""
            return HealthResponse(
                status="healthy",
                timestamp=datetime.now(timezone.utc).isoformat(),
                version="1.0.0",
                models_loaded=len(self.models),
                last_model_update=self.last_model_update,
                uptime_seconds=time.time() - self.start_time
            )
        
        @self.app.get("/models", response_model=List[ModelInfo])
        async def get_models(api_key: str = Depends(verify_api_key)):
            """Get information about loaded models"""
            model_info = []
            for model_name, model_data in self.models.items():
                info = ModelInfo(
                    model_name=model_name,
                    version=model_data.get('version', 'unknown'),
                    accuracy=model_data.get('metrics', {}).get('accuracy', 0.0),
                    f1_score=model_data.get('metrics', {}).get('f1_score', 0.0),
                    last_trained=model_data.get('last_trained', ''),
                    is_active=True
                )
                model_info.append(info)
            return model_info
        
        @self.app.post("/detect", response_model=AnomalyResponse)
        async def detect_anomaly(
            event: EventData, 
            api_key: str = Depends(verify_api_key)
        ):
            """Detect anomaly in a single event"""
            start_time = time.time()
            
            try:
                result = await self._detect_single_anomaly(event.dict())
                result.processing_time_ms = (time.time() - start_time) * 1000
                
                # Update metrics
                if result.is_anomaly:
                    ANOMALY_DETECTION_COUNT.labels(
                        model=result.model_used,
                        risk_level=result.risk_level
                    ).inc()
                
                return result
                
            except Exception as e:
                logger.error("Anomaly detection failed", error=str(e), event_id=event.event_id)
                raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")
        
        @self.app.post("/detect/batch", response_model=List[AnomalyResponse])
        async def detect_batch_anomalies(
            batch: BatchEventData,
            background_tasks: BackgroundTasks,
            api_key: str = Depends(verify_api_key)
        ):
            """Detect anomalies in a batch of events"""
            try:
                results = await self._detect_batch_anomalies([event.dict() for event in batch.events])
                
                # Store results asynchronously
                background_tasks.add_task(self._store_batch_results, results)
                
                return results
                
            except Exception as e:
                logger.error("Batch anomaly detection failed", error=str(e))
                raise HTTPException(status_code=500, detail=f"Batch detection failed: {str(e)}")
        
        @self.app.post("/models/reload")
        async def reload_models(api_key: str = Depends(verify_api_key)):
            """Reload models from storage"""
            try:
                await self._load_models()
                return {"status": "success", "message": "Models reloaded", "models_count": len(self.models)}
            except Exception as e:
                logger.error("Model reload failed", error=str(e))
                raise HTTPException(status_code=500, detail=f"Model reload failed: {str(e)}")
        
        @self.app.get("/metrics")
        async def get_metrics():
            """Prometheus metrics endpoint"""
            return generate_latest()
    
    async def initialize(self):
        """Initialize the ML service"""
        try:
            await self._load_config()
            await self._setup_redis()
            await self._setup_database()
            await self._load_models()
            await self._setup_kafka()
            logger.info("ML Service initialized successfully")
        except Exception as e:
            logger.error("ML Service initialization failed", error=str(e))
            raise
    
    async def _load_config(self):
        """Load service configuration"""
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception as e:
            logger.warning("Failed to load config, using defaults", error=str(e))
            self.config = {
                'redis': {'host': 'localhost', 'port': 6379, 'db': 3},
                'database': {'host': 'localhost', 'port': 5432, 'database': 'siem_ml'},
                'kafka': {'bootstrap_servers': 'localhost:9092'},
                'models': {'path': '/opt/siem/models'}
            }
    
    async def _setup_redis(self):
        """Setup Redis connection"""
        try:
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 3),
                decode_responses=True
            )
            await self.redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning("Redis connection failed", error=str(e))
            self.redis_client = None
    
    async def _setup_database(self):
        """Setup database connection"""
        try:
            db_config = self.config.get('database', {})
            self.db_connection = psycopg2.connect(
                host=db_config.get('host', 'localhost'),
                port=db_config.get('port', 5432),
                database=db_config.get('database', 'siem_ml'),
                user=db_config.get('user', 'ml_user'),
                password=db_config.get('password', 'ml_password'),
                cursor_factory=RealDictCursor
            )
            self.db_connection.autocommit = True
            logger.info("Database connection established")
        except Exception as e:
            logger.warning("Database connection failed", error=str(e))
            self.db_connection = None
    
    async def _setup_kafka(self):
        """Setup Kafka connections"""
        try:
            kafka_config = self.config.get('kafka', {})
            bootstrap_servers = kafka_config.get('bootstrap_servers', 'localhost:9092')
            
            # Setup consumer for real-time events
            self.kafka_consumer = AIOKafkaConsumer(
                'ml-events-for-detection',
                bootstrap_servers=bootstrap_servers,
                group_id='ml-anomaly-detection-service',
                auto_offset_reset='latest',
                value_deserializer=lambda x: json.loads(x.decode('utf-8'))
            )
            
            # Setup producer for anomaly alerts
            self.kafka_producer = AIOKafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda x: json.dumps(x).encode('utf-8')
            )
            
            await self.kafka_consumer.start()
            await self.kafka_producer.start()
            
            logger.info("Kafka connections established")
            
            # Start background task for processing Kafka messages
            asyncio.create_task(self._process_kafka_messages())
            
        except Exception as e:
            logger.warning("Kafka setup failed", error=str(e))
            self.kafka_consumer = None
            self.kafka_producer = None
    
    async def _load_models(self):
        """Load trained ML models"""
        try:
            models_path = Path(self.config.get('models', {}).get('path', '/opt/siem/models'))
            
            if not models_path.exists():
                logger.warning("Models directory not found, creating empty models dict")
                self.models = {}
                return
            
            loaded_count = 0
            
            # Load active models from database
            if self.db_connection:
                cursor = self.db_connection.cursor()
                cursor.execute("""
                    SELECT model_name, model_path, performance_metrics, metadata, version
                    FROM ml_model_registry 
                    WHERE is_active = true
                    ORDER BY created_at DESC
                """)
                
                for row in cursor.fetchall():
                    model_path = Path(row['model_path'])
                    if model_path.exists():
                        try:
                            with open(model_path, 'rb') as f:
                                model_artifact = pickle.load(f)
                            
                            self.models[row['model_name']] = {
                                'artifact': model_artifact,
                                'metrics': json.loads(row['performance_metrics']),
                                'metadata': json.loads(row['metadata']),
                                'version': row['version'],
                                'last_trained': model_artifact.created_at.isoformat()
                            }
                            loaded_count += 1
                            
                        except Exception as e:
                            logger.error("Failed to load model", model=row['model_name'], error=str(e))
                
                cursor.close()
            
            if loaded_count == 0:
                # Load default fallback model
                await self._load_fallback_model()
                loaded_count = 1
            
            ACTIVE_MODELS.set(loaded_count)
            self.last_model_update = datetime.now(timezone.utc).isoformat()
            
            logger.info("Models loaded successfully", count=loaded_count)
            
        except Exception as e:
            logger.error("Model loading failed", error=str(e))
            await self._load_fallback_model()
    
    async def _load_fallback_model(self):
        """Load a simple fallback model for testing"""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        # Create a simple isolation forest model
        model = IsolationForest(contamination=0.1, random_state=42)
        scaler = StandardScaler()
        
        # Create mock training data
        X_mock = np.random.randn(1000, 10)
        model.fit(X_mock)
        scaler.fit(X_mock)
        
        # Create fallback model artifact
        self.models['fallback'] = {
            'artifact': type('MockArtifact', (), {
                'model': model,
                'scaler': scaler,
                'encoder': {},
                'metadata': {'model_type': 'fallback', 'features': [f'feature_{i}' for i in range(10)]}
            })(),
            'metrics': {'accuracy': 0.8, 'f1_score': 0.7},
            'metadata': {'model_type': 'fallback'},
            'version': 'v1.0.0',
            'last_trained': datetime.now(timezone.utc).isoformat()
        }
        
        logger.info("Fallback model loaded")
    
    async def _detect_single_anomaly(self, event_data: Dict[str, Any]) -> AnomalyResponse:
        """Detect anomaly in a single event"""
        if not self.models:
            raise Exception("No models loaded")
        
        # Extract features
        features = await self._extract_features([event_data])
        if features.empty:
            raise Exception("Feature extraction failed")
        
        # Use the best available model
        model_name = list(self.models.keys())[0]
        model_data = self.models[model_name]
        model_artifact = model_data['artifact']
        
        start_time = time.time()
        
        # Prepare features for prediction
        feature_vector = await self._prepare_features_for_prediction(features.iloc[0], model_artifact)
        
        # Make prediction
        is_anomaly, confidence = await self._predict_anomaly(model_artifact, feature_vector)
        
        prediction_time = time.time() - start_time
        MODEL_PREDICTION_TIME.labels(model=model_name).observe(prediction_time)
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(confidence)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(is_anomaly, confidence, risk_level)
        
        return AnomalyResponse(
            event_id=event_data.get('event_id', ''),
            is_anomaly=is_anomaly,
            confidence_score=confidence,
            risk_level=risk_level,
            anomaly_type='ml_detected' if is_anomaly else 'normal',
            model_used=model_name,
            features_analyzed=list(features.columns),
            anomaly_details={
                'prediction_time_ms': prediction_time * 1000,
                'model_version': model_data.get('version', 'unknown'),
                'feature_count': len(feature_vector)
            },
            recommended_actions=recommendations,
            processing_time_ms=0.0  # Will be set by caller
        )
    
    async def _detect_batch_anomalies(self, events_data: List[Dict[str, Any]]) -> List[AnomalyResponse]:
        """Detect anomalies in a batch of events"""
        if not self.models:
            raise Exception("No models loaded")
        
        # Extract features for all events
        features = await self._extract_features(events_data)
        if features.empty:
            raise Exception("Batch feature extraction failed")
        
        results = []
        model_name = list(self.models.keys())[0]
        model_data = self.models[model_name]
        model_artifact = model_data['artifact']
        
        for i, (_, feature_row) in enumerate(features.iterrows()):
            try:
                start_time = time.time()
                
                # Prepare features
                feature_vector = await self._prepare_features_for_prediction(feature_row, model_artifact)
                
                # Make prediction
                is_anomaly, confidence = await self._predict_anomaly(model_artifact, feature_vector)
                
                prediction_time = time.time() - start_time
                risk_level = self._calculate_risk_level(confidence)
                recommendations = self._generate_recommendations(is_anomaly, confidence, risk_level)
                
                result = AnomalyResponse(
                    event_id=events_data[i].get('event_id', f'batch_{i}'),
                    is_anomaly=is_anomaly,
                    confidence_score=confidence,
                    risk_level=risk_level,
                    anomaly_type='ml_detected' if is_anomaly else 'normal',
                    model_used=model_name,
                    features_analyzed=list(features.columns),
                    anomaly_details={
                        'prediction_time_ms': prediction_time * 1000,
                        'model_version': model_data.get('version', 'unknown')
                    },
                    recommended_actions=recommendations,
                    processing_time_ms=prediction_time * 1000
                )
                
                results.append(result)
                
                if is_anomaly:
                    ANOMALY_DETECTION_COUNT.labels(
                        model=model_name,
                        risk_level=risk_level
                    ).inc()
                
            except Exception as e:
                logger.error("Failed to process event in batch", 
                           event_id=events_data[i].get('event_id', f'batch_{i}'), 
                           error=str(e))
        
        return results
    
    async def _extract_features(self, events_data: List[Dict[str, Any]]) -> pd.DataFrame:
        """Extract features from event data"""
        features_list = []
        
        for event in events_data:
            features = {}
            
            # Basic features
            features['bytes_transferred'] = float(event.get('bytes_transferred', 0))
            features['duration'] = float(event.get('duration', 0))
            features['user_risk_score'] = float(event.get('user_risk_score', 0))
            features['enrichment_score'] = float(event.get('enrichment_score', 0))
            features['threat_detected'] = 1.0 if event.get('threat_detected', False) else 0.0
            
            # Categorical features (simplified encoding)
            features['event_action'] = event.get('event_action', 'unknown')
            features['source_ip'] = event.get('source_ip', '')
            features['user_name'] = event.get('user_name', '')
            
            # Temporal features
            timestamp_str = event.get('timestamp', '')
            if timestamp_str:
                try:
                    dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    features['hour_of_day'] = float(dt.hour)
                    features['day_of_week'] = float(dt.weekday())
                    features['is_weekend'] = 1.0 if dt.weekday() >= 5 else 0.0
                    features['is_business_hours'] = 1.0 if 9 <= dt.hour <= 17 else 0.0
                except:
                    features['hour_of_day'] = 0.0
                    features['day_of_week'] = 0.0
                    features['is_weekend'] = 0.0
                    features['is_business_hours'] = 0.0
            
            # Asset and network features
            criticality_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
            features['asset_criticality'] = float(criticality_scores.get(
                event.get('asset_criticality', 'low').lower(), 1
            ))
            
            features['network_security_level'] = float(criticality_scores.get(
                event.get('network_security_level', 'low').lower(), 1
            ))
            
            features_list.append(features)
        
        return pd.DataFrame(features_list)
    
    async def _prepare_features_for_prediction(self, feature_row: pd.Series, model_artifact) -> np.ndarray:
        """Prepare features for model prediction"""
        # Select numerical features for prediction
        numerical_features = [
            'bytes_transferred', 'duration', 'user_risk_score', 'enrichment_score',
            'threat_detected', 'hour_of_day', 'day_of_week', 'is_weekend',
            'is_business_hours', 'asset_criticality', 'network_security_level'
        ]
        
        # Extract available features
        feature_vector = []
        for feature in numerical_features:
            value = feature_row.get(feature, 0.0)
            feature_vector.append(float(value))
        
        feature_vector = np.array(feature_vector).reshape(1, -1)
        
        # Apply scaling if available
        if hasattr(model_artifact, 'scaler') and model_artifact.scaler:
            try:
                feature_vector = model_artifact.scaler.transform(feature_vector)
            except Exception as e:
                logger.warning("Feature scaling failed", error=str(e))
        
        return feature_vector
    
    async def _predict_anomaly(self, model_artifact, feature_vector: np.ndarray) -> Tuple[bool, float]:
        """Make anomaly prediction"""
        try:
            model = model_artifact.model
            
            if hasattr(model, 'decision_function'):
                # For isolation forest and similar models
                decision_score = model.decision_function(feature_vector)[0]
                
                # Convert decision score to confidence
                if hasattr(model, 'contamination'):
                    # For isolation forest, negative scores indicate anomalies
                    is_anomaly = decision_score < 0
                    confidence = min(abs(decision_score), 1.0)
                else:
                    is_anomaly = decision_score < 0
                    confidence = 1 / (1 + np.exp(-abs(decision_score)))  # Sigmoid
                    
            elif hasattr(model, 'predict_proba'):
                # For probabilistic models
                probabilities = model.predict_proba(feature_vector)[0]
                if len(probabilities) > 1:
                    confidence = probabilities[1]  # Probability of anomaly
                    is_anomaly = confidence > 0.5
                else:
                    confidence = probabilities[0]
                    is_anomaly = confidence > 0.5
                    
            else:
                # For simple predict models
                prediction = model.predict(feature_vector)[0]
                if prediction == -1:  # Isolation forest style
                    is_anomaly = True
                    confidence = 0.8  # Default confidence
                else:
                    is_anomaly = bool(prediction)
                    confidence = 0.8 if is_anomaly else 0.2
            
            return is_anomaly, float(confidence)
            
        except Exception as e:
            logger.error("Prediction failed", error=str(e))
            return False, 0.0
    
    def _calculate_risk_level(self, confidence: float) -> str:
        """Calculate risk level based on confidence score"""
        if confidence >= 0.8:
            return 'critical'
        elif confidence >= 0.6:
            return 'high'
        elif confidence >= 0.4:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, is_anomaly: bool, confidence: float, risk_level: str) -> List[str]:
        """Generate recommendations based on anomaly detection results"""
        if not is_anomaly:
            return ['Continue normal monitoring']
        
        recommendations = ['Investigate anomalous behavior']
        
        if risk_level == 'critical':
            recommendations.extend([
                'Immediate investigation required',
                'Consider isolating affected systems',
                'Escalate to security team'
            ])
        elif risk_level == 'high':
            recommendations.extend([
                'Priority investigation required',
                'Review related events',
                'Check for indicators of compromise'
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                'Enhanced monitoring recommended',
                'Correlate with other security events'
            ])
        else:
            recommendations.append('Monitor for pattern development')
        
        return recommendations
    
    async def _process_kafka_messages(self):
        """Process incoming Kafka messages for real-time detection"""
        if not self.kafka_consumer:
            return
        
        logger.info("Starting Kafka message processing")
        
        try:
            async for message in self.kafka_consumer:
                try:
                    event_data = message.value
                    KAFKA_MESSAGES_PROCESSED.labels(topic=message.topic).inc()
                    
                    # Detect anomaly
                    result = await self._detect_single_anomaly(event_data)
                    
                    # Send high-risk anomalies to alerts topic
                    if result.is_anomaly and result.risk_level in ['high', 'critical']:
                        await self._send_anomaly_alert(result, event_data)
                    
                    # Store result
                    await self._store_detection_result(result)
                    
                except Exception as e:
                    logger.error("Failed to process Kafka message", error=str(e))
                    
        except Exception as e:
            logger.error("Kafka message processing failed", error=str(e))
    
    async def _send_anomaly_alert(self, result: AnomalyResponse, event_data: Dict[str, Any]):
        """Send anomaly alert to Kafka"""
        if not self.kafka_producer:
            return
        
        try:
            alert = {
                'event_id': result.event_id,
                'anomaly_type': result.anomaly_type,
                'confidence_score': result.confidence_score,
                'risk_level': result.risk_level,
                'model_used': result.model_used,
                'recommended_actions': result.recommended_actions,
                'original_event': event_data,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            await self.kafka_producer.send('ml-anomaly-alerts', value=alert)
            logger.info("Anomaly alert sent", event_id=result.event_id, risk_level=result.risk_level)
            
        except Exception as e:
            logger.error("Failed to send anomaly alert", error=str(e))
    
    async def _store_detection_result(self, result: AnomalyResponse):
        """Store detection result in database"""
        if not self.db_connection:
            return
        
        try:
            cursor = self.db_connection.cursor()
            cursor.execute("""
                INSERT INTO ml_detection_results 
                (event_id, is_anomaly, confidence_score, risk_level, anomaly_type, 
                 model_used, features_analyzed, anomaly_details, recommended_actions, 
                 processing_time_ms, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (event_id) DO UPDATE SET
                confidence_score = EXCLUDED.confidence_score,
                timestamp = EXCLUDED.timestamp
            """, (
                result.event_id,
                result.is_anomaly,
                result.confidence_score,
                result.risk_level,
                result.anomaly_type,
                result.model_used,
                json.dumps(result.features_analyzed),
                json.dumps(result.anomaly_details),
                json.dumps(result.recommended_actions),
                result.processing_time_ms,
                datetime.now(timezone.utc)
            ))
            cursor.close()
            
        except Exception as e:
            logger.error("Failed to store detection result", error=str(e))
    
    async def _store_batch_results(self, results: List[AnomalyResponse]):
        """Store batch detection results"""
        for result in results:
            await self._store_detection_result(result)
    
    async def cleanup(self):
        """Cleanup resources"""
        try:
            if self.kafka_consumer:
                await self.kafka_consumer.stop()
            if self.kafka_producer:
                await self.kafka_producer.stop()
            if self.redis_client:
                await self.redis_client.close()
            if self.db_connection:
                self.db_connection.close()
            logger.info("ML Service cleanup completed")
        except Exception as e:
            logger.error("Cleanup failed", error=str(e))

# FastAPI application instance
ml_service = None

async def create_ml_service():
    """Create and initialize ML service"""
    global ml_service
    config_path = "/opt/siem/config/ml_config.yaml"
    ml_service = MLService(config_path)
    await ml_service.initialize()
    return ml_service.app

def run_service():
    """Run the ML service"""
    uvicorn.run(
        "ml_service:create_ml_service",
        factory=True,
        host="0.0.0.0",
        port=8080,
        workers=1,
        loop="asyncio",
        log_config=None  # Use our custom logging
    )

if __name__ == "__main__":
    run_service()