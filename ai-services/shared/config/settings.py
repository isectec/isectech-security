"""
Production-grade configuration management for iSECTECH AI services.

This module provides comprehensive configuration management with security,
multi-tenancy, and enterprise features.
"""

import os
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Union

from pydantic import BaseSettings, Field, validator
from pydantic_settings import SettingsConfigDict


class Environment(str, Enum):
    """Deployment environment types."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class SecurityClassification(str, Enum):
    """Security classification levels for data and operations."""
    UNCLASSIFIED = "UNCLASSIFIED"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP_SECRET"


class DatabaseType(str, Enum):
    """Supported database types."""
    POSTGRESQL = "postgresql"
    MONGODB = "mongodb"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"


class MLFramework(str, Enum):
    """Supported ML frameworks."""
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    SKLEARN = "sklearn"
    HUGGINGFACE = "huggingface"


class SecuritySettings(BaseSettings):
    """Security configuration for AI services."""
    
    # Encryption settings
    encryption_algorithm: str = Field(default="AES-256-GCM", description="Encryption algorithm for sensitive data")
    key_rotation_interval_hours: int = Field(default=24, description="Key rotation interval in hours")
    
    # Authentication and authorization
    jwt_secret_key: str = Field(..., description="JWT secret key for token validation")
    jwt_algorithm: str = Field(default="HS256", description="JWT signing algorithm")
    jwt_expiration_minutes: int = Field(default=60, description="JWT token expiration in minutes")
    
    # Multi-tenancy and access control
    enable_multi_tenancy: bool = Field(default=True, description="Enable multi-tenant isolation")
    default_security_classification: SecurityClassification = Field(
        default=SecurityClassification.UNCLASSIFIED,
        description="Default security classification level"
    )
    
    # API security
    api_rate_limit_per_minute: int = Field(default=1000, description="API rate limit per minute per client")
    enable_api_key_auth: bool = Field(default=True, description="Enable API key authentication")
    
    # Audit and compliance
    enable_audit_logging: bool = Field(default=True, description="Enable comprehensive audit logging")
    audit_log_retention_days: int = Field(default=2555, description="Audit log retention period (7 years)")
    
    # Model security
    enable_model_encryption: bool = Field(default=True, description="Encrypt ML models at rest")
    enable_adversarial_protection: bool = Field(default=True, description="Enable adversarial attack protection")
    
    model_config = SettingsConfigDict(
        env_prefix="ISECTECH_SECURITY_",
        case_sensitive=False
    )


class DatabaseSettings(BaseSettings):
    """Database configuration for AI services."""
    
    # PostgreSQL settings
    postgresql_host: str = Field(default="localhost", description="PostgreSQL host")
    postgresql_port: int = Field(default=5432, description="PostgreSQL port")
    postgresql_database: str = Field(default="isectech", description="PostgreSQL database name")
    postgresql_username: str = Field(..., description="PostgreSQL username")
    postgresql_password: str = Field(..., description="PostgreSQL password")
    postgresql_pool_size: int = Field(default=20, description="PostgreSQL connection pool size")
    postgresql_max_overflow: int = Field(default=30, description="PostgreSQL max overflow connections")
    
    # MongoDB settings
    mongodb_host: str = Field(default="localhost", description="MongoDB host")
    mongodb_port: int = Field(default=27017, description="MongoDB port")
    mongodb_database: str = Field(default="isectech", description="MongoDB database name")
    mongodb_username: Optional[str] = Field(default=None, description="MongoDB username")
    mongodb_password: Optional[str] = Field(default=None, description="MongoDB password")
    mongodb_pool_size: int = Field(default=50, description="MongoDB connection pool size")
    
    # Redis settings
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_database: int = Field(default=0, description="Redis database number")
    redis_password: Optional[str] = Field(default=None, description="Redis password")
    redis_pool_size: int = Field(default=50, description="Redis connection pool size")
    
    # Elasticsearch settings
    elasticsearch_hosts: List[str] = Field(default=["localhost:9200"], description="Elasticsearch hosts")
    elasticsearch_username: Optional[str] = Field(default=None, description="Elasticsearch username")
    elasticsearch_password: Optional[str] = Field(default=None, description="Elasticsearch password")
    
    # Connection settings
    connection_timeout_seconds: int = Field(default=30, description="Database connection timeout")
    query_timeout_seconds: int = Field(default=300, description="Database query timeout")
    enable_ssl: bool = Field(default=True, description="Enable SSL/TLS for database connections")
    
    model_config = SettingsConfigDict(
        env_prefix="ISECTECH_DB_",
        case_sensitive=False
    )

    @property
    def postgresql_url(self) -> str:
        """Generate PostgreSQL connection URL."""
        return (
            f"postgresql://{self.postgresql_username}:{self.postgresql_password}"
            f"@{self.postgresql_host}:{self.postgresql_port}/{self.postgresql_database}"
        )

    @property
    def mongodb_url(self) -> str:
        """Generate MongoDB connection URL."""
        if self.mongodb_username and self.mongodb_password:
            return (
                f"mongodb://{self.mongodb_username}:{self.mongodb_password}"
                f"@{self.mongodb_host}:{self.mongodb_port}/{self.mongodb_database}"
            )
        return f"mongodb://{self.mongodb_host}:{self.mongodb_port}/{self.mongodb_database}"


class MLSettings(BaseSettings):
    """Machine Learning configuration for AI services."""
    
    # Model training settings
    default_batch_size: int = Field(default=32, description="Default batch size for training")
    default_learning_rate: float = Field(default=0.001, description="Default learning rate")
    default_epochs: int = Field(default=100, description="Default number of training epochs")
    
    # Model inference settings
    inference_batch_size: int = Field(default=64, description="Batch size for inference")
    max_sequence_length: int = Field(default=512, description="Maximum sequence length for NLP models")
    model_cache_size_mb: int = Field(default=1024, description="Model cache size in MB")
    
    # Behavioral analysis settings
    behavioral_baseline_days: int = Field(default=30, description="Days of data for behavioral baseline")
    anomaly_threshold: float = Field(default=0.95, description="Anomaly detection threshold")
    confidence_threshold: float = Field(default=0.8, description="Minimum confidence threshold")
    
    # Model serving settings
    model_workers: int = Field(default=4, description="Number of model serving workers")
    enable_model_caching: bool = Field(default=True, description="Enable model caching")
    model_warmup_requests: int = Field(default=10, description="Number of warmup requests for models")
    
    # Experiment tracking
    mlflow_tracking_uri: Optional[str] = Field(default=None, description="MLflow tracking server URI")
    experiment_name: str = Field(default="isectech-ai", description="Default experiment name")
    
    # Hardware acceleration
    enable_gpu: bool = Field(default=True, description="Enable GPU acceleration if available")
    gpu_memory_fraction: float = Field(default=0.8, description="Fraction of GPU memory to use")
    
    # Data processing
    max_parallel_workers: int = Field(default=8, description="Maximum parallel workers for data processing")
    data_preprocessing_cache_size_gb: float = Field(default=2.0, description="Data preprocessing cache size in GB")
    
    model_config = SettingsConfigDict(
        env_prefix="ISECTECH_ML_",
        case_sensitive=False
    )

    @validator("anomaly_threshold")
    def validate_anomaly_threshold(cls, v):
        """Validate anomaly threshold is between 0 and 1."""
        if not 0 < v < 1:
            raise ValueError("Anomaly threshold must be between 0 and 1")
        return v

    @validator("confidence_threshold")
    def validate_confidence_threshold(cls, v):
        """Validate confidence threshold is between 0 and 1."""
        if not 0 < v < 1:
            raise ValueError("Confidence threshold must be between 0 and 1")
        return v

    @validator("gpu_memory_fraction")
    def validate_gpu_memory_fraction(cls, v):
        """Validate GPU memory fraction is between 0 and 1."""
        if not 0 < v <= 1:
            raise ValueError("GPU memory fraction must be between 0 and 1")
        return v


class MonitoringSettings(BaseSettings):
    """Monitoring and observability configuration."""
    
    # Metrics settings
    enable_prometheus_metrics: bool = Field(default=True, description="Enable Prometheus metrics")
    metrics_port: int = Field(default=8090, description="Metrics server port")
    metrics_path: str = Field(default="/metrics", description="Metrics endpoint path")
    
    # Health check settings
    health_check_interval_seconds: int = Field(default=30, description="Health check interval")
    health_check_timeout_seconds: int = Field(default=10, description="Health check timeout")
    
    # Logging settings
    log_level: str = Field(default="INFO", description="Logging level")
    log_format: str = Field(default="json", description="Log format (json or text)")
    enable_structured_logging: bool = Field(default=True, description="Enable structured logging")
    
    # Alerting settings
    enable_alerting: bool = Field(default=True, description="Enable alerting")
    alert_webhook_url: Optional[str] = Field(default=None, description="Webhook URL for alerts")
    
    # Performance monitoring
    enable_performance_tracking: bool = Field(default=True, description="Enable performance tracking")
    slow_query_threshold_seconds: float = Field(default=1.0, description="Slow query threshold")
    
    model_config = SettingsConfigDict(
        env_prefix="ISECTECH_MONITORING_",
        case_sensitive=False
    )


class Settings(BaseSettings):
    """Main configuration class for iSECTECH AI services."""
    
    # Environment settings
    environment: Environment = Field(default=Environment.DEVELOPMENT, description="Deployment environment")
    service_name: str = Field(..., description="Service name")
    service_version: str = Field(default="1.0.0", description="Service version")
    
    # API settings
    host: str = Field(default="0.0.0.0", description="API host")
    port: int = Field(default=8000, description="API port")
    reload: bool = Field(default=False, description="Enable auto-reload for development")
    
    # Worker settings
    workers: int = Field(default=1, description="Number of worker processes")
    worker_class: str = Field(default="uvicorn.workers.UvicornWorker", description="Worker class")
    
    # Request settings
    max_request_size_mb: int = Field(default=100, description="Maximum request size in MB")
    request_timeout_seconds: int = Field(default=300, description="Request timeout in seconds")
    
    # Component settings
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    ml: MLSettings = Field(default_factory=MLSettings)
    monitoring: MonitoringSettings = Field(default_factory=MonitoringSettings)
    
    # File paths
    data_directory: Path = Field(default=Path("/data"), description="Data directory path")
    model_directory: Path = Field(default=Path("/models"), description="Model directory path")
    log_directory: Path = Field(default=Path("/logs"), description="Log directory path")
    
    model_config = SettingsConfigDict(
        env_prefix="ISECTECH_",
        case_sensitive=False,
        env_file=".env",
        env_file_encoding="utf-8"
    )

    @validator("environment", pre=True)
    def validate_environment(cls, v):
        """Validate environment value."""
        if isinstance(v, str):
            return Environment(v.lower())
        return v

    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment == Environment.DEVELOPMENT

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION

    def get_log_config(self) -> Dict:
        """Get logging configuration."""
        return {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                },
                "json": {
                    "()": "structlog.stdlib.ProcessorFormatter",
                    "processor": "structlog.processors.JSONRenderer",
                },
            },
            "handlers": {
                "default": {
                    "formatter": "json" if self.monitoring.log_format == "json" else "default",
                    "class": "logging.StreamHandler",
                    "stream": "ext://sys.stdout",
                },
            },
            "root": {
                "level": self.monitoring.log_level,
                "handlers": ["default"],
            },
        }


def get_settings() -> Settings:
    """Get application settings with caching."""
    return Settings()