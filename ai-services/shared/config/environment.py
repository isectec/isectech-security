"""
Environment configuration utilities for iSECTECH AI services.

This module provides utilities for managing environment-specific configurations
and ensuring proper deployment across different environments.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Optional

from .settings import Environment, Settings


class EnvironmentManager:
    """Manages environment-specific configurations and validations."""
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.environment = settings.environment
    
    def validate_environment(self) -> bool:
        """Validate environment configuration and requirements."""
        validation_methods = {
            Environment.DEVELOPMENT: self._validate_development,
            Environment.STAGING: self._validate_staging,
            Environment.PRODUCTION: self._validate_production,
        }
        
        return validation_methods[self.environment]()
    
    def _validate_development(self) -> bool:
        """Validate development environment requirements."""
        # Development can be more lenient
        return True
    
    def _validate_staging(self) -> bool:
        """Validate staging environment requirements."""
        required_vars = [
            "ISECTECH_DB_POSTGRESQL_PASSWORD",
            "ISECTECH_SECURITY_JWT_SECRET_KEY",
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            print(f"Missing required environment variables for staging: {missing_vars}")
            return False
        
        return True
    
    def _validate_production(self) -> bool:
        """Validate production environment requirements."""
        required_vars = [
            "ISECTECH_DB_POSTGRESQL_PASSWORD",
            "ISECTECH_DB_MONGODB_PASSWORD",
            "ISECTECH_DB_REDIS_PASSWORD",
            "ISECTECH_SECURITY_JWT_SECRET_KEY",
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            print(f"Missing required environment variables for production: {missing_vars}")
            return False
        
        # Production-specific validations
        if not self.settings.database.enable_ssl:
            print("SSL must be enabled in production")
            return False
        
        if not self.settings.security.enable_audit_logging:
            print("Audit logging must be enabled in production")
            return False
        
        if self.settings.security.default_security_classification.value == "UNCLASSIFIED":
            print("Warning: Using UNCLASSIFIED as default security classification in production")
        
        return True
    
    def get_environment_config(self) -> Dict:
        """Get environment-specific configuration overrides."""
        config_overrides = {
            Environment.DEVELOPMENT: {
                "reload": True,
                "workers": 1,
                "log_level": "DEBUG",
                "enable_ssl": False,
            },
            Environment.STAGING: {
                "reload": False,
                "workers": 2,
                "log_level": "INFO",
                "enable_ssl": True,
            },
            Environment.PRODUCTION: {
                "reload": False,
                "workers": 4,
                "log_level": "WARNING",
                "enable_ssl": True,
                "enable_audit_logging": True,
            },
        }
        
        return config_overrides.get(self.environment, {})
    
    def setup_directories(self) -> None:
        """Create necessary directories for the service."""
        directories = [
            self.settings.data_directory,
            self.settings.model_directory,
            self.settings.log_directory,
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            
            # Set appropriate permissions for production
            if self.environment == Environment.PRODUCTION:
                os.chmod(directory, 0o750)
    
    def get_resource_limits(self) -> Dict:
        """Get environment-specific resource limits."""
        limits = {
            Environment.DEVELOPMENT: {
                "max_memory_mb": 2048,
                "max_cpu_cores": 2,
                "max_gpu_memory_fraction": 0.5,
            },
            Environment.STAGING: {
                "max_memory_mb": 8192,
                "max_cpu_cores": 4,
                "max_gpu_memory_fraction": 0.7,
            },
            Environment.PRODUCTION: {
                "max_memory_mb": 32768,
                "max_cpu_cores": 16,
                "max_gpu_memory_fraction": 0.9,
            },
        }
        
        return limits.get(self.environment, limits[Environment.DEVELOPMENT])
    
    def configure_python_environment(self) -> None:
        """Configure Python environment settings."""
        # Set Python path
        current_dir = Path(__file__).parent.parent.parent
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))
        
        # Configure TensorFlow/PyTorch settings based on environment
        if self.environment == Environment.PRODUCTION:
            # Production optimizations
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")  # Reduce TF logging
            os.environ.setdefault("CUDA_CACHE_DISABLE", "0")    # Enable CUDA caching
        else:
            # Development settings
            os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "1")
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for API responses."""
        base_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        
        if self.environment == Environment.PRODUCTION:
            base_headers.update({
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
            })
        
        return base_headers


def setup_environment(settings: Settings) -> EnvironmentManager:
    """Setup and validate environment configuration."""
    env_manager = EnvironmentManager(settings)
    
    # Validate environment
    if not env_manager.validate_environment():
        raise ValueError(f"Invalid configuration for {settings.environment} environment")
    
    # Setup directories
    env_manager.setup_directories()
    
    # Configure Python environment
    env_manager.configure_python_environment()
    
    return env_manager


def get_deployment_info() -> Dict:
    """Get deployment information for monitoring and debugging."""
    return {
        "python_version": sys.version,
        "platform": sys.platform,
        "executable": sys.executable,
        "environment_variables": {
            key: value for key, value in os.environ.items()
            if key.startswith("ISECTECH_") and "PASSWORD" not in key and "SECRET" not in key
        },
        "working_directory": os.getcwd(),
        "user": os.getenv("USER", "unknown"),
    }