#!/usr/bin/env python3
"""
Health check script for ML Service Docker container
Verifies service availability and model readiness
"""

import sys
import time
import requests
import json
from typing import Dict, Any

def check_service_health() -> Dict[str, Any]:
    """Check ML service health"""
    try:
        # Check main health endpoint
        response = requests.get('http://localhost:8080/health', timeout=5)
        
        if response.status_code == 200:
            health_data = response.json()
            
            # Check if models are loaded
            if health_data.get('models_loaded', 0) > 0:
                return {
                    'status': 'healthy',
                    'models_loaded': health_data.get('models_loaded'),
                    'uptime': health_data.get('uptime_seconds'),
                    'response_time_ms': response.elapsed.total_seconds() * 1000
                }
            else:
                return {
                    'status': 'unhealthy',
                    'reason': 'No models loaded',
                    'models_loaded': 0
                }
        else:
            return {
                'status': 'unhealthy',
                'reason': f'HTTP {response.status_code}',
                'response': response.text[:200]
            }
            
    except requests.exceptions.ConnectionError:
        return {
            'status': 'unhealthy',
            'reason': 'Service not responding'
        }
    except requests.exceptions.Timeout:
        return {
            'status': 'unhealthy',
            'reason': 'Service timeout'
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'reason': f'Health check failed: {str(e)}'
        }

def check_metrics_endpoint() -> bool:
    """Check if metrics endpoint is responding"""
    try:
        response = requests.get('http://localhost:8080/metrics', timeout=3)
        return response.status_code == 200
    except:
        return False

def main():
    """Main health check function"""
    print("Starting ML Service health check...")
    
    # Wait a bit for service to start
    time.sleep(2)
    
    # Check service health
    health_result = check_service_health()
    
    print(f"Health check result: {json.dumps(health_result, indent=2)}")
    
    if health_result['status'] == 'healthy':
        # Additional checks
        metrics_ok = check_metrics_endpoint()
        
        if metrics_ok:
            print("✓ All health checks passed")
            sys.exit(0)
        else:
            print("✗ Metrics endpoint not responding")
            sys.exit(1)
    else:
        print(f"✗ Health check failed: {health_result.get('reason', 'Unknown')}")
        sys.exit(1)

if __name__ == "__main__":
    main()