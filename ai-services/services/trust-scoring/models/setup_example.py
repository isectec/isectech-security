"""
Complete Trust Scoring Setup Example

This module provides a complete example of how to set up the trust scoring system
with device posture assessment, real MDM integration, and Redis caching.
"""

import asyncio
import logging
import os
from typing import Dict, Any, Optional

from .device_connectors import MDMCredentials
from .device_integration_service import (
    DeviceIntegrationService, 
    DeviceIntegrationServiceFactory,
    DeviceIntegrationConfig,
    MDMConfiguration
)
from .network_integration_service import (
    NetworkIntegrationService,
    NetworkIntegrationServiceFactory
)
from .device_cache import CacheConfig
from .trust_parameters import TrustScoreConfiguration
from ..service.trust_scoring_service import TrustScoringService, TrustScoreRequest
import redis.asyncio as redis

logger = logging.getLogger(__name__)


class TrustScoringSystemSetup:
    """Complete setup helper for the trust scoring system."""
    
    @staticmethod
    async def create_production_system(tenant_id: str) -> tuple[TrustScoringService, DeviceIntegrationService, NetworkIntegrationService]:
        """Create a complete production trust scoring system."""
        
        # 1. Configure MDM credentials from environment variables
        mdm_credentials = {}
        
        # Microsoft Intune configuration
        if all(os.getenv(key) for key in ["INTUNE_TENANT_ID", "INTUNE_CLIENT_ID", "INTUNE_CLIENT_SECRET"]):
            mdm_credentials["intune"] = MDMCredentials(
                platform="intune",
                tenant_id=os.getenv("INTUNE_TENANT_ID"),
                client_id=os.getenv("INTUNE_CLIENT_ID"),
                client_secret=os.getenv("INTUNE_CLIENT_SECRET")
            )
            logger.info("Microsoft Intune credentials configured")
        
        # VMware Workspace ONE configuration
        if all(os.getenv(key) for key in ["WORKSPACE_ONE_USERNAME", "WORKSPACE_ONE_PASSWORD", "WORKSPACE_ONE_API_KEY"]):
            mdm_credentials["workspace_one"] = MDMCredentials(
                platform="workspace_one",
                username=os.getenv("WORKSPACE_ONE_USERNAME"),
                password=os.getenv("WORKSPACE_ONE_PASSWORD"),
                api_key=os.getenv("WORKSPACE_ONE_API_KEY"),
                base_url=os.getenv("WORKSPACE_ONE_BASE_URL", "https://your-server.awmdm.com")
            )
            logger.info("VMware Workspace ONE credentials configured")
        
        # JAMF Pro configuration
        if all(os.getenv(key) for key in ["JAMF_USERNAME", "JAMF_PASSWORD"]):
            mdm_credentials["jamf"] = MDMCredentials(
                platform="jamf",
                username=os.getenv("JAMF_USERNAME"),
                password=os.getenv("JAMF_PASSWORD"),
                base_url=os.getenv("JAMF_BASE_URL", "https://your-server.jamfcloud.com")
            )
            logger.info("JAMF Pro credentials configured")
        
        # 2. Configure Redis
        redis_config = {
            "host": os.getenv("REDIS_HOST", "localhost"),
            "port": int(os.getenv("REDIS_PORT", "6379")),
            "db": int(os.getenv("REDIS_DB", "0")),
            "password": os.getenv("REDIS_PASSWORD"),
            "ssl": os.getenv("REDIS_SSL", "false").lower() == "true"
        }
        
        # 3. Create device integration service
        device_service = DeviceIntegrationServiceFactory.create_production_service(
            tenant_id=tenant_id,
            mdm_credentials=mdm_credentials,
            redis_config=redis_config
        )
        
        await device_service.initialize()
        logger.info("Device integration service initialized")
        
        # 4. Create network integration service
        network_service = NetworkIntegrationServiceFactory.create_production_service(
            tenant_id=tenant_id,
            corporate_ip_ranges=os.getenv("CORPORATE_IP_RANGES", "").split(",") if os.getenv("CORPORATE_IP_RANGES") else None,
            high_risk_countries=os.getenv("HIGH_RISK_COUNTRIES", "").split(",") if os.getenv("HIGH_RISK_COUNTRIES") else None
        )
        
        await network_service.initialize()
        logger.info("Network integration service initialized")
        
        # 5. Create Redis client for trust scoring service
        redis_client = redis.Redis(
            host=redis_config["host"],
            port=redis_config["port"],
            db=redis_config["db"],
            password=redis_config["password"],
            ssl=redis_config["ssl"]
        )
        
        # 6. Configure trust scoring parameters
        trust_config = TrustScoreConfiguration(
            behavioral_weight=0.4,
            device_weight=0.4,
            network_weight=0.2,
            enable_trend_analysis=True,
            anomaly_detection_threshold=0.7
        )
        
        # 7. Create trust scoring service
        trust_service = TrustScoringService(
            config=trust_config,
            redis_client=redis_client,
            tenant_id=tenant_id,
            device_integration_service=device_service,
            network_integration_service=network_service
        )
        
        logger.info(f"Complete trust scoring system initialized for tenant {tenant_id}")
        return trust_service, device_service, network_service
    
    @staticmethod
    async def create_development_system(tenant_id: str = "dev") -> tuple[TrustScoringService, Optional[DeviceIntegrationService], Optional[NetworkIntegrationService]]:
        """Create a development system with mock data."""
        
        # Simple Redis configuration for development
        redis_client = None
        try:
            redis_client = redis.Redis(host="localhost", port=6379, db=1)
            await redis_client.ping()
            logger.info("Connected to Redis for development")
        except Exception as e:
            logger.warning(f"Redis not available for development: {e}")
        
        # Create development device service (no real MDM connectors)
        device_service = DeviceIntegrationServiceFactory.create_development_service(tenant_id)
        
        try:
            await device_service.initialize()
            logger.info("Development device service initialized")
        except Exception as e:
            logger.warning(f"Device service initialization failed: {e}")
            device_service = None
        
        # Create development network service (no real threat intel/geolocation APIs)
        network_service = NetworkIntegrationServiceFactory.create_development_service(tenant_id)
        
        try:
            await network_service.initialize()
            logger.info("Development network service initialized")
        except Exception as e:
            logger.warning(f"Network service initialization failed: {e}")
            network_service = None
        
        # Configure trust scoring with development settings
        trust_config = TrustScoreConfiguration(
            behavioral_weight=0.4,
            device_weight=0.4,
            network_weight=0.2,
            enable_trend_analysis=False  # Disable for dev
        )
        
        # Create trust scoring service
        trust_service = TrustScoringService(
            config=trust_config,
            redis_client=redis_client,
            tenant_id=tenant_id,
            device_integration_service=device_service,
            network_integration_service=network_service
        )
        
        logger.info(f"Development trust scoring system initialized for tenant {tenant_id}")
        return trust_service, device_service, network_service


async def demo_trust_scoring():
    """Demonstration of the complete trust scoring system."""
    
    print("🔒 Trust Scoring System Demo")
    print("=" * 50)
    
    try:
        # Create development system
        trust_service, device_service, network_service = await TrustScoringSystemSetup.create_development_system("demo")
        
        print("✅ Trust scoring system initialized")
        
        # Demo device posture assessment
        print("\n📱 Testing Device Posture Assessment:")
        if device_service:
            device_posture = await device_service.assess_device_posture(
                device_id="demo-device-001",
                user_id="demo-user-001"
            )
            
            print(f"   Device ID: {device_posture.device_id}")
            print(f"   Trust Score: {device_posture.trust_score:.3f}")
            print(f"   Risk Score: {device_posture.overall_risk_score:.3f}")
            print(f"   Device Type: {device_posture.device_type.value}")
            print(f"   OS: {device_posture.operating_system.value}")
            print(f"   Managed: {device_posture.is_managed_device}")
            print(f"   Critical Issues: {len(device_posture.get_critical_issues())}")
        
        # Demo network context analysis
        print("\n🌐 Testing Network Context Analysis:")
        if network_service:
            network_context = await network_service.analyze_network_context(
                ip_address="192.168.1.100",
                user_id="demo-user-001",
                session_id="demo-session-001"
            )
            
            print(f"   IP Address: {network_context.ip_address}")
            print(f"   Network Trust Score: {network_context.calculate_network_trust_score():.3f}")
            print(f"   Risk Level: {network_context.risk_level.value}")
            print(f"   Network Type: {network_context.network_type.value}")
            print(f"   Country: {network_context.geolocation.country or 'Unknown'}")
            print(f"   ISP: {network_context.geolocation.isp or 'Unknown'}")
            print(f"   Threat Score: {network_context.threat_intel.reputation_score:.3f}")
            print(f"   Location Consistent: {network_context.location_consistency:.3f}")
            print(f"   VPN/Tor: {network_context.is_vpn}/{network_context.is_tor}")
        
        # Demo trust score calculation
        print("\n🎯 Testing Trust Score Calculation:")
        
        trust_request = TrustScoreRequest(
            entity_id="demo-user-001",
            entity_type="user",
            user_id="demo-user-001",
            device_id="demo-device-001",
            tenant_id="demo",
            current_ip="192.168.1.100"
        )
        
        trust_response = await trust_service.calculate_trust_score(trust_request)
        
        print(f"   Request ID: {trust_response.request_id}")
        print(f"   Trust Score: {trust_response.trust_score_result.trust_score:.3f}")
        print(f"   Trust Level: {trust_response.trust_score_result.trust_level.value}")
        print(f"   Confidence: {trust_response.trust_score_result.confidence:.3f}")
        print(f"   Processing Time: {trust_response.processing_time_ms}ms")
        print(f"   Cache Hit: {trust_response.cache_hit}")
        
        if trust_response.trust_score_result.anomaly_indicators:
            print(f"   🚨 Anomalies: {', '.join(trust_response.trust_score_result.anomaly_indicators)}")
        
        # Demo multiple device assessment
        print("\n📊 Testing Multiple Device Assessment:")
        device_ids = ["device-001", "device-002", "device-003"]
        
        if device_service:
            results = await device_service.assess_multiple_devices(device_ids)
            print(f"   Assessed {len(results)} devices:")
            
            for device_id, posture in results.items():
                print(f"     {device_id}: trust={posture.trust_score:.3f}, "
                     f"type={posture.device_type.value}, managed={posture.is_managed_device}")
        
        # Demo service health check
        print("\n🏥 System Health Check:")
        health_status = await trust_service.health_check()
        
        print(f"   Overall Status: {health_status['status']}")
        for check_name, check_result in health_status['checks'].items():
            if check_name != "device_integration_details":
                status_emoji = "✅" if "healthy" in str(check_result) else "❌"
                print(f"   {status_emoji} {check_name}: {check_result}")
        
        # Demo service metrics
        print("\n📈 Performance Metrics:")
        metrics = trust_service.get_service_metrics()
        
        print(f"   Requests Processed: {metrics['requests_processed']}")
        print(f"   Cache Hit Rate: {metrics['cache_hit_rate_percent']:.1f}%")
        print(f"   Avg Response Time: {metrics['avg_processing_time_ms']:.1f}ms")
        print(f"   Error Count: {metrics['error_count']}")
        
        if device_service:
            device_status = await device_service.get_service_status()
            device_metrics = device_status.get("performance_metrics", {})
            
            print(f"   Devices Assessed: {device_metrics.get('devices_assessed', 0)}")
            print(f"   MDM API Calls: {device_metrics.get('mdm_api_calls', 0)}")
        
        print("\n🎉 Demo completed successfully!")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        logger.error(f"Demo error: {e}")
        
    finally:
        # Cleanup
        try:
            if device_service:
                await device_service.shutdown()
            print("\n🧹 Cleanup completed")
        except Exception as e:
            print(f"⚠️  Cleanup warning: {e}")


def print_environment_setup_guide():
    """Print guide for setting up environment variables."""
    
    print("🔧 Environment Setup Guide")
    print("=" * 50)
    print()
    
    print("Redis Configuration:")
    print("  export REDIS_HOST=localhost")
    print("  export REDIS_PORT=6379")
    print("  export REDIS_DB=0")
    print("  export REDIS_PASSWORD=your_redis_password  # Optional")
    print("  export REDIS_SSL=false")
    print()
    
    print("Microsoft Intune (Optional):")
    print("  export INTUNE_TENANT_ID=your-tenant-id")
    print("  export INTUNE_CLIENT_ID=your-client-id")
    print("  export INTUNE_CLIENT_SECRET=your-client-secret")
    print()
    
    print("VMware Workspace ONE (Optional):")
    print("  export WORKSPACE_ONE_USERNAME=your-username")
    print("  export WORKSPACE_ONE_PASSWORD=your-password")
    print("  export WORKSPACE_ONE_API_KEY=your-api-key")
    print("  export WORKSPACE_ONE_BASE_URL=https://your-server.awmdm.com")
    print()
    
    print("JAMF Pro (Optional):")
    print("  export JAMF_USERNAME=your-username")
    print("  export JAMF_PASSWORD=your-password")
    print("  export JAMF_BASE_URL=https://your-server.jamfcloud.com")
    print()
    
    print("Threat Intelligence APIs (Optional):")
    print("  export VIRUSTOTAL_API_KEY=your-virustotal-api-key")
    print("  export ABUSEIPDB_API_KEY=your-abuseipdb-api-key") 
    print("  export GREYNOISE_API_KEY=your-greynoise-api-key")
    print("  export OTX_API_KEY=your-otx-api-key")
    print()
    
    print("Geolocation APIs (Optional):")
    print("  export MAXMIND_USER_ID=your-maxmind-user-id")
    print("  export MAXMIND_LICENSE_KEY=your-maxmind-license-key")
    print("  export IPINFO_API_KEY=your-ipinfo-api-key")
    print("  export IP2LOCATION_API_KEY=your-ip2location-api-key")
    print()
    
    print("Network Configuration (Optional):")
    print("  export CORPORATE_IP_RANGES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16")
    print("  export HIGH_RISK_COUNTRIES=CN,RU,KP  # Example countries")
    print()
    
    print("Note: At least one MDM platform should be configured for production use.")
    print("Threat intelligence and geolocation APIs enhance network risk assessment.")
    print("For development/testing, the system will use mock data if no APIs are configured.")


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "setup-guide":
        print_environment_setup_guide()
    else:
        # Run the demo
        asyncio.run(demo_trust_scoring())


# Export main setup classes
__all__ = [
    "TrustScoringSystemSetup",
    "demo_trust_scoring",
    "print_environment_setup_guide"
]