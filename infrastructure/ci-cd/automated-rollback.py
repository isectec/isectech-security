#!/usr/bin/env python3
"""
iSECTECH Automated Rollback System
Production-grade automated rollback with intelligent monitoring and decision-making
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import yaml


# Configuration
@dataclass
class RollbackConfig:
    """Configuration for automated rollback system"""
    project_id: str
    environment: str
    primary_region: str
    secondary_regions: List[str]
    monitoring_interval: int = 60  # seconds
    rollback_threshold_error_rate: float = 2.0  # percentage
    rollback_threshold_latency: int = 1000  # milliseconds
    rollback_threshold_availability: float = 99.0  # percentage
    health_check_retries: int = 3
    notification_channels: List[str] = None
    dry_run: bool = False

@dataclass
class ServiceMetrics:
    """Service health metrics"""
    service_name: str
    region: str
    error_rate: float
    latency_p95: float
    availability: float
    request_count: int
    timestamp: datetime
    healthy: bool

@dataclass
class DeploymentInfo:
    """Deployment information"""
    deployment_id: str
    build_version: str
    git_commit: str
    deployment_time: datetime
    services: List[str]
    regions: List[str]
    strategy: str

class AutomatedRollbackSystem:
    """Automated rollback system with intelligent monitoring"""
    
    def __init__(self, config: RollbackConfig):
        self.config = config
        self.logger = self._setup_logging()
        self.deployment_info: Optional[DeploymentInfo] = None
        self.rollback_in_progress = False
        self.monitoring_active = True
        
    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'/tmp/rollback-system-{datetime.now().strftime("%Y%m%d")}.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)
    
    async def load_deployment_info(self, deployment_id: str) -> Optional[DeploymentInfo]:
        """Load deployment information from storage"""
        try:
            # Load from Cloud Storage
            result = subprocess.run([
                'gsutil', 'cat', 
                f'gs://{self.config.project_id}-deployment-artifacts/rollback-configs/{deployment_id}.json'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                deployment_info = DeploymentInfo(
                    deployment_id=data['deployment_id'],
                    build_version=data['build_version'],
                    git_commit=data['git_commit'],
                    deployment_time=datetime.fromisoformat(data['deployment_time'].replace('Z', '+00:00')),
                    services=data['services_deployed'],
                    regions=[data['primary_region']] + data['secondary_regions'].split(','),
                    strategy=data.get('deployment_strategy', 'blue-green')
                )
                
                self.deployment_info = deployment_info
                self.logger.info(f"Loaded deployment info: {deployment_id}")
                return deployment_info
            else:
                self.logger.error(f"Failed to load deployment info: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error loading deployment info: {e}")
            return None
    
    async def get_service_metrics(self, service: str, region: str) -> Optional[ServiceMetrics]:
        """Get service health metrics from monitoring systems"""
        try:
            # Get service URL
            service_name = f"isectech-{service}-{self.config.environment}-{region}"
            
            result = subprocess.run([
                'gcloud', 'run', 'services', 'describe', service_name,
                '--region', region,
                '--format', 'value(status.url)'
            ], capture_output=True, text=True)
            
            if result.returncode != 0 or not result.stdout.strip():
                self.logger.warning(f"Could not get URL for {service_name}")
                return None
            
            service_url = result.stdout.strip()
            
            # Perform health check
            async with aiohttp.ClientSession() as session:
                start_time = time.time()
                try:
                    async with session.get(f"{service_url}/health", timeout=30) as response:
                        response_time = (time.time() - start_time) * 1000
                        
                        if response.status == 200:
                            # Service is responding - simulate metrics collection
                            # In production, this would query actual monitoring systems
                            metrics = ServiceMetrics(
                                service_name=service,
                                region=region,
                                error_rate=0.5,  # Would come from actual metrics
                                latency_p95=response_time,
                                availability=99.5,
                                request_count=1000,
                                timestamp=datetime.now(),
                                healthy=True
                            )
                        else:
                            metrics = ServiceMetrics(
                                service_name=service,
                                region=region,
                                error_rate=100.0,
                                latency_p95=30000,
                                availability=0.0,
                                request_count=0,
                                timestamp=datetime.now(),
                                healthy=False
                            )
                            
                except asyncio.TimeoutError:
                    metrics = ServiceMetrics(
                        service_name=service,
                        region=region,
                        error_rate=100.0,
                        latency_p95=30000,
                        availability=0.0,
                        request_count=0,
                        timestamp=datetime.now(),
                        healthy=False
                    )
                
                return metrics
                
        except Exception as e:
            self.logger.error(f"Error getting metrics for {service} in {region}: {e}")
            return None
    
    async def should_rollback(self, metrics_list: List[ServiceMetrics]) -> Tuple[bool, List[str]]:
        """Determine if rollback should be triggered based on metrics"""
        rollback_reasons = []
        
        for metrics in metrics_list:
            # Check error rate threshold
            if metrics.error_rate > self.config.rollback_threshold_error_rate:
                rollback_reasons.append(
                    f"{metrics.service_name} in {metrics.region}: Error rate {metrics.error_rate:.2f}% > {self.config.rollback_threshold_error_rate}%"
                )
            
            # Check latency threshold
            if metrics.latency_p95 > self.config.rollback_threshold_latency:
                rollback_reasons.append(
                    f"{metrics.service_name} in {metrics.region}: Latency {metrics.latency_p95:.1f}ms > {self.config.rollback_threshold_latency}ms"
                )
            
            # Check availability threshold
            if metrics.availability < self.config.rollback_threshold_availability:
                rollback_reasons.append(
                    f"{metrics.service_name} in {metrics.region}: Availability {metrics.availability:.2f}% < {self.config.rollback_threshold_availability}%"
                )
            
            # Check if service is completely unhealthy
            if not metrics.healthy:
                rollback_reasons.append(
                    f"{metrics.service_name} in {metrics.region}: Service unhealthy"
                )
        
        should_rollback = len(rollback_reasons) > 0
        return should_rollback, rollback_reasons
    
    async def execute_rollback(self, service: str, region: str) -> bool:
        """Execute rollback for a specific service in a region"""
        try:
            service_name = f"isectech-{service}-{self.config.environment}-{region}"
            
            self.logger.info(f"Starting rollback for {service} in {region}")
            
            if self.config.dry_run:
                self.logger.info(f"[DRY RUN] Would rollback {service_name}")
                await asyncio.sleep(2)  # Simulate rollback time
                return True
            
            # Get previous stable revision
            result = subprocess.run([
                'gcloud', 'run', 'revisions', 'list',
                '--service', service_name,
                '--region', region,
                '--filter', 'metadata.labels.deployment!=blue AND metadata.labels.deployment!=canary',
                '--sort-by', '~metadata.creationTimestamp',
                '--limit', '1',
                '--format', 'value(metadata.name)'
            ], capture_output=True, text=True)
            
            if result.returncode != 0 or not result.stdout.strip():
                self.logger.error(f"Could not find previous revision for {service_name}")
                return False
            
            previous_revision = result.stdout.strip()
            self.logger.info(f"Rolling back to revision: {previous_revision}")
            
            # Execute rollback
            rollback_result = subprocess.run([
                'gcloud', 'run', 'services', 'update-traffic', service_name,
                '--to-revisions', f'{previous_revision}=100',
                '--region', region,
                '--quiet'
            ], capture_output=True, text=True)
            
            if rollback_result.returncode == 0:
                self.logger.info(f"✓ Rollback completed for {service} in {region}")
                
                # Wait for rollback to take effect
                await asyncio.sleep(30)
                
                # Verify rollback success
                metrics = await self.get_service_metrics(service, region)
                if metrics and metrics.healthy:
                    self.logger.info(f"✓ Rollback verification successful for {service} in {region}")
                    return True
                else:
                    self.logger.warning(f"⚠ Rollback verification failed for {service} in {region}")
                    return False
            else:
                self.logger.error(f"❌ Rollback failed for {service} in {region}: {rollback_result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error executing rollback for {service} in {region}: {e}")
            return False
    
    async def notify_rollback(self, reasons: List[str], services_affected: List[str]):
        """Send notifications about rollback"""
        try:
            notification_data = {
                "timestamp": datetime.now().isoformat(),
                "deployment_id": self.deployment_info.deployment_id if self.deployment_info else "unknown",
                "build_version": self.deployment_info.build_version if self.deployment_info else "unknown",
                "rollback_reasons": reasons,
                "services_affected": services_affected,
                "project_id": self.config.project_id,
                "environment": self.config.environment
            }
            
            # Log notification (in production, this would send to actual notification channels)
            self.logger.critical(f"ROLLBACK TRIGGERED: {json.dumps(notification_data, indent=2)}")
            
            # Save notification to file
            notification_file = f"/tmp/rollback-notification-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            with open(notification_file, 'w') as f:
                json.dump(notification_data, f, indent=2)
            
            # Upload to Cloud Storage
            subprocess.run([
                'gsutil', 'cp', notification_file,
                f'gs://{self.config.project_id}-deployment-artifacts/rollback-notifications/'
            ], capture_output=True)
            
        except Exception as e:
            self.logger.error(f"Error sending notifications: {e}")
    
    async def monitor_deployment(self, deployment_id: str):
        """Main monitoring loop for deployment health"""
        self.logger.info(f"Starting deployment monitoring for: {deployment_id}")
        
        # Load deployment information
        deployment_info = await self.load_deployment_info(deployment_id)
        if not deployment_info:
            self.logger.error("Could not load deployment info, exiting monitoring")
            return
        
        # Monitor for specified duration (e.g., 1 hour)
        monitoring_start = datetime.now()
        monitoring_duration = timedelta(hours=1)
        
        while self.monitoring_active and datetime.now() - monitoring_start < monitoring_duration:
            try:
                if self.rollback_in_progress:
                    self.logger.info("Rollback in progress, pausing monitoring...")
                    await asyncio.sleep(30)
                    continue
                
                self.logger.info("Collecting service metrics...")
                
                # Collect metrics from all services and regions
                all_metrics = []
                tasks = []
                
                for service in deployment_info.services:
                    for region in deployment_info.regions:
                        task = self.get_service_metrics(service, region)
                        tasks.append(task)
                
                # Wait for all metric collection tasks
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if isinstance(result, ServiceMetrics):
                        all_metrics.append(result)
                    elif isinstance(result, Exception):
                        self.logger.error(f"Error collecting metrics: {result}")
                
                if not all_metrics:
                    self.logger.warning("No metrics collected, skipping this cycle")
                    await asyncio.sleep(self.config.monitoring_interval)
                    continue
                
                # Check if rollback should be triggered
                should_rollback, rollback_reasons = await self.should_rollback(all_metrics)
                
                if should_rollback:
                    self.logger.critical(f"Rollback criteria met! Reasons: {rollback_reasons}")
                    
                    # Trigger rollback
                    self.rollback_in_progress = True
                    
                    # Identify affected services
                    affected_services = list(set([m.service_name for m in all_metrics if not m.healthy]))
                    
                    # Send notifications
                    await self.notify_rollback(rollback_reasons, affected_services)
                    
                    # Execute rollback for affected services
                    rollback_tasks = []
                    for service in deployment_info.services:
                        for region in deployment_info.regions:
                            # Check if this service-region combo needs rollback
                            service_metrics = [m for m in all_metrics if m.service_name == service and m.region == region]
                            if service_metrics and not service_metrics[0].healthy:
                                task = self.execute_rollback(service, region)
                                rollback_tasks.append(task)
                    
                    # Wait for all rollbacks to complete
                    if rollback_tasks:
                        rollback_results = await asyncio.gather(*rollback_tasks, return_exceptions=True)
                        successful_rollbacks = sum(1 for r in rollback_results if r is True)
                        total_rollbacks = len(rollback_tasks)
                        
                        self.logger.info(f"Rollback completed: {successful_rollbacks}/{total_rollbacks} successful")
                    
                    # Stop monitoring after rollback
                    self.monitoring_active = False
                    break
                else:
                    # Log healthy status
                    healthy_services = [m for m in all_metrics if m.healthy]
                    unhealthy_services = [m for m in all_metrics if not m.healthy]
                    
                    self.logger.info(
                        f"Deployment health check: {len(healthy_services)} healthy, "
                        f"{len(unhealthy_services)} unhealthy services"
                    )
                    
                    if unhealthy_services:
                        for metrics in unhealthy_services:
                            self.logger.warning(
                                f"Unhealthy service: {metrics.service_name} in {metrics.region} "
                                f"(error_rate: {metrics.error_rate:.2f}%, "
                                f"latency: {metrics.latency_p95:.1f}ms, "
                                f"availability: {metrics.availability:.2f}%)"
                            )
                
                # Wait before next monitoring cycle
                await asyncio.sleep(self.config.monitoring_interval)
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(self.config.monitoring_interval)
        
        self.logger.info("Deployment monitoring completed")
    
    def stop_monitoring(self):
        """Stop the monitoring loop"""
        self.monitoring_active = False
        self.logger.info("Monitoring stop requested")


async def main():
    """Main entry point"""
    # Configuration
    config = RollbackConfig(
        project_id=os.getenv('PROJECT_ID', 'isectech-security-platform'),
        environment=os.getenv('ENVIRONMENT', 'production'),
        primary_region=os.getenv('PRIMARY_REGION', 'us-central1'),
        secondary_regions=os.getenv('SECONDARY_REGIONS', 'europe-west1,asia-northeast1,australia-southeast1').split(','),
        monitoring_interval=int(os.getenv('MONITORING_INTERVAL', '60')),
        rollback_threshold_error_rate=float(os.getenv('ROLLBACK_THRESHOLD_ERROR_RATE', '2.0')),
        rollback_threshold_latency=int(os.getenv('ROLLBACK_THRESHOLD_LATENCY', '1000')),
        rollback_threshold_availability=float(os.getenv('ROLLBACK_THRESHOLD_AVAILABILITY', '99.0')),
        dry_run=os.getenv('DRY_RUN', 'false').lower() == 'true'
    )
    
    # Get deployment ID from command line or environment
    import sys
    deployment_id = sys.argv[1] if len(sys.argv) > 1 else os.getenv('DEPLOYMENT_ID')
    
    if not deployment_id:
        print("Usage: python automated-rollback.py <deployment_id>")
        print("Or set DEPLOYMENT_ID environment variable")
        sys.exit(1)
    
    # Initialize and start monitoring
    rollback_system = AutomatedRollbackSystem(config)
    
    try:
        await rollback_system.monitor_deployment(deployment_id)
    except KeyboardInterrupt:
        rollback_system.stop_monitoring()
        print("\nMonitoring stopped by user")
    except Exception as e:
        logging.error(f"Fatal error in rollback system: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())