#!/usr/bin/env python3
"""
iSECTECH Network Security Monitoring Load Testing Framework
Comprehensive load and stress testing for NSM components including packet capture and analysis systems
"""

import asyncio
import json
import logging
import random
import time
import uuid
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import subprocess
import requests
import yaml
import numpy as np
import socket
import struct
from scapy.all import IP, TCP, UDP, Raw, send, sr1, conf
from collections import defaultdict


@dataclass
class LoadTestConfig:
    """Load test configuration"""
    test_name: str
    target_component: str
    test_duration_seconds: int
    concurrent_users: int
    requests_per_second: int
    ramp_up_time: int
    ramp_down_time: int
    test_data_file: Optional[str] = None
    custom_payload: Optional[Dict[str, Any]] = None


@dataclass
class LoadTestResult:
    """Load test result metrics"""
    test_id: str
    test_name: str
    component: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    
    # Request metrics
    total_requests: int
    successful_requests: int
    failed_requests: int
    requests_per_second: float
    
    # Response time metrics
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p50_response_time: float
    p95_response_time: float
    p99_response_time: float
    
    # Error metrics
    error_rate: float
    timeout_count: int
    connection_errors: int
    
    # Resource utilization
    peak_cpu_usage: float
    peak_memory_usage: float
    peak_disk_io: float
    peak_network_io: float
    
    # Custom metrics
    custom_metrics: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.custom_metrics is None:
            self.custom_metrics = {}


@dataclass
class StressTestScenario:
    """Stress test scenario definition"""
    scenario_name: str
    component: str
    stress_type: str  # cpu, memory, network, disk, concurrent_connections
    intensity_levels: List[int]  # Increasing intensity levels
    duration_per_level: int
    recovery_time: int
    failure_threshold: float  # Error rate threshold to consider failure


class NetworkPacketGenerator:
    """Generate realistic network packets for testing"""
    
    def __init__(self):
        self.src_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.50", "10.0.0.51", "172.16.0.10", "172.16.0.11"
        ]
        self.dst_ips = [
            "8.8.8.8", "1.1.1.1", "208.67.222.222",
            "10.0.0.1", "192.168.1.1", "172.16.0.1"
        ]
        self.ports = [80, 443, 22, 21, 25, 53, 8080, 8443, 3389, 23]
        
    def generate_tcp_packet(self, size: int = None) -> bytes:
        """Generate a TCP packet"""
        src_ip = random.choice(self.src_ips)
        dst_ip = random.choice(self.dst_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.ports)
        
        # Create packet with Scapy
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
        
        if size:
            payload_size = max(0, size - len(packet))
            payload = 'A' * payload_size
            packet = packet / Raw(load=payload)
        
        return bytes(packet)
    
    def generate_udp_packet(self, size: int = None) -> bytes:
        """Generate a UDP packet"""
        src_ip = random.choice(self.src_ips)
        dst_ip = random.choice(self.dst_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(self.ports)
        
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
        
        if size:
            payload_size = max(0, size - len(packet))
            payload = 'B' * payload_size
            packet = packet / Raw(load=payload)
        
        return bytes(packet)
    
    def generate_malicious_packet(self) -> bytes:
        """Generate a packet that should trigger detection"""
        # Create a packet with a signature that should be detected
        malicious_payloads = [
            b"GET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n",
            b"SELECT * FROM users WHERE id=1 OR 1=1",
            b"<script>alert('xss')</script>",
            b"\x90\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68",  # Shellcode pattern
        ]
        
        src_ip = random.choice(self.src_ips)
        dst_ip = random.choice(self.dst_ips)
        
        packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=12345, dport=80) / Raw(load=random.choice(malicious_payloads))
        return bytes(packet)


class NSMLoadTestFramework:
    """Main load testing framework for NSM components"""
    
    def __init__(self, config_path: str = "/etc/nsm/load_testing.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Network packet generator
        self.packet_generator = NetworkPacketGenerator()
        
        # Test results storage
        self.test_results: List[LoadTestResult] = []
        
        # Component endpoints
        self.component_endpoints = self._get_component_endpoints()
        
        # Thread pool for concurrent testing
        self.executor = ThreadPoolExecutor(max_workers=50)
        
        # Test data generators
        self.test_data_generators = self._init_test_data_generators()
        
        # Resource monitoring
        self.monitor_resources = True
        self.resource_metrics = defaultdict(list)
        
    def _load_config(self) -> Dict[str, Any]:
        """Load load testing configuration"""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Error loading load test config: {e}")
            return {
                'default_test_duration': 300,
                'max_concurrent_users': 100,
                'default_rps': 10,
                'resource_monitoring_interval': 5
            }
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('NSMLoadTestFramework')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # File handler
        file_handler = logging.FileHandler('/var/log/nsm/load_test_framework.log')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _get_component_endpoints(self) -> Dict[str, Dict[str, str]]:
        """Get component endpoints for load testing"""
        return {
            'signature_detection': {
                'health': 'http://localhost:8437/health',
                'api': 'http://localhost:8437/api/v1',
                'process_event': 'http://localhost:8437/api/v1/events',
                'process_packet': 'http://localhost:8437/api/v1/packets'
            },
            'anomaly_detection': {
                'health': 'http://localhost:8441/health',
                'api': 'http://localhost:8441/api/v1',
                'analyze': 'http://localhost:8441/api/v1/analyze',
                'pattern': 'http://localhost:8441/api/v1/patterns'
            },
            'behavioral_analysis': {
                'health': 'http://localhost:8444/health',
                'api': 'http://localhost:8444/api/v1',
                'analyze': 'http://localhost:8444/api/v1/behavior',
                'baseline': 'http://localhost:8444/api/v1/baseline'
            },
            'encrypted_analysis': {
                'health': 'http://localhost:8445/health',
                'api': 'http://localhost:8445/api/v1',
                'analyze': 'http://localhost:8445/api/v1/encrypted',
                'metadata': 'http://localhost:8445/api/v1/metadata'
            },
            'integration_orchestrator': {
                'health': 'http://localhost:8450/health',
                'api': 'http://localhost:8450/api/v1',
                'events': 'http://localhost:8450/api/v1/events',
                'incidents': 'http://localhost:8450/api/v1/incidents'
            }
        }
    
    def _init_test_data_generators(self) -> Dict[str, Callable]:
        """Initialize test data generators for different components"""
        return {
            'signature_detection': self._generate_signature_test_data,
            'anomaly_detection': self._generate_anomaly_test_data,
            'behavioral_analysis': self._generate_behavioral_test_data,
            'encrypted_analysis': self._generate_encrypted_test_data,
            'integration_orchestrator': self._generate_integration_test_data
        }
    
    async def run_load_test(self, config: LoadTestConfig) -> LoadTestResult:
        """Run a comprehensive load test"""
        test_id = str(uuid.uuid4())
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting load test {test_id}: {config.test_name}")
        self.logger.info(f"Target: {config.target_component}, Duration: {config.test_duration_seconds}s, "
                        f"Concurrent Users: {config.concurrent_users}, RPS: {config.requests_per_second}")
        
        # Initialize result tracking
        response_times = []
        request_results = []
        error_counts = defaultdict(int)
        resource_usage = defaultdict(list)
        
        # Start resource monitoring
        monitor_task = None
        if self.monitor_resources:
            monitor_task = asyncio.create_task(
                self._monitor_resources(config.target_component, resource_usage)
            )
        
        try:
            # Execute load test phases
            await self._execute_ramp_up(config, response_times, request_results, error_counts)
            await self._execute_steady_state(config, response_times, request_results, error_counts)
            await self._execute_ramp_down(config, response_times, request_results, error_counts)
            
        finally:
            # Stop resource monitoring
            if monitor_task:
                monitor_task.cancel()
                try:
                    await monitor_task
                except asyncio.CancelledError:
                    pass
        
        end_time = datetime.utcnow()
        duration = (end_time - start_time).total_seconds()
        
        # Calculate metrics
        result = self._calculate_load_test_metrics(
            test_id, config, start_time, end_time, duration,
            response_times, request_results, error_counts, resource_usage
        )
        
        self.test_results.append(result)
        self.logger.info(f"Load test {test_id} completed: {result.successful_requests}/{result.total_requests} "
                        f"requests successful ({result.error_rate:.2f}% error rate)")
        
        return result
    
    async def _execute_ramp_up(self, config: LoadTestConfig, response_times: List[float], 
                              request_results: List[bool], error_counts: Dict[str, int]):
        """Execute ramp-up phase"""
        if config.ramp_up_time <= 0:
            return
        
        self.logger.info(f"Starting ramp-up phase: {config.ramp_up_time}s")
        
        ramp_steps = 10
        step_duration = config.ramp_up_time / ramp_steps
        max_users = config.concurrent_users
        
        for step in range(ramp_steps):
            current_users = int((step + 1) * max_users / ramp_steps)
            step_rps = int((step + 1) * config.requests_per_second / ramp_steps)
            
            self.logger.debug(f"Ramp-up step {step + 1}/{ramp_steps}: {current_users} users, {step_rps} RPS")
            
            # Execute requests for this step
            tasks = []
            for _ in range(current_users):
                task = asyncio.create_task(
                    self._execute_user_requests(
                        config, step_duration, step_rps // current_users if current_users > 0 else 1,
                        response_times, request_results, error_counts
                    )
                )
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _execute_steady_state(self, config: LoadTestConfig, response_times: List[float],
                                   request_results: List[bool], error_counts: Dict[str, int]):
        """Execute steady-state phase"""
        steady_duration = config.test_duration_seconds - config.ramp_up_time - config.ramp_down_time
        if steady_duration <= 0:
            return
        
        self.logger.info(f"Starting steady-state phase: {steady_duration}s with {config.concurrent_users} users")
        
        # Calculate requests per user
        requests_per_user = config.requests_per_second // config.concurrent_users if config.concurrent_users > 0 else config.requests_per_second
        
        # Execute concurrent users
        tasks = []
        for _ in range(config.concurrent_users):
            task = asyncio.create_task(
                self._execute_user_requests(
                    config, steady_duration, requests_per_user,
                    response_times, request_results, error_counts
                )
            )
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _execute_ramp_down(self, config: LoadTestConfig, response_times: List[float],
                                request_results: List[bool], error_counts: Dict[str, int]):
        """Execute ramp-down phase"""
        if config.ramp_down_time <= 0:
            return
        
        self.logger.info(f"Starting ramp-down phase: {config.ramp_down_time}s")
        
        ramp_steps = 5
        step_duration = config.ramp_down_time / ramp_steps
        max_users = config.concurrent_users
        
        for step in range(ramp_steps):
            current_users = int(max_users * (ramp_steps - step) / ramp_steps)
            step_rps = int(config.requests_per_second * (ramp_steps - step) / ramp_steps)
            
            if current_users <= 0:
                break
            
            self.logger.debug(f"Ramp-down step {step + 1}/{ramp_steps}: {current_users} users, {step_rps} RPS")
            
            # Execute requests for this step
            requests_per_user = step_rps // current_users if current_users > 0 else 1
            tasks = []
            for _ in range(current_users):
                task = asyncio.create_task(
                    self._execute_user_requests(
                        config, step_duration, requests_per_user,
                        response_times, request_results, error_counts
                    )
                )
                tasks.append(task)
            
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _execute_user_requests(self, config: LoadTestConfig, duration: float, 
                                    requests_per_second: int, response_times: List[float],
                                    request_results: List[bool], error_counts: Dict[str, int]):
        """Execute requests for a single virtual user"""
        start_time = time.time()
        end_time = start_time + duration
        
        interval = 1.0 / requests_per_second if requests_per_second > 0 else 1.0
        
        while time.time() < end_time:
            request_start = time.time()
            
            try:
                # Generate test data
                test_data = self._generate_test_data(config)
                
                # Make request
                success, response_time = await self._make_request(config, test_data)
                
                response_times.append(response_time)
                request_results.append(success)
                
                if not success:
                    error_counts['request_failed'] += 1
                
            except asyncio.TimeoutError:
                error_counts['timeout'] += 1
                request_results.append(False)
                response_times.append(30.0)  # Timeout duration
                
            except Exception as e:
                error_counts[type(e).__name__] += 1
                request_results.append(False)
                response_times.append(0.0)
            
            # Wait for next request
            elapsed = time.time() - request_start
            wait_time = max(0, interval - elapsed)
            if wait_time > 0:
                await asyncio.sleep(wait_time)
    
    async def _make_request(self, config: LoadTestConfig, test_data: Dict[str, Any]) -> tuple[bool, float]:
        """Make a single request to the target component"""
        endpoints = self.component_endpoints.get(config.target_component, {})
        if not endpoints:
            raise ValueError(f"Unknown component: {config.target_component}")
        
        # Select appropriate endpoint based on test data
        endpoint_url = self._select_endpoint(config.target_component, endpoints, test_data)
        
        start_time = time.time()
        
        try:
            # Make HTTP request
            timeout = 30
            headers = {
                'Content-Type': 'application/json',
                'X-API-Key': 'load-test-key',
                'User-Agent': 'NSM-LoadTest/1.0'
            }
            
            if test_data.get('method', 'POST') == 'GET':
                response = requests.get(endpoint_url, headers=headers, timeout=timeout)
            else:
                response = requests.post(endpoint_url, json=test_data, headers=headers, timeout=timeout)
            
            response_time = time.time() - start_time
            
            # Consider 2xx and 3xx as successful
            success = 200 <= response.status_code < 400
            
            return success, response_time
            
        except requests.exceptions.Timeout:
            return False, time.time() - start_time
        except Exception:
            return False, time.time() - start_time
    
    def _select_endpoint(self, component: str, endpoints: Dict[str, str], test_data: Dict[str, Any]) -> str:
        """Select appropriate endpoint based on component and test data"""
        endpoint_map = {
            'signature_detection': 'process_event',
            'anomaly_detection': 'analyze',
            'behavioral_analysis': 'analyze',
            'encrypted_analysis': 'analyze',
            'integration_orchestrator': 'events'
        }
        
        endpoint_key = endpoint_map.get(component, 'api')
        return endpoints.get(endpoint_key, endpoints.get('api', endpoints.get('health', '')))
    
    def _generate_test_data(self, config: LoadTestConfig) -> Dict[str, Any]:
        """Generate test data for the request"""
        if config.custom_payload:
            return config.custom_payload.copy()
        
        generator = self.test_data_generators.get(config.target_component)
        if generator:
            return generator()
        
        # Default test data
        return {
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'source': 'load_test',
            'test_data': True
        }
    
    def _generate_signature_test_data(self) -> Dict[str, Any]:
        """Generate test data for signature detection"""
        return {
            'packet_data': self.packet_generator.generate_tcp_packet().hex(),
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': random.choice(['192.168.1.100', '10.0.0.50', '172.16.0.10']),
            'destination_ip': random.choice(['8.8.8.8', '1.1.1.1', '208.67.222.222']),
            'protocol': 'TCP',
            'size': random.randint(64, 1500)
        }
    
    def _generate_anomaly_test_data(self) -> Dict[str, Any]:
        """Generate test data for anomaly detection"""
        return {
            'network_flow': {
                'src_ip': random.choice(['192.168.1.100', '10.0.0.50']),
                'dst_ip': random.choice(['8.8.8.8', '1.1.1.1']),
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 21]),
                'protocol': random.choice(['TCP', 'UDP']),
                'bytes_sent': random.randint(100, 10000),
                'bytes_received': random.randint(50, 5000),
                'duration': random.uniform(0.1, 300.0)
            },
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {
                'test_scenario': 'load_test',
                'flow_id': str(uuid.uuid4())
            }
        }
    
    def _generate_behavioral_test_data(self) -> Dict[str, Any]:
        """Generate test data for behavioral analysis"""
        return {
            'user_activity': {
                'user_id': f"user_{random.randint(1, 1000)}",
                'session_id': str(uuid.uuid4()),
                'actions': [
                    {
                        'action': random.choice(['login', 'file_access', 'network_connection', 'process_execution']),
                        'timestamp': datetime.utcnow().isoformat(),
                        'resource': f"resource_{random.randint(1, 100)}",
                        'success': random.choice([True, True, True, False])  # 75% success rate
                    }
                    for _ in range(random.randint(1, 5))
                ]
            },
            'context': {
                'source_ip': random.choice(['192.168.1.100', '10.0.0.50']),
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'geolocation': random.choice(['US', 'UK', 'CA', 'AU'])
            }
        }
    
    def _generate_encrypted_test_data(self) -> Dict[str, Any]:
        """Generate test data for encrypted traffic analysis"""
        return {
            'encrypted_flow': {
                'src_ip': random.choice(['192.168.1.100', '10.0.0.50']),
                'dst_ip': random.choice(['8.8.8.8', '1.1.1.1']),
                'protocol': 'TLS',
                'cipher_suite': random.choice(['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']),
                'tls_version': random.choice(['1.2', '1.3']),
                'cert_fingerprint': ''.join(random.choices('0123456789abcdef', k=64)),
                'packet_sizes': [random.randint(64, 1500) for _ in range(random.randint(5, 20))],
                'timing_patterns': [random.uniform(0.001, 0.1) for _ in range(random.randint(5, 20))]
            },
            'metadata': {
                'flow_duration': random.uniform(1.0, 600.0),
                'total_bytes': random.randint(1000, 100000)
            }
        }
    
    def _generate_integration_test_data(self) -> Dict[str, Any]:
        """Generate test data for integration orchestrator"""
        return {
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.utcnow().isoformat(),
            'source': random.choice(['signature_detection', 'anomaly_detection', 'behavioral_analysis']),
            'event_type': random.choice(['malware_detected', 'anomaly_detected', 'suspicious_behavior']),
            'severity': random.choice(['critical', 'high', 'medium', 'low']),
            'title': f"Load Test Event {random.randint(1, 10000)}",
            'description': "Simulated security event for load testing",
            'metadata': {
                'src_ip': random.choice(['192.168.1.100', '10.0.0.50']),
                'dst_ip': random.choice(['8.8.8.8', '1.1.1.1']),
                'protocol': random.choice(['TCP', 'UDP']),
                'confidence': random.uniform(0.5, 1.0)
            }
        }
    
    async def _monitor_resources(self, component: str, resource_usage: Dict[str, List[float]]):
        """Monitor resource usage during load test"""
        import psutil
        
        while True:
            try:
                # System resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                network_io = psutil.net_io_counters()
                
                resource_usage['cpu'].append(cpu_percent)
                resource_usage['memory'].append(memory.percent)
                
                if disk_io:
                    resource_usage['disk_read'].append(disk_io.read_bytes)
                    resource_usage['disk_write'].append(disk_io.write_bytes)
                
                if network_io:
                    resource_usage['network_sent'].append(network_io.bytes_sent)
                    resource_usage['network_recv'].append(network_io.bytes_recv)
                
                await asyncio.sleep(self.config.get('resource_monitoring_interval', 5))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.debug(f"Error monitoring resources: {e}")
                await asyncio.sleep(5)
    
    def _calculate_load_test_metrics(self, test_id: str, config: LoadTestConfig,
                                   start_time: datetime, end_time: datetime, duration: float,
                                   response_times: List[float], request_results: List[bool],
                                   error_counts: Dict[str, int], resource_usage: Dict[str, List[float]]) -> LoadTestResult:
        """Calculate comprehensive load test metrics"""
        
        total_requests = len(request_results)
        successful_requests = sum(request_results)
        failed_requests = total_requests - successful_requests
        
        if total_requests > 0:
            error_rate = (failed_requests / total_requests) * 100
            requests_per_second = total_requests / duration
        else:
            error_rate = 0.0
            requests_per_second = 0.0
        
        # Response time statistics
        if response_times:
            avg_response_time = statistics.mean(response_times)
            min_response_time = min(response_times)
            max_response_time = max(response_times)
            
            sorted_times = sorted(response_times)
            p50_response_time = sorted_times[int(0.5 * len(sorted_times))]
            p95_response_time = sorted_times[int(0.95 * len(sorted_times))]
            p99_response_time = sorted_times[int(0.99 * len(sorted_times))]
        else:
            avg_response_time = min_response_time = max_response_time = 0.0
            p50_response_time = p95_response_time = p99_response_time = 0.0
        
        # Resource utilization peaks
        peak_cpu_usage = max(resource_usage.get('cpu', [0.0]))
        peak_memory_usage = max(resource_usage.get('memory', [0.0]))
        
        # Calculate disk and network I/O rates
        disk_read_values = resource_usage.get('disk_read', [])
        disk_write_values = resource_usage.get('disk_write', [])
        
        if len(disk_read_values) >= 2 and len(disk_write_values) >= 2:
            disk_read_rate = (disk_read_values[-1] - disk_read_values[0]) / duration
            disk_write_rate = (disk_write_values[-1] - disk_write_values[0]) / duration
            peak_disk_io = max(disk_read_rate, disk_write_rate)
        else:
            peak_disk_io = 0.0
        
        network_sent_values = resource_usage.get('network_sent', [])
        network_recv_values = resource_usage.get('network_recv', [])
        
        if len(network_sent_values) >= 2 and len(network_recv_values) >= 2:
            network_sent_rate = (network_sent_values[-1] - network_sent_values[0]) / duration
            network_recv_rate = (network_recv_values[-1] - network_recv_values[0]) / duration
            peak_network_io = max(network_sent_rate, network_recv_rate)
        else:
            peak_network_io = 0.0
        
        return LoadTestResult(
            test_id=test_id,
            test_name=config.test_name,
            component=config.target_component,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            requests_per_second=requests_per_second,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            p50_response_time=p50_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_rate=error_rate,
            timeout_count=error_counts.get('timeout', 0),
            connection_errors=error_counts.get('ConnectionError', 0),
            peak_cpu_usage=peak_cpu_usage,
            peak_memory_usage=peak_memory_usage,
            peak_disk_io=peak_disk_io,
            peak_network_io=peak_network_io,
            custom_metrics={
                'error_breakdown': dict(error_counts),
                'resource_usage_samples': {k: len(v) for k, v in resource_usage.items()}
            }
        )
    
    async def run_stress_test(self, scenario: StressTestScenario) -> Dict[str, Any]:
        """Run a stress test scenario"""
        self.logger.info(f"Starting stress test: {scenario.scenario_name}")
        
        stress_results = []
        
        for level, intensity in enumerate(scenario.intensity_levels, 1):
            self.logger.info(f"Stress level {level}/{len(scenario.intensity_levels)}: intensity {intensity}")
            
            # Create load test config for this intensity level
            load_config = LoadTestConfig(
                test_name=f"{scenario.scenario_name}_level_{level}",
                target_component=scenario.component,
                test_duration_seconds=scenario.duration_per_level,
                concurrent_users=intensity,
                requests_per_second=intensity * 2,  # 2 RPS per user
                ramp_up_time=10,
                ramp_down_time=5
            )
            
            # Run load test
            result = await self.run_load_test(load_config)
            stress_results.append(result)
            
            # Check if failure threshold exceeded
            if result.error_rate > scenario.failure_threshold:
                self.logger.warning(f"Failure threshold exceeded at level {level}: "
                                  f"{result.error_rate:.2f}% > {scenario.failure_threshold}%")
                break
            
            # Recovery time between levels
            if scenario.recovery_time > 0 and level < len(scenario.intensity_levels):
                self.logger.info(f"Recovery period: {scenario.recovery_time}s")
                await asyncio.sleep(scenario.recovery_time)
        
        # Analyze stress test results
        stress_summary = self._analyze_stress_results(scenario, stress_results)
        
        self.logger.info(f"Stress test completed: {scenario.scenario_name}")
        return stress_summary
    
    def _analyze_stress_results(self, scenario: StressTestScenario, results: List[LoadTestResult]) -> Dict[str, Any]:
        """Analyze stress test results"""
        if not results:
            return {}
        
        # Find breaking point
        breaking_point = None
        for i, result in enumerate(results):
            if result.error_rate > scenario.failure_threshold:
                breaking_point = {
                    'level': i + 1,
                    'intensity': scenario.intensity_levels[i],
                    'error_rate': result.error_rate,
                    'avg_response_time': result.avg_response_time
                }
                break
        
        # Performance degradation analysis
        baseline_result = results[0]
        degradation_points = []
        
        for i, result in enumerate(results[1:], 1):
            response_time_increase = ((result.avg_response_time - baseline_result.avg_response_time) / 
                                    baseline_result.avg_response_time) * 100
            
            if response_time_increase > 50:  # 50% degradation
                degradation_points.append({
                    'level': i + 1,
                    'intensity': scenario.intensity_levels[i],
                    'response_time_increase_percent': response_time_increase,
                    'avg_response_time': result.avg_response_time
                })
        
        return {
            'scenario_name': scenario.scenario_name,
            'component': scenario.component,
            'stress_type': scenario.stress_type,
            'total_levels_tested': len(results),
            'max_intensity_achieved': scenario.intensity_levels[len(results) - 1],
            'breaking_point': breaking_point,
            'degradation_points': degradation_points,
            'baseline_performance': {
                'avg_response_time': baseline_result.avg_response_time,
                'requests_per_second': baseline_result.requests_per_second,
                'error_rate': baseline_result.error_rate
            },
            'peak_performance': {
                'avg_response_time': results[-1].avg_response_time,
                'requests_per_second': results[-1].requests_per_second,
                'error_rate': results[-1].error_rate,
                'peak_cpu_usage': results[-1].peak_cpu_usage,
                'peak_memory_usage': results[-1].peak_memory_usage
            },
            'detailed_results': [asdict(result) for result in results]
        }
    
    def generate_load_test_report(self, results: List[LoadTestResult]) -> str:
        """Generate comprehensive load test report"""
        if not results:
            return "No load test results available."
        
        report = []
        report.append("=" * 80)
        report.append("NSM LOAD TEST REPORT")
        report.append("=" * 80)
        report.append(f"Generated: {datetime.utcnow().isoformat()}")
        report.append(f"Total Tests: {len(results)}")
        report.append("")
        
        # Summary statistics
        total_requests = sum(r.total_requests for r in results)
        total_successful = sum(r.successful_requests for r in results)
        avg_error_rate = statistics.mean([r.error_rate for r in results])
        avg_response_time = statistics.mean([r.avg_response_time for r in results])
        
        report.append("SUMMARY STATISTICS")
        report.append("-" * 40)
        report.append(f"Total Requests: {total_requests:,}")
        report.append(f"Successful Requests: {total_successful:,}")
        report.append(f"Average Error Rate: {avg_error_rate:.2f}%")
        report.append(f"Average Response Time: {avg_response_time:.3f}s")
        report.append("")
        
        # Individual test results
        report.append("INDIVIDUAL TEST RESULTS")
        report.append("-" * 40)
        
        for result in results:
            report.append(f"Test: {result.test_name}")
            report.append(f"  Component: {result.component}")
            report.append(f"  Duration: {result.duration_seconds:.1f}s")
            report.append(f"  Requests: {result.total_requests:,} ({result.requests_per_second:.1f} RPS)")
            report.append(f"  Success Rate: {((result.successful_requests/result.total_requests)*100):.2f}%")
            report.append(f"  Response Time: avg={result.avg_response_time:.3f}s, p95={result.p95_response_time:.3f}s")
            report.append(f"  Resource Usage: CPU={result.peak_cpu_usage:.1f}%, Memory={result.peak_memory_usage:.1f}%")
            report.append("")
        
        # Performance recommendations
        report.append("PERFORMANCE RECOMMENDATIONS")
        report.append("-" * 40)
        
        # Analyze results for recommendations
        high_error_rate_tests = [r for r in results if r.error_rate > 5.0]
        slow_response_tests = [r for r in results if r.avg_response_time > 2.0]
        high_resource_tests = [r for r in results if r.peak_cpu_usage > 80 or r.peak_memory_usage > 80]
        
        if high_error_rate_tests:
            report.append("⚠️  High Error Rate Detected:")
            for test in high_error_rate_tests:
                report.append(f"   - {test.component}: {test.error_rate:.2f}% error rate")
            report.append("")
        
        if slow_response_tests:
            report.append("🐌 Slow Response Times Detected:")
            for test in slow_response_tests:
                report.append(f"   - {test.component}: {test.avg_response_time:.3f}s average response time")
            report.append("")
        
        if high_resource_tests:
            report.append("🔥 High Resource Usage Detected:")
            for test in high_resource_tests:
                report.append(f"   - {test.component}: CPU={test.peak_cpu_usage:.1f}%, Memory={test.peak_memory_usage:.1f}%")
            report.append("")
        
        if not (high_error_rate_tests or slow_response_tests or high_resource_tests):
            report.append("✅ All tests performed within acceptable parameters.")
            report.append("")
        
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_results(self, filename: str):
        """Save test results to file"""
        results_data = {
            'generated_at': datetime.utcnow().isoformat(),
            'framework_version': '1.0',
            'test_results': [asdict(result) for result in self.test_results]
        }
        
        filepath = Path(filename)
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'w') as f:
            json.dump(results_data, f, indent=2, default=str)
        
        self.logger.info(f"Test results saved to {filepath}")


async def main():
    """Main execution for load testing framework"""
    framework = NSMLoadTestFramework()
    
    # Example load test configurations
    test_configs = [
        LoadTestConfig(
            test_name="Signature Detection Load Test",
            target_component="signature_detection",
            test_duration_seconds=300,
            concurrent_users=50,
            requests_per_second=100,
            ramp_up_time=30,
            ramp_down_time=30
        ),
        LoadTestConfig(
            test_name="Anomaly Detection Load Test",
            target_component="anomaly_detection",
            test_duration_seconds=240,
            concurrent_users=30,
            requests_per_second=60,
            ramp_up_time=20,
            ramp_down_time=20
        ),
        LoadTestConfig(
            test_name="Integration Orchestrator Load Test",
            target_component="integration_orchestrator",
            test_duration_seconds=180,
            concurrent_users=20,
            requests_per_second=40,
            ramp_up_time=15,
            ramp_down_time=15
        )
    ]
    
    # Run load tests
    results = []
    for config in test_configs:
        try:
            result = await framework.run_load_test(config)
            results.append(result)
        except Exception as e:
            framework.logger.error(f"Load test failed for {config.test_name}: {e}")
    
    # Example stress test
    stress_scenario = StressTestScenario(
        scenario_name="Integration Orchestrator Stress Test",
        component="integration_orchestrator",
        stress_type="concurrent_connections",
        intensity_levels=[10, 25, 50, 75, 100, 150, 200],
        duration_per_level=60,
        recovery_time=30,
        failure_threshold=10.0
    )
    
    try:
        stress_results = await framework.run_stress_test(stress_scenario)
        print(f"Stress test completed: {stress_results.get('scenario_name', 'Unknown')}")
        print(f"Breaking point: {stress_results.get('breaking_point', 'Not reached')}")
    except Exception as e:
        framework.logger.error(f"Stress test failed: {e}")
    
    # Generate and save report
    if results:
        report = framework.generate_load_test_report(results)
        print(report)
        
        # Save results
        framework.save_results("/var/lib/nsm/load_test_results.json")


if __name__ == "__main__":
    asyncio.run(main())