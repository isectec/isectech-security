"""
Trust Scoring Engine Performance Tests

This module provides comprehensive performance testing to validate sub-100ms
response times and high-throughput capabilities of the trust scoring engine.
"""

import asyncio
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
import uuid
import httpx
import pytest
from datetime import datetime

@dataclass
class PerformanceMetrics:
    """Performance test metrics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    response_times_ms: List[float] = None
    cache_hits: int = 0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.response_times_ms is None:
            self.response_times_ms = []
        if self.errors is None:
            self.errors = []
    
    @property
    def success_rate(self) -> float:
        return (self.successful_requests / max(self.total_requests, 1)) * 100
    
    @property
    def cache_hit_rate(self) -> float:
        return (self.cache_hits / max(self.successful_requests, 1)) * 100
    
    @property
    def avg_response_time_ms(self) -> float:
        return statistics.mean(self.response_times_ms) if self.response_times_ms else 0
    
    @property
    def p95_response_time_ms(self) -> float:
        if not self.response_times_ms:
            return 0
        sorted_times = sorted(self.response_times_ms)
        p95_index = int(0.95 * len(sorted_times))
        return sorted_times[p95_index]
    
    @property
    def p99_response_time_ms(self) -> float:
        if not self.response_times_ms:
            return 0
        sorted_times = sorted(self.response_times_ms)
        p99_index = int(0.99 * len(sorted_times))
        return sorted_times[p99_index]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "success_rate_percent": round(self.success_rate, 2),
            "cache_hit_rate_percent": round(self.cache_hit_rate, 2),
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "p95_response_time_ms": round(self.p95_response_time_ms, 2),
            "p99_response_time_ms": round(self.p99_response_time_ms, 2),
            "min_response_time_ms": min(self.response_times_ms) if self.response_times_ms else 0,
            "max_response_time_ms": max(self.response_times_ms) if self.response_times_ms else 0,
            "response_time_std_dev": statistics.stdev(self.response_times_ms) if len(self.response_times_ms) > 1 else 0
        }

class TrustScoringPerformanceTest:
    """Performance test suite for trust scoring engine."""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.client = httpx.AsyncClient(timeout=30.0)
        
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
    
    async def single_trust_score_request(
        self, 
        entity_id: str = None,
        include_cache_warmup: bool = False
    ) -> Dict[str, Any]:
        """Make a single trust score calculation request."""
        
        if entity_id is None:
            entity_id = f"user_{uuid.uuid4().hex[:8]}"
        
        request_data = {
            "entity_id": entity_id,
            "entity_type": "user",
            "user_id": entity_id,
            "device_id": f"device_{uuid.uuid4().hex[:8]}",
            "tenant_id": "performance_test",
            "current_ip": "192.168.1.100",
            "force_refresh": not include_cache_warmup,
            "include_trends": False,
            "include_risk_details": True,
            "authentication_context": {
                "mfa_enabled": True,
                "session_encrypted": True,
                "recent_auth_success": True
            },
            "network_context": {
                "is_corporate_network": True,
                "vpn_detected": False,
                "geolocation_consistent": True
            }
        }
        
        start_time = time.time()
        
        try:
            response = await self.client.post(
                f"{self.base_url}/api/trust-score/calculate",
                json=request_data,
                headers={"Content-Type": "application/json"}
            )
            
            response_time_ms = (time.time() - start_time) * 1000
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "response_time_ms": response_time_ms,
                    "cache_hit": result.get("cache_hit", False),
                    "trust_score": result.get("trust_score"),
                    "trust_level": result.get("trust_level"),
                    "processing_time_ms": result.get("processing_time_ms", 0),
                    "data": result
                }
            else:
                return {
                    "success": False,
                    "response_time_ms": response_time_ms,
                    "status_code": response.status_code,
                    "error": response.text
                }
                
        except Exception as e:
            response_time_ms = (time.time() - start_time) * 1000
            return {
                "success": False,
                "response_time_ms": response_time_ms,
                "error": str(e)
            }
    
    async def warmup_cache(self, entity_ids: List[str]) -> None:
        """Warm up cache with test entities."""
        print(f"Warming up cache with {len(entity_ids)} entities...")
        
        warmup_tasks = [
            self.single_trust_score_request(entity_id, include_cache_warmup=False)
            for entity_id in entity_ids
        ]
        
        await asyncio.gather(*warmup_tasks, return_exceptions=True)
        print("Cache warmup completed")
    
    async def load_test(
        self,
        concurrent_requests: int = 10,
        total_requests: int = 1000,
        unique_entities: int = 100,
        warmup_cache: bool = True
    ) -> PerformanceMetrics:
        """Run load test with specified parameters."""
        
        print(f"Starting load test: {total_requests} requests, {concurrent_requests} concurrent")
        
        # Generate test entity IDs
        entity_ids = [f"load_test_user_{i}" for i in range(unique_entities)]
        
        # Warm up cache if requested
        if warmup_cache:
            await self.warmup_cache(entity_ids[:min(10, len(entity_ids))])
        
        metrics = PerformanceMetrics()
        semaphore = asyncio.Semaphore(concurrent_requests)
        
        async def make_request():
            async with semaphore:
                # Randomly select entity ID (to simulate cache hits/misses)
                import random
                entity_id = random.choice(entity_ids)
                return await self.single_trust_score_request(entity_id, include_cache_warmup=warmup_cache)
        
        start_time = time.time()
        
        # Execute all requests
        tasks = [make_request() for _ in range(total_requests)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        total_time = time.time() - start_time
        
        # Process results
        for result in results:
            metrics.total_requests += 1
            
            if isinstance(result, Exception):
                metrics.failed_requests += 1
                metrics.errors.append(str(result))
            elif result.get("success"):
                metrics.successful_requests += 1
                metrics.response_times_ms.append(result["response_time_ms"])
                if result.get("cache_hit"):
                    metrics.cache_hits += 1
            else:
                metrics.failed_requests += 1
                metrics.errors.append(result.get("error", "Unknown error"))
        
        # Calculate throughput
        requests_per_second = total_requests / total_time
        
        print(f"Load test completed in {total_time:.2f}s")
        print(f"Throughput: {requests_per_second:.2f} requests/second")
        print(f"Success rate: {metrics.success_rate:.2f}%")
        print(f"Cache hit rate: {metrics.cache_hit_rate:.2f}%")
        print(f"Average response time: {metrics.avg_response_time_ms:.2f}ms")
        print(f"95th percentile: {metrics.p95_response_time_ms:.2f}ms")
        print(f"99th percentile: {metrics.p99_response_time_ms:.2f}ms")
        
        return metrics
    
    async def latency_test(
        self,
        entity_id: str = "latency_test_user",
        iterations: int = 100,
        include_cache_test: bool = True
    ) -> Dict[str, PerformanceMetrics]:
        """Test latency with and without cache."""
        
        print(f"Running latency test with {iterations} iterations")
        
        results = {}
        
        # Test cold cache performance
        print("Testing cold cache performance...")
        cold_metrics = PerformanceMetrics()
        
        for i in range(iterations):
            unique_entity = f"{entity_id}_{i}"
            result = await self.single_trust_score_request(unique_entity, include_cache_warmup=False)
            
            cold_metrics.total_requests += 1
            if result.get("success"):
                cold_metrics.successful_requests += 1
                cold_metrics.response_times_ms.append(result["response_time_ms"])
            else:
                cold_metrics.failed_requests += 1
                cold_metrics.errors.append(result.get("error", "Unknown error"))
        
        results["cold_cache"] = cold_metrics
        
        # Test warm cache performance
        if include_cache_test:
            print("Testing warm cache performance...")
            
            # First warm up the cache
            await self.single_trust_score_request(entity_id, include_cache_warmup=False)
            
            warm_metrics = PerformanceMetrics()
            
            for i in range(iterations):
                result = await self.single_trust_score_request(entity_id, include_cache_warmup=True)
                
                warm_metrics.total_requests += 1
                if result.get("success"):
                    warm_metrics.successful_requests += 1
                    warm_metrics.response_times_ms.append(result["response_time_ms"])
                    if result.get("cache_hit"):
                        warm_metrics.cache_hits += 1
                else:
                    warm_metrics.failed_requests += 1
                    warm_metrics.errors.append(result.get("error", "Unknown error"))
            
            results["warm_cache"] = warm_metrics
        
        # Print comparison
        print(f"Cold cache avg response time: {cold_metrics.avg_response_time_ms:.2f}ms")
        if include_cache_test:
            print(f"Warm cache avg response time: {results['warm_cache'].avg_response_time_ms:.2f}ms")
            print(f"Warm cache hit rate: {results['warm_cache'].cache_hit_rate:.2f}%")
        
        return results
    
    async def stress_test(
        self,
        max_concurrent: int = 100,
        duration_seconds: int = 60,
        ramp_up_time: int = 10
    ) -> PerformanceMetrics:
        """Run stress test to find breaking points."""
        
        print(f"Running stress test: {max_concurrent} max concurrent for {duration_seconds}s")
        
        metrics = PerformanceMetrics()
        active_requests = 0
        stop_time = time.time() + duration_seconds
        
        async def make_continuous_requests():
            nonlocal active_requests, metrics
            
            while time.time() < stop_time:
                if active_requests < max_concurrent:
                    active_requests += 1
                    
                    try:
                        result = await self.single_trust_score_request()
                        active_requests -= 1
                        
                        metrics.total_requests += 1
                        if result.get("success"):
                            metrics.successful_requests += 1
                            metrics.response_times_ms.append(result["response_time_ms"])
                            if result.get("cache_hit"):
                                metrics.cache_hits += 1
                        else:
                            metrics.failed_requests += 1
                            metrics.errors.append(result.get("error", "Unknown error"))
                    
                    except Exception as e:
                        active_requests -= 1
                        metrics.total_requests += 1
                        metrics.failed_requests += 1
                        metrics.errors.append(str(e))
                
                else:
                    await asyncio.sleep(0.01)  # Brief pause when at max concurrency
        
        # Start multiple request generators
        generators = [make_continuous_requests() for _ in range(min(10, max_concurrent))]
        
        await asyncio.gather(*generators, return_exceptions=True)
        
        print(f"Stress test completed:")
        print(f"Total requests: {metrics.total_requests}")
        print(f"Success rate: {metrics.success_rate:.2f}%")
        print(f"Average response time: {metrics.avg_response_time_ms:.2f}ms")
        print(f"95th percentile: {metrics.p95_response_time_ms:.2f}ms")
        
        return metrics

    async def bulk_operation_test(
        self,
        batch_sizes: List[int] = [10, 25, 50, 100],
        iterations_per_batch: int = 10
    ) -> Dict[int, PerformanceMetrics]:
        """Test bulk operations with different batch sizes."""
        
        print("Testing bulk operations...")
        results = {}
        
        for batch_size in batch_sizes:
            print(f"Testing batch size: {batch_size}")
            metrics = PerformanceMetrics()
            
            for iteration in range(iterations_per_batch):
                # Create bulk request
                bulk_requests = []
                for i in range(batch_size):
                    bulk_requests.append({
                        "entity_id": f"bulk_test_{batch_size}_{iteration}_{i}",
                        "entity_type": "user",
                        "user_id": f"user_{i}",
                        "tenant_id": "bulk_test",
                        "force_refresh": False
                    })
                
                bulk_data = {
                    "requests": bulk_requests,
                    "max_concurrent": min(10, batch_size),
                    "timeout_seconds": 30
                }
                
                start_time = time.time()
                
                try:
                    response = await self.client.post(
                        f"{self.base_url}/api/trust-score/bulk",
                        json=bulk_data,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    response_time_ms = (time.time() - start_time) * 1000
                    
                    if response.status_code == 200:
                        result = response.json()
                        metrics.total_requests += 1
                        metrics.successful_requests += 1
                        metrics.response_times_ms.append(response_time_ms)
                        
                        # Track individual success rates within bulk
                        successful_individual = len(result.get("successful_responses", []))
                        metrics.cache_hits += int(result.get("cache_hit_rate", 0) * successful_individual / 100)
                    else:
                        metrics.total_requests += 1
                        metrics.failed_requests += 1
                        metrics.errors.append(f"HTTP {response.status_code}: {response.text}")
                
                except Exception as e:
                    response_time_ms = (time.time() - start_time) * 1000
                    metrics.total_requests += 1
                    metrics.failed_requests += 1
                    metrics.response_times_ms.append(response_time_ms)
                    metrics.errors.append(str(e))
            
            results[batch_size] = metrics
            print(f"Batch size {batch_size}: {metrics.avg_response_time_ms:.2f}ms avg")
        
        return results

# Test execution functions
async def run_comprehensive_performance_test():
    """Run comprehensive performance testing suite."""
    
    print("=" * 60)
    print("TRUST SCORING ENGINE PERFORMANCE TEST SUITE")
    print("=" * 60)
    
    async with TrustScoringPerformanceTest() as tester:
        all_results = {}
        
        # 1. Latency Test
        print("\n1. LATENCY TEST")
        print("-" * 30)
        latency_results = await tester.latency_test(iterations=50)
        all_results["latency"] = latency_results
        
        # Validate sub-100ms requirement
        cold_avg = latency_results["cold_cache"].avg_response_time_ms
        warm_avg = latency_results.get("warm_cache", latency_results["cold_cache"]).avg_response_time_ms
        
        print(f"✓ Cold cache latency: {cold_avg:.2f}ms")
        print(f"✓ Warm cache latency: {warm_avg:.2f}ms")
        
        if warm_avg < 100:
            print("✅ SUB-100MS REQUIREMENT MET")
        else:
            print("❌ SUB-100MS REQUIREMENT NOT MET")
        
        # 2. Load Test
        print("\n2. LOAD TEST")
        print("-" * 30)
        load_results = await tester.load_test(
            concurrent_requests=20,
            total_requests=1000,
            unique_entities=100,
            warmup_cache=True
        )
        all_results["load"] = load_results
        
        if load_results.p95_response_time_ms < 100:
            print("✅ LOAD TEST P95 < 100MS")
        else:
            print("❌ LOAD TEST P95 > 100MS")
        
        # 3. Bulk Operations Test
        print("\n3. BULK OPERATIONS TEST")
        print("-" * 30)
        bulk_results = await tester.bulk_operation_test(
            batch_sizes=[10, 25, 50],
            iterations_per_batch=5
        )
        all_results["bulk"] = bulk_results
        
        # 4. High Concurrency Test
        print("\n4. HIGH CONCURRENCY TEST")
        print("-" * 30)
        concurrency_results = await tester.load_test(
            concurrent_requests=50,
            total_requests=500,
            unique_entities=50,
            warmup_cache=True
        )
        all_results["concurrency"] = concurrency_results
        
        # Summary
        print("\n" + "=" * 60)
        print("PERFORMANCE TEST SUMMARY")
        print("=" * 60)
        
        print(f"Latency (warm cache): {warm_avg:.2f}ms avg")
        print(f"Load test P95: {load_results.p95_response_time_ms:.2f}ms")
        print(f"Load test success rate: {load_results.success_rate:.2f}%")
        print(f"Concurrency test success rate: {concurrency_results.success_rate:.2f}%")
        
        # Generate report
        report = {
            "test_timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "sub_100ms_requirement_met": warm_avg < 100,
                "load_test_p95_under_100ms": load_results.p95_response_time_ms < 100,
                "overall_success_rate": load_results.success_rate
            },
            "detailed_results": all_results
        }
        
        return report

if __name__ == "__main__":
    # Run the comprehensive test suite
    asyncio.run(run_comprehensive_performance_test())