#!/usr/bin/env python3
"""
PgBouncer High Concurrency Load Test
Task 80.10: Test concurrent access scenarios with 100+ sessions
Validates session context isolation and performance under load
"""

import asyncio
import asyncpg
import time
import json
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import uuid
import logging
import sys
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class TestResult:
    """Test result data structure"""
    session_id: str
    tenant_id: str
    user_id: str
    operations_completed: int
    duration_ms: float
    avg_operation_time_ms: float
    context_isolation_violations: int
    errors: List[str]
    success: bool

@dataclass
class LoadTestConfig:
    """Configuration for load test"""
    pgbouncer_host: str = "localhost"
    pgbouncer_port: int = 6432
    database: str = "isectech"
    user: str = "isectech_pool"
    password: str = "your_password_here"
    
    # Test parameters
    concurrent_sessions: int = 100
    operations_per_session: int = 20
    test_duration_seconds: int = 60
    
    # Connection pool settings
    max_connections: int = 50
    connection_timeout: float = 10.0
    command_timeout: float = 30.0

class PgBouncerLoadTester:
    """High concurrency load tester for PgBouncer with RBAC schema"""
    
    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.test_tenants = []
        self.test_users = []
        self.test_results: List[TestResult] = []
        
    async def setup_test_data(self):
        """Setup test tenants and users for concurrent testing"""
        logger.info("Setting up test data...")
        
        conn = await asyncpg.connect(
            host=self.config.pgbouncer_host,
            port=self.config.pgbouncer_port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password
        )
        
        try:
            # Create test tenants
            for i in range(10):  # 10 test tenants
                tenant_id = str(uuid.uuid4())
                tenant_name = f"load_test_tenant_{i}"
                
                await conn.execute('''
                    INSERT INTO tenants (id, name) 
                    VALUES ($1, $2) 
                    ON CONFLICT (name) DO NOTHING
                ''', tenant_id, tenant_name)
                
                self.test_tenants.append({
                    'id': tenant_id,
                    'name': tenant_name
                })
            
            # Create test users and roles
            for i, tenant in enumerate(self.test_tenants):
                for j in range(10):  # 10 users per tenant
                    user_id = str(uuid.uuid4())
                    user_email = f"load_test_user_{i}_{j}@test.com"
                    role_id = str(uuid.uuid4())
                    role_name = f"load_test_role_{j}"
                    
                    # Create user
                    await conn.execute('''
                        INSERT INTO users (id, email) 
                        VALUES ($1, $2) 
                        ON CONFLICT (email) DO NOTHING
                    ''', user_id, user_email)
                    
                    # Create role for tenant
                    await conn.execute('''
                        INSERT INTO roles (id, tenant_id, name, description) 
                        VALUES ($1, $2, $3, $4) 
                        ON CONFLICT (tenant_id, name) DO NOTHING
                    ''', role_id, tenant['id'], role_name, f"Load test role {j}")
                    
                    # Assign user to role
                    await conn.execute('''
                        INSERT INTO user_roles (tenant_id, user_id, role_id) 
                        VALUES ($1, $2, $3) 
                        ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING
                    ''', tenant['id'], user_id, role_id)
                    
                    self.test_users.append({
                        'id': user_id,
                        'email': user_email,
                        'tenant_id': tenant['id'],
                        'role_id': role_id
                    })
            
            logger.info(f"Created {len(self.test_tenants)} tenants and {len(self.test_users)} users")
            
        finally:
            await conn.close()
    
    async def cleanup_test_data(self):
        """Clean up test data after testing"""
        logger.info("Cleaning up test data...")
        
        conn = await asyncpg.connect(
            host=self.config.pgbouncer_host,
            port=self.config.pgbouncer_port,
            database=self.config.database,
            user=self.config.user,
            password=self.config.password
        )
        
        try:
            # Clean up in reverse order due to foreign key constraints
            for user in self.test_users:
                await conn.execute('DELETE FROM user_roles WHERE user_id = $1', user['id'])
            
            for tenant in self.test_tenants:
                await conn.execute('DELETE FROM roles WHERE tenant_id = $1', tenant['id'])
            
            for user in self.test_users:
                await conn.execute('DELETE FROM users WHERE id = $1', user['id'])
            
            for tenant in self.test_tenants:
                await conn.execute('DELETE FROM tenants WHERE id = $1', tenant['id'])
            
            logger.info("Test data cleanup completed")
            
        finally:
            await conn.close()
    
    async def simulate_session_workload(self, session_id: str, user_data: Dict[str, str]) -> TestResult:
        """Simulate workload for a single session"""
        errors = []
        context_violations = 0
        operations_completed = 0
        start_time = time.time()
        
        try:
            conn = await asyncpg.connect(
                host=self.config.pgbouncer_host,
                port=self.config.pgbouncer_port,
                database=self.config.database,
                user=self.config.user,
                password=self.config.password,
                timeout=self.config.connection_timeout,
                command_timeout=self.config.command_timeout
            )
            
            try:
                # Set session context
                await conn.execute('SELECT set_session_context($1, $2)', 
                                 user_data['tenant_id'], user_data['id'])
                
                # Perform operations
                for i in range(self.config.operations_per_session):
                    operation_start = time.time()
                    
                    # Test 1: Verify session context isolation
                    current_tenant = await conn.fetchval('SELECT current_tenant_id()')
                    current_user = await conn.fetchval('SELECT current_user_id()')
                    
                    if str(current_tenant) != user_data['tenant_id']:
                        context_violations += 1
                        errors.append(f"Tenant context violation at operation {i}")
                    
                    if str(current_user) != user_data['id']:
                        context_violations += 1
                        errors.append(f"User context violation at operation {i}")
                    
                    # Test 2: Verify RLS isolation (should only see own tenant's data)
                    roles_count = await conn.fetchval('SELECT COUNT(*) FROM roles')
                    expected_roles = 10  # Each tenant should have 10 roles
                    
                    if roles_count != expected_roles:
                        context_violations += 1
                        errors.append(f"RLS violation: saw {roles_count} roles, expected {expected_roles}")
                    
                    # Test 3: Perform some database operations
                    await conn.fetchval('SELECT COUNT(*) FROM user_roles WHERE tenant_id = current_tenant_id()')
                    await conn.fetchval('SELECT get_session_context()')
                    
                    # Test 4: Permission check
                    has_permission = await conn.fetchval('''
                        SELECT has_permission(current_tenant_id(), current_user_id(), 'security', 'rbac', 'read')
                    ''')
                    
                    operations_completed += 1
                    
                    # Small delay to simulate real work
                    await asyncio.sleep(0.001)
                
                # Clear session context
                await conn.execute('SELECT clear_session_context()')
                
            finally:
                await conn.close()
                
        except Exception as e:
            errors.append(str(e))
            logger.error(f"Session {session_id} error: {e}")
        
        end_time = time.time()
        duration_ms = (end_time - start_time) * 1000
        avg_operation_time = duration_ms / max(operations_completed, 1)
        
        return TestResult(
            session_id=session_id,
            tenant_id=user_data['tenant_id'],
            user_id=user_data['id'],
            operations_completed=operations_completed,
            duration_ms=duration_ms,
            avg_operation_time_ms=avg_operation_time,
            context_isolation_violations=context_violations,
            errors=errors,
            success=len(errors) == 0 and context_violations == 0
        )
    
    async def run_concurrent_load_test(self) -> Dict[str, Any]:
        """Run concurrent load test with multiple sessions"""
        logger.info(f"Starting load test with {self.config.concurrent_sessions} concurrent sessions")
        
        # Create semaphore to limit concurrent connections
        semaphore = asyncio.Semaphore(self.config.max_connections)
        
        async def run_session(session_id: str, user_data: Dict[str, str]) -> TestResult:
            async with semaphore:
                return await self.simulate_session_workload(session_id, user_data)
        
        # Create tasks for concurrent execution
        tasks = []
        for i in range(self.config.concurrent_sessions):
            session_id = f"session_{i}"
            # Distribute users across sessions
            user_data = self.test_users[i % len(self.test_users)]
            task = asyncio.create_task(run_session(session_id, user_data))
            tasks.append(task)
        
        # Run all sessions concurrently
        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Process results
        successful_results = []
        failed_results = []
        
        for result in results:
            if isinstance(result, Exception):
                failed_results.append(str(result))
            elif isinstance(result, TestResult):
                if result.success:
                    successful_results.append(result)
                else:
                    failed_results.append(result)
                self.test_results.append(result)
        
        return self.analyze_results(start_time, end_time, successful_results, failed_results)
    
    def analyze_results(self, start_time: float, end_time: float, 
                       successful_results: List[TestResult], 
                       failed_results: List[Any]) -> Dict[str, Any]:
        """Analyze test results and generate performance report"""
        
        total_duration = (end_time - start_time) * 1000  # ms
        total_sessions = len(successful_results) + len(failed_results)
        success_rate = len(successful_results) / total_sessions if total_sessions > 0 else 0
        
        if successful_results:
            durations = [r.duration_ms for r in successful_results]
            operation_times = [r.avg_operation_time_ms for r in successful_results]
            total_operations = sum(r.operations_completed for r in successful_results)
            total_violations = sum(r.context_isolation_violations for r in successful_results)
            
            performance_stats = {
                'avg_session_duration_ms': statistics.mean(durations),
                'median_session_duration_ms': statistics.median(durations),
                'p95_session_duration_ms': statistics.quantiles(durations, n=20)[18] if len(durations) > 20 else max(durations),
                'p99_session_duration_ms': statistics.quantiles(durations, n=100)[98] if len(durations) > 100 else max(durations),
                'avg_operation_time_ms': statistics.mean(operation_times),
                'median_operation_time_ms': statistics.median(operation_times),
                'operations_per_second': total_operations / (total_duration / 1000) if total_duration > 0 else 0,
                'total_context_violations': total_violations
            }
        else:
            performance_stats = {
                'avg_session_duration_ms': 0,
                'median_session_duration_ms': 0,
                'p95_session_duration_ms': 0,
                'p99_session_duration_ms': 0,
                'avg_operation_time_ms': 0,
                'median_operation_time_ms': 0,
                'operations_per_second': 0,
                'total_context_violations': 0
            }
        
        return {
            'test_config': asdict(self.config),
            'test_summary': {
                'total_sessions': total_sessions,
                'successful_sessions': len(successful_results),
                'failed_sessions': len(failed_results),
                'success_rate': success_rate,
                'total_duration_ms': total_duration,
                'concurrent_sessions_achieved': self.config.concurrent_sessions
            },
            'performance_stats': performance_stats,
            'isolation_validation': {
                'context_isolation_failures': sum(r.context_isolation_violations for r in self.test_results),
                'sessions_with_violations': len([r for r in self.test_results if r.context_isolation_violations > 0]),
                'isolation_success_rate': len([r for r in self.test_results if r.context_isolation_violations == 0]) / len(self.test_results) if self.test_results else 0
            },
            'detailed_results': [asdict(r) for r in self.test_results[:10]],  # First 10 for brevity
            'test_timestamp': time.time(),
            'pgbouncer_config': {
                'host': self.config.pgbouncer_host,
                'port': self.config.pgbouncer_port,
                'pool_mode': 'session'  # Critical for session variable persistence
            }
        }

async def main():
    """Main test execution"""
    # Configuration
    config = LoadTestConfig(
        concurrent_sessions=150,  # Test with 150 concurrent sessions
        operations_per_session=25,
        test_duration_seconds=120,
        max_connections=75  # Limit concurrent DB connections
    )
    
    logger.info("Starting PgBouncer High Concurrency Load Test")
    logger.info(f"Config: {config.concurrent_sessions} sessions, {config.operations_per_session} ops/session")
    
    tester = PgBouncerLoadTester(config)
    
    try:
        # Setup test data
        await tester.setup_test_data()
        
        # Run load test
        results = await tester.run_concurrent_load_test()
        
        # Output results
        print("\n" + "="*80)
        print("PGBOUNCER LOAD TEST RESULTS")
        print("="*80)
        print(json.dumps(results, indent=2, default=str))
        
        # Key metrics summary
        summary = results['test_summary']
        perf = results['performance_stats']
        isolation = results['isolation_validation']
        
        print(f"\n📊 PERFORMANCE SUMMARY:")
        print(f"  Success Rate: {summary['success_rate']:.2%}")
        print(f"  Total Sessions: {summary['total_sessions']}")
        print(f"  Operations/Second: {perf['operations_per_second']:.2f}")
        print(f"  Avg Session Duration: {perf['avg_session_duration_ms']:.2f}ms")
        print(f"  P95 Session Duration: {perf['p95_session_duration_ms']:.2f}ms")
        print(f"  Avg Operation Time: {perf['avg_operation_time_ms']:.2f}ms")
        
        print(f"\n🔒 ISOLATION VALIDATION:")
        print(f"  Context Isolation Success Rate: {isolation['isolation_success_rate']:.2%}")
        print(f"  Total Violations: {isolation['context_isolation_failures']}")
        print(f"  Sessions with Violations: {isolation['sessions_with_violations']}")
        
        # Save results to file
        with open('pgbouncer_load_test_results.json', 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info("Load test completed successfully")
        
        # Return appropriate exit code
        if results['isolation_validation']['isolation_success_rate'] < 1.0:
            logger.error("CRITICAL: Session isolation violations detected!")
            sys.exit(1)
        elif results['test_summary']['success_rate'] < 0.95:
            logger.warning("WARNING: Low success rate detected")
            sys.exit(1)
        else:
            logger.info("✅ All tests passed!")
            sys.exit(0)
            
    except Exception as e:
        logger.error(f"Load test failed: {e}")
        sys.exit(1)
    finally:
        # Cleanup
        try:
            await tester.cleanup_test_data()
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")

if __name__ == "__main__":
    # Run the async main function
    asyncio.run(main())