#!/usr/bin/env python3
"""
iSECTECH Comprehensive Test Suite
Unified testing framework that integrates all NSM testing components for complete validation
"""

import asyncio
import json
import logging
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import yaml
from concurrent.futures import ThreadPoolExecutor

# Import our testing frameworks
from test_framework import NSMTestFramework, TestResult
from load_test_framework import NSMLoadTestFramework, LoadTestConfig, LoadTestResult
from detection_accuracy_validator import DetectionAccuracyValidator, AccuracyMetrics
from performance.performance_optimizer import NSMPerformanceOptimizer


@dataclass
class TestSuiteConfig:
    """Configuration for comprehensive test suite"""
    # Test selection
    run_unit_tests: bool = True
    run_integration_tests: bool = True
    run_performance_tests: bool = True
    run_security_tests: bool = True
    run_load_tests: bool = True
    run_detection_accuracy_tests: bool = True
    
    # Test parameters
    performance_monitoring_duration: int = 300  # 5 minutes
    load_test_duration: int = 180  # 3 minutes
    detection_accuracy_dataset: str = "comprehensive"
    
    # Reporting
    generate_html_report: bool = True
    generate_json_report: bool = True
    save_raw_data: bool = True
    
    # Thresholds
    max_acceptable_error_rate: float = 0.05  # 5%
    max_acceptable_response_time: float = 2.0  # 2 seconds
    max_acceptable_fpr: float = 0.03  # 3% false positive rate
    min_acceptable_precision: float = 0.90  # 90% precision
    min_acceptable_recall: float = 0.85  # 85% recall


@dataclass
class TestSuiteResults:
    """Comprehensive test suite results"""
    suite_id: str
    start_time: datetime
    end_time: datetime
    total_duration: float
    
    # Test results
    unit_test_results: Optional[Dict[str, Any]] = None
    integration_test_results: Optional[Dict[str, Any]] = None
    performance_test_results: Optional[Dict[str, Any]] = None
    security_test_results: Optional[Dict[str, Any]] = None
    load_test_results: Optional[List[LoadTestResult]] = None
    detection_accuracy_results: Optional[Dict[str, AccuracyMetrics]] = None
    
    # Summary metrics
    total_tests_run: int = 0
    total_tests_passed: int = 0
    total_tests_failed: int = 0
    overall_success_rate: float = 0.0
    
    # Component health
    component_health_status: Dict[str, str] = None
    
    # Performance summary
    performance_summary: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.component_health_status is None:
            self.component_health_status = {}
        if self.performance_summary is None:
            self.performance_summary = {}


class ComprehensiveTestSuite:
    """Main comprehensive testing framework for NSM"""
    
    def __init__(self, config_path: str = "/etc/nsm/test_suite.yaml"):
        self.config_path = config_path
        self.config = self._load_config()
        self.logger = self._setup_logging()
        
        # Initialize test frameworks
        self.unit_test_framework = NSMTestFramework()
        self.load_test_framework = NSMLoadTestFramework()
        self.detection_validator = DetectionAccuracyValidator()
        self.performance_optimizer = NSMPerformanceOptimizer()
        
        # Results storage
        self.test_results: List[TestSuiteResults] = []
        
        # Component endpoints for health checks
        self.component_endpoints = self._get_component_endpoints()
        
        # Report templates
        self.report_templates = self._load_report_templates()
    
    def _load_config(self) -> TestSuiteConfig:
        """Load test suite configuration"""
        try:
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f)
                return TestSuiteConfig(**config_data)
        except Exception as e:
            print(f"Error loading test suite config: {e}, using defaults")
            return TestSuiteConfig()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('ComprehensiveTestSuite')
        logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler
        log_file = Path("/var/log/nsm/comprehensive_test_suite.log")
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def _get_component_endpoints(self) -> Dict[str, str]:
        """Get component endpoints for health checks"""
        return {
            'signature_detection': 'http://localhost:8437/health',
            'anomaly_detection': 'http://localhost:8441/health',
            'behavioral_analysis': 'http://localhost:8444/health',
            'encrypted_analysis': 'http://localhost:8445/health',
            'asset_discovery': 'http://localhost:8446/health',
            'vulnerability_correlation': 'http://localhost:8447/health',
            'siem_integration': 'http://localhost:8448/health',
            'soar_integration': 'http://localhost:8449/health',
            'integration_orchestrator': 'http://localhost:8450/health'
        }
    
    def _load_report_templates(self) -> Dict[str, str]:
        """Load report templates"""
        templates = {}
        
        # HTML report template
        templates['html'] = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>NSM Comprehensive Test Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .success { background-color: #d4edda; }
                .warning { background-color: #fff3cd; }
                .error { background-color: #f8d7da; }
                .metric { display: inline-block; margin: 10px; padding: 10px; background-color: #f8f9fa; border-radius: 3px; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .chart { margin: 20px 0; }
            </style>
        </head>
        <body>
            {content}
        </body>
        </html>
        """
        
        return templates
    
    async def run_comprehensive_test_suite(self) -> TestSuiteResults:
        """Run the complete test suite"""
        suite_id = f"test_suite_{int(time.time())}"
        start_time = datetime.utcnow()
        
        self.logger.info(f"Starting comprehensive test suite: {suite_id}")
        
        # Initialize results
        results = TestSuiteResults(
            suite_id=suite_id,
            start_time=start_time,
            end_time=start_time,  # Will be updated at the end
            total_duration=0.0
        )
        
        try:
            # Phase 1: Component Health Check
            self.logger.info("Phase 1: Component Health Check")
            health_status = await self._check_component_health()
            results.component_health_status = health_status
            
            unhealthy_components = [comp for comp, status in health_status.items() if status != 'healthy']
            if unhealthy_components:
                self.logger.warning(f"Unhealthy components detected: {unhealthy_components}")
            
            # Phase 2: Unit and Integration Tests
            if self.config.run_unit_tests or self.config.run_integration_tests:
                self.logger.info("Phase 2: Unit and Integration Tests")
                test_types = []
                if self.config.run_unit_tests:
                    test_types.append('unit')
                if self.config.run_integration_tests:
                    test_types.append('integration')
                if self.config.run_performance_tests:
                    test_types.append('performance')
                if self.config.run_security_tests:
                    test_types.append('security')
                
                basic_test_results = await self.unit_test_framework.run_all_tests(test_types)
                
                # Categorize results
                if 'unit' in test_types:
                    results.unit_test_results = self._extract_test_type_results(basic_test_results, 'unit')
                if 'integration' in test_types:
                    results.integration_test_results = self._extract_test_type_results(basic_test_results, 'integration')
                if 'performance' in test_types:
                    results.performance_test_results = self._extract_test_type_results(basic_test_results, 'performance')
                if 'security' in test_types:
                    results.security_test_results = self._extract_test_type_results(basic_test_results, 'security')
            
            # Phase 3: Load Testing
            if self.config.run_load_tests:
                self.logger.info("Phase 3: Load Testing")
                load_test_results = await self._run_load_tests()
                results.load_test_results = load_test_results
            
            # Phase 4: Detection Accuracy Validation
            if self.config.run_detection_accuracy_tests:
                self.logger.info("Phase 4: Detection Accuracy Validation")
                accuracy_results = await self.detection_validator.validate_all_components(
                    self.config.detection_accuracy_dataset
                )
                results.detection_accuracy_results = accuracy_results
            
            # Phase 5: Performance Monitoring
            self.logger.info("Phase 5: Performance Analysis")
            performance_summary = await self._analyze_performance()
            results.performance_summary = performance_summary
            
            # Calculate summary metrics
            results = self._calculate_summary_metrics(results)
            
        except Exception as e:
            self.logger.error(f"Test suite execution failed: {e}")
            raise
        
        finally:
            # Update final timing
            end_time = datetime.utcnow()
            results.end_time = end_time
            results.total_duration = (end_time - start_time).total_seconds()
            
            # Store results
            self.test_results.append(results)
            
            self.logger.info(f"Test suite completed: {suite_id} in {results.total_duration:.1f}s")
        
        return results
    
    async def _check_component_health(self) -> Dict[str, str]:
        """Check health status of all components"""
        import aiohttp
        
        health_status = {}
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            for component, endpoint in self.component_endpoints.items():
                try:
                    async with session.get(endpoint) as response:
                        if response.status == 200:
                            health_status[component] = 'healthy'
                        else:
                            health_status[component] = f'unhealthy_http_{response.status}'
                except aiohttp.ClientTimeout:
                    health_status[component] = 'unhealthy_timeout'
                except aiohttp.ClientConnectorError:
                    health_status[component] = 'unhealthy_connection_error'
                except Exception as e:
                    health_status[component] = f'unhealthy_error_{type(e).__name__}'
        
        return health_status
    
    def _extract_test_type_results(self, test_results: Dict[str, Any], test_type: str) -> Dict[str, Any]:
        """Extract results for a specific test type"""
        filtered_results = []
        
        for result_dict in test_results.get('results', []):
            if result_dict.get('test_type') == test_type:
                filtered_results.append(result_dict)
        
        if not filtered_results:
            return {'total': 0, 'passed': 0, 'failed': 0, 'results': []}
        
        passed = len([r for r in filtered_results if r.get('status') == 'passed'])
        failed = len([r for r in filtered_results if r.get('status') == 'failed'])
        
        return {
            'total': len(filtered_results),
            'passed': passed,
            'failed': failed,
            'success_rate': (passed / len(filtered_results)) * 100 if filtered_results else 0,
            'results': filtered_results
        }
    
    async def _run_load_tests(self) -> List[LoadTestResult]:
        """Run comprehensive load tests"""
        load_test_configs = [
            LoadTestConfig(
                test_name="Signature Detection Load Test",
                target_component="signature_detection",
                test_duration_seconds=self.config.load_test_duration,
                concurrent_users=30,
                requests_per_second=60,
                ramp_up_time=20,
                ramp_down_time=20
            ),
            LoadTestConfig(
                test_name="Anomaly Detection Load Test",
                target_component="anomaly_detection",
                test_duration_seconds=self.config.load_test_duration,
                concurrent_users=25,
                requests_per_second=50,
                ramp_up_time=15,
                ramp_down_time=15
            ),
            LoadTestConfig(
                test_name="Integration Orchestrator Load Test",
                target_component="integration_orchestrator",
                test_duration_seconds=self.config.load_test_duration,
                concurrent_users=20,
                requests_per_second=40,
                ramp_up_time=10,
                ramp_down_time=10
            )
        ]
        
        load_results = []
        for config in load_test_configs:
            try:
                result = await self.load_test_framework.run_load_test(config)
                load_results.append(result)
            except Exception as e:
                self.logger.error(f"Load test failed for {config.test_name}: {e}")
        
        return load_results
    
    async def _analyze_performance(self) -> Dict[str, Any]:
        """Analyze system performance"""
        # Get current performance metrics
        performance_summary = self.performance_optimizer.get_current_metrics()
        
        # Add analysis
        recommendations = []
        
        # Analyze system metrics
        system_metrics = performance_summary.get('system_metrics', {})
        for metric_name, metric_data in system_metrics.items():
            if 'cpu_usage' in metric_name and metric_data.get('value', 0) > 80:
                recommendations.append({
                    'type': 'performance',
                    'priority': 'high',
                    'message': f"High CPU usage detected: {metric_data.get('value', 0):.1f}%"
                })
            
            if 'memory_usage' in metric_name and metric_data.get('value', 0) > 85:
                recommendations.append({
                    'type': 'performance',
                    'priority': 'high',
                    'message': f"High memory usage detected: {metric_data.get('value', 0):.1f}%"
                })
        
        performance_summary['recommendations'] = recommendations
        performance_summary['analysis_timestamp'] = datetime.utcnow().isoformat()
        
        return performance_summary
    
    def _calculate_summary_metrics(self, results: TestSuiteResults) -> TestSuiteResults:
        """Calculate overall summary metrics"""
        total_tests = 0
        total_passed = 0
        total_failed = 0
        
        # Count unit tests
        if results.unit_test_results:
            total_tests += results.unit_test_results.get('total', 0)
            total_passed += results.unit_test_results.get('passed', 0)
            total_failed += results.unit_test_results.get('failed', 0)
        
        # Count integration tests
        if results.integration_test_results:
            total_tests += results.integration_test_results.get('total', 0)
            total_passed += results.integration_test_results.get('passed', 0)
            total_failed += results.integration_test_results.get('failed', 0)
        
        # Count performance tests
        if results.performance_test_results:
            total_tests += results.performance_test_results.get('total', 0)
            total_passed += results.performance_test_results.get('passed', 0)
            total_failed += results.performance_test_results.get('failed', 0)
        
        # Count security tests
        if results.security_test_results:
            total_tests += results.security_test_results.get('total', 0)
            total_passed += results.security_test_results.get('passed', 0)
            total_failed += results.security_test_results.get('failed', 0)
        
        # Count load tests (simplified)
        if results.load_test_results:
            load_test_count = len(results.load_test_results)
            load_test_passed = len([r for r in results.load_test_results if r.error_rate < 5.0])
            
            total_tests += load_test_count
            total_passed += load_test_passed
            total_failed += load_test_count - load_test_passed
        
        # Count detection accuracy tests (simplified)
        if results.detection_accuracy_results:
            accuracy_test_count = len(results.detection_accuracy_results)
            accuracy_test_passed = len([
                comp for comp, metrics in results.detection_accuracy_results.items()
                if metrics.precision >= self.config.min_acceptable_precision
                and metrics.recall >= self.config.min_acceptable_recall
                and metrics.false_positive_rate <= self.config.max_acceptable_fpr
            ])
            
            total_tests += accuracy_test_count
            total_passed += accuracy_test_passed
            total_failed += accuracy_test_count - accuracy_test_passed
        
        # Update results
        results.total_tests_run = total_tests
        results.total_tests_passed = total_passed
        results.total_tests_failed = total_failed
        results.overall_success_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0
        
        return results
    
    def generate_comprehensive_report(self, results: TestSuiteResults) -> Dict[str, str]:
        """Generate comprehensive test report in multiple formats"""
        reports = {}
        
        # Generate text report
        reports['text'] = self._generate_text_report(results)
        
        # Generate JSON report
        if self.config.generate_json_report:
            reports['json'] = self._generate_json_report(results)
        
        # Generate HTML report
        if self.config.generate_html_report:
            reports['html'] = self._generate_html_report(results)
        
        return reports
    
    def _generate_text_report(self, results: TestSuiteResults) -> str:
        """Generate text-based comprehensive report"""
        report = []
        report.append("=" * 100)
        report.append("NSM COMPREHENSIVE TEST SUITE REPORT")
        report.append("=" * 100)
        report.append(f"Suite ID: {results.suite_id}")
        report.append(f"Generated: {results.end_time.isoformat()}")
        report.append(f"Test Duration: {results.total_duration:.1f} seconds")
        report.append(f"Overall Success Rate: {results.overall_success_rate:.1f}%")
        report.append("")
        
        # Executive Summary
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 50)
        report.append(f"Total Tests Run: {results.total_tests_run}")
        report.append(f"Tests Passed: {results.total_tests_passed}")
        report.append(f"Tests Failed: {results.total_tests_failed}")
        
        # Determine overall status
        if results.overall_success_rate >= 95:
            status = "EXCELLENT ✅"
        elif results.overall_success_rate >= 90:
            status = "GOOD ✅"
        elif results.overall_success_rate >= 80:
            status = "ACCEPTABLE ⚠️"
        else:
            status = "NEEDS ATTENTION ❌"
        
        report.append(f"Overall Status: {status}")
        report.append("")
        
        # Component Health Status
        report.append("COMPONENT HEALTH STATUS")
        report.append("-" * 50)
        for component, status in results.component_health_status.items():
            status_icon = "✅" if status == "healthy" else "❌"
            report.append(f"{component}: {status} {status_icon}")
        report.append("")
        
        # Unit Test Results
        if results.unit_test_results:
            report.append("UNIT TEST RESULTS")
            report.append("-" * 50)
            unit_results = results.unit_test_results
            report.append(f"Total Unit Tests: {unit_results['total']}")
            report.append(f"Passed: {unit_results['passed']}")
            report.append(f"Failed: {unit_results['failed']}")
            report.append(f"Success Rate: {unit_results['success_rate']:.1f}%")
            report.append("")
        
        # Integration Test Results
        if results.integration_test_results:
            report.append("INTEGRATION TEST RESULTS")
            report.append("-" * 50)
            int_results = results.integration_test_results
            report.append(f"Total Integration Tests: {int_results['total']}")
            report.append(f"Passed: {int_results['passed']}")
            report.append(f"Failed: {int_results['failed']}")
            report.append(f"Success Rate: {int_results['success_rate']:.1f}%")
            report.append("")
        
        # Load Test Results
        if results.load_test_results:
            report.append("LOAD TEST RESULTS")
            report.append("-" * 50)
            for load_result in results.load_test_results:
                report.append(f"Test: {load_result.test_name}")
                report.append(f"  Component: {load_result.component}")
                report.append(f"  Total Requests: {load_result.total_requests:,}")
                report.append(f"  Success Rate: {((load_result.successful_requests/load_result.total_requests)*100):.1f}%")
                report.append(f"  Average Response Time: {load_result.avg_response_time:.3f}s")
                report.append(f"  Requests per Second: {load_result.requests_per_second:.1f}")
                
                # Status indicator
                if load_result.error_rate <= self.config.max_acceptable_error_rate * 100:
                    report.append(f"  Status: PASS ✅")
                else:
                    report.append(f"  Status: FAIL ❌ (Error rate: {load_result.error_rate:.1f}%)")
                
                report.append("")
        
        # Detection Accuracy Results
        if results.detection_accuracy_results:
            report.append("DETECTION ACCURACY RESULTS")
            report.append("-" * 50)
            for component, metrics in results.detection_accuracy_results.items():
                report.append(f"Component: {component}")
                report.append(f"  Precision: {metrics.precision:.3f}")
                report.append(f"  Recall: {metrics.recall:.3f}")
                report.append(f"  F1-Score: {metrics.f1_score:.3f}")
                report.append(f"  False Positive Rate: {metrics.false_positive_rate:.3f}")
                report.append(f"  Average Detection Time: {metrics.avg_detection_time:.3f}s")
                
                # Status based on thresholds
                precision_ok = metrics.precision >= self.config.min_acceptable_precision
                recall_ok = metrics.recall >= self.config.min_acceptable_recall
                fpr_ok = metrics.false_positive_rate <= self.config.max_acceptable_fpr
                
                if precision_ok and recall_ok and fpr_ok:
                    report.append(f"  Status: PASS ✅")
                else:
                    issues = []
                    if not precision_ok:
                        issues.append(f"Low precision ({metrics.precision:.3f})")
                    if not recall_ok:
                        issues.append(f"Low recall ({metrics.recall:.3f})")
                    if not fpr_ok:
                        issues.append(f"High FPR ({metrics.false_positive_rate:.3f})")
                    
                    report.append(f"  Status: FAIL ❌ ({', '.join(issues)})")
                
                report.append("")
        
        # Performance Analysis
        if results.performance_summary:
            report.append("PERFORMANCE ANALYSIS")
            report.append("-" * 50)
            
            recommendations = results.performance_summary.get('recommendations', [])
            if recommendations:
                report.append("Performance Recommendations:")
                for rec in recommendations:
                    priority_icon = "🔥" if rec['priority'] == 'high' else "⚠️"
                    report.append(f"  {priority_icon} {rec['message']}")
            else:
                report.append("No performance issues detected ✅")
            
            report.append("")
        
        # Overall Recommendations
        report.append("OVERALL RECOMMENDATIONS")
        report.append("-" * 50)
        
        recommendations = []
        
        # Check for failed components
        unhealthy_components = [comp for comp, status in results.component_health_status.items() if status != 'healthy']
        if unhealthy_components:
            recommendations.append(f"🔥 CRITICAL: Fix unhealthy components: {', '.join(unhealthy_components)}")
        
        # Check load test performance
        if results.load_test_results:
            slow_components = [
                r.component for r in results.load_test_results 
                if r.avg_response_time > self.config.max_acceptable_response_time
            ]
            if slow_components:
                recommendations.append(f"⚠️ PERFORMANCE: Optimize slow components: {', '.join(slow_components)}")
        
        # Check detection accuracy
        if results.detection_accuracy_results:
            inaccurate_components = [
                comp for comp, metrics in results.detection_accuracy_results.items()
                if (metrics.precision < self.config.min_acceptable_precision or 
                    metrics.recall < self.config.min_acceptable_recall or
                    metrics.false_positive_rate > self.config.max_acceptable_fpr)
            ]
            if inaccurate_components:
                recommendations.append(f"⚠️ ACCURACY: Tune detection accuracy for: {', '.join(inaccurate_components)}")
        
        if not recommendations:
            report.append("✅ All systems performing within acceptable parameters")
        else:
            for rec in recommendations:
                report.append(rec)
        
        report.append("")
        report.append("=" * 100)
        
        return "\n".join(report)
    
    def _generate_json_report(self, results: TestSuiteResults) -> str:
        """Generate JSON report"""
        report_data = asdict(results)
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_html_report(self, results: TestSuiteResults) -> str:
        """Generate HTML report"""
        # This is a simplified HTML report - in production, you'd use a proper template engine
        html_content = f"""
        <div class="header">
            <h1>NSM Comprehensive Test Report</h1>
            <p>Suite ID: {results.suite_id}</p>
            <p>Generated: {results.end_time.isoformat()}</p>
            <p>Duration: {results.total_duration:.1f} seconds</p>
        </div>
        
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric">Total Tests: {results.total_tests_run}</div>
            <div class="metric">Passed: {results.total_tests_passed}</div>
            <div class="metric">Failed: {results.total_tests_failed}</div>
            <div class="metric">Success Rate: {results.overall_success_rate:.1f}%</div>
        </div>
        
        <div class="section">
            <h2>Component Health Status</h2>
            <table>
                <tr><th>Component</th><th>Status</th></tr>
        """
        
        for component, status in results.component_health_status.items():
            css_class = "success" if status == "healthy" else "error"
            html_content += f'<tr class="{css_class}"><td>{component}</td><td>{status}</td></tr>'
        
        html_content += """
            </table>
        </div>
        """
        
        # Add more sections as needed...
        
        return self.report_templates['html'].format(content=html_content)
    
    async def save_reports(self, results: TestSuiteResults, output_dir: str = "/var/lib/nsm/reports"):
        """Save all reports to files"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = results.end_time.strftime("%Y%m%d_%H%M%S")
        base_filename = f"nsm_test_report_{timestamp}"
        
        # Generate all reports
        reports = self.generate_comprehensive_report(results)
        
        # Save each report type
        for report_type, content in reports.items():
            if report_type == 'json':
                filename = f"{base_filename}.json"
            elif report_type == 'html':
                filename = f"{base_filename}.html"
            else:
                filename = f"{base_filename}.txt"
            
            filepath = output_path / filename
            
            if report_type == 'json':
                with open(filepath, 'w') as f:
                    f.write(content)
            else:
                async with aiofiles.open(filepath, 'w') as f:
                    await f.write(content)
            
            self.logger.info(f"Saved {report_type} report to: {filepath}")
        
        # Save raw test data if configured
        if self.config.save_raw_data:
            raw_data_file = output_path / f"nsm_test_raw_data_{timestamp}.json"
            raw_data = {
                'suite_results': asdict(results),
                'test_framework_results': getattr(self.unit_test_framework, 'test_results', []),
                'load_test_detailed_results': [asdict(r) for r in results.load_test_results] if results.load_test_results else [],
                'detection_validator_samples': getattr(self.detection_validator, 'test_samples', [])
            }
            
            with open(raw_data_file, 'w') as f:
                json.dump(raw_data, f, indent=2, default=str)
            
            self.logger.info(f"Saved raw test data to: {raw_data_file}")


async def main():
    """Main execution for comprehensive test suite"""
    test_suite = ComprehensiveTestSuite()
    
    try:
        # Run comprehensive test suite
        results = await test_suite.run_comprehensive_test_suite()
        
        # Generate and display report
        reports = test_suite.generate_comprehensive_report(results)
        print(reports['text'])
        
        # Save all reports
        await test_suite.save_reports(results)
        
        print(f"\nTest suite completed successfully!")
        print(f"Overall success rate: {results.overall_success_rate:.1f}%")
        print(f"Reports saved to: /var/lib/nsm/reports/")
        
        # Exit with appropriate code
        sys.exit(0 if results.overall_success_rate >= 80 else 1)
        
    except Exception as e:
        print(f"Test suite execution failed: {e}")
        logging.exception("Test suite error")
        sys.exit(2)


if __name__ == "__main__":
    asyncio.run(main())