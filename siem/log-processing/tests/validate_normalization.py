#!/usr/bin/env python3
"""
iSECTECH SIEM Log Normalization Validation Script
Comprehensive validation framework for log parsing accuracy and ECS compliance
Production-grade testing with detailed reporting and performance metrics
"""

import asyncio
import json
import time
import yaml
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple
import sys
import os
from dataclasses import dataclass, asdict
import traceback

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from log_normalizer import LogNormalizer, NormalizationConfig, NormalizedLog

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of a single validation test"""
    test_name: str
    log_format: str
    success: bool
    processing_time_ms: float
    expected_fields: Dict[str, Any]
    actual_fields: Dict[str, Any]
    missing_fields: List[str]
    incorrect_fields: List[str]
    validation_errors: List[str]
    error_message: str = ""

@dataclass
class ValidationSummary:
    """Summary of all validation results"""
    total_tests: int
    successful_tests: int
    failed_tests: int
    success_rate: float
    avg_processing_time_ms: float
    total_processing_time_ms: float
    performance_metrics: Dict[str, Any]
    compliance_score: float

class LogNormalizationValidator:
    """
    Comprehensive validation framework for log normalization
    Tests parsing accuracy, ECS compliance, and performance
    """
    
    def __init__(self, config_file: str, sample_logs_file: str):
        self.config_file = config_file
        self.sample_logs_file = sample_logs_file
        self.normalizer = None
        self.sample_data = None
        self.results: List[ValidationResult] = []
        
    async def initialize(self):
        """Initialize the validator"""
        try:
            # Load sample data
            with open(self.sample_logs_file, 'r') as f:
                self.sample_data = json.load(f)
                
            # Create normalizer config
            config = NormalizationConfig(
                ecs_mapping_file=self.config_file,
                enable_geoip=False,  # Disable for testing
                enable_dns_lookup=False,  # Disable for testing
                enable_user_agent=True,
                drop_invalid_entries=False
            )
            
            # Initialize normalizer
            self.normalizer = LogNormalizer(config)
            await self.normalizer.initialize()
            
            logger.info("Validator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize validator: {e}")
            raise
            
    async def run_all_validations(self) -> ValidationSummary:
        """Run all validation tests"""
        logger.info("Starting comprehensive validation suite")
        start_time = time.time()
        
        # Run functional tests
        await self._run_format_parsing_tests()
        await self._run_field_mapping_tests()
        await self._run_data_type_conversion_tests()
        await self._run_validation_rule_tests()
        
        # Run performance tests
        await self._run_performance_tests()
        
        # Run compliance tests
        await self._run_ecs_compliance_tests()
        
        total_time = time.time() - start_time
        
        # Generate summary
        summary = self._generate_summary(total_time)
        
        logger.info(f"Validation completed in {total_time:.2f} seconds")
        logger.info(f"Success rate: {summary.success_rate:.1f}%")
        
        return summary
        
    async def _run_format_parsing_tests(self):
        """Test parsing of different log formats"""
        logger.info("Running format parsing tests")
        
        for scenario_name, scenario_data in self.sample_data["test_scenarios"].items():
            logger.info(f"Testing scenario: {scenario_name}")
            
            for i, log_entry in enumerate(scenario_data["logs"]):
                test_name = f"{scenario_name}_log_{i+1}"
                await self._validate_single_log(
                    test_name=test_name,
                    raw_log=log_entry["raw_log"],
                    log_format=log_entry["format"],
                    expected_fields=log_entry.get("expected_fields", {})
                )
                
    async def _run_field_mapping_tests(self):
        """Test ECS field mapping accuracy"""
        logger.info("Running field mapping tests")
        
        # Test specific field mappings
        test_cases = [
            {
                "name": "crowdstrike_field_mapping",
                "raw_log": '{"event_simpleName": "ProcessRollup2", "ComputerName": "TEST01", "UserName": "admin", "ProcessId": "1234"}',
                "format": "json",
                "expected_fields": {
                    "event.action": "ProcessRollup2",
                    "host.name": "TEST01",
                    "user.name": "admin",
                    "process.pid": 1234
                }
            },
            {
                "name": "okta_field_mapping",
                "raw_log": '{"eventType": "user.authentication.auth_via_mfa", "actor": {"alternateId": "test@example.com"}, "client": {"ipAddress": "192.168.1.100"}}',
                "format": "json",
                "expected_fields": {
                    "event.action": "user.authentication.auth_via_mfa",
                    "user.email": "test@example.com",
                    "source.ip": "192.168.1.100"
                }
            }
        ]
        
        for test_case in test_cases:
            await self._validate_single_log(
                test_name=test_case["name"],
                raw_log=test_case["raw_log"],
                log_format=test_case["format"],
                expected_fields=test_case["expected_fields"]
            )
            
    async def _run_data_type_conversion_tests(self):
        """Test data type conversions"""
        logger.info("Running data type conversion tests")
        
        test_cases = [
            {
                "name": "port_number_conversion",
                "raw_log": '{"source_port": "80", "destination_port": "443", "event_action": "connection"}',
                "format": "json",
                "expected_fields": {
                    "source.port": 80,
                    "destination.port": 443
                }
            },
            {
                "name": "severity_normalization",
                "raw_log": '{"severity": "high", "event_action": "alert"}',
                "format": "json",
                "expected_fields": {
                    "event.severity": 70
                }
            },
            {
                "name": "outcome_normalization",
                "raw_log": '{"result": "success", "event_action": "login"}',
                "format": "json",
                "expected_fields": {
                    "event.outcome": "success"
                }
            }
        ]
        
        for test_case in test_cases:
            await self._validate_single_log(
                test_name=test_case["name"],
                raw_log=test_case["raw_log"],
                log_format=test_case["format"],
                expected_fields=test_case["expected_fields"]
            )
            
    async def _run_validation_rule_tests(self):
        """Test validation rules"""
        logger.info("Running validation rule tests")
        
        # Test required fields validation
        await self._validate_single_log(
            test_name="missing_required_fields",
            raw_log='{"some_field": "value"}',  # Missing event.action
            log_format="json",
            expected_fields={},
            expect_validation_errors=True
        )
        
        # Test IP validation
        await self._validate_single_log(
            test_name="invalid_ip_address",
            raw_log='{"source_ip": "300.300.300.300", "event_action": "test"}',
            log_format="json",
            expected_fields={},
            expect_validation_errors=True
        )
        
    async def _run_performance_tests(self):
        """Test performance metrics"""
        logger.info("Running performance tests")
        
        # Test single log processing time
        test_log = '{"timestamp": "2024-01-15T10:30:00Z", "event_action": "test", "source_ip": "192.168.1.100"}'
        
        times = []
        for i in range(100):
            start_time = time.perf_counter()
            result = await self.normalizer.normalize_log(test_log, "json")
            end_time = time.perf_counter()
            
            if result:
                times.append((end_time - start_time) * 1000)  # Convert to milliseconds
                
        if times:
            avg_time = sum(times) / len(times)
            max_time = max(times)
            min_time = min(times)
            
            performance_result = ValidationResult(
                test_name="single_log_performance",
                log_format="json",
                success=avg_time < 100,  # Should be under 100ms
                processing_time_ms=avg_time,
                expected_fields={"avg_time_ms": "<100"},
                actual_fields={"avg_time_ms": avg_time, "max_time_ms": max_time, "min_time_ms": min_time},
                missing_fields=[],
                incorrect_fields=[],
                validation_errors=[]
            )
            
            self.results.append(performance_result)
            
        # Test batch processing
        test_logs = [test_log] * 1000
        start_time = time.perf_counter()
        batch_results = await self.normalizer.normalize_batch(test_logs)
        end_time = time.perf_counter()
        
        batch_time = (end_time - start_time) * 1000
        throughput = len(batch_results) / (batch_time / 1000)  # logs per second
        
        batch_performance_result = ValidationResult(
            test_name="batch_processing_performance",
            log_format="json",
            success=throughput >= 1000,  # Should process at least 1000 logs/sec
            processing_time_ms=batch_time,
            expected_fields={"throughput_logs_per_sec": ">=1000"},
            actual_fields={"throughput_logs_per_sec": throughput, "total_time_ms": batch_time},
            missing_fields=[],
            incorrect_fields=[],
            validation_errors=[]
        )
        
        self.results.append(batch_performance_result)
        
    async def _run_ecs_compliance_tests(self):
        """Test ECS compliance"""
        logger.info("Running ECS compliance tests")
        
        test_log = '{"timestamp": "2024-01-15T10:30:00Z", "event_action": "test", "source_ip": "192.168.1.100"}'
        result = await self.normalizer.normalize_log(test_log, "json")
        
        if result:
            # Check for required ECS fields
            required_ecs_fields = ["@timestamp", "ecs.version", "event.action"]
            missing_ecs_fields = []
            
            for field in required_ecs_fields:
                if field not in result.normalized_fields:
                    missing_ecs_fields.append(field)
                    
            # Check ECS version
            ecs_version_correct = result.ecs_version == "8.11.0"
            
            compliance_result = ValidationResult(
                test_name="ecs_compliance",
                log_format="json",
                success=len(missing_ecs_fields) == 0 and ecs_version_correct,
                processing_time_ms=0,
                expected_fields={"ecs.version": "8.11.0", "required_fields": required_ecs_fields},
                actual_fields={"ecs.version": result.ecs_version, "present_fields": list(result.normalized_fields.keys())},
                missing_fields=missing_ecs_fields,
                incorrect_fields=[],
                validation_errors=result.validation_errors
            )
            
            self.results.append(compliance_result)
            
    async def _validate_single_log(self, test_name: str, raw_log: str, log_format: str, 
                                 expected_fields: Dict[str, Any], expect_validation_errors: bool = False) -> ValidationResult:
        """Validate a single log entry"""
        start_time = time.perf_counter()
        
        try:
            result = await self.normalizer.normalize_log(raw_log, log_format)
            processing_time = (time.perf_counter() - start_time) * 1000
            
            if result is None:
                validation_result = ValidationResult(
                    test_name=test_name,
                    log_format=log_format,
                    success=False,
                    processing_time_ms=processing_time,
                    expected_fields=expected_fields,
                    actual_fields={},
                    missing_fields=list(expected_fields.keys()),
                    incorrect_fields=[],
                    validation_errors=[],
                    error_message="Normalization returned None"
                )
            else:
                # Check expected fields
                missing_fields = []
                incorrect_fields = []
                
                for field, expected_value in expected_fields.items():
                    if field not in result.normalized_fields:
                        missing_fields.append(field)
                    elif result.normalized_fields[field] != expected_value:
                        # For numeric fields, allow small differences
                        if isinstance(expected_value, (int, float)) and isinstance(result.normalized_fields[field], (int, float)):
                            if abs(result.normalized_fields[field] - expected_value) > 0.001:
                                incorrect_fields.append(field)
                        else:
                            incorrect_fields.append(field)
                            
                # Determine success
                success = (
                    len(missing_fields) == 0 and 
                    len(incorrect_fields) == 0 and
                    (not expect_validation_errors or len(result.validation_errors) > 0)
                )
                
                validation_result = ValidationResult(
                    test_name=test_name,
                    log_format=log_format,
                    success=success,
                    processing_time_ms=processing_time,
                    expected_fields=expected_fields,
                    actual_fields=result.normalized_fields,
                    missing_fields=missing_fields,
                    incorrect_fields=incorrect_fields,
                    validation_errors=result.validation_errors
                )
                
        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            validation_result = ValidationResult(
                test_name=test_name,
                log_format=log_format,
                success=False,
                processing_time_ms=processing_time,
                expected_fields=expected_fields,
                actual_fields={},
                missing_fields=list(expected_fields.keys()),
                incorrect_fields=[],
                validation_errors=[],
                error_message=str(e)
            )
            
        self.results.append(validation_result)
        return validation_result
        
    def _generate_summary(self, total_time: float) -> ValidationSummary:
        """Generate validation summary"""
        successful_tests = sum(1 for r in self.results if r.success)
        failed_tests = len(self.results) - successful_tests
        success_rate = (successful_tests / len(self.results)) * 100 if self.results else 0
        
        processing_times = [r.processing_time_ms for r in self.results if r.processing_time_ms > 0]
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        total_processing_time = sum(processing_times)
        
        # Calculate performance metrics
        performance_results = [r for r in self.results if "performance" in r.test_name]
        performance_metrics = {}
        
        for result in performance_results:
            if result.test_name == "single_log_performance":
                performance_metrics["avg_single_log_time_ms"] = result.actual_fields.get("avg_time_ms", 0)
                performance_metrics["max_single_log_time_ms"] = result.actual_fields.get("max_time_ms", 0)
            elif result.test_name == "batch_processing_performance":
                performance_metrics["throughput_logs_per_sec"] = result.actual_fields.get("throughput_logs_per_sec", 0)
                
        # Calculate compliance score
        compliance_tests = [r for r in self.results if "compliance" in r.test_name or "ecs" in r.test_name]
        compliance_score = (sum(1 for r in compliance_tests if r.success) / len(compliance_tests)) * 100 if compliance_tests else 100
        
        return ValidationSummary(
            total_tests=len(self.results),
            successful_tests=successful_tests,
            failed_tests=failed_tests,
            success_rate=success_rate,
            avg_processing_time_ms=avg_processing_time,
            total_processing_time_ms=total_processing_time,
            performance_metrics=performance_metrics,
            compliance_score=compliance_score
        )
        
    def generate_report(self, summary: ValidationSummary, output_file: str = None):
        """Generate detailed validation report"""
        report = {
            "validation_summary": asdict(summary),
            "test_results": [asdict(result) for result in self.results],
            "failed_tests": [asdict(result) for result in self.results if not result.success],
            "performance_analysis": self._analyze_performance(),
            "compliance_analysis": self._analyze_compliance(),
            "recommendations": self._generate_recommendations(),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Validation report saved to {output_file}")
        
        return report
        
    def _analyze_performance(self) -> Dict[str, Any]:
        """Analyze performance metrics"""
        processing_times = [r.processing_time_ms for r in self.results if r.processing_time_ms > 0]
        
        if not processing_times:
            return {"analysis": "No performance data available"}
            
        return {
            "total_logs_processed": len(processing_times),
            "avg_processing_time_ms": sum(processing_times) / len(processing_times),
            "min_processing_time_ms": min(processing_times),
            "max_processing_time_ms": max(processing_times),
            "percentile_95_ms": sorted(processing_times)[int(len(processing_times) * 0.95)],
            "logs_over_100ms": sum(1 for t in processing_times if t > 100),
            "performance_grade": "A" if max(processing_times) < 100 else "B" if max(processing_times) < 500 else "C"
        }
        
    def _analyze_compliance(self) -> Dict[str, Any]:
        """Analyze ECS compliance"""
        compliance_issues = []
        
        for result in self.results:
            if result.missing_fields:
                compliance_issues.append({
                    "test": result.test_name,
                    "issue": "missing_fields",
                    "fields": result.missing_fields
                })
                
            if result.incorrect_fields:
                compliance_issues.append({
                    "test": result.test_name,
                    "issue": "incorrect_fields",
                    "fields": result.incorrect_fields
                })
                
        return {
            "total_compliance_issues": len(compliance_issues),
            "compliance_issues": compliance_issues,
            "most_common_missing_fields": self._get_most_common_missing_fields(),
            "compliance_grade": "A" if len(compliance_issues) == 0 else "B" if len(compliance_issues) < 5 else "C"
        }
        
    def _get_most_common_missing_fields(self) -> List[Tuple[str, int]]:
        """Get most commonly missing fields"""
        field_counts = {}
        
        for result in self.results:
            for field in result.missing_fields:
                field_counts[field] = field_counts.get(field, 0) + 1
                
        return sorted(field_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on validation results"""
        recommendations = []
        
        # Performance recommendations
        slow_tests = [r for r in self.results if r.processing_time_ms > 100]
        if slow_tests:
            recommendations.append(f"Performance: {len(slow_tests)} tests took longer than 100ms. Consider optimizing log parsing for these formats: {set(r.log_format for r in slow_tests)}")
            
        # Compliance recommendations
        failed_tests = [r for r in self.results if not r.success]
        if failed_tests:
            recommendations.append(f"Compliance: {len(failed_tests)} tests failed. Review field mappings and validation rules.")
            
        # Missing fields recommendations
        common_missing_fields = self._get_most_common_missing_fields()
        if common_missing_fields:
            top_missing = common_missing_fields[0][0]
            recommendations.append(f"Field Mapping: '{top_missing}' is the most commonly missing field. Review ECS mapping configuration.")
            
        return recommendations
        
    async def cleanup(self):
        """Cleanup resources"""
        if self.normalizer:
            await self.normalizer.cleanup()

async def main():
    """Main validation script"""
    parser = argparse.ArgumentParser(description="Validate iSECTECH SIEM log normalization")
    parser.add_argument("--config", required=True, help="ECS mapping configuration file")
    parser.add_argument("--samples", required=True, help="Sample logs JSON file")
    parser.add_argument("--output", help="Output report file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    validator = LogNormalizationValidator(args.config, args.samples)
    
    try:
        await validator.initialize()
        summary = await validator.run_all_validations()
        
        # Generate report
        output_file = args.output or f"validation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report = validator.generate_report(summary, output_file)
        
        # Print summary to console
        print("\n" + "="*60)
        print("VALIDATION SUMMARY")
        print("="*60)
        print(f"Total Tests: {summary.total_tests}")
        print(f"Successful: {summary.successful_tests}")
        print(f"Failed: {summary.failed_tests}")
        print(f"Success Rate: {summary.success_rate:.1f}%")
        print(f"Average Processing Time: {summary.avg_processing_time_ms:.2f}ms")
        print(f"Compliance Score: {summary.compliance_score:.1f}%")
        print(f"Performance Grade: {report['performance_analysis']['performance_grade']}")
        print(f"Compliance Grade: {report['compliance_analysis']['compliance_grade']}")
        
        if summary.failed_tests > 0:
            print(f"\nFailed Tests:")
            for result in validator.results:
                if not result.success:
                    print(f"  - {result.test_name}: {result.error_message or 'Field validation failed'}")
                    
        print(f"\nDetailed report saved to: {output_file}")
        
        # Exit with error code if tests failed
        return 0 if summary.success_rate >= 95 else 1
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        traceback.print_exc()
        return 1
        
    finally:
        await validator.cleanup()

if __name__ == "__main__":
    exit_code = asyncio.run(main())