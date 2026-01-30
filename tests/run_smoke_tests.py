#!/usr/bin/env python3
"""
Comprehensive smoke test and readiness validation runner
Requirements: 11.6, 11.8, 11.10, 11.11, 11.14

This script runs all smoke tests and readiness validation tests for the OpsAgent Controller.
It can be used as part of CI/CD pipelines or manual deployment validation.
"""
import os
import sys
import json
import time
import argparse
import subprocess
from datetime import datetime
from typing import Dict, List, Tuple, Optional


class SmokeTestRunner:
    """Comprehensive smoke test runner for OpsAgent Controller"""
    
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.results = {
            "start_time": datetime.utcnow().isoformat(),
            "test_suites": {},
            "summary": {
                "total_tests": 0,
                "passed_tests": 0,
                "failed_tests": 0,
                "skipped_tests": 0
            }
        }
    
    def log(self, level: str, message: str):
        """Log message with timestamp"""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")
    
    def run_pytest_suite(self, test_file: str, suite_name: str, timeout: int = 300) -> Tuple[bool, str, str]:
        """Run a pytest suite and return results"""
        self.log("INFO", f"Running {suite_name} test suite...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            test_file,
            "-v",
            "--tb=short"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=os.path.dirname(os.path.abspath(__file__))
            )
            
            # Parse pytest output for basic statistics
            stdout_lines = result.stdout.split('\n')
            total_tests = 0
            passed_tests = 0
            failed_tests = 0
            skipped_tests = 0
            
            # Look for pytest summary line
            for line in stdout_lines:
                if "passed" in line and "failed" in line:
                    # Parse line like "2 failed, 3 passed in 1.23s"
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "passed" and i > 0:
                            passed_tests = int(parts[i-1])
                        elif part == "failed" and i > 0:
                            failed_tests = int(parts[i-1])
                        elif part == "skipped" and i > 0:
                            skipped_tests = int(parts[i-1])
                elif "passed in" in line:
                    # Parse line like "5 passed in 1.23s"
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "passed" and i > 0:
                            passed_tests = int(parts[i-1])
                elif "failed in" in line:
                    # Parse line like "2 failed in 1.23s"
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == "failed" and i > 0:
                            failed_tests = int(parts[i-1])
            
            total_tests = passed_tests + failed_tests + skipped_tests
            
            self.results["test_suites"][suite_name] = {
                "status": "passed" if result.returncode == 0 else "failed",
                "return_code": result.returncode,
                "total": total_tests,
                "passed": passed_tests,
                "failed": failed_tests,
                "skipped": skipped_tests,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
            
            # Update summary
            self.results["summary"]["total_tests"] += total_tests
            self.results["summary"]["passed_tests"] += passed_tests
            self.results["summary"]["failed_tests"] += failed_tests
            self.results["summary"]["skipped_tests"] += skipped_tests
            
            return result.returncode == 0, result.stdout, result.stderr
            
        except subprocess.TimeoutExpired:
            self.log("ERROR", f"{suite_name} test suite timed out after {timeout} seconds")
            self.results["test_suites"][suite_name] = {
                "status": "timeout",
                "return_code": -1,
                "error": f"Timeout after {timeout} seconds"
            }
            return False, "", f"Timeout after {timeout} seconds"
        except Exception as e:
            self.log("ERROR", f"Failed to run {suite_name} test suite: {e}")
            self.results["test_suites"][suite_name] = {
                "status": "error",
                "return_code": -1,
                "error": str(e)
            }
            return False, "", str(e)
    
    def check_prerequisites(self) -> bool:
        """Check that all prerequisites are met"""
        self.log("INFO", "Checking prerequisites...")
        
        # Check Python and pytest
        try:
            result = subprocess.run([sys.executable, "-m", "pytest", "--version"], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                self.log("ERROR", "pytest is not available")
                return False
        except Exception as e:
            self.log("ERROR", f"Failed to check pytest: {e}")
            return False
        
        # Check required Python packages
        required_packages = ["boto3", "requests", "hypothesis"]
        for package in required_packages:
            try:
                __import__(package)
            except ImportError:
                self.log("ERROR", f"Required package {package} is not installed")
                return False
        
        self.log("INFO", "Prerequisites check passed")
        return True
    
    def validate_configuration(self) -> bool:
        """Validate configuration for readiness tests"""
        self.log("INFO", "Validating configuration...")
        
        required_for_readiness = ["CHAT_ENDPOINT", "HEALTH_ENDPOINT"]
        missing_config = []
        
        for key in required_for_readiness:
            if not self.config.get(key):
                missing_config.append(key)
        
        if missing_config:
            self.log("WARN", f"Missing configuration for readiness tests: {missing_config}")
            self.log("WARN", "Readiness tests may be skipped")
        
        # Check AWS credentials for AWS-dependent tests
        try:
            import boto3
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            self.log("INFO", f"AWS credentials available for account: {identity.get('Account')}")
        except Exception as e:
            self.log("WARN", f"AWS credentials not available: {e}")
            self.log("WARN", "Some tests may be skipped")
        
        return True
    
    def run_infrastructure_smoke_tests(self) -> bool:
        """Run infrastructure smoke tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING INFRASTRUCTURE SMOKE TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_smoke_tests.py::TestInfrastructureSmokeTests",
            "infrastructure_smoke",
            timeout=180
        )
        
        if success:
            self.log("INFO", "✅ Infrastructure smoke tests PASSED")
        else:
            self.log("ERROR", "❌ Infrastructure smoke tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_infrastructure_provisioning_tests(self) -> bool:
        """Run infrastructure provisioning validation tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING INFRASTRUCTURE PROVISIONING TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_infrastructure_provisioning.py",
            "infrastructure_provisioning",
            timeout=300
        )
        
        if success:
            self.log("INFO", "✅ Infrastructure provisioning tests PASSED")
        else:
            self.log("ERROR", "❌ Infrastructure provisioning tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_plugin_operations_validation_tests(self) -> bool:
        """Run plugin operations validation tests for all 8 operations"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING PLUGIN OPERATIONS VALIDATION TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_plugin_operations.py",
            "plugin_operations",
            timeout=240
        )
        
        if success:
            self.log("INFO", "✅ Plugin operations validation tests PASSED")
        else:
            self.log("ERROR", "❌ Plugin operations validation tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_end_to_end_workflow_tests(self) -> bool:
        """Run end-to-end approval workflow tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING END-TO-END WORKFLOW TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_integration.py::TestSystemIntegration::test_end_to_end_remediation_flow",
            "end_to_end_workflow",
            timeout=180
        )
        
        if success:
            self.log("INFO", "✅ End-to-end workflow tests PASSED")
        else:
            self.log("ERROR", "❌ End-to-end workflow tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_monitoring_integration_tests(self) -> bool:
        """Run monitoring and integration tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING MONITORING INTEGRATION TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_infrastructure_provisioning.py::TestInfrastructurePerformance",
            "monitoring_integration",
            timeout=300
        )
        
        if success:
            self.log("INFO", "✅ Monitoring integration tests PASSED")
        else:
            self.log("ERROR", "❌ Monitoring integration tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_diagnosis_tools_tests(self) -> bool:
        """Run diagnosis tools validation tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING DIAGNOSIS TOOLS VALIDATION TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_smoke_tests.py::TestDiagnosisToolValidation",
            "diagnosis_tools",
            timeout=240
        )
        
        if success:
            self.log("INFO", "✅ Diagnosis tools validation tests PASSED")
        else:
            self.log("ERROR", "❌ Diagnosis tools validation tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_approval_gate_tests(self) -> bool:
        """Run approval gate and remediation tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING APPROVAL GATE AND REMEDIATION TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_smoke_tests.py::TestApprovalGateAndRemediationTesting",
            "approval_gate",
            timeout=300
        )
        
        if success:
            self.log("INFO", "✅ Approval gate and remediation tests PASSED")
        else:
            self.log("ERROR", "❌ Approval gate and remediation tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_audit_logging_tests(self) -> bool:
        """Run audit logging verification tests"""
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING AUDIT LOGGING VERIFICATION TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_smoke_tests.py::TestAuditLoggingVerification",
            "audit_logging",
            timeout=180
        )
        
        if success:
            self.log("INFO", "✅ Audit logging verification tests PASSED")
        else:
            self.log("ERROR", "❌ Audit logging verification tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_deployed_readiness_tests(self) -> bool:
        """Run readiness tests against deployed infrastructure"""
        if not self.config.get("CHAT_ENDPOINT") or not self.config.get("HEALTH_ENDPOINT"):
            self.log("WARN", "Skipping deployed readiness tests - endpoints not configured")
            return True
        
        self.log("INFO", "=" * 60)
        self.log("INFO", "RUNNING DEPLOYED INFRASTRUCTURE READINESS TESTS")
        self.log("INFO", "=" * 60)
        
        success, stdout, stderr = self.run_pytest_suite(
            "test_readiness_validation.py",
            "deployed_readiness",
            timeout=600
        )
        
        if success:
            self.log("INFO", "✅ Deployed readiness tests PASSED")
        else:
            self.log("ERROR", "❌ Deployed readiness tests FAILED")
            if stderr:
                self.log("ERROR", f"Error output: {stderr}")
        
        return success
    
    def run_all_tests(self) -> bool:
        """Run all smoke tests and readiness validation"""
        self.log("INFO", "🚀 Starting comprehensive smoke tests and readiness validation")
        self.log("INFO", f"Configuration: {json.dumps(self.config, indent=2)}")
        
        if not self.check_prerequisites():
            return False
        
        if not self.validate_configuration():
            return False
        
        # Run all test suites
        test_suites = [
            ("Infrastructure Smoke Tests", self.run_infrastructure_smoke_tests),
            ("Infrastructure Provisioning Tests", self.run_infrastructure_provisioning_tests),
            ("Plugin Operations Validation Tests", self.run_plugin_operations_validation_tests),
            ("Diagnosis Tools Tests", self.run_diagnosis_tools_tests),
            ("Approval Gate Tests", self.run_approval_gate_tests),
            ("End-to-End Workflow Tests", self.run_end_to_end_workflow_tests),
            ("Audit Logging Tests", self.run_audit_logging_tests),
            ("Monitoring Integration Tests", self.run_monitoring_integration_tests),
            ("Deployed Readiness Tests", self.run_deployed_readiness_tests)
        ]
        
        all_passed = True
        
        for suite_name, test_func in test_suites:
            try:
                success = test_func()
                if not success:
                    all_passed = False
            except Exception as e:
                self.log("ERROR", f"Failed to run {suite_name}: {e}")
                all_passed = False
            
            # Small delay between test suites
            time.sleep(2)
        
        return all_passed
    
    def generate_report(self) -> str:
        """Generate comprehensive test report"""
        self.results["end_time"] = datetime.utcnow().isoformat()
        
        # Calculate total duration
        start_time = datetime.fromisoformat(self.results["start_time"])
        end_time = datetime.fromisoformat(self.results["end_time"])
        total_duration = (end_time - start_time).total_seconds()
        
        self.results["total_duration_seconds"] = total_duration
        
        # Generate summary
        summary = self.results["summary"]
        
        report = f"""
OpsAgent Controller Smoke Tests and Readiness Validation Report
================================================================

Execution Summary:
- Start Time: {self.results['start_time']}
- End Time: {self.results['end_time']}
- Total Duration: {total_duration:.2f} seconds
- Total Tests: {summary['total_tests']}
- Passed: {summary['passed_tests']}
- Failed: {summary['failed_tests']}
- Skipped: {summary['skipped_tests']}

Test Suite Results:
"""
        
        for suite_name, suite_result in self.results["test_suites"].items():
            status_emoji = {
                "passed": "✅",
                "failed": "❌",
                "timeout": "⏰",
                "error": "💥"
            }.get(suite_result["status"], "❓")
            
            report += f"\n{status_emoji} {suite_name.replace('_', ' ').title()}: {suite_result['status'].upper()}"
            
            if "total" in suite_result:
                report += f" ({suite_result['passed']}/{suite_result['total']} tests passed)"
            
            if "duration" in suite_result:
                report += f" - {suite_result['duration']:.2f}s"
        
        # Overall result
        overall_status = "PASSED" if summary["failed_tests"] == 0 else "FAILED"
        status_emoji = "✅" if overall_status == "PASSED" else "❌"
        
        report += f"""

Overall Result: {status_emoji} {overall_status}

Configuration Used:
{json.dumps(self.config, indent=2)}
"""
        
        return report
    
    def save_report(self, filename: str):
        """Save detailed JSON report"""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        
        self.log("INFO", f"Detailed report saved to: {filename}")


def get_configuration() -> Dict[str, str]:
    """Get configuration from environment variables and CloudFormation"""
    config = {
        "EXECUTION_MODE": os.environ.get("EXECUTION_MODE", "LOCAL_MOCK"),
        "ENVIRONMENT": os.environ.get("ENVIRONMENT", "sandbox"),
        "AWS_REGION": os.environ.get("AWS_REGION", "us-east-1"),
        "HEALTH_ENDPOINT": os.environ.get("HEALTH_ENDPOINT"),
        "CHAT_ENDPOINT": os.environ.get("CHAT_ENDPOINT"),
        "API_KEY": os.environ.get("API_KEY"),
        "TEST_INSTANCE_ID": os.environ.get("TEST_INSTANCE_ID"),
        "AUDIT_LOG_GROUP": os.environ.get("AUDIT_LOG_GROUP"),
        "AUDIT_TABLE": os.environ.get("AUDIT_TABLE"),
        "STACK_NAME": os.environ.get("STACK_NAME")
    }
    
    # Try to get missing values from CloudFormation
    if not config["STACK_NAME"]:
        config["STACK_NAME"] = f"opsagent-controller-{config['ENVIRONMENT']}"
    
    try:
        import boto3
        cf_client = boto3.client('cloudformation', region_name=config["AWS_REGION"])
        response = cf_client.describe_stacks(StackName=config["STACK_NAME"])
        
        if response["Stacks"]:
            outputs = response["Stacks"][0].get("Outputs", [])
            output_map = {output["OutputKey"]: output["OutputValue"] for output in outputs}
            
            # Map CloudFormation outputs to config
            cf_mappings = {
                "HealthEndpoint": "HEALTH_ENDPOINT",
                "ChatEndpoint": "CHAT_ENDPOINT",
                "TestInstanceId": "TEST_INSTANCE_ID",
                "AuditLogGroupName": "AUDIT_LOG_GROUP",
                "AuditTableName": "AUDIT_TABLE"
            }
            
            for cf_key, config_key in cf_mappings.items():
                if cf_key in output_map and not config[config_key]:
                    config[config_key] = output_map[cf_key]
    
    except Exception as e:
        print(f"Warning: Could not get CloudFormation outputs: {e}")
    
    # Try to get API key from SSM
    if not config["API_KEY"]:
        try:
            import boto3
            ssm_client = boto3.client('ssm', region_name=config["AWS_REGION"])
            param_name = f"/opsagent/{config['ENVIRONMENT']}/api-key"
            response = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
            config["API_KEY"] = response["Parameter"]["Value"]
        except Exception:
            pass
    
    # Remove None values
    return {k: v for k, v in config.items() if v is not None}


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Run OpsAgent Controller smoke tests and readiness validation"
    )
    parser.add_argument(
        "--suite",
        choices=["all", "smoke", "readiness", "infrastructure", "diagnosis", "approval", "audit"],
        default="all",
        help="Test suite to run"
    )
    parser.add_argument(
        "--report-file",
        default="smoke_test_report.json",
        help="JSON report output file"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Get configuration
    config = get_configuration()
    
    # Create test runner
    runner = SmokeTestRunner(config)
    
    # Run tests based on suite selection
    if args.suite == "all":
        success = runner.run_all_tests()
    elif args.suite == "smoke":
        success = (
            runner.run_infrastructure_smoke_tests() and
            runner.run_diagnosis_tools_tests() and
            runner.run_approval_gate_tests() and
            runner.run_audit_logging_tests()
        )
    elif args.suite == "readiness":
        success = runner.run_deployed_readiness_tests()
    elif args.suite == "infrastructure":
        success = runner.run_infrastructure_smoke_tests()
    elif args.suite == "diagnosis":
        success = runner.run_diagnosis_tools_tests()
    elif args.suite == "approval":
        success = runner.run_approval_gate_tests()
    elif args.suite == "audit":
        success = runner.run_audit_logging_tests()
    else:
        runner.log("ERROR", f"Unknown test suite: {args.suite}")
        return 1
    
    # Generate and display report
    report = runner.generate_report()
    print("\n" + "=" * 80)
    print(report)
    print("=" * 80)
    
    # Save detailed report
    runner.save_report(args.report_file)
    
    # Return appropriate exit code
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())