#!/usr/bin/env python3
"""
OpsAgent Controller Live Environment Validation Script
Requirements: 13.1, 13.2

This script validates the live environment deployment and performs comprehensive
readiness checks for all OpsAgent Controller components.
"""
import os
import sys
import json
import time
import boto3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class ValidationResult:
    """Result of a validation check"""
    name: str
    status: str  # PASS, FAIL, WARN, SKIP
    message: str
    details: Optional[Dict[str, Any]] = None
    duration_ms: Optional[int] = None


class LiveEnvironmentValidator:
    """Comprehensive live environment validation for OpsAgent Controller"""
    
    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.results: List[ValidationResult] = []
        self.aws_session = boto3.Session(region_name=config.get('AWS_REGION', 'us-east-1'))
        
        # Initialize AWS clients
        self.cloudformation = self.aws_session.client('cloudformation')
        self.lambda_client = self.aws_session.client('lambda')
        self.dynamodb = self.aws_session.client('dynamodb')
        self.logs = self.aws_session.client('logs')
        self.ssm = self.aws_session.client('ssm')
        self.apigateway = self.aws_session.client('apigateway')
        self.sts = self.aws_session.client('sts')
    
    def log(self, level: str, message: str):
        """Log message with timestamp"""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        colors = {
            'INFO': '\033[0;32m',
            'WARN': '\033[1;33m', 
            'ERROR': '\033[0;31m',
            'DEBUG': '\033[0;34m'
        }
        color = colors.get(level, '')
        reset = '\033[0m'
        print(f"{color}[{level}]{reset} [{timestamp}] {message}")
    
    def add_result(self, name: str, status: str, message: str, 
                   details: Optional[Dict[str, Any]] = None, 
                   duration_ms: Optional[int] = None):
        """Add validation result"""
        result = ValidationResult(name, status, message, details, duration_ms)
        self.results.append(result)
        
        # Log result
        emoji = {'PASS': '✅', 'FAIL': '❌', 'WARN': '⚠️', 'SKIP': '⏭️'}
        self.log('INFO', f"{emoji.get(status, '❓')} {name}: {message}")
        
        if details and status in ['FAIL', 'WARN']:
            self.log('DEBUG', f"Details: {json.dumps(details, indent=2)}")
    
    def timed_check(self, func, *args, **kwargs) -> Tuple[Any, int]:
        """Execute function and measure duration"""
        start_time = time.time()
        result = func(*args, **kwargs)
        duration_ms = int((time.time() - start_time) * 1000)
        return result, duration_ms
    
    def validate_aws_credentials(self) -> bool:
        """Validate AWS credentials and permissions"""
        try:
            start_time = time.time()
            identity = self.sts.get_caller_identity()
            duration_ms = int((time.time() - start_time) * 1000)
            
            account_id = identity.get('Account')
            user_arn = identity.get('Arn', 'Unknown')
            
            self.add_result(
                "AWS Credentials",
                "PASS",
                f"Valid credentials for account {account_id}",
                {"account_id": account_id, "user_arn": user_arn},
                duration_ms
            )
            return True
            
        except Exception as e:
            self.add_result(
                "AWS Credentials",
                "FAIL",
                f"Invalid AWS credentials: {str(e)}"
            )
            return False
    
    def validate_cloudformation_stack(self) -> bool:
        """Validate CloudFormation stack exists and is in good state"""
        stack_name = self.config.get('STACK_NAME')
        if not stack_name:
            self.add_result(
                "CloudFormation Stack",
                "SKIP",
                "Stack name not configured"
            )
            return False
        
        try:
            start_time = time.time()
            response = self.cloudformation.describe_stacks(StackName=stack_name)
            duration_ms = int((time.time() - start_time) * 1000)
            
            if not response['Stacks']:
                self.add_result(
                    "CloudFormation Stack",
                    "FAIL",
                    f"Stack {stack_name} not found"
                )
                return False
            
            stack = response['Stacks'][0]
            status = stack['StackStatus']
            
            if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                # Get stack outputs
                outputs = {output['OutputKey']: output['OutputValue'] 
                          for output in stack.get('Outputs', [])}
                
                self.add_result(
                    "CloudFormation Stack",
                    "PASS",
                    f"Stack {stack_name} is {status}",
                    {"status": status, "outputs": list(outputs.keys())},
                    duration_ms
                )
                
                # Update config with stack outputs
                self.config.update(outputs)
                return True
            else:
                self.add_result(
                    "CloudFormation Stack",
                    "FAIL",
                    f"Stack {stack_name} is in {status} state"
                )
                return False
                
        except Exception as e:
            self.add_result(
                "CloudFormation Stack",
                "FAIL",
                f"Error checking stack: {str(e)}"
            )
            return False
    
    def validate_lambda_function(self) -> bool:
        """Validate Lambda function exists and is configured correctly"""
        function_name = self.config.get('LambdaFunctionName')
        if not function_name:
            self.add_result(
                "Lambda Function",
                "SKIP",
                "Function name not available"
            )
            return False
        
        try:
            start_time = time.time()
            response = self.lambda_client.get_function(FunctionName=function_name)
            duration_ms = int((time.time() - start_time) * 1000)
            
            config_info = response['Configuration']
            state = config_info['State']
            
            if state == 'Active':
                details = {
                    "runtime": config_info['Runtime'],
                    "memory_size": config_info['MemorySize'],
                    "timeout": config_info['Timeout'],
                    "last_modified": config_info['LastModified']
                }
                
                self.add_result(
                    "Lambda Function",
                    "PASS",
                    f"Function {function_name} is active",
                    details,
                    duration_ms
                )
                return True
            else:
                self.add_result(
                    "Lambda Function",
                    "FAIL",
                    f"Function {function_name} is in {state} state"
                )
                return False
                
        except Exception as e:
            self.add_result(
                "Lambda Function",
                "FAIL",
                f"Error checking function: {str(e)}"
            )
            return False
    
    def validate_dynamodb_tables(self) -> bool:
        """Validate DynamoDB tables exist and are active"""
        tables = {
            'Audit Table': self.config.get('AuditTableName'),
            'Incident Table': self.config.get('IncidentTableName')
        }
        
        all_valid = True
        
        for table_type, table_name in tables.items():
            if not table_name:
                self.add_result(
                    f"DynamoDB {table_type}",
                    "SKIP",
                    f"{table_type} name not configured"
                )
                continue
            
            try:
                start_time = time.time()
                response = self.dynamodb.describe_table(TableName=table_name)
                duration_ms = int((time.time() - start_time) * 1000)
                
                table_info = response['Table']
                status = table_info['TableStatus']
                
                if status == 'ACTIVE':
                    details = {
                        "item_count": table_info.get('ItemCount', 0),
                        "table_size_bytes": table_info.get('TableSizeBytes', 0),
                        "billing_mode": table_info.get('BillingModeSummary', {}).get('BillingMode', 'Unknown')
                    }
                    
                    self.add_result(
                        f"DynamoDB {table_type}",
                        "PASS",
                        f"Table {table_name} is active",
                        details,
                        duration_ms
                    )
                else:
                    self.add_result(
                        f"DynamoDB {table_type}",
                        "FAIL",
                        f"Table {table_name} is {status}"
                    )
                    all_valid = False
                    
            except Exception as e:
                self.add_result(
                    f"DynamoDB {table_type}",
                    "FAIL",
                    f"Error checking table: {str(e)}"
                )
                all_valid = False
        
        return all_valid
    
    def validate_cloudwatch_logs(self) -> bool:
        """Validate CloudWatch log groups exist"""
        log_group = self.config.get('AuditLogGroupName')
        if not log_group:
            self.add_result(
                "CloudWatch Logs",
                "SKIP",
                "Log group name not configured"
            )
            return False
        
        try:
            start_time = time.time()
            response = self.logs.describe_log_groups(logGroupNamePrefix=log_group)
            duration_ms = int((time.time() - start_time) * 1000)
            
            matching_groups = [lg for lg in response['logGroups'] if lg['logGroupName'] == log_group]
            
            if matching_groups:
                log_group_info = matching_groups[0]
                details = {
                    "retention_days": log_group_info.get('retentionInDays', 'Never expire'),
                    "stored_bytes": log_group_info.get('storedBytes', 0),
                    "creation_time": log_group_info.get('creationTime', 0)
                }
                
                self.add_result(
                    "CloudWatch Logs",
                    "PASS",
                    f"Log group {log_group} exists",
                    details,
                    duration_ms
                )
                return True
            else:
                self.add_result(
                    "CloudWatch Logs",
                    "FAIL",
                    f"Log group {log_group} not found"
                )
                return False
                
        except Exception as e:
            self.add_result(
                "CloudWatch Logs",
                "FAIL",
                f"Error checking log group: {str(e)}"
            )
            return False
    
    def validate_ssm_parameters(self) -> bool:
        """Validate SSM parameters exist"""
        parameters = {
            'API Key': self.config.get('ApiKeyParameterName', '/opsagent/api-key'),
            'Plugin API Key': f"/opsagent/plugin-api-key-{self.config.get('ENVIRONMENT', 'sandbox')}"
        }
        
        all_valid = True
        
        for param_type, param_name in parameters.items():
            try:
                start_time = time.time()
                response = self.ssm.get_parameter(Name=param_name)
                duration_ms = int((time.time() - start_time) * 1000)
                
                param_info = response['Parameter']
                details = {
                    "type": param_info['Type'],
                    "last_modified": param_info.get('LastModifiedDate', '').isoformat() if param_info.get('LastModifiedDate') else 'Unknown',
                    "version": param_info.get('Version', 0)
                }
                
                self.add_result(
                    f"SSM {param_type}",
                    "PASS",
                    f"Parameter {param_name} exists",
                    details,
                    duration_ms
                )
                
            except self.ssm.exceptions.ParameterNotFound:
                self.add_result(
                    f"SSM {param_type}",
                    "FAIL",
                    f"Parameter {param_name} not found"
                )
                all_valid = False
            except Exception as e:
                self.add_result(
                    f"SSM {param_type}",
                    "FAIL",
                    f"Error checking parameter: {str(e)}"
                )
                all_valid = False
        
        return all_valid
    
    def validate_api_gateway(self) -> bool:
        """Validate API Gateway is accessible"""
        health_endpoint = self.config.get('HealthEndpointUrl')
        if not health_endpoint:
            self.add_result(
                "API Gateway Health",
                "SKIP",
                "Health endpoint not configured"
            )
            return False
        
        try:
            start_time = time.time()
            response = requests.get(health_endpoint, timeout=30)
            duration_ms = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    status = data.get('data', {}).get('status', 'unknown')
                    
                    if status == 'healthy':
                        details = {
                            "response_time_ms": duration_ms,
                            "status_code": response.status_code,
                            "execution_mode": data.get('data', {}).get('execution_mode', 'unknown')
                        }
                        
                        self.add_result(
                            "API Gateway Health",
                            "PASS",
                            "Health endpoint is healthy",
                            details,
                            duration_ms
                        )
                        return True
                    else:
                        self.add_result(
                            "API Gateway Health",
                            "FAIL",
                            f"Health endpoint returned status: {status}"
                        )
                        return False
                        
                except json.JSONDecodeError:
                    self.add_result(
                        "API Gateway Health",
                        "FAIL",
                        "Health endpoint returned invalid JSON"
                    )
                    return False
            else:
                self.add_result(
                    "API Gateway Health",
                    "FAIL",
                    f"Health endpoint returned HTTP {response.status_code}"
                )
                return False
                
        except requests.RequestException as e:
            self.add_result(
                "API Gateway Health",
                "FAIL",
                f"Error accessing health endpoint: {str(e)}"
            )
            return False
    
    def validate_plugin_operations(self) -> bool:
        """Validate plugin operations are working"""
        chat_endpoint = self.config.get('ChatEndpointUrl', '').replace('/chat', '/operations/diagnostic')
        api_key = self.config.get('API_KEY')
        
        if not chat_endpoint or not api_key:
            self.add_result(
                "Plugin Operations",
                "SKIP",
                "Chat endpoint or API key not configured"
            )
            return False
        
        # Test a simple diagnostic operation
        payload = {
            "operation": "get_ec2_status",
            "parameters": {"instance_id": "i-nonexistent"},
            "user_context": {"user_id": "validation@test.com"}
        }
        
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": api_key
        }
        
        try:
            start_time = time.time()
            response = requests.post(chat_endpoint, json=payload, headers=headers, timeout=30)
            duration_ms = int((time.time() - start_time) * 1000)
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    success = data.get('success', False)
                    
                    # For non-existent resources, we expect success=False but proper error handling
                    if 'error' in data or 'message' in data:
                        details = {
                            "response_time_ms": duration_ms,
                            "status_code": response.status_code,
                            "operation_handled": True
                        }
                        
                        self.add_result(
                            "Plugin Operations",
                            "PASS",
                            "Plugin operations are responding correctly",
                            details,
                            duration_ms
                        )
                        return True
                    else:
                        self.add_result(
                            "Plugin Operations",
                            "FAIL",
                            "Plugin operations returned unexpected response format"
                        )
                        return False
                        
                except json.JSONDecodeError:
                    self.add_result(
                        "Plugin Operations",
                        "FAIL",
                        "Plugin operations returned invalid JSON"
                    )
                    return False
            else:
                self.add_result(
                    "Plugin Operations",
                    "FAIL",
                    f"Plugin operations returned HTTP {response.status_code}"
                )
                return False
                
        except requests.RequestException as e:
            self.add_result(
                "Plugin Operations",
                "FAIL",
                f"Error testing plugin operations: {str(e)}"
            )
            return False
    
    def validate_test_resources(self) -> bool:
        """Validate test resources are available"""
        test_instance_id = self.config.get('TestInstanceId')
        if not test_instance_id:
            self.add_result(
                "Test Resources",
                "SKIP",
                "Test instance ID not configured"
            )
            return True  # Not required for validation
        
        try:
            ec2 = self.aws_session.client('ec2')
            start_time = time.time()
            response = ec2.describe_instances(InstanceIds=[test_instance_id])
            duration_ms = int((time.time() - start_time) * 1000)
            
            if response['Reservations']:
                instance = response['Reservations'][0]['Instances'][0]
                state = instance['State']['Name']
                
                details = {
                    "instance_type": instance['InstanceType'],
                    "state": state,
                    "launch_time": instance.get('LaunchTime', '').isoformat() if instance.get('LaunchTime') else 'Unknown'
                }
                
                if state in ['running', 'stopped']:
                    self.add_result(
                        "Test Resources",
                        "PASS",
                        f"Test instance {test_instance_id} is {state}",
                        details,
                        duration_ms
                    )
                    return True
                else:
                    self.add_result(
                        "Test Resources",
                        "WARN",
                        f"Test instance {test_instance_id} is {state}",
                        details,
                        duration_ms
                    )
                    return True  # Not a failure, just a warning
            else:
                self.add_result(
                    "Test Resources",
                    "FAIL",
                    f"Test instance {test_instance_id} not found"
                )
                return False
                
        except Exception as e:
            self.add_result(
                "Test Resources",
                "FAIL",
                f"Error checking test resources: {str(e)}"
            )
            return False
    
    def validate_security_configuration(self) -> bool:
        """Validate security configuration"""
        checks_passed = 0
        total_checks = 0
        
        # Check KMS key
        kms_key_id = self.config.get('KMSKeyId')
        if kms_key_id:
            total_checks += 1
            try:
                kms = self.aws_session.client('kms')
                response = kms.describe_key(KeyId=kms_key_id)
                
                if response['KeyMetadata']['KeyState'] == 'Enabled':
                    checks_passed += 1
                    self.add_result(
                        "KMS Key",
                        "PASS",
                        f"KMS key {kms_key_id} is enabled"
                    )
                else:
                    self.add_result(
                        "KMS Key",
                        "FAIL",
                        f"KMS key {kms_key_id} is not enabled"
                    )
            except Exception as e:
                self.add_result(
                    "KMS Key",
                    "FAIL",
                    f"Error checking KMS key: {str(e)}"
                )
        
        # Check execution mode
        total_checks += 1
        execution_mode = self.config.get('EXECUTION_MODE', 'unknown')
        if execution_mode in ['SANDBOX_LIVE', 'DRY_RUN']:
            checks_passed += 1
            self.add_result(
                "Execution Mode",
                "PASS",
                f"Execution mode is {execution_mode}"
            )
        else:
            self.add_result(
                "Execution Mode",
                "WARN",
                f"Execution mode is {execution_mode} (consider SANDBOX_LIVE for testing)"
            )
        
        return checks_passed == total_checks
    
    def run_all_validations(self) -> bool:
        """Run all validation checks"""
        self.log('INFO', "🔍 Starting comprehensive live environment validation")
        
        validations = [
            ("AWS Credentials", self.validate_aws_credentials),
            ("CloudFormation Stack", self.validate_cloudformation_stack),
            ("Lambda Function", self.validate_lambda_function),
            ("DynamoDB Tables", self.validate_dynamodb_tables),
            ("CloudWatch Logs", self.validate_cloudwatch_logs),
            ("SSM Parameters", self.validate_ssm_parameters),
            ("API Gateway Health", self.validate_api_gateway),
            ("Plugin Operations", self.validate_plugin_operations),
            ("Test Resources", self.validate_test_resources),
            ("Security Configuration", self.validate_security_configuration)
        ]
        
        all_critical_passed = True
        
        for validation_name, validation_func in validations:
            self.log('INFO', f"Validating {validation_name}...")
            try:
                result = validation_func()
                # Consider FAIL as critical, WARN as non-critical
                if not result and validation_name not in ["Test Resources"]:
                    all_critical_passed = False
            except Exception as e:
                self.log('ERROR', f"Validation {validation_name} failed with exception: {e}")
                self.add_result(validation_name, "FAIL", f"Exception: {str(e)}")
                all_critical_passed = False
        
        return all_critical_passed
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive validation report"""
        summary = {
            'total_checks': len(self.results),
            'passed': len([r for r in self.results if r.status == 'PASS']),
            'failed': len([r for r in self.results if r.status == 'FAIL']),
            'warnings': len([r for r in self.results if r.status == 'WARN']),
            'skipped': len([r for r in self.results if r.status == 'SKIP'])
        }
        
        report = {
            'validation_timestamp': datetime.utcnow().isoformat(),
            'environment': self.config.get('ENVIRONMENT', 'unknown'),
            'region': self.config.get('AWS_REGION', 'unknown'),
            'stack_name': self.config.get('STACK_NAME', 'unknown'),
            'summary': summary,
            'results': [asdict(result) for result in self.results],
            'configuration': {k: v for k, v in self.config.items() if 'KEY' not in k.upper()}
        }
        
        return report
    
    def print_summary(self):
        """Print validation summary"""
        summary = {
            'PASS': len([r for r in self.results if r.status == 'PASS']),
            'FAIL': len([r for r in self.results if r.status == 'FAIL']),
            'WARN': len([r for r in self.results if r.status == 'WARN']),
            'SKIP': len([r for r in self.results if r.status == 'SKIP'])
        }
        
        total = sum(summary.values())
        
        self.log('INFO', "")
        self.log('INFO', "🎯 Validation Summary")
        self.log('INFO', "===================")
        self.log('INFO', f"Total Checks: {total}")
        self.log('INFO', f"✅ Passed: {summary['PASS']}")
        self.log('INFO', f"❌ Failed: {summary['FAIL']}")
        self.log('INFO', f"⚠️  Warnings: {summary['WARN']}")
        self.log('INFO', f"⏭️  Skipped: {summary['SKIP']}")
        
        success_rate = (summary['PASS'] / total * 100) if total > 0 else 0
        self.log('INFO', f"Success Rate: {success_rate:.1f}%")
        
        if summary['FAIL'] == 0:
            self.log('INFO', "🎉 Environment validation PASSED! System is ready.")
        else:
            self.log('ERROR', "❌ Environment validation FAILED. Please fix issues before proceeding.")


def get_configuration() -> Dict[str, str]:
    """Get configuration from environment and CloudFormation"""
    config = {
        'ENVIRONMENT': os.environ.get('ENVIRONMENT', 'test'),
        'AWS_REGION': os.environ.get('AWS_REGION', 'us-west-2'),
        'STACK_NAME': os.environ.get('STACK_NAME'),
        'EXECUTION_MODE': os.environ.get('EXECUTION_MODE', 'SANDBOX_LIVE'),
        'API_KEY': os.environ.get('API_KEY')
    }
    
    # Set default stack name if not provided
    if not config['STACK_NAME']:
        config['STACK_NAME'] = f"opsagent-controller-{config['ENVIRONMENT']}"
    
    return {k: v for k, v in config.items() if v is not None}


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Validate OpsAgent Controller live environment deployment"
    )
    parser.add_argument(
        '--config-file',
        help='Configuration file (JSON format)'
    )
    parser.add_argument(
        '--report-file',
        default=f'validation_report_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json',
        help='Output report file'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Get configuration
    if args.config_file and os.path.exists(args.config_file):
        with open(args.config_file, 'r') as f:
            config = json.load(f)
    else:
        config = get_configuration()
    
    # Create validator
    validator = LiveEnvironmentValidator(config)
    
    # Run validations
    success = validator.run_all_validations()
    
    # Generate and save report
    report = validator.generate_report()
    with open(args.report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary
    validator.print_summary()
    validator.log('INFO', f"Detailed report saved to: {args.report_file}")
    
    # Return appropriate exit code
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())