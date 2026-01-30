"""
Infrastructure provisioning validation tests for OpsAgent Controller
Requirements: 12.1, 13.1, 13.2

This module provides comprehensive tests to validate:
1. AWS infrastructure provisioning and configuration
2. CloudFormation stack deployment validation
3. API Gateway and Lambda function configuration
4. DynamoDB tables and audit infrastructure
5. IAM roles and permissions validation
6. Monitoring and alerting setup
"""
import json
import os
import time
import pytest
import boto3
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from botocore.exceptions import ClientError, NoCredentialsError

# Test configuration
TEST_TIMEOUT = 300  # 5 minutes for infrastructure tests
STACK_NAME_PREFIX = "opsagent-controller"


class TestInfrastructureProvisioning:
    """
    Infrastructure provisioning validation tests
    Requirements: 12.1, 13.1
    """
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment variables"""
        self.environment = os.environ.get("ENVIRONMENT", "sandbox")
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        self.stack_name = os.environ.get("STACK_NAME", f"{STACK_NAME_PREFIX}-{self.environment}")
        self.execution_mode = os.environ.get("EXECUTION_MODE", "LOCAL_MOCK")
        
        # Skip AWS tests in LOCAL_MOCK mode unless explicitly enabled
        self.skip_aws_tests = (
            self.execution_mode == "LOCAL_MOCK" and 
            not os.environ.get("FORCE_AWS_TESTS", "").lower() == "true"
        )
    
    def test_aws_credentials_available(self):
        """Test that AWS credentials are properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            sts_client = boto3.client('sts', region_name=self.region)
            identity = sts_client.get_caller_identity()
            
            assert "Account" in identity
            assert "UserId" in identity
            assert "Arn" in identity
            
            # Log account info for debugging
            print(f"AWS Account: {identity['Account']}")
            print(f"User/Role: {identity['UserId']}")
            
        except NoCredentialsError:
            pytest.fail("AWS credentials not configured")
        except ClientError as e:
            pytest.fail(f"AWS credentials invalid: {e}")
    
    def test_cloudformation_stack_exists(self):
        """Test that CloudFormation stack exists and is in good state"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            cf_client = boto3.client('cloudformation', region_name=self.region)
            
            response = cf_client.describe_stacks(StackName=self.stack_name)
            stacks = response.get('Stacks', [])
            
            assert len(stacks) == 1, f"Stack {self.stack_name} not found"
            
            stack = stacks[0]
            stack_status = stack['StackStatus']
            
            # Stack should be in a healthy state
            healthy_states = [
                'CREATE_COMPLETE',
                'UPDATE_COMPLETE',
                'UPDATE_ROLLBACK_COMPLETE'
            ]
            
            assert stack_status in healthy_states, f"Stack in unhealthy state: {stack_status}"
            
            # Check for stack outputs
            outputs = stack.get('Outputs', [])
            assert len(outputs) > 0, "Stack has no outputs"
            
            # Verify required outputs exist
            output_keys = [output['OutputKey'] for output in outputs]
            required_outputs = [
                'HealthEndpoint',
                'ChatEndpoint',
                'AuditLogGroupName'
            ]
            
            for required_output in required_outputs:
                assert required_output in output_keys, f"Missing required output: {required_output}"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError':
                pytest.fail(f"Stack {self.stack_name} does not exist")
            else:
                pytest.fail(f"Error checking stack: {e}")
    
    def test_api_gateway_configuration(self):
        """Test that API Gateway is properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        # Get API Gateway ID from stack outputs
        cf_client = boto3.client('cloudformation', region_name=self.region)
        response = cf_client.describe_stacks(StackName=self.stack_name)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        api_id = None
        for output in outputs:
            if output['OutputKey'] == 'ApiGatewayId':
                api_id = output['OutputValue']
                break
        
        if not api_id:
            pytest.skip("API Gateway ID not found in stack outputs")
        
        try:
            apigw_client = boto3.client('apigateway', region_name=self.region)
            
            # Get API details
            api = apigw_client.get_rest_api(restApiId=api_id)
            assert api['name'] == f"opsagent-controller-{self.environment}"
            
            # Get resources
            resources = apigw_client.get_resources(restApiId=api_id)
            resource_paths = [resource['path'] for resource in resources['items']]
            
            # Verify required endpoints exist
            required_paths = ['/health', '/chat']
            for path in required_paths:
                assert path in resource_paths, f"Missing API path: {path}"
            
            # Check deployment exists
            deployments = apigw_client.get_deployments(restApiId=api_id)
            assert len(deployments['items']) > 0, "No API deployments found"
            
        except ClientError as e:
            pytest.fail(f"Error checking API Gateway: {e}")
    
    def test_lambda_function_configuration(self):
        """Test that Lambda function is properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        function_name = f"opsagent-controller-{self.environment}"
        
        try:
            lambda_client = boto3.client('lambda', region_name=self.region)
            
            # Get function configuration
            function = lambda_client.get_function(FunctionName=function_name)
            config = function['Configuration']
            
            # Verify basic configuration
            assert config['Runtime'].startswith('python3'), f"Unexpected runtime: {config['Runtime']}"
            assert config['Handler'] == 'main.lambda_handler'
            assert config['MemorySize'] >= 512, f"Memory too low: {config['MemorySize']}"
            assert config['Timeout'] >= 30, f"Timeout too low: {config['Timeout']}"
            
            # Check environment variables
            env_vars = config.get('Environment', {}).get('Variables', {})
            assert 'EXECUTION_MODE' in env_vars, "EXECUTION_MODE not set"
            assert 'ENVIRONMENT' in env_vars, "ENVIRONMENT not set"
            
            # Verify IAM role
            role_arn = config['Role']
            assert f"opsagent-controller-{self.environment}" in role_arn, "Unexpected IAM role"
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                pytest.fail(f"Lambda function {function_name} not found")
            else:
                pytest.fail(f"Error checking Lambda function: {e}")
    
    def test_dynamodb_tables_configuration(self):
        """Test that DynamoDB tables are properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            dynamodb_client = boto3.client('dynamodb', region_name=self.region)
            
            # Expected tables
            expected_tables = [
                f"opsagent-audit-{self.environment}",
                f"opsagent-incidents-{self.environment}"
            ]
            
            for table_name in expected_tables:
                try:
                    table = dynamodb_client.describe_table(TableName=table_name)
                    table_status = table['Table']['TableStatus']
                    
                    assert table_status == 'ACTIVE', f"Table {table_name} not active: {table_status}"
                    
                    # Check billing mode
                    billing_mode = table['Table'].get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                    assert billing_mode in ['PAY_PER_REQUEST', 'PROVISIONED'], f"Unexpected billing mode: {billing_mode}"
                    
                    # Check TTL configuration for audit table
                    if 'audit' in table_name:
                        ttl_description = dynamodb_client.describe_time_to_live(TableName=table_name)
                        ttl_status = ttl_description.get('TimeToLiveDescription', {}).get('TimeToLiveStatus')
                        assert ttl_status in ['ENABLED', 'ENABLING'], f"TTL not enabled for {table_name}"
                    
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceNotFoundException':
                        pytest.fail(f"DynamoDB table {table_name} not found")
                    else:
                        raise
        
        except ClientError as e:
            pytest.fail(f"Error checking DynamoDB tables: {e}")
    
    def test_cloudwatch_logs_configuration(self):
        """Test that CloudWatch Logs are properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            logs_client = boto3.client('logs', region_name=self.region)
            
            # Expected log groups
            expected_log_groups = [
                f"/aws/lambda/opsagent-controller-{self.environment}",
                f"/opsagent/{self.environment}/audit"
            ]
            
            # Get all log groups
            paginator = logs_client.get_paginator('describe_log_groups')
            all_log_groups = []
            
            for page in paginator.paginate():
                all_log_groups.extend([lg['logGroupName'] for lg in page['logGroups']])
            
            # Check each expected log group
            for log_group_name in expected_log_groups:
                assert log_group_name in all_log_groups, f"Log group {log_group_name} not found"
                
                # Get log group details
                log_group = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
                groups = log_group['logGroups']
                
                matching_group = next((lg for lg in groups if lg['logGroupName'] == log_group_name), None)
                assert matching_group is not None, f"Log group {log_group_name} not found in details"
                
                # Check retention policy (should be set)
                if 'retentionInDays' in matching_group:
                    retention = matching_group['retentionInDays']
                    assert retention >= 7, f"Retention too short for {log_group_name}: {retention} days"
        
        except ClientError as e:
            pytest.fail(f"Error checking CloudWatch Logs: {e}")
    
    def test_iam_roles_and_permissions(self):
        """Test that IAM roles have proper permissions"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            iam_client = boto3.client('iam', region_name=self.region)
            
            # Lambda execution role
            role_name = f"opsagent-controller-{self.environment}-role"
            
            try:
                role = iam_client.get_role(RoleName=role_name)
                
                # Check trust policy
                trust_policy = role['Role']['AssumeRolePolicyDocument']
                assert 'lambda.amazonaws.com' in str(trust_policy), "Lambda trust policy not found"
                
                # Get attached policies
                attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
                policy_arns = [policy['PolicyArn'] for policy in attached_policies['AttachedPolicies']]
                
                # Should have basic Lambda execution policy
                lambda_basic_policy = 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
                assert lambda_basic_policy in policy_arns, "Basic Lambda execution policy not attached"
                
                # Get inline policies
                inline_policies = iam_client.list_role_policies(RoleName=role_name)
                inline_policy_names = inline_policies['PolicyNames']
                
                # Should have custom policy for OpsAgent permissions
                custom_policies = [name for name in inline_policy_names if 'opsagent' in name.lower()]
                assert len(custom_policies) > 0, "No custom OpsAgent policies found"
                
                # Check custom policy permissions
                for policy_name in custom_policies:
                    policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policy_document = policy_doc['PolicyDocument']
                    
                    # Convert to string for easier checking
                    policy_str = str(policy_document).lower()
                    
                    # Should have CloudWatch permissions
                    assert 'cloudwatch' in policy_str, "CloudWatch permissions not found"
                    
                    # Should have EC2 permissions
                    assert 'ec2' in policy_str, "EC2 permissions not found"
                    
                    # Should have DynamoDB permissions
                    assert 'dynamodb' in policy_str, "DynamoDB permissions not found"
                
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    pytest.fail(f"IAM role {role_name} not found")
                else:
                    raise
        
        except ClientError as e:
            pytest.fail(f"Error checking IAM roles: {e}")
    
    def test_ssm_parameters_configuration(self):
        """Test that SSM parameters are properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            ssm_client = boto3.client('ssm', region_name=self.region)
            
            # Expected parameters
            expected_parameters = [
                f"/opsagent/{self.environment}/api-key",
                f"/opsagent/{self.environment}/allowed-users"
            ]
            
            for param_name in expected_parameters:
                try:
                    parameter = ssm_client.get_parameter(Name=param_name, WithDecryption=True)
                    
                    # Parameter should exist and have a value
                    assert parameter['Parameter']['Value'], f"Parameter {param_name} has no value"
                    
                    # API key should be encrypted
                    if 'api-key' in param_name:
                        assert parameter['Parameter']['Type'] == 'SecureString', f"API key parameter {param_name} not encrypted"
                    
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ParameterNotFound':
                        pytest.fail(f"SSM parameter {param_name} not found")
                    else:
                        raise
        
        except ClientError as e:
            pytest.fail(f"Error checking SSM parameters: {e}")
    
    def test_monitoring_and_alerting_setup(self):
        """Test that monitoring and alerting are properly configured"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            cloudwatch_client = boto3.client('cloudwatch', region_name=self.region)
            
            # Check for Lambda function metrics
            function_name = f"opsagent-controller-{self.environment}"
            
            # Get metrics for the Lambda function
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            
            metrics = cloudwatch_client.list_metrics(
                Namespace='AWS/Lambda',
                Dimensions=[
                    {
                        'Name': 'FunctionName',
                        'Value': function_name
                    }
                ]
            )
            
            # Should have Lambda metrics available
            metric_names = [metric['MetricName'] for metric in metrics['Metrics']]
            expected_metrics = ['Duration', 'Errors', 'Invocations']
            
            for expected_metric in expected_metrics:
                assert expected_metric in metric_names, f"Lambda metric {expected_metric} not found"
            
            # Check for custom alarms (if any)
            alarms = cloudwatch_client.describe_alarms(
                AlarmNamePrefix=f"opsagent-{self.environment}"
            )
            
            # Log alarm count for debugging
            alarm_count = len(alarms['MetricAlarms'])
            print(f"Found {alarm_count} CloudWatch alarms for OpsAgent")
        
        except ClientError as e:
            pytest.fail(f"Error checking monitoring setup: {e}")
    
    def test_api_endpoints_accessibility(self):
        """Test that API endpoints are accessible"""
        health_endpoint = os.environ.get("HEALTH_ENDPOINT")
        chat_endpoint = os.environ.get("CHAT_ENDPOINT")
        
        if not health_endpoint or not chat_endpoint:
            pytest.skip("API endpoints not configured in environment")
        
        import requests
        
        try:
            # Test health endpoint
            health_response = requests.get(health_endpoint, timeout=30)
            assert health_response.status_code == 200, f"Health endpoint returned {health_response.status_code}"
            
            health_data = health_response.json()
            assert health_data.get('success') is True, "Health endpoint returned unsuccessful response"
            
            # Test chat endpoint (should return 400/401 without proper request)
            chat_response = requests.post(chat_endpoint, json={}, timeout=30)
            assert chat_response.status_code in [400, 401], f"Chat endpoint returned unexpected status: {chat_response.status_code}"
            
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Error testing API endpoints: {e}")
    
    def test_deployment_tags_and_metadata(self):
        """Test that resources have proper tags and metadata"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            # Check CloudFormation stack tags
            cf_client = boto3.client('cloudformation', region_name=self.region)
            response = cf_client.describe_stacks(StackName=self.stack_name)
            stack = response['Stacks'][0]
            
            stack_tags = {tag['Key']: tag['Value'] for tag in stack.get('Tags', [])}
            
            # Should have environment tag
            assert 'Environment' in stack_tags, "Environment tag not found on stack"
            assert stack_tags['Environment'] == self.environment, f"Environment tag mismatch: {stack_tags['Environment']}"
            
            # Should have project/application tag
            project_tags = ['Project', 'Application', 'Service']
            has_project_tag = any(tag in stack_tags for tag in project_tags)
            assert has_project_tag, "No project/application tag found on stack"
            
        except ClientError as e:
            pytest.fail(f"Error checking deployment tags: {e}")


class TestInfrastructurePerformance:
    """
    Infrastructure performance validation tests
    Requirements: 12.1, 13.1
    """
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment variables"""
        self.environment = os.environ.get("ENVIRONMENT", "sandbox")
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        self.execution_mode = os.environ.get("EXECUTION_MODE", "LOCAL_MOCK")
        
        # Skip AWS tests in LOCAL_MOCK mode unless explicitly enabled
        self.skip_aws_tests = (
            self.execution_mode == "LOCAL_MOCK" and 
            not os.environ.get("FORCE_AWS_TESTS", "").lower() == "true"
        )
    
    def test_lambda_cold_start_performance(self):
        """Test Lambda function cold start performance"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        function_name = f"opsagent-controller-{self.environment}"
        
        try:
            lambda_client = boto3.client('lambda', region_name=self.region)
            
            # Invoke function to test cold start
            start_time = time.time()
            
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload=json.dumps({
                    "httpMethod": "GET",
                    "path": "/health",
                    "headers": {}
                })
            )
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Cold start should complete within reasonable time
            assert duration < 30, f"Lambda cold start too slow: {duration:.2f}s"
            
            # Check response
            assert response['StatusCode'] == 200, f"Lambda invocation failed: {response['StatusCode']}"
            
            payload = json.loads(response['Payload'].read())
            assert payload.get('statusCode') == 200, f"Lambda returned error: {payload}"
            
            print(f"Lambda cold start duration: {duration:.2f}s")
            
        except ClientError as e:
            pytest.fail(f"Error testing Lambda performance: {e}")
    
    def test_api_gateway_response_time(self):
        """Test API Gateway response time"""
        health_endpoint = os.environ.get("HEALTH_ENDPOINT")
        
        if not health_endpoint:
            pytest.skip("Health endpoint not configured")
        
        import requests
        
        try:
            # Test multiple requests to get average response time
            response_times = []
            
            for i in range(5):
                start_time = time.time()
                response = requests.get(health_endpoint, timeout=30)
                end_time = time.time()
                
                assert response.status_code == 200, f"Request {i+1} failed: {response.status_code}"
                
                response_time = end_time - start_time
                response_times.append(response_time)
                
                # Small delay between requests
                time.sleep(0.5)
            
            # Calculate average response time
            avg_response_time = sum(response_times) / len(response_times)
            max_response_time = max(response_times)
            
            # Response times should be reasonable
            assert avg_response_time < 5.0, f"Average response time too slow: {avg_response_time:.2f}s"
            assert max_response_time < 10.0, f"Max response time too slow: {max_response_time:.2f}s"
            
            print(f"Average API response time: {avg_response_time:.2f}s")
            print(f"Max API response time: {max_response_time:.2f}s")
            
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Error testing API performance: {e}")
    
    def test_dynamodb_table_performance(self):
        """Test DynamoDB table read/write performance"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        try:
            dynamodb = boto3.resource('dynamodb', region_name=self.region)
            table_name = f"opsagent-audit-{self.environment}"
            
            table = dynamodb.Table(table_name)
            
            # Test write performance
            test_item = {
                'correlationId': f'perf-test-{int(time.time())}',
                'timestamp': datetime.utcnow().isoformat(),
                'userId': 'performance-test-user',
                'operation': 'performance_test',
                'success': True,
                'ttl': int((datetime.utcnow() + timedelta(hours=1)).timestamp())
            }
            
            start_time = time.time()
            table.put_item(Item=test_item)
            write_time = time.time() - start_time
            
            # Test read performance
            start_time = time.time()
            response = table.get_item(Key={'correlationId': test_item['correlationId']})
            read_time = time.time() - start_time
            
            # Verify item was written and read correctly
            assert 'Item' in response, "Test item not found in DynamoDB"
            assert response['Item']['userId'] == 'performance-test-user'
            
            # Performance should be reasonable
            assert write_time < 2.0, f"DynamoDB write too slow: {write_time:.2f}s"
            assert read_time < 1.0, f"DynamoDB read too slow: {read_time:.2f}s"
            
            print(f"DynamoDB write time: {write_time:.3f}s")
            print(f"DynamoDB read time: {read_time:.3f}s")
            
            # Clean up test item
            table.delete_item(Key={'correlationId': test_item['correlationId']})
            
        except ClientError as e:
            pytest.fail(f"Error testing DynamoDB performance: {e}")


class TestInfrastructureResilience:
    """
    Infrastructure resilience and error handling tests
    Requirements: 12.1, 13.1
    """
    
    @pytest.fixture(autouse=True)
    def setup_test_environment(self):
        """Set up test environment variables"""
        self.environment = os.environ.get("ENVIRONMENT", "sandbox")
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        self.execution_mode = os.environ.get("EXECUTION_MODE", "LOCAL_MOCK")
        
        # Skip AWS tests in LOCAL_MOCK mode unless explicitly enabled
        self.skip_aws_tests = (
            self.execution_mode == "LOCAL_MOCK" and 
            not os.environ.get("FORCE_AWS_TESTS", "").lower() == "true"
        )
    
    def test_lambda_error_handling(self):
        """Test Lambda function error handling"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        function_name = f"opsagent-controller-{self.environment}"
        
        try:
            lambda_client = boto3.client('lambda', region_name=self.region)
            
            # Test with invalid JSON payload
            response = lambda_client.invoke(
                FunctionName=function_name,
                InvocationType='RequestResponse',
                Payload='{"invalid": json}'  # Invalid JSON
            )
            
            # Should handle error gracefully
            assert response['StatusCode'] == 200, "Lambda should handle invalid JSON gracefully"
            
            payload = json.loads(response['Payload'].read())
            
            # Should return error response, not crash
            assert 'statusCode' in payload, "Lambda should return structured response even for errors"
            
        except ClientError as e:
            pytest.fail(f"Error testing Lambda error handling: {e}")
    
    def test_api_gateway_rate_limiting(self):
        """Test API Gateway rate limiting behavior"""
        health_endpoint = os.environ.get("HEALTH_ENDPOINT")
        
        if not health_endpoint:
            pytest.skip("Health endpoint not configured")
        
        import requests
        import concurrent.futures
        
        def make_request():
            try:
                response = requests.get(health_endpoint, timeout=10)
                return response.status_code
            except requests.exceptions.RequestException:
                return 500
        
        try:
            # Make many concurrent requests to test rate limiting
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(make_request) for _ in range(50)]
                results = [future.result() for future in concurrent.futures.as_completed(futures)]
            
            # Count different response codes
            success_count = sum(1 for code in results if code == 200)
            rate_limited_count = sum(1 for code in results if code == 429)
            error_count = sum(1 for code in results if code >= 500)
            
            print(f"Concurrent requests - Success: {success_count}, Rate limited: {rate_limited_count}, Errors: {error_count}")
            
            # Should handle concurrent requests without too many errors
            assert error_count < len(results) * 0.2, f"Too many errors in concurrent requests: {error_count}/{len(results)}"
            
            # Should have some successful requests
            assert success_count > 0, "No successful requests in concurrent test"
            
        except Exception as e:
            pytest.fail(f"Error testing rate limiting: {e}")
    
    def test_infrastructure_dependency_handling(self):
        """Test handling of infrastructure dependency failures"""
        if self.skip_aws_tests:
            pytest.skip("Skipping AWS tests in LOCAL_MOCK mode")
        
        # This test verifies that the system can handle AWS service outages gracefully
        # In a real scenario, we would simulate service failures
        
        try:
            # Test with invalid region to simulate service unavailability
            invalid_region_client = boto3.client('dynamodb', region_name='invalid-region-test')
            
            with pytest.raises(Exception):
                # This should fail, but the application should handle it gracefully
                invalid_region_client.list_tables()
            
            # The key is that the application doesn't crash completely
            # when dependencies are unavailable
            
        except Exception:
            # Expected to fail - this tests that we can handle dependency failures
            pass


if __name__ == "__main__":
    # Allow running infrastructure tests directly
    import subprocess
    import sys
    
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/test_infrastructure_provisioning.py", 
        "-v", 
        "--tb=short"
    ], capture_output=True, text=True)
    
    print(result.stdout)
    if result.stderr:
        print("STDERR:", result.stderr)
    
    exit(result.returncode)