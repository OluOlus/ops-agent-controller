#!/bin/bash

# OpsAgent Controller Live Testing Setup Script
# This script sets up a complete live testing environment in AWS

set -e

# Configuration
AWS_REGION="us-west-2"
ENVIRONMENT="test"
STACK_NAME="opsagent-controller-${ENVIRONMENT}"
ADMIN_EMAIL="admin@oluofnotts.onmicrosoft.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to log messages
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        INFO)  echo -e "${GREEN}[INFO]${NC}  [$timestamp] $message" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC}  [$timestamp] $message" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} [$timestamp] $message" ;;
        DEBUG) echo -e "${BLUE}[DEBUG]${NC} [$timestamp] $message" ;;
    esac
}

# Function to check prerequisites
check_prerequisites() {
    log INFO "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        log ERROR "AWS CLI is not installed. Please install it first."
        exit 1
    fi
    
    # Check SAM CLI
    if ! command -v sam &> /dev/null; then
        log WARN "SAM CLI not found. Installing..."
        if command -v brew &> /dev/null; then
            brew install aws-sam-cli
        elif command -v pip3 &> /dev/null; then
            pip3 install aws-sam-cli
        else
            log ERROR "Cannot install SAM CLI. Please install manually."
            exit 1
        fi
    fi
    
    # Check Python dependencies
    if ! python3 -c "import boto3, pytest, hypothesis" &> /dev/null; then
        log WARN "Installing Python dependencies..."
        pip3 install boto3 pytest hypothesis requests
    fi
    
    log INFO "Prerequisites check completed"
}

# Function to configure AWS credentials
configure_aws() {
    log INFO "Configuring AWS credentials..."
    
    # Set AWS credentials
    export AWS_ACCESS_KEY_ID="AKIAY5CEVT5WBJNLRI57"
    export AWS_SECRET_ACCESS_KEY="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"
    export AWS_DEFAULT_REGION="$AWS_REGION"
    
    # Verify credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log ERROR "AWS credentials are not valid"
        exit 1
    fi
    
    local account_id=$(aws sts get-caller-identity --query Account --output text)
    log INFO "AWS Account ID: $account_id"
    log INFO "AWS Region: $AWS_REGION"
}

# Function to create test configuration
create_test_config() {
    log INFO "Creating test configuration..."
    
    # Create test environment config
    cat > infrastructure/config/test.yaml << EOF
# Test Environment Configuration
environment: test
region: us-west-2
execution_mode: SANDBOX_LIVE

# User Configuration
allowed_users:
  - admin@oluofnotts.onmicrosoft.com
  - test@oluofnotts.onmicrosoft.com

# Resource Configuration
lambda:
  memory_size: 1024
  timeout: 60
  
dynamodb:
  billing_mode: PAY_PER_REQUEST
  
# Monitoring Configuration
monitoring:
  enable_alarms: true
  notification_email: admin@oluofnotts.onmicrosoft.com
  
# Test Resources
test_resources:
  create_ec2_instances: true
  create_ecs_cluster: true
  instance_type: t3.micro
  instance_count: 2
EOF

    log INFO "Test configuration created"
}

# Function to create test resources CloudFormation template
create_test_resources_template() {
    log INFO "Creating test resources template..."
    
    cat > infrastructure/test-resources.yaml << 'EOF'
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Test resources for OpsAgent Controller live testing'

Parameters:
  Environment:
    Type: String
    Default: test
    Description: Environment name
  
  InstanceType:
    Type: String
    Default: t3.micro
    Description: EC2 instance type for testing

Resources:
  # VPC for test resources
  TestVPC:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.0.0.0/16
      EnableDnsHostnames: true
      EnableDnsSupport: true
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-vpc-${Environment}'
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'

  # Internet Gateway
  TestIGW:
    Type: AWS::EC2::InternetGateway
    Properties:
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-igw-${Environment}'

  AttachGateway:
    Type: AWS::EC2::VPCGatewayAttachment
    Properties:
      VpcId: !Ref TestVPC
      InternetGatewayId: !Ref TestIGW

  # Public Subnet
  TestSubnet:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref TestVPC
      CidrBlock: 10.0.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      MapPublicIpOnLaunch: true
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-subnet-${Environment}'
        - Key: Environment
          Value: !Ref Environment

  # Route Table
  TestRouteTable:
    Type: AWS::EC2::RouteTable
    Properties:
      VpcId: !Ref TestVPC
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-rt-${Environment}'

  TestRoute:
    Type: AWS::EC2::Route
    DependsOn: AttachGateway
    Properties:
      RouteTableId: !Ref TestRouteTable
      DestinationCidrBlock: 0.0.0.0/0
      GatewayId: !Ref TestIGW

  SubnetRouteTableAssociation:
    Type: AWS::EC2::SubnetRouteTableAssociation
    Properties:
      SubnetId: !Ref TestSubnet
      RouteTableId: !Ref TestRouteTable

  # Security Group
  TestSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Security group for OpsAgent test instances
      VpcId: !Ref TestVPC
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 22
          ToPort: 22
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 0.0.0.0/0
        - IpProtocol: tcp
          FromPort: 443
          ToPort: 443
          CidrIp: 0.0.0.0/0
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-sg-${Environment}'
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'

  # Test EC2 Instance 1
  TestInstance1:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-00d8a0260a086a99e  # Amazon Linux 2 AMI (us-west-2)
      InstanceType: !Ref InstanceType
      SubnetId: !Ref TestSubnet
      SecurityGroupIds:
        - !Ref TestSecurityGroup
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          yum install -y httpd
          systemctl start httpd
          systemctl enable httpd
          echo "<h1>OpsAgent Test Instance 1</h1>" > /var/www/html/index.html
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-instance-1-${Environment}'
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'
        - Key: TestInstance
          Value: 'true'

  # Test EC2 Instance 2
  TestInstance2:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: ami-00d8a0260a086a99e  # Amazon Linux 2 AMI (us-west-2)
      InstanceType: !Ref InstanceType
      SubnetId: !Ref TestSubnet
      SecurityGroupIds:
        - !Ref TestSecurityGroup
      UserData:
        Fn::Base64: !Sub |
          #!/bin/bash
          yum update -y
          yum install -y httpd
          systemctl start httpd
          systemctl enable httpd
          echo "<h1>OpsAgent Test Instance 2</h1>" > /var/www/html/index.html
      Tags:
        - Key: Name
          Value: !Sub 'opsagent-test-instance-2-${Environment}'
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'
        - Key: TestInstance
          Value: 'true'

  # ECS Cluster for testing
  TestECSCluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Sub 'opsagent-test-cluster-${Environment}'
      Tags:
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'

  # ECS Task Definition
  TestTaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Sub 'opsagent-test-task-${Environment}'
      NetworkMode: awsvpc
      RequiresCompatibilities:
        - FARGATE
      Cpu: 256
      Memory: 512
      ExecutionRoleArn: !Ref ECSExecutionRole
      ContainerDefinitions:
        - Name: test-container
          Image: nginx:latest
          PortMappings:
            - ContainerPort: 80
              Protocol: tcp
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref ECSLogGroup
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: ecs
      Tags:
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'

  # ECS Service
  TestECSService:
    Type: AWS::ECS::Service
    Properties:
      ServiceName: !Sub 'opsagent-test-service-${Environment}'
      Cluster: !Ref TestECSCluster
      TaskDefinition: !Ref TestTaskDefinition
      LaunchType: FARGATE
      DesiredCount: 2
      NetworkConfiguration:
        AwsvpcConfiguration:
          SecurityGroups:
            - !Ref TestSecurityGroup
          Subnets:
            - !Ref TestSubnet
          AssignPublicIp: ENABLED
      Tags:
        - Key: Environment
          Value: !Ref Environment
        - Key: OpsAgentManaged
          Value: 'true'

  # ECS Execution Role
  ECSExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ecs-tasks.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy

  # CloudWatch Log Group for ECS
  ECSLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/ecs/opsagent-test-${Environment}'
      RetentionInDays: 7

Outputs:
  TestInstance1Id:
    Description: Test Instance 1 ID
    Value: !Ref TestInstance1
    Export:
      Name: !Sub '${AWS::StackName}-TestInstance1Id'

  TestInstance2Id:
    Description: Test Instance 2 ID
    Value: !Ref TestInstance2
    Export:
      Name: !Sub '${AWS::StackName}-TestInstance2Id'

  TestClusterName:
    Description: Test ECS Cluster Name
    Value: !Ref TestECSCluster
    Export:
      Name: !Sub '${AWS::StackName}-TestClusterName'

  TestServiceName:
    Description: Test ECS Service Name
    Value: !Ref TestECSService
    Export:
      Name: !Sub '${AWS::StackName}-TestServiceName'

  VPCId:
    Description: Test VPC ID
    Value: !Ref TestVPC
    Export:
      Name: !Sub '${AWS::StackName}-VPCId'

  SubnetId:
    Description: Test Subnet ID
    Value: !Ref TestSubnet
    Export:
      Name: !Sub '${AWS::StackName}-SubnetId'
EOF

    log INFO "Test resources template created"
}

# Function to deploy test resources
deploy_test_resources() {
    log INFO "Deploying test resources..."
    
    aws cloudformation deploy \
        --template-file infrastructure/test-resources.yaml \
        --stack-name "opsagent-test-resources-${ENVIRONMENT}" \
        --parameter-overrides \
            Environment="$ENVIRONMENT" \
            InstanceType="t3.micro" \
        --capabilities CAPABILITY_IAM \
        --region "$AWS_REGION"
    
    if [ $? -eq 0 ]; then
        log INFO "Test resources deployed successfully"
    else
        log ERROR "Failed to deploy test resources"
        exit 1
    fi
}

# Function to update SAM template for testing
update_sam_template() {
    log INFO "Updating SAM template for live testing..."
    
    # Backup original template
    cp infrastructure/template.yaml infrastructure/template.yaml.backup
    
    # Update template with test-specific parameters
    cat >> infrastructure/template.yaml << 'EOF'

  # Test-specific parameters
  TestInstance1Id:
    Type: String
    Default: ""
    Description: Test EC2 Instance 1 ID
    
  TestInstance2Id:
    Type: String
    Default: ""
    Description: Test EC2 Instance 2 ID
    
  TestClusterName:
    Type: String
    Default: ""
    Description: Test ECS Cluster Name
    
  TestServiceName:
    Type: String
    Default: ""
    Description: Test ECS Service Name
EOF

    log INFO "SAM template updated for testing"
}

# Function to deploy OpsAgent infrastructure
deploy_opsagent() {
    log INFO "Deploying OpsAgent Controller infrastructure..."
    
    # Get test resource outputs
    local test_instance_1=$(aws cloudformation describe-stacks \
        --stack-name "opsagent-test-resources-${ENVIRONMENT}" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestInstance1Id`].OutputValue' \
        --output text)
    
    local test_instance_2=$(aws cloudformation describe-stacks \
        --stack-name "opsagent-test-resources-${ENVIRONMENT}" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestInstance2Id`].OutputValue' \
        --output text)
    
    local test_cluster=$(aws cloudformation describe-stacks \
        --stack-name "opsagent-test-resources-${ENVIRONMENT}" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestClusterName`].OutputValue' \
        --output text)
    
    local test_service=$(aws cloudformation describe-stacks \
        --stack-name "opsagent-test-resources-${ENVIRONMENT}" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`TestServiceName`].OutputValue' \
        --output text)
    
    log INFO "Test Instance 1: $test_instance_1"
    log INFO "Test Instance 2: $test_instance_2"
    log INFO "Test Cluster: $test_cluster"
    log INFO "Test Service: $test_service"
    
    # Build and deploy SAM application
    sam build
    
    sam deploy \
        --stack-name "$STACK_NAME" \
        --parameter-overrides \
            Environment="$ENVIRONMENT" \
            ExecutionMode="SANDBOX_LIVE" \
            AllowedUsers="$ADMIN_EMAIL,test@oluofnotts.onmicrosoft.com" \
            TestInstance1Id="$test_instance_1" \
            TestInstance2Id="$test_instance_2" \
            TestClusterName="$test_cluster" \
            TestServiceName="$test_service" \
        --capabilities CAPABILITY_IAM \
        --region "$AWS_REGION" \
        --confirm-changeset
    
    if [ $? -eq 0 ]; then
        log INFO "OpsAgent Controller deployed successfully"
    else
        log ERROR "Failed to deploy OpsAgent Controller"
        exit 1
    fi
}

# Function to configure environment variables for testing
setup_test_environment() {
    log INFO "Setting up test environment variables..."
    
    # Get stack outputs
    local health_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`HealthEndpoint`].OutputValue' \
        --output text)
    
    local chat_endpoint=$(aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$AWS_REGION" \
        --query 'Stacks[0].Outputs[?OutputKey==`ChatEndpoint`].OutputValue' \
        --output text)
    
    local api_key=$(aws ssm get-parameter \
        --name "/opsagent/${ENVIRONMENT}/api-key" \
        --with-decryption \
        --region "$AWS_REGION" \
        --query 'Parameter.Value' \
        --output text)
    
    # Create environment file
    cat > .env.test << EOF
# OpsAgent Controller Test Environment
ENVIRONMENT=$ENVIRONMENT
AWS_REGION=$AWS_REGION
EXECUTION_MODE=SANDBOX_LIVE
HEALTH_ENDPOINT=$health_endpoint
CHAT_ENDPOINT=$chat_endpoint
API_KEY=$api_key
STACK_NAME=$STACK_NAME
ADMIN_EMAIL=$ADMIN_EMAIL

# Test Resource IDs (will be populated after deployment)
TEST_INSTANCE_1_ID=
TEST_INSTANCE_2_ID=
TEST_CLUSTER_NAME=
TEST_SERVICE_NAME=
EOF

    log INFO "Test environment configured"
    log INFO "Health Endpoint: $health_endpoint"
    log INFO "Chat Endpoint: $chat_endpoint"
    log INFO "API Key: ${api_key:0:10}..."
}

# Function to run initial validation
run_initial_validation() {
    log INFO "Running initial validation..."
    
    source .env.test
    
    # Test health endpoint
    local health_response=$(curl -s -H "X-API-Key: $API_KEY" "$HEALTH_ENDPOINT")
    local health_status=$(echo "$health_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('data', {}).get('status', 'unknown'))" 2>/dev/null || echo "error")
    
    if [ "$health_status" = "healthy" ]; then
        log INFO "✅ Health endpoint is working"
    else
        log ERROR "❌ Health endpoint failed: $health_status"
        log DEBUG "Response: $health_response"
    fi
    
    # Test basic chat functionality
    local chat_response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-API-Key: $API_KEY" \
        -d '{"userId":"test@oluofnotts.onmicrosoft.com","messageText":"health check","channel":"web"}' \
        "$CHAT_ENDPOINT")
    
    local chat_success=$(echo "$chat_response" | python3 -c "import sys, json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "false")
    
    if [ "$chat_success" = "True" ]; then
        log INFO "✅ Chat endpoint is working"
    else
        log ERROR "❌ Chat endpoint failed"
        log DEBUG "Response: $chat_response"
    fi
}

# Main execution
main() {
    log INFO "🚀 Starting OpsAgent Controller Live Testing Setup"
    log INFO "Environment: $ENVIRONMENT"
    log INFO "Region: $AWS_REGION"
    log INFO "Admin Email: $ADMIN_EMAIL"
    
    check_prerequisites
    configure_aws
    create_test_config
    create_test_resources_template
    deploy_test_resources
    update_sam_template
    deploy_opsagent
    setup_test_environment
    run_initial_validation
    
    log INFO "🎉 Live testing environment setup completed!"
    log INFO ""
    log INFO "Next steps:"
    log INFO "1. Run live tests: ./infrastructure/run-live-tests.sh"
    log INFO "2. Validate deployment: ./infrastructure/validate-live-environment.py"
    log INFO "3. Clean up when done: ./infrastructure/cleanup.sh --environment test"
    log INFO ""
    log INFO "Environment file created: .env.test"
    log INFO "Load it with: source .env.test"
}

# Run main function
main "$@"