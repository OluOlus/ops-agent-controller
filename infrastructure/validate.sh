#!/bin/bash

# OpsAgent Controller Template Validation Script
# This script validates the SAM template without deploying

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🔍 Validating OpsAgent Controller SAM Template${NC}"
echo ""

# Check prerequisites
echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

if ! command -v sam &> /dev/null; then
    echo -e "${RED}❌ AWS SAM CLI is not installed. Please install it first.${NC}"
    exit 1
fi

if ! command -v aws &> /dev/null; then
    echo -e "${RED}❌ AWS CLI is not installed. Please install it first.${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Prerequisites check passed${NC}"
echo ""

# Validate template syntax
echo -e "${YELLOW}🔍 Validating SAM template syntax...${NC}"
if sam validate; then
    echo -e "${GREEN}✅ SAM template syntax is valid${NC}"
else
    echo -e "${RED}❌ SAM template syntax validation failed${NC}"
    exit 1
fi

echo ""

# Build to check for issues
echo -e "${YELLOW}🔨 Building SAM application (dry run)...${NC}"
if sam build; then
    echo -e "${GREEN}✅ SAM build successful${NC}"
else
    echo -e "${RED}❌ SAM build failed${NC}"
    exit 1
fi

echo ""

# Check CloudFormation template
echo -e "${YELLOW}🔍 Validating CloudFormation template...${NC}"
if aws cloudformation validate-template --template-body file://.aws-sam/build/template.yaml > /dev/null; then
    echo -e "${GREEN}✅ CloudFormation template is valid${NC}"
else
    echo -e "${RED}❌ CloudFormation template validation failed${NC}"
    exit 1
fi

echo ""

# Summary
echo -e "${GREEN}🎉 All validations passed!${NC}"
echo ""
echo -e "${YELLOW}Template Summary:${NC}"
echo "- API Gateway with CORS and authentication"
echo "- Lambda function with proper IAM permissions"
echo "- KMS encryption for data at rest"
echo "- CloudWatch Logs for audit logging"
echo "- DynamoDB table for audit storage"
echo "- Test EC2 instance for remediation testing"
echo "- Comprehensive security controls"
echo ""
echo -e "${GREEN}✅ Template is ready for deployment!${NC}"