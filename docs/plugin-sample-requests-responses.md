# OpsAgent Plugin Sample Requests and Responses

This document provides comprehensive examples of all 8 plugin operations with sample requests and expected responses for Amazon Q Business integration.

## Table of Contents

1. [Diagnostic Operations](#diagnostic-operations)
2. [Write Operations](#write-operations)
3. [Workflow Operations](#workflow-operations)
4. [Error Responses](#error-responses)
5. [Execution Modes](#execution-modes)

## Diagnostic Operations

### 1. get_ec2_status

**Description**: Get EC2 instance status and basic metrics

#### Sample Request
```json
{
  "operation": "get_ec2_status",
  "parameters": {
    "instance_id": "i-1234567890abcdef0",
    "metrics": ["cpu", "memory", "network"],
    "time_window": "1h"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Sample Response (SANDBOX_LIVE)
```json
{
  "success": true,
  "summary": "Instance i-1234567890abcdef0 is running. CPU: 45.2%, Memory: 68.1%, Network: Normal",
  "details": {
    "instance_id": "i-1234567890abcdef0",
    "instance_state": "running",
    "instance_type": "t3.medium",
    "availability_zone": "us-east-1a",
    "launch_time": "2024-01-15T08:30:00Z",
    "metrics": {
      "cpu_utilization": {
        "current": 45.2,
        "average_1h": 42.8,
        "maximum_1h": 78.5,
        "minimum_1h": 12.3
      },
      "memory_utilization": {
        "current": 68.1,
        "average_1h": 65.4,
        "maximum_1h": 82.1,
        "minimum_1h": 45.2
      },
      "network": {
        "network_in": "1.2 MB/s",
        "network_out": "0.8 MB/s",
        "network_packets_in": 1250,
        "network_packets_out": 980
      }
    },
    "tags": [
      {"Key": "Name", "Value": "web-server-01"},
      {"Key": "Environment", "Value": "production"},
      {"Key": "OpsAgentManaged", "Value": "true"}
    ]
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-ec2-status-001",
  "timestamp": "2024-01-15T10:15:30Z"
}
```

#### Sample Response (LOCAL_MOCK)
```json
{
  "success": true,
  "summary": "Mock: Instance i-1234567890abcdef0 status retrieved successfully",
  "details": {
    "instance_id": "i-1234567890abcdef0",
    "instance_state": "running",
    "instance_type": "t3.medium",
    "mock": true,
    "metrics": {
      "cpu_utilization": {
        "current": 25.0,
        "average_1h": 30.0,
        "note": "Mock data for testing"
      },
      "memory_utilization": {
        "current": 50.0,
        "average_1h": 55.0,
        "note": "Mock data for testing"
      }
    }
  },
  "execution_mode": "LOCAL_MOCK",
  "correlation_id": "req-ec2-status-001",
  "timestamp": "2024-01-15T10:15:30Z"
}
```

### 2. get_cloudwatch_metrics

**Description**: Retrieve CloudWatch metrics for resources with time windows

#### Sample Request
```json
{
  "operation": "get_cloudwatch_metrics",
  "parameters": {
    "namespace": "AWS/EC2",
    "metric_name": "CPUUtilization",
    "resource_id": "i-1234567890abcdef0",
    "time_window": "6h",
    "statistic": "Average"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Sample Response
```json
{
  "success": true,
  "summary": "CPU utilization for i-1234567890abcdef0: Average 42.8% over last 6 hours",
  "details": {
    "namespace": "AWS/EC2",
    "metric_name": "CPUUtilization",
    "resource_id": "i-1234567890abcdef0",
    "time_window": "6h",
    "statistic": "Average",
    "unit": "Percent",
    "statistics": {
      "average": 42.8,
      "maximum": 89.2,
      "minimum": 8.1,
      "sample_count": 72
    },
    "data_points": [
      {
        "timestamp": "2024-01-15T04:00:00Z",
        "value": 35.2,
        "unit": "Percent"
      },
      {
        "timestamp": "2024-01-15T05:00:00Z",
        "value": 41.8,
        "unit": "Percent"
      },
      {
        "timestamp": "2024-01-15T06:00:00Z",
        "value": 38.9,
        "unit": "Percent"
      },
      {
        "timestamp": "2024-01-15T07:00:00Z",
        "value": 52.1,
        "unit": "Percent"
      },
      {
        "timestamp": "2024-01-15T08:00:00Z",
        "value": 48.3,
        "unit": "Percent"
      },
      {
        "timestamp": "2024-01-15T09:00:00Z",
        "value": 45.7,
        "unit": "Percent"
      }
    ],
    "trend_analysis": {
      "direction": "stable",
      "variance": "normal",
      "anomalies_detected": false
    }
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-cw-metrics-002",
  "timestamp": "2024-01-15T10:16:45Z"
}
```

### 3. describe_alb_target_health

**Description**: Check ALB/Target Group health status

#### Sample Request
```json
{
  "operation": "describe_alb_target_health",
  "parameters": {
    "alb_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web-alb/1234567890123456"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Sample Response
```json
{
  "success": true,
  "summary": "ALB web-alb has 3 target groups with 8/10 healthy targets total",
  "details": {
    "load_balancer": {
      "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web-alb/1234567890123456",
      "name": "web-alb",
      "state": "active",
      "type": "application",
      "scheme": "internet-facing",
      "availability_zones": ["us-east-1a", "us-east-1b", "us-east-1c"]
    },
    "target_groups": [
      {
        "name": "web-tg-80",
        "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-tg-80/1234567890123456",
        "port": 80,
        "protocol": "HTTP",
        "health_check": {
          "path": "/health",
          "interval": 30,
          "timeout": 5,
          "healthy_threshold": 2,
          "unhealthy_threshold": 3
        },
        "targets": [
          {
            "id": "i-1234567890abcdef0",
            "port": 80,
            "health": "healthy",
            "reason": "Target.ResponseCodeMismatch",
            "description": "Health checks succeeded"
          },
          {
            "id": "i-0987654321fedcba0",
            "port": 80,
            "health": "healthy",
            "reason": "Target.ResponseCodeMismatch",
            "description": "Health checks succeeded"
          },
          {
            "id": "i-abcdef1234567890a",
            "port": 80,
            "health": "unhealthy",
            "reason": "Target.Timeout",
            "description": "Health check timeout"
          }
        ],
        "healthy_count": 2,
        "total_count": 3
      },
      {
        "name": "web-tg-443",
        "arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/web-tg-443/1234567890123456",
        "port": 443,
        "protocol": "HTTPS",
        "targets": [
          {
            "id": "i-1234567890abcdef0",
            "port": 443,
            "health": "healthy",
            "description": "Health checks succeeded"
          },
          {
            "id": "i-0987654321fedcba0",
            "port": 443,
            "health": "healthy",
            "description": "Health checks succeeded"
          }
        ],
        "healthy_count": 2,
        "total_count": 2
      }
    ],
    "summary": {
      "total_target_groups": 2,
      "total_targets": 5,
      "healthy_targets": 4,
      "unhealthy_targets": 1,
      "overall_health": "degraded"
    }
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-alb-health-003",
  "timestamp": "2024-01-15T10:17:20Z"
}
```

### 4. search_cloudtrail_events

**Description**: Search CloudTrail events with filters and time windows

#### Sample Request
```json
{
  "operation": "search_cloudtrail_events",
  "parameters": {
    "event_name": "RunInstances",
    "time_window": "24h",
    "max_results": 10
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Sample Response
```json
{
  "success": true,
  "summary": "Found 3 RunInstances events in the last 24 hours",
  "details": {
    "search_criteria": {
      "event_name": "RunInstances",
      "time_window": "24h",
      "start_time": "2024-01-14T10:17:30Z",
      "end_time": "2024-01-15T10:17:30Z"
    },
    "events": [
      {
        "event_time": "2024-01-15T09:45:12Z",
        "event_name": "RunInstances",
        "user_name": "admin@company.com",
        "user_type": "IAMUser",
        "source_ip": "203.0.113.12",
        "user_agent": "aws-cli/2.15.0",
        "aws_region": "us-east-1",
        "resources": [
          {
            "resource_type": "AWS::EC2::Instance",
            "resource_name": "i-0abcdef1234567890"
          }
        ],
        "request_parameters": {
          "instanceType": "t3.micro",
          "minCount": 1,
          "maxCount": 1,
          "imageId": "ami-0abcdef1234567890"
        },
        "response_elements": {
          "instancesSet": {
            "items": [
              {
                "instanceId": "i-0abcdef1234567890",
                "instanceState": {
                  "code": 0,
                  "name": "pending"
                }
              }
            ]
          }
        }
      },
      {
        "event_time": "2024-01-15T08:22:45Z",
        "event_name": "RunInstances",
        "user_name": "ops-team-role",
        "user_type": "AssumedRole",
        "source_ip": "10.0.1.100",
        "aws_region": "us-east-1",
        "resources": [
          {
            "resource_type": "AWS::EC2::Instance",
            "resource_name": "i-0fedcba0987654321"
          }
        ],
        "request_parameters": {
          "instanceType": "t3.small",
          "minCount": 2,
          "maxCount": 2,
          "imageId": "ami-0fedcba0987654321"
        }
      },
      {
        "event_time": "2024-01-14T16:30:18Z",
        "event_name": "RunInstances",
        "user_name": "deployment-pipeline",
        "user_type": "AssumedRole",
        "source_ip": "192.168.1.50",
        "aws_region": "us-east-1",
        "resources": [
          {
            "resource_type": "AWS::EC2::Instance",
            "resource_name": "i-0123456789abcdef0"
          }
        ]
      }
    ],
    "total_events": 3,
    "truncated": false
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-cloudtrail-004",
  "timestamp": "2024-01-15T10:17:30Z"
}
```

## Write Operations

### 5. reboot_ec2 (Approval Required)

**Description**: Reboot an EC2 instance with approval workflow

#### Step 1: Propose Action Request
```json
{
  "operation": "propose_action",
  "parameters": {
    "action": "reboot_ec2",
    "instance_id": "i-1234567890abcdef0",
    "reason": "High memory utilization causing application timeouts"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Step 1: Propose Action Response
```json
{
  "success": true,
  "approval_required": true,
  "approval_token": "approve-abc123def456ghi789",
  "expires_at": "2024-01-15T10:33:00Z",
  "action_summary": "Reboot EC2 instance i-1234567890abcdef0",
  "risk_assessment": {
    "risk_level": "medium",
    "impact_analysis": {
      "downtime_estimate": "2-5 minutes",
      "affected_services": ["web-application", "api-gateway"],
      "recovery_time": "automatic",
      "business_impact": "minimal - load balancer will route traffic to other instances"
    },
    "prerequisites_check": {
      "instance_tagged": true,
      "instance_state": "running",
      "load_balancer_healthy": true,
      "backup_instances_available": 2
    }
  },
  "approval_instructions": {
    "message": "To proceed with this action, respond with: approve token:approve-abc123def456ghi789",
    "expires_in_minutes": 15,
    "can_be_denied": true,
    "denial_command": "deny token:approve-abc123def456ghi789"
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-reboot-propose-005",
  "timestamp": "2024-01-15T10:18:00Z"
}
```

#### Step 2: Approve Action Request
```json
{
  "operation": "approve_action",
  "parameters": {
    "token": "approve-abc123def456ghi789"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Step 2: Approve Action Response (SANDBOX_LIVE)
```json
{
  "success": true,
  "action_executed": true,
  "approval_details": {
    "token": "approve-abc123def456ghi789",
    "approved_by": "engineer@company.com",
    "approved_at": "2024-01-15T10:20:15Z",
    "original_request_time": "2024-01-15T10:18:00Z"
  },
  "execution_details": {
    "operation": "reboot_ec2",
    "instance_id": "i-1234567890abcdef0",
    "execution_status": "initiated",
    "aws_request_id": "12345678-1234-1234-1234-123456789012",
    "expected_completion": "2024-01-15T10:25:15Z"
  },
  "monitoring_info": {
    "check_status_command": "Get status of EC2 instance i-1234567890abcdef0",
    "recommended_wait_time": "3-5 minutes",
    "recovery_indicators": [
      "Instance state changes to 'running'",
      "System status checks pass",
      "Application health checks resume"
    ]
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-reboot-approve-005",
  "timestamp": "2024-01-15T10:20:15Z"
}
```

#### Step 2: Approve Action Response (DRY_RUN)
```json
{
  "success": true,
  "action_executed": false,
  "simulation_result": {
    "operation": "reboot_ec2",
    "instance_id": "i-1234567890abcdef0",
    "execution_status": "WOULD_EXECUTE",
    "message": "DRY RUN: Would reboot instance i-1234567890abcdef0. No actual changes made.",
    "validation_checks": {
      "instance_exists": true,
      "instance_tagged": true,
      "instance_state": "running",
      "permissions_valid": true
    }
  },
  "execution_mode": "DRY_RUN",
  "correlation_id": "req-reboot-approve-005",
  "timestamp": "2024-01-15T10:20:15Z"
}
```

### 6. scale_ecs_service (Approval Required)

**Description**: Scale ECS service desired count with approval workflow

#### Step 1: Propose Action Request
```json
{
  "operation": "propose_action",
  "parameters": {
    "action": "scale_ecs_service",
    "cluster": "production-cluster",
    "service": "web-service",
    "desired_count": 5,
    "reason": "Increased traffic during peak hours"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Step 1: Propose Action Response
```json
{
  "success": true,
  "approval_required": true,
  "approval_token": "approve-xyz789abc123def456",
  "expires_at": "2024-01-15T10:35:30Z",
  "action_summary": "Scale ECS service web-service in production-cluster from 3 to 5 tasks",
  "risk_assessment": {
    "risk_level": "low",
    "impact_analysis": {
      "current_desired_count": 3,
      "new_desired_count": 5,
      "scaling_direction": "up",
      "resource_impact": "Additional 2 tasks will consume ~1GB memory and 0.5 vCPU",
      "cost_impact": "Estimated additional cost: $15/day"
    },
    "prerequisites_check": {
      "service_exists": true,
      "service_tagged": true,
      "cluster_capacity": "sufficient",
      "service_health": "stable"
    }
  },
  "approval_instructions": {
    "message": "To proceed with scaling, respond with: approve token:approve-xyz789abc123def456",
    "expires_in_minutes": 15
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-scale-propose-006",
  "timestamp": "2024-01-15T10:20:30Z"
}
```

#### Step 2: Approve Action Response
```json
{
  "success": true,
  "action_executed": true,
  "execution_details": {
    "operation": "scale_ecs_service",
    "cluster": "production-cluster",
    "service": "web-service",
    "previous_desired_count": 3,
    "new_desired_count": 5,
    "execution_status": "scaling_in_progress",
    "aws_request_id": "87654321-4321-4321-4321-210987654321"
  },
  "scaling_progress": {
    "current_running_count": 3,
    "target_count": 5,
    "pending_count": 2,
    "estimated_completion": "2024-01-15T10:25:00Z"
  },
  "monitoring_info": {
    "check_progress_command": "Get ECS service status for web-service in production-cluster",
    "scaling_indicators": [
      "Running count increases to 5",
      "All tasks pass health checks",
      "Service reaches steady state"
    ]
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-scale-approve-006",
  "timestamp": "2024-01-15T10:22:45Z"
}
```

## Workflow Operations

### 7. create_incident_record

**Description**: Create incident record for workflow management

#### Sample Request
```json
{
  "operation": "create_incident_record",
  "parameters": {
    "summary": "High CPU utilization on production web servers",
    "severity": "medium",
    "links": [
      "https://console.aws.amazon.com/ec2/v2/home#Instances:instanceId=i-1234567890abcdef0",
      "https://monitoring.company.com/dashboard/production-web",
      "https://grafana.company.com/d/ec2-overview/ec2-overview"
    ],
    "additional_context": {
      "affected_instances": ["i-1234567890abcdef0", "i-0987654321fedcba0"],
      "symptoms": "Response times increased by 200%, error rate at 2.5%",
      "initial_actions": "Scaled ECS service from 3 to 5 tasks"
    }
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Sample Response
```json
{
  "success": true,
  "incident_created": true,
  "incident_details": {
    "incident_id": "INC-2024-001234",
    "summary": "High CPU utilization on production web servers",
    "severity": "medium",
    "status": "open",
    "created_at": "2024-01-15T10:25:00Z",
    "created_by": "engineer@company.com",
    "assigned_to": "ops-team",
    "priority": "P2",
    "links": [
      "https://console.aws.amazon.com/ec2/v2/home#Instances:instanceId=i-1234567890abcdef0",
      "https://monitoring.company.com/dashboard/production-web",
      "https://grafana.company.com/d/ec2-overview/ec2-overview"
    ],
    "tags": ["production", "high-cpu", "web-servers", "performance"]
  },
  "notifications": {
    "teams_channel": {
      "sent": true,
      "channel": "ops-alerts",
      "message_id": "msg-123456789"
    },
    "email": {
      "sent": true,
      "recipients": ["ops-team@company.com", "on-call@company.com"]
    },
    "pagerduty": {
      "sent": false,
      "reason": "Severity below P1 threshold"
    }
  },
  "tracking_info": {
    "incident_url": "https://incidents.company.com/INC-2024-001234",
    "update_command": "Update incident INC-2024-001234 with status resolved",
    "escalation_policy": "Escalate to P1 if not resolved in 4 hours"
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-incident-007",
  "timestamp": "2024-01-15T10:25:00Z"
}
```

### 8. post_summary_to_channel

**Description**: Post operational summary to Teams channel or webhook

#### Sample Request
```json
{
  "operation": "post_summary_to_channel",
  "parameters": {
    "text": "🟢 **System Status Update**\n\n**Incident**: INC-2024-001234 - High CPU utilization\n**Status**: Resolved\n**Resolution**: Scaled ECS service from 3 to 5 tasks\n**Duration**: 45 minutes\n**Impact**: Minimal - no service disruption\n\n**Actions Taken**:\n• Identified high CPU on i-1234567890abcdef0\n• Scaled web-service from 3 to 5 tasks\n• Verified system stability\n• Updated monitoring thresholds\n\n**Next Steps**:\n• Monitor for 24 hours\n• Review capacity planning\n• Update runbooks",
    "channel": "ops-alerts",
    "format": "markdown"
  },
  "user_context": {
    "user_id": "engineer@company.com",
    "teams_tenant": "company.onmicrosoft.com"
  }
}
```

#### Sample Response
```json
{
  "success": true,
  "message_posted": true,
  "posting_details": {
    "channel": "ops-alerts",
    "message_id": "msg-987654321",
    "posted_at": "2024-01-15T10:30:15Z",
    "format": "markdown",
    "character_count": 456
  },
  "delivery_confirmation": {
    "teams_webhook": {
      "status": "delivered",
      "response_code": 200,
      "delivery_time_ms": 245
    },
    "backup_channels": {
      "slack": {
        "attempted": false,
        "reason": "Primary delivery successful"
      },
      "email": {
        "attempted": false,
        "reason": "Primary delivery successful"
      }
    }
  },
  "message_preview": {
    "title": "System Status Update",
    "summary": "Incident INC-2024-001234 resolved - High CPU utilization fixed by scaling ECS service",
    "urgency": "normal"
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-channel-post-008",
  "timestamp": "2024-01-15T10:30:15Z"
}
```

## Error Responses

### Authentication Error
```json
{
  "success": false,
  "error": {
    "code": "AUTHENTICATION_FAILED",
    "message": "Invalid API key or user not authorized",
    "details": {
      "user_id": "unauthorized@company.com",
      "reason": "User not in allowed users list"
    }
  },
  "correlation_id": "req-error-001",
  "timestamp": "2024-01-15T10:35:00Z"
}
```

### Validation Error
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid parameters provided",
    "details": {
      "field": "instance_id",
      "provided_value": "invalid-instance-id",
      "expected_format": "i-xxxxxxxxxxxxxxxxx",
      "validation_rule": "Must be a valid EC2 instance ID"
    }
  },
  "correlation_id": "req-error-002",
  "timestamp": "2024-01-15T10:36:00Z"
}
```

### Resource Not Found Error
```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "EC2 instance not found or not accessible",
    "details": {
      "resource_type": "EC2Instance",
      "resource_id": "i-nonexistent123456",
      "possible_causes": [
        "Instance does not exist",
        "Instance in different region",
        "Insufficient permissions"
      ]
    }
  },
  "correlation_id": "req-error-003",
  "timestamp": "2024-01-15T10:37:00Z"
}
```

### Tag Validation Error
```json
{
  "success": false,
  "error": {
    "code": "TAG_VALIDATION_FAILED",
    "message": "Resource not tagged for OpsAgent management",
    "details": {
      "resource_id": "i-1234567890abcdef0",
      "required_tag": "OpsAgentManaged=true",
      "current_tags": [
        {"Key": "Name", "Value": "web-server"},
        {"Key": "Environment", "Value": "production"}
      ],
      "remediation": "Add tag 'OpsAgentManaged=true' to the resource"
    }
  },
  "correlation_id": "req-error-004",
  "timestamp": "2024-01-15T10:38:00Z"
}
```

### Approval Token Error
```json
{
  "success": false,
  "error": {
    "code": "APPROVAL_TOKEN_INVALID",
    "message": "Approval token is invalid or expired",
    "details": {
      "token": "approve-expired123456",
      "reason": "Token expired",
      "expired_at": "2024-01-15T10:25:00Z",
      "current_time": "2024-01-15T10:40:00Z",
      "remediation": "Generate a new approval token by re-proposing the action"
    }
  },
  "correlation_id": "req-error-005",
  "timestamp": "2024-01-15T10:40:00Z"
}
```

### AWS Service Error
```json
{
  "success": false,
  "error": {
    "code": "AWS_SERVICE_ERROR",
    "message": "AWS service temporarily unavailable",
    "details": {
      "service": "EC2",
      "aws_error_code": "ServiceUnavailable",
      "aws_error_message": "The service is temporarily unavailable",
      "retry_after": 30,
      "correlation_id": "aws-req-123456789"
    }
  },
  "correlation_id": "req-error-006",
  "timestamp": "2024-01-15T10:41:00Z"
}
```

## Execution Modes

### LOCAL_MOCK Mode Responses

All operations in LOCAL_MOCK mode return simulated data:

```json
{
  "success": true,
  "summary": "Mock: Operation completed successfully",
  "details": {
    "mock": true,
    "execution_mode": "LOCAL_MOCK",
    "note": "This is simulated data for testing purposes",
    "simulated_data": {
      "operation_result": "success",
      "mock_values": true
    }
  },
  "execution_mode": "LOCAL_MOCK",
  "correlation_id": "req-mock-001",
  "timestamp": "2024-01-15T10:42:00Z"
}
```

### DRY_RUN Mode Responses

Write operations in DRY_RUN mode show what would happen:

```json
{
  "success": true,
  "summary": "DRY RUN: Would execute reboot_ec2 on i-1234567890abcdef0",
  "details": {
    "operation": "reboot_ec2",
    "instance_id": "i-1234567890abcdef0",
    "execution_status": "WOULD_EXECUTE",
    "validation_checks": {
      "instance_exists": true,
      "instance_tagged": true,
      "permissions_valid": true
    },
    "simulated_outcome": "Instance would be rebooted successfully"
  },
  "execution_mode": "DRY_RUN",
  "correlation_id": "req-dryrun-001",
  "timestamp": "2024-01-15T10:43:00Z"
}
```

### SANDBOX_LIVE Mode Responses

Operations in SANDBOX_LIVE mode execute against real AWS resources:

```json
{
  "success": true,
  "summary": "Instance i-1234567890abcdef0 reboot initiated successfully",
  "details": {
    "operation": "reboot_ec2",
    "instance_id": "i-1234567890abcdef0",
    "execution_status": "initiated",
    "aws_request_id": "12345678-1234-1234-1234-123456789012",
    "real_execution": true
  },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-live-001",
  "timestamp": "2024-01-15T10:44:00Z"
}
```

## Response Format Standards

All plugin responses follow these standards:

### Required Fields
- `success`: Boolean indicating operation success
- `execution_mode`: Current execution mode
- `correlation_id`: Unique request identifier
- `timestamp`: ISO 8601 timestamp

### Success Response Structure
```json
{
  "success": true,
  "summary": "Human-readable summary",
  "details": { /* Operation-specific details */ },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-unique-id",
  "timestamp": "2024-01-15T10:45:00Z"
}
```

### Error Response Structure
```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": { /* Error-specific details */ }
  },
  "correlation_id": "req-unique-id",
  "timestamp": "2024-01-15T10:45:00Z"
}
```

### Approval Response Structure
```json
{
  "success": true,
  "approval_required": true,
  "approval_token": "approve-token-string",
  "expires_at": "2024-01-15T11:00:00Z",
  "action_summary": "Action description",
  "risk_assessment": { /* Risk analysis */ },
  "approval_instructions": { /* How to approve */ },
  "execution_mode": "SANDBOX_LIVE",
  "correlation_id": "req-unique-id",
  "timestamp": "2024-01-15T10:45:00Z"
}
```

This comprehensive sample documentation provides Amazon Q Business integrators with complete examples of all plugin operations, including various execution modes and error scenarios.