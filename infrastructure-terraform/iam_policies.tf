data "aws_iam_policy_document" "audit_logging" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = [
      aws_cloudwatch_log_group.audit.arn,
      aws_cloudwatch_log_group.api_gateway.arn,
    ]
  }

  statement {
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:UpdateItem",
    ]
    resources = [
      aws_dynamodb_table.audit.arn,
      aws_dynamodb_table.incidents.arn,
      aws_dynamodb_table.approval_gate.arn,
      "${aws_dynamodb_table.incidents.arn}/index/*",
    ]
  }

  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.notifications.arn]
  }

  statement {
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.opsagent.arn]
  }

  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "audit_logging" {
  name   = "OpsAgentAuditLoggingPolicy"
  role   = aws_iam_role.opsagent_execution.id
  policy = data.aws_iam_policy_document.audit_logging.json
}

data "aws_iam_policy_document" "diagnosis_tools" {
  statement {
    effect = "Allow"
    actions = [
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:GetMetricData",
      "cloudwatch:ListMetrics",
      "cloudwatch:DescribeAlarms",
      "cloudwatch:GetMetricWidgetImage",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeTags",
      "ec2:DescribeImages",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcs",
      "ec2:DescribeSubnets",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ecs:DescribeServices",
      "ecs:DescribeTasks",
      "ecs:DescribeClusters",
      "ecs:DescribeTaskDefinition",
      "ecs:ListTasks",
      "ecs:ListServices",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeRules",
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "application-autoscaling:DescribeScalingPolicies",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeScalingActivities",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
      "logs:FilterLogEvents",
      "cloudtrail:LookupEvents",
      "cloudtrail:DescribeTrails",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "diagnosis_tools" {
  name   = "OpsAgentDiagnosisToolsPolicy"
  role   = aws_iam_role.opsagent_execution.id
  policy = data.aws_iam_policy_document.diagnosis_tools.json
}

data "aws_iam_policy_document" "remediation_tools" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:RebootInstances",
      "ec2:StartInstances",
      "ec2:StopInstances",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/OpsAgentManaged"
      values   = ["true"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "ecs:UpdateService",
      "ecs:RestartTask",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/OpsAgentManaged"
      values   = ["true"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:UpdateAutoScalingGroup",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/OpsAgentManaged"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role_policy" "remediation_tools" {
  name   = "OpsAgentRemediationToolsPolicy"
  role   = aws_iam_role.opsagent_execution.id
  policy = data.aws_iam_policy_document.remediation_tools.json
}

data "aws_iam_policy_document" "llm_provider" {
  statement {
    effect = "Allow"
    actions = [
      "bedrock:InvokeModel",
      "bedrock:InvokeModelWithResponseStream",
    ]
    resources = ["arn:aws:bedrock:${var.aws_region}::foundation-model/anthropic.*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]
    resources = ["arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/opsagent/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["arn:aws:secretsmanager:${var.aws_region}:${data.aws_caller_identity.current.account_id}:secret:opsagent/*"]
  }
}

resource "aws_iam_role_policy" "llm_provider" {
  name   = "OpsAgentLLMProviderPolicy"
  role   = aws_iam_role.opsagent_execution.id
  policy = data.aws_iam_policy_document.llm_provider.json
}

data "aws_iam_policy_document" "system" {
  statement {
    effect    = "Allow"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "system" {
  name   = "OpsAgentSystemPolicy"
  role   = aws_iam_role.opsagent_execution.id
  policy = data.aws_iam_policy_document.system.json
}

# Generic read-only access to all AWS services for the aws_read tool
data "aws_iam_policy_document" "generic_read" {
  statement {
    sid    = "AllowDescribeListGet"
    effect = "Allow"
    actions = [
      "s3:ListBucket",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketTagging",
      "rds:DescribeDBInstances",
      "rds:DescribeDBClusters",
      "rds:ListTagsForResource",
      "lambda:ListFunctions",
      "lambda:GetFunction",
      "lambda:ListEventSourceMappings",
      "ecs:DescribeServices",
      "ecs:DescribeClusters",
      "ecs:DescribeTasks",
      "ecs:ListClusters",
      "ecs:ListServices",
      "ecs:ListTasks",
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:GetHealthCheck",
      "dynamodb:ListTables",
      "dynamodb:DescribeTable",
      "sqs:ListQueues",
      "sqs:GetQueueAttributes",
      "sns:ListTopics",
      "sns:ListSubscriptions",
      "sns:GetTopicAttributes",
      "elasticache:DescribeCacheClusters",
      "elasticache:DescribeReplicationGroups",
      "cloudfront:ListDistributions",
      "cloudfront:GetDistribution",
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeLaunchConfigurations",
      "eks:ListClusters",
      "eks:DescribeCluster",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "kms:ListKeys",
      "kms:DescribeKey",
      "kms:ListAliases",
      "secretsmanager:ListSecrets",
      "ssm:DescribeParameters",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeListeners",
      "apigateway:GET",
      "tag:GetResources",
      "tag:GetTagKeys",
      "resource-groups:ListGroups",
      "resource-groups:ListGroupResources",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "generic_read" {
  name   = "OpsAgentGenericReadPolicy"
  role   = aws_iam_role.opsagent_execution.id
  policy = data.aws_iam_policy_document.generic_read.json
}
