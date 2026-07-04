resource "aws_cloudwatch_log_group" "audit" {
  name              = "/aws/lambda/opsagent-audit-${var.environment}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.opsagent.arn

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_cloudwatch_dashboard" "opsagent" {
  dashboard_name = "OpsAgent-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", { stat = "Sum", label = "Total Invocations" }],
            [".", "Errors", { stat = "Sum", label = "Errors", yAxis = "right" }],
            [".", "Duration", { stat = "Average", label = "Avg Duration (ms)" }],
            [".", "Throttles", { stat = "Sum", label = "Throttles", yAxis = "right" }],
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Lambda Function Metrics"
          period  = 300
          yAxis = {
            left  = { min = 0 }
            right = { min = 0 }
          }
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/DynamoDB", "ConsumedReadCapacityUnits", { stat = "Sum" }],
            [".", "ConsumedWriteCapacityUnits", { stat = "Sum" }],
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "DynamoDB Capacity Units"
          period  = 300
        }
      },
      {
        type = "log"
        properties = {
          query   = "SOURCE '${aws_cloudwatch_log_group.audit.name}'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 20"
          region  = var.aws_region
          title   = "Recent Errors"
          stacked = false
        }
      },
      {
        type = "metric"
        properties = {
          metrics = [
            ["AWS/ApiGateway", "Count", { stat = "Sum", label = "API Requests" }],
            [".", "4XXError", { stat = "Sum", label = "4XX Errors", yAxis = "right" }],
            [".", "5XXError", { stat = "Sum", label = "5XX Errors", yAxis = "right" }],
            [".", "Latency", { stat = "Average", label = "Avg Latency (ms)" }],
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "API Gateway Metrics"
          period  = 300
          yAxis = {
            left  = { min = 0 }
            right = { min = 0 }
          }
        }
      },
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "OpsAgent-${var.environment}-HighErrorRate"
  alarm_description   = "Lambda error rate exceeded 5 errors in 10 minutes"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = aws_lambda_function.opsagent_controller.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
  ok_actions          = [aws_sns_topic.notifications.arn]
}

resource "aws_cloudwatch_metric_alarm" "high_latency" {
  alarm_name          = "OpsAgent-${var.environment}-HighLatency"
  alarm_description   = "Lambda average duration exceeded 10 seconds"
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  dimensions          = { FunctionName = aws_lambda_function.opsagent_controller.function_name }
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 10000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
}

resource "aws_cloudwatch_metric_alarm" "throttles" {
  alarm_name          = "OpsAgent-${var.environment}-Throttles"
  alarm_description   = "Lambda throttling detected"
  namespace           = "AWS/Lambda"
  metric_name         = "Throttles"
  dimensions          = { FunctionName = aws_lambda_function.opsagent_controller.function_name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
}

resource "aws_cloudwatch_metric_alarm" "api_5xx_errors" {
  alarm_name          = "OpsAgent-${var.environment}-Api5xxErrors"
  alarm_description   = "API Gateway 5XX error rate elevated"
  namespace           = "AWS/ApiGateway"
  metric_name         = "5XXError"
  dimensions          = { ApiName = "opsagent-controller-${var.environment}" }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 5
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "OpsAgent-${var.environment}-DLQMessages"
  alarm_description   = "Messages arriving in the dead-letter queue"
  namespace           = "AWS/SQS"
  metric_name         = "NumberOfMessagesSent"
  dimensions          = { QueueName = aws_sqs_queue.dlq.name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.notifications.arn]
}
