resource "aws_sqs_queue" "dlq" {
  name                      = "opsagent-dlq-${var.environment}"
  message_retention_seconds = 1209600 # 14 days
  kms_master_key_id         = aws_kms_key.opsagent.key_id
}

resource "aws_sns_topic" "notifications" {
  name              = "opsagent-notifications-${var.environment}"
  display_name      = "OpsAgent Notifications"
  kms_master_key_id = aws_kms_key.opsagent.key_id
}
