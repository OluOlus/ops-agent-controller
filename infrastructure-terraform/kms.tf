data "aws_iam_policy_document" "opsagent_kms" {
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
  }

  statement {
    sid    = "AllowLambdaFunction"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.opsagent_execution.arn]
    }
  }
}

resource "aws_kms_key" "opsagent" {
  description             = "KMS Key for OpsAgent Controller encryption"
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.opsagent_kms.json

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_kms_alias" "opsagent" {
  name          = "alias/opsagent-${var.environment}"
  target_key_id = aws_kms_key.opsagent.key_id
}
