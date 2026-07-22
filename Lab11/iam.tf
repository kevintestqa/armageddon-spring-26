resource "aws_iam_role" "odin_lambda_role" {
  name = "odin_lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "odin_lambda_vpc_execution" {
  role       = aws_iam_role.odin_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_app_policy_attachment" {
  role       = aws_iam_role.odin_lambda_role.name
  policy_arn = aws_iam_policy.odin_lambda_app_policy.arn
}

resource "aws_iam_policy" "odin_lambda_app_policy" {
  name        = "odin_lambda_app_policy"
  description = "Allows Lambda to filter logs, invoke Bedrock, and retrieve RDS credentials from Secrets Manager."

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:FilterLogEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = aws_secretsmanager_secret.odin_db_secret.arn
      }
    ]
  })
}