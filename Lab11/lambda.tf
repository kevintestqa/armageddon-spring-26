data "archive_file" "handler_py" {
  type        = "zip"
  source_file = "${path.module}/Lambda/Python_Src/handler.py"
  output_path = "${path.module}/Lambda/Python_Src/handler.zip"
}
# Lambda function
resource "aws_lambda_function" "handler_py" {
  filename      = data.archive_file.handler_py.output_path
  function_name = "handler_lambda_function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "handler.lambda_handler"
  code_sha256   = data.archive_file.handler_py.output_base64sha256

  runtime = "python3.14"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
    }
  }
}

data "archive_file" "lambda_function" {
  type        = "zip"
  source_file = "${path.module}/Lambda/Python_Src/lambda_function.py"
  output_path = "${path.module}/Lambda/Python_Src/lambda_function.zip"
}
# Lambda function
resource "aws_lambda_function" "lambda_function" {
  filename      = data.archive_file.lambda_function.output_path
  function_name = "python_lambda_function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  code_sha256   = data.archive_file.lambda_function.output_base64sha256

  runtime = "python3.14"

  environment {
    variables = {
      ENVIRONMENT = "production"
      LOG_LEVEL   = "info"
    }
  }
}