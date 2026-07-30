output "asgard_lambda_role_arn" {
  value = aws_iam_role.asgard_lambda_role.arn
}

output "asgard_api_gateway_url" {
  value = aws_api_gateway_rest_api.asgard_api_rest.execution_arn
}

output "asgard_lambda_function_arn" {
  value = aws_lambda_function.asgard_lambda_function.arn
}