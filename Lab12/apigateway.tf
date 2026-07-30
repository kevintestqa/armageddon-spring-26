data "aws_region" "current" {}
data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

resource "aws_api_gateway_rest_api" "asgard_api_rest" {
  name = "asgard_api_rest"

  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# #Node Resources
resource "aws_api_gateway_resource" "node_resource" {
  rest_api_id = aws_api_gateway_rest_api.asgard_api_rest.id
  parent_id   = aws_api_gateway_rest_api.asgard_api_rest.root_resource_id
  path_part   = "node"
}

resource "aws_api_gateway_method" "node_method" {
  rest_api_id          = aws_api_gateway_rest_api.asgard_api_rest.id
  resource_id          = aws_api_gateway_resource.node_resource.id
  http_method          = "GET"
  authorization        = "COGNITO_USER_POOLS"
  authorizer_id        = aws_api_gateway_authorizer.asgard_authorizer.id
  authorization_scopes = ["aws.cognito.signin.user.admin"]
}

resource "aws_api_gateway_integration" "node_integration" {
  rest_api_id             = aws_api_gateway_rest_api.asgard_api_rest.id
  resource_id             = aws_api_gateway_resource.node_resource.id
  http_method             = aws_api_gateway_method.node_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.node_auth.invoke_arn
}

resource "aws_api_gateway_deployment" "api_deploy" {
  rest_api_id = aws_api_gateway_rest_api.asgard_api_rest.id

  triggers = {
    # NOTE: The configuration below will satisfy ordering considerations,
    #       but not pick up all future REST API changes. More advanced patterns
    #       are possible, such as using the filesha1() function against the
    #       Terraform configuration file(s) or removing the .id references to
    #       calculate a hash against whole resources. Be aware that using whole
    #       resources will show a difference after the initial implementation.
    #       It will stabilize to only change when resources change afterwards.
    redeployment = sha1(jsonencode([
      aws_api_gateway_resource.node_resource.id,
      aws_api_gateway_method.node_method.id,
      aws_api_gateway_integration.node_integration.id,
      aws_api_gateway_resource.python_resource.id,
      aws_api_gateway_method.python_method.id,
      aws_api_gateway_integration.python_integration.id
    ]))
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_api_gateway_stage" "qa_environment" {
  deployment_id = aws_api_gateway_deployment.api_deploy.id
  rest_api_id   = aws_api_gateway_rest_api.asgard_api_rest.id
  stage_name    = "qa"
}

# //Python Resources
resource "aws_api_gateway_resource" "python_resource" {
  rest_api_id = aws_api_gateway_rest_api.asgard_api_rest.id
  parent_id   = aws_api_gateway_rest_api.asgard_api_rest.root_resource_id
  path_part   = "python"
}

resource "aws_api_gateway_method" "python_method" {
  rest_api_id          = aws_api_gateway_rest_api.asgard_api_rest.id
  resource_id          = aws_api_gateway_resource.python_resource.id
  http_method          = "GET"
  authorization        = "COGNITO_USER_POOLS"
  authorizer_id        = aws_api_gateway_authorizer.asgard_authorizer.id
  authorization_scopes = ["aws.cognito.signin.user.admin"]
}

resource "aws_api_gateway_integration" "python_integration" {
  rest_api_id             = aws_api_gateway_rest_api.asgard_api_rest.id
  resource_id             = aws_api_gateway_resource.python_resource.id
  http_method             = aws_api_gateway_method.python_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.python_auth.invoke_arn
}


resource "aws_lambda_permission" "python_lambda_permission" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.python_auth.function_name
  principal     = "apigateway.amazonaws.com"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  source_arn = "arn:${data.aws_partition.current.partition}:execute-api:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.asgard_api_rest.id}/*/*"
}

resource "aws_lambda_permission" "node_lambda_permission" {
  statement_id  = "AllowMyDemoAPIInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.node_auth.function_name
  principal     = "apigateway.amazonaws.com"

  # The /* part allows invocation from any stage, method and resource path
  # within API Gateway.
  source_arn = "arn:${data.aws_partition.current.partition}:execute-api:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:${aws_api_gateway_rest_api.asgard_api_rest.id}/*/*"
}

resource "aws_api_gateway_authorizer" "asgard_authorizer" {
  name        = "CognitoUserPoolAuthorizer"
  rest_api_id = aws_api_gateway_rest_api.asgard_api_rest.id

  type = "COGNITO_USER_POOLS"
  provider_arns = [
    aws_cognito_user_pool.asgard_pool.arn
  ]

  identity_source = "method.request.header.Authorization"
}