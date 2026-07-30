###############################################################################
# API Gateway Checks
###############################################################################

check "asgard_api_uses_expected_configuration" {
  # Given the Asgard REST API,
  # when Terraform evaluates the API configuration,
  # then it must use the approved name and a regional endpoint.

  assert {
    condition = (
      aws_api_gateway_rest_api.asgard_api_rest.name == "asgard_api_rest"
      &&
      toset(
        aws_api_gateway_rest_api.asgard_api_rest.endpoint_configuration[0].types
      ) == toset(["REGIONAL"])
    )

    error_message = "The Asgard REST API must be named asgard_api_rest and use a REGIONAL endpoint."
  }
}

check "api_gateway_uses_expected_resource_paths" {
  # Given the Node.js and Python API resources,
  # when Terraform evaluates their resource paths,
  # then the REST API must expose the /node and /python endpoints.

  assert {
    condition = (
      aws_api_gateway_resource.node_resource.path_part == "node"
      &&
      aws_api_gateway_resource.python_resource.path_part == "python"
      &&
      aws_api_gateway_resource.node_resource.rest_api_id ==
      aws_api_gateway_rest_api.asgard_api_rest.id
      &&
      aws_api_gateway_resource.python_resource.rest_api_id ==
      aws_api_gateway_rest_api.asgard_api_rest.id
    )

    error_message = "The REST API must expose the node and python resources."
  }
}

check "api_gateway_methods_use_get" {
  # Given the REST API methods,
  # when Terraform evaluates the HTTP methods,
  # then both endpoints must use GET.

  assert {
    condition = (
      aws_api_gateway_method.node_method.http_method == "GET"
      &&
      aws_api_gateway_method.python_method.http_method == "GET"
    )

    error_message = "Both API Gateway methods must use GET."
  }
}

check "api_gateway_methods_use_cognito_authorization" {
  # Given the protected REST API methods,
  # when Terraform evaluates authorization,
  # then both methods must use Cognito User Pools.

  assert {
    condition = (
      aws_api_gateway_method.node_method.authorization ==
      "COGNITO_USER_POOLS"
      &&
      aws_api_gateway_method.python_method.authorization ==
      "COGNITO_USER_POOLS"
      &&
      aws_api_gateway_method.node_method.authorizer_id ==
      aws_api_gateway_authorizer.asgard_authorizer.id
      &&
      aws_api_gateway_method.python_method.authorizer_id ==
      aws_api_gateway_authorizer.asgard_authorizer.id
    )

    error_message = "Both API Gateway methods must use the Asgard Cognito authorizer."
  }
}

check "api_gateway_methods_use_expected_scope" {
  # Given the protected REST API methods,
  # when Terraform evaluates authorization scopes,
  # then both methods must require the administrator scope.

  assert {
    condition = (
      toset(
        aws_api_gateway_method.node_method.authorization_scopes
        ) == toset([
          "aws.cognito.signin.user.admin"
      ])
      &&
      toset(
        aws_api_gateway_method.python_method.authorization_scopes
        ) == toset([
          "aws.cognito.signin.user.admin"
      ])
    )

    error_message = "Both API Gateway methods must require the aws.cognito.signin.user.admin scope."
  }
}

check "node_api_integrates_with_node_lambda" {
  # Given the /node endpoint,
  # when Terraform evaluates the integration,
  # then it must proxy requests to the Node.js authentication Lambda.

  assert {
    condition = (
      aws_api_gateway_integration.node_integration.type ==
      "AWS_PROXY"
      &&
      aws_api_gateway_integration.node_integration.integration_http_method ==
      "POST"
      &&
      aws_api_gateway_integration.node_integration.uri ==
      aws_lambda_function.node_auth.invoke_arn
      &&
      aws_api_gateway_integration.node_integration.http_method ==
      aws_api_gateway_method.node_method.http_method
    )

    error_message = "The /node endpoint must integrate with the Node.js authentication Lambda using AWS_PROXY."
  }
}

check "python_api_integrates_with_python_lambda" {
  # Given the /python endpoint,
  # when Terraform evaluates the integration,
  # then it must proxy requests to the Python authentication Lambda.

  assert {
    condition = (
      aws_api_gateway_integration.python_integration.type ==
      "AWS_PROXY"
      &&
      aws_api_gateway_integration.python_integration.integration_http_method ==
      "POST"
      &&
      aws_api_gateway_integration.python_integration.uri ==
      aws_lambda_function.python_auth.invoke_arn
      &&
      aws_api_gateway_integration.python_integration.http_method ==
      aws_api_gateway_method.python_method.http_method
    )

    error_message = "The /python endpoint must integrate with the Python authentication Lambda using AWS_PROXY."
  }
}

check "api_gateway_uses_qa_stage" {
  # Given the REST API deployment,
  # when Terraform evaluates the deployment stage,
  # then the deployment must use the qa stage.

  assert {
    condition = (
      aws_api_gateway_stage.qa_environment.stage_name == "qa"
      &&
      aws_api_gateway_stage.qa_environment.rest_api_id ==
      aws_api_gateway_rest_api.asgard_api_rest.id
      &&
      aws_api_gateway_stage.qa_environment.deployment_id ==
      aws_api_gateway_deployment.api_deploy.id
    )

    error_message = "The REST API deployment must expose the qa stage."
  }
}

check "authorizer_uses_expected_configuration" {
  # Given the Cognito authorizer,
  # when Terraform evaluates the authorizer configuration,
  # then it must use the Asgard Cognito user pool and Authorization header.

  assert {
    condition = (
      aws_api_gateway_authorizer.asgard_authorizer.type ==
      "COGNITO_USER_POOLS"
      &&
      aws_api_gateway_authorizer.asgard_authorizer.identity_source ==
      "method.request.header.Authorization"
      &&
      toset(
        aws_api_gateway_authorizer.asgard_authorizer.provider_arns
        ) == toset([
          aws_cognito_user_pool.asgard_pool.arn
      ])
    )

    error_message = "The API authorizer must use the Asgard Cognito user pool and Authorization header."
  }
}

check "api_gateway_can_invoke_node_lambda" {
  # Given the Node.js Lambda integration,
  # when Terraform evaluates the Lambda permission,
  # then API Gateway must be allowed to invoke the Node.js function.

  assert {
    condition = (
      aws_lambda_permission.node_lambda_permission.action ==
      "lambda:InvokeFunction"
      &&
      aws_lambda_permission.node_lambda_permission.principal ==
      "apigateway.amazonaws.com"
      &&
      aws_lambda_permission.node_lambda_permission.function_name ==
      aws_lambda_function.node_auth.function_name
    )

    error_message = "API Gateway must have permission to invoke the Node.js authentication Lambda."
  }
}

check "api_gateway_can_invoke_python_lambda" {
  # Given the Python Lambda integration,
  # when Terraform evaluates the Lambda permission,
  # then API Gateway must be allowed to invoke the Python function.

  assert {
    condition = (
      aws_lambda_permission.python_lambda_permission.action ==
      "lambda:InvokeFunction"
      &&
      aws_lambda_permission.python_lambda_permission.principal ==
      "apigateway.amazonaws.com"
      &&
      aws_lambda_permission.python_lambda_permission.function_name ==
      aws_lambda_function.python_auth.function_name
    )

    error_message = "API Gateway must have permission to invoke the Python authentication Lambda."
  }
}