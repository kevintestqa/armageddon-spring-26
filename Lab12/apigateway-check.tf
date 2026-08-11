###############################################################################
# API Gateway Checks
###############################################################################

check "asgard_api_uses_expected_configuration" {
  # Given the Asgard REST API is configured,
  # when the API configuration is checked,
  # then the API should use the asgard_api_rest name and a REGIONAL endpoint.

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
  # Given the REST API is configured with Node.js and Python resources,
  # when the resource paths are checked,
  # then the API should expose the /node and /python endpoints.

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
  # Given the REST API resources are configured with methods,
  # when the HTTP methods are checked,
  # then both endpoints should use GET.

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
  # Given the REST API methods are configured with authorization,
  # when the authorization settings are checked,
  # then both methods should use the Asgard Cognito authorizer.

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
  # Given the REST API methods are configured with authorization scopes,
  # when the scopes are checked,
  # then both methods should require the aws.cognito.signin.user.admin scope.

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
  # Given the /node endpoint is configured with a Lambda integration,
  # when the integration settings are checked,
  # then requests should be proxied to the Node.js authentication Lambda.

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
  # Given the /python endpoint is configured with a Lambda integration,
  # when the integration settings are checked,
  # then requests should be proxied to the Python authentication Lambda.

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
  # Given the REST API is configured with a deployment stage,
  # when the stage configuration is checked,
  # then the API should use the qa stage.

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
  # Given the REST API is configured with a Cognito authorizer,
  # when the authorizer settings are checked,
  # then it should use the Asgard user pool and Authorization header.

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
  # Given API Gateway is configured to invoke the Node.js Lambda,
  # when the Lambda permission is checked,
  # then API Gateway should have permission to invoke the Node.js authentication function.

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
  # Given API Gateway is configured to invoke the Python Lambda,
  # when the Lambda permission is checked,
  # then API Gateway should have permission to invoke the Python authentication function.

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