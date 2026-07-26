######
#https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_resource_server 
#https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints-oauth-grants.html 
#Cognito resource server
resource "aws_cognito_resource_server" "asgard_resource" {
  identifier = "asgard_api_rest"
  name       = "RBAC REST API"

  scope {
    scope_name        = "admin-scope"
    scope_description = "Admin level permissions"
  }

  scope {
    scope_name        = "user-scope"
    scope_description = "User level permissions"
  }

  user_pool_id = aws_cognito_user_pool.asgard_pool.id
}

# Cognito user pool 1
#https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool

resource "aws_cognito_user_pool" "asgard_pool" {
  name                     = "asgard_pool"
  auto_verified_attributes = ["email"]
  mfa_configuration        = "ON"

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length    = 8
    require_symbols   = false
    require_uppercase = true
    require_lowercase = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }

    recovery_mechanism {
      name     = "verified_phone_number"
      priority = 2
    }
  }
}

#cognito user pool client
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cognito_user_pool_client

resource "aws_cognito_user_pool_client" "asgard_client" {
  name                                 = "asgard_client"
  user_pool_id                         = aws_cognito_user_pool.asgard_pool.id
  callback_urls                        = ["https://localhost/callback"]
  logout_urls                          = ["https://localhost/logout"]
  generate_secret                      = false
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes = [
    "email",
    "openid",
    "profile",
    "${aws_cognito_resource_server.asgard_resource.identifier}/admin-scope",
    "${aws_cognito_resource_server.asgard_resource.identifier}/user-scope"
  ]

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]

  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }

  //supported_identity_providers = ["COGNITO"]
}

//login page domain for cognito user pool
resource "aws_user_pool_domain" "asgard_domain" {
  domain       = "asgard-domain"
  user_pool_id = aws_cognito_user_pool.asgard_pool.id
}

resource "aws_cognito_managed_login_branding" "client" {
  client_id    = aws_cognito_user_pool_client.asgard_client.id
  user_pool_id = aws_cognito_user_pool.asgard_pool.id

  use_cognito_provided_values = true
}
resource "aws_cognito_user_group" "asgard_user_group" {
  name         = "asgard_user_group"
  user_pool_id = aws_cognito_user_pool.asgard_pool.id
  description  = "Managed by Terraform"
  precedence   = 10
  // role_arn     = aws_iam_role.group_role.arn
}

resource "aws_cognito_user_group" "asgard_admin_group" {
  name         = "asgard_admin_group"
  user_pool_id = aws_cognito_user_pool.asgard_pool.id
  description  = "Managed by Terraform"
  precedence   = 1
  // role_arn     = aws_iam_role.group_role.arn
}

resource "aws_cognito_user" "odin" {
    user_pool_id = aws_cognito_user_pool.asgard_pool.id
    username = "odin"
    password = "Password123!"

    attributes = {
      "email" = "kevinwillocks@icloud.com"
      email_verified = true
    }
}

resource "aws_cognito_user" "thor" {
    user_pool_id = aws_cognito_user_pool.asgard_pool.id
    username = "thor"
    password = "Password123!!"

    attributes = {
      "email" = "kevinwillocks@gmail.com"
      email_verified = true
    }
}

resource "aws_cognito_user_in_group" "odin_admin" {
  user_pool_id = aws_cognito_user_pool.asgard_pool.id
  username     = aws_cognito_user.odin.username
  group_name   = aws_cognito_user_group.asgard_admin_group.name
}

resource "aws_cognito_user_in_group" "thor_general" {
  user_pool_id = aws_cognito_user_pool.asgard_pool.id
  username     = aws_cognito_user.thor.username
  group_name   = aws_cognito_user_group.asgard_user_group.name
}

