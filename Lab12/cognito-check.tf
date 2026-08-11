###############################################################################
# Cognito Checks
###############################################################################

check "cognito_resource_server_uses_expected_scopes" {
  # Given the Asgard Cognito resource server is configured with OAuth scopes,
  # when the resource server configuration is checked,
  # then it should use the Asgard API identifier and expose the admin and user scopes.

  assert {
    condition = (
      aws_cognito_resource_server.asgard_resource.identifier ==
      "asgard_api_rest"
      &&
      aws_cognito_resource_server.asgard_resource.name ==
      "RBAC REST API"
      &&
      toset([
        for scope in aws_cognito_resource_server.asgard_resource.scope :
        scope.scope_name
        ]) == toset([
        "admin-scope",
        "user-scope"
      ])
      &&
      aws_cognito_resource_server.asgard_resource.user_pool_id ==
      aws_cognito_user_pool.asgard_pool.id
    )

    error_message = "The Cognito resource server must use the asgard_api_rest identifier and expose exactly admin-scope and user-scope."
  }
}

check "cognito_user_pool_requires_mfa" {
  # Given the Asgard Cognito user pool is configured with MFA,
  # when the MFA settings are checked,
  # then MFA and software-token MFA should be enabled.

  assert {
    condition = (
      aws_cognito_user_pool.asgard_pool.mfa_configuration == "ON"
      &&
      aws_cognito_user_pool.asgard_pool
      .software_token_mfa_configuration[0]
      .enabled == true
    )

    error_message = "The Asgard Cognito user pool must require MFA and enable software-token MFA."
  }
}

check "cognito_user_pool_uses_expected_password_policy" {
  # Given the Asgard Cognito user pool is configured with a password policy,
  # when the password policy is checked,
  # then passwords should require at least eight characters with uppercase and lowercase letters.

  assert {
    condition = (
      aws_cognito_user_pool.asgard_pool
      .password_policy[0]
      .minimum_length == 8
      &&
      aws_cognito_user_pool.asgard_pool
      .password_policy[0]
      .require_uppercase == true
      &&
      aws_cognito_user_pool.asgard_pool
      .password_policy[0]
      .require_lowercase == true
      &&
      aws_cognito_user_pool.asgard_pool
      .password_policy[0]
      .require_symbols == false
    )

    error_message = "The Asgard Cognito password policy must require at least eight characters with uppercase and lowercase letters."
  }
}

check "cognito_user_pool_auto_verifies_email" {
  # Given the Asgard Cognito user pool is configured with automatic verification,
  # when the verified attributes are checked,
  # then email should be the only automatically verified attribute.

  assert {
    condition = (
      toset(
        aws_cognito_user_pool.asgard_pool.auto_verified_attributes
        ) == toset([
          "email"
      ])
    )

    error_message = "The Asgard Cognito user pool must automatically verify email addresses."
  }
}

check "cognito_user_pool_uses_expected_recovery_methods" {
  # Given the Asgard Cognito user pool is configured with account recovery methods,
  # when the recovery methods are checked,
  # then verified email should have first priority and verified phone should have second priority.

  assert {
    condition = (
      length([
        for mechanism in aws_cognito_user_pool.asgard_pool
        .account_recovery_setting[0]
        .recovery_mechanism :
        mechanism

        if mechanism.name == "verified_email"
        && mechanism.priority == 1
      ]) == 1
      &&
      length([
        for mechanism in aws_cognito_user_pool.asgard_pool
        .account_recovery_setting[0]
        .recovery_mechanism :
        mechanism

        if mechanism.name == "verified_phone_number"
        && mechanism.priority == 2
      ]) == 1
    )

    error_message = "Account recovery must prioritize verified email first and verified phone number second."
  }
}

check "cognito_client_uses_authorization_code_flow" {
  # Given the Asgard Cognito application client is configured for OAuth,
  # when the OAuth flow settings are checked,
  # then it should use the authorization-code flow without a generated client secret.

  assert {
    condition = (
      aws_cognito_user_pool_client.asgard_client.generate_secret ==
      false
      &&
      aws_cognito_user_pool_client.asgard_client
      .allowed_oauth_flows_user_pool_client == true
      &&
      toset(
        aws_cognito_user_pool_client.asgard_client.allowed_oauth_flows
        ) == toset([
          "code"
      ])
    )

    error_message = "The Asgard Cognito client must use the authorization-code OAuth flow without a generated client secret."
  }
}

check "cognito_client_uses_expected_oauth_scopes" {
  # Given the Asgard Cognito application client is configured with OAuth scopes,
  # when the allowed scopes are checked,
  # then it should include the identity scopes and both Asgard API scopes.

  assert {
    condition = (
      toset(
        aws_cognito_user_pool_client.asgard_client.allowed_oauth_scopes
        ) == toset([
          "email",
          "openid",
          "profile",
          "${aws_cognito_resource_server.asgard_resource.identifier}/admin-scope",
          "${aws_cognito_resource_server.asgard_resource.identifier}/user-scope"
      ])
    )

    error_message = "The Asgard Cognito client must use email, openid, profile, admin-scope, and user-scope."
  }
}

check "cognito_client_uses_expected_authentication_flows" {
  # Given the Asgard Cognito application client is configured with authentication flows,
  # when the explicit authentication flows are checked,
  # then password, SRP, and refresh-token authentication should be enabled.

  assert {
    condition = (
      toset(
        aws_cognito_user_pool_client.asgard_client.explicit_auth_flows
        ) == toset([
          "ALLOW_USER_PASSWORD_AUTH",
          "ALLOW_USER_SRP_AUTH",
          "ALLOW_REFRESH_TOKEN_AUTH"
      ])
    )

    error_message = "The Asgard Cognito client must allow password, SRP, and refresh-token authentication flows."
  }
}

check "cognito_groups_use_expected_precedence" {
  # Given the Asgard Cognito administrator and general-user groups are configured,
  # when the group precedence values are checked,
  # then the administrator group should have higher priority than the general-user group.

  assert {
    condition = (
      aws_cognito_user_group.asgard_admin_group.precedence == 1
      &&
      aws_cognito_user_group.asgard_user_group.precedence == 10
      &&
      aws_cognito_user_group.asgard_admin_group.precedence <
      aws_cognito_user_group.asgard_user_group.precedence
    )

    error_message = "The administrator Cognito group must have higher priority than the general user group."
  }
}

check "cognito_users_use_expected_user_pool" {
  # Given the Odin and Thor Cognito users are configured,
  # when their user-pool assignments are checked,
  # then both users should belong to the Asgard user pool with the expected usernames.

  assert {
    condition = (
      aws_cognito_user.odin.user_pool_id ==
      aws_cognito_user_pool.asgard_pool.id
      &&
      aws_cognito_user.thor.user_pool_id ==
      aws_cognito_user_pool.asgard_pool.id
      &&
      aws_cognito_user.odin.username == "Odin"
      &&
      aws_cognito_user.thor.username == "Thor"
    )

    error_message = "Odin and Thor must be created in the Asgard Cognito user pool with the expected usernames."
  }
}

check "odin_is_assigned_to_admin_group" {
  # Given the Odin Cognito user is configured with a group membership,
  # when Odin's group assignment is checked,
  # then Odin should belong to the Asgard administrator group.

  assert {
    condition = (
      aws_cognito_user_in_group.odin_admin.user_pool_id ==
      aws_cognito_user_pool.asgard_pool.id
      &&
      aws_cognito_user_in_group.odin_admin.username ==
      aws_cognito_user.odin.username
      &&
      aws_cognito_user_in_group.odin_admin.group_name ==
      aws_cognito_user_group.asgard_admin_group.name
    )

    error_message = "Odin must be assigned to the Asgard administrator Cognito group."
  }
}

check "thor_is_assigned_to_general_group" {
  # Given the Thor Cognito user is configured with a group membership,
  # when Thor's group assignment is checked,
  # then Thor should belong to the Asgard general-user group.

  assert {
    condition = (
      aws_cognito_user_in_group.thor_general.user_pool_id ==
      aws_cognito_user_pool.asgard_pool.id
      &&
      aws_cognito_user_in_group.thor_general.username ==
      aws_cognito_user.thor.username
      &&
      aws_cognito_user_in_group.thor_general.group_name ==
      aws_cognito_user_group.asgard_user_group.name
    )

    error_message = "Thor must be assigned to the Asgard general-user Cognito group."
  }
}