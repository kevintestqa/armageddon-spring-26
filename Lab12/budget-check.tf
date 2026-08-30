###############################################################################
# AWS Budget Checks
###############################################################################

check "asgard_budget_uses_expected_configuration" {
  # Given the Asgard monthly AWS budget is active,
  # when Terraform evaluates the budget configuration,
  # then it must use the expected cost budget settings.

  assert {
    condition = (
      aws_budgets_budget.asgard_budget.name == "asgard-budget"
      && aws_budgets_budget.asgard_budget.budget_type == "COST"
      && aws_budgets_budget.asgard_budget.limit_unit == "USD"
      && aws_budgets_budget.asgard_budget.time_unit == "MONTHLY"
      && tonumber(aws_budgets_budget.asgard_budget.limit_amount) == var.budget_limit
      && aws_budgets_budget.asgard_budget.time_period_start == var.budget_start_date
    )

    error_message = "The Asgard budget must use the expected monthly COST configuration, USD unit, configured limit amount, and configured start date."
  }
}

check "asgard_budget_uses_expected_project_tag_filter" {
  # Given the Asgard budget is scoped to the project,
  # when Terraform evaluates the budget cost filter,
  # then it must filter on the Project tag and current project name.

  assert {
    condition = (
      one(
        aws_budgets_budget.asgard_budget.cost_filter
      ).name == "TagKeyValue"
      &&
      one(
        aws_budgets_budget.asgard_budget.cost_filter
        ).values == tolist([
          "Project${"$"}${local.common_tags.Project}"
      ])
    )

    error_message = "The Asgard budget must filter costs using the Project tag and the configured project name."
  }
}

check "asgard_budget_uses_expected_cost_types" {
  # Given the Asgard budget tracks project cost,
  # when Terraform evaluates the budget cost type settings,
  # then taxes and subscriptions must be included and blended costs must be disabled.

  assert {
    condition = (
      one(
        aws_budgets_budget.asgard_budget.cost_types
      ).include_tax == true
      &&
      one(
        aws_budgets_budget.asgard_budget.cost_types
      ).include_subscription == true
      &&
      one(
        aws_budgets_budget.asgard_budget.cost_types
      ).use_blended == false
    )

    error_message = "The Asgard budget must include tax and subscription costs and must not use blended costs."
  }
}
