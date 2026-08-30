resource "aws_budgets_budget" "asgard_budget" {
  name         = "asgard-budget"
  budget_type  = "COST"
  limit_amount = var.budget_limit
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name   = "TagKeyValue"
    values = ["Project${"$"}${local.common_tags.Project}"]
  }

  cost_types {
    include_tax          = true
    include_subscription = true
    use_blended          = false
  }

  time_period_start = var.budget_start_date
}
