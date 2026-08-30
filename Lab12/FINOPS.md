# Asgard FinOps configuration

- Resource names retain the lowercase `asgard` prefix. The cost tag is
  case-sensitive: **Project=Asgard**. Cost allocation activates the key
  `Project`, and the budget filters the pair `Project$Asgard`.
- AWS Billing currently recognizes `Project` as inactive in this account.
  The next reviewed apply can activate it. In new accounts the key may not
  appear immediately after resources are tagged; activate only once available.
- `finops.auto.tfvars` selects the existing account-wide SERVICE monitor
  **Guardian** in account `461593447802`. Terraform does not own, rename, or
  delete this monitor; it manages Asgard's subscription to it. These alerts
  cover account service spend, not only Project=Asgard costs.
- For another account, replace `existing_service_monitor_arn` with that
  account's monitor ARN. Use null only when creating a new SERVICE monitor is
  appropriate. Do not remove the reference simply to retry an apply.
- The `moved` block preserves the address of monitors already managed by older
  versions of this configuration. Switching an existing managed deployment to
  an external monitor still requires reviewing any proposed deletion.

## Checks and CI

Local `*-check.tf` files retain Given/When/Then comments. CI discovers
`tests/finops_regressions.tftest.hcl` and `tests/validations.tftest.hcl` using
mocked providers. Budget comparisons convert provider string amounts to
numbers and explicitly match collection types.

After a partially failed apply, retain state and review a fresh plan. Do not
destroy or reset state to retry. No apply or import was performed by this fix.
