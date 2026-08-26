resource "aws_ce_cost_allocation_tag" "asgard_cost_allocation_tag" {
  tag_key = var.project_name
  status  = "Active"
}
