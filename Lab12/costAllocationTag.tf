resource "aws_ce_cost_allocation_tag" "asgard_cost_allocation_tag" {
  tag_key = "Project" # Activate the tag key, not its Asgard value.
  status  = "Active"
}
