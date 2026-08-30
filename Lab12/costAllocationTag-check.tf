# ============================================================
# Feature: Asgard Cost Allocation Tag
# ============================================================
#
# As a platform owner,
# I want Asgard resources assigned to an active cost allocation tag,
# So that project spending can be identified and monitored.
#


# ============================================================
# Scenario: Verify the Project cost allocation tag key
# ============================================================
#
#   Given the Asgard cost allocation tag is configured,
#   When the cost allocation tag key is checked,
#   Then the tag key should equal "Project".
#
check "asgard_cost_allocation_tag_uses_project_key" {
  assert {
    condition = (
      aws_ce_cost_allocation_tag.asgard_cost_allocation_tag.tag_key ==
      "Project"
    )

    error_message = "The Asgard cost allocation tag key must be Project."
  }
}


# ============================================================
# Scenario: Verify the Project cost allocation tag is active
# ============================================================
#
#   Given the Asgard Project cost allocation tag is configured,
#   When the activation status is checked,
#   Then the cost allocation tag should be active.
#
check "asgard_project_cost_allocation_tag_is_active" {
  assert {
    condition = (
      aws_ce_cost_allocation_tag.asgard_cost_allocation_tag.status ==
      "Active"
    )

    error_message = "The Asgard Cost Allocation tag must be active."
  }
}


# ============================================================
# Scenario: Verify the Asgard project tag value
# ============================================================
#
#   Given common resource tags are configured,
#   When the Project tag value is checked,
#   Then the value should equal "Asgard".
#
check "common_tags_use_asgard_project_value" {
  assert {
    condition = (
      local.common_tags["Project"] ==
      "Asgard"
    )

    error_message = "The common Project tag value must be Asgard."
  }
}
