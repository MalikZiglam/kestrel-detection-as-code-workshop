# Outputs — the readable `terraform plan` teaching moment.

output "deployed_rule_count" {
  description = "Number of eligible (deployed) detection rules."
  value       = length(local.eligible_detections)
}

output "deployed_rule_ids" {
  description = "Rule ids (rule_id) of the eligible, deployed detections."
  value       = sort(keys(local.eligible_detections))
}

output "excluded_detections" {
  description = <<-EOT
    Teaching aid: files read from the two globs that were NOT deployed, keyed by
    path, with the reason. Confirms draft / deprecated / not_detectable /
    disabled / placeholder files were correctly skipped by the eligibility
    filter, not silently dropped.
  EOT
  value       = local.excluded_detections
}
