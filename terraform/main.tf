# Data-driven deployment of Elastic Security detection rules.
#
# TRANSPARENCY POINT (for advanced participants, requirement 5):
# Terraform owns desired-state DEPLOYMENT of SIEM detection objects — one part
# of the broader detection lifecycle (authoring, review, testing, tuning,
# retirement happen elsewhere). It does NOT own the whole lifecycle.
#
# Serverless auth = API key only (proven in spike-kit/spike1-terraform). Two
# DISTINCT endpoints. Values come from vars/env; nothing is hardcoded.

provider "elasticstack" {
  # Elasticsearch connection — separate block, API key only.
  elasticsearch {
    endpoints = [var.es_endpoint]
    api_key   = var.api_key
  }

  # Kibana connection — separate block, API key only. Detection-engine API lives here.
  kibana {
    endpoints = [var.kb_endpoint]
    api_key   = var.api_key
  }
}

locals {
  # --- Read BOTH authoritative globs (Deployment Contract §20.2) -------------
  # Plain `detection.yaml` filename keeps test-fixture YAML/JSON out of the set.
  # Test fixtures live under tests/ and never match either glob.
  detection_files = concat(
    tolist(fileset(path.module, "../detections/baseline/*/detection.yaml")),
    tolist(fileset(path.module, "../detections/workshop/*/detection.yaml")),
  )

  # Decode every candidate file. A comment-only placeholder decodes to null;
  # yamldecode(null-content) yields null, so coalesce to an empty map and let
  # the eligibility filter exclude it (it will lack status/deployment).
  detections_raw = {
    for f in local.detection_files :
    f => try(yamldecode(file("${path.module}/${f}")), null)
  }

  # --- ENFORCED eligibility filter (requirement 6, Contract clauses 3 & 4) ---
  # Deployable IFF status in {test, production} AND deployment.enabled == true.
  # draft / deprecated / not_detectable and enabled==false are EXCLUDED.
  # Non-map / null (placeholder) files are excluded: they carry no status.
  eligible_detections = {
    for f, d in local.detections_raw :
    d.id => d
    if(
      d != null &&
      can(d.id) &&
      can(d.status) &&
      contains(["test", "production"], try(d.status, "")) &&
      try(d.deployment.enabled, false) == true
    )
  }

  # --- Excluded set with reason (teaching aid, outputs below) ----------------
  # Any decoded file that did not make the eligible set, with why.
  excluded_detections = {
    for f, d in local.detections_raw :
    f => (
      d == null || !can(d.status) ? "unparsed_or_no_status (placeholder or invalid)" :
      !contains(["test", "production"], try(d.status, "")) ? "status_not_deployable (${try(d.status, "unknown")})" :
      try(d.deployment.enabled, false) != true ? "deployment_disabled (enabled != true)" :
      "excluded"
    )
    if !(
      d != null &&
      can(d.id) &&
      can(d.status) &&
      contains(["test", "production"], try(d.status, "")) &&
      try(d.deployment.enabled, false) == true
    )
  }

  # --- Central log_source family -> destination index (requirement 7) --------
  # Facilitator-controlled. The rule's index is looked up from THIS map by the
  # detection's declared log_source family. Participant YAML supplies only the
  # family; it can never set an index. Families with no mapping are not
  # deployable to an index in this build.
  log_source_to_index = {
    identity = var.index_identity
    network  = var.index_network
    cloud    = var.index_cloud
  }

  # --- Documented severity -> risk_score mapping (WORKSHOP_SPEC.md §14) ------
  # Elastic requires a numeric risk_score; derive it from severity so the two
  # never contradict. Standard Elastic default bands.
  severity_to_risk_score = {
    low      = 21
    medium   = 47
    high     = 73
    critical = 99
  }
}

# One canonical rule type: custom query (KQL). for_each over the ELIGIBLE map
# only — ineligible files never produce a resource.
resource "elasticstack_kibana_security_detection_rule" "workshop" {
  for_each = local.eligible_detections

  name        = each.value.title
  type        = "query"
  query       = each.value.query
  language    = "kuery" # KQL
  enabled     = true
  description = each.value.description

  severity   = each.value.severity
  risk_score = local.severity_to_risk_score[each.value.severity]

  interval = "1m"
  from     = "now-360s"
  to       = "now"

  # Stable client rule_id keeps re-applies idempotent.
  rule_id = each.value.id

  tags = try(each.value.tags, [])

  # Central facilitator mapping resolves the index from the declared family.
  # NEVER from participant YAML.
  index = [local.log_source_to_index[each.value.log_source]]
}
