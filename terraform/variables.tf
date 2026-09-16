# Facilitator-controlled inputs. NO secret defaults; nothing here is committed
# with a value. Supply via TF_VAR_* env or a gitignored terraform.tfvars.
#
# Participant detection.yaml NEVER sets any of these — endpoints, credentials,
# and destination index are facilitator-controlled mappings (Deployment
# Contract §20.2 / WORKSHOP_SPEC.md §14, S5).

variable "es_endpoint" {
  type        = string
  description = "Elasticsearch Serverless endpoint URL. Supply via TF_VAR_es_endpoint."
}

variable "kb_endpoint" {
  type        = string
  description = "Kibana Serverless endpoint URL (hosts the detection-engine API). Supply via TF_VAR_kb_endpoint."
}

variable "api_key" {
  type        = string
  sensitive   = true
  description = "Elastic API key (Serverless is API-key auth only). Supply via TF_VAR_api_key. Never commit."
}

# --- Facilitator-controlled log_source family -> destination index ------------
# One variable per mapped family. The rule's index comes from these, keyed by
# the detection's declared `log_source`. Participant YAML declares only the
# family; it can never name an index. Matches the contract table:
#   identity -> workshop-auth-*   network -> workshop-network-*   cloud -> workshop-cloud-*

variable "index_identity" {
  type        = string
  default     = "workshop-auth-*"
  description = "Destination index pattern for the identity log_source family."
}

variable "index_network" {
  type        = string
  default     = "workshop-network-*"
  description = "Destination index pattern for the network log_source family."
}

variable "index_cloud" {
  type        = string
  default     = "workshop-cloud-*"
  description = "Destination index pattern for the cloud log_source family."
}
