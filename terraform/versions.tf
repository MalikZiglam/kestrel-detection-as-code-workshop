# Provider + version pins.
#
# Plan A (proven by spike-kit/spike1-terraform): the official Elastic provider
# `elastic/elasticstack` manages Elastic Security detection rules on Elastic
# Cloud Serverless via its Kibana Security detection-rule resource. No
# `elastic/ec` (that provisions deployments; Serverless needs only endpoints +
# API key). Version range matches the spike kit's proven `~> 0.11`.

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    elasticstack = {
      source  = "elastic/elasticstack"
      version = "~> 0.11"
    }
  }
}
