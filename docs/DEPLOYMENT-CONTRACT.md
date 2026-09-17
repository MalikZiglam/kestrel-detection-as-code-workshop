# Detection Deployment Contract (AUTHORITATIVE)

Single source of truth for where deployable rules live, what participants may
edit, and when a file deploys. `detections/`,
`terraform/`, and CI reference this file rather than restating its rules.

```text
AUTHORITATIVE DETECTION DEPLOYMENT CONTRACT
Participant detection location:  detections/workshop/<team-id>/detection.yaml
Baseline detection location:     detections/baseline/<rule-id>/detection.yaml
Participant-editable paths:
  assessments/<team-id>.md
  detections/workshop/<team-id>/detection.yaml
  tests/workshop/<team-id>/*
Deployable if and only if:
  1. file matches approved detection path;
  2. schema validation succeeds;
  3. status is test or production;
  4. deployment.enabled is true.
Terraform never reads test fixtures as rules.
Participant YAML cannot specify: Elastic endpoint; provider credentials;
  destination index/data stream; Terraform backend; replay destination.
Those are facilitator-controlled mappings.
```

## Authoritative deployment status table

Governs Git existence and deploy eligibility.

| Status | Can exist in Git? | Can deploy? |
|---|---|---|
| draft | Yes | No |
| test | Yes | Yes |
| production | Yes | Yes |
| deprecated | Yes | No |
| not_detectable | Yes, assessment only | No |

Deployable set is exactly `{test, production}`.

## Authoritative deployment globs

Two explicit globs, both using the plain `detection.yaml` filename:

```text
detections/baseline/*/detection.yaml
detections/workshop/*/detection.yaml
```

Test fixtures live under `tests/` and must never match either glob.

## Facilitator-controlled infra mapping

Participant YAML declares only `log_source: <family>`. The facilitator-controlled
central mapping resolves family→index. The replay script decides the destination
and ignores any target/index/destination field in a participant fixture.

| log_source family | destination index |
|---|---|
| `network` | `workshop-network-*` |
| `identity` | `workshop-auth-*` |
| `cloud` | `workshop-cloud-*` |

Deployment defaults and provider details are centrally mapped, not authored by
participants.
