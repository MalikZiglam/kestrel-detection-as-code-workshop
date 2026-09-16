# Terraform — Elastic Security detection rules

One simple root module. It reads the detection catalogue, filters to the
deployable set, and creates one Elastic Security query rule per eligible
detection. No per-team modules, no per-environment trees.

## What Terraform owns here

Terraform owns desired-state **DEPLOYMENT** of SIEM detection objects — one part
of the broader detection lifecycle. Authoring, review, testing, tuning, and
retirement happen elsewhere (Git, CI, the assessment). Terraform does **not**
own the whole lifecycle; it makes the live rule set match the eligible files.

## Plan A (confirmed, proven by the spike kit)

- Official Elastic provider `elastic/elasticstack` (`~> 0.11`), resource
  `elasticstack_kibana_security_detection_rule`.
- Target: Elastic Cloud Serverless. Auth = API key only, two distinct endpoints
  (Elasticsearch + Kibana), each in its own provider sub-block.
- One canonical rule type: custom query rule, KQL (`language = "kuery"`).

## Data-driven flow

```
detections/baseline/*/detection.yaml
detections/workshop/*/detection.yaml
        │  fileset() + yamldecode()
        ▼
locals.eligible_detections   ← ENFORCED filter (see below)
        │  for_each (eligible only)
        ▼
elasticstack_kibana_security_detection_rule  (one per eligible detection)
```

Test fixtures live under `tests/` and use other filenames, so they never match
either glob. Comment-only placeholder slots decode to null and are excluded.

## Eligibility contract (ENFORCED, not just documented)

A detection is deployed **if and only if**:

- `status` is in `{test, production}`, **and**
- `deployment.enabled == true`.

`draft`, `deprecated`, `not_detectable`, and `enabled == false` are excluded.
The filter lives in `locals.eligible_detections`; `for_each` iterates the
filtered map only, so an ineligible file can never produce a rule. Authoritative
source: `../docs/DEPLOYMENT-CONTRACT.md`.

Verify the same decision without Terraform:

```
python3 ../scripts/deployment_eligibility.py
```

That checker mirrors the `locals` filter and prints the deployable set plus the
excluded set with reasons. `outputs.tf` exposes the same split
(`deployed_rule_count`, `deployed_rule_ids`, `excluded_detections`) so
`terraform plan` shows why each file was kept or skipped.

## log_source → index (facilitator-controlled)

Participant YAML declares only `log_source: <family>`. The rule's `index` is
looked up from the facilitator-controlled `locals.log_source_to_index` map, keyed
by that family:

| family | index variable | default |
|---|---|---|
| identity | `var.index_identity` | `workshop-auth-*` |
| network | `var.index_network` | `workshop-network-*` |
| cloud | `var.index_cloud` | `workshop-cloud-*` |

Participant YAML **cannot** set an index, endpoint, credential, or backend.
`risk_score` is derived from `severity` via a documented `locals` map (low 21,
medium 47, high 73, critical 99), so the two never contradict.

## Workflow

Set all three `TF_VAR_*` values BEFORE running Terraform so it never prompts
interactively. Serverless auth = API key only, two distinct endpoints.

```
cd terraform

# Set all three up front — non-interactive; Terraform reads TF_VAR_* directly.
export TF_VAR_es_endpoint="https://<project>.es.<region>.<csp>.elastic.cloud"
export TF_VAR_kb_endpoint="https://<project>.kb.<region>.<csp>.elastic.cloud"
export TF_VAR_api_key="<encoded API key>"

terraform init
terraform validate   # operator step — structural + provider-schema check
terraform plan       # human reviews; the teaching moment
terraform apply      # only after human approval; no --auto-approve
```

After apply, run the runtime smoke test from the repo root (same
`ELASTIC_ES_ENDPOINT` / `ELASTIC_KB_ENDPOINT` / `ELASTIC_API_KEY` env the
runtime scripts expect):

```
cd ..
# WORKSHOP_CONFIRM=yes is required — replay writes to Elastic.
WORKSHOP_CONFIRM=yes python3 scripts/smoke_test.py --rule-id baseline-privileged-password-only-auth   # ingest fixtures -> poll alerts by event.id -> PASS/FAIL
```

A selector is required: the live demo uses a single `--rule-id`. `--all` is
rehearsal-only (runs every rule in `tests/shared-fixtures/expectations.yaml`).

Rule schedule: `interval = "1m"`, `from = "now-360s"`. The 1-minute schedule
keeps scheduled ingest-to-alert within the smoke test's 120s bound.

## Secrets

Credentials come from `TF_VAR_*` env vars or a gitignored `terraform.tfvars`.
Never commit state, `.tfvars`, or credentials — the repo `.gitignore` already
covers `.terraform/`, `*.tfstate*`, and `*.tfvars*` repo-wide, so `terraform/`
is covered. Secret scanning runs against git HISTORY before publication.
