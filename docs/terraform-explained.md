# Terraform Explained

## What Terraform owns here (and what it does not)

**Terraform owns desired-state DEPLOYMENT of SIEM detection objects.** It reads
the detection definitions the repo declares as deployable, reconciles the live
Elastic environment to match, and reports drift. That is its whole job in this
workshop.

Terraform does **not** own the detection lifecycle. Deployment is one step in a
longer chain. A detection is engineered before Terraform ever runs and is
verified after it finishes:

```text
security problem
   ↓
telemetry analysis        (what evidence do we actually have?)
   ↓
detection design          (author the rule against real fields)
   ↓
validation                (PR-time: schema, fields, ATT&CK, fixtures)
   ↓
review                    (human approval on the PR)
   ↓
desired-state deployment  (Terraform apply — THIS is Terraform's part)
   ↓
runtime verification       (replay fixtures, confirm the rule fires / stays quiet)
   ↓
tuning / rollback         (adjust or revert based on real behavior)
```

Terraform sits in the middle. It makes the environment match the reviewed,
version-controlled desired state. It does not decide whether a detection is
good, whether the telemetry supports it, or whether it behaves correctly once
live — those are engineering and verification steps around it.

## Why desired-state deployment matters

The alternative is clicking rules into a UI by hand. That drifts: nobody can say
what is deployed, why, or by whom. Declaring detections as code and letting
Terraform reconcile means:

- the repo is the single source of truth for what should be deployed;
- `terraform plan` shows the exact change before it happens;
- `terraform apply` makes the environment match — no more, no less;
- drift (a hand-edited or leftover rule) is visible and correctable.

## What deployment does and does not prove

> Deployment proves the configuration exists. It does not prove the detection is
> good.

A rule can deploy cleanly and still be noisy, or fail to fire because the author
misread the telemetry. That is why **runtime verification** follows deployment
(see `scripts/smoke_test.py`) and why **tuning/rollback** follows verification
(see `docs/rollback-explained.md`). Terraform guarantees the *state*; the runtime
step checks the *behavior*.

## In this repo

- Deployable set: `detections/baseline/*/detection.yaml` and
  `detections/workshop/*/detection.yaml` with `status` in `{test, production}`
  and `deployment.enabled: true` (see `docs/DEPLOYMENT-CONTRACT.md`).
- Participants declare only `log_source: <family>`. They never author an Elastic
  endpoint, credentials, destination index, or Terraform backend — those are
  facilitator-controlled mappings.
- After `terraform apply`, run `scripts/verify_baseline.py` to confirm the live
  environment matches the Git-declared desired set.
