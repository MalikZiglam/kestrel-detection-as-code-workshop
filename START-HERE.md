# START HERE

You have joined a short security engagement for **Kestrel Freight Cloud (KFC)**, a
fictional cloud-native freight company. Goal: turn evidence into **one
version-controlled detection**, shipped through a real branch → PR → CI → review →
deploy lifecycle in 90 minutes.

New to Git? Read [`docs/github-survival-guide.md`](docs/github-survival-guide.md)
first, everything is browser-only.

## Pick your route

| Route | Who takes it | What you deliver |
|---|---|---|
| **Foundation** | Little/no coding or Git experience. You want to understand and observe the path. | A filled detection from the guided template (one condition to complete) + a positive/negative fixture. |
| **Engineering** | Comfortable authoring. You want to build a rule from scratch. | A detection you author end-to-end + your own positive/negative fixtures. |

Both routes produce a real detection and go through the same lifecycle.

## The sequence

1. Confirm your **team ID** and pick your route.
2. **Investigate the evidence** — read [`SCENARIO.md`](SCENARIO.md), then
   [`evidence/`](evidence/), and the logs in [`logs/`](logs/).
3. **Assess candidates** — fill [`assessments/<team>.md`](assessments/) with 3
   candidate detections; note which are actually detectable with today's telemetry.
   ("Not detectable — onboard telemetry first" is a valid answer.)
4. **Pick one** to engineer, toward a **deployable** rule (`status: test` or
   `production` and `deployment.enabled: true`).
5. **Author** `detections/workshop/<team>/detection.yaml` from a template
   (below), using only fields in the [field dictionary](logs/field-dictionary.md).
   Add positive + negative fixtures under `tests/workshop/<team>/`.
   How rules work: [`docs/detection-engineering-guide.md`](docs/detection-engineering-guide.md).
6. **Open a PR** against `main` — see the [GitHub survival guide](docs/github-survival-guide.md).
7. **Watch CI** — L1 (structural) and L2 (semantic) run automatically. Green = valid
   shape and real fields; it does **not** prove the rule alerts (that is L3, run later
   by the facilitator).
8. **Peer review** — review your assigned team's PR; address comments on yours.
9. **Facilitator deploys** the merged rule via Terraform.
10. **Runtime validation** (L3) — the facilitator replays events and confirms the
    rule fires. This is done for you post-merge.

## Your slots and starting points

| Thing | Path |
|---|---|
| Evidence to investigate | [`evidence/`](evidence/), [`SCENARIO.md`](SCENARIO.md) |
| Field dictionary (what telemetry exists) | [`logs/field-dictionary.md`](logs/field-dictionary.md) |
| Foundation template (guided) | [`templates/foundation-detection-template.yaml`](templates/foundation-detection-template.yaml) |
| Engineering template (minimal) | [`templates/engineering-detection-template.yaml`](templates/engineering-detection-template.yaml) |
| Your detection slot | `detections/workshop/<team>/detection.yaml` |
| Your fixtures slot | `tests/workshop/<team>/` |
| Browser-only Git | [`docs/github-survival-guide.md`](docs/github-survival-guide.md) |

The currently **mapped, deployable** families are **identity**, **network**, and
**cloud** — the ones Terraform can deploy today, so author toward these. The field
dictionary also lists other families (e.g. application, admin, endpoint) that exist
but are unmapped and not deployable in this build. Do not invent fields — CI rejects
any field not in the dictionary.
