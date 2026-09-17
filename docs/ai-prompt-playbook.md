# AI Prompt Playbook

AI is an assistant in detection engineering, not an authority. Use it to move
faster and think harder — never to decide what only a deterministic check or a
human should decide.

## The advisory boundary (authoritative)

**AI MAY:**

- explain a detection, a query, a field, or an ATT&CK technique;
- suggest a rule, a threshold, an enrichment, or a tuning change;
- challenge an assumption ("is this telemetry actually present?");
- review a draft and point out gaps, false-positive risks, or weak logic.

**AI MUST NOT:**

- determine whether CI passes — the deterministic validator decides pass/fail;
- invent telemetry that does not exist — if a field or event is not in the field
  dictionary, the answer is a telemetry-onboarding requirement, not a fabricated
  field;
- auto-merge a pull request;
- be the sole approval to deploy — deployment requires human review;
- replace the deterministic ATT&CK / field / schema checks — those are code, not
  judgment calls.

In one line: **AI advises; deterministic checks and humans decide.**

## How to prompt well

- **Ground it in the scenario.** Point the model at `logs/*/`, the field
  dictionary, and the business context. Ask it to reason from the telemetry you
  have, not from what a generic environment might have.
- **Ask for the reasoning, not just the answer.** "Why would this fire?" and
  "what benign event looks similar?" surface false positives early.
- **Make it challenge you.** "What telemetry does this detection assume, and is
  that assumption true here?" is the single most valuable prompt in this
  workshop.
- **Verify every field.** If the model references a field, confirm it exists in
  `logs/field-dictionary.yaml`. A plausible-sounding field name is the most
  common AI failure mode in detection engineering.

## What still gates the work

The deterministic validator, human PR review, `terraform plan`/`apply`, and the
runtime smoke test (`scripts/smoke_test.py`) are the gates. AI output is an input
to those gates, never a substitute for them.
