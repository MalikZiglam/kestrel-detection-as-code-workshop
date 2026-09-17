# Contributing

This repository is a hands-on workshop. Participants contribute one detection
each through the normal branch → pull request → CI → review → merge flow.

## What you change

A participant pull request touches only your team's own paths:

- `assessments/<team-id>.md` — your candidate assessment.
- `detections/workshop/<team-id>/detection.yaml` — your detection rule.
- `tests/workshop/<team-id>/*.ndjson` — your positive and negative fixtures.

Anything else — baseline detections, scripts, Terraform, CI, other teams' slots —
is protected. A PR that edits a protected path fails CI. See
[`docs/BRANCH-PROTECTION.md`](docs/BRANCH-PROTECTION.md).

## How to get a rule merged

1. Branch from `main`.
2. Author the rule from a template in [`templates/`](templates/), using only
   fields defined in [`logs/field-dictionary.md`](logs/field-dictionary.md).
3. Add a positive and a negative fixture under your team slot.
4. Open a pull request against `main`.
5. CI runs L1 (structural) and L2 (semantic) checks. Both must pass. Passing CI
   confirms the rule's shape and fields — it does not prove the rule fires.
6. Get review: two non-author approvals, at least one from a code owner for the
   paths you changed.
7. A facilitator deploys the merged rule and runs the runtime (L3) check.

## Ground rules

- Do not invent log fields. The field dictionary is authoritative; CI and review
  reject fields it does not define.
- Everything in this repository is fictional and synthetic. Do not add client,
  confidential, credential, or personal data, here or in an AI prompt.
- Copilot is available as an advisory aid. It does not review or approve pull
  requests; people and CI do.
