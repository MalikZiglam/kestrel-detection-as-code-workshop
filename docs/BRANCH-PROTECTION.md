# Branch Protection & Protected Paths (facilitator setup)

Required GitHub settings for `main`. Do NOT apply remote settings without human
approval. Mirrors `WORKSHOP_SPEC.md` §17.3/§17.4.

## Required `main` branch-protection settings

- Disallow direct push to `main`.
- Require a pull request before merging.
- Require status checks to pass (the `validate-detections` workflow).
- Require review from Code Owners.
- Separate deployment permissions from contribution permissions.

**Enforcement note (S1):** CODEOWNERS only blocks a merge when "Require review
from Code Owners" is ENABLED. Path protection depends on this setting. The
in-workflow diff check is defense-in-depth, not the primary control.

Set the real facilitator handle in `.github/CODEOWNERS` (placeholder is
`@MalikZiglam`) before the workshop.

## Protected paths (authoritative)

Any participant PR touching these fails immediately:

```text
.github/
terraform/
scripts/
detections/baseline/
tests/shared-fixtures/
CODEOWNERS
facilitator-owned configuration
```

## Participant-editable paths

```text
assessments/<team-id>.md
detections/workshop/<team-id>/detection.yaml
tests/workshop/<team-id>/*
```

## Deployment credentials

Never store Elastic/Terraform credentials as ordinary repo secrets reachable by
participant branch workflows. Prefer facilitator-local Terraform deployment, or a
protected GitHub Environment restricted to the trusted deployment workflow /
default branch with facilitator approval. Participants must never invoke
Elastic/Terraform credentials from an arbitrary branch.
