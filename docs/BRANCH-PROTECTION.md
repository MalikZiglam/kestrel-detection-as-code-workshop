# Branch Protection, Dynamic CODEOWNERS, and Protected Paths

The active `Protect main` ruleset requires a pull request, two approvals, Code
Owner review, and the `validate-detections/validate` status check. Force pushes
and branch deletion are blocked.

## Dynamic participant ownership

Attendance and group count are decided at onboarding time. Do not pre-create a
fixed number of team directories and do not encode a fixed review ring.

For each actual group, assign a namespace such as `team-01` and add three exact
CODEOWNERS entries listing every group member:

```text
/assessments/team-01.md                 @alice @bob @charlie
/detections/workshop/team-01/           @alice @bob @charlie
/tests/workshop/team-01/                @alice @bob @charlie
```

One member may author the PR; other group members may approve it. Participants
may also review other groups. Merge still requires two non-author approvals, at
least one Code Owner approval, and green CI.

## Facilitator onboarding-governance path

`.github/CODEOWNERS` protects itself, so onboarding uses a tightly controlled
facilitator path:

1. `MalikZiglam` creates a branch and changes only `.github/CODEOWNERS`.
2. The CI guard permits that exact author/path combination and rejects mixed or
   participant-authored protected-path changes.
3. The active ruleset grants only GitHub user `MalikZiglam` pull-request-only
   bypass. A PR is still required; this is not direct-push bypass.
4. Malik reviews the diff in the PR and uses the bypass merge for this onboarding
   governance change only.

GitHub rulesets cannot scope a bypass actor to one file, so the CI exception and
this documented operating restriction provide the file-level scope. No
participant is a bypass actor.

## Protected facilitator infrastructure

Normal participant PRs touching any of these paths fail CI and require the
facilitator as Code Owner:

```text
.github/
terraform/
scripts/
detections/baseline/
tests/shared-fixtures/
CODEOWNERS
```

The only CI exception is the onboarding PR described above. It does not permit
changes to the workflow, scripts, Terraform, baseline detections, or shared
fixtures.

## Participant-editable paths

```text
assessments/<group-id>.md
detections/workshop/<group-id>/detection.yaml
tests/workshop/<group-id>/*
```

Participants create these paths on their own branches after namespaces are
assigned. Core CI, validation, and Terraform use wildcard discovery and do not
depend on the number of groups.

## Deployment credentials

Elastic and Terraform credentials remain facilitator-local. Participant PR CI is
credentialless and never deploys.
