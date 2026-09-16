# Rollback Explained

## Rollback is a verified operation, not "revert the file and hope"

The naive view is: "the rule went bad, I reverted the file, done." That is not
rollback. Reverting a file changes the *desired state*; it does nothing to the
*live environment* until Terraform reconciles it — and you have not rolled back
anything until you have **verified** Elastic actually returned to the known-good
state.

Rollback in Detection-as-Code is: revert the source, reconcile the environment,
and **confirm the environment matches** again. The confirmation is the point.

## The demonstrable path

```text
known bad change            (e.g. a rule now firing tens of thousands of times)
   ↓
git revert / restore        (return the source to the known-good detection)
   ↓
terraform plan              (INSPECT the expected change — what will apply undo?)
   ↓
terraform apply             (reconcile the live environment to the reverted state)
   ↓
VERIFY in Elastic           (confirm the environment returned to the expected state)
```

Each step, concretely:

1. **known bad change** — a detection is edited (or deployed) such that it is
   now harmful: flooding alerts, or matching everything. This is the trigger.
2. **git revert / restore** — bring the detection source back to the last
   known-good version. This fixes the *declared* desired state only.
3. **terraform plan** — read the plan before applying. It should show exactly the
   inverse of the bad change and nothing else. If the plan shows more than you
   expect, stop: the repo and environment disagree about more than one thing.
4. **terraform apply** — Terraform reconciles the live environment to the
   reverted desired state. This is the step that actually changes Elastic.
5. **verify in Elastic** — confirm the rollback took effect: the bad rule is gone
   or restored to its prior definition, and no drift remains. Use
   `scripts/verify_baseline.py`, which reports whether the Git-declared expected
   set matches the live rules.

## Why reconciliation + verification is the whole lesson

Git and Terraform give you a *reversible, inspectable, verifiable* path. The
value is not that you can edit a file back — anyone can do that. The value is
that:

- the revert is **inspectable** (`terraform plan` shows the change first);
- the reconciliation is **deterministic** (`terraform apply` makes live match
  declared);
- the result is **verifiable** (`verify_baseline.py` proves the environment
  returned to the expected state).

A rollback you cannot verify is a hope, not a control.

## For the workshop

A live rollback is optional on the day. What is required is that the path above
is **documented and plan-demonstrable**: the facilitator can show the revert, run
`terraform plan` to display the expected change, and explain the apply + verify
steps — even if the apply is not run live. See `docs/terraform-explained.md` for
how deployment (and its reversal) fits the fuller detection lifecycle.
