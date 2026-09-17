# Tests

Fixtures describe the behavior a detection is intended to have. They are
validated and reviewed as part of detection design; actual runtime behavior is
proven at L3. Each rule references a **positive** and a **negative** fixture
from its `test_cases`.

## How a fixture works

- One file per case: `positive.ndjson` and `negative.ndjson`.
- **Use exactly one event in the positive fixture and exactly one event in the
  negative fixture** — one JSON object on a single line (ndjson), ECS-style flat
  fields, the same field names as the [field dictionary](../logs/field-dictionary.md).
  The validator rejects a fixture with zero or more than one event. Example line:

  ```json
  {"@timestamp":"2024-11-12T09:22:41Z","event.id":"team01-pos-01","event.action":"iam_change","event.category":"iam","cloud.api_operation":"SetBucketPolicy","cloud.resource.type":"object_store","cloud.actor.principal":"j.okafor","cloud.actor.type":"user"}
  ```

- The **positive** event *should* make the rule alert. The **negative** is a benign
  look-alike that must *not* alert.
- A fixture **never names an index**. You declare only `log_source: <family>`; the
  facilitator resolves family → index at replay time. Any target/index field in a
  fixture is ignored.
- Give each event a stable, unique `event.id` — runtime checks correlate alerts by it.
- Every event needs a `@timestamp` with an explicit timezone (a trailing `Z` or a
  `+hh:mm` offset). A naive timestamp with no zone is rejected.
- Every field you use must exist in the [field dictionary](../logs/field-dictionary.md)
  and be valid for your `log_source` family — an unknown or wrong-family field fails L1.
- The positive and negative fixtures must be **two different files** — the validator
  rejects a rule that points both cases at the same file.

## What you provide

Your own two files under your team slot:

```
tests/workshop/<team>/positive.ndjson
tests/workshop/<team>/negative.ndjson
```

Reference them from your detection's `test_cases`:

```yaml
test_cases:
  positive:
    - tests/workshop/<team>/positive.ndjson
  negative:
    - tests/workshop/<team>/negative.ndjson
```

## The non-circularity rule

A fixture is **scenario evidence, not a copy of the query.** Do not build the
positive event by mechanically restating every clause of your rule; write a
realistic event from the scenario that happens to match. The negative should be a
plausible *benign* case that is close but legitimately different — that is what
proves the rule discriminates.

## Paths

| Path | Owner | Editable |
|---|---|---|
| `tests/shared-fixtures/` | Facilitator | No — read-only |
| `tests/workshop/<team>/` | Your team | Yes |

Fixtures live under `tests/` and **never** match a deployment glob. Terraform never
reads a fixture as a rule.
