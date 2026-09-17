# Team 04 — Test Fixtures

Create exactly two fixture files in this directory:

- `positive.ndjson` — one event that SHOULD match your detection
- `negative.ndjson` — one event that SHOULD NOT match your detection

## Rules

- Each file must contain exactly **one JSON event**
- Use only fields documented in `logs/field-dictionary.md`
- The event must belong to the same telemetry family as your detection's `log_source`
- Do not invent fields
- Keep the positive and negative events as similar as possible; change only what is necessary to prove the detection condition

Your detection already references:

```
tests/workshop/team-04/positive.ndjson
tests/workshop/team-04/negative.ndjson
```

When your fixtures and detection are ready, change the detection to:

```yaml
status: test

deployment:
  enabled: true
```

CI will then validate the deployable rule and its fixture references.
