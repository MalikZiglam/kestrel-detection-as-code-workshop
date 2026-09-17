# Detection Engineering Guide

How a detection is built in this workshop, and the exact rule language CI accepts.
Read [`START-HERE.md`](../START-HERE.md) first for the lifecycle.

## The pipeline: evidence → telemetry → rule → tests

| Step | Means here |
|---|---|
| **Evidence** | Something in [`evidence/`](../evidence/) or [`SCENARIO.md`](../SCENARIO.md) that suggests a threat worth detecting. |
| **Telemetry** | The logs that could show that threat. Only fields in the [field dictionary](../logs/field-dictionary.md) exist. If the field you need is not there, the honest answer is `status: not_detectable` — propose onboarding the telemetry, do not invent a field. |
| **Rule** | A single KQL query over one log family, plus metadata (see the template). |
| **Positive / negative test** | Two fixtures. The **positive** is an event your rule *should* alert on; the **negative** is a benign look-alike it must *not* alert on. See [`tests/README.md`](../tests/README.md). |

Author toward a **deployable** rule: `status: test` or `production` **and**
`deployment.enabled: true`. Anything else is a lifecycle artifact that lives in Git
but does not deploy (see [`DEPLOYMENT-CONTRACT.md`](DEPLOYMENT-CONTRACT.md)).

## Where to start

Copy a template into your slot `detections/workshop/<team>/detection.yaml`:

- **Foundation** (guided, one condition to fill):
  [`templates/foundation-detection-template.yaml`](../templates/foundation-detection-template.yaml)
- **Engineering** (minimal):
  [`templates/engineering-detection-template.yaml`](../templates/engineering-detection-template.yaml)

Every required field is defined by the validator's `REQUIRED_KEYS`: `id`, `title`,
`status`, `owner`, `deployment`, `severity`, `log_source`, `query`, `mitre_attack`,
`test_cases`, `review_date`. Look at a real one for the shape:
[`detections/baseline/baseline-object-store-policy-change/detection.yaml`](../detections/baseline/baseline-object-store-policy-change/detection.yaml)
(a facilitator example — a shape reference, not an answer to copy).

## The three validation levels

| Level | What it checks | Where it runs |
|---|---|---|
| **L1 structural** | Valid YAML, required keys, id format + uniqueness, allowed status/severity, positive + negative fixtures referenced. | CI, on your PR |
| **L2 semantic** | Bounded syntax and semantic validation for the workshop-supported query subset: query syntax is well-formed (balanced parens, closed quotes, at least one field predicate, separate predicates joined by `and`/`or`, no leading/dangling `and`/`or`, no bare or trailing `not`; a leading `not` before a predicate **is** allowed); `log_source` is a real family; every field in your query exists **and** belongs to that family; numeric operators used only on numeric fields; ATT&CK ids exist in the pinned subset. Anything outside the subset **fails as unsupported** — it is never silently accepted. It does **not** prove that arbitrary Elastic KQL is valid — only the workshop subset. | CI, on your PR |
| **L3 runtime** | Replays events into the SIEM and confirms the rule actually fires. | **Facilitator, post-merge** |

**L1 pass ≠ L2 pass ≠ runtime pass.** Green CI proves shape and real fields — not
that the rule detects anything. That is what L3 is for.

## KQL — exactly what this workshop supports

The CI validator uses a deliberately small, bounded parser for the workshop query
subset. It is **not** a full Elastic KQL engine and does not prove your query is
valid Elastic KQL — it checks that the subset below is well-formed. Use only this
grammar; anything outside it **fails as unsupported by the workshop KQL subset** —
it is not silently ignored.

**Field–value conditions** — `field:value`, or `field <op> value` where `<op>` is
one of `:` `>=` `<=` `>` `<` `=`:

```
event.action: authentication_success
network.bytes_out_10m >= 1000000
```

**Combine with** `and`, `or`, `not`, and parentheses:

```
event.category: iam
and cloud.resource.type: object_store
and not cloud.actor.type: service_account
```

**A value list** is written in parentheses with quoted values — this is a *value*,
not a set of fields:

```
cloud.api_operation: ("SetBucketPolicy" or "PutBucketAcl")
```

### Rules the validator enforces

- **Query syntax must be well-formed for the subset** — balanced parentheses,
  closed quotes, at least one field predicate, separate predicates joined by
  `and`/`or`, no leading or dangling `and`/`or`, and no `field:` with a missing
  value. A leading `not` before a predicate is allowed; a bare or trailing `not`
  is not. Anything outside the subset fails L2 as "unsupported by workshop KQL
  subset" (a subset check, not a full-Elastic guarantee) — it is never silently
  ignored.
- **Every field must be in the [field dictionary](../logs/field-dictionary.md)**
  and belong to your declared `log_source` family. Unknown field = fail (this is
  how a telemetry gap surfaces).
- **Numeric operators** (`>= <= > <`) are allowed **only** on numeric/date fields
  (e.g. `destination.port`, `network.bytes`, `network.bytes_out_10m`). Using them
  on a keyword field fails.
- **Address field name depends on family:** identity and network use `source.ip`;
  application uses `client.address`. Use your family's name.

### Not supported (do not use)

Nested KQL functions, scripted fields, and wildcards **in field names**. The parser
does not understand them.

## Worked examples (real families and fields)

**identity** — successful login after repeated failures (uses the enrichment field):

```
event.action: authentication_success
and workshop.enrichment.failed_logins_same_source_5m >= 5
```

**network** — inbound flow to an unusual port:

```
network.direction: inbound
and not destination.port: (22 or 443)
```

**cloud** — object-store access policy changed:

```
event.category: iam
and cloud.resource.type: object_store
and cloud.api_operation: ("SetBucketPolicy" or "PutBucketAcl")
```

## ATT&CK

Declare `mitre_attack.tactics` / `techniques` / `subtechniques` using ids that
exist in the pinned subset (`docs/attack/attack-subset.yaml`). CI checks the id
**exists** — a human reviewer judges whether the mapping is *right*.
