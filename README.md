# Detection-as-Code Engineering Literacy Workshop

## → New here? Read [`START-HERE.md`](START-HERE.md) first.

Fictional, self-contained Detection-as-Code workshop for **Kestrel Freight Cloud**.
90 minutes: turn security evidence into one version-controlled detection, shipped
through branch → PR → CI → review → Terraform deploy → runtime validation.

## What's in each directory

| Path | Contents |
|---|---|
| [`detections/`](detections/) | Detection rules. `baseline/` = facilitator examples; `workshop/<team>/` = your rule slot. |
| [`logs/`](logs/) | Synthetic log samples and the authoritative [field dictionary](logs/field-dictionary.md) — what telemetry exists. |
| [`evidence/`](evidence/) | The engagement material to investigate: threat brief, incident post-mortem, purple-team findings. |
| [`assessments/`](assessments/) | Your team's candidate-detection assessment. |
| [`templates/`](templates/) | Foundation (guided) and Engineering detection templates; assessment template. |
| [`tests/`](tests/) | Positive/negative fixtures. `shared-fixtures/` read-only; `workshop/<team>/` is yours. See [`tests/README.md`](tests/README.md). |
| [`docs/`](docs/) | Guides: [GitHub survival](docs/github-survival-guide.md), [detection engineering](docs/detection-engineering-guide.md), deployment contract, and more. |
| [`terraform/`](terraform/) | Deployment config. **Facilitator-run** — participants do not edit this. |
| [`scripts/`](scripts/) | Validator and facilitator tooling. |
| [`SCENARIO.md`](SCENARIO.md) | The fictional client and your job. |

Everything is fictional and synthetic. Do not invent log fields — CI validates
every field against the dictionary.
