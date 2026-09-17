# Use-Case Assessment — team-04

This artifact is the reasoning bridge
between evidence discovery and your detection rule: it records what you found,
whether the telemetry can actually detect it, and why you picked the one you
will engineer.

## How to use

1. Work directly in this team assessment file.
2. As a group, identify **three** candidate security use cases from the evidence
   (`evidence/`, `business-context/`, `architecture/`, `logs/`).
3. Fill in all three candidates, then prioritize and select **one** to engineer
   fully. A second is a stretch goal — you are not expected to build three.

## Filling-in guidance (applies to every candidate)

- **Security problem** — the behavior or risk in one or two plain sentences.
- **Supporting evidence** — cite specific files/sections you relied on
  (e.g. `evidence/incident-postmortem.md`, `evidence/threat-brief.md`). Name the
  evidence; do not assert from memory.
- **Business impact** — what it costs the organization if undetected. Tie to a
  critical service where you can (`business-context/critical-services.md`).
- **Available telemetry** — which `log_source` family and which documented fields
  would carry the signal (check `logs/field-dictionary.md`). State plainly if the
  needed telemetry is **missing** — a documented gap is a valid, valuable finding
  and its correct outcome is `status: not_detectable`, not an invented field.
- **Detectability** — can the available telemetry actually catch this? One of:
  `detectable` / `partially detectable (needs enrichment or tuning)` /
  `not detectable (telemetry gap)`. Separate facts from assumptions.
- **Priority / rationale** — High / Medium / Low and why, weighing impact,
  detectability, and effort.

## Candidate 1
- Security problem:
- Supporting evidence:
- Business impact:
- Available telemetry:
- Detectability:
- Priority / rationale:

## Candidate 2
- Security problem:
- Supporting evidence:
- Business impact:
- Available telemetry:
- Detectability:
- Priority / rationale:

## Candidate 3
- Security problem:
- Supporting evidence:
- Business impact:
- Available telemetry:
- Detectability:
- Priority / rationale:

## Selected use case
- Which candidate (1 / 2 / 3):
- Why this one was selected:
- Key assumptions (mark each as fact vs assumption):
- Required telemetry (families + specific fields it depends on):
