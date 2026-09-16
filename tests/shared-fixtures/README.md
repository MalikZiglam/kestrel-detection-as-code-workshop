# Shared fixtures (facilitator-owned, immutable)

Protected path. Participant PRs must not modify this directory.

These fixtures exercise the **deployable baseline detections** at runtime. Each
deployable baseline that is a good teaching example ships a positive fixture
(should alert) and a negative/control fixture (should not). `expectations.yaml`
maps every fixture to its `rule_id` and the expected alert outcome.

## Layout

```text
tests/shared-fixtures/
├── expectations.yaml                        # fixture -> rule_id -> expected_alert
├── baseline-privileged-password-only-auth/  # identity family
│   ├── positive.ndjson                      # privileged password-only login -> ALERT
│   └── negative.ndjson                      # same admin with MFA -> NO alert
├── baseline-object-store-policy-change/     # cloud family
│   ├── positive.ndjson                      # bucket policy loosened -> ALERT
│   └── negative.ndjson                      # routine PutObject -> NO alert
└── baseline-management-plane-unusual-port/  # network family
    ├── positive.ndjson                      # inbound mgmt-plane port 8443 -> ALERT
    └── negative.ndjson                      # inbound mgmt-plane port 22 -> NO alert
```

Three production baselines carry fixtures here. **Participant teams follow the
same pattern** for their own detection under `tests/workshop/<team-id>/` — one
positive and one negative fixture built from the scenario, listed in the team's
`detection.yaml` `test_cases`.

## The non-circularity rule (authoritative)

> **A test event represents known evidence from the scenario. Do NOT build the
> event by copying the query's fields — that only proves the query matches
> itself. Build the event from the scenario/telemetry, then check whether the
> detection catches it.**

A fixture derived from the query is a tautology: it passes by construction and
proves nothing about whether the detection reflects reality. A good fixture is an
event that *actually happened* in the fictional scenario — drawn from the log
families in `logs/*/` and the field dictionary — that you then run past the
detection to see if it fires.

### Bad (circular) — do not do this

The query is:

```text
event.category: authentication
and event.action: authentication_success
and authentication.privileged: true
and authentication.method: ("password" or "api_key")
```

A circular fixture just re-types those four predicates and nothing else:

```json
{"event.category":"authentication","event.action":"authentication_success","authentication.privileged":true,"authentication.method":"password"}
```

This alerts, but only because it is the query wearing a JSON hat. It carries no
account, no host, no source — it is not a thing that happened, so it cannot tell
you whether the detection is *right*.

### Good (scenario-derived)

Start from the scenario: privileged admin `j.okafor` completed a login with a
password only (the org's strong-auth policy for privileged roles was breached).
Write that event with its natural fields, then check the detection:

```json
{"@timestamp":"2024-11-12T08:05:09Z","event.id":"fixture-priv-auth-pos-01","event.action":"authentication_success","event.outcome":"success","event.category":"authentication","host.name":"idp.ctrl.example","user.name":"j.okafor","source.ip":"203.0.113.45","user.roles":["admin"],"authentication.method":"password","authentication.privileged":true,"workshop.enrichment.failed_logins_same_source_5m":6}
```

It carries the account, host, source, and roles that make it a real event. The
detection *should* catch it — and if it did not, that would be a real finding
about the detection, not the fixture. The negative fixture is the same admin on
the same host authenticating with **MFA**: a believable benign look-alike that
must **not** alert.

## Correlation by event.id (matches the runtime pattern)

Every fixture carries a stable, unique `event.id` (e.g. `fixture-priv-auth-pos-01`).
At runtime, replay rewrites each event's `event.id` with a unique per-run token and
preserves the fixture's original id as `workshop.original_event_id`. So the static
`event_id:` in `expectations.yaml` is the fixture's ORIGINAL id (a documentation and
correlation reference); the alert is correlated on the unique per-run id at
smoke-test time. Runtime scripts credit an alert only when it carries **both** the
rule's `rule_id` **and** that unique run id. This is the proven spike pattern
(`spike-kit/spike2-runtime/measure_latency.sh`): a pre-existing or unrelated alert
can never satisfy the check.

## What a fixture must never contain

- **No destination index, endpoint, or data stream.** The family→index mapping
  is facilitator-controlled; `replay_events.py` resolves `log_source` → index and
  ignores any target/index/destination field in a fixture (S5, `WORKSHOP_SPEC.md`
  §22.2, `docs/DEPLOYMENT-CONTRACT.md`).
- **No real identifiers.** Hosts are `*.example`; IPs are RFC 5737
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). Everything is synthetic.

## Expected results

`expectations.yaml` is authoritative: it lists each fixture path, its `rule_id`,
its `event_id`, and `expected_alert` (`true` for positive, `false` for negative).
`smoke_test.py` reads it to decide PASS/FAIL.
