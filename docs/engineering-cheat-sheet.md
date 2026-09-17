# Engineering Cheat Sheet

One page for the Engineering track. Everything here is grounded in the repo.

## Detection schema (required keys)

`id`, `title`, `status`, `owner`, `deployment.enabled`, `severity`,
`log_source`, `query`, `mitre_attack`, `test_cases`, `review_date`.

- `status`: `draft` | `test` | `production` | `deprecated` | `not_detectable`
- `severity`: `low` | `medium` | `high` | `critical`
- `log_source` (family): `identity` | `network` | `cloud` | `application` |
  `admin` | `endpoint`
- Declare only `log_source`. Never set an index, data view, endpoint, or
  credentials — the facilitator mapping resolves the index from the family.

## Deployable vs not

A rule deploys only when `status` is `test` or `production` AND
`deployment.enabled: true`, on a family mapped to an index. Mapped families:
`identity`, `network`, `cloud`. The other families are useful for analysis but
have no index in this build, so a rule on them cannot deploy — keep it
`draft`/`not_detectable` and note the telemetry you would onboard.

## Query

One KQL query per rule. Use only fields in
[`logs/field-dictionary.md`](../logs/field-dictionary.md), and only fields that
belong to your chosen family. Address-representation quirk: `identity` and
`network` use `source.ip`; `application` uses `client.address`.

## Fixtures

Two ndjson files under `tests/workshop/<team-id>/`: `positive.ndjson` (should
alert) and `negative.ndjson` (benign look-alike that should not). One JSON event
per line. A fixture is scenario evidence, not a restatement of the query.

## The three checks

- **L1 structural** — required keys, valid status/severity, id format, fixtures
  referenced and shaped correctly.
- **L2 semantic** — fields exist and belong to the family; ATT&CK ids exist in
  the pinned subset; a deployable rule targets a mapped family.
- **L3 runtime** — the deployed rule fires on a replayed event. Run by the
  facilitator after merge. L1 and L2 passing does not prove L3.

## Lifecycle

Branch → author rule + fixtures → PR against `main` → CI (L1/L2) → two non-author
approvals incl. one code owner → merge → facilitator deploys and runs L3.
