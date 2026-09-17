# Synthetic Log Samples

Source of truth for what is and is not detectable in this workshop. Every event
conforms to [`field-dictionary.yaml`](./field-dictionary.yaml) — no field appears
that the dictionary does not define. All identifiers are documentation-safe: RFC
5737 IPv4 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 IPv6
(`2001:db8::/32`), and `.example` / `example.com` hosts. No real Internet assets.

Format: **NDJSON** — one JSON event per line, ready for replay. The dataset is
deliberately small enough to scan live, dense enough to reason about. Every event
contributes to a candidate class, an existing-detection example, or necessary
baseline context; there is no filler.

## Timestamps

All events use stable historical timestamps (2024-11-12 UTC) so correlations line
up on the page: auth failures precede the success, flow-summary windows follow the
foothold, IAM and app-access events sit in the same hours. The replay layer
rewrites `@timestamp` into each rule's evaluation window when events are ingested
for runtime validation. Treat the absolute date as illustrative; treat the
relative ordering as real.

## Files

| File | Family (`log_source`) | Events | Address field |
|---|---|---|---|
| `authentication/auth-events.ndjson` | `identity` | 20 | `source.ip` |
| `network/network-events.ndjson` | `network` | 12 | `source.ip` / `destination.ip` |
| `cloud-audit/cloud-events.ndjson` | `cloud` | 10 | — |
| `application/app-access.ndjson` | `application` | 8 | `client.address` |
| `admin/admin-events.ndjson` | `admin` | 5 | — |

Address-representation quirk (documented in the dictionary): `identity` and
`network` name the client source `source.ip`; `application` names the same concept
`client.address`. Queries must use the target family's field name.

## What each family carries

- **identity / authentication** — login success and failure for corporate,
  carrier, admin, and service accounts. Carries the enrichment field
  `workshop.enrichment.failed_logins_same_source_5m` on every auth event, with
  both a high-count and a low-count situation present so a single-document
  predicate can separate them. Also carries the routine, high-frequency
  service-account login pattern.
- **network / firewall / flow** — individual flows plus the periodic
  `flow_summary` event carrying the enrichment field `network.bytes_out_10m`.
  Includes both a large-volume outbound situation and a large-volume-but-routine
  internal situation, so volume alone does not decide the answer. Flows carry
  `source.plane` / `destination.plane`.
- **cloud control-plane** — routine API calls, IAM change events
  (`iam.change.type`, `iam.target.principal`), and a logging-control operation.
  Actors are tagged `user` or `service_account`. **No secrets-management audit
  events exist in this family or any other** — that telemetry is deliberately
  absent (see below).
- **application access** — Tier-1 `orders-portal` requests, including read paths
  and bulk-export paths, from carrier and operator accounts. Uses
  `client.address`.
- **admin activity** — administrative sessions and config changes, some staying
  within one trust plane and some crossing planes (`source.plane` →
  `destination.plane`).

## Candidate-class coverage

The dataset supports all eight candidate classes **except #7**, which is
non-detectable by design. This table maps classes to the families that hold their
supporting telemetry. It does not identify which individual events are benign or
malicious — that judgment is the workshop exercise.

| # | Candidate class | Supporting family/files |
|---|---|---|
| 1 | Cross-plane admin / lateral movement | `admin/admin-events.ndjson` (+ `network/network-events.ndjson`) |
| 2 | Auth failures then success | `authentication/auth-events.ndjson` |
| 3 | Logging / security-control impairment | `cloud-audit/cloud-events.ndjson` |
| 4 | Unexpected privilege / IAM change | `cloud-audit/cloud-events.ndjson` |
| 5 | Suspicious Tier-1 app access | `application/app-access.ndjson` |
| 6 | Bulk outbound transfer | `network/network-events.ndjson` |
| 7 | Secrets-management problem | **none — deliberate telemetry gap** |
| 8 | Noisy automation / service account | `authentication/auth-events.ndjson`, `cloud-audit/cloud-events.ndjson` |

## Deliberate telemetry gap (candidate #7)

No file contains secrets-management **audit** events. No field carries the
secrets-audit actor, operation, or target secret. The Secrets Manager
(`vault.ctrl.example`) emits no audit telemetry. This is intentional: the correct
engineering outcome for the secrets-management candidate is a telemetry-onboarding
requirement (`status: not_detectable`), not an invented detection.

## Enrichment fields

Two fields are produced by the fictional upstream pipeline, not by any rule:

- `workshop.enrichment.failed_logins_same_source_5m` (identity) — serves #2.
- `network.bytes_out_10m` (network, on `flow_summary`) — serves #6.

Each appears with both a high-signal and a benign situation so participants must
reason about thresholds and context, not just field presence.
