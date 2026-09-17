# Canonical Workshop Field Dictionary

**Authoritative for static field-reference validation.**
CI validates every field a participant references in `detection.yaml` against this
dictionary. The machine-readable twin is [`field-dictionary.yaml`](./field-dictionary.yaml);
if the two ever disagree, the `.yaml` wins and this file is corrected.

> **Teaching note.** Detection capability depends not only on raw logs, but also on
> normalization and enrichment. Fields marked **enrichment** are produced by a
> fictional **upstream telemetry pipeline**, not by the detection rule.

All identifiers are documentation-safe and synthetic: `*.example` / `example.com`
hostnames (RFC 6761), RFC 5737 IPv4 ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), RFC 3849 IPv6 (`2001:db8::/32`). No real Internet assets appear.

---

## Allowed `log_source` enum

A detection's schema `log_source:` field **must be exactly one** of these family
identifiers. This is the single source of truth for the schema `log_source`
value and matches the CI validator.

| `log_source` | Family | Notes |
|---|---|---|
| `identity` | identity / authentication | login success/failure, roles, MFA |
| `network` | network / firewall / flow | flows + periodic flow-summary event |
| `cloud` | cloud control-plane API | API operations, IAM changes |
| `application` | Tier-1 application access | app-access requests to the orders portal |
| `admin` | administrative activity | admin sessions, config changes, plane crossings |
| `endpoint` | endpoint / process (optional) | present but sparse; not on every host |

**Family → index mapping is facilitator-controlled.** Participants never name
an index. The replay script resolves family → index and ignores any target field
in a participant fixture. Currently mapped to deployable indices:

| Family | Destination index |
|---|---|
| `identity` | `workshop-auth-*` |
| `network` | `workshop-network-*` |
| `cloud` | `workshop-cloud-*` |

`application`, `admin`, and `endpoint` are valid `log_source` values used for
evidence and telemetry reasoning; the facilitator may map them to indices later.
They are not wired to a deployable index in this build.

---

## Deliberate address-representation quirk

Two families encode the same "who connected from where" concept with **different
field names**. This is realistic messiness, and it is fair because it is documented.

| Concept | `identity` | `network` | `application` |
|---|---|---|---|
| Client source address | `source.ip` | `source.ip` | `client.address` |

A query cannot assume one field name across families. Use the field name of the
**target family**. CI rejects `source.ip` on an application-only rule and
`client.address` on an identity-only rule.

---

## Deliberate telemetry gap — candidate #7

**Secrets-management audit events are `not available` in any family.** No field
carries the secrets-audit **actor**, **operation**, or **target secret**. This is
the intended non-detectable candidate. The correct engineering outcome is a
**telemetry-onboarding requirement** (`status: not_detectable`), not an invented
detection. CI rejects invented secrets-audit fields at L2; the correct move is to
document the gap, which review credits.

---

## Upstream-enrichment fields (G3 — REQUIRED)

Produced by the fictional upstream pipeline, **not** by the rule. They let the
single canonical KQL rule type serve correlation/aggregation candidates as
single-document predicates.

| Field | Type | Family | Serves | Meaning |
|---|---|---|---|---|
| `workshop.enrichment.failed_logins_same_source_5m` | integer | identity | #2 | Failed logins from the same `source.ip` in the prior 5 min, stamped on each auth event. Rule: `event.action: authentication_success AND workshop.enrichment.failed_logins_same_source_5m >= 5`. |
| `network.bytes_out_10m` | integer | network | #6 | Outbound bytes per source over a rolling 10 min, on the periodic `flow_summary` event. Lets candidate #6 reason about volume in one document. |

---

## Fields by family

`Guaranteed` = always present on events of that family. `Optional` = conditional.
`Enrichment` = upstream-pipeline-produced (not raw log content).

### Common (all families)

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `@timestamp` | date | Event time (ISO 8601, UTC). Replay rewrites it into the rule window. | Guaranteed |
| `event.id` | keyword | Unique event identifier. | Guaranteed |
| `event.action` | keyword | Normalized action (e.g. `authentication_success`, `flow_summary`, `iam_role_assigned`). | Guaranteed |
| `event.outcome` | keyword | `success` \| `failure` \| `unknown`. | Guaranteed (identity, cloud, application, admin) |
| `event.category` | keyword | Coarse class (e.g. `authentication`, `network`, `iam`, `process`). | Guaranteed |
| `host.name` | keyword | Host emitting/targeted (e.g. `edge-gw.example`). | Guaranteed |
| `workshop.scenario_id` | keyword | Replay-added scenario tag. Absent in raw fixtures until replay. | Optional |
| `workshop.team_id` | keyword | Replay-added team tag (e.g. `team-01`). | Optional |
| `workshop.test_case` | keyword | Replay-added `positive`\|`negative` label. | Optional |
| `workshop.original_timestamp` | date | Original fixture time preserved when replay rewrites `@timestamp`. | Optional |

### `identity` — identity / authentication

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `user.name` | keyword | Account presented (e.g. `svc-replicator`, `j.okafor`). | Guaranteed |
| `source.ip` | ip | Client source address (identity uses this name — see quirk). | Guaranteed |
| `user.roles` | keyword | Roles asserted at auth (e.g. `admin`, `operator`). | Optional |
| `authentication.method` | keyword | `password` \| `mfa` \| `api_key` \| `sso`. | Optional |
| `authentication.privileged` | boolean | True if the account is privileged (candidate #2 targeting). | Optional |
| `workshop.enrichment.failed_logins_same_source_5m` | integer | **Enrichment.** Failed logins from same `source.ip` in prior 5 min. Serves #2. | Optional (enrichment) |

### `network` — network / firewall / flow

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `source.ip` | ip | Flow source address (network uses this name — see quirk). | Guaranteed |
| `destination.ip` | ip | Flow destination address. | Guaranteed |
| `destination.port` | integer | Flow destination port. | Guaranteed |
| `network.protocol` | keyword | `tcp` \| `udp` \| `icmp`. | Optional |
| `network.direction` | keyword | `inbound` \| `outbound` \| `internal`. | Optional |
| `network.bytes` | integer | Bytes for a single flow event. | Optional |
| `network.bytes_out_10m` | integer | **Enrichment.** Outbound bytes/source over 10 min on `flow_summary`. Serves #6. | Optional (enrichment) |
| `source.plane` | keyword | Originating trust plane (`corporate`\|`workload`\|`management`). | Optional |
| `destination.plane` | keyword | Target trust plane. | Optional |

### `cloud` — cloud control-plane API

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `cloud.api_operation` | keyword | Control-plane operation (e.g. `StopLogStream`, `PutRolePolicy`). | Guaranteed |
| `cloud.resource.type` | keyword | Target resource type (e.g. `log_stream`, `iam_role`, `object_store`). | Guaranteed |
| `cloud.resource.id` | keyword | Target resource identifier. | Optional |
| `cloud.actor.principal` | keyword | Principal performing the call (user or service account). | Guaranteed |
| `cloud.actor.type` | keyword | `user` \| `service_account`. | Optional |
| `iam.change.type` | keyword | `role_assigned` \| `policy_attached` \| `permission_granted`. Serves #4. | Optional |
| `iam.target.principal` | keyword | Principal receiving the IAM change. Serves #4. | Optional |

### `application` — Tier-1 application access

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `client.address` | ip | Source address of an app request (application uses THIS name — see quirk). | Guaranteed |
| `url.path` | keyword | Requested path (e.g. `/orders/export`). | Guaranteed |
| `http.request.method` | keyword | `GET` \| `POST` \| `PUT` \| `DELETE`. | Optional |
| `http.response.status_code` | integer | HTTP status returned. | Optional |
| `application.name` | keyword | Application identifier (e.g. `orders-portal`). | Guaranteed |
| `user.name` | keyword | Authenticated app user, where present. | Optional |

### `admin` — administrative activity

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `admin.action` | keyword | Administrative action (e.g. `ssh_session_open`, `config_change`). | Guaranteed |
| `user.name` | keyword | Administrator account. | Optional |
| `source.plane` | keyword | Originating trust plane. Serves #1 (plane crossing). | Optional |
| `destination.plane` | keyword | Target trust plane. Serves #1. | Optional |

### `endpoint` — endpoint / process (optional family)

| Field | Type | Meaning | Guaranteed |
|---|---|---|---|
| `process.name` | keyword | Process image name. Present only on select hosts. | Optional |
| `process.command_line` | keyword | Process command line. Sparse. | Optional |

---

## Candidate-class support map

Which families and fields each candidate class draws on. This maps only the
telemetry each class relies on; it does not say which events are benign or
malicious.

| # | Candidate class | Primary family | Key fields |
|---|---|---|---|
| 1 | Cross-plane admin / lateral movement | `admin` (+`network`) | `admin.action`, `source.plane`, `destination.plane` |
| 2 | Auth failures then success | `identity` | `event.action`, `authentication.privileged`, `workshop.enrichment.failed_logins_same_source_5m` |
| 3 | Logging / security-control impairment | `cloud` | `cloud.api_operation` (e.g. `StopLogStream`), `cloud.actor.principal` |
| 4 | Unexpected privilege / IAM change | `cloud` | `iam.change.type`, `iam.target.principal`, `cloud.actor.principal` |
| 5 | Suspicious Tier-1 app access | `application` | `application.name`, `url.path`, `client.address`, `user.name` |
| 6 | Bulk outbound transfer | `network` | `event.action: flow_summary`, `network.bytes_out_10m`, `source.ip` |
| 7 | Secrets-mgmt problem (NOT detectable) | — | **none — telemetry gap** (see above) |
| 8 | Noisy automation / service account | `identity` / `cloud` | `user.name` (e.g. `svc-*`), `cloud.actor.type: service_account` |
