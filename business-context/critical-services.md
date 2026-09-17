# Critical Services — Kestrel Freight Cloud

> Fictional and synthetic. All names, accounts, and
> identifiers are invented. Documentation-safe identifiers only.

## Company profile

Kestrel Freight Cloud (KFC) is a fictional cloud-native freight-orchestration
company. It provides regional carriers a single platform to book shipments, track
vehicles, and settle billing. ~180 staff; a lean security team of three. All
customer-facing capability runs on a vendor-neutral fictional cloud (see
`architecture/`). Revenue depends on the platform being available and on carrier
and shipment data staying confidential and intact.

## Business services and dependencies

| Service | What it does | Depends on |
|---|---|---|
| Orders Portal (`orders-portal`) | Tier-1: carriers book/track shipments, export manifests | Identity service, Orders DB, object storage |
| Dispatch Engine | Assigns loads to vehicles | Orders DB, message bus |
| Billing & Settlement | Invoices carriers | Orders DB, object storage |
| Identity Service | Authenticates staff, carriers, service accounts | (foundational for all) |
| Object/Data Storage | Manifests, PoD scans, billing exports | Secrets manager (access keys) |
| Secrets Manager | Holds DB creds, API keys, storage keys | (foundational) |
| Logging / SIEM pipeline | Collects telemetry to Elastic | All planes |

## Criticality classification

| Tier | Services | Meaning |
|---|---|---|
| Tier-1 | Orders Portal, Identity Service | Outage stops carrier operations and revenue |
| Tier-2 | Dispatch Engine, Object Storage | Degrades operations; short outage tolerable |
| Tier-3 | Billing & Settlement | Delayable; no real-time carrier impact |

## RTO / RPO (simplified)

| Service | RTO | RPO |
|---|---|---|
| Orders Portal | 1 hour | 5 minutes |
| Identity Service | 1 hour | 15 minutes |
| Dispatch Engine | 4 hours | 1 hour |
| Object Storage | 4 hours | 1 hour |
| Billing & Settlement | 24 hours | 24 hours |

## Important identities / service accounts

| Identity | Type | Purpose | Note |
|---|---|---|---|
| `svc-replicator` | service account | Replicates Orders DB to storage | Noisy: high-volume, periodic — looks like exfil (candidate #8) |
| `svc-billing-export` | service account | Nightly billing export to storage | Scheduled bulk transfer |
| `j.okafor` | user (admin) | Platform administrator | Privileged; crosses to management plane |
| `a.mensah` | user (operator) | SOC/operations | Read-heavy |
| `carrier-*` | federated users | Carrier logins to Orders Portal | Untrusted origin |

## Network / cloud trust zones

- **Corporate access zone** — staff devices, admin workstations.
- **Workload plane** — Orders Portal, Dispatch, Billing, Orders DB.
- **Management/control plane** — cloud control-plane API, IAM, secrets manager,
  logging pipeline config.
- **Trust boundary:** corporate/workload -> management crossings are sensitive.
  Admin access should originate only from approved paths (candidate #1).

## Business impact of disruption / compromise

| Event | Impact |
|---|---|
| Orders Portal outage | Carriers cannot book/track; direct revenue loss; RTO 1h |
| Identity compromise | Account takeover across all services; regulatory exposure |
| Object-storage exfiltration | Carrier/shipment data disclosure; contractual + reputational harm |
| Logging impairment | Loss of detection/forensic capability; hides other attacks (candidate #3) |
| Secrets-manager misuse | Undetectable today — no audit telemetry (candidate #7) |
