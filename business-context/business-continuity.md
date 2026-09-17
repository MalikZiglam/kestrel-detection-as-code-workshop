# Business Continuity — Kestrel Freight Cloud

> Fictional and synthetic. Invented content only.

Business continuity management (BCM) at KFC exists to keep carrier operations
running through disruption and to recover quickly when prevention fails. This
brief gives detection engineers the continuity context that shapes severity and
priority: what must stay up, how fast it must return, and what a compromise costs.

## Continuity objectives

KFC's board sets one continuity principle: **carriers must be able to book and
track shipments.** The Orders Portal and the Identity Service it depends on are
therefore the continuity anchors. Everything else is recoverable on a slower clock
(see RTO/RPO in `critical-services.md`).

## Dependency chain that matters for continuity

```text
Carrier  ->  Orders Portal  ->  Identity Service
                   |                 |
                   v                 v
              Orders DB   <-   Secrets Manager (DB creds, storage keys)
                   |
                   v
             Object Storage (manifests, exports)
```

A break anywhere on this chain degrades the Tier-1 service. The Secrets Manager is
a single point of trust: its credentials unlock the database and storage. KFC has
**no audit telemetry** on the Secrets Manager today, so misuse there is a
continuity risk it cannot currently see (feeds candidate #7).

## Backup and recovery posture

| Asset | Backup | Recovery method |
|---|---|---|
| Orders DB | Continuous replication + hourly snapshot | Promote replica / restore snapshot |
| Object Storage | Versioned objects | Restore prior version |
| Detection rules (this repo) | Git history + Terraform state | Revert commit, `terraform apply` (see `docs/rollback-explained.md`) |
| Identity config | Daily config export | Re-import config |

## Continuity risks a compromise creates

- **Availability:** an account takeover or IAM change (candidates #2, #4) can lock
  out operators or disable services, breaching the 1-hour Orders RTO.
- **Integrity:** tampering with Orders DB or manifests corrupts shipment records;
  RPO limits data loss to minutes for Tier-1.
- **Confidentiality:** bulk outbound transfer of carrier data (candidate #6)
  breaches carrier contracts even with zero downtime.
- **Detection continuity:** disabling the logging pipeline (candidate #3) blinds
  the SOC and undermines every other control — treated as high severity.

## Detection engineering as a continuity control

Version-controlled detections are themselves a continuity asset. Because rules
live in Git and deploy through Terraform, a bad rule that floods the SOC can be
**reverted to a known-good state** on the same clock as any other change — the
rollback discipline. Continuity is not only about servers staying up; it is
about being able to trust, change, and restore the controls that protect them.
