# Incident Post-Mortem — Orders Portal Admin Account Takeover

> Fictional past incident, reconstructed for learning. Synthetic,
> documentation-safe identifiers only. Timeline is illustrative.

**Incident ID:** KFC-IR-0142 (closed)
**Severity:** High — privileged access to a Tier-1 service
**Services touched:** Identity Service, Orders Portal (Tier-1)

## What happened

An external actor gained interactive access to a **privileged KFC account** by
guessing its password from a single source address. Over a short window the
Identity Service recorded a **burst of failed logins** from that source against
the account, followed by a **successful authentication** from the same source.
No brute-force lockout or alert fired at the time; the security team learned of
the access only when an operator noticed unfamiliar portal activity the next
morning.

With the account authenticated, the actor reached the **Orders Portal** and
browsed carrier manifests before the session was terminated. There was no
confirmed data export in this incident, but the actor was one step from the
manifest export path.

## Timeline (illustrative)

| Time | Event | Where |
|---|---|---|
| T+0 | Repeated failed logins from a single external source against a privileged account | `idp.ctrl.example` (`identity`) |
| T+6m | Successful login from the **same source**, same account | `idp.ctrl.example` (`identity`) |
| T+9m | Session reaches the Orders Portal; carrier manifests browsed | `app-orders.example` (`application`) |
| +14h | Operator spots anomalous portal activity; account disabled, session killed | — |

## Contributing gaps

- **No failure-to-success correlation.** The auth telemetry contained the
  signal — the same source produced many failures then a success — but nothing
  correlated the two. A rolling failed-login count per source, stamped on each
  auth event, would have made this a single-document detection.
- **Privileged accounts were not treated differently.** The account was
  privileged, yet its auth events were not prioritized over ordinary logins.
- **Detection lag was human-paced.** Discovery took ~14 hours and depended on an
  operator's eye, not an alert.
- **Tier-1 proximity.** Once authenticated, the actor was directly on the
  Orders Portal. Suspicious access to a Tier-1 service deserves its own signal,
  independent of how the account was obtained.

## What we changed

- Enabled an upstream enrichment that stamps a **rolling 5-minute failed-login
  count per source** onto every auth event, so a success preceded by many
  failures is visible in one record.
- Flagged privileged accounts explicitly at authentication so detections can
  target them.
- Opened a follow-on to watch Tier-1 (Orders Portal) access patterns directly.

## Still open

The purple-team engagement later showed the same privileged-access exposure can
be reached other ways (unexpected plane crossings, unmonitored IAM grants). This
incident closed the auth-correlation gap; it did not close every path to
privileged access.
