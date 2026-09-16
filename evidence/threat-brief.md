# Threat-Context Brief — Freight-Orchestration Platforms

> Fictional briefing for the KFC security team. Synthetic and documentation-safe.
> Context only — it names behaviors to reason about, not rule logic.

## Why KFC is a target

KFC holds shipment manifests, carrier data, and billing records, and runs a
control plane that governs them. Two things draw intruders: **carrier/shipment
data** worth exfiltrating, and a **control plane** whose keys unlock everything
below it. An outage also stops carrier revenue.

## Behaviors seen against similar platforms

- **Credential-first entry.** Intruders log in rather than exploit. Password
  guessing against a valued account, then a clean success from the same origin,
  is a common opening move.
- **Move to the control plane.** From a workload foothold, actors seek the
  management plane, where logging, identity, and keys live. Crossings that skip
  the sanctioned admin path are a strong tell.
- **Blind defenders early.** A capable actor's first control-plane act is often
  to weaken telemetry — pausing or reconfiguring a log stream so later steps go
  unobserved. Logging gaps are themselves a signal.
- **Grant themselves rights.** Rather than hold stolen creds, actors attach a new
  role or permission to a principal they control. A privilege change with no
  business reason warrants a hard look.
- **Reach the crown-jewel app.** The Tier-1 Orders Portal and its manifest export
  are a direct route to bulk data. Access that ignores a carrier's normal booking
  rhythm deserves scrutiny.
- **Stage, then move data out.** Exfiltration shows as outbound volume above a
  source's baseline — hard to judge, because legitimate replication and nightly
  billing exports look the same. Context and thresholds separate them.
- **Abuse secrets stores.** Where a secrets manager issues DB and storage
  credentials, actors target it for durable keys. If that store is unaudited, the
  abuse leaves no trace — a coverage risk to raise early.

## Framing

Map each behavior to the telemetry KFC actually collects, and be honest where it
collects none. A defensible outcome for an unobservable behavior is a **telemetry
requirement**, not a rule against fields that do not exist. Rules that ignore
known automation bury the team in false positives; context and tuning are the job.
