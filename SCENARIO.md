# Scenario

> **Everything here is fictional and synthetic.** No real company, person, IP,
> hostname, or system is represented. See `WORKSHOP_SPEC.md` §7.

> **Fictional org name pending human sign-off (§38 item 3):** **Kestrel Freight
> Cloud**. "Kestrel" is a coined word chosen to avoid collision with a real
> firm. Confirm no real-world collision before any public release. Network access
> was unavailable during authoring, so the collision check has not been performed.

## The engagement

You have joined a small **security-improvement engagement** for **Kestrel
Freight Cloud (KFC)**, a fictional cloud-native freight-orchestration company. KFC
runs a shipment-tracking and dispatch platform for regional carriers. It has a
lean security team and has asked for help maturing its detection capability.

You are not rebuilding KFC's platform. You work from the evidence a short
engagement produces: architecture notes, business-continuity material, a
purple-team assessment, an incident post-mortem, a threat brief, synthetic log
samples, and a small existing detection catalogue.

## Your job in 90 minutes

1. Read the evidence and understand what KFC runs and what matters to it.
2. Find candidate security-monitoring problems the evidence supports.
3. Assess which are actually **detectable with the telemetry KFC has today**.
4. Prioritize, then engineer **one** detection as version-controlled code through
   a real branch -> commit -> pull request -> review -> CI -> merge -> Terraform
   -> Elastic -> replay lifecycle.

## What the evidence will show you

- A cloud environment split into **corporate**, **workload**, and **management**
  trust planes, with a Tier-1 orders portal, an identity service, object storage,
  and a secrets-management component.
- Telemetry from several **log families** — identity, network/flow, cloud
  control-plane, application access, administrative activity — described in the
  canonical [`logs/field-dictionary.md`](logs/field-dictionary.md).
- Realistic gaps and noise: at least one important problem KFC **cannot currently
  detect** because the telemetry is missing, and at least one **noisy automation
  account** that looks suspicious but is legitimate.

## Ground rules

- Use **only** the supplied evidence and the documented telemetry. Do not invent
  log fields; CI and review will catch invented fields.
- A valid outcome can be **"not detectable — onboard this telemetry first."**
- The field dictionary is authoritative for what exists. When in doubt, check it.
