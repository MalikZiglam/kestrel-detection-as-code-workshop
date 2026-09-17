# Use-Case Assessment — team-01

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

- Security problem: A privileged account may be compromised through repeated password guessing followed by a successful authentication from the same source. The compromised account could then be used to access the Tier-1 Orders Portal.

- Supporting evidence: `evidence/incident-postmortem.md`, sections “What happened,” “Contributing gaps,” and “What we changed,” document repeated failed logins against a privileged account followed by a successful authentication from the same source. The authenticated session subsequently reached the Orders Portal. `evidence/threat-brief.md`, section “Credential-first entry,” identifies password guessing followed by a success from the same origin as a common intrusion pattern. `evidence/pentest-purple-team-findings.md`, section “Cross-cutting observations,” recommends monitoring repeated authentication failures followed by a successful login against a privileged account.

- Business impact: If undetected, a compromised privileged account could provide unauthorized access to the Tier-1 Orders Portal and its carrier manifest data. In the documented incident, suspicious activity was detected approximately 14 hours later by an operator rather than through an automated alert.

- Available telemetry: The required `log_source` family is `identity`. The incident post-mortem confirms that authentication events contain a rolling five-minute failed-login count per source and an explicit privileged-account indicator. The rule also requires a successful-authentication event and the originating source. Exact field names must match the `identity` entries in `logs/field-dictionary.md`; no undocumented field should be added.

- Detectability: `detectable`. The post-mortem explicitly states that the required failure-to-success signal is available in the enriched authentication records. The detection still requires a defined failed-login threshold and validation against the supplied identity log samples.

- Priority / rationale: High. The use case involves a privileged account, a documented previous incident, and access to a Tier-1 service. The required correlation signal is available in the identity telemetry, making this a high-impact and technically achievable detection.

## Candidate 2

- Security problem: An attacker with control-plane access may stop or reconfigure a logging stream feeding the SIEM. This creates a visibility gap in which later attacker actions may go unobserved.

- Supporting evidence: `evidence/pentest-purple-team-findings.md`, finding F2, documents that an actor stopped a log stream feeding the SIEM pipeline and re-enabled it minutes later. Actions during that gap went unobserved. `evidence/threat-brief.md`, section “Blind defenders early,” identifies pausing or reconfiguring a log stream as a way attackers weaken telemetry. `evidence/pentest-purple-team-findings.md`, section “Recommended focus,” recommends alerting on interference with the logging pipeline.

- Business impact: If undetected, logging interference reduces the security team’s visibility during an active intrusion. Unauthorized control-plane operations, privilege changes, or access to sensitive services performed during the gap may not be available for timely detection and investigation.

- Available telemetry: The required `log_source` family is `cloud`. The documented fields carrying the signal are `cloud.api_operation`, which identifies the control-plane operation, and `cloud.actor.principal`, which identifies the principal that performed it. The exact operation value representing the stopped log stream must be taken from `logs/field-dictionary.md` and the supplied cloud log records.

- Detectability: `detectable`. Finding F2 explicitly states that this behavior was observed in the `cloud` telemetry family and identifies the operation and actor fields carrying the signal.

- Priority / rationale: High. Logging interference can hide subsequent malicious activity and directly weaken the organization’s detection capability. The event is visible in existing telemetry, uses a focused set of documented fields, and should be comparatively straightforward to test.

## Candidate 3

- Security problem: An attacker may grant a new administrative permission to a principal under their control. This can provide persistent privileged access even after the originally compromised credentials are disabled.

- Supporting evidence: `evidence/pentest-purple-team-findings.md`, finding F3, documents a new administrative permission granted to a principal that had not previously held it through a single control-plane call, with no corresponding change ticket. `evidence/threat-brief.md`, section “Grant themselves rights,” identifies new role or permission assignments as attacker behavior. `evidence/pentest-purple-team-findings.md`, section “Recommended focus,” recommends monitoring privilege and IAM grants to unexpected principals.

- Business impact: If undetected, an unauthorized administrative permission could provide persistent access to the control plane and sensitive services. The principal could potentially modify security controls, access protected information, or make further administrative changes.

- Available telemetry: The required `log_source` family is `cloud`. The documented fields are `iam.change.type`, identifying the IAM change; `iam.target.principal`, identifying the principal receiving the permission; and `cloud.actor.principal`, identifying the principal making the change. The evidence does not identify a change-ticket field, so a rule must not claim to correlate change tickets unless such telemetry is documented in `logs/field-dictionary.md`.

- Detectability: `partially detectable (needs enrichment or tuning)`. The permission change, target principal, and acting principal are observable. However, determining whether the change is authorized or whether the target principal is expected requires approved-principal context, an allowlist, or change-management enrichment that is not confirmed in the available evidence.

- Priority / rationale: High. An unauthorized administrative grant can establish persistent privileged access and has significant security impact. The core event is observable, but additional context is required to distinguish malicious grants from legitimate administrative changes.

## Selected use case

- Which candidate (1 / 2 / 3): Candidate 2

- Why this one was selected: Candidate 2 was selected because interference with the logging pipeline can immediately reduce security visibility and allow subsequent attacker actions to go unobserved. The purple-team engagement directly reproduced the behavior, and the evidence identifies both the required telemetry family and the specific fields carrying the signal. Unlike Candidate 3, the core logic does not require undocumented change-ticket or authorization context. It therefore provides a strong combination of high impact, clear evidence, detectability, and manageable implementation effort.

- Key assumptions (mark each as fact vs assumption):
  - Fact: The purple-team actor stopped a log stream feeding the SIEM pipeline.
  - Fact: The actor re-enabled the stream minutes later.
  - Fact: Actions performed during the logging gap went unobserved.
  - Fact: The stop-stream behavior was observed in the `cloud` telemetry family.
  - Fact: `cloud.api_operation` carries the performed operation.
  - Fact: `cloud.actor.principal` carries the acting principal.
  - Fact: The threat brief identifies pausing or reconfiguring logging as behavior that can weaken defensive visibility.
  - Assumption: The supplied cloud logs contain an exact `cloud.api_operation` value representing the stop-stream behavior. This value must be copied from the supplied data rather than invented.
  - Assumption: Legitimate administrators or automation may occasionally perform similar logging operations.
  - Assumption: If legitimate actors exist in the supplied data, they may need to be handled through a documented exception or tuning condition.

- Required telemetry (families + specific fields it depends on):
  - Telemetry family: `cloud`
  - Required field: `cloud.api_operation`
  - Required field: `cloud.actor.principal`
  - Required value: the documented `cloud.api_operation` value representing the stopping or disabling of the log stream
  - Required validation source: `logs/field-dictionary.md`
  - Required test source: supplied cloud log samples
  - Optional tuning context: documented approved administrative principals or automation accounts, but only if those values are present in the supplied workshop material
