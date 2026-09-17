# MITRE ATT&CK Guide

MITRE ATT&CK is the primary framework for this workshop. Each
detection maps to a tactic, a technique (optionally a sub-technique), and — where
they fit — a Detection Strategy and Data Components. A correct technique ID with
no supporting telemetry is NOT a strong detection.

## Pinned local subset

CI must not depend on live Internet lookups on workshop day. `docs/attack/attack-subset.yaml`
is a PINNED, LOCAL subset of ATT&CK Enterprise covering only the tactics,
techniques, and sub-techniques relevant to the 8 candidate classes and the 6
baseline example rules.

- `attack_version` and `pinned_on` in that file record exactly which release the
  subset was cut from.
- The subset is deliberately narrow (~30 ids). It is not the whole framework.
- Offline and deterministic: the validator reads the file, never the network.
- **The pinned version is intentional, not a currency claim.** `attack_version`
  (e.g. `v16.1`) names the release this subset was authored from so the check is
  reproducible; it is **not** asserted to be the newest ATT&CK release at workshop
  time. Whether to adopt a newer ATT&CK version is a separate, deliberate
  facilitator decision — the validator only checks id *existence* against whatever
  version is pinned here.

## Deterministic check vs human/AI judgment (the boundary)

This split is a core teaching point.

| Question | Who answers | Where |
|---|---|---|
| Does `Txxxx` / `Txxxx.yyy` / `TAxxxx` EXIST in the pinned subset, and is it well-formed? | Deterministic CI (`scripts/validate_detections.py`, L2) | PR-time, binary pass/fail |
| Is this the RIGHT technique for what the rule actually detects? | Human reviewer + Claude qualitative review | Review-time, judgment |

CI answers only existence and format. It never scores mapping quality. "Wrong but
real" technique IDs pass CI and are caught by human/AI review — by design. If you
need a technique the subset lacks, the fix is to extend `attack-subset.yaml` (a
facilitator change under a protected path), not to invent an ID.

## How the validator uses ATT&CK

`scripts/validate_detections.py` L2 SEMANTIC checks every id in a detection's
`mitre_attack` block against the pinned subset:

- `tactics:` entries must match `TAxxxx` and exist in the subset;
- `techniques:` entries must match `Txxxx` and exist;
- `subtechniques:` entries must match `Txxxx.yyy` and exist.

A malformed or unknown id fails L2 (non-zero exit). Remember the level ladder:
L1 structural pass != L2 semantic pass != runtime pass.
