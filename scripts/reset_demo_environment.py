#!/usr/bin/env python3
"""Reset the demo environment toward the golden baseline (WORKSHOP_SPEC.md §22.1).

Workshop-depth reset: bring the Elastic demo project back to the known starting
state before a rehearsal or the live run, so the Terraform teaching moment is not
polluted by old rehearsal drift.

Scope (bounded and honest):
  - Reports the Git-declared golden baseline (the desired deployed set).
  - When creds are present, DELETES stale workshop detection rules left in Kibana
    from a previous rehearsal (rule_id starting with `workshop-`, or a participant
    team id `teamNN-...` such as `team01-cross-plane-admin`), so only the baseline
    remains. It does NOT create/deploy rules — Terraform apply owns desired-state
    deployment. Order: clear stale drift with this script, THEN `terraform apply`,
    THEN `verify_baseline.py`.
  - It does NOT touch Git or Terraform state; those are reset with git + terraform
    directly. This script only clears live rehearsal drift in Elastic.
  - baseline-* rules are NEVER selected for deletion (the golden baselines survive).

Config is ENV-only; deletes are gated behind WORKSHOP_CONFIRM=yes. Without creds
it prints the intended plan and the manual reset sequence, then exits cleanly.

Env:
  ELASTIC_KB_ENDPOINT   Serverless Kibana URL
  ELASTIC_API_KEY       base64 API key
  ELASTIC_SPACE         Kibana space (default: default)
  WORKSHOP_CONFIRM      must be "yes" to delete stale rules
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
BASELINE_DIR = os.path.join(REPO_ROOT, "detections", "baseline")

# Rehearsal-drift rule_ids, safe to clear on reset:
#   - `workshop-...`  facilitator rehearsal rules
#   - `teamNN-...`    participant rules (WORKSHOP_SPEC.md §, GITHUB-SETUP.md, and
#                     templates/foundation-detection-template.yaml document the
#                     convention as teamNN-<slug>, e.g. team01-cross-plane-admin).
# The prior ("workshop-", "team-") tuple MISSED team01-... (no hyphen after team).
STALE_RE = re.compile(r"^(workshop-|team\d)")

# baseline-* rules are the golden set and must NEVER be deleted, regardless of any
# future STALE_RE change. Hard guard applied in is_stale_rule_id().
PROTECTED_PREFIX = "baseline-"


def is_stale_rule_id(rule_id: str) -> bool:
    """True if rule_id is rehearsal drift safe to delete. Protected baselines are
    never stale, even if STALE_RE is later broadened."""
    if not rule_id:
        return False
    if rule_id.startswith(PROTECTED_PREFIX):
        return False
    return STALE_RE.match(rule_id) is not None


MANUAL_SEQUENCE = """\
Manual golden-baseline reset sequence (run in this order):
  1. git checkout main && git pull            # Git back to the golden baseline
  2. python3 scripts/reset_demo_environment.py # clear stale rehearsal rules (this script)
  3. terraform -chdir=terraform init           # provider ready
  4. terraform -chdir=terraform plan           # inspect the desired change
  5. terraform -chdir=terraform apply          # desired-state deploy of baseline
  6. python3 scripts/verify_baseline.py        # confirm Git == Elastic, no drift\
"""


def _kb_base(kb_endpoint: str, space: str) -> str:
    base = kb_endpoint.rstrip("/")
    if space and space != "default":
        base = f"{base}/s/{space}"
    return base


def _find_rules(base: str, api_key: str) -> list[dict] | None:
    url = f"{base}/api/detection_engine/rules/_find?per_page=200"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"ApiKey {api_key}")
    req.add_header("kbn-xsrf", "workshop-reset")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"  WARN: could not query Elastic detection rules: {exc}", file=sys.stderr)
        return None
    return body.get("data", [])


def _delete_rule(base: str, api_key: str, rule_id: str) -> bool:
    url = f"{base}/api/detection_engine/rules?rule_id={urllib.parse.quote(rule_id)}"
    req = urllib.request.Request(url, method="DELETE")
    req.add_header("Authorization", f"ApiKey {api_key}")
    req.add_header("kbn-xsrf", "workshop-reset")
    try:
        with urllib.request.urlopen(req, timeout=30):
            return True
    except (urllib.error.HTTPError, urllib.error.URLError) as exc:
        print("  WARN: could not remove rule", rule_id, "-", exc, file=sys.stderr)
        return False


def golden_baseline_ids() -> list[str]:
    ids: list[str] = []
    if os.path.isdir(BASELINE_DIR):
        for name in sorted(os.listdir(BASELINE_DIR)):
            if os.path.isfile(os.path.join(BASELINE_DIR, name, "detection.yaml")):
                ids.append(name)
    return ids


def main() -> int:
    print("=== reset_demo_environment (WORKSHOP_SPEC.md §22.1) ===")

    baseline = golden_baseline_ids()
    print(f"\nGolden baseline in Git: {len(baseline)} detection(s)")
    for rid in baseline:
        print(f"  - {rid}")

    kb_endpoint = os.environ.get("ELASTIC_KB_ENDPOINT", "").strip()
    api_key = os.environ.get("ELASTIC_API_KEY", "").strip()
    if not (kb_endpoint and api_key):
        print("\nElastic reset SKIPPED: ELASTIC_KB_ENDPOINT / ELASTIC_API_KEY not set.")
        print("Nothing was changed. To reset the live project, set creds and re-run.\n")
        print(MANUAL_SEQUENCE)
        return 0

    space = os.environ.get("ELASTIC_SPACE", "default").strip() or "default"
    base = _kb_base(kb_endpoint, space)

    rules = _find_rules(base, api_key)
    if rules is None:
        print("\nElastic query failed. Nothing changed. Manual sequence:\n")
        print(MANUAL_SEQUENCE)
        return 0

    stale = [r.get("rule_id") for r in rules if is_stale_rule_id(str(r.get("rule_id") or ""))]
    if not stale:
        print("\nNo stale workshop/team rules in Elastic. Environment is clean.")
        return 0

    print(f"\nStale rehearsal rules to clear: {len(stale)}")
    for rid in stale:
        print(f"  - {rid}")

    if os.environ.get("WORKSHOP_CONFIRM", "no") != "yes":
        print("\nDRY RUN: set WORKSHOP_CONFIRM=yes to delete the stale rules above.")
        print("(Baseline rules are never deleted by this script.)")
        return 0

    deleted = sum(1 for rid in stale if _delete_rule(base, api_key, rid))
    print(f"\nDeleted {deleted}/{len(stale)} stale rule(s).")
    print("Now run `terraform apply` (desired-state deploy) then verify_baseline.py.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
