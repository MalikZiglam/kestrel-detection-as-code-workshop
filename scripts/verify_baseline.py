#!/usr/bin/env python3
"""Verify the workshop baseline against the golden state (WORKSHOP_SPEC.md §22.1).

Reports whether:
  - expected baseline detections exist in Git under detections/baseline/;
  - each declares a coherent status/deployment (which SHOULD be deployed);
  - (when creds present) the expected-to-be-deployed rules exist in Elastic and
    no stale workshop rules remain.

Bounded and honest: with no creds it verifies Git only and says so. It does NOT
inspect Terraform state (that belongs to the Terraform tooling); it reports the
Git-declared desired set and the live Elastic set, and flags drift between them.

Config is ENV-only; read-only (never writes, so no confirm gate).

Fail-closed: RESULT: CLEAN is printed ONLY when BOTH the Git expected set AND the
live Elastic set were fetched and compared. Missing creds or a failed Elastic
query is UNAVAILABLE (reconciliation NOT proven), never a clean exit.

Env (optional — absence is UNAVAILABLE, not clean):
  ELASTIC_ES_ENDPOINT   Serverless Elasticsearch URL
  ELASTIC_KB_ENDPOINT   Serverless Kibana URL (detection rules live in Kibana)
  ELASTIC_API_KEY       base64 API key
  ELASTIC_SPACE         Kibana space (default: default)

Exit: 0 = CLEAN (Git and live Elastic compared, no drift); 2 = DRIFT or missing
baseline; 3 = UNAVAILABLE/ERROR (could not compare, incl. missing creds or a
failed Elastic query).
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
BASELINE_DIR = os.path.join(REPO_ROOT, "detections", "baseline")

DEPLOYABLE_STATUS = {"test", "production"}

# Exit codes: CLEAN=0, DRIFT/missing-baseline=2, UNAVAILABLE/ERROR=3 (fail-closed).
EXIT_CLEAN = 0
EXIT_DRIFT = 2
EXIT_UNAVAILABLE = 3


def _scan_field(text: str, key: str) -> str | None:
    """Read a top-level `key: value` scalar from a detection.yaml without a YAML
    dependency. Handles `key: value` and quoted values; ignores nested keys."""
    for raw in text.splitlines():
        if raw.startswith(f"{key}:"):
            value = raw.split(":", 1)[1].strip()
            return value.strip('"').strip("'")
    return None


def _scan_enabled(text: str) -> bool:
    """Read deployment.enabled (nested one level under `deployment:`)."""
    in_deploy = False
    for raw in text.splitlines():
        if raw.startswith("deployment:"):
            in_deploy = True
            continue
        if in_deploy:
            if raw and not raw[0].isspace():
                break  # left the deployment block
            if raw.strip().startswith("enabled:"):
                return raw.split(":", 1)[1].strip().lower() == "true"
    return False


def scan_git_baseline() -> list[dict]:
    rules: list[dict] = []
    if not os.path.isdir(BASELINE_DIR):
        return rules
    for name in sorted(os.listdir(BASELINE_DIR)):
        path = os.path.join(BASELINE_DIR, name, "detection.yaml")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        rule_id = _scan_field(text, "id") or name
        status = _scan_field(text, "status") or "unknown"
        enabled = _scan_enabled(text)
        should_deploy = status in DEPLOYABLE_STATUS and enabled
        rules.append(
            {"rule_id": rule_id, "status": status, "enabled": enabled, "should_deploy": should_deploy}
        )
    return rules


def fetch_elastic_rule_ids(kb_endpoint: str, api_key: str, space: str) -> set[str] | None:
    """Return the set of rule_id values in Kibana, or None on any failure."""
    base = kb_endpoint.rstrip("/")
    if space and space != "default":
        base = f"{base}/s/{space}"
    url = f"{base}/api/detection_engine/rules/_find?per_page=200"
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"ApiKey {api_key}")
    req.add_header("kbn-xsrf", "workshop-verify")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"  WARN: could not query Elastic detection rules: {exc}", file=sys.stderr)
        return None
    return {r.get("rule_id") for r in body.get("data", []) if r.get("rule_id")}


def main() -> int:
    print("=== verify_baseline (WORKSHOP_SPEC.md §22.1) ===")

    git_rules = scan_git_baseline()
    if not git_rules:
        print("FAIL: no baseline detections found under detections/baseline/.")
        return EXIT_DRIFT

    print(f"\nGit baseline: {len(git_rules)} detection(s)")
    for r in git_rules:
        flag = "DEPLOY" if r["should_deploy"] else "in-git-only"
        print(f"  [{flag:11s}] {r['rule_id']}  (status={r['status']}, enabled={r['enabled']})")

    expected_deployed = {r["rule_id"] for r in git_rules if r["should_deploy"]}
    print(
        "\nExpected deployed set (status in",
        sorted(DEPLOYABLE_STATUS),
        "with enabled=true):",
        len(expected_deployed),
    )
    for rid in sorted(expected_deployed):
        print(f"  - {rid}")

    kb_endpoint = os.environ.get("ELASTIC_KB_ENDPOINT", "").strip()
    api_key = os.environ.get("ELASTIC_API_KEY", "").strip()
    if not (kb_endpoint and api_key):
        print("\nRESULT: UNAVAILABLE — ELASTIC_KB_ENDPOINT / ELASTIC_API_KEY not set.")
        print("Reconciliation NOT proven: the live Elastic set could not be fetched, so")
        print("Git-vs-Elastic drift is unknown. Run WITH creds to get a real CLEAN.")
        return EXIT_UNAVAILABLE

    space = os.environ.get("ELASTIC_SPACE", "default").strip() or "default"
    live = fetch_elastic_rule_ids(kb_endpoint, api_key, space)
    if live is None:
        print("\nRESULT: UNAVAILABLE — Elastic query failed; live rule set unknown.")
        print("Reconciliation NOT proven. This is not a clean state.")
        return EXIT_UNAVAILABLE

    missing = expected_deployed - live
    stale = {rid for rid in live if rid not in expected_deployed and str(rid).startswith("baseline-")}

    print(f"\nElastic live rules: {len(live)}")
    drift = False
    if missing:
        drift = True
        print("  DRIFT: expected-deployed rules absent from Elastic:")
        for rid in sorted(missing):
            print(f"    - {rid}")
    if stale:
        drift = True
        print("  DRIFT: stale baseline rules in Elastic not in the expected set:")
        for rid in sorted(stale):
            print(f"    - {rid}")
    if not drift:
        print("  OK: Elastic matches the Git-declared expected-deployed baseline.")

    print(f"\nRESULT: {'DRIFT' if drift else 'CLEAN'}")
    return EXIT_DRIFT if drift else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
