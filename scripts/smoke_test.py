#!/usr/bin/env python3
"""Bounded schedule-based runtime smoke test for a workshop baseline detection.

Reuses the PROVEN spike pattern (spike-kit/spike2-runtime/measure_latency.sh):
NO manual rule run — the deployed rule fires on its own ~1-minute schedule. Each
replay assigns a UNIQUE per-run event.id; we poll the alerts index for an alert
that carries BOTH the rule's rule_id AND that unique event.id, so a stale or
unrelated alert can never count.

Flow per rule:
  positive: replay positive fixture (unique run event.id) -> poll
            .alerts-security.alerts-default for an alert with rule_id AND that
            event.id -> measure ingest->alert seconds (expect ~12-75s on schedule;
            timeout 120s) -> PASS if seen.
  negative: replay negative fixture (unique run event.id) -> confirm NO alert
            carries that event.id within a bounded window -> PASS only if every
            query succeeded and none matched.

Fail-closed: a query/API/index failure is NEVER counted as "0 alerts". It yields
an ERROR/INCONCLUSIVE result and a non-zero exit — never a silent PASS or clean 0.

Exit codes: PASS=0; FAIL=2; ERROR/INCONCLUSIVE=3.

Config is ENV-only (never printed); replay is write-gated by WORKSHOP_CONFIRM=yes.

Env:
  ELASTIC_ES_ENDPOINT   Serverless Elasticsearch URL (required)
  ELASTIC_API_KEY       base64 API key (required)
  WORKSHOP_CONFIRM      must be "yes" (passed through to replay_events.py)
  ELASTIC_SPACE         Kibana space; drives alerts index name (default: default)
  WORKSHOP_TIMEOUT_S    positive poll timeout seconds (default 120)
  WORKSHOP_NEG_WINDOW_S negative observation window seconds (default 90)
  WORKSHOP_POLL_EVERY_S poll interval seconds (default 4)

Usage:
  WORKSHOP_CONFIRM=yes smoke_test.py --rule-id baseline-object-store-policy-change
  WORKSHOP_CONFIRM=yes smoke_test.py --all
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
EXPECTATIONS = os.path.join(REPO_ROOT, "tests", "shared-fixtures", "expectations.yaml")

# Result states for one positive/negative check.
PASS = "PASS"
FAIL = "FAIL"
ERROR = "ERROR"  # could not query -> inconclusive, must never look like a pass

# Exit codes: PASS=0, FAIL=2 (unchanged), ERROR/INCONCLUSIVE=3 (new, fail-closed).
EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_ERROR = 3


class AlertQueryError(Exception):
    """Raised when an alert query could not be completed (HTTP/URL/JSON/index).

    Distinct from a successful query that returned 0 alerts. Callers MUST NOT
    treat this as '0 alerts' — it fails the run closed."""


def _require_env(name: str) -> str:
    val = os.environ.get(name, "").strip()
    if not val:
        sys.exit(f"FATAL: {name} is not set. This script is env-driven; nothing is hardcoded.")
    return val


def _alerts_index() -> str:
    space = os.environ.get("ELASTIC_SPACE", "default").strip() or "default"
    # Kibana-managed detection alerts data stream. VERIFY exact name per project
    # (GET {es}/_cat/indices/.alerts-security*?v). Matches the spike kit default.
    return os.environ.get("WORKSHOP_ALERTS_INDEX", f".alerts-security.alerts-{space}")


def _load_expectations() -> list[dict]:
    """Minimal parse of expectations.yaml without a YAML dependency.

    The file is a flat list of simple key: value records under `fixtures:`. We
    parse only the keys we need (path, rule_id, log_source, event_id,
    expected_alert) and ignore multi-line `why:` blocks.
    """
    fixtures: list[dict] = []
    current: dict | None = None
    in_fixtures = False
    with open(EXPECTATIONS, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            if stripped == "fixtures:":
                in_fixtures = True
                continue
            if not in_fixtures:
                continue
            if stripped.startswith("- "):
                if current:
                    fixtures.append(current)
                current = {}
                stripped = stripped[2:].strip()
            if current is None:
                continue
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip()
                value = value.strip().strip('"')
                if key in ("path", "rule_id", "log_source", "event_id", "expected_alert"):
                    if key == "expected_alert":
                        current[key] = value.lower() == "true"
                    elif value and value != ">":
                        current[key] = value
    if current:
        fixtures.append(current)
    # Drop records that lost their scalar fields to a following `why:` block.
    return [f for f in fixtures if f.get("path") and f.get("rule_id")]


def _count_run_alerts(endpoint: str, api_key: str, alerts_index: str, rule_id: str, event_id: str) -> int:
    """Count alerts carrying THIS event.id for THIS rule. Exact reuse of the spike
    correlation: rule_id is a hard must; event.id is matched across the flat and
    nested locations so a field-location difference cannot silently fail the gate.

    Fail-closed: raises AlertQueryError on any HTTP/URL/JSON/decode failure so the
    caller can distinguish 'queried fine, 0 alerts' from 'could not query'. It must
    NEVER return 0 on a query failure."""
    query = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [{"term": {"kibana.alert.rule.rule_id": rule_id}}],
                "should": [
                    {"term": {"event.id": event_id}},
                    {"term": {"event.id.keyword": event_id}},
                    {"match_phrase": {"kibana.alert.original_event.id": event_id}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    # No ignore_unavailable: a missing/unavailable alerts index MUST error, not
    # return 200 with zero hits (that would fail OPEN on a negative test).
    url = f"{endpoint.rstrip('/')}/{alerts_index}/_search"
    req = urllib.request.Request(url, data=json.dumps(query).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"ApiKey {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise AlertQueryError(str(exc)) from exc
    # Fail closed if the body signals a missing/unavailable index despite a 200
    # (some serverless configs report the error in the body, not the status).
    if isinstance(body, dict) and body.get("error") is not None:
        raise AlertQueryError(f"search error response: {body.get('error')}")
    # A well-formed hits.total is the ONLY thing that yields a count. A missing
    # hits/total, or an unrecognizable shape, is a query failure — never a silent 0.
    if not isinstance(body, dict) or "hits" not in body or not isinstance(body["hits"], dict):
        raise AlertQueryError(f"malformed search response: no hits object in {body!r}")
    if "total" not in body["hits"]:
        raise AlertQueryError(f"malformed search response: no hits.total in {body!r}")
    total = body["hits"]["total"]
    if isinstance(total, bool):
        raise AlertQueryError(f"malformed hits.total (bool): {total!r}")
    if isinstance(total, dict):
        value = total.get("value")
        if not isinstance(value, int) or isinstance(value, bool):
            raise AlertQueryError(f"malformed hits.total.value: {value!r}")
        return value
    if isinstance(total, int):
        return total
    raise AlertQueryError(f"malformed hits.total shape: {total!r}")


def _parse_ingested_ids(stdout: str) -> list[str]:
    """Extract the unique per-run event.ids from replay's INGESTED_EVENT_IDS= line."""
    for line in stdout.splitlines():
        if line.startswith("INGESTED_EVENT_IDS="):
            raw = line.split("=", 1)[1].strip()
            return [i for i in raw.split(",") if i]
    return []


def _replay(fixture_path: str, log_source: str, test_case: str) -> list[str]:
    """Invoke replay_events.py so ingest/timestamp-rewrite logic lives in one place.
    Captures stdout and returns the unique per-run event.ids it actually ingested,
    so the poller correlates on the real run id, not the static expectations value."""
    cmd = [
        sys.executable,
        os.path.join(HERE, "replay_events.py"),
        "--fixture",
        os.path.join(REPO_ROOT, fixture_path),
        "--log-source",
        log_source,
        "--test-case",
        test_case,
    ]
    result = subprocess.run(cmd, env=os.environ.copy(), capture_output=True, text=True)
    if result.stderr:
        sys.stderr.write(result.stderr)
    if result.returncode != 0:
        sys.exit(f"FATAL: replay failed for {fixture_path} (exit {result.returncode}).")
    ingested = _parse_ingested_ids(result.stdout)
    if not ingested:
        sys.exit(f"FATAL: replay for {fixture_path} emitted no INGESTED_EVENT_IDS line.")
    return ingested


def _check_positive(endpoint, api_key, alerts_index, fx, timeout_s, poll_every_s) -> str:
    rule_id = fx["rule_id"]
    print(f"\n[POSITIVE] {rule_id}  fixture event_id={fx['event_id']}", file=sys.stderr)
    print("  rule fires on its own ~1-min schedule; expecting an alert within the bound.", file=sys.stderr)
    t0 = time.monotonic()
    run_ids = _replay(fx["path"], fx["log_source"], "positive")
    event_id = run_ids[0]
    print(f"  polling for unique run event.id={event_id}", file=sys.stderr)
    while True:
        elapsed = int(time.monotonic() - t0)
        try:
            count = _count_run_alerts(endpoint, api_key, alerts_index, rule_id, event_id)
        except AlertQueryError as exc:
            # Fail closed: a query error is INCONCLUSIVE, never a benign timeout.
            print(f"  ERROR: alert query failed after {elapsed}s: {exc}")
            print("         Positive result INCONCLUSIVE — could not query alerts. Not a PASS, not a plain FAIL.")
            return ERROR
        if count >= 1:
            print(f"  PASS: alert seen (rule_id AND unique event.id). ingest->alert ~{elapsed}s")
            return PASS
        if elapsed >= timeout_s:
            print(f"  FAIL: TIMEOUT after {elapsed}s — queried OK but no alert carrying event.id={event_id}.")
            print("        Check the rule is enabled and running, the alerts index name, and event.id mapping.")
            return FAIL
        time.sleep(poll_every_s)


def _check_negative(endpoint, api_key, alerts_index, fx, window_s, poll_every_s) -> str:
    rule_id = fx["rule_id"]
    print(f"\n[NEGATIVE] {rule_id}  fixture event_id={fx['event_id']}", file=sys.stderr)
    print(f"  benign control; expecting NO alert within a {window_s}s window.", file=sys.stderr)
    run_ids = _replay(fx["path"], fx["log_source"], "negative")
    event_id = run_ids[0]
    print(f"  polling for unique run event.id={event_id}", file=sys.stderr)
    t0 = time.monotonic()
    # Observe for the full window: one schedule interval + margin. A PASS is only
    # valid if EVERY query in the window SUCCEEDED and none carried this run id. A
    # single query error makes the result INCONCLUSIVE — never a silent "0 -> PASS".
    while True:
        elapsed = int(time.monotonic() - t0)
        try:
            count = _count_run_alerts(endpoint, api_key, alerts_index, rule_id, event_id)
        except AlertQueryError as exc:
            print(f"  ERROR: alert query failed after {elapsed}s: {exc}")
            print("         Negative result INCONCLUSIVE — a query error can NOT count as PASS.")
            return ERROR
        if count >= 1:
            print(f"  FAIL: an alert carried the benign event.id={event_id} after {elapsed}s — rule too broad.")
            return FAIL
        if elapsed >= window_s:
            print(f"  PASS: queries succeeded across {window_s}s and no alert carried event.id={event_id}.")
            return PASS
        time.sleep(poll_every_s)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bounded schedule-based runtime smoke test.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--rule-id", help="Run the positive+negative check for one baseline rule_id.")
    group.add_argument("--all", action="store_true", help="Run every rule in expectations.yaml.")
    args = parser.parse_args()

    endpoint = _require_env("ELASTIC_ES_ENDPOINT")
    api_key = _require_env("ELASTIC_API_KEY")
    if os.environ.get("WORKSHOP_CONFIRM", "no") != "yes":
        sys.exit("FATAL: set WORKSHOP_CONFIRM=yes (replay writes to Elastic).")

    timeout_s = int(os.environ.get("WORKSHOP_TIMEOUT_S", "120"))
    neg_window_s = int(os.environ.get("WORKSHOP_NEG_WINDOW_S", "90"))
    poll_every_s = int(os.environ.get("WORKSHOP_POLL_EVERY_S", "4"))
    alerts_index = _alerts_index()

    fixtures = _load_expectations()
    if args.rule_id:
        fixtures = [f for f in fixtures if f["rule_id"] == args.rule_id]
        if not fixtures:
            sys.exit(f"FATAL: no fixtures for rule_id={args.rule_id} in {EXPECTATIONS}.")

    positives = [f for f in fixtures if f.get("expected_alert")]
    negatives = [f for f in fixtures if not f.get("expected_alert")]

    print(f"=== runtime smoke test (schedule-driven, NO manual run) ===", file=sys.stderr)
    print(f"alerts index: {alerts_index}  positive timeout: {timeout_s}s  negative window: {neg_window_s}s", file=sys.stderr)

    results: list[tuple[str, str, str]] = []
    for fx in positives:
        state = _check_positive(endpoint, api_key, alerts_index, fx, timeout_s, poll_every_s)
        results.append((fx["rule_id"], "positive", state))
    for fx in negatives:
        state = _check_negative(endpoint, api_key, alerts_index, fx, neg_window_s, poll_every_s)
        results.append((fx["rule_id"], "negative", state))

    print("\n=== SUMMARY ===")
    any_error = False
    any_fail = False
    for rule_id, kind, state in results:
        label = state if state != ERROR else "ERROR(INCONCLUSIVE)"
        print(f"  {label:18s}  {kind:8s}  {rule_id}")
        any_error = any_error or state == ERROR
        any_fail = any_fail or state == FAIL

    # Fail-closed precedence: any inconclusive query -> ERROR exit, never clean 0.
    if any_error:
        result, code = "ERROR (INCONCLUSIVE — could not query alerts; fail-closed)", EXIT_ERROR
    elif any_fail:
        result, code = "FAIL", EXIT_FAIL
    else:
        result, code = "PASS", EXIT_PASS
    print(f"\nRESULT: {result}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
