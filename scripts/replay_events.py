#!/usr/bin/env python3
"""Deterministic synthetic event replay for the workshop demo environment.

Reads a fixture (one ECS-style JSON event per line), rewrites @timestamp to now
so the deployed detection sees the event inside its lookback window, preserves
the original fixture time in workshop.original_timestamp, adds workshop
correlation metadata, and ingests into the facilitator-resolved destination
index. The fixture NEVER names an index: destination is resolved from the
log_source family via the facilitator-controlled mapping and any
target/index/destination field in the fixture is ignored (S5, WORKSHOP_SPEC.md
§22.2).

Config comes from ENV only (never hardcoded, never printed). Writes are gated
behind WORKSHOP_CONFIRM=yes.

Env:
  ELASTIC_ES_ENDPOINT   Serverless Elasticsearch URL (required)
  ELASTIC_API_KEY       base64 API key, the only Serverless auth path (required)
  WORKSHOP_CONFIRM      must be "yes" to write (safety gate)
  WORKSHOP_SCENARIO_ID  optional workshop.scenario_id tag
  WORKSHOP_TEAM_ID      optional workshop.team_id tag

Usage:
  WORKSHOP_CONFIRM=yes replay_events.py \\
      --fixture tests/shared-fixtures/<rule>/positive.ndjson \\
      --log-source identity --test-case positive
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request
import uuid

# Facilitator-controlled family -> destination index. Mirrors
# docs/DEPLOYMENT-CONTRACT.md and logs/field-dictionary.yaml family_index_mapping.
# Participants never author this; the fixture never names an index.
FAMILY_INDEX = {
    "identity": "workshop-auth-events",
    "network": "workshop-network-events",
    "cloud": "workshop-cloud-events",
}

# Fields a fixture must never dictate; stripped before ingest (S5).
FORBIDDEN_TARGET_FIELDS = ("_index", "index", "target", "destination_index", "data_stream")


def _require_env(name: str) -> str:
    import os

    val = os.environ.get(name, "").strip()
    if not val:
        sys.exit(f"FATAL: {name} is not set. This script is env-driven; nothing is hardcoded.")
    return val


def _require_confirm() -> None:
    import os

    if os.environ.get("WORKSHOP_CONFIRM", "no") != "yes":
        sys.exit(
            "FATAL: write blocked. Set WORKSHOP_CONFIRM=yes only after confirming the\n"
            "endpoints point at the throwaway demo project with synthetic data — never a\n"
            "client or production project."
        )


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _es_post(endpoint: str, api_key: str, path: str, body: dict) -> dict:
    """POST JSON to Elasticsearch. Auth header never logged. Raises on HTTP error."""
    url = f"{endpoint.rstrip('/')}/{path.lstrip('/')}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"ApiKey {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        sys.exit(f"FATAL: ingest failed HTTP {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        sys.exit(f"FATAL: cannot reach Elasticsearch endpoint: {exc.reason}")


def load_fixture(path: str) -> list[dict]:
    events: list[dict] = []
    with open(path, encoding="utf-8") as handle:
        for lineno, raw in enumerate(handle, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError as exc:
                sys.exit(f"FATAL: {path}:{lineno} is not valid JSON: {exc}")
    if not events:
        sys.exit(f"FATAL: {path} contains no events.")
    return events


def _run_token() -> str:
    """Short per-run token so every replay ingests unique event.ids.

    A normal Python script (not a sandboxed workflow script), so uuid is fine.
    Kept short and lowercase-hex so it reads cleanly in Kibana alerts.
    """
    return uuid.uuid4().hex[:12]


def prepare_event(
    event: dict, test_case: str, scenario_id: str, team_id: str, run_token: str
) -> dict:
    """Rewrite time into the rule window, assign a unique per-run event.id,
    preserve the fixture original id/time, add correlation tags, strip any
    participant-supplied index target. Returns a new dict."""
    out = dict(event)
    for key in FORBIDDEN_TARGET_FIELDS:
        out.pop(key, None)  # a fixture never chooses its destination (S5)

    original = out.get("@timestamp")
    if original:
        out["workshop.original_timestamp"] = original
    out["@timestamp"] = _now_iso()

    # Unique runtime correlation id for THIS run. event.id survives into Elastic
    # alerts, so smoke_test can poll for exactly this run's alert and never match
    # a stale alert from a prior rehearsal. Namespaced <original>-<runtoken> so a
    # human reading alerts still sees which fixture it came from.
    original_event_id = out.get("event.id")
    if original_event_id:
        out["workshop.original_event_id"] = original_event_id
        out["event.id"] = f"{original_event_id}-{run_token}"
    else:
        out["event.id"] = f"fixture-{run_token}"

    if test_case:
        out["workshop.test_case"] = test_case
    if scenario_id:
        out["workshop.scenario_id"] = scenario_id
    if team_id:
        out["workshop.team_id"] = team_id
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay a workshop fixture into Elastic.")
    parser.add_argument("--fixture", required=True, help="Path to a .ndjson fixture.")
    parser.add_argument(
        "--log-source",
        required=True,
        choices=sorted(FAMILY_INDEX),
        help="Fixture log family; resolves the facilitator-controlled destination index.",
    )
    parser.add_argument(
        "--test-case",
        default="",
        choices=["", "positive", "negative"],
        help="Optional workshop.test_case label.",
    )
    args = parser.parse_args()

    import os

    endpoint = _require_env("ELASTIC_ES_ENDPOINT")
    api_key = _require_env("ELASTIC_API_KEY")
    _require_confirm()
    scenario_id = os.environ.get("WORKSHOP_SCENARIO_ID", "").strip()
    team_id = os.environ.get("WORKSHOP_TEAM_ID", "").strip()

    index = FAMILY_INDEX[args.log_source]
    events = load_fixture(args.fixture)
    run_token = _run_token()

    print(
        "Replaying %d event(s) [%s]\n"
        "  log_source=%s -> destination index (facilitator-resolved): %s\n"
        "  @timestamp rewritten to now; original preserved in workshop.original_timestamp\n"
        "  unique per-run event.id assigned (run token %s); original in workshop.original_event_id"
        % (len(events), args.fixture, args.log_source, index, run_token),
        file=sys.stderr,
    )

    ingested_ids: list[str] = []
    for event in events:
        doc = prepare_event(event, args.test_case, scenario_id, team_id, run_token)
        # refresh=true so the next scheduled rule run sees the event immediately.
        _es_post(endpoint, api_key, f"{index}/_doc?refresh=true", doc)
        event_id = doc["event.id"]
        ingested_ids.append(event_id)
        print(f"  ingested event.id={event_id} into {index}", file=sys.stderr)

    # Machine-readable line for callers (smoke_test.py captures this): the ACTUAL
    # unique per-run ids that were ingested, NOT the static fixture ids.
    print("INGESTED_EVENT_IDS=" + ",".join(ingested_ids))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
