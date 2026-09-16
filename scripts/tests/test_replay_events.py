#!/usr/bin/env python3
"""Offline unit tests for replay_events.prepare_event unique-id scheme.

No network, no creds. Asserts the unique per-run event.id scheme:
  - event.id is rewritten to <original>-<runtoken>
  - the original id is preserved in workshop.original_event_id
  - the original @timestamp is preserved in workshop.original_timestamp
  - forbidden target fields are stripped

unittest only. No pytest.
"""
from __future__ import annotations

import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(SCRIPTS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


replay = _load("replay_events", "replay_events.py")


class PrepareEventTest(unittest.TestCase):
    def test_prepare_event_assigns_unique_namespaced_id(self):
        event = {"@timestamp": "2024-11-12T08:05:09Z", "event.id": "fixture-priv-auth-pos-01"}
        out = replay.prepare_event(event, "positive", "", "", run_token="abc123")
        self.assertEqual(out["event.id"], "fixture-priv-auth-pos-01-abc123")
        self.assertEqual(out["workshop.original_event_id"], "fixture-priv-auth-pos-01")
        self.assertEqual(out["workshop.original_timestamp"], "2024-11-12T08:05:09Z")
        self.assertNotEqual(out["@timestamp"], "2024-11-12T08:05:09Z")

    def test_prepare_event_is_unique_across_runs(self):
        event = {"@timestamp": "2024-11-12T08:05:09Z", "event.id": "fixture-x"}
        a = replay.prepare_event(event, "", "", "", run_token=replay._run_token())
        b = replay.prepare_event(event, "", "", "", run_token=replay._run_token())
        self.assertNotEqual(a["event.id"], b["event.id"])
        # both still carry the human-readable original prefix
        self.assertTrue(a["event.id"].startswith("fixture-x-"))
        self.assertTrue(b["event.id"].startswith("fixture-x-"))

    def test_prepare_event_handles_missing_original_id(self):
        out = replay.prepare_event({"@timestamp": "2024-01-01T00:00:00Z"}, "", "", "", run_token="tok")
        self.assertEqual(out["event.id"], "fixture-tok")
        self.assertNotIn("workshop.original_event_id", out)

    def test_prepare_event_strips_forbidden_target_fields(self):
        event = {"event.id": "e1", "_index": "x", "index": "y", "target": "z", "data_stream": {}}
        out = replay.prepare_event(event, "", "", "", run_token="t")
        for key in replay.FORBIDDEN_TARGET_FIELDS:
            self.assertNotIn(key, out)

    def test_run_token_is_short_hex(self):
        tok = replay._run_token()
        self.assertEqual(len(tok), 12)
        int(tok, 16)  # valid hex


if __name__ == "__main__":
    unittest.main()
