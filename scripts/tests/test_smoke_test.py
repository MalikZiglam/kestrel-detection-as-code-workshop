#!/usr/bin/env python3
"""Offline unit tests for smoke_test fail-closed + unique-id correlation.

No network, no creds, no live Elastic. We patch the alert query and replay so the
schedule-driven checks resolve immediately, and assert:

  positive + alert (queried OK)             -> PASS
  negative + no alert (full window queried) -> PASS
  ANY query error on positive               -> ERROR (non-zero)
  ANY query error on negative               -> ERROR (never PASS)
  stale-id scenario (alert exists for the OLD id but not this run's unique id)
        -> positive FAIL, negative PASS
  INGESTED_EVENT_IDS parsing                -> unique run id used, not static value

Fail-closed at the source (_count_run_alerts):
  missing alert index (search errors)       -> AlertQueryError -> ERROR/non-zero
  malformed HTTP 200 body (no hits.total)   -> AlertQueryError -> ERROR/non-zero
  well-formed zero-hit body                 -> count 0 -> negative still PASS

unittest + unittest.mock only. No pytest.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(SCRIPTS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


smoke = _load("smoke_test", "smoke_test.py")


FX_POS = {
    "path": "tests/shared-fixtures/x/positive.ndjson",
    "rule_id": "baseline-x",
    "log_source": "identity",
    "event_id": "fixture-x-pos-01",
    "expected_alert": True,
}
FX_NEG = dict(FX_POS, event_id="fixture-x-neg-01", expected_alert=False)

UNIQUE_ID = "fixture-x-pos-01-run0001"

ARGS = ("es", "key", ".alerts-security.alerts-default")


class _SmokeBase(unittest.TestCase):
    """Shared setup: replay returns a known unique run id (no subprocess) and
    polling sleep is a no-op so bounded loops resolve immediately."""

    def setUp(self):
        self._patchers = [
            mock.patch.object(smoke, "_replay", lambda path, log_source, test_case: [UNIQUE_ID]),
            mock.patch.object(smoke.time, "sleep", lambda s: None),
        ]
        for p in self._patchers:
            p.start()
            self.addCleanup(p.stop)

    def _patch_count(self, *, seen_ids=None, raise_error=False):
        """Patch _count_run_alerts to simulate the alerts index.

        seen_ids: set of event.ids that already have an alert (models stale alerts).
        raise_error: simulate a query/API/index failure (fail-closed path).
        """
        seen = set(seen_ids or [])

        def fake(endpoint, api_key, alerts_index, rule_id, event_id):
            if raise_error:
                raise smoke.AlertQueryError("simulated HTTP 500")
            return 1 if event_id in seen else 0

        p = mock.patch.object(smoke, "_count_run_alerts", fake)
        p.start()
        self.addCleanup(p.stop)


class ParseIngestedIdsTest(unittest.TestCase):
    def test_parse_ingested_ids(self):
        stdout = "Replaying 1 event\nINGESTED_EVENT_IDS=fixture-x-pos-01-run0001\n"
        self.assertEqual(smoke._parse_ingested_ids(stdout), ["fixture-x-pos-01-run0001"])

    def test_parse_ingested_ids_multiple(self):
        stdout = "INGESTED_EVENT_IDS=a-1,b-2,c-3\n"
        self.assertEqual(smoke._parse_ingested_ids(stdout), ["a-1", "b-2", "c-3"])

    def test_parse_ingested_ids_absent(self):
        self.assertEqual(smoke._parse_ingested_ids("no marker here\n"), [])


class PositiveCheckTest(_SmokeBase):
    def test_positive_with_alert_passes(self):
        self._patch_count(seen_ids={UNIQUE_ID})
        state = smoke._check_positive(*ARGS, FX_POS, timeout_s=5, poll_every_s=0)
        self.assertEqual(state, smoke.PASS)

    def test_positive_no_alert_times_out_fail(self):
        self._patch_count(seen_ids=set())
        state = smoke._check_positive(*ARGS, FX_POS, timeout_s=0, poll_every_s=0)
        self.assertEqual(state, smoke.FAIL)

    def test_positive_query_error_is_error_not_fail(self):
        self._patch_count(raise_error=True)
        state = smoke._check_positive(*ARGS, FX_POS, timeout_s=5, poll_every_s=0)
        self.assertEqual(state, smoke.ERROR)

    def test_positive_stale_old_id_only_fails(self):
        # An alert exists for the ORIGINAL static id but NOT this run's unique id.
        self._patch_count(seen_ids={"fixture-x-pos-01"})
        state = smoke._check_positive(*ARGS, FX_POS, timeout_s=0, poll_every_s=0)
        self.assertEqual(state, smoke.FAIL)  # stale alert must never count as a pass


class NegativeCheckTest(_SmokeBase):
    def test_negative_no_alert_full_window_passes(self):
        self._patch_count(seen_ids=set())
        state = smoke._check_negative(*ARGS, FX_NEG, window_s=0, poll_every_s=0)
        self.assertEqual(state, smoke.PASS)

    def test_negative_query_error_is_error_never_pass(self):
        self._patch_count(raise_error=True)
        state = smoke._check_negative(*ARGS, FX_NEG, window_s=0, poll_every_s=0)
        self.assertEqual(state, smoke.ERROR)

    def test_negative_alert_on_unique_id_fails(self):
        self._patch_count(seen_ids={UNIQUE_ID})
        state = smoke._check_negative(*ARGS, FX_NEG, window_s=5, poll_every_s=0)
        self.assertEqual(state, smoke.FAIL)

    def test_negative_stale_old_id_only_passes(self):
        # Alert exists for the OLD static id; this run's unique id is clean -> PASS.
        self._patch_count(seen_ids={"fixture-x-neg-01"})
        state = smoke._check_negative(*ARGS, FX_NEG, window_s=0, poll_every_s=0)
        self.assertEqual(state, smoke.PASS)


# --- _count_run_alerts fail-closed at the source ------------------------------


class _Resp:
    """Minimal urlopen context-manager stand-in returning a fixed JSON body."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


def _fake_urlopen_error(exc):
    def _raise(req, timeout=None):
        raise exc

    return _raise


def _fake_urlopen_body(body: bytes):
    def _open(req, timeout=None):
        return _Resp(body)

    return _open


class CountRunAlertsSourceTest(unittest.TestCase):
    def test_count_raises_on_httperror(self):
        import urllib.error

        err = urllib.error.HTTPError("u", 500, "boom", {}, io.BytesIO(b""))
        with mock.patch.object(smoke.urllib.request, "urlopen", _fake_urlopen_error(err)):
            with self.assertRaises(smoke.AlertQueryError):
                smoke._count_run_alerts("https://es.example", "k", "idx", "r", "e")

    def test_count_raises_on_urlerror(self):
        import urllib.error

        with mock.patch.object(
            smoke.urllib.request, "urlopen", _fake_urlopen_error(urllib.error.URLError("down"))
        ):
            with self.assertRaises(smoke.AlertQueryError):
                smoke._count_run_alerts("https://es.example", "k", "idx", "r", "e")

    def test_count_returns_value_on_success(self):
        body = json.dumps({"hits": {"total": {"value": 3}}}).encode()
        with mock.patch.object(smoke.urllib.request, "urlopen", _fake_urlopen_body(body)):
            self.assertEqual(
                smoke._count_run_alerts("https://es.example", "k", "idx", "r", "e"), 3
            )

    # --- Item 1: fail-closed hardenings ------------------------------------ #

    def test_count_raises_on_missing_index(self):
        """Missing alert index: ES errors (404 index_not_found) -> AlertQueryError."""
        import urllib.error

        err = urllib.error.HTTPError(
            "u",
            404,
            "index_not_found_exception",
            {},
            io.BytesIO(b'{"error":{"type":"index_not_found_exception"}}'),
        )
        with mock.patch.object(smoke.urllib.request, "urlopen", _fake_urlopen_error(err)):
            with self.assertRaises(smoke.AlertQueryError):
                smoke._count_run_alerts("https://es.example", "k", "missing-idx", "r", "e")

    def test_count_raises_on_error_body_despite_200(self):
        """Serverless variant: 200 status but the body carries an error object."""
        body = json.dumps({"error": {"type": "index_not_found_exception"}}).encode()
        with mock.patch.object(smoke.urllib.request, "urlopen", _fake_urlopen_body(body)):
            with self.assertRaises(smoke.AlertQueryError):
                smoke._count_run_alerts("https://es.example", "k", "idx", "r", "e")

    def test_count_raises_on_malformed_200_bodies(self):
        """A 200 without a recognizable hits.total must fail closed, never 0."""
        malformed = [
            b"{}",
            b'{"hits":{}}',
            b'{"hits":{"total":"weird"}}',
            b'{"hits":{"total":{}}}',
            b'{"hits":{"total":{"value":"nope"}}}',
            b'{"hits":"notadict"}',
            b"[]",
        ]
        for raw in malformed:
            with self.subTest(body=raw):
                with mock.patch.object(
                    smoke.urllib.request, "urlopen", _fake_urlopen_body(raw)
                ):
                    with self.assertRaises(smoke.AlertQueryError):
                        smoke._count_run_alerts("https://es.example", "k", "idx", "r", "e")

    def test_count_accepts_wellformed_zero_and_bare_int(self):
        """Well-formed zero-hit and bare-int totals are valid counts, not errors."""
        for raw, expected in (
            (b'{"hits":{"total":{"value":0}}}', 0),
            (b'{"hits":{"total":0}}', 0),
            (b'{"hits":{"total":5}}', 5),
        ):
            with self.subTest(body=raw):
                with mock.patch.object(
                    smoke.urllib.request, "urlopen", _fake_urlopen_body(raw)
                ):
                    self.assertEqual(
                        smoke._count_run_alerts("https://es.example", "k", "idx", "r", "e"),
                        expected,
                    )

    def test_negative_wellformed_zero_hits_still_passes(self):
        """End-to-end: a real well-formed zero-hit body across the window -> negative PASS."""
        body = json.dumps({"hits": {"total": {"value": 0}}}).encode()
        with mock.patch.object(smoke, "_replay", lambda p, ls, tc: [UNIQUE_ID]), mock.patch.object(
            smoke.time, "sleep", lambda s: None
        ), mock.patch.object(smoke.urllib.request, "urlopen", _fake_urlopen_body(body)):
            # Real _count_run_alerts here (only urlopen is faked), so the endpoint
            # must be a well-formed URL for urllib.request.Request.
            state = smoke._check_negative(
                "https://es.example", "key", ".alerts-security.alerts-default",
                FX_NEG, window_s=0, poll_every_s=0,
            )
        self.assertEqual(state, smoke.PASS)


if __name__ == "__main__":
    unittest.main()
