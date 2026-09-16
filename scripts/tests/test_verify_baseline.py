#!/usr/bin/env python3
"""Offline unit tests for verify_baseline fail-closed exit codes.

No network. Asserts:
  missing creds         -> UNAVAILABLE, exit 3 (was 0 — the bug)
  Elastic query fails   -> UNAVAILABLE, exit 3
  live matches expected -> CLEAN, exit 0
  drift                 -> exit 2

unittest + unittest.mock only. No pytest.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
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


vb = _load("verify_baseline", "verify_baseline.py")

GIT_RULES = [
    {"rule_id": "baseline-a", "status": "production", "enabled": True, "should_deploy": True},
    {"rule_id": "baseline-b", "status": "production", "enabled": True, "should_deploy": True},
]


class VerifyBaselineTest(unittest.TestCase):
    def setUp(self):
        # Clear creds so each test controls its own environment.
        self._env = mock.patch.dict(os.environ, {}, clear=False)
        self._env.start()
        self.addCleanup(self._env.stop)
        for var in ("ELASTIC_KB_ENDPOINT", "ELASTIC_API_KEY", "ELASTIC_SPACE"):
            os.environ.pop(var, None)
        p = mock.patch.object(vb, "scan_git_baseline", lambda: list(GIT_RULES))
        p.start()
        self.addCleanup(p.stop)

    def _run_main(self):
        """Run vb.main() capturing stdout; return (exit_code, stdout)."""
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = vb.main()
        return code, buf.getvalue()

    def test_missing_creds_is_unavailable_nonzero(self):
        code, out = self._run_main()
        self.assertEqual(code, vb.EXIT_UNAVAILABLE)
        self.assertNotEqual(code, 0)
        self.assertIn("UNAVAILABLE", out)

    def test_query_failure_is_unavailable_nonzero(self):
        os.environ["ELASTIC_KB_ENDPOINT"] = "https://kb.example"
        os.environ["ELASTIC_API_KEY"] = "key"
        with mock.patch.object(vb, "fetch_elastic_rule_ids", lambda *a, **k: None):
            code, out = self._run_main()
        self.assertEqual(code, vb.EXIT_UNAVAILABLE)
        self.assertIn("UNAVAILABLE", out)

    def test_clean_when_live_matches_expected(self):
        os.environ["ELASTIC_KB_ENDPOINT"] = "https://kb.example"
        os.environ["ELASTIC_API_KEY"] = "key"
        with mock.patch.object(
            vb, "fetch_elastic_rule_ids", lambda *a, **k: {"baseline-a", "baseline-b"}
        ):
            code, out = self._run_main()
        self.assertEqual(code, vb.EXIT_CLEAN)
        self.assertIn("RESULT: CLEAN", out)

    def test_drift_when_expected_missing_from_live(self):
        os.environ["ELASTIC_KB_ENDPOINT"] = "https://kb.example"
        os.environ["ELASTIC_API_KEY"] = "key"
        with mock.patch.object(vb, "fetch_elastic_rule_ids", lambda *a, **k: {"baseline-a"}):
            code, out = self._run_main()
        self.assertEqual(code, vb.EXIT_DRIFT)
        self.assertIn("DRIFT", out)

    def test_missing_baseline_exits_drift(self):
        with mock.patch.object(vb, "scan_git_baseline", lambda: []):
            code, _ = self._run_main()
        self.assertEqual(code, vb.EXIT_DRIFT)


if __name__ == "__main__":
    unittest.main()
