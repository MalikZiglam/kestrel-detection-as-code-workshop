#!/usr/bin/env python3
"""Offline unit tests for reset_demo_environment stale matching + baseline guard.

No network. Asserts:
  - documented participant ids teamNN-... ARE stale (the prior bug missed these)
  - workshop-... ARE stale
  - baseline-* are NEVER stale (golden set protected)
  - unrelated ids are NOT stale
  - the baseline guard holds even if STALE_RE were broadened
  - stale selection in main() never picks a baseline id

unittest + unittest.mock only. No pytest.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, os.path.join(SCRIPTS, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


reset = _load("reset_demo_environment", "reset_demo_environment.py")


class StaleMatchingTest(unittest.TestCase):
    def test_documented_participant_and_workshop_ids_are_stale(self):
        for rule_id in (
            "team01-cross-plane-admin",
            "team01-privileged-login-review",
            "team02-foo",
            "team10-bar",
            "workshop-rehearsal-1",
        ):
            with self.subTest(rule_id=rule_id):
                self.assertIs(reset.is_stale_rule_id(rule_id), True)

    def test_baseline_rules_never_stale(self):
        for rule_id in (
            "baseline-privileged-password-only-auth",
            "baseline-object-store-policy-change",
            "baseline-management-plane-unusual-port",
        ):
            with self.subTest(rule_id=rule_id):
                self.assertIs(reset.is_stale_rule_id(rule_id), False)

    def test_non_participant_ids_not_stale(self):
        # "team-" (hyphen, no digit) and "teamwork" must NOT match the teamNN convention.
        for rule_id in ("team-slot-legacy", "teamwork-notes", "elastic-builtin", "", "some-other-rule"):
            with self.subTest(rule_id=rule_id):
                self.assertIs(reset.is_stale_rule_id(rule_id), False)

    def test_baseline_guard_holds_even_if_regex_broadened(self):
        # Simulate a future over-broad STALE_RE that would match everything.
        with mock.patch.object(reset, "STALE_RE", re.compile(r"^")):
            self.assertIs(reset.is_stale_rule_id("baseline-a"), False)  # guard wins
            self.assertIs(reset.is_stale_rule_id("anything-else"), True)


class MainSelectionTest(unittest.TestCase):
    def _run_main(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = reset.main()
        return code, buf.getvalue()

    def test_main_selection_excludes_baseline(self):
        live_rules = [
            {"rule_id": "baseline-a"},
            {"rule_id": "team01-foo"},
            {"rule_id": "workshop-bar"},
            {"rule_id": "unrelated-x"},
        ]
        with mock.patch.dict(
            os.environ,
            {"ELASTIC_KB_ENDPOINT": "https://kb.example", "ELASTIC_API_KEY": "key"},
            clear=False,
        ):
            os.environ.pop("WORKSHOP_CONFIRM", None)  # dry run, no deletes
            with mock.patch.object(reset, "golden_baseline_ids", lambda: ["baseline-a"]), \
                    mock.patch.object(reset, "_find_rules", lambda base, api_key: live_rules):
                code, out = self._run_main()
        self.assertEqual(code, 0)  # dry run exits clean
        self.assertIn("team01-foo", out)
        self.assertIn("workshop-bar", out)
        # never listed as stale
        self.assertNotIn("baseline-a", out.split("Stale rehearsal rules")[-1])
        self.assertNotIn("unrelated-x", out.split("Stale rehearsal rules")[-1])

    def test_no_creds_prints_plan_and_exits_zero(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for var in ("ELASTIC_KB_ENDPOINT", "ELASTIC_API_KEY"):
                os.environ.pop(var, None)
            with mock.patch.object(reset, "golden_baseline_ids", lambda: ["baseline-a"]):
                code, out = self._run_main()
        self.assertEqual(code, 0)
        self.assertIn("Manual golden-baseline reset sequence", out)


if __name__ == "__main__":
    unittest.main()
