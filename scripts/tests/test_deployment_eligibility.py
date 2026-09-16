#!/usr/bin/env python3
"""Deterministic tests for the deployment-eligibility filter.

Covers each status/enabled combination from the authoritative status table
(docs/DEPLOYMENT-CONTRACT.md) using small temp fixtures, plus an assertion over
the 6 real baselines so the checker and the shipped catalogue stay in sync.
"""

from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from deployment_eligibility import eligibility_reason, evaluate, repo_root  # noqa: E402

import yaml  # noqa: E402


def _doc(status: str, enabled) -> dict:
    return {"id": f"r-{status}-{enabled}", "status": status, "deployment": {"enabled": enabled}}


class EligibilityFilterTest(unittest.TestCase):
    def test_production_enabled_is_deployable(self):
        ok, _ = eligibility_reason(_doc("production", True))
        self.assertTrue(ok)

    def test_test_enabled_is_deployable(self):
        ok, _ = eligibility_reason(_doc("test", True))
        self.assertTrue(ok)

    def test_draft_is_excluded(self):
        ok, reason = eligibility_reason(_doc("draft", True))
        self.assertFalse(ok)
        self.assertIn("status_not_deployable", reason)

    def test_deprecated_is_excluded(self):
        ok, reason = eligibility_reason(_doc("deprecated", True))
        self.assertFalse(ok)
        self.assertIn("status_not_deployable", reason)

    def test_not_detectable_is_excluded(self):
        ok, reason = eligibility_reason(_doc("not_detectable", True))
        self.assertFalse(ok)
        self.assertIn("status_not_deployable", reason)

    def test_enabled_false_is_excluded_even_when_production(self):
        ok, reason = eligibility_reason(_doc("production", False))
        self.assertFalse(ok)
        self.assertIn("deployment_disabled", reason)

    def test_missing_deployment_block_is_excluded(self):
        ok, reason = eligibility_reason({"id": "x", "status": "production"})
        self.assertFalse(ok)
        self.assertIn("deployment_disabled", reason)

    def test_placeholder_or_non_dict_is_excluded(self):
        for junk in (None, "just a comment", [1, 2, 3]):
            ok, reason = eligibility_reason(junk)
            self.assertFalse(ok)
            self.assertIn("unparsed_or_no_status", reason)


class EvaluateOverTempFixturesTest(unittest.TestCase):
    def test_evaluate_splits_a_mixed_tree(self):
        with tempfile.TemporaryDirectory() as root:
            base = os.path.join(root, "detections", "baseline")
            cases = {
                "keep-prod": ("production", True),
                "keep-test": ("test", True),
                "drop-draft": ("draft", True),
                "drop-disabled": ("production", False),
            }
            for name, (status, enabled) in cases.items():
                d = os.path.join(base, name)
                os.makedirs(d)
                with open(os.path.join(d, "detection.yaml"), "w", encoding="utf-8") as fh:
                    yaml.safe_dump(
                        {"id": name, "status": status, "deployment": {"enabled": enabled}}, fh
                    )
            # A comment-only placeholder must be excluded, not crash.
            ph = os.path.join(base, "placeholder")
            os.makedirs(ph)
            with open(os.path.join(ph, "detection.yaml"), "w", encoding="utf-8") as fh:
                fh.write("# no content yet\n")

            from deployment_eligibility import discover

            deployable, excluded = evaluate(discover(root))
            self.assertEqual(set(deployable.values()), {"keep-prod", "keep-test"})
            self.assertEqual(len(excluded), 3)

    def test_fixture_under_tests_dir_never_matches_glob(self):
        with tempfile.TemporaryDirectory() as root:
            # A detection.yaml under tests/ must NOT be discovered.
            d = os.path.join(root, "tests", "workshop", "team-99")
            os.makedirs(d)
            with open(os.path.join(d, "detection.yaml"), "w", encoding="utf-8") as fh:
                yaml.safe_dump(
                    {"id": "sneaky", "status": "production", "deployment": {"enabled": True}}, fh
                )
            from deployment_eligibility import discover

            self.assertEqual(discover(root), [])


class RealBaselinesTest(unittest.TestCase):
    """Guard the shipped catalogue against the documented status/enabled values."""

    def test_six_baselines_split_as_documented(self):
        from deployment_eligibility import discover

        root = repo_root()
        baselines = [
            p for p in discover(root) if os.sep + "baseline" + os.sep in p
        ]
        self.assertEqual(len(baselines), 6, "expected exactly 6 baseline detections")
        deployable, excluded = evaluate(baselines)
        self.assertEqual(
            set(deployable.values()),
            {
                "baseline-privileged-password-only-auth",
                "baseline-management-plane-unusual-port",
                "baseline-object-store-policy-change",
            },
        )
        # 3 excluded: noisy (enabled=false), draft, deprecated.
        excluded_ids = set()
        for path in excluded:
            with open(path, encoding="utf-8") as fh:
                excluded_ids.add((yaml.safe_load(fh) or {}).get("id"))
        self.assertEqual(
            excluded_ids,
            {
                "baseline-all-auth-failures",
                "baseline-endpoint-suspicious-process",
                "baseline-icmp-sweep-legacy",
            },
        )


if __name__ == "__main__":
    unittest.main()
