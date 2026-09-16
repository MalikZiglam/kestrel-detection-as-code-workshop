#!/usr/bin/env python3
"""Deterministic unit tests for scripts/validate_detections.py.

Run:  python3 -m unittest scripts.tests.test_validate_detections
  or: python3 -m unittest discover -s scripts/tests

Offline. Builds in-memory rules and drives the validator's own functions so each
assertion targets a specific level (L1 vs L2). Uses the REAL field dictionary and
pinned ATT&CK subset shipped in the repo.
"""

import os
import sys
import tempfile
import unittest

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import yaml  # noqa: E402

import validate_detections as vd  # noqa: E402


def _good_rule() -> dict:
    """A known-good deployable identity rule that passes L1 and L2."""
    return {
        "id": "test-good-privileged-auth",
        "title": "Test good rule",
        "status": "test",
        "owner": "team-99",
        "deployment": {"enabled": True},
        "description": "x",
        "business_rationale": "x",
        "evidence_refs": [],
        "telemetry_requirements": [],
        "severity": "high",
        "log_source": "identity",
        "query": "event.category: authentication and authentication.privileged: true",
        "mitre_attack": {
            "tactics": ["TA0001"],
            "techniques": ["T1078"],
            "subtechniques": ["T1078.004"],
        },
        "detection_strategy": {"ids": []},
        "data_components": {"ids": []},
        "false_positives": [],
        "known_exceptions": [],
        "investigation_guidance": "x",
        "tags": [],
        "test_cases": {
            "positive": ["tests/workshop/team-99/positive.ndjson"],
            "negative": ["tests/workshop/team-99/negative.ndjson"],
        },
        "review_date": "2026-12-31",
    }


class ValidatorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fd = vd.load_field_dictionary(vd.FIELD_DICT_PATH)
        cls.attack = vd.load_attack_subset(vd.ATTACK_SUBSET_PATH)

    def _run(self, rule: dict):
        """Return (FileResult) after L1 then L2 on an in-memory rule."""
        raw = yaml.safe_dump(rule)
        res = vd.FileResult("mem://test")
        parsed = vd.validate_l1("mem://test", raw, {}, res)
        if parsed is not None:
            vd.validate_l2(parsed, self.fd, self.attack, res)
        return res, parsed

    # --- 1. known-good rule passes L1 + L2 --------------------------------- #
    def test_good_rule_passes_l1_and_l2(self):
        res, _ = self._run(_good_rule())
        self.assertTrue(res.l1.passed, f"L1 errors: {res.l1.errors}")
        self.assertTrue(res.l2.passed, f"L2 errors: {res.l2.errors}")

    # --- 2. bad severity fails L1 ------------------------------------------ #
    def test_bad_severity_fails_l1(self):
        rule = _good_rule()
        rule["severity"] = "spicy"
        res, _ = self._run(rule)
        self.assertFalse(res.l1.passed)
        self.assertTrue(any("severity" in e for e in res.l1.errors), res.l1.errors)

    # --- 3. field not in dictionary fails L2 ------------------------------- #
    def test_unknown_field_fails_l2(self):
        rule = _good_rule()
        rule["query"] = "event.category: authentication and made.up.field: 1"
        res, _ = self._run(rule)
        self.assertTrue(res.l1.passed, res.l1.errors)
        self.assertFalse(res.l2.passed)
        self.assertTrue(any("made.up.field" in e for e in res.l2.errors), res.l2.errors)

    # --- 4. bogus ATT&CK id fails L2 --------------------------------------- #
    def test_bogus_attack_id_fails_l2(self):
        rule = _good_rule()
        rule["mitre_attack"]["techniques"] = ["T9999"]
        res, _ = self._run(rule)
        self.assertTrue(res.l1.passed, res.l1.errors)
        self.assertFalse(res.l2.passed)
        self.assertTrue(any("T9999" in e for e in res.l2.errors), res.l2.errors)

    # --- 5. secrets-audit telemetry gap fails L2 (candidate #7) ------------ #
    def test_secrets_audit_gap_fails_l2(self):
        rule = _good_rule()
        rule["log_source"] = "cloud"
        rule["query"] = "secrets.audit.operation: rotate and secrets.audit.actor: someone"
        res, _ = self._run(rule)
        self.assertTrue(res.l1.passed, res.l1.errors)
        self.assertFalse(res.l2.passed)
        self.assertTrue(
            any("secrets.audit" in e for e in res.l2.errors),
            f"expected secrets-audit gap failure, got {res.l2.errors}",
        )

    # --- extra: wrong-family field fails L2 (address quirk) ---------------- #
    def test_wrong_family_field_fails_l2(self):
        rule = _good_rule()
        # client.address belongs to application, not identity
        rule["query"] = "event.category: authentication and client.address: 192.0.2.1"
        res, _ = self._run(rule)
        self.assertTrue(res.l1.passed, res.l1.errors)
        self.assertFalse(res.l2.passed)
        self.assertTrue(any("client.address" in e for e in res.l2.errors), res.l2.errors)

    # --- extra: draft with empty query passes relaxed L1 ------------------- #
    def test_draft_empty_query_passes_l1(self):
        rule = _good_rule()
        rule["status"] = "draft"
        rule["deployment"]["enabled"] = False
        rule["query"] = ""
        rule["test_cases"] = {"positive": [], "negative": []}
        res, _ = self._run(rule)
        self.assertTrue(res.l1.passed, f"draft should pass relaxed L1: {res.l1.errors}")

    # --- extra: duplicate id fails L1 -------------------------------------- #
    def test_duplicate_id_fails_l1(self):
        seen = {}
        raw = yaml.safe_dump(_good_rule())
        r1 = vd.FileResult("a")
        vd.validate_l1("a", raw, seen, r1)
        r2 = vd.FileResult("b")
        vd.validate_l1("b", raw, seen, r2)
        self.assertTrue(r1.l1.passed, r1.l1.errors)
        self.assertFalse(r2.l1.passed)
        self.assertTrue(any("duplicate id" in e for e in r2.l1.errors), r2.l1.errors)

    # --- extra: comment-only placeholder is skipped, not failed ------------ #
    def test_placeholder_skipped(self):
        res = vd.FileResult("slot")
        parsed = vd.validate_l1("slot", "# just a comment\n", {}, res)
        self.assertIsNone(parsed)
        self.assertTrue(res.skipped_placeholder)
        self.assertTrue(res.ok)


def _write_detection(root: str, family_dir: str, slug: str, rule: dict) -> str:
    """Write a detection.yaml under root/detections/<family_dir>/<slug>/."""
    d = os.path.join(root, "detections", family_dir, slug)
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "detection.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(yaml.safe_dump(rule))
    return path


class DataRootCliTest(unittest.TestCase):
    """End-to-end proof of the DATA-root vs REFERENCE-root split (the CI fix).

    Drives main() with --all --data-root pointing at a temp DATA tree, so the
    tests exercise exactly what CI does: trusted validator code + reference data
    from the validator's own checkout, detection DATA from --data-root.
    """

    def _run_main(self, data_root: str) -> int:
        return vd.main(["--all", "--data-root", data_root, "--format", "text"])

    # --- A. invalid PR detection under a data-root FAILS ------------------- #
    def test_invalid_pr_detection_fails(self):
        with tempfile.TemporaryDirectory() as data_root:
            bad = _good_rule()
            bad["id"] = "team-01-bad"
            bad["query"] = ""  # deployable rule with empty query -> L1 FAIL
            _write_detection(data_root, "workshop", "team-01", bad)
            rc = self._run_main(data_root)
            self.assertEqual(rc, 1, "invalid PR detection must exit non-zero")

    # --- B. valid PR detection under a data-root PASSES -------------------- #
    def test_valid_pr_detection_passes(self):
        with tempfile.TemporaryDirectory() as data_root:
            good = _good_rule()
            good["id"] = "team-01-good"
            _write_detection(data_root, "workshop", "team-01", good)
            rc = self._run_main(data_root)
            self.assertEqual(rc, 0, "valid PR detection must exit 0")

    # --- C. cannot bypass by planting a permissive dict in the data-root --- #
    def test_tampered_data_root_dict_is_ignored(self):
        """Prove field dictionary + ATT&CK subset load from the REFERENCE root.

        Plant a permissive field-dictionary.yaml AND attack subset in the
        data-root that WOULD allow a bogus field/technique, plus a detection
        that uses them. The trusted reference data must still be used, so the
        detection FAILS. This is the "can't swap the rules to pass" proof.
        """
        with tempfile.TemporaryDirectory() as data_root:
            # Planted permissive dict that (falsely) blesses a made-up field.
            planted_logs = os.path.join(data_root, "logs")
            os.makedirs(planted_logs, exist_ok=True)
            with open(os.path.join(planted_logs, "field-dictionary.yaml"), "w", encoding="utf-8") as fh:
                fh.write(
                    yaml.safe_dump(
                        {
                            "log_source_enum": ["identity"],
                            "fields": [
                                {"name": "totally.made.up.field", "families": ["identity"], "type": "keyword"},
                                {"name": "event.category", "families": ["identity"], "type": "keyword"},
                            ],
                        }
                    )
                )
            # Planted permissive ATT&CK subset that (falsely) blesses T9999.
            planted_attack = os.path.join(data_root, "docs", "attack")
            os.makedirs(planted_attack, exist_ok=True)
            with open(os.path.join(planted_attack, "attack-subset.yaml"), "w", encoding="utf-8") as fh:
                fh.write(
                    yaml.safe_dump(
                        {
                            "meta": {"attack_version": "tampered", "pinned_on": "never"},
                            "tactics": [{"id": "TA0001"}],
                            "techniques": [{"id": "T9999"}],
                            "subtechniques": [],
                        }
                    )
                )

            rule = _good_rule()
            rule["id"] = "team-01-tamper"
            rule["query"] = "event.category: authentication and totally.made.up.field: 1"
            _write_detection(data_root, "workshop", "team-01", rule)

            # Must FAIL: trusted dict has no 'totally.made.up.field', so L2 fails
            # even though the planted data-root dict would allow it.
            rc = self._run_main(data_root)
            self.assertEqual(rc, 1, "planted permissive dict must be ignored; rule must FAIL")

    # --- backward compat: default (no --data-root) globs REFERENCE root ---- #
    def test_default_data_root_is_reference_root(self):
        rc = vd.main(["--all", "--format", "text"])
        self.assertEqual(rc, 0, "default --all from full checkout must still PASS the baselines")


if __name__ == "__main__":
    unittest.main()
