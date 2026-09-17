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


def _write_fixture(root: str, rel: str, lines: list[str]) -> None:
    """Write an ndjson fixture at root/<rel> with the given raw lines."""
    abs_path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(abs_path), exist_ok=True)
    with open(abs_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def _slot_rule(slug: str, family: str = "identity") -> dict:
    """A deployable rule whose fixtures point at its OWN team slot."""
    rule = _good_rule()
    rule["id"] = f"{slug}-rule"
    rule["log_source"] = family
    rule["test_cases"] = {
        "positive": [f"tests/workshop/{slug}/positive.ndjson"],
        "negative": [f"tests/workshop/{slug}/negative.ndjson"],
    }
    return rule


def _write_slot_fixtures(root: str, slug: str) -> None:
    """Real positive/negative ndjson for a team slot (one JSON object each)."""
    _write_fixture(root, f"tests/workshop/{slug}/positive.ndjson",
                   ['{"event.id":"p1","event.category":"authentication"}'])
    _write_fixture(root, f"tests/workshop/{slug}/negative.ndjson",
                   ['{"event.id":"n1","event.category":"authentication"}'])


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
            bad = _slot_rule("team-01")
            bad["query"] = ""  # deployable rule with empty query -> L1 FAIL
            _write_slot_fixtures(data_root, "team-01")
            _write_detection(data_root, "workshop", "team-01", bad)
            rc = self._run_main(data_root)
            self.assertEqual(rc, 1, "invalid PR detection must exit non-zero")

    # --- B. valid PR detection under a data-root PASSES -------------------- #
    def test_valid_pr_detection_passes(self):
        with tempfile.TemporaryDirectory() as data_root:
            good = _slot_rule("team-01")
            _write_slot_fixtures(data_root, "team-01")
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

            rule = _slot_rule("team-01")
            rule["id"] = "team-01-tamper"
            rule["query"] = "event.category: authentication and totally.made.up.field: 1"
            _write_slot_fixtures(data_root, "team-01")
            _write_detection(data_root, "workshop", "team-01", rule)

            # Must FAIL: trusted dict has no 'totally.made.up.field', so L2 fails
            # even though the planted data-root dict would allow it.
            rc = self._run_main(data_root)
            self.assertEqual(rc, 1, "planted permissive dict must be ignored; rule must FAIL")

    # --- backward compat: default (no --data-root) globs REFERENCE root ---- #
    def test_default_data_root_is_reference_root(self):
        rc = vd.main(["--all", "--format", "text"])
        self.assertEqual(rc, 0, "default --all from full checkout must still PASS the baselines")


class DeployabilityMappingTest(unittest.TestCase):
    """Deployable rule x family->index mapping (Phase 1 hardening).

    A deployable rule must target a MAPPED family (identity/network/cloud). The
    same family on a NON-deployable lifecycle artifact is legitimate.
    """

    @classmethod
    def setUpClass(cls):
        cls.fd = vd.load_field_dictionary(vd.FIELD_DICT_PATH)
        cls.attack = vd.load_attack_subset(vd.ATTACK_SUBSET_PATH)

    def _run(self, rule: dict):
        raw = yaml.safe_dump(rule)
        res = vd.FileResult("mem://map")
        parsed = vd.validate_l1("mem://map", raw, {}, res)
        if parsed is not None:
            vd.validate_l2(parsed, self.fd, self.attack, res)
        return res

    def test_dictionary_exposes_mapped_families(self):
        self.assertEqual(self.fd["mapped_families"], {"identity", "network", "cloud"})

    def test_deployable_unmapped_family_fails_l2(self):
        # 'admin' is a real family but unmapped; deployable -> must fail L2.
        rule = _good_rule()
        rule["log_source"] = "admin"
        rule["query"] = "event.category: iam and admin.action: config_change"
        res = self._run(rule)
        self.assertFalse(res.l2.passed)
        self.assertTrue(any("mapped to a deployable index" in e for e in res.l2.errors), res.l2.errors)

    def test_nondeployable_unmapped_family_passes(self):
        # Same unmapped family, but draft + disabled -> legitimate, passes.
        rule = _good_rule()
        rule["log_source"] = "admin"
        rule["status"] = "draft"
        rule["deployment"]["enabled"] = False
        rule["query"] = "event.category: iam and admin.action: config_change"
        res = self._run(rule)
        self.assertTrue(res.l1.passed, res.l1.errors)
        self.assertTrue(res.l2.passed, res.l2.errors)

    def test_deployable_mapped_network_family_passes(self):
        rule = _good_rule()
        rule["log_source"] = "network"
        rule["query"] = "network.direction: outbound and destination.port >= 1024"
        # network positive/negative fixtures still reference team-99 slot; L2 only here
        res = self._run(rule)
        self.assertTrue(
            all("not mapped" not in e for e in res.l2.errors),
            res.l2.errors,
        )


class YamlTypeTest(unittest.TestCase):
    """deployment.enabled boolean + test_cases list-of-strings enforcement."""

    def _run_l1(self, rule: dict) -> vd.FileResult:
        raw = yaml.safe_dump(rule)
        res = vd.FileResult("mem://type")
        vd.validate_l1("mem://type", raw, {}, res)
        return res

    def test_enabled_string_true_fails_l1(self):
        rule = _good_rule()
        rule["deployment"]["enabled"] = "true"  # YAML string, not boolean
        res = self._run_l1(rule)
        self.assertFalse(res.l1.passed)
        self.assertTrue(any("must be a YAML boolean" in e for e in res.l1.errors), res.l1.errors)

    def test_enabled_string_true_is_not_deployable(self):
        rule = _good_rule()
        rule["deployment"]["enabled"] = "true"
        self.assertFalse(vd.is_deployable(rule), "string 'true' must not count as deployable")

    def test_test_cases_scalar_fails_l1(self):
        rule = _good_rule()
        rule["test_cases"] = {
            "positive": "tests/workshop/team-99/positive.ndjson",  # scalar, not list
            "negative": ["tests/workshop/team-99/negative.ndjson"],
        }
        res = self._run_l1(rule)
        self.assertFalse(res.l1.passed)
        self.assertTrue(any("must be a YAML list" in e for e in res.l1.errors), res.l1.errors)

    def test_test_cases_nonstring_entry_fails_l1(self):
        rule = _good_rule()
        rule["test_cases"] = {"positive": [123], "negative": ["tests/workshop/team-99/negative.ndjson"]}
        res = self._run_l1(rule)
        self.assertFalse(res.l1.passed)
        self.assertTrue(any("non-empty path string" in e for e in res.l1.errors), res.l1.errors)


class FixtureRefTest(unittest.TestCase):
    """Deployable fixture references must resolve to real, shaped ndjson files."""

    def _run_main(self, data_root: str) -> int:
        return vd.main(["--all", "--data-root", data_root, "--format", "text"])

    def test_missing_fixture_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_detection(root, "workshop", "team-01", rule)  # no fixtures written
            self.assertEqual(self._run_main(root), 1)

    def test_present_fixtures_pass(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 0)

    def test_non_ndjson_extension_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["test_cases"]["positive"] = ["tests/workshop/team-01/positive.json"]
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/positive.json",
                           ['{"event.id":"p1"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_wrong_subtree_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            # points at another team's slot
            rule["test_cases"]["positive"] = ["tests/workshop/team-02/positive.ndjson"]
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-02/positive.ndjson", ['{"event.id":"p1"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_empty_fixture_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/positive.ndjson", [""])  # blank only
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_non_object_line_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/positive.ndjson", ['[1,2,3]'])  # array
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_invalid_json_line_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/positive.ndjson", ['{not json}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_nondeployable_skips_fixture_checks(self):
        # A draft with empty fixture lists must not trigger fixture-ref failures.
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["status"] = "draft"
            rule["deployment"]["enabled"] = False
            rule["query"] = ""
            rule["test_cases"] = {"positive": [], "negative": []}
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 0)


if __name__ == "__main__":
    unittest.main()
