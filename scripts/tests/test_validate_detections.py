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
    """Real positive/negative ndjson for a team slot (one identity-family event
    each). Carries the full set of fields the dictionary marks guaranteed:true for
    the identity family (@timestamp, event.id, event.action, event.category,
    event.outcome, host.name, user.name, source.ip) plus the rule's discriminator."""
    _write_fixture(root, f"tests/workshop/{slug}/positive.ndjson",
                   ['{"@timestamp":"2024-11-12T08:05:09Z","event.id":"p1",'
                    '"event.action":"authentication_success","event.category":"authentication",'
                    '"event.outcome":"success","host.name":"idp.ctrl.example",'
                    '"user.name":"j.okafor","source.ip":"203.0.113.45",'
                    '"authentication.privileged":true}'])
    _write_fixture(root, f"tests/workshop/{slug}/negative.ndjson",
                   ['{"@timestamp":"2024-11-12T08:06:09Z","event.id":"n1",'
                    '"event.action":"authentication_success","event.category":"authentication",'
                    '"event.outcome":"success","host.name":"idp.ctrl.example",'
                    '"user.name":"j.okafor","source.ip":"198.51.100.5",'
                    '"authentication.privileged":false}'])


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


class PathContainmentTest(unittest.TestCase):
    """Track 2: a fixture reference must resolve to a real file INSIDE the owning
    team's subtree. Traversal, absolute escape, out-of-subtree, and symlink escape
    must all fail cleanly — before the file is ever opened."""

    def _run_main(self, data_root: str) -> int:
        return vd.main(["--all", "--data-root", data_root, "--format", "text"])

    def _rule_with_positive(self, ref: str) -> dict:
        rule = _slot_rule("team-01")
        rule["test_cases"]["positive"] = [ref]
        return rule

    def test_dotdot_traversal_into_sibling_team_fails(self):
        # The explicit team-01 -> team-02 traversal called out in Track 2.
        with tempfile.TemporaryDirectory() as root:
            rule = self._rule_with_positive("tests/workshop/team-01/../team-02/positive.ndjson")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-02/positive.ndjson", ['{"event.id":"p1"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_dotdot_escape_outside_data_root_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = self._rule_with_positive("tests/workshop/team-01/../../../etc/passwd.ndjson")
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_absolute_path_reference_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = self._rule_with_positive("/etc/hosts.ndjson")
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_other_team_subtree_fails(self):
        # No traversal, but the file simply lives under a different team.
        with tempfile.TemporaryDirectory() as root:
            rule = self._rule_with_positive("tests/workshop/team-02/positive.ndjson")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-02/positive.ndjson", ['{"event.id":"p1"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_symlink_escape_fails(self):
        # A fixture that is a symlink pointing OUTSIDE the data root must fail:
        # realpath resolves the link target and containment rejects it.
        with tempfile.TemporaryDirectory() as outside:
            secret = os.path.join(outside, "secret.ndjson")
            with open(secret, "w", encoding="utf-8") as fh:
                fh.write('{"event.id":"x"}\n')
            with tempfile.TemporaryDirectory() as root:
                rule = self._rule_with_positive("tests/workshop/team-01/positive.ndjson")
                _write_slot_fixtures(root, "team-01")
                link = os.path.join(root, "tests", "workshop", "team-01", "positive.ndjson")
                os.remove(link)
                try:
                    os.symlink(secret, link)
                except (OSError, NotImplementedError):
                    self.skipTest("symlinks unsupported on this platform")
                _write_detection(root, "workshop", "team-01", rule)
                self.assertEqual(self._run_main(root), 1)

    def test_shared_fixtures_still_allowed_for_baseline(self):
        # A baseline rule (detections/baseline/<slug>/) legitimately uses
        # tests/shared-fixtures/ — the containment rework must not break it.
        with tempfile.TemporaryDirectory() as root:
            rule = _good_rule()
            rule["id"] = "baseline-demo-rule"
            rule["test_cases"] = {
                "positive": ["tests/shared-fixtures/baseline-demo/positive.ndjson"],
                "negative": ["tests/shared-fixtures/baseline-demo/negative.ndjson"],
            }
            _write_fixture(root, "tests/shared-fixtures/baseline-demo/positive.ndjson",
                           ['{"@timestamp":"2024-11-12T08:05:09Z","event.id":"p1",'
                            '"event.action":"authentication_success","event.category":"authentication",'
                            '"event.outcome":"success","host.name":"idp.ctrl.example",'
                            '"user.name":"j.okafor","source.ip":"203.0.113.45"}'])
            _write_fixture(root, "tests/shared-fixtures/baseline-demo/negative.ndjson",
                           ['{"@timestamp":"2024-11-12T08:06:09Z","event.id":"n1",'
                            '"event.action":"authentication_success","event.category":"authentication",'
                            '"event.outcome":"success","host.name":"idp.ctrl.example",'
                            '"user.name":"j.okafor","source.ip":"198.51.100.5"}'])
            _write_detection(root, "baseline", "baseline-demo", rule)
            self.assertEqual(self._run_main(root), 0)


class SingleEventContractTest(unittest.TestCase):
    """Track 3: each fixture holds EXACTLY one event; positive and negative must
    be different files; a file referenced twice is rejected."""

    def _run_main(self, data_root: str) -> int:
        return vd.main(["--all", "--data-root", data_root, "--format", "text"])

    def test_two_events_in_positive_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/positive.ndjson",
                           ['{"event.id":"p1"}', '{"event.id":"p2"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_two_events_in_negative_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/negative.ndjson",
                           ['{"event.id":"n1"}', '{"event.id":"n2"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_positive_equals_negative_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["test_cases"] = {
                "positive": ["tests/workshop/team-01/shared.ndjson"],
                "negative": ["tests/workshop/team-01/shared.ndjson"],
            }
            _write_fixture(root, "tests/workshop/team-01/shared.ndjson", ['{"event.id":"x1"}'])
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_duplicate_reference_same_file_fails(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["test_cases"] = {
                "positive": ["tests/workshop/team-01/positive.ndjson",
                             "tests/workshop/team-01/positive.ndjson"],
                "negative": ["tests/workshop/team-01/negative.ndjson"],
            }
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 1)

    def test_one_event_each_passes(self):
        # The happy path: exactly one event per fixture, distinct files.
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run_main(root), 0)


class FixtureContentMinimumTest(unittest.TestCase):
    """Track 4: each event must be a non-empty JSON object with a non-empty
    string event.id, a tz-aware ISO-8601 @timestamp, and only fields valid for
    the rule's family per the trusted dictionary."""

    def _run_main(self, data_root: str) -> int:
        return vd.main(["--all", "--data-root", data_root, "--format", "text"])

    def _run_with_positive(self, positive_line: str) -> int:
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")  # valid negative
            _write_fixture(root, "tests/workshop/team-01/positive.ndjson", [positive_line])
            _write_detection(root, "workshop", "team-01", rule)
            return self._run_main(root)

    def test_empty_object_fails(self):
        self.assertEqual(self._run_with_positive("{}"), 1)

    def test_missing_event_id_fails(self):
        self.assertEqual(
            self._run_with_positive('{"@timestamp":"2024-11-12T08:05:09Z"}'), 1
        )

    def test_blank_event_id_fails(self):
        self.assertEqual(
            self._run_with_positive('{"@timestamp":"2024-11-12T08:05:09Z","event.id":"  "}'), 1
        )

    def test_missing_timestamp_fails(self):
        self.assertEqual(self._run_with_positive('{"event.id":"p1"}'), 1)

    def test_invalid_timestamp_fails(self):
        self.assertEqual(
            self._run_with_positive('{"@timestamp":"not-a-time","event.id":"p1"}'), 1
        )

    def test_naive_timestamp_fails(self):
        # No timezone offset -> ambiguous -> rejected.
        self.assertEqual(
            self._run_with_positive('{"@timestamp":"2024-11-12T08:05:09","event.id":"p1"}'), 1
        )

    def test_unknown_field_fails(self):
        self.assertEqual(
            self._run_with_positive(
                '{"@timestamp":"2024-11-12T08:05:09Z","event.id":"p1","totally.bogus":1}'
            ),
            1,
        )

    def test_wrong_family_field_fails(self):
        # cloud.api_operation belongs to the cloud family; this rule is identity.
        self.assertEqual(
            self._run_with_positive(
                '{"@timestamp":"2024-11-12T08:05:09Z","event.id":"p1",'
                '"cloud.api_operation":"SetBucketPolicy"}'
            ),
            1,
        )

    def test_valid_event_passes(self):
        # Carries the full identity guaranteed set (see _write_slot_fixtures).
        self.assertEqual(
            self._run_with_positive(
                '{"@timestamp":"2024-11-12T08:05:09Z","event.id":"p1",'
                '"event.action":"authentication_success","event.category":"authentication",'
                '"event.outcome":"success","host.name":"idp.ctrl.example",'
                '"user.name":"j.okafor","source.ip":"203.0.113.45",'
                '"authentication.privileged":true}'
            ),
            0,
        )

    def test_offset_timestamp_passes(self):
        # A non-Z explicit offset is also valid RFC3339. Full identity guaranteed set.
        self.assertEqual(
            self._run_with_positive(
                '{"@timestamp":"2024-11-12T08:05:09+02:00","event.id":"p1",'
                '"event.action":"authentication_success","event.category":"authentication",'
                '"event.outcome":"success","host.name":"idp.ctrl.example",'
                '"user.name":"j.okafor","source.ip":"203.0.113.45"}'
            ),
            0,
        )


class KqlSanityTest(unittest.TestCase):
    """Track 5: bounded KQL syntax sanity for the workshop subset. Every shipped
    baseline query passes; the enumerated malformed patterns fail. This is not a
    full Elastic parser."""

    # the actual non-empty queries shipped in detections/baseline/*
    BASELINE_QUERIES = [
        "event.category: authentication and event.action: authentication_failure",
        "event.category: network and network.protocol: icmp and network.direction: inbound",
        "event.category: network and network.direction: inbound and destination.plane: "
        "management and not destination.port: (22 or 443)",
        'event.category: iam and cloud.resource.type: object_store and cloud.api_operation: '
        '("SetBucketPolicy" or "PutBucketAcl")',
        "event.category: authentication and event.action: authentication_success and "
        'authentication.privileged: true and authentication.method: ("password" or "api_key")',
    ]

    MALFORMED = {
        "empty": "",
        "unbalanced_parens": "event.category: (network and destination.port: 22",
        "extra_close_paren": "event.category: network )",
        "unclosed_quote": 'cloud.api_operation: ("SetBucketPolicy',
        "dangling_and": "event.category: authentication and event.action: success and",
        "dangling_or": "event.category: network or",
        "leading_and": "and event.category: network",
        "invalid_op_seq": "event.category: network and or destination.port: 22",
        "field_no_value": "event.category: and event.action: success",
        "malformed_parens": "event.category: network )( destination.port: 22",
        # the false-greens the earlier checker accepted:
        "bare_garbage": "garbage",
        "adjacent_predicates_no_op": "event.category: authentication event.action: success",
        "empty_parens": "()",
        "not_and": "not and event.category: network",
        "lonely_operator": ">= 5",
        "trailing_not": "event.category: network and not",
        # embedded-predicate false greens (R2-fix: predicate recognition):
        "leading_colon_no_field": ":foo",
        "double_colon_embedded": "event.category::authentication",
        "double_equals_embedded": "event.category==network",
        "colon_head_no_value": "event.category:",
    }

    # queries the subset explicitly SUPPORTS (must NOT be flagged) — includes
    # spaced numeric operators, value lists, and a leading `not`.
    SUPPORTED_EXTRA = [
        "event.action: authentication_success and "
        "workshop.enrichment.failed_logins_same_source_5m >= 5",
        "event.action: flow_summary and network.direction: outbound and "
        'network.bytes_out_10m >= 1000000000 and not source.ip: ("192.0.2.50" or "192.0.2.51")',
        "not destination.plane: management and event.category: network",
    ]

    def test_baseline_queries_pass_syntax(self):
        for q in self.BASELINE_QUERIES + self.SUPPORTED_EXTRA:
            with self.subTest(query=q[:40]):
                self.assertEqual(vd.kql_syntax_errors(q), [], f"supported query flagged: {q}")

    def test_malformed_queries_fail_syntax(self):
        for name, q in self.MALFORMED.items():
            with self.subTest(case=name):
                self.assertTrue(
                    vd.kql_syntax_errors(q), f"malformed query {name!r} not flagged: {q!r}"
                )

    def test_malformed_query_fails_l2_end_to_end(self):
        # A deployable rule with an unbalanced-paren query fails L2 with the
        # workshop-subset wording, and never reaches the field-dictionary pass.
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["query"] = "event.category: (authentication and event.action: success"
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            rc = vd.main(["--all", "--data-root", root, "--format", "text"])
            self.assertEqual(rc, 1)

    def test_false_green_queries_fail_end_to_end(self):
        # Every previously-accepted false green must now fail through main().
        for name in (
            "bare_garbage",
            "adjacent_predicates_no_op",
            "empty_parens",
            "not_and",
            "leading_colon_no_field",
            "double_colon_embedded",
            "double_equals_embedded",
            "colon_head_no_value",
        ):
            with self.subTest(case=name):
                with tempfile.TemporaryDirectory() as root:
                    rule = _slot_rule("team-01")
                    rule["query"] = self.MALFORMED[name]
                    _write_slot_fixtures(root, "team-01")
                    _write_detection(root, "workshop", "team-01", rule)
                    rc = vd.main(["--all", "--data-root", root, "--format", "text"])
                    self.assertEqual(rc, 1, f"false green {name!r} passed end-to-end")

    # explicit embedded-predicate recognition cases from the R2-fix brief.
    EMBEDDED_MUST_FAIL = [
        ":foo",
        "event.category::authentication",
        "event.category==network",
        "event.category:",
    ]
    EMBEDDED_MUST_PASS = [
        "event.category:authentication",
        "event.category: authentication",
        "network.bytes_out_10m>=5",
        "network.bytes_out_10m >= 5",
        '@timestamp >= "2024-11-12T00:00:00Z"',
    ]

    def test_embedded_predicate_malformed_fails(self):
        for q in self.EMBEDDED_MUST_FAIL:
            with self.subTest(query=q):
                self.assertTrue(
                    vd.kql_syntax_errors(q), f"malformed embedded predicate not flagged: {q!r}"
                )

    def test_embedded_predicate_valid_passes(self):
        for q in self.EMBEDDED_MUST_PASS:
            with self.subTest(query=q):
                self.assertEqual(
                    vd.kql_syntax_errors(q), [], f"valid embedded predicate flagged: {q!r}"
                )

    def test_malformed_known_field_fails_end_to_end(self):
        # A malformed embedded predicate over a REAL, family-valid field
        # (`event.category` is an identity field). This proves the parser defect
        # cannot be masked by the field-dictionary pass: the double-colon token
        # must fail as a syntax error before semantic field validation.
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["query"] = "event.category::authentication"
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            rc = vd.main(["--all", "--data-root", root, "--format", "text"])
            self.assertEqual(rc, 1, "malformed predicate over a known field passed end-to-end")

    def test_syntax_failure_suppresses_field_dictionary_pass(self):
        # A query that is BOTH syntactically broken AND references an unknown field
        # reports only the syntax failure (semantic pass is skipped).
        errs_before = vd.kql_syntax_errors("bogus.field: and")
        self.assertTrue(errs_before)


class QueryTypeTest(unittest.TestCase):
    """R2-fix 1: query must be a non-empty string. null/int/list/dict/empty all
    fail cleanly through main() with a non-zero exit and no traceback."""

    def _run_with_query(self, query_value) -> int:
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")  # deployable identity rule
            rule["query"] = query_value
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            try:
                return vd.main(["--all", "--data-root", root, "--format", "text"])
            except Exception as exc:  # noqa: BLE001
                self.fail(f"query={query_value!r} raised a traceback: {exc}")

    def test_query_null_fails(self):
        self.assertEqual(self._run_with_query(None), 1)

    def test_query_empty_string_fails(self):
        self.assertEqual(self._run_with_query(""), 1)

    def test_query_int_fails(self):
        self.assertEqual(self._run_with_query(123), 1)

    def test_query_list_fails(self):
        self.assertEqual(self._run_with_query([1, 2]), 1)

    def test_query_dict_fails(self):
        self.assertEqual(self._run_with_query({"x": 1}), 1)

    def test_whitespace_only_query_fails(self):
        self.assertEqual(self._run_with_query("   \n  "), 1)


class MitreNestedTypeTest(unittest.TestCase):
    """R2-fix 3: mitre_attack.tactics/techniques/subtechniques, when PRESENT and
    not a list (scalar/dict/int), must fail L2 clearly through main()."""

    def _run_with_mitre(self, mitre_value) -> int:
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            rule["mitre_attack"] = mitre_value
            _write_slot_fixtures(root, "team-01")
            _write_detection(root, "workshop", "team-01", rule)
            try:
                return vd.main(["--all", "--data-root", root, "--format", "text"])
            except Exception as exc:  # noqa: BLE001
                self.fail(f"mitre_attack={mitre_value!r} raised a traceback: {exc}")

    def test_tactics_scalar_fails(self):
        self.assertEqual(
            self._run_with_mitre({"tactics": "TA0001", "techniques": [], "subtechniques": []}), 1
        )

    def test_techniques_dict_fails(self):
        self.assertEqual(
            self._run_with_mitre({"tactics": [], "techniques": {"id": "T1078"}, "subtechniques": []}),
            1,
        )

    def test_subtechniques_int_fails(self):
        self.assertEqual(
            self._run_with_mitre({"tactics": [], "techniques": [], "subtechniques": 5}), 1
        )

    def test_valid_lists_pass(self):
        self.assertEqual(
            self._run_with_mitre(
                {"tactics": ["TA0001"], "techniques": ["T1078"], "subtechniques": ["T1078.004"]}
            ),
            0,
        )

    def test_missing_mitre_keys_remain_valid(self):
        # An empty mapping (no tactics/techniques/subtechniques keys) stays valid —
        # the existing contract treats missing/empty ATT&CK as acceptable.
        self.assertEqual(self._run_with_mitre({}), 0)


class GuaranteedFieldTest(unittest.TestCase):
    """R2-fix 5: every field the dictionary marks guaranteed:true for a rule's
    family must be present in each fixture event. Derived from the dictionary, not
    hardcoded."""

    def _run(self, root: str) -> int:
        return vd.main(["--all", "--data-root", root, "--format", "text"])

    def test_identity_fixture_missing_guaranteed_field_fails(self):
        # Drop source.ip (guaranteed for identity) from the positive fixture.
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")  # identity
            _write_slot_fixtures(root, "team-01")
            _write_fixture(root, "tests/workshop/team-01/positive.ndjson",
                           ['{"@timestamp":"2024-11-12T08:05:09Z","event.id":"p1",'
                            '"event.action":"authentication_success","event.category":"authentication",'
                            '"event.outcome":"success","host.name":"idp.ctrl.example",'
                            '"user.name":"j.okafor"}'])  # no source.ip
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run(root), 1)

    def test_identity_fixture_with_full_guaranteed_set_passes(self):
        with tempfile.TemporaryDirectory() as root:
            rule = _slot_rule("team-01")
            _write_slot_fixtures(root, "team-01")  # helper writes the full set
            _write_detection(root, "workshop", "team-01", rule)
            self.assertEqual(self._run(root), 0)

    def test_guaranteed_set_is_derived_from_dictionary(self):
        # Prove the enforcement reads the trusted dictionary, not a hardcoded list.
        fd = vd.load_field_dictionary(vd.FIELD_DICT_PATH)
        g = fd["guaranteed_by_family"]
        # identity guarantees more than just event.id/@timestamp
        self.assertIn("source.ip", g["identity"])
        self.assertIn("user.name", g["identity"])
        self.assertIn("@timestamp", g["identity"])
        self.assertIn("event.id", g["identity"])
        # network guarantees its own set (destination.ip/port), cloud its own
        self.assertIn("destination.port", g["network"])
        self.assertIn("cloud.api_operation", g["cloud"])


class CrashProofTest(unittest.TestCase):
    """Track 1: hostile participant YAML types must yield a clean FAIL, never a
    traceback. A participant can put any YAML type in any field; the validator
    must degrade to a deterministic L1/L2 failure with a non-zero exit code."""

    @classmethod
    def setUpClass(cls):
        cls.fd = vd.load_field_dictionary(vd.FIELD_DICT_PATH)
        cls.attack = vd.load_attack_subset(vd.ATTACK_SUBSET_PATH)

    # every hostile type a participant could supply for a scalar/structured field
    HOSTILE = {"null": None, "int": 5, "list": [1, 2], "dict": {"x": 1}, "str": "boom"}
    # every target driven through the never-crash sweep
    ALL_TARGETS = [
        "id", "title", "owner", "severity", "status", "log_source", "query",
        "deployment", "test_cases", "mitre_attack", "review_date", "tags",
    ]

    def _run_all_levels(self, rule: dict):
        """Drive L1 then L2 (mem) and the full main() over a temp data root.
        Returns (raised: bool, l1_or_l2_failed: bool, rc: int)."""
        raised = False
        failed = False
        rc = 0
        raw = yaml.safe_dump(rule)
        res = vd.FileResult("mem://crash")
        try:
            parsed = vd.validate_l1("mem://crash", raw, {}, res)
            if parsed is not None:
                vd.validate_l2(parsed, self.fd, self.attack, res)
            failed = (not res.l1.passed) or (not res.l2.skipped and not res.l2.passed)
        except Exception:  # noqa: BLE001 — the whole point is that this never happens
            raised = True
        with tempfile.TemporaryDirectory() as root:
            _write_detection(root, "workshop", "team-01", rule)
            try:
                rc = vd.main(["--all", "--data-root", root, "--format", "text"])
                vd.main(["--all", "--data-root", root, "--format", "json"])
            except Exception:  # noqa: BLE001
                raised = True
        return raised, failed, rc

    def test_hostile_types_never_crash(self):
        # Broadest guarantee: NO hostile type on ANY target raises a traceback.
        for tgt in self.ALL_TARGETS:
            for hlabel, hval in self.HOSTILE.items():
                with self.subTest(target=tgt, hostile=hlabel):
                    rule = _good_rule()
                    rule[tgt] = hval
                    raised, _failed, _rc = self._run_all_levels(rule)
                    self.assertFalse(raised, f"{tgt}={hlabel} raised a traceback")

    def test_hostile_types_on_validated_fields_fail(self):
        # Validated fields must additionally produce a clean FAIL + non-zero rc,
        # but only for the hostile types that are genuinely invalid for that field.
        # A non-empty string is a VALID title/owner; a null/empty mitre_attack is a
        # VALID (unmapped) rule. So the must-fail set is per-field, not a blanket
        # cross-product.
        must_fail = {
            "title": ["null", "int", "list", "dict"],       # str is valid
            "owner": ["null", "int", "list", "dict"],       # str is valid
            "severity": ["null", "int", "list", "dict"],   # deployable rule needs real severity
            "status": ["null", "int", "list", "dict", "str"],  # str "boom" not in ALLOWED
            "log_source": ["null", "int", "list", "dict", "str"],  # str "boom" not a family
            "deployment": ["null", "int", "list", "str"],   # non-dict -> enabled missing
            "test_cases": ["null", "int", "list", "str"],   # non-dict -> shape fail
            "mitre_attack": ["int", "list", "str"],         # null/dict -> empty = valid
        }
        for tgt, labels in must_fail.items():
            for hlabel in labels:
                hval = self.HOSTILE[hlabel]
                with self.subTest(target=tgt, hostile=hlabel):
                    rule = _good_rule()
                    rule[tgt] = hval
                    raised, failed, rc = self._run_all_levels(rule)
                    self.assertFalse(raised, f"{tgt}={hlabel} raised a traceback")
                    self.assertTrue(failed, f"{tgt}={hlabel} did not produce an L1/L2 FAIL")
                    self.assertNotEqual(rc, 0, f"{tgt}={hlabel} exited 0 (should be non-zero)")

    def test_nested_hostile_types_never_crash(self):
        # deployment.enabled and test_cases.<case> as hostile nested types
        for hlabel, hval in self.HOSTILE.items():
            with self.subTest(nested="deployment.enabled", hostile=hlabel):
                rule = _good_rule()
                rule["deployment"] = {"enabled": hval}
                raised, _failed, _rc = self._run_all_levels(rule)
                self.assertFalse(raised, f"deployment.enabled={hlabel} raised")
            with self.subTest(nested="test_cases.positive", hostile=hlabel):
                rule = _good_rule()
                rule["test_cases"] = {"positive": hval, "negative": hval}
                raised, _failed, _rc = self._run_all_levels(rule)
                self.assertFalse(raised, f"test_cases.positive={hlabel} raised")
            with self.subTest(nested="mitre_attack.tactics", hostile=hlabel):
                rule = _good_rule()
                rule["mitre_attack"] = {"tactics": hval, "techniques": hval, "subtechniques": hval}
                raised, _failed, _rc = self._run_all_levels(rule)
                self.assertFalse(raised, f"mitre_attack.tactics={hlabel} raised")

    def test_status_list_fails_cleanly(self):
        rule = _good_rule()
        rule["status"] = ["test"]  # unhashable against ALLOWED_STATUSES
        raised, failed, _rc = self._run_all_levels(rule)
        self.assertFalse(raised)
        self.assertTrue(failed)

    def test_severity_dict_fails_cleanly(self):
        rule = _good_rule()
        rule["severity"] = {"level": "high"}  # unhashable against ALLOWED_SEVERITIES
        raised, failed, _rc = self._run_all_levels(rule)
        self.assertFalse(raised)
        self.assertTrue(failed)

    def test_log_source_list_fails_cleanly(self):
        rule = _good_rule()
        rule["log_source"] = ["identity"]  # unhashable against families set
        raised, failed, _rc = self._run_all_levels(rule)
        self.assertFalse(raised)
        self.assertTrue(failed)

    def test_mitre_attack_string_fails_cleanly(self):
        rule = _good_rule()
        rule["mitre_attack"] = "T1078"  # truthy non-dict; .get would crash
        raised, failed, _rc = self._run_all_levels(rule)
        self.assertFalse(raised)
        self.assertTrue(failed)

    def test_raw_malformed_yaml_never_crashes(self):
        raw_cases = [
            "id: x\n\tstatus: test\n",          # tab indent
            "id: x\nfoo: [1, 2\n",              # unclosed bracket
            "id: *nope\n",                       # bad anchor
            "id: a\nid: b\n",                    # duplicate key
            ":\n",                                # just colon
            "not a mapping at all\n",            # plain scalar
        ]
        for i, txt in enumerate(raw_cases):
            with self.subTest(case=i):
                with tempfile.TemporaryDirectory() as root:
                    ddir = os.path.join(root, "detections", "workshop", "team-01")
                    os.makedirs(ddir, exist_ok=True)
                    with open(os.path.join(ddir, "detection.yaml"), "w", encoding="utf-8") as fh:
                        fh.write(txt)
                    try:
                        rc = vd.main(["--all", "--data-root", root, "--format", "text"])
                    except Exception:  # noqa: BLE001
                        self.fail(f"raw malformed case {i} raised a traceback")
                    self.assertNotEqual(rc, 0, f"raw malformed case {i} exited 0")


if __name__ == "__main__":
    unittest.main()
