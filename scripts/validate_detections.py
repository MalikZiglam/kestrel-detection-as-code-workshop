#!/usr/bin/env python3
"""Offline, deterministic PR-time detection validator (WORKSHOP_SPEC §14/§18/§19).

Runs from the TRUSTED base ref, never PR head. Participant YAML is DATA: parsed
with yaml.safe_load() ONLY. Never executes participant content. Offline; needs
only the Python stdlib plus PyYAML.

THREE EXPLICIT VALIDATION LEVELS
--------------------------------
L1 STRUCTURAL  valid YAML, required metadata, id format+uniqueness, allowed
               severity/status, positive+negative fixture references present.
L2 SEMANTIC    field-dictionary AS CONTRACT: log_source is a real family; every
               field the query references exists in the dictionary AND belongs
               to that family; cheap datatype/exact-match misuse flags; ATT&CK
               ids exist in the pinned local subset (docs/attack/attack-subset.yaml).
L3 RUNTIME     NOT run here. Behavioral detection proof: does the rule actually
               fire? Run post-merge in the facilitator env by
               scripts/smoke_test.py (drives replay_events.py, polls alerts).
               Structural/semantic PASS does NOT prove runtime detection.
               (Separate from desired-state reconciliation, which
               scripts/verify_baseline.py checks — Git desired set vs live
               Elastic set — and which is NOT detection behavior.)

TEACHING LINE: L1 pass != L2 pass != runtime pass.

DEPLOYABILITY GATE (docs/DEPLOYMENT-CONTRACT.md)
A detection is DEPLOYABLE iff status in {test, production} AND deployment.enabled
is true. Deployable rules are held to STRICT L1/L2 (non-empty query, real
severity, fixtures, valid fields+ATT&CK). Non-deployable rules (draft, deprecated,
not_detectable, or enabled=false) are lifecycle artifacts that legitimately live
in Git; they get RELAXED L1 (metadata keys must exist, but a draft may carry an
empty query / TBD severity / no fixtures). Where a non-deployable rule DOES carry
a query or ATT&CK ids, those are still validated.

KQL FIELD PARSER — LIMITS (deliberately simple + deterministic)
Extracts field tokens matching `field:value` and `field <op> value`
(op in : >= <= > < =). Recognizes `and`, `or`, `not`, parentheses, and quoted /
parenthesized value lists as NON-fields. It does NOT parse nested KQL functions,
scripted fields, or wildcards in field names. This is enough for the workshop
grammar and is documented so participants trust the failures.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write("PyYAML is required: pip install pyyaml\n")
    raise SystemExit(2)

# --------------------------------------------------------------------------- #
# Two independent roots (the trust boundary lives here).
#
#   REFERENCE root  = the TRUSTED validator's own checkout, derived from
#                     __file__. Field dictionary + pinned ATT&CK subset load
#                     from here ONLY, so participant content can never swap the
#                     rules to weaken L2. Constant; not overridable by any flag.
#
#   DATA root       = the content being validated. Defaults to the same
#                     __file__-derived root (so a local `--all` from a full
#                     checkout behaves exactly as before), but is overridable
#                     via --data-root so CI can run the trusted validator from
#                     base/ against participant DATA in pr/.
#
# `--all` globs detections under the DATA root; relpath in output is against the
# DATA root. Field dict + ATT&CK subset always come from the REFERENCE root.
# --------------------------------------------------------------------------- #
REFERENCE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIELD_DICT_PATH = os.path.join(REFERENCE_ROOT, "logs", "field-dictionary.yaml")
ATTACK_SUBSET_PATH = os.path.join(REFERENCE_ROOT, "docs", "attack", "attack-subset.yaml")

# Back-compat alias: some callers/tests referenced REPO_ROOT. It now names the
# REFERENCE root (validator location), which is where it always resolved to.
REPO_ROOT = REFERENCE_ROOT
RUNTIME_SCRIPT_HINT = (
    "scripts/smoke_test.py (facilitator-controlled runtime stage: drives replay_events.py, polls alerts)"
)

DEPLOYABLE_STATUSES = {"test", "production"}
ALLOWED_STATUSES = {"draft", "test", "production", "deprecated", "not_detectable"}
ALLOWED_SEVERITIES = {"low", "medium", "high", "critical"}

# §14 required metadata keys.
REQUIRED_KEYS = [
    "id",
    "title",
    "status",
    "owner",
    "deployment",
    "severity",
    "log_source",
    "query",
    "mitre_attack",
    "test_cases",
    "review_date",
]

ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
REVIEW_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
ATTACK_TACTIC_RE = re.compile(r"^TA\d{4}$")
ATTACK_TECH_RE = re.compile(r"^T\d{4}$")
ATTACK_SUBTECH_RE = re.compile(r"^T\d{4}\.\d{3}$")

# Participant-added tool config we ignore even if globbed (§17.4).
IGNORED_CONFIG = {
    ".yamllint",
    "pyproject.toml",
    ".pre-commit-config.yaml",
    "conftest.py",
    "Makefile",
}

# KQL reserved words that are never field names.
KQL_KEYWORDS = {"and", "or", "not", "true", "false"}
# field <op> value  — op captured so we can do a cheap type sanity check.
FIELD_TOKEN_RE = re.compile(r"([a-zA-Z_][a-zA-Z0-9_.]*)\s*(:|>=|<=|>|<|=)")


# --------------------------------------------------------------------------- #
# Result model
# --------------------------------------------------------------------------- #
class LevelResult:
    def __init__(self, level: str):
        self.level = level  # "L1" | "L2"
        self.errors: list[str] = []
        self.skipped = False
        self.skip_reason = ""

    @property
    def passed(self) -> bool:
        return not self.errors

    def fail(self, msg: str) -> None:
        self.errors.append(msg)


class FileResult:
    def __init__(self, path: str):
        self.path = path
        self.skipped_placeholder = False
        self.l1 = LevelResult("L1")
        self.l2 = LevelResult("L2")

    @property
    def ok(self) -> bool:
        if self.skipped_placeholder:
            return True
        return self.l1.passed and (self.l2.skipped or self.l2.passed)


# --------------------------------------------------------------------------- #
# Reference data loaders
# --------------------------------------------------------------------------- #
def load_field_dictionary(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    families = set(doc.get("log_source_enum", []))
    field_families: dict[str, set[str]] = {}
    field_types: dict[str, str] = {}
    for entry in doc.get("fields", []):
        name = entry["name"]
        field_families[name] = set(entry.get("families", []))
        field_types[name] = entry.get("type", "")
    # Families that map to a deployable index are the SINGLE trusted source in
    # family_index_mapping.mapped (facilitator-controlled). A deployable rule on
    # a family NOT listed here has nowhere to deploy (L2 failure below). Derive
    # the set here so there is never a second, drifting copy of the mapping.
    mapping = doc.get("family_index_mapping") or {}
    mapped_families = set((mapping.get("mapped") or {}).keys())
    return {
        "families": families,
        "field_families": field_families,
        "field_types": field_types,
        "mapped_families": mapped_families,
    }


def load_attack_subset(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    tactics = {t["id"] for t in doc.get("tactics", [])}
    techniques = {t["id"] for t in doc.get("techniques", [])}
    subtechs = {s["id"] for s in doc.get("subtechniques", [])}
    version = doc.get("meta", {}).get("attack_version", "unknown")
    pinned = doc.get("meta", {}).get("pinned_on", "unknown")
    return {
        "tactics": tactics,
        "techniques": techniques,
        "subtechniques": subtechs,
        "version": version,
        "pinned_on": pinned,
    }


# --------------------------------------------------------------------------- #
# KQL field extraction (documented limits in module docstring)
# --------------------------------------------------------------------------- #
def extract_query_fields(query: str) -> list[tuple[str, str]]:
    """Return [(field, op)] tokens. Deterministic, best-effort, documented."""
    if not query:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in FIELD_TOKEN_RE.finditer(query):
        field, op = match.group(1), match.group(2)
        if field.lower() in KQL_KEYWORDS:
            continue
        if field in seen:
            continue
        seen.add(field)
        out.append((field, op))
    return out


def is_deployable(rule: dict) -> bool:
    status = rule.get("status")
    enabled = (rule.get("deployment") or {}).get("enabled") is True
    return status in DEPLOYABLE_STATUSES and enabled


def _check_fixture_list(value: object, case: str, l1: LevelResult) -> None:
    """A deployable rule's test_cases.<case> must be a non-empty list of
    non-empty path strings. A bare scalar (e.g. one path without a `- `) or a
    non-string entry is rejected — those are the common authoring mistakes that
    would otherwise pass a truthiness check and then break replay."""
    if not value:
        l1.fail(f"deployable rule missing {case} fixture reference")
        return
    if not isinstance(value, list):
        l1.fail(
            f"test_cases.{case} must be a YAML list of path strings, not "
            f"{type(value).__name__} (start each path with '- ')"
        )
        return
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            l1.fail(f"test_cases.{case}[{i}] must be a non-empty path string (got {item!r})")


def _expected_fixture_prefix(detection_path: str, data_root: str) -> str | None:
    """The fixture subtree a rule's fixtures must live under, by rule location.

    Participant rules (detections/workshop/<ns>/) own tests/workshop/<ns>/.
    Facilitator baselines (detections/baseline/<slug>/) use tests/shared-fixtures/.
    Returns None if the path is not under a known detections subtree (then only
    generic checks apply)."""
    rel = os.path.relpath(detection_path, data_root).replace(os.sep, "/")
    parts = rel.split("/")
    if len(parts) >= 3 and parts[0] == "detections" and parts[1] == "workshop":
        return f"tests/workshop/{parts[2]}/"
    if len(parts) >= 3 and parts[0] == "detections" and parts[1] == "baseline":
        return "tests/shared-fixtures/"
    return None


def validate_fixture_refs(rule: dict, detection_path: str, data_root: str, l1: LevelResult) -> None:
    """Validate that a DEPLOYABLE rule's fixture references resolve to real,
    correctly-shaped ndjson files INSIDE the data root's expected subtree.

    Structural only (L1): the file must exist, be a regular file, end in
    .ndjson, sit under the rule's owning fixture subtree, hold >=1 non-empty
    line, and every non-empty line must parse as a JSON OBJECT. This never
    executes a fixture and never evaluates KQL — it proves the reference is a
    usable ndjson event file, nothing about whether the rule fires (that is L3).
    """
    tc = rule.get("test_cases")
    if not isinstance(tc, dict):
        return  # shape already failed above
    prefix = _expected_fixture_prefix(detection_path, data_root)
    root_abs = os.path.abspath(data_root)
    for case in ("positive", "negative"):
        refs = tc.get(case)
        if not isinstance(refs, list):
            continue  # list-shape already failed in _check_fixture_list
        for ref in refs:
            if not isinstance(ref, str) or not ref.strip():
                continue  # already failed in _check_fixture_list
            ref = ref.strip()
            if not ref.endswith(".ndjson"):
                l1.fail(f"{case} fixture {ref!r} must be a .ndjson file")
                continue
            if prefix is not None and not ref.startswith(prefix):
                l1.fail(f"{case} fixture {ref!r} must live under {prefix}")
                continue
            abs_ref = os.path.abspath(os.path.join(data_root, ref))
            # containment: never escape the data root (no ../ traversal)
            if os.path.commonpath([root_abs, abs_ref]) != root_abs:
                l1.fail(f"{case} fixture {ref!r} resolves outside the repository")
                continue
            if not os.path.exists(abs_ref):
                l1.fail(f"{case} fixture {ref!r} does not exist")
                continue
            if not os.path.isfile(abs_ref):
                l1.fail(f"{case} fixture {ref!r} is not a regular file")
                continue
            _check_fixture_content(abs_ref, ref, case, l1)


def _check_fixture_content(abs_ref: str, ref: str, case: str, l1: LevelResult) -> None:
    """>=1 non-empty line, each non-empty line a JSON object. No execution."""
    try:
        with open(abs_ref, encoding="utf-8") as fh:
            nonempty = 0
            for lineno, raw in enumerate(fh, 1):
                s = raw.strip()
                if not s:
                    continue
                nonempty += 1
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError as exc:
                    l1.fail(f"{case} fixture {ref!r} line {lineno} is not valid JSON: {exc}")
                    continue
                if not isinstance(obj, dict):
                    l1.fail(f"{case} fixture {ref!r} line {lineno} is not a JSON object")
        if nonempty == 0:
            l1.fail(f"{case} fixture {ref!r} has no event lines")
    except OSError as exc:
        l1.fail(f"{case} fixture {ref!r} cannot be read: {exc}")


# --------------------------------------------------------------------------- #
# LEVEL 1 — STRUCTURAL
# --------------------------------------------------------------------------- #
def validate_l1(path: str, raw: str, seen_ids: dict[str, str], res: FileResult) -> dict | None:
    l1 = res.l1

    # valid YAML via safe_load ONLY
    try:
        rule = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        l1.fail(f"invalid YAML: {exc}")
        return None

    if rule is None:
        # comment-only placeholder (team slots). Not a rule; skip cleanly.
        res.skipped_placeholder = True
        return None
    if not isinstance(rule, dict):
        l1.fail("top-level YAML is not a mapping")
        return None

    # required metadata present
    for key in REQUIRED_KEYS:
        if key not in rule:
            l1.fail(f"missing required key: {key}")
    dep = rule.get("deployment")
    if not isinstance(dep, dict) or "enabled" not in (dep or {}):
        l1.fail("deployment.enabled missing")
    elif not isinstance(dep.get("enabled"), bool):
        # A YAML string "true"/"false" is truthy regardless of value and would
        # silently mis-gate deployment. Require a real boolean.
        l1.fail(
            f"deployment.enabled must be a YAML boolean true/false, not "
            f"{type(dep.get('enabled')).__name__} {dep.get('enabled')!r} "
            "(remove the quotes: enabled: true)"
        )
    tc = rule.get("test_cases")
    if not isinstance(tc, dict) or "positive" not in tc or "negative" not in tc:
        l1.fail("test_cases must define positive and negative")

    # status
    status = rule.get("status")
    if status not in ALLOWED_STATUSES:
        l1.fail(f"status {status!r} not in {sorted(ALLOWED_STATUSES)}")

    deployable = is_deployable(rule) if isinstance(rule.get("deployment"), dict) else False

    # severity: real value required for deployable; non-deployable may be a placeholder
    sev = rule.get("severity")
    if deployable:
        if sev not in ALLOWED_SEVERITIES:
            l1.fail(f"severity {sev!r} not in {sorted(ALLOWED_SEVERITIES)} (deployable rule)")
    else:
        if sev is not None and sev not in ALLOWED_SEVERITIES:
            # allow explicit placeholder like TBD on non-deployable lifecycle artifacts
            if str(sev).strip().upper() not in {"TBD", ""}:
                l1.fail(f"severity {sev!r} not valid and not an accepted placeholder")

    # id format + uniqueness
    rid = rule.get("id")
    if isinstance(rid, str):
        if not ID_RE.match(rid):
            l1.fail(f"id {rid!r} must be lowercase [a-z0-9-], 3-64 chars")
        elif rid in seen_ids:
            l1.fail(f"duplicate id {rid!r} (also in {seen_ids[rid]})")
        else:
            seen_ids[rid] = path
    elif "id" in rule:
        l1.fail("id must be a string")

    # review_date format
    rd = rule.get("review_date")
    if rd is not None and not REVIEW_DATE_RE.match(str(rd)):
        l1.fail(f"review_date {rd!r} must be YYYY-MM-DD")

    # query + fixtures — strict for deployable, relaxed for lifecycle artifacts
    query = rule.get("query")
    query_str = "" if query is None else str(query).strip()
    pos = (tc or {}).get("positive") if isinstance(tc, dict) else None
    neg = (tc or {}).get("negative") if isinstance(tc, dict) else None
    if deployable:
        if not query_str:
            l1.fail("deployable rule has empty query")
        _check_fixture_list(pos, "positive", l1)
        _check_fixture_list(neg, "negative", l1)

    # participant YAML must NOT declare infra routing (§14 / S5)
    for forbidden in ("index", "data_view", "endpoint", "destination", "credentials"):
        if forbidden in rule:
            l1.fail(f"forbidden facilitator-controlled key present: {forbidden}")

    return rule


# --------------------------------------------------------------------------- #
# LEVEL 2 — SEMANTIC (field dictionary contract + pinned ATT&CK)
# --------------------------------------------------------------------------- #
def validate_l2(rule: dict, fd: dict, attack: dict, res: FileResult) -> None:
    l2 = res.l2
    if rule is None:
        l2.skipped = True
        l2.skip_reason = "no rule"
        return

    # log_source must be a defined family
    family = rule.get("log_source")
    if family not in fd["families"]:
        l2.fail(f"log_source {family!r} is not a defined family {sorted(fd['families'])}")
        family = None  # can't do family-scoped field checks

    # DEPLOYABILITY x TELEMETRY MAPPING.
    # A rule marked deployable (status test/production AND deployment.enabled true)
    # must target a family that maps to a deployable index. Only the families in
    # the field dictionary's family_index_mapping.mapped (identity/network/cloud
    # in this build) have somewhere to deploy. A deployable rule on an unmapped
    # family (application/admin/endpoint) cannot ship — the correct move is to
    # keep it non-deployable (draft/not_detectable, enabled:false) and request
    # telemetry onboarding, exactly like the candidate #7 gap. This is a teaching
    # failure, not a shape error: L1 can be perfect and this still fails.
    if family is not None and is_deployable(rule) and family not in fd["mapped_families"]:
        l2.fail(
            f"deployable rule targets family {family!r}, which is NOT mapped to a "
            f"deployable index in this build (mapped: {sorted(fd['mapped_families'])}). "
            "A deployable rule needs a mapped family. Either target a mapped family, "
            "or keep this non-deployable (status draft/not_detectable, "
            "deployment.enabled false) and onboard telemetry for this family first."
        )

    # field-dictionary contract over the query
    query = rule.get("query")
    query_str = "" if query is None else str(query).strip()
    if query_str:
        for field, op in extract_query_fields(query_str):
            if field not in fd["field_families"]:
                # unknown field: this is the candidate-#7 secrets-audit gap path
                l2.fail(f"query field {field!r} not in field dictionary (telemetry gap or typo)")
                continue
            if family is not None and family not in fd["field_families"][field]:
                l2.fail(
                    f"query field {field!r} not available in family {family!r} "
                    f"(belongs to {sorted(fd['field_families'][field])})"
                )
            # cheap datatype misuse: numeric comparison on a non-numeric field
            if op in {">=", "<=", ">", "<"}:
                ftype = fd["field_types"].get(field, "")
                if ftype not in {"integer", "long", "float", "double", "date"}:
                    l2.fail(f"field {field!r} type {ftype!r} misused with numeric op {op!r}")

    # ATT&CK ids exist in the pinned local subset (existence only — not mapping quality)
    ma = rule.get("mitre_attack") or {}
    for tid in ma.get("tactics", []) or []:
        if not ATTACK_TACTIC_RE.match(str(tid)):
            l2.fail(f"ATT&CK tactic {tid!r} malformed (expect TAxxxx)")
        elif tid not in attack["tactics"]:
            l2.fail(f"ATT&CK tactic {tid!r} not in pinned subset {attack['version']}")
    for tid in ma.get("techniques", []) or []:
        if not ATTACK_TECH_RE.match(str(tid)):
            l2.fail(f"ATT&CK technique {tid!r} malformed (expect Txxxx)")
        elif tid not in attack["techniques"]:
            l2.fail(f"ATT&CK technique {tid!r} not in pinned subset {attack['version']}")
    for tid in ma.get("subtechniques", []) or []:
        if not ATTACK_SUBTECH_RE.match(str(tid)):
            l2.fail(f"ATT&CK sub-technique {tid!r} malformed (expect Txxxx.yyy)")
        elif tid not in attack["subtechniques"]:
            l2.fail(f"ATT&CK sub-technique {tid!r} not in pinned subset {attack['version']}")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def deployable_glob(data_root: str) -> list[str]:
    patterns = [
        os.path.join(data_root, "detections", "baseline", "*", "detection.yaml"),
        os.path.join(data_root, "detections", "workshop", "*", "detection.yaml"),
    ]
    files: list[str] = []
    for pat in patterns:
        files.extend(sorted(glob.glob(pat)))
    return files


def validate_files(paths: list[str], levels: str, data_root: str) -> list[FileResult]:
    fd = load_field_dictionary(FIELD_DICT_PATH)
    attack = load_attack_subset(ATTACK_SUBSET_PATH)
    seen_ids: dict[str, str] = {}
    results: list[FileResult] = []
    for path in paths:
        if os.path.basename(path) in IGNORED_CONFIG:
            continue
        res = FileResult(path)
        try:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            res.l1.fail(f"cannot read file: {exc}")
            results.append(res)
            continue

        rule = validate_l1(path, raw, seen_ids, res) if levels in {"1", "all"} else _quiet_load(raw, res)
        if res.skipped_placeholder:
            results.append(res)
            continue
        # Fixture references resolve against the DATA root (L1, deployable only).
        if levels in {"1", "all"} and rule is not None and is_deployable(rule):
            validate_fixture_refs(rule, path, data_root, res.l1)
        if levels in {"2", "all"}:
            if rule is None:
                res.l2.skipped = True
                res.l2.skip_reason = "L1 could not parse a rule"
            else:
                validate_l2(rule, fd, attack, res)
        else:
            res.l2.skipped = True
            res.l2.skip_reason = "level 1 only"
        results.append(res)
    return results, attack


def _quiet_load(raw: str, res: FileResult) -> dict | None:
    """Load a rule for L2-only runs without recording L1 errors."""
    try:
        rule = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if rule is None:
        res.skipped_placeholder = True
        return None
    return rule if isinstance(rule, dict) else None


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
L3_NOTICE = (
    "[L3 RUNTIME] NOT RUN. No Elastic at PR time. Structural/semantic PASS does "
    "NOT prove runtime detection. Runtime behavior is proven post-merge by "
    + RUNTIME_SCRIPT_HINT
    + "."
)


def render_text(results: list[FileResult], attack: dict, levels: str, data_root: str) -> tuple[str, bool]:
    lines: list[str] = []
    any_fail = False
    lines.append(
        f"ATT&CK pinned subset: {attack['version']} (pinned {attack['pinned_on']}) "
        f"[deterministic existence check only; mapping correctness is human/AI review]"
    )
    lines.append("")
    for res in results:
        rel = os.path.relpath(res.path, data_root)
        if res.skipped_placeholder:
            lines.append(f"SKIP  {rel}  (placeholder/empty slot — no rule authored)")
            continue
        # L1
        if levels in {"1", "all"}:
            if res.l1.passed:
                lines.append(f"[L1 STRUCTURAL] PASS  {rel}")
            else:
                any_fail = True
                lines.append(f"[L1 STRUCTURAL] FAIL  {rel}")
                for e in res.l1.errors:
                    lines.append(f"    - {e}")
        # L2
        if levels in {"2", "all"}:
            if res.l2.skipped:
                lines.append(f"[L2 SEMANTIC]   SKIP  {rel}  ({res.l2.skip_reason})")
            elif res.l2.passed:
                lines.append(f"[L2 SEMANTIC]   PASS  {rel}")
            else:
                any_fail = True
                lines.append(f"[L2 SEMANTIC]   FAIL  {rel}")
                for e in res.l2.errors:
                    lines.append(f"    - {e}")
    lines.append("")
    lines.append(L3_NOTICE)
    lines.append("")
    lines.append("TEACHING: L1 pass != L2 pass != runtime pass.")
    return "\n".join(lines), any_fail


def render_json(results: list[FileResult], attack: dict, levels: str, data_root: str) -> tuple[str, bool]:
    any_fail = False
    out = {
        "attack_subset": {"version": attack["version"], "pinned_on": attack["pinned_on"]},
        "l3_runtime": {"run": False, "notice": L3_NOTICE},
        "teaching": "L1 pass != L2 pass != runtime pass.",
        "results": [],
    }
    for res in results:
        rel = os.path.relpath(res.path, data_root)
        if res.skipped_placeholder:
            out["results"].append({"file": rel, "skipped_placeholder": True})
            continue
        entry = {"file": rel}
        if levels in {"1", "all"}:
            entry["l1"] = {"pass": res.l1.passed, "errors": res.l1.errors}
            any_fail = any_fail or not res.l1.passed
        if levels in {"2", "all"}:
            if res.l2.skipped:
                entry["l2"] = {"skipped": True, "reason": res.l2.skip_reason}
            else:
                entry["l2"] = {"pass": res.l2.passed, "errors": res.l2.errors}
                any_fail = any_fail or not res.l2.passed
        out["results"].append(entry)
    return json.dumps(out, indent=2), any_fail


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline 3-level detection validator (L1/L2; L3 is runtime).")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--files", nargs="+", help="explicit detection.yaml paths")
    src.add_argument("--all", action="store_true", help="glob all deployable-path detections")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--level", choices=["1", "2", "all"], default="all",
                    help="run L1 only, L2 only, or both (teaching aid). L3 never runs here.")
    ap.add_argument(
        "--data-root",
        default=None,
        help=(
            "Root of the DATA being validated (participant content). --all globs "
            "detections/{baseline,workshop}/*/detection.yaml under this root and "
            "output relpaths are computed against it. Defaults to the validator's "
            "own checkout (REFERENCE_ROOT). Falls back to $VALIDATE_DETECTIONS_DATA_ROOT. "
            "The field dictionary and ATT&CK subset ALWAYS load from the trusted "
            "validator location, never from this root."
        ),
    )
    args = ap.parse_args(argv)

    data_root = args.data_root or os.environ.get("VALIDATE_DETECTIONS_DATA_ROOT") or REFERENCE_ROOT
    data_root = os.path.abspath(data_root)

    paths = deployable_glob(data_root) if args.all else [os.path.abspath(p) for p in args.files]
    if not paths:
        sys.stderr.write("no detection files matched\n")
        return 2

    results, attack = validate_files(paths, args.level, data_root)
    if args.format == "json":
        text, any_fail = render_json(results, attack, args.level, data_root)
    else:
        text, any_fail = render_text(results, attack, args.level, data_root)
    print(text)
    return 1 if any_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
