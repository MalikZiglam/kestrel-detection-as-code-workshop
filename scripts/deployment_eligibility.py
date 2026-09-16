#!/usr/bin/env python3
"""Deterministic deployment-eligibility checker.

Mirrors the Terraform `locals` eligibility filter (terraform/main.tf) so the
deploy decision can be verified without a live Elastic cluster or Terraform
install. This is BOTH a teaching tool and the test oracle for
scripts/tests/test_deployment_eligibility.py.

Contract (docs/DEPLOYMENT-CONTRACT.md / WORKSHOP_SPEC.md §20.2, §14):
  A detection is DEPLOYABLE if and only if
    status in {test, production}  AND  deployment.enabled == true.
  draft / deprecated / not_detectable, deployment.enabled != true, and
  unparsed placeholder files are EXCLUDED. Test fixtures live under tests/ and
  never match the two authoritative globs.

Authoritative globs (both use the plain `detection.yaml` filename):
  detections/baseline/*/detection.yaml
  detections/workshop/*/detection.yaml

Participant YAML declares only `log_source: <family>`; it can never set an
index/endpoint/credential. Those are facilitator-controlled. This checker does
not read any credential and makes no network call.
"""

from __future__ import annotations

import argparse
import glob
import os
import sys

import yaml

DEPLOYABLE_STATUSES = {"test", "production"}

# Authoritative globs, relative to the repo root.
GLOBS = (
    "detections/baseline/*/detection.yaml",
    "detections/workshop/*/detection.yaml",
)


def repo_root() -> str:
    """Repo root = parent of the scripts/ directory holding this file."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def discover(root: str) -> list[str]:
    """Return sorted detection.yaml paths matching the two authoritative globs."""
    found: list[str] = []
    for pattern in GLOBS:
        found.extend(glob.glob(os.path.join(root, pattern)))
    return sorted(found)


def eligibility_reason(doc: object) -> tuple[bool, str]:
    """Apply the eligibility filter to one decoded document.

    Returns (deployable, reason). Reason explains an exclusion, or "deployable".
    """
    if not isinstance(doc, dict):
        return False, "unparsed_or_no_status (placeholder or invalid)"
    if "status" not in doc:
        return False, "unparsed_or_no_status (placeholder or invalid)"
    status = doc.get("status")
    if status not in DEPLOYABLE_STATUSES:
        return False, f"status_not_deployable ({status})"
    enabled = (doc.get("deployment") or {}).get("enabled", False)
    if enabled is not True:
        return False, "deployment_disabled (enabled != true)"
    return True, "deployable"


def evaluate(paths: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    """Split paths into (deployable {path: id}, excluded {path: reason})."""
    deployable: dict[str, str] = {}
    excluded: dict[str, str] = {}
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        ok, reason = eligibility_reason(doc)
        if ok:
            deployable[path] = doc["id"]
        else:
            excluded[path] = reason
    return deployable, excluded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        default=repo_root(),
        help="Repo root to scan (default: repo containing this script).",
    )
    args = parser.parse_args(argv)

    paths = discover(args.root)
    deployable, excluded = evaluate(paths)

    rel = lambda p: os.path.relpath(p, args.root)  # noqa: E731

    print(f"DEPLOYABLE ({len(deployable)}):")
    for path in sorted(deployable):
        print(f"  {rel(path)}  ->  id={deployable[path]}")
    print(f"\nEXCLUDED ({len(excluded)}):")
    for path in sorted(excluded):
        print(f"  {rel(path)}  ->  {excluded[path]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
