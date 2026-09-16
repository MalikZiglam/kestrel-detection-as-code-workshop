# GitHub Survival Guide

Browser only. No command line, no Git install. Every step is a click in the GitHub
web UI. You need a GitHub account and access to this repo.

## 1. Create your branch

1. Open the repo on GitHub. Click the **branch dropdown** (top-left of the file
   list, usually says `main`).
2. Type your branch name, e.g. `team-01-detection`.
3. Click **Create branch: team-01-detection from main**.

You are now on your own branch. Changes here do not touch `main`.

## 2. Edit or add a file in the web editor

**Edit an existing file:** open it, click the **pencil** (Edit) icon top-right.

**Add a new file** (e.g. your detection or fixture):
1. Navigate into the folder (e.g. `detections/workshop/team-01/`).
2. Click **Add file → Create new file**.
3. Type the filename (e.g. `detection.yaml`), paste your content.

Confirm the branch dropdown above the editor shows **your branch**, not `main`.

## 3. Commit

1. Scroll to **Commit changes**.
2. Write a short message, e.g. `Add team-01 detection`.
3. Ensure **"Commit directly to the `team-01-detection` branch"** is selected.
4. Click **Commit changes**.

Repeat steps 2–3 for each file (detection.yaml, positive.ndjson, negative.ndjson).

## 4. Open a pull request against main

1. Go to the **Pull requests** tab → **New pull request**.
2. Set **base: `main`** and **compare: your branch**.
3. Click **Create pull request**, add a title, click **Create pull request** again.

## 5. Read the CI check result

1. On the PR page, scroll to the **checks** box near the bottom.
2. Green check = passed. Red X = failed.
3. Click **Details** next to a check to read the log. CI failures name the exact
   problem (e.g. a field not in the dictionary). Fix it by editing your file
   (step 2), commit again — the PR and CI update automatically.

## 6. Review a pull request

To **read** the assigned team's PR: open their PR → **Files changed** tab.

To **leave a review:**
1. On **Files changed**, click a line to add an inline comment (optional).
2. Click **Review changes** (top-right).
3. Choose **Comment**, **Approve**, or **Request changes**, add a summary, click
   **Submit review**.

To **request a review** on your own PR: on the PR page, use the **Reviewers** gear
(right sidebar) and pick the reviewer.

## What NOT to do

- Do not commit to `main` directly.
- Do not edit `terraform/`, `scripts/`, or `tests/shared-fixtures/` — those are
  facilitator-controlled.
