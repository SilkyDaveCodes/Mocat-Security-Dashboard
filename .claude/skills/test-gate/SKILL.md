---
name: test-gate
description: Runs the read-only test-gate agent on the current changes and reports APPROVE or BLOCK. Default mode reviews the uncommitted diff (are the new tests real, did anything regress); "full" audits the whole project for release readiness. Use after changing code by hand, before a commit or push, after a merge, and with "full" before a release or demo.
argument-hint: '[full] [optional note on what changed]'
---

Arguments (may be blank):

$ARGUMENTS

## Step 0 - Pick the mode

- If the first word of the arguments is `full`, the mode is **full**: a release-readiness audit
  of the whole project.
- Otherwise the mode is **diff**: review what changed since the last commit. Anything else in
  the arguments is a note on what the change is meant to do; pass it to the agent.

## Step 1 - Gather what the agent needs

The agent has no memory of this conversation, so collect it here:
- `git status`, `git diff HEAD --stat`, and `git log --oneline -5`.
- **diff mode:** if there is nothing uncommitted, compare the working branch from `CLAUDE.md`
  `## Branches` against `main` instead (`git diff main...HEAD --stat`). If that is empty too,
  tell the user there is nothing to gate and suggest `/test-gate full`. Then stop.
- **Intended behavior:** use the user's note. If the change came from earlier in this
  conversation, add a short summary of what it was meant to do. If neither exists, say "infer
  from the diff".
- **Baseline:** if checks were run before the change earlier in this conversation, pass their
  per-check exit status and failing test names. Otherwise pass "no baseline". Do not stash or
  check out code to build one; the agent will treat every failure as blocking.

## Step 2 - Run the gate

Spawn `subagent_type: test-gate` (read-only, defined in `.claude/agents/test-gate.md`) in the
foreground (`run_in_background: false`). Give it a self-contained prompt with:
- `Mode: diff` or `Mode: full`.
- The intended behavior from Step 1 (diff mode).
- The diff summary and recent commits.
- The baseline summary, or "no baseline".

Do not run other test suites while it works. Two runs at once can fight over ports and files.

## Step 3 - Report

Show the agent's `## Verdict` line and `## Blocking items` verbatim, then summarize:
- Tests it rejected and why, and any test tampering it found.
- Regressions, and any layers marked UNGUARDED.
- **full mode:** each release-readiness item that is a PROBLEM.

On **APPROVE**, say the change is clear to commit (or, in full mode, to merge to `main`). Do
not commit, push or merge unless the user asks. On **BLOCK**, list what must change and let
the user decide whether you fix it. Do not fix anything as part of this skill.
