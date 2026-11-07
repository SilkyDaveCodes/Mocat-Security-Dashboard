---
name: implement-ticket
description: Implements a ticket by delegating to a developer subagent, optionally checks it against the ticket with a read-only verifier subagent, then always runs the test-gate agent to approve the ticket's test cases and confirm nothing else broke, then has a cheaper subagent write a short beginner study guide (what each piece does, plus a Mermaid map of the changes) to docs/study-guides/, and after an approved commit and push closes the issue. Use when the user gives a ticket/task description or issue number and wants it built and verified in one pass.
argument-hint: <ticket description, issue number, or issue URL>
---

Ticket to implement:

$ARGUMENTS

If no ticket description was provided above, stop here and ask the user to paste the ticket
text before doing anything else - do not guess at requirements. The ticket can be a GitHub
issue (paste the number or URL and read it with `gh issue view`) or raw ticket text the user
pastes directly - handle both the same way once you have the requirements.

## Step 0 - Sync with the working branch and record a baseline

Work directly in the current checkout. Do not create a git worktree, and do not create a
feature branch unless the user explicitly asks for one.

Read the **working branch** name from the `CLAUDE.md` `## Branches` section (the
"Working branch:" line). If there is no such line, ask the user which branch to work on.
Never implement on the default branch (`main`) unless that is the named working branch.

Before implementing, get the checkout up to date with the working branch:
- `git status` - if the working tree is dirty, stop and ask the user how to proceed rather
  than moving or stashing their changes.
- If clean: `git checkout <working branch>` then `git pull` so the implementation starts
  from the latest working branch.

Then record the **baseline**: run every command in the `CLAUDE.md` `## Checks` table plus the
smoke test, and note for each one the exit status and the names of any failing tests. Keep
this summary - the test gate in Step 3 compares against it to tell "this ticket broke it"
apart from "it was already broken". If `## Checks` has no commands yet, write down
"baseline: no checks configured".

If the baseline is already red, tell the user which checks fail before starting, and ask
whether to proceed anyway.

## Step 1 - Developer subagent

Spawn one subagent with the Agent tool (`subagent_type: general-purpose`,
`run_in_background: false` - the next steps depend on its result). Give it a fully
self-contained prompt (it has no memory of this conversation) that includes:
- The ticket description, verbatim.
- Instruction to implement it completely in the current project, directly in the current
  checkout - it must not create a git worktree or branch, and must not commit or push.
  Follow the code principles in the root `CLAUDE.md`, if it lists any.
- **Tests are part of the ticket.** Write at least one automated test per acceptance
  criterion, in the layer's existing test runner (see `CLAUDE.md` `## Checks`). Tests must
  assert real behavior - not just that a function was called or that a mock returned what it
  was told to. Mock external AI/model calls; never require a real API key in a unit test.
  If the layer has no test runner yet, set up the minimal one and add its command to
  `## Checks`.
- **Do not delete, skip, `xfail`, or loosen any existing test** to make the change pass. If
  an existing test is genuinely wrong because the ticket changes intended behavior, update it
  and call that out explicitly in the report with the reason.
- Run the full `## Checks` commands and the smoke test before finishing, not just the new
  tests.
- End its final message with a clear report: files created/changed and why, the approach,
  a table mapping each acceptance criterion to the test(s) that cover it (file + test name),
  every existing test it modified and why, the check commands it ran with their results, and
  any assumptions or open questions.

Wait for this subagent to finish before continuing.

## Step 2 - Ask whether to run the ticket verifier

If the issue has the `size:S` label, skip the verifier without asking and say so in the
report. The test gate already re-checks the tests and runs the suite, so a second reviewer
adds little for a small ticket.

Otherwise use the AskUserQuestion tool: "Run the read-only ticket verifier on this
implementation?" with options "Yes, verify it" (recommended) and "No, skip verification".
Mention that the test gate in Step 3 runs either way.

If the user chooses to verify: spawn `subagent_type: ticket-verifier` (read-only, defined in
`.claude/agents/ticket-verifier.md`) in the foreground. Give it the original ticket verbatim,
a **short summary** of the developer's report (changed files, key design choices, the
criterion -> test table, open questions — not the full report), and instruction to
independently verify the implementation satisfies the ticket by reading the changed files
itself and checking for bugs, missed requirements, or `CLAUDE.md` principle violations.

## Step 3 - Test gate (always runs)

Spawn `subagent_type: test-gate` (read-only, defined in `.claude/agents/test-gate.md`) with
`run_in_background: false`. Do this after Step 2's verifier has returned, not in parallel -
two agents running test suites at once can fight over ports and files. Give it:
- Mode: `ticket`.
- The original ticket, verbatim (so it can map acceptance criteria to tests).
- The criterion -> test table from the developer's report, plus the list of changed files.
  Don't paste the full report.
- The verifier's findings as one-line bullets, if it ran.
- The baseline summary from Step 0.

This step is not optional. Only skip it if the user explicitly says to skip the test gate in
their own words, and say so prominently in the report.

## Step 4 - Write the study guide

Write a guide whatever the gate's verdict, but do not write it in this conversation: reading
every changed file here is the most expensive part of the run. Spawn one subagent
(`subagent_type: general-purpose`, `model: sonnet`, `run_in_background: false`). Tell it to
follow `.claude/skills/ticket-study-guide/SKILL.md` for this ticket (issue number and short
title), and give it the *why* in a few bullets: the ticket's goal, the key design choices
from the developer's report, the verifier's findings, and the gate verdict with any
blocking items. It reads the diff itself for the *what*. A BLOCKed ticket still gets a
guide, with the blocking items under "Open questions / risks". Only the guide's path comes
back here.

## Step 5 - Report to the user

Do not automatically retry or send fixes back to the developer subagent, even on a FAIL or
BLOCK - this skill does one dev pass, an optional verify pass, and one gate pass, then hands
control back. Summarize concisely:
- What was implemented (1-2 sentences), and the path to the study guide.
- The ticket verifier's verdict (PASS/FAIL) and findings, or that it was skipped.
- The test gate's verdict (APPROVE/BLOCK), its per-test decisions, and any regressions
  against the baseline.
- **Ready to commit** only if the gate said APPROVE (and the verifier, if run, said PASS).
  Do not commit or push - that still needs an explicit ask. On BLOCK, list exactly what has
  to change and let the user decide whether to re-run this skill, fix it themselves, or have
  you fix it directly.

## Step 6 - After the user asks to commit and push

1. Commit only the ticket's files and its study guide to the working branch.
2. `git fetch`. If the remote has new commits, rebase onto it, re-run the `## Checks`
   commands, and push only if they still pass.
3. Once the push succeeds and everything was green (gate APPROVE, verifier PASS if it ran),
   close the GitHub issue without asking: `gh issue close <n> --reason completed` with a
   one-line comment giving the commit hash, the verdicts and the test count, and saying it
   isn't merged to `main` yet. If the issue still has a `blocked` label and its
   prerequisites are done, remove that label.
4. End by telling the user, in one line, to run `/clear` before the next ticket. Every new
   message re-reads the whole conversation, so starting fresh per ticket is the biggest
   token saving. You can't run `/clear` yourself.
