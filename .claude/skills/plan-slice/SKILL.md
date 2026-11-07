---
name: plan-slice
description: 'Turn a project brief (requirements, challenge prompt, or spec) into a thin end-to-end vertical slice, write the narrative to docs/backlog.md, and open the 6-12 slice tasks as GitHub issues (after approval). Use at kickoff of a new project, or to re-plan the slice later. Takes the brief as optional input and falls back to docs/prompt.md.'
argument-hint: 'project brief text, or blank to read docs/prompt.md'
---

Project brief (may be blank):

$ARGUMENTS

## Step 0 - Get the brief

Use the argument above if present. Otherwise read `docs/prompt.md`. If both are empty or
still say "TBD", stop and ask the user to paste the brief and how success will be judged
before continuing. Do not invent requirements.

## Step 1 - Gather context

Read, in this order:
- The brief and any success / judging criteria.
- `CLAUDE.md` for code principles, the current stack decision, and the `## Checks` table.
- Current repo state: `git log --oneline -10`, `git branch -a`, and a top-level directory
  listing. Note what already exists so the plan builds on it instead of ignoring it.

## Step 2 - Define the vertical slice

The slice is the smallest thing that demonstrates the core idea working start to finish -
one real path through the whole system, nothing extra. Write:
- **Outcome** - one sentence, user-facing ("A user types X and gets Y").
- **End-to-end path** - the actual hops, e.g. frontend input -> backend route -> core
  logic / external call -> response handling -> frontend render. Name each hop concretely.
- **Out of scope for the slice** - the tempting features that are explicitly deferred (auth,
  multiple entity types, polish, edge cases). Be blunt; this list is what stops the team
  building sideways.

## Step 3 - Break into tasks

Produce 6-12 tasks that together deliver the slice:
- Each task is roughly 1-3 hours for one person.
- Prefer tasks that can proceed in parallel; call out the few that block others.
- Give each a suggested owner from `CLAUDE.md` `## Team` or handles the user gives. If
  neither exists, ask how many people are on the team and use owner A / B / C / ...; for a
  solo project, drop owners entirely.
- Give each concrete acceptance criteria (how you know it is done). Write each criterion so
  it can be asserted by an automated test - `test-gate` will reject a ticket whose criteria
  have no test.
- Give each a size: S (<1h), M (1-3h), L (3h+). Split any L task before continuing.
- Note dependencies by task title.
- Mark which tasks are on the critical demo path (these get the `slice` label).
- If `CLAUDE.md` `## Checks` is still empty, include one early S/M task (usually owner D) to
  set up the test runner for each layer, a smoke test for the main path, and fill in
  `## Checks`. Nothing else can pass `test-gate` meaningfully until that lands.

## Step 4 - Write docs/backlog.md

Create or overwrite `docs/backlog.md` with this structure - it holds the narrative, not the
task list (tasks live in GitHub Issues, see Step 5):

    # Backlog

    ## Goal
    <one short paragraph, derived from the brief>

    ## Success criteria
    - <criterion> - <what it rewards / how weighted, if known>

    ## Vertical slice (MVP)
    **Outcome:** <one sentence>
    **End-to-end path:** <hop -> hop -> hop>
    **Out of scope for the slice:** <comma-separated list>

    ## Tasks
    Tracked as GitHub issues. Regenerate this snapshot with `gh issue list --state all`.

    | Issue | Task | Owner | Size | Status |
    |-------|------|-------|------|--------|
    | #1 | <task> | A | M | open |

## Step 5 - Create the GitHub issues

Preconditions - check before creating anything:
- `gh auth status` succeeds and `git remote -v` shows a GitHub `origin`. If not, stop and
  tell the user to run `gh auth login` / add a remote, and offer to keep the task list in
  `docs/backlog.md` as a plain table instead.
- Issues are enabled on the repo (a `gh issue list` that returns without error confirms it).
  If `gh issue create` later fails with "Issues has been disabled", stop and tell the user
  to enable Issues in the repo settings.

First show the user the full task list from Step 3 (title, why, acceptance, size, owner,
critical-path flag) and wait for approval, edits, or cuts. Do not create issues before the
user signs off.

On approval:
1. Create the labels this skill uses, idempotently (`--force` upserts):

       gh label create "size:S" --color 0E8A16 --description "under 1h" --force
       gh label create "size:M" --color FBCA04 --description "1-3h" --force
       gh label create "size:L" --color D93F0B --description "3h+" --force
       gh label create "slice"  --color 1D76DB --description "on the MVP demo path" --force
       gh label create "blocked" --color B60205 --description "waiting on another task" --force
       gh label create "owner:<A|name>" --color 5319E7 --force   # one per owner, if any
2. Create one issue per task. Put the structured fields in the body:

       gh issue create \
         --title "<task title>" \
         --label "size:M" --label "owner:A" [--label "slice"] \
         --body "$(cat <<'EOF'
       **Why:** <ties to the slice or a success criterion>

       **Acceptance:**
       - <criterion>
       - <criterion>

       **Depends on:** <other task titles, or "nothing">
       EOF
       )"

   Run these one at a time so a failure is obvious; collect the returned issue URLs/numbers.
3. Fill the `## Tasks` table in `docs/backlog.md` with the real issue numbers, then save.

## Step 6 - Report

Print: the slice outcome, the critical path (the chain of blocking issues by number), the
list of created issues, and anything the team must decide before starting (stack choice, API
keys, test runners, who owns which layer). Do not implement anything and do not create
branches - this skill only plans.
