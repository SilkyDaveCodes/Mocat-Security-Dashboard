---
name: pm
description: 'Project-manager pass - compares the goal and requirements against what is actually built (git history, branches, and the real source on disk) and proposes ranked tickets for the gaps in the team''s GitHub issue format, verifies the finalized list with a read-only subagent, then opens the passing ones as GitHub issues. Use at phase boundaries - after kickoff planning, after the MVP slice lands, and shortly before a release or demo. Optional input - a focus area or phase note.'
argument-hint: 'focus area or phase, e.g. pre-release or phase:2'
---

Focus / phase note (may be blank):

$ARGUMENTS

## Step 0 - Preconditions

Tasks live in GitHub Issues. Check before doing anything:
- `gh auth status` succeeds and `git remote -v` shows a GitHub `origin`.
- `gh issue list` returns without error (confirms Issues is enabled on the repo).

If either fails, stop and tell the user how to fix it (`gh auth login`, add a remote, or
enable Issues in repo settings). Offer to fall back to a plain task table in
`docs/backlog.md` only if they ask.

Read the goal and requirements:
- `docs/prompt.md` - the brief: core requirements, stretch goals, and how success is
  judged. Treat these as the success criteria.
- `docs/project.md` - the architecture, the phase plan, and the open questions.
- `docs/backlog.md` if it exists - the vertical slice narrative.

If `docs/prompt.md` and `docs/project.md` are both missing, ask the user where the goal and
requirements are written down (or to paste them) before going further.

## Step 1 - Read project status

Gather all of this before forming an opinion:

**Tracker state**
- `gh issue list --state all --limit 100`. Read the bodies of every open issue and every
  issue closed in the last few hours so you know exactly what is tracked and what was just
  finished.
- Note the phase/area labels in use (`phase:1|2|3`, `area:<your areas>`) and which phase is
  currently in progress.

**Git state**
- Read the working branch from `CLAUDE.md` `## Branches`; all in-progress work lives there
  and `main` only holds milestone merges. Judge what is built from the working branch.
- `git fetch`, `git log --oneline -25 origin/<working branch>`, `git branch -a`,
  `git status`, `git diff <working branch> --stat`.
- `git log --oneline origin/main..origin/<working branch>` - work not yet promoted to
  `main`. Note it in the report so the user knows whether a milestone merge is due.
- For each other active branch: `git diff <working branch>..<branch> --stat`.

**The actual codebase - do not skip this, it is the point of the pass**
- For each phase, list the artifacts it is supposed to have produced (from the `## Owns`
  blocks of that phase's issues and the architecture in `docs/project.md`).
- Open those files. Do not just check they exist - read enough to confirm the described work
  is really there and is wired into the main user path. Grep for the key symbols, endpoint
  routes, and call sites. A file that exists but is never called is "built but not
  integrated", not done.
- Check the wiring end to end: does an endpoint actually invoke the logic it's supposed to?
  is the endpoint registered? does the frontend call it? does the output actually reach the
  user?

**Build / test health**
- Run every command in the `CLAUDE.md` `## Checks` table plus the smoke test. Any layer
  still marked "none yet" is a gap - say so explicitly and consider ticketing it.
- Note closed issues that have no tests covering their acceptance criteria - that is drift
  too (done-but-unguarded).

## Step 2 - Compute the gap

Identify, with concrete evidence (file paths, missing symbols, issue numbers) from Step 1:
- **Missing for a requirement** - work a core requirement, stretch goal, or success
  criterion needs that is neither built nor an open issue.
- **Missing for the current phase** - the phase in progress has an artifact or wiring step
  that nothing covers.
- **Drift** - an issue closed as done whose code is absent or not wired in; or an open issue
  whose work is actually finished and should be closed.
- **Built but not integrated** - code on a branch or in isolation that is not on the main
  user path.
- **Unguarded** - main-path behavior with no test, or a layer with no test command.
- **Risk / blocker** - anything that will stop a release or demo (missing API key, broken build,
  failing test, unmerged branch with conflicts, an unresolved item from `docs/project.md`
  "open questions" that now blocks progress).

If the focus note is `pre-demo` or `pre-release`, rank risk/blocker and unguarded items above new features,
and recommend running `/test-gate full` after the resulting fixes land.

## Step 3 - Propose tickets

Present a ranked table - highest impact on the main user path first:

| # | Title | Why (requirement / phase tie-in) | Owns | Size | Phase | Area | Assignee |

- Match the title, label, and body conventions of the existing issues. If there are none
  yet, use the defaults below: title `[P<n>-<AREA>] <short imperative>`.
- Size is S / M / L (<1h / 1-3h / 3h+). Split any L before proposing.
- For assignee, suggest a real GitHub handle taken from `CLAUDE.md` `## Team` (if present), existing issue
  assignees, or recent commit authors; if you cannot map it confidently, put `?` and ask the
  user before Step 5.

Then, for each proposed ticket, render the exact issue body you would post, in the repo's
format (default below):

    **Assignee:** @<handle> · **Size:** <S|M|L> · **Phase:** <n> · **Area:** <area>

    ## Owns
    - `<path>` (new | extend)

    ## Depends on
    - `[P<n>-XX]` <what> - or "nothing"

    ## Work
    <2-4 sentences: what to build and why it closes the gap>

    ## Acceptance
    - [ ] <concrete, checkable criterion - assertable by an automated test>
    - [ ] <concrete, checkable criterion - assertable by an automated test>

    ## Contract N - <name>   (only if this ticket owns a shared schema/interface)
    ```json
    { ... }
    ```

Dedupe explicitly: list any gap you are NOT ticketing because an open issue already covers
it, and name the issue number. Also list any issues you think should be closed or reopened
(drift) and why.

Then STOP. Do not verify, create, or close anything yet. Wait for the user to approve, cut,
or edit the list.

## Step 4 - Verify the finalized list with a subagent

Once the user has approved / edited the list, spawn one subagent with the Agent tool
(`subagent_type: backlog-verifier`, `run_in_background: false` - Step 5 depends on its
verdict). It is a project-defined, read-only agent (`.claude/agents/backlog-verifier.md`);
it cannot create or edit anything.

Give it a fully self-contained prompt (it has no memory of this conversation) containing:
- Every finalized ticket: title, labels, assignee, size, phase/area, and the full rendered
  issue body from Step 3.
- The PM rationale line for each ticket (which requirement or phase gap it fills).
- The full list of drift closes / reopens you are proposing.
- Instruction to independently check each ticket against the real codebase and the open
  issues - confirm the gap is real, not already tracked, not already done, correctly
  formatted, with dependencies that exist and checkable acceptance criteria - and to return a
  PASS/FAIL verdict per ticket plus a check on each drift item.

Wait for its report. Show the user its summary verdict verbatim. Then:
- **PASS tickets** proceed to Step 5.
- **FAIL tickets** do not get created. Show the finding for each. Let the user decide per
  ticket: fix it and re-run Step 4 for that ticket, drop it, or explicitly override the
  verdict. Never post a FAIL ticket without an explicit override in the user's own words.

## Step 5 - Create the approved and verified issues

1. Ensure the labels exist (idempotent, `--force` upserts). Use the team's existing set;
   only add a new `area:` / `phase:` label if a genuinely new one is needed:

       gh label create "size:S" --color 0E8A16 --description "under 1h" --force
       gh label create "size:M" --color FBCA04 --description "1-3h" --force
       gh label create "size:L" --color D93F0B --description "3h+" --force
       gh label create "slice" --color 1D76DB --description "MVP demo path" --force
       gh label create "blocked" --color B60205 --description "waiting on another task" --force

2. Create one issue per passing ticket, one command at a time so failures are obvious:

       gh issue create \
         --title "[P2-BE] <title>" \
         --label "size:M" --label "area:backend" --label "phase:2" [--label "slice"] \
         --assignee "<handle>" \
         --body "$(cat <<'EOF'
       **Assignee:** @<handle> · **Size:** M · **Phase:** 2 · **Area:** backend

       ## Owns
       - `<path>` (new)

       ## Depends on
       - `[P2-XX]` <what>

       ## Work
       <2-4 sentences>

       ## Acceptance
       - [ ] <criterion>
       - [ ] <criterion>
       EOF
       )"

   Collect the returned issue numbers / URLs.
3. For each drift item the user confirmed (and the verifier did not flag as wrong):
   `gh issue close <n> --comment "<reason>"` for finished work, or
   `gh issue reopen <n> --comment "<reason>"` if it was closed but is not actually done.
4. If `docs/backlog.md` exists and has a `## Tasks` snapshot table, refresh it from
   `gh issue list --state all`.

## Step 6 - Report

Print: the created issue numbers / URLs, the verifier's per-ticket verdicts, any issues
closed or reopened, the current `## Checks` health (pass/fail per command), the updated
critical path (blocking issues by number), and which new issues are ready to hand to
`/implement-ticket` now versus which are blocked. Do not implement anything and do not
create branches.

## Rules
- Advisory and approval-gated. Never verify, create, close, or reopen issues without the
  user signing off on the list first.
- The verifier gate is not optional - every ticket that gets posted has passed it or been
  explicitly overridden by the user.
- Run at phase boundaries, not on a timer - running every few minutes just churns the
  tracker.
- Keep issue titles short and imperative; the structured detail goes in the body in the
  format above.
