# Claude Code ticket workflow

Skills: `/implement-ticket`, `/test-gate`, `/ticket-study-guide`, `/pm`, `/plan-slice`.
Agents (used by the skills): `test-gate`, `ticket-verifier`, `backlog-verifier`.

## Install into a repo

```bash
cp -R ~/claude-workflow/.claude /path/to/repo/
```

Then add the sections below to the repo's root `CLAUDE.md`. The skills read them; nothing
project-specific lives in the skill files.

## Required in the target repo

- **`gh` CLI** logged in, a GitHub `origin`, and Issues enabled (for `/pm`, `/plan-slice`,
  `/implement-ticket <issue#>`).
- **`CLAUDE.md`** with at least `## Checks` and `## Branches`:

```markdown
## Checks
Single source of truth for "does the project still work". The test-gate and verifiers run
exactly these. An empty entry means that layer is unguarded.

| Layer | Build | Test | Lint/typecheck |
|-------|-------|------|----------------|
| backend | `<cmd>` | `<cmd>` | `<cmd>` |
| frontend | `<cmd>` | `<cmd>` | `<cmd>` |

**Smoke test:** `<cmd>` — exercises the main user path end to end.

## Branches
- **Working branch: `<branch>`.** All work happens here; `main` only receives merges once
  `/test-gate full` returns APPROVE.
```

## Optional (used when present)

- `CLAUDE.md` `## Code principles` — the verifier checks changes against it.
- `CLAUDE.md` `## Team` — GitHub handles for assigning tickets.
- `docs/prompt.md` — the brief / requirements (`/plan-slice`, `/pm`).
- `docs/project.md` — architecture and phase plan (`/pm`).
- `docs/backlog.md` — written by `/plan-slice`.

## Which skill when

- New project from a brief → `/plan-slice` once.
- Build a ticket → `/implement-ticket <issue# or text>` (runs `test-gate` and
  `ticket-study-guide` itself; the guide lands in `docs/study-guides/`).
- Changed code by hand and want a beginner walkthrough of it → `/ticket-study-guide`.
- Changed code by hand, before a commit, after a merge → `/test-gate`.
- Before a release → `/test-gate full`.
- Phase boundary, "what's missing?" → `/pm`.
