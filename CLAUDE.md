# Mocat Security Dashboard

## Checks
Single source of truth for "does the project still work". The test-gate and verifiers run
exactly these. An empty entry means that layer is unguarded.

| Layer | Build | Test | Lint/typecheck |
|-------|-------|------|----------------|
| backend | none yet | none yet | none yet |
| frontend | none yet | none yet | none yet |

**Smoke test:** none yet — exercises the main user path end to end.

## Branches
- **Working branch: `dev`.** All work happens here; `main` only receives merges once
  `/test-gate full` returns APPROVE.
