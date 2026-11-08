---
name: ticket-study-guide
description: Writes a short beginner-friendly study guide for a code change to docs/study-guides/. Explains what each changed piece does and why in plain words, with a Mermaid map of which files changed and how they connect. Called by implement-ticket at the end of every ticket (run in a cheaper subagent); also use on its own after changing code by hand.
argument-hint: '[issue number or short title] [optional commit range, e.g. HEAD~2..HEAD]'
---

Arguments (may be blank):

$ARGUMENTS

The reader is a beginner: someone who knows what a file and a website are but may never have
read code. Explain terms in plain words the first time they appear. **Keep it short**: aim for
about 150–250 lines in total. The point is understanding, not a transcript of the code.

## Step 1 - Find the change

- If the arguments include a commit range, use `git diff <range>`. Otherwise use the
  uncommitted work (`git diff HEAD`, plus `git status` for new untracked files). If there is
  no uncommitted work, use the last commit (`git show HEAD`).
- If that is empty, tell the user there is nothing to explain and stop.
- **Ticket:** if the arguments contain an issue number, read it with `gh issue view <n>`. If
  the caller supplied the *why* (ticket goal, design choices, verifier findings, gate
  verdict), use it. Otherwise describe the change from the diff and write `**Ticket:** none`.
- Read the changed files. Skim (don't read in full) the unchanged files they import or are
  called by, just enough to place them as grey boxes in the map.

## Step 2 - Write the guide

Save it to `docs/study-guides/<issue#>-<short-kebab-title>.md`, or
`docs/study-guides/<YYYY-MM-DD>-<short-kebab-title>.md` when there is no issue. Create the
folder if needed. Use this structure, in this order:

    # Study guide: <ticket title in plain words>

    **Ticket:** #<n> · **Date:** <YYYY-MM-DD> · **Gate:** <APPROVE | BLOCK | not run>

    ## The big picture
    <1-2 short paragraphs: what was different before, what it does now, and one everyday
    analogy.>

    ## Map of the changes
    <Mermaid flowchart, see the rules below>
    **How to read it:** <one-line legend>

    ## File by file
    <one ### section per changed file, in the order things happen at runtime, tests last>

    ## How you know it works
    <3-5 bullets: what the test groups prove, plus the gate's numbers>

    ## Try it yourself
    <2-4 numbered steps, including the exact `CLAUDE.md` ## Checks command that runs just
    these tests>

    ## Open questions / risks
    <short bullets: limits, verifier findings; on a BLOCK, every blocking item from the gate>

### The map

- `flowchart LR`, one box per file, labelled with its path plus a `<br/>` list of what
  changed inside it, using `+` added, `~` changed, `-` removed.
- Group boxes with `subgraph` by layer.
- Colour with these classes, always included:

      classDef new fill:#d4f8d4,stroke:#2a7a2a,color:#000
      classDef changed fill:#fff3c4,stroke:#a07800,color:#000
      classDef removed fill:#f8d4d4,stroke:#a02a2a,color:#000,stroke-dasharray:4 3
      classDef untouched fill:#eee,stroke:#999,color:#000

- Label every arrow with what flows along it. Thick `==>` for connections this change added,
  thin `-->` for existing ones. Include the unchanged files it plugs into, as `untouched`.

### Each file section

    ### `<path>` - new | changed | removed (test)

    **What it's for:** <one sentence>
    **What changed and why:** <one or two sentences tied to the ticket>

    <then, for each main piece (function, class, config block): a bold name, ONE short code
    excerpt of the key lines (not the whole thing), and 2-4 sentences in plain words on what
    it does and why. Explain an unusual piece of syntax in a few words when it first appears.>

Rules for the content:
- Cover every changed file and every main piece, but **don't walk through code line by
  line** and don't add a glossary section. Group small edits together.
- Quote only short excerpts; say "(shortened)" when you trim.
- Use one concrete worked example where the logic is mathematical or tricky.
- For test files: describe the fake data in one or two sentences, then list the tests grouped
  by acceptance criterion, one short line per group (not per test).
- Don't invent behavior. If you're unsure why something was written a certain way, say so
  under Open questions instead of guessing.

## Step 3 - Report

Return only the path to the guide and a one-line summary. Do not commit it unless the user
asks. `implement-ticket` reports it as part of its own summary.
