---
name: ticket-study-guide
description: Writes a beginner-friendly study guide for a code change to docs/study-guides/. Explains every edit and its syntax line by line in plain words, with a glossary and a Mermaid map of which files changed and how they connect. Called by implement-ticket at the end of every ticket; also use on its own after changing code by hand.
argument-hint: '[issue number or short title] [optional commit range, e.g. HEAD~2..HEAD]'
---

Arguments (may be blank):

$ARGUMENTS

The reader is a beginner: someone who knows what a file and a website are but may never have
read code. Every term gets explained the first time it appears. Nothing is assumed.

## Step 1 - Find the change

- If the arguments include a commit range, use `git diff <range>`. Otherwise use the
  uncommitted work (`git diff HEAD`, plus `git status` for new untracked files, which you read
  in full). If there is no uncommitted work, use the last commit (`git show HEAD`).
- If that is empty, tell the user there is nothing to explain and stop.
- **Ticket:** if the arguments contain an issue number, read it with `gh issue view <n>`. If
  this skill was called from `implement-ticket`, use the ticket, the developer's report, the
  verifier's findings and the test-gate verdict already in the conversation. Otherwise describe
  the change from the diff and write `**Ticket:** none`.
- Read each changed file in full, not just the diff hunks, so you can explain what the file is
  for. Also read the unchanged files the changed code imports or is called by. They become the
  grey boxes in the map.

## Step 2 - Write the guide

Save it to `docs/study-guides/<issue#>-<short-kebab-title>.md`, or
`docs/study-guides/<YYYY-MM-DD>-<short-kebab-title>.md` when there is no issue. Create the
folder if needed. Use this structure, in this order:

    # Study guide: <ticket title in plain words>

    **Ticket:** #<n> · **Date:** <YYYY-MM-DD> · **Gate:** <APPROVE | BLOCK | not run>

    ## The big picture
    <2 short paragraphs: what the app does in this area, what was different before, what it
    does now. Then one everyday analogy ("it's like the Sort by menu on a shopping app").>

    ## Map of the changes
    <Mermaid flowchart, see the rules below>
    **How to read it:** <legend: colours, + / ~ / - marks, thick vs thin arrows>

    ## Words you'll see
    | Word | What it means here |
    <every technical term the guide uses, explained in one plain sentence each>

    ## File by file
    <one ### section per changed file, in the order things happen at runtime, tests last>

    ## How you know it works
    <bullets: which tests exist and what each group proves, in plain words>

    ## Try it yourself
    <numbered steps: what to open or run, what you should see; include the exact command
    from `CLAUDE.md` ## Checks that runs just these tests>

    ## Open questions / risks
    <limits, things left out of the ticket, verifier findings; on a BLOCK, every blocking
    item from the gate>

### The map

- `flowchart LR`, one box per file, labelled with its path plus a `<br/>` list of what
  changed inside it, using `+` added, `~` changed, `-` removed.
- Group boxes with `subgraph` by layer (e.g. what you see / the server / tests).
- Colour with these classes, always included:

      classDef new fill:#d4f8d4,stroke:#2a7a2a,color:#000
      classDef changed fill:#fff3c4,stroke:#a07800,color:#000
      classDef removed fill:#f8d4d4,stroke:#a02a2a,color:#000,stroke-dasharray:4 3
      classDef untouched fill:#eee,stroke:#999,color:#000

- Label every arrow with what flows along it, in plain words. Use thick arrows `==>` for
  connections this change added and thin `-->` for ones that already existed.
- Include the unchanged files the change depends on, as `untouched`, so the reader sees where
  the new code plugs in.

### Each file section

    ### `<path>` - new | changed | removed (test)

    **What this file is for:** <one sentence>
    **What changed and why:** <one or two sentences tied to the ticket>

    #### Piece N - <short name>      (new files)
    #### Edit N - <short name>       (changed files)

    <code block: the real code; a ```diff block for edits to existing files>

    **In plain words:** <what the piece does, no jargon>

    **Line by line:**
    1. <each line or syntax element: what every symbol means — keywords, brackets, operators,
       `=>`, `?:`, `...`, `||`, types, JSX — with a tiny concrete example where it helps>

    **Why it's written this way:** <the design reason, or what would break otherwise>

Rules for the content:
- Cover **every** edit in the diff. Group small related edits into one piece, but don't skip
  any. If a long line is split for readability, say so.
- Quote the real code. Shorten only repetitive parts, and say "(shortened)" when you do.
- Explain syntax the first time it appears. Later, a short reminder ("the short if/else
  again") is enough.
- Use concrete values when explaining logic, e.g. "0.9 - 0.5 = 0.4, positive, so b goes first".
- For test files, explain what fake data is used and what each `expect` checks. Then list
  every test in one sentence each rather than walking through all of them line by line.
- Don't invent behavior. If you're unsure why something was written a certain way, say so
  under Open questions instead of guessing.

## Step 3 - Report

Give the path to the guide and a one-line summary of what it covers. Do not commit it unless
the user asks. `implement-ticket` reports it as part of its own summary.
