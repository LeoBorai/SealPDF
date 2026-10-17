---
name: reviewable-chunks
description: Implement a task in small, reviewable code chunks. After each chunk, test it, commit it on a new task branch using Conventional Commits, and stop for explicit user confirmation before rebasing onto main and continuing.
---

# Reviewable Chunks

Complete the user's task in small, independently reviewable increments. After each increment, commit the work and end your turn so the user can review it. Continue only after the user explicitly confirms.

## Start

1. Read the task and identify a sensible sequence of independently reviewable chunks. Each chunk should deliver a coherent, useful change—not merely a mechanical slice of a larger change.
2. Inspect the repository instructions, current branch, working tree, and recent commit style. Do not overwrite, discard, or include unrelated user changes.
3. Use `main` as the default integration branch. If the user specifies a different default branch, use that instead.
4. Before editing, check whether the working tree has changes. If pre-existing changes could be affected or mixed into the task's commit, preserve them and ask the user how to proceed; do not commit them.
5. Create a new task branch before making task changes. Use a descriptive name such as `feat/task-summary` or `fix/task-summary`. Do not reuse or overwrite an existing branch. If the branch name is already taken, choose another.
6. Do not switch branches if doing so would risk losing or carrying along unrelated working-tree changes.

## Implement one chunk

For the current chunk:

1. Make only the changes needed for that chunk.
2. Run relevant tests, checks, or builds. Fix failures caused by your changes; report pre-existing or unrelated failures accurately.
3. Review the diff for correctness, scope, accidental changes, and exposed secrets. Do not stage unrelated files.
4. Stage only the files for this chunk.
5. Create a commit with a Conventional Commit message:
   - Format: `<type>(optional-scope): <imperative summary>`
   - Use an appropriate type, such as `feat`, `fix`, `refactor`, `test`, `docs`, `build`, or `chore`.
   - Include a brief commit body that elaborates on the chunk’s contents: summarize what was added, changed, or fixed, rather than repeating the subject line.
   - Add a breaking-change footer when applicable.
   - Do not amend existing commits.
6. Report the chunk, commit hash and message, checks run and their results, and the next planned chunk.
7. **Stop. End your turn here and wait.** Do not start another chunk, rebase, push, or make further changes until the user explicitly confirms they want you to continue.

## After confirmation

Treat an unambiguous response such as “confirmed,” “continue,” or “looks good, proceed” as approval for the next chunk. Questions, review comments, or requests for changes are not approval to proceed unchanged.

1. If the user requests revisions, make only the requested revisions, rerun relevant checks, and create a new Conventional Commit on the task branch. Then report it and stop for confirmation again.
2. Before starting the next chunk, fetch the latest remote state if a remote is configured, then rebase the task branch onto the latest available `main` (or the user-specified default branch). If no remote is configured, rebase onto the local default branch.
3. Never force-push or reset to discard work. If the rebase conflicts, stop, explain the conflict, and ask how the user wants to proceed. Do not silently resolve ambiguous conflicts.
4. After a successful rebase, continue with the next planned chunk and follow **Implement one chunk**. Commit and stop for confirmation again.
5. If all chunks are complete, perform a final relevant check and report completion. Do not create an extra commit unless there are uncommitted task changes.

## Git safety

- Do not push unless the user explicitly asks.
- Do not use destructive commands such as `git reset --hard`, `git clean`, or force-push.
- Do not commit secrets, generated artifacts, or unrelated user changes.
- If the repository has no `main` branch and no user-specified default branch, stop and ask which branch to use.
