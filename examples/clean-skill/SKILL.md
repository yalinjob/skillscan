---
name: commit-message
description: Writes concise conventional commit messages from a staged diff.
allowed-tools: Bash(git diff:*), Bash(git status:*)
---

# Commit message

1. Run `git diff --staged` to read the changes.
2. Write a subject line under 72 characters in the imperative mood.
3. Add a short body only if the change needs explanation.
