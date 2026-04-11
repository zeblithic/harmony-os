# Agent Instructions

This project uses **Linear** for issue tracking via the Linear MCP plugin.

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Issue Tracking with Linear

**IMPORTANT**: This project uses **Linear** for ALL issue tracking. Do NOT use markdown TODOs, task lists, or other ad-hoc tracking methods.

Use the Linear MCP plugin tools (e.g., `list_issues`, `save_issue`, `get_issue`, `list_teams`) to interact with Linear.

### Workflow for AI Agents

1. **Check available work**: Use `list_issues` to find open/in-progress issues
2. **View details**: Use `get_issue` for full context on a specific issue
3. **Work on it**: Implement, test, document
4. **Discover new work?** Create a new issue in Linear with `save_issue`
5. **Complete**: Update the issue status in Linear when done

### Important Rules

- Use Linear for ALL task tracking
- Check Linear issues before asking "what should I work on?"
- Do NOT create markdown TODO lists for project tracking
- Do NOT use bd/beads (legacy system, now read-only)

## Code Changes MUST Go Through Pull Requests

**NEVER push code changes directly to main.** All implementation work goes through feature branches and pull requests with code review.

**MANDATORY WORKFLOW for code changes:**

1. **Create a feature branch** before starting work (e.g., `feat/mail-v1-smtp`)
2. **Commit to the branch** — not to main
3. **Push the branch** and create a PR against main
4. **Code review** — PRs are reviewed by automated code review agents. Use the `/review-pr` skill or `pr-review-toolkit` plugin. Do NOT merge without review.
5. **Merge after review passes**

The ONLY exception is trivial documentation/guidance updates (like CLAUDE.md or AGENTS.md edits) — those may go directly to main if the user explicitly approves.

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until your branch is pushed and a PR is created.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues in Linear for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Update Linear issues (close finished work, update in-progress items)
4. **PUSH BRANCH TO REMOTE AND CREATE PR** - This is MANDATORY:
   ```bash
   git push -u origin <your-branch>
   gh pr create --title "..." --body "..."
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed, pushed, and PR created
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- NEVER push directly to main — always use feature branches + PRs
- Work is NOT complete until your branch is pushed and a PR exists
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push the branch
- If push fails, resolve and retry until it succeeds
