## Agent skills

### Issue tracker

GitHub issues via `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Canonical 5-role vocabulary (`needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`). See `docs/agents/triage-labels.md`.

### Domain docs

Single-context (`CONTEXT.md` and `docs/adr/` at repo root). See `docs/agents/domain.md`.

### External worker delegation

When the user asks to delegate implementation, debugging, or review to external agent CLIs, follow `docs/agents/external-agent-orchestration.md`. Keep Codex as the planner and integrator; use isolated worktrees for writers, never store credentials in the repository, and do not run concurrent writers against the same worktree or task scope.
