# External Agent Orchestration

## Purpose

Codex Sol is the project-aware coordinator for PayoutProof: it reads `AGENTS.md`, `CONTEXT.md`, relevant ADRs, the current diff, and the user's requested outcome. External agents are bounded workers for implementation, diagnosis, testing, or review. They do not decide product direction, merge competing changes, or perform Money Actions.

Credentials must stay outside this repository. Use only API keys and accounts you are authorized to use; do not rotate keys to evade provider or account-level limits.

## Division of responsibilities

| Role | Preferred runtime | Writes? | Output |
| --- | --- | --- | --- |
| Coordinator and integrator | Codex Sol | Main worktree only, after review | Task breakdown, acceptance criteria, integration decision |
| Feature implementer | Claude Code using the GLM gateway | Yes, own worktree only | Focused diff, tests run, known limitations |
| Investigator / codebase researcher | Antigravity Flash | No | Evidence with paths, commands, and a recommended next step |
| Debugger | Claude Code or Antigravity Flash | No by default | Reproduction, root-cause hypothesis, minimal fix plan |
| Reviewer | Antigravity Flash or Claude Code | No | Findings only, ordered by severity |

Only one worker may write to a given worktree. Run reviews after the associated implementer stops writing. A group of 4–5 simultaneous workers should therefore be two or three isolated feature worktrees plus one or two read-only investigators—not several agents editing the same branch.

## Worker contract

Sol gives every worker a complete, bounded brief:

1. Read `AGENTS.md`, `CONTEXT.md`, and relevant `docs/adr/` entries before changing code.
2. State one task, a list of allowed files or component boundary, acceptance criteria, and test command.
3. State whether the worker is read-only or may edit its dedicated worktree.
4. Forbid commits, pushes, dependency upgrades, schema migrations, credential access, and network calls unless the task explicitly permits them.
5. Require a concise final report: files changed, commands run and outcomes, risks, and anything not verified.

Sol should not ask a worker to "implement the feature" without a file/component boundary. It should first split independent work, dispatch it, then inspect each diff and test result before it integrates anything.

## Safe concurrency topology

```
                  Codex Sol: plan, route, review, integrate
                         │
      ┌──────────────────┼───────────────────────────────────────┐
      │                  │                                       │
GLM implementer A  GLM implementer B                     Flash investigator
  worktree A          worktree B                             read-only
      │                  │                                       │
      └──────────> read-only reviewers / test reports <──────────┘
                         │
                    Sol merges manually
```

Create the worktree before starting an Antigravity worker, because `agy` has no worktree flag in the installed 1.1.24 CLI. Claude Code 2.1.236 has `--worktree [name]`, but a unique name per worker is still required.

## Claude Code worker recipe

The installed Claude Code supports `-p`, `--model`, `--effort`, `--worktree`, `--permission-mode`, `--allowedTools`, `--disallowedTools`, `--max-turns`, `--output-format`, and `--no-session-persistence`.

Use a new process for every GLM worker. Give each process its own legitimate key via its process environment; an exported key affects only processes started after the export. Do not use `--bare` for project tasks because it disables automatic discovery of repository instructions such as `CLAUDE.md`.

```bash
ANTHROPIC_BASE_URL="$TOKENROUTER_BASE_URL" \
ANTHROPIC_API_KEY="$GLM_KEY_1" \
claude -p "$WORKER_PROMPT" \
  --model 'z-ai/glm-5.3-free' \
  --effort max \
  --worktree worker-feature-a \
  --permission-mode acceptEdits \
  --allowedTools 'Read,Glob,Grep,Edit,Write,Bash(git diff *),Bash(npm test *)' \
  --disallowedTools 'Bash(git commit *),Bash(git push *),Bash(git reset *),Bash(rm *)' \
  --max-turns 20 \
  --output-format json \
  --no-session-persistence
```

`acceptEdits` permits file edits but does not broadly approve shell commands. Keep `Bash` allow rules narrow and task-specific. Never use `--dangerously-skip-permissions` for a worker with network or credential access. For a review-only Claude worker, omit `Edit,Write`, use `--permission-mode plan`, and restrict tools to reading, search, and explicitly approved test commands.

Claude Code may report that the GLM model is unrecognized. That warning concerns its assumed context window; if a response follows, the gateway request succeeded. Set the model with `--model` on every worker regardless of any exported default.

## Antigravity (`agy`) worker recipe

The installed Antigravity CLI supports `-p`, `--model`, `--effort low|medium|high`, `--mode accept-edits|plan`, `--sandbox`, `--output-format json|stream-json`, `--json-schema`, `--print-timeout`, `--conversation`, and `--agent`. Use `agy models` locally to select the exact Gemini Flash slug exposed by the authenticated account.

Run it from an already-created, dedicated worktree when it may edit:

```bash
cd "$WORKTREE_FOR_FEATURE_B"
agy -p "$WORKER_PROMPT" \
  --model "$AGY_FLASH_MODEL" \
  --effort high \
  --mode accept-edits \
  --sandbox \
  --output-format json \
  --print-timeout 15m
```

For investigation and review, use `--mode plan --sandbox`; that makes the worker's intended role read-only. Do not use `--dangerously-skip-permissions` for concurrent workers.

Antigravity also supports asynchronous subagents in an interactive session. Its `invoke_subagent` can use `inherit`, `branch`, or `share` workspace modes. For any writer, select `branch`; use `inherit` only for read-only tasks. Monitor and stop agents through `/agents`, and use `/tasks` for non-agentic background commands.

Project-local custom Antigravity agents belong in `.agents/agents/<name>.md`. Define reviewers with read/search/test tools only, and give write-capable agents `commandExecutionPolicy: sandbox`. Validate each declared tool name before relying on it: current documentation notes that an invalid tool name can hang the subagent.

## Operational loop for Sol

1. Sol reads project context and writes a task brief with acceptance criteria.
2. Sol dispatches only independent tasks, each with a unique worktree and credential process.
3. Workers return JSON or a concise report; Sol checks status, reads the diff, and runs the agreed tests.
4. A separate read-only worker reviews each completed diff when the risk warrants it.
5. Sol decides what to integrate. It never assumes a successful worker response means the change is correct.

## Sources

- [Claude Code CLI reference](https://docs.anthropic.com/en/docs/claude-code/cli-usage)
- [Claude Code LLM gateway configuration](https://docs.anthropic.com/en/docs/claude-code/llm-gateway)
- [Antigravity headless mode](https://antigravity.google/docs/cli/headless/)
- [Antigravity subagents](https://www.agy.dev/docs/subagents/)
- [Antigravity CLI background tasks and subagents](https://www.agy.dev/docs/cli/subagents/)
