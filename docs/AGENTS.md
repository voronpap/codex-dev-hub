# Worker Agents

## Role
Worker agents execute bounded independent subtasks. **Codex remains the main orchestrator.**

Candidate workers include Cursor Agent, OpenHands, local coding agents and future compatible agents.

## Task contract
A worker receives task, scope, relevant Project Brain context, workspace/worktree, permissions, acceptance criteria and tests.

## Execution
Prefer isolated worktrees/containers so multiple workers cannot corrupt one working directory. Main-branch writes are denied by default.

## Handoff
Return structured status, concise summary, changed files, test results, decisions, warnings and artifact/diff references. Do not inject full transcripts into Codex context.

## When to delegate
Good: independent implementation slice, repetitive change, parallel investigation, bounded test generation.

Bad: tiny change, task tightly coupled to Codex's current reasoning, unclear scope, or delegation overhead greater than the work.

## Paid agents
Cursor/other subscription or paid workers are resources with quota/budget policy, not default execution targets.
