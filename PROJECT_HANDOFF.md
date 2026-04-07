# PROJECT_HANDOFF.md (authoritative, living)

## 1. Project Overview

- Brief: Export/import AI tool sessions (Claude Code, Codex CLI, OpenCode) as portable `.tgz` archives for syncing via a shared directory (e.g. OneDrive).
- Scope: Local filesystem discovery, archive creation/extraction, session selection UI, and safe deletion via a dedicated cleanup command.
- Last updated: 2026-02-10 23:16 CST
- Last coding CLI used (informational): OpenCode

## 2. Current State

- Session export/import (Claude/Codex/OpenCode): Completed (Completed in Session 2026-02-10 22:13 CST)
- Repo rename alignment (`coding-cli-session-sync`) + URLs: Completed (Completed in Session 2026-02-10 20:35 CST)
- Tooling health (pytest/ruff/mypy): Completed (Completed in Session 2026-02-10 20:35 CST)
- Claude robustness:
  - Prefers `~/.claude/session-env` when present: Completed (Completed in Session 2026-02-10 22:13 CST)
  - Selective import/export filters `history.jsonl` by selected `sessionId`s: Completed (Completed in Session 2026-02-10 22:13 CST)
- Codex robustness:
  - Archives preserve `.codex/sessions/...` layout: Completed (Completed in Session 2026-02-10 22:13 CST)
  - Session IDs are relative paths under `.codex/sessions/` (e.g. `2026/02/10`): Completed (Completed in Session 2026-02-10 22:58 CST)
  - Archive filenames sanitized when session IDs contain `/`: Completed (Completed in Session 2026-02-10 22:58 CST)
- Session deletion:
  - `session-cleanup` (selective, tool-specific, destructive; dry-run + typed confirmation): Completed (Completed in Session 2026-02-10 22:58 CST)
- Packaging/release:
  - Current version: `1.7.0` (Completed in Session 2026-02-10 23:12 CST)
  - Latest commit on `main`: `3e1edb7` (Release v1.7.0)

## 3. Execution Plan Status

- Phase A: Repo rename + docs/URLs alignment
  - Status: Completed
  - Last updated: 2026-02-10 20:35 CST
- Phase B: Tooling + tests stabilized
  - Status: Completed
  - Last updated: 2026-02-10 20:35 CST
- Phase C: Claude/Codex import/export robustness + overrides
  - Status: Completed
  - Last updated: 2026-02-10 22:13 CST
- Phase D: Codex session ID correctness + safe filenames
  - Status: Completed
  - Last updated: 2026-02-10 22:58 CST
- Phase E: Session cleanup command
  - Status: Completed
  - Last updated: 2026-02-10 22:58 CST
- Phase F: Documentation + handoff hygiene
  - Status: Completed
  - Last updated: 2026-02-10 23:16 CST
  - Note: Reformatted `PROJECT_HANDOFF.md` to the required living-state schema

## 4. Outstanding Work

- None

## 5. Risks, Open Questions, and Assumptions

- Codex storage layout differences across versions
  - Status: Open
  - Date opened: 2026-02-10
  - Default assumption: Use `--config-dir` / `--session-dir` overrides when Codex stores sessions differently than `.codex/sessions/...`.

- Codex legacy leaf-only IDs in old archives can be ambiguous
  - Status: Mitigated
  - Date opened: 2026-02-10
  - Default resolution: Import fails fast with an "Ambiguous Codex session id" error; re-export with v1.7.0+ or select full relative IDs to resolve.

- Codex recursive discovery performance on very large trees
  - Status: Mitigated
  - Date opened: 2026-02-10
  - Default assumption: Real-world `.codex/sessions/` hierarchy remains small enough; if not, add pruning/limits and/or caching.

- Destructive deletion via `session-cleanup`
  - Status: Mitigated
  - Date opened: 2026-02-10
  - Default resolution: `--dry-run` support + typed `DELETE` confirmation (or explicit `--yes`).

- Python compatibility vs lint suggestions
  - Status: Mitigated
  - Date opened: 2026-02-10
  - Default assumption: Runtime remains `>=3.8`; avoid 3.10-only syntax in runtime code; ruff ignores `UP045` accordingly.

## 6. Verification Status

- Verified: `pytest`
  - Method: `pytest`
  - Result: PASS
  - Date/time verified: 2026-02-10 23:16 CST

- Verified: `ruff`
  - Method: `ruff check session_sync/ tests/`
  - Result: PASS
  - Date/time verified: 2026-02-10 23:16 CST

- Verified: `mypy`
  - Method: `mypy session_sync/`
  - Result: PASS
  - Date/time verified: 2026-02-10 23:16 CST

## 7. Restart Instructions

- Starting point: read `PROJECT_HANDOFF.md` then the latest entry in `PROJECT_LOG.md`.
- Recommended next actions:
  - Confirm repo clean: `git status -sb`
  - Install/update commands: `./setup.sh`
  - Quick sanity:
    - `pytest`
    - `session-export --tool codex`
    - `session-import`
    - `session-cleanup --tool codex --dry-run`
- Notes:
  - Codex UI IDs are relative paths under `.codex/sessions/` (e.g. `2026/02/10`).
  - If importing an old Codex archive fails due to ambiguity, re-export with v1.7.0+.
- Last updated: 2026-02-10 23:16 CST
