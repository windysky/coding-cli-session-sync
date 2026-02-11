# PROJECT_LOG (append-only)

Authoritative current state: `PROJECT_HANDOFF.md`.

Do not edit past entries; append new sessions at the end.

## Session 2026-02-10 20:00 CST

- Inventory-only session: identified repo rename alignment work and placeholder repo URLs.

## Session 2026-02-10 20:35 CST

- Fixed tooling/test breakage after scripts moved into `session_sync/`.
- Added repo-root wrappers `export_session.py` and `import_session.py` for backward compatibility.
- Updated docs/URLs for `coding-cli-session-sync`.

## Session 2026-02-10 20:40 CST

- Final verification + handoff update (no functional code changes).

## Session 2026-02-10 21:26 CST

- Updated git remote `origin` to `https://github.com/windysky/coding-cli-session-sync.git`.
- Updated `.gitignore` to ignore local/untracked repo artifacts: `.claude/`, `.mcp.json`, `CLAUDE.md`, `fixtures/`.
- Updated `pyproject.toml` for distribution metadata (author/email) and removed stdlib `pathlib` dependency.
- Added `LICENSE` (MIT).
- Created `PROJECT_LOG.md`.

## Session 2026-02-10 21:44 CST

- Reviewed Claude Code and Codex CLI export/import readiness.
- Identified likely path/layout mismatches for Claude new-format sessions and multi-session archive import logic.
- Outlined recommended next fixes/tests (not yet implemented).

## Session 2026-02-10 21:48 CST

- Deep-dive review notes (not implemented):
  - Claude new-format discovery/import appears miswired via `session_sync/utils.py:get_tool_directories()` returning `~/.claude/sessions` (likely should involve `~/.claude/session-env` and/or base `~/.claude`).
  - Claude selective import likely not honored because export/import use global `history.jsonl` (may bring more sessions than selected).
  - Codex export/import path handling appears fragile: export drops the year component; import has a hard-coded year prefix check (`"2026"`) before falling back.
  - Codex multi-session archive selection UI exists, but import path appears to handle only one extracted session directory in the non-"session-*" structure.

## Session 2026-02-10 22:13 CST

- Implemented Claude fixes:
  - `get_tool_directories()` now prefers `~/.claude/session-env` when present.
  - Claude selective import is enforced by filtering `history.jsonl` on import (allowlist by selected sessionIds).
  - Claude exports filter `history.jsonl` to only selected sessionIds.
- Implemented Codex fixes:
  - Codex export now preserves paths under `.codex/sessions/YYYY/MM/<session>/...`.
  - Codex import installs from extracted `.codex/sessions/...` and preserves the same YYYY/MM structure.
  - Removed hard-coded year assumptions in the primary import path.
- Added path override flags:
  - `session-export`: `--config-dir`, `--session-dir`
  - `session-import`: `--archive-dir`, `--config-dir`, `--session-dir`
- Added tests:
  - Claude history filtering and import allowlist
  - Codex archive path prefix and install behavior
- Updated docs:
  - `README.md` now documents override flags and Codex layout caveat (`codex-cli 0.98.0`).

## Session 2026-02-10 22:17 CST

- Bumped version to `1.6.0`.
- Added release notes for `1.6.0` in `CHANGELOG.md` and `README.md`.
