# PROJECT HANDOFF / STATE DOCUMENT

## 1. Project Overview

- Purpose: Export/import AI tool sessions (Claude Code, Codex, OpenCode) as portable `.tgz` archives so they can be synced across machines via OneDrive.
- Tech stack/tools: Python package (`session_sync`), `pyproject.toml` (setuptools), CLI entrypoints (`session-export`, `session-import`), tests via `pytest`, lint/format via `ruff`, type checks via `mypy`, installer script `setup.sh`.
- Architecture / mental model:
  - CLI entrypoints are defined in `pyproject.toml` under `[project.scripts]`.
  - `session_sync/export_session.py` implements the interactive export flow (tool selection, session discovery, archive creation).
  - `session_sync/import_session.py` implements the interactive import flow (archive discovery, validation, selective import, extraction).
  - `session_sync/core.py` contains shared logic (discover sessions/archives, create/extract archives, checksum, disk space checks, credential filtering, etc.).
  - `session_sync/ui.py` provides terminal UI helpers (tables, headers, prompts).
  - `session_sync/file_lock.py` provides thread-safe file locking to avoid TOCTOU/race issues.

## 2. Current State (living section — update as needed)

- Completed and stable functionality:
  - Export/import for Claude Code, Codex, and OpenCode (see `README.md`).
  - Multi-session archives + selective import.
  - Checksum validation and credential filtering.
  - Setup/install via `setup.sh` which installs `session-export`, `session-import`, and `session-cleanup`.
  - Backward-compatible repo-root wrappers: `export_session.py` and `import_session.py`.
  - Quality gates currently pass: `pytest`, `ruff check session_sync/ tests/`, `mypy session_sync/`.
  - Distribution metadata cleanup: `LICENSE` added; `pyproject.toml` author/email updated; stdlib-only dependency removed.
  - Local repo hygiene: `.gitignore` updated to ignore local artifacts; `origin` remote updated to renamed GitHub repo.
  - Claude/Codex robustness: Claude uses `session-env` when present; Codex sessions preserved under `.codex/sessions/YYYY/MM/`; path override flags added.
  - Codex session IDs now use the relative path under `.codex/sessions/` (e.g. `2026/02/10`), and archive filenames are sanitized when IDs contain path separators.
  - Session deletion: `session-cleanup` command added (selective, tool-specific, destructive).
- Partially implemented features:
  - None.
- Not started items:
  - None.

## 3. Session Log (append-only)

### Session 2026-02-10 20:00 CST

- Goals for the session:
  - Assess the codebase and identify what needs updating after renaming the repository directory to `coding-cli-session-sync` and renaming the GitHub repo.
- What was implemented or changed:
  - No code/doc changes applied in this session (analysis + inventory only).
- Files/modules/functions touched (read/inspected):
  - `README.md`
  - `pyproject.toml`
  - `CHANGELOG.md`
  - `setup.sh`
  - `session_sync/export_session.py`
  - `session_sync/import_session.py`
- Key technical decisions:
  - Keep Python package/module name `session_sync` unchanged; only update references that are specifically about the *repo directory name* and *GitHub URLs*.
- Problems encountered and how they were addressed:
  - Local git remote `origin` still points at `https://github.com/windysky/codex_session_sync.git` (needs updating to the renamed repo URL).
  - Docs contain a mix of references where `session_sync` means “repo folder” vs “python package”; updates must avoid breaking import/package references.

### Session 2026-02-10 20:35 CST

- Goals for the session:
  - Fix broken tests/tooling after script moves into `session_sync/`.
  - Align docs/scripts with repo rename to `coding-cli-session-sync` and update GitHub URLs.
- What was implemented or changed:
  - Added backward-compatible repo-root modules: `export_session.py` and `import_session.py` (delegate to `session_sync.*`).
  - Fixed `pyproject.toml` ruff config so `ruff check` runs; applied ruff autofixes; cleaned up remaining lint issues.
  - Fixed mypy config + type issues so `mypy session_sync/` passes (kept runtime compatibility for Python 3.8 by removing `set[int]` usage).
  - Updated tests to match current interactive flows and updated return type of `display_archive_menu()`.
  - Updated repo rename references + placeholder URLs in docs/config.
  - Updated version reporting: `session_sync/__init__.py` and `session_sync/export_session.py --version` now reflect `1.5.0`.
- Files/modules/functions touched:
  - `export_session.py`
  - `import_session.py`
  - `README.md`
  - `pyproject.toml`
  - `CHANGELOG.md`
  - `session_sync/__init__.py`
  - `session_sync/core.py`
  - `session_sync/export_session.py`
  - `session_sync/import_session.py`
  - `session_sync/file_lock.py`
  - `session_sync/utils.py`
  - `tests/test_export.py`
  - `tests/test_import.py`
  - `tests/test_tool_support.py`
- Key technical decisions:
  - Keep the Python package/module name `session_sync` unchanged; only update repo-folder and GitHub URL references.
  - Keep declared runtime support `>=3.8`, but set `[tool.mypy] python_version = "3.9"` because current mypy no longer supports analyzing as 3.8.
  - Preserve interactive UX; adjust tests to provide multi-step `input()` sequences instead of changing runtime behavior.
- Problems encountered and how they were addressed:
  - `pytest` hung in interactive-menu tests because `input()` was mocked with a single return value; fixed by switching tests to `side_effect` sequences.
  - Import tests were stale after moving scripts into the package; fixed via repo-root wrappers.

### Session Update 2026-02-10 20:40 CST

- Goals for the session:
  - Final verification + handoff update.
- What was implemented or changed:
  - No additional code changes beyond the fixes already recorded in the 20:35 CST session entry.
- Files/modules/functions touched:
  - `PROJECT_STATE.md`
- Key technical decisions:
  - None.
- Problems encountered and how they were addressed:
  - None.

### Session Update 2026-02-10 21:26 CST

- Goals for the session:
  - Complete remaining tasks from Section 4 (remote URL alignment, ignore local artifacts, distribution polish).
- What was implemented or changed:
  - Updated `origin` remote to `https://github.com/windysky/coding-cli-session-sync.git`.
  - Updated `.gitignore` to ignore `.claude/`, `.mcp.json`, `CLAUDE.md`, and `fixtures/`.
  - Updated `pyproject.toml` authors and removed stdlib `pathlib` dependency.
  - Added `LICENSE` (MIT).
  - Created `PROJECT_LOG.md`.
- Files/modules/functions touched:
  - `.gitignore`
  - `pyproject.toml`
  - `LICENSE`
  - `PROJECT_LOG.md`
  - `PROJECT_HANDOFF.md`
- Key technical decisions:
  - Used `windysky@users.noreply.github.com` as a default author email for packaging metadata.
- Problems encountered and how they were addressed:
  - Noted that an earlier log entry referenced `PROJECT_STATE.md`; this project now treats `PROJECT_HANDOFF.md` as authoritative.

### Session Update 2026-02-10 22:13 CST

- Goals for the session:
  - Make Claude Code and Codex behavior clearer and more robust; add overrides for unknown Codex layouts (`codex-cli 0.98.0`).
- What was implemented or changed:
  - Claude: `get_tool_directories()` now prefers `~/.claude/session-env` when present.
  - Claude: selective import/export now filters `history.jsonl` by selected `sessionId`s.
  - Codex: archive now preserves `.codex/sessions/YYYY/MM/<session>/...` and import restores the same structure.
  - Added CLI overrides:
    - `session-export`: `--config-dir`, `--session-dir`
    - `session-import`: `--archive-dir`, `--config-dir`, `--session-dir`
  - Added tests covering Claude filtering and Codex path preservation.
  - Updated `README.md` with override examples and Codex layout caveat.
- Files/modules/functions touched:
  - `session_sync/utils.py`
  - `session_sync/core.py`
  - `session_sync/export_session.py`
  - `session_sync/import_session.py`
  - `README.md`
  - `tests/test_tool_support.py`
  - `tests/test_claude_selective.py`
  - `tests/test_codex_paths.py`
  - `PROJECT_LOG.md`
  - `PROJECT_HANDOFF.md`
- Key technical decisions:
  - Treat Codex sessions/config as `.codex/`-rooted in archives to make import unambiguous.
  - Keep a safe escape hatch for unknown layouts via CLI overrides.
- Problems encountered and how they were addressed:
  - `ruff` docstring checks required minimal docstrings for new public functions and new tests.

### Session Update 2026-02-10 22:17 CST

- Goals for the session:
  - Cut a minor release for the Claude/Codex robustness work.
- What was implemented or changed:
  - Version bumped to `1.6.0`.
  - Release notes added/updated in `CHANGELOG.md` and `README.md`.
- Files/modules/functions touched:
  - `session_sync/__init__.py`
  - `pyproject.toml`
  - `CHANGELOG.md`
  - `README.md`
  - `PROJECT_LOG.md`
  - `PROJECT_HANDOFF.md`
- Key technical decisions:
  - Minor version bump for behavior changes in Claude/Codex handling.
- Problems encountered and how they were addressed:
  - None.

### Session Update 2026-02-10 23:12 CST

- Goals for the session:
  - Address remaining follow-ups (handoff staleness, setup output, Python runtime compatibility, Codex doc clarity) and cut a minor release.
- What was implemented or changed:
  - `PROJECT_HANDOFF.md` refreshed: outstanding tasks cleaned up; risks updated.
  - `setup.sh` now prints `session-cleanup` as an installed command.
  - `session-cleanup` kept compatible with Python `>=3.8` (removed `X | None` syntax).
  - Codex legacy-ID ambiguity documented in `README.md`.
  - Version bumped to `1.7.0` and release notes updated.
- Files/modules/functions touched:
  - `PROJECT_HANDOFF.md`
  - `PROJECT_LOG.md`
  - `setup.sh`
  - `session_sync/cleanup_session.py`
  - `README.md`
  - `CHANGELOG.md`
  - `session_sync/__init__.py`
  - `pyproject.toml`
- Key technical decisions:
  - Keep runtime `requires-python` at `>=3.8`; avoid Python 3.10-only syntax in runtime modules.
- Problems encountered and how they were addressed:
  - None.

## 4. Outstanding Tasks (living section — update as needed)

Prioritized next steps:

- None.

## 5. Open Questions & Risks (living section — update as needed)

- Confirm the canonical GitHub repo URL (now set for `origin`, and used in `README.md`, `pyproject.toml`, `CHANGELOG.md`).
- Packaging metadata: author/email defaults were set; adjust if you want a different attribution.
- Python compatibility: runtime remains `>=3.8`, but mypy analysis runs as 3.9.
- Codex legacy IDs: importing older archives that contain leaf-only IDs may fail if ambiguous; re-export with a newer version to resolve.

## 6. Restart Instructions (living section — update as needed)

Where to start next:

1. Check the current repo state:
   - `git status --porcelain=v1`
   - `git remote -v`

2. Verify the main quality gates (they should already pass):
   - `python -m compileall session_sync`
   - `pytest`
   - `ruff check session_sync/ tests/`
   - `mypy session_sync/`

3. If you want to align the local remote with the renamed GitHub repo:
   - `git remote set-url origin https://github.com/windysky/coding-cli-session-sync.git`

4. If preparing a release:
   - Review diffs (ruff autofix + mypy fixes) and then commit.
