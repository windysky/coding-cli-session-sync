# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] - 2026-02-10

### Added
- `--config-dir` / `--session-dir` overrides for `session-export`
- `--archive-dir` / `--config-dir` / `--session-dir` overrides for `session-import`

### Fixed
- Claude new-format directory wiring now prefers `~/.claude/session-env` when present
- Claude selective import/export now filters `history.jsonl` by selected `sessionId`s
- Codex export/import now preserves date-based session hierarchy under `.codex/sessions/YYYY/MM/`

### Changed
- Codex archives now store session data under a `.codex/` root to make restores unambiguous

## [1.5.0] - 2026-02-07

### Added
- **SETUP-001**: Added setup.sh script for easy installation
  - Uses `pip install -e . --user` for editable package installation
  - Installs `session-export` and `session-import` commands to ~/.local/bin/
  - Package structure reorganized: scripts moved into session_sync/ package
  - Package name standardized to `session_sync` (was `session-sync`)

### Fixed
- **BUG-005**: Fixed tuple unpacking for `get_tool_directories()` return value
  - Root cause: Function returns `(session_dir, config_dir)` but code was unpacking as `_, session_dir`
  - This caused `session_dir` to receive the value of `config_dir` (wrong directory)
  - Fixed in `select_sessions_from_archive()` and `check_any_session_exists()` functions
  - Sessions exported from the same computer now correctly show as "Exists" instead of "New"

### Changed
- Moved `export_session.py` and `import_session.py` into `session_sync/` package directory
- Entry point commands: `session-export` and `session-import` (without .py extension)

## [1.4.0] - 2026-02-07

### Added
- **UI-004**: Multi-session archive support in import menu
  - Displays session count for each archive
  - Shows which sessions from multi-session archives already exist locally
  - Selective session import from multi-session archives
  - Toggle selection UI for choosing individual sessions
- **UI-005**: Archive deletion functionality in import menu
  - Delete individual archives with 'D' command
  - Supports batch deletion (e.g., D 1,3,5)
  - Supports range deletion (e.g., D 1-5)
  - Confirmation prompt before deletion
- **UI-006**: Improved session existence detection
  - Properly checks all sessions in multi-session archives
  - Displays accurate status for each archive
  - Fixed detection for Claude, OpenCode, and Codex sessions
- **UI-007**: Enhanced session selection display with Status column
  - Shows session details (Name, ID, Modified, Status) in table format
  - Recycles export script UI pattern for consistency
  - Status column shows "New" (green) or "Exists" (yellow) for each session
  - Auto-selects sessions that are NOT available on current machine (smart default)
  - Users can toggle selections from the pre-populated state
- **UI-008**: Improved archive list with timestamps
  - Removed Status column from archive list (didn't make sense at archive level)
  - Added Date column showing archive file modification time
  - Source hostname shown separately
- **DIR-002**: Updated sync directory name for visibility
  - New directory: `~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/`
  - Exclamation marks make the directory more prominent and prevent accidental deletion
- **SETUP-001**: Added setup.sh script for easy installation
  - Uses `pip install -e .` for editable package installation
  - Installs `session-export` and `session-import` commands to system PATH
  - Moved export_session.py and import_session.py into session_sync/ package for proper module structure
  - Package name changed from `session-sync` to `session_sync` to match module name

### Fixed
- **BUG-001**: Archive discovery pattern now matches both "session" and "sessions"
  - Multi-session archives use plural "sessions" in filename
  - Previous pattern only matched singular "session"
  - Now correctly discovers all archive formats
- **BUG-002**: Session details extraction from archives
  - Added `get_session_details_from_archive()` function
  - Extracts session names from OpenCode session JSON files
  - Shows meaningful names instead of just session IDs
  - Extracts actual session timestamps from session data (not archive time)
- **UI-004**: Multi-session archive support in import menu
  - Displays session count for each archive
  - Shows which sessions from multi-session archives already exist locally
  - Selective session import from multi-session archives
  - Toggle selection UI for choosing individual sessions
- **UI-005**: Archive deletion functionality in import menu
  - Delete individual archives with 'D' command
  - Supports batch deletion (e.g., D 1,3,5)
  - Supports range deletion (e.g., D 1-5)
  - Confirmation prompt before deletion
- **UI-006**: Improved session existence detection
  - Properly checks all sessions in multi-session archives
  - Displays accurate status for each archive
  - Fixed detection for Claude, OpenCode, and Codex sessions
- **UI-009**: Single-session archives now show session selection display
  - Previously, single-session archives only showed a simple confirmation prompt
  - Now all archives show the full session selection table with Status column
  - Allows users to see session details and toggle selection even for single sessions
- **BUG-003**: Fixed OpenCode session existence check path
  - Corrected path for checking if OpenCode sessions exist locally
  - Fixed path was checking `session_dir / f"{session_id}.json"` (correct) instead of adding extra directories
- **BUG-004**: Fixed OpenCode session ID extraction from archives
  - Root cause: Session ID was extracted from filename (ses_*.json) instead of JSON's `id` field
  - Import script now correctly reads session ID from JSON's `id` field (matching export behavior)
  - The actual OpenCode session ID is stored in the JSON's `id` field, not the filename
- **BUG-005**: Fixed tuple unpacking for `get_tool_directories()` return value
  - Root cause: Function returns `(session_dir, config_dir)` but code was unpacking as `_, session_dir`
  - This caused `session_dir` to receive the value of `config_dir` (wrong directory)
  - Fixed in `select_sessions_from_archive()` and `check_any_session_exists()` functions
  - Now correctly checks session existence in the proper directory path
- **DIR-002**: Updated sync directory name for visibility
  - New directory: `~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/`
  - Exclamation marks make the directory more prominent and prevent accidental deletion

### Changed
- Import menu now returns tuple of (archive, selected_session_ids)
- Updated `check_session_exists()` to use `check_any_session_exists()` for better multi-session support
- Added `get_archive_sessions_info()` to extract session information from archive metadata
- Archive deletion removes archives from the list after successful deletion

## [1.3.0] - 2026-02-07

### Added
- **UI-001**: Interactive session selection menu with toggle UI pattern
  - Checkbox column showing selected state [✓] / [ ]
  - Enter number to toggle selection on/off
  - Press C or Enter to continue with selection
  - Press Q to quit operation
- **UI-002**: Session existence status display in import menu
  - New "Status" column showing whether session exists locally
  - "New" (green) - session doesn't exist on this machine
  - "Exists" (yellow) - session already present on this machine
  - Helps users avoid import conflicts and decide whether to skip or overwrite
- **UI-003**: Enhanced visual design with boxed headers and color-coded output
  - Professional boxed headers with Unicode box-drawing characters
  - Color-coded tool types and status indicators
  - Improved table layout with proper column alignment
- **DIR-001**: Changed default sync location to reduce Desktop clutter
  - New default: `~/OneDrive/Desktop/Current/SyncSessionDoNotDelete/`
  - Previous default: `~/OneDrive/Desktop/`
  - Organizes session archives in a dedicated subdirectory

### Security
- **AUTH-001**: Fixed credential exposure in archives
  - Excluded auth.json and other auth-related files from Codex exports
  - Added filtering for Claude config directory to exclude tokens and credentials
  - Added _is_auth_file() function with comprehensive auth file pattern detection
  - Each machine now maintains its own authentication credentials

## [1.2.0] - 2026-02-07

### Added
- **CONC-001**: Thread-safe global history cache with threading.Lock protection
- **HIGH-003**: File size limits (100MB default) to prevent memory exhaustion
- **MED-003**: Monotonic time tracking for lock timeout measurements
- **TYPE-002**: None check for tarfile.fileobj before type checking
- **DRY-001**: Refactored duplicate archive creation code into shared helper

### Security
- **CRIT-001**: Fixed TOCTOU race condition in stale lock detection
  - Eliminated time-of-check-to-time-of-use vulnerability in lock file validation
  - Added atomic lock acquisition with proper error handling
- **CRIT-003**: Fixed JSON injection vulnerability in merge_claude_history
  - Added input validation for JSON data before merging
  - Prevented potential code execution through malicious JSON payloads
- **CONC-003**: Fixed TOCTOU race condition in merge_claude_history
  - Added proper file locking during history merge operations
  - Prevented race conditions in concurrent read-modify-write cycles
- **AUTH-001**: Fixed credential exposure in archives
  - Excluded auth.json and other auth-related files from Codex exports
  - Added filtering for Claude config directory to exclude tokens and credentials
  - Added _is_auth_file() function with comprehensive auth file pattern detection
  - Each machine now maintains its own authentication credentials

### Changed
- Enhanced thread safety across all concurrent operations
- Improved error handling for corrupted archive files
- Better timeout handling with monotonic time sources

### Fixed
- Thread safety issues in global state management
- Type checking errors when tarfile.fileobj is None
- Memory exhaustion potential with unlimited file sizes
- Race conditions in lock file management

### Security Notes
This release includes critical security fixes addressing:
- Time-of-check-to-time-of-use (TOCTOU) race conditions
- JSON injection vulnerabilities
- Concurrent access issues
- Memory exhaustion prevention

Users are encouraged to upgrade immediately due to the critical security fixes.

## [1.1.0] - 2026-02-07

### Added
- Multi-tool support for Codex and OpenCode sessions
- Tool selection menu in export script
- Automatic tool detection in import script
- Enhanced metadata with tool type field
- 59 tests with 92% code coverage

### Changed
- Updated archive naming convention with tool prefix
- Improved session handling for multiple AI tools

## [1.0.0] - 2025-02-07

### Added
- Initial release of session synchronization system
- Claude Code export and import functionality
- Interactive menu system
- Checksum validation
- File permission preservation
- Comprehensive test coverage

## Security Issue References

- **AUTH-001**: Credential exposure in archives (auth files now excluded)
- **CRIT-001**: TOCTOU race condition in stale lock detection
- **CRIT-003**: JSON injection vulnerability in merge_claude_history
- **CONC-001**: Thread-safety for global history cache
- **CONC-003**: TOCTOU race condition in merge_claude_history
- **TYPE-002**: None check for tarfile.fileobj
- **MED-003**: Monotonic time for lock timeouts
- **HIGH-003**: File size limits for memory safety
- **DRY-001**: Archive creation code refactoring

## Links

- [Repository](https://github.com/windysky/coding-cli-session-sync)
- [Issue Tracker](https://github.com/windysky/coding-cli-session-sync/issues)
- [Documentation](https://github.com/windysky/coding-cli-session-sync#readme)
