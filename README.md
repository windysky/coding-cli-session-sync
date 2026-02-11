# AI Tool Session Synchronization System

Export and import sessions from multiple AI tools (Claude Code, Codex, OpenCode) across machines via OneDrive synchronization.

## Overview

This system provides command-line tools that allow you to:

1. **Export** sessions (conversation history + configuration) to portable `.tgz` archives
2. **Import** session archives to another machine, restoring sessions and configuration
3. **Multi-session support**: Export/import multiple sessions at once
4. **Selective import**: Choose which sessions to import from multi-session archives

## Supported Tools

- **Claude Code**: Full session support with conversation history and `.claude` directory
- **Codex**: Session support with conversation history and configuration files
- **OpenCode**: Session support with conversation history in JSON format

## Requirements

- Python 3.8+
- WSL2 environment on both machines
- OneDrive with automatic sync enabled
- At least one of the supported AI tools installed

## Installation

Run the setup script:

```bash
git clone https://github.com/windysky/coding-cli-session-sync.git
cd coding-cli-session-sync
./setup.sh
```

The setup script will:
- Install the package in editable mode to `~/.local/bin/`
- Create `session-export`, `session-import`, and `session-cleanup` commands
- Ensure `~/.local/bin` is in your PATH

**Note**: If `~/.local/bin` is not in your PATH, add this to your `~/.bashrc` or `~/.zshrc`:
```bash
export PATH="$HOME/.local/bin:$PATH"
```

Then reload: `source ~/.bashrc`

## Usage

### Exporting Sessions

From the source machine (where the session exists):

```bash
session-export
```

Optional overrides (useful if your tool stores sessions elsewhere):

```bash
# Override tool paths
session-export --tool claude --config-dir ~/.claude --session-dir ~/.claude/session-env
session-export --tool codex --config-dir ~/.codex --session-dir ~/.codex/sessions
```

The script will:
1. Prompt you to select the AI tool (codex, opencode, or claude)
2. Scan the appropriate directory for available sessions
3. Display an interactive menu with session details in a table format
4. Allow you to toggle selection of multiple sessions
5. Create a `.tgz` archive in `~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/`
6. Display the archive location and checksum

**Archive filename formats:**
- Single session: `{TOOL}-session-{SESSION_ID}-{TIMESTAMP}.tgz`
- All sessions: `{TOOL}-sessions-all-{TIMESTAMP}.tgz`
- Selected sessions: `{TOOL}-sessions-{COUNT}-{TIMESTAMP}.tgz`

**Toggle UI**: Enter number to select/deselect, `C` to continue, `Q` to quit

### Importing Sessions

From the target machine (where you want to restore the session):

```bash
session-import
```

Optional overrides:

```bash
# Override archive folder and/or tool paths
session-import --archive-dir ~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!
session-import --config-dir ~/.claude --session-dir ~/.claude/session-env
session-import --config-dir ~/.codex --session-dir ~/.codex/sessions
```

The script will:
1. Scan `~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/` for available `.tgz` archives
2. Display an interactive menu with archive details (tool, size, date, source)
3. For multi-session archives, show which sessions already exist locally (Status column)
4. Auto-select sessions that are NOT available on current machine
5. Allow you to toggle selection before importing
6. Validate archive checksum
7. Extract sessions to the appropriate directories
8. Display confirmation

**Archive list menu commands:**
- Enter number to select archive
- `D {number}` or `D {range}` to delete archives (e.g., `D 1`, `D 1-5`, `D 1,3,5`)
- `Q` to quit

### Deleting Sessions (Destructive)

To delete sessions from the local machine:

```bash
session-cleanup
```

Safe usage examples:

```bash
# Preview what would be deleted
session-cleanup --tool codex --dry-run

# Apply deletion (requires typing DELETE)
session-cleanup --tool claude

# Non-interactive confirmation (dangerous)
session-cleanup --tool opencode --yes
```

## Tool-Specific Details

### Claude Code

- **Session Directory**: `~/.claude/sessions/` and `~/.claude/session-env/`
- **Configuration**: `~/.claude/`
- **Session ID Format**: `sess-XXXXXXXX` (8 characters)

### Codex

- **Session Directory**: `~/.codex/sessions/YYYY/MM/`
- **Configuration**: `~/.codex/config.toml`
- **Session ID Format**: Directory name (variable length)

Note: This project assumes a date-based Codex layout. If you're using `codex-cli 0.98.0` (or another build) and the layout differs, use `--config-dir` / `--session-dir` overrides.

Codex IDs shown in the selection UI are the relative path under `~/.codex/sessions/` (e.g. `2026/02/10`).

Legacy compatibility: older archives may contain leaf-only IDs (e.g. `10`). If that leaf matches multiple sessions on restore, import will fail with an "Ambiguous Codex session id" error. Re-export with a newer version (or select the full relative ID) to resolve.

### OpenCode

- **Session Directory**: `~/.local/share/opencode/storage/session/global/`
- **Configuration**: Not included in archive (machine-specific)
- **Session ID Format**: `ses_XXXXXXXXXX` (variable length, from JSON `id` field)

## Archive Format

Each archive is a gzipped tarfile (`.tgz`) containing:

- **Session data**: Tool-specific conversation history and metadata
- **Configuration** (if applicable): Tool configuration files (excluding auth files)
- **Metadata**: `metadata.json` - Archive information including:
  - Tool type (codex, opencode, claude)
  - Export timestamp
  - Source machine hostname
  - Session details (ID, name, created/modified dates)
  - Archive checksum (SHA-256)
  - File count and size

## Security Considerations

### Important Security Notes

This version includes critical security fixes:

- **BUG-005**: Fixed tuple unpacking bug causing incorrect directory paths
- **Credential Protection**: Auth files are excluded from exports (AUTH-001)
- **Session Existence Check**: Fixed OpenCode session ID extraction from JSON (BUG-004)
- **Thread Safety**: Proper locking for concurrent operations
- **Memory Safety**: File size limits to prevent exhaustion

### General Security

- **No encryption**: Archives are not encrypted (assume trusted OneDrive storage)
- **Credential filtering**: Sensitive credentials are NOT included in archives
  - Excluded: `auth.json`, `token.json`, `credentials.json`, `.token`, `.auth`
  - Excluded: Files containing "token", "auth", "credential", "secret", "api_key"
  - Each machine maintains its own authentication accounts
- **Permission preservation**: File permissions are maintained during export/import
- **Checksum validation**: SHA-256 ensures archive integrity

## Troubleshooting

### Commands Not Found

If `session-export` or `session-import` commands are not found:

```bash
# Check if ~/.local/bin is in PATH
echo $PATH | grep -o ~/.local/bin

# If not, add to ~/.bashrc or ~/.zshrc:
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### OneDrive Sync Issues

If OneDrive doesn't sync automatically:
1. Check OneDrive is running on both machines
2. Verify `~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/` folder exists
3. Manually trigger sync if needed

### Session Shows as "New" When It Exists

This is fixed in version 1.5.0 (BUG-005, BUG-004). Ensure you have the latest version:

```bash
cd /path/to/coding-cli-session-sync
git pull
./setup.sh
```

## Development

### Project Structure

```
coding-cli-session-sync/
├── session_sync/
│   ├── __init__.py          # Package initialization
│   ├── core.py              # Core functionality with multi-tool support
│   ├── file_lock.py         # Thread-safe file locking
│   ├── ui.py                # UI utilities (colors, formatting)
│   ├── utils.py             # Shared utility functions
│   ├── export_session.py    # Export script with tool selection
│   └── import_session.py    # Import script with tool detection
├── tests/                   # Test suite
├── setup.sh                 # Installation script
├── pyproject.toml           # Package configuration
├── CHANGELOG.md             # Version history
└── README.md                # This file
```

### Code Quality

```bash
# Run tests
pytest

# Run with coverage
pytest --cov=session_sync --cov-report=html

# Format code
ruff check session_sync/ tests/ --fix

# Type check
mypy session_sync/
```

## License

MIT License - See LICENSE file for details

## Version History

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

### Recent Releases

- **1.7.0** (2026-02-10): Cleanup Command + Codex ID Fix
  - Added `session-cleanup` for selective deletion with dry-run + confirmations
  - Codex session IDs now show as relative paths (e.g. `2026/02/10`)

- **1.6.0** (2026-02-10): Claude/Codex Robustness
  - Claude new-format uses `~/.claude/session-env` when present
  - Claude selective import/export filters `history.jsonl` by selected `sessionId`s
  - Codex archives preserve `.codex/sessions/YYYY/MM/` structure
  - Added path override flags for unknown layouts

- **1.5.0** (2026-02-07): Package Structure & Bug Fixes
  - Added setup.sh for easy installation to ~/.local/bin
  - Fixed session existence check (BUG-005): tuple unpacking issue
  - Fixed OpenCode session ID extraction (BUG-004): reads from JSON `id` field
  - Moved scripts into session_sync/ package for proper module structure
  - Commands renamed: `session-export` and `session-import`

- **1.4.0** (2026-02-07): UI Enhancements
  - Multi-session archive support with selective import
  - Archive deletion functionality in import menu (D command)
  - Enhanced session selection display with Status column (New/Exists)
  - Auto-selects sessions not available on current machine
  - Improved archive list with timestamps and source hostname
  - Updated sync directory: `~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/`

- **1.3.0** (2026-02-07): UI Improvements
  - Interactive session selection with toggle UI pattern
  - Session existence status display (New/Exists)
  - Professional boxed headers and color-coded output

- **1.2.0** (2026-02-07): Security and Concurrency Fixes
  - Fixed TOCTOU race conditions in lock management
  - Fixed JSON injection vulnerability
  - Thread-safe global history cache
  - File size limits for memory safety
