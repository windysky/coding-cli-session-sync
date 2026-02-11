"""Utility functions for session synchronization.

This module provides shared utility functions used across
the session_sync package for consistent output formatting.
"""

import sys
from pathlib import Path
from typing import List, Set, Tuple


def print_error(message: str) -> None:
    """Print error message to stderr.

    Args:
        message: Error message to display
    """
    print(f"ERROR: {message}", file=sys.stderr)


def print_success(message: str) -> None:
    """Print success message to stdout.

    Args:
        message: Success message to display
    """
    print(f"SUCCESS: {message}")


def print_info(message: str) -> None:
    """Print info message to stdout.

    Args:
        message: Info message to display
    """
    print(f"INFO: {message}")


def print_warning(message: str) -> None:
    """Print warning message to stdout.

    Args:
        message: Warning message to display
    """
    print(f"WARNING: {message}")


def get_tool_directories(tool: str) -> Tuple[Path, Path]:
    """Get session and config directories for the selected tool.

    Args:
        tool: Tool type (codex, opencode, claude)

    Returns:
        Tuple of (session_dir, config_dir) as Path objects
    """
    home_dir = Path.home()

    if tool == "opencode":
        # OpenCode sessions are in storage/session/global/
        opencode_base = home_dir / ".local" / "share" / "opencode"
        session_dir = opencode_base / "storage" / "session" / "global"
        config_dir = opencode_base
    elif tool == "codex":
        session_dir = home_dir / ".codex" / "sessions"
        config_dir = home_dir / ".codex"
    else:
        # claude (default)
        # For export: session-env directory for session IDs
        # For import: sessions directory
        session_dir = home_dir / ".claude" / "sessions"
        config_dir = home_dir / ".claude"

    return session_dir, config_dir


def parse_session_selection(input_str: str, max_sessions: int) -> List[int]:
    """Parse session selection input.

    Examples:
    - "1" -> [0]
    - "1,3,5" -> [0, 2, 4]
    - "1-5" -> [0, 1, 2, 3, 4]
    - "all" -> all sessions

    Args:
        input_str: User input string
        max_sessions: Maximum number of sessions

    Returns:
        List of selected indices (0-based)
    """
    input_str = input_str.strip().lower()

    if not input_str:
        return []

    if input_str == "all":
        return list(range(max_sessions))

    selected: Set[int] = set()
    parts = input_str.split(",")

    for part in parts:
        part = part.strip()
        if "-" in part:
            # Range: 1-5
            try:
                start, end = part.split("-")
                start_idx = int(start) - 1
                end_idx = int(end)
                # Clamp to valid range
                start_idx = max(0, min(start_idx, max_sessions - 1))
                end_idx = max(0, min(end_idx, max_sessions))
                selected.update(range(start_idx, end_idx))
            except ValueError:
                # Invalid range, skip this part
                continue
        else:
            # Single: 3
            try:
                idx = int(part) - 1
                if 0 <= idx < max_sessions:
                    selected.add(idx)
            except ValueError:
                # Invalid number, skip this part
                continue

    return sorted(selected)
