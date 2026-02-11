#!/usr/bin/env python3
"""Import AI tool session from portable archive.

This script imports sessions from various AI tools (codex, opencode, claude)
from .tgz archives created by the export script.
"""

import argparse
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Configure security audit logging
security_logger = logging.getLogger("session_sync.security")
security_logger.setLevel(logging.WARNING)

# Security constants
MAX_LINE_LENGTH = 10 * 1024  # 10KB maximum line length
SESSION_ID_PATTERN = re.compile(
    r"^[a-zA-Z0-9\-_]+$"
)  # Alphanumeric, hyphens, underscores
MAX_SESSION_ID_LENGTH = 256

# Graceful import error handling
try:
    from session_sync.core import (
        Archive,
        check_disk_space,
        discover_archives,
        discover_sessions,
        ensure_directory,
        extract_archive,
    )
    from session_sync.file_lock import FileLock
    from session_sync.ui import (
        Colors,
        clear_screen,
        format_size,
        print_box_header,
        print_error,
        print_header,
        print_info,
        print_section,
        print_separator,
        print_success,
        print_warning,
    )
    from session_sync.utils import (
        get_tool_directories,
    )
except ImportError as e:
    print("=" * 60)
    print("ERROR: session_sync module not found!")
    print("=" * 60)
    print()
    print("This usually means the package is not installed or you are")
    print("running from a different Python environment than where it was installed.")
    print()
    print("SOLUTIONS:")
    print()
    print("1. Install the package:")
    print("   cd /path/to/coding-cli-session-sync")
    print("   ./setup.sh")
    print()
    print("2. If using conda, make sure you're in the right environment:")
    print("   conda activate YOUR_ENV_NAME")
    print("   session-import")
    print()
    print("3. If installed, check your PATH includes ~/.local/bin:")
    print("   echo $PATH | grep local/bin")
    print()
    print("4. Try running with the Python interpreter directly:")
    print("   python -m session_sync.import_session")
    print()
    print(f"Import error details: {e}")
    print("=" * 60)
    sys.exit(1)


def validate_session_id(session_id: Any, source_file: str, line_number: int) -> bool:
    """Validate session ID meets security requirements.

    Args:
        session_id: The session ID to validate
        source_file: File path for logging
        line_number: Line number for logging

    Returns:
        True if valid, False otherwise
    """
    if session_id is None:
        return False

    if not isinstance(session_id, str):
        security_logger.warning(
            f"Invalid session ID type in {source_file}:{line_number}: "
            f"expected str, got {type(session_id).__name__}"
        )
        return False

    if len(session_id) > MAX_SESSION_ID_LENGTH:
        security_logger.warning(
            f"Session ID too long in {source_file}:{line_number}: "
            f"{len(session_id)} chars (max {MAX_SESSION_ID_LENGTH})"
        )
        return False

    if not SESSION_ID_PATTERN.match(session_id):
        security_logger.warning(
            f"Invalid session ID characters in {source_file}:{line_number}: "
            f"{session_id[:50]}{'...' if len(session_id) > 50 else ''}"
        )
        return False

    return True


def validate_json_line_size(line: str, source_file: str, line_number: int) -> bool:
    """Validate JSON line size to prevent memory exhaustion.

    Args:
        line: The line to validate
        source_file: File path for logging
        line_number: Line number for logging

    Returns:
        True if valid, False otherwise
    """
    if len(line) > MAX_LINE_LENGTH:
        security_logger.warning(
            f"Line exceeds maximum length in {source_file}:{line_number}: "
            f"{len(line)} chars (max {MAX_LINE_LENGTH})"
        )
        return False
    return True


def validate_session_json_schema(
    data: Dict[str, Any], source_file: str, line_number: int
) -> bool:
    """Validate JSON schema for session data.

    Args:
        data: Parsed JSON data
        source_file: File path for logging
        line_number: Line number for logging

    Returns:
        True if valid, False otherwise
    """

    # Check for suspicious nested structures (potential injection) FIRST
    # This prevents stack overflow attacks regardless of sessionId presence
    def check_depth(obj: Any, current_depth: int = 0, max_depth: int = 10) -> bool:
        """Recursively check nesting depth to prevent stack overflow."""
        if current_depth > max_depth:
            return False
        if isinstance(obj, dict):
            return all(
                check_depth(v, current_depth + 1, max_depth) for v in obj.values()
            )
        elif isinstance(obj, list):
            return all(check_depth(item, current_depth + 1, max_depth) for item in obj)
        return True

    if not check_depth(data):
        security_logger.warning(
            f"Excessive nesting depth in {source_file}:{line_number}"
        )
        return False

    # Check for required sessionId field
    if "sessionId" not in data:
        # sessionId is optional for some entries
        return True

    # Validate sessionId format
    if not validate_session_id(data["sessionId"], source_file, line_number):
        return False

    return True


class BackupManager:
    """Manage backup creation and cleanup for session imports."""

    DEFAULT_BACKUP_RETENTION_DAYS = 7

    def __init__(
        self, backup_dir: Optional[Path] = None, retention_days: Optional[int] = None
    ):
        """Initialize backup manager.

        Args:
            backup_dir: Custom backup directory (defaults to ~/.claude/session_sync/backups)
            retention_days: Backup retention period in days (defaults to 7)
        """
        if backup_dir is None:
            backup_dir = Path.home() / ".claude" / "session_sync" / "backups"
        self.backup_dir = Path(backup_dir)
        self.retention_days = retention_days or self.DEFAULT_BACKUP_RETENTION_DAYS

    def create_backup(self, source_path: Path, session_id: str) -> Optional[Path]:
        """Create a backup of the specified directory or file.

        Args:
            source_path: Path to back up
            session_id: Session identifier for backup naming

        Returns:
            Path to backup directory, or None if source doesn't exist
        """
        if not source_path.exists():
            return None

        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Create backup with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{session_id}.bak-{timestamp}"
        backup_path = self.backup_dir / backup_name

        print_info(f"Creating backup: {backup_path}")

        try:
            if source_path.is_dir():
                shutil.copytree(source_path, backup_path)
            else:
                backup_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, backup_path)

            print_success(f"Backup created: {backup_path}")
            return backup_path
        except Exception as e:
            print_error(f"Failed to create backup: {e}")
            return None

    def restore_backup(self, backup_path: Path, target_path: Path) -> bool:
        """Restore from backup.

        Args:
            backup_path: Path to backup
            target_path: Where to restore

        Returns:
            True if restore succeeded
        """
        if not backup_path.exists():
            print_error(f"Backup not found: {backup_path}")
            return False

        print_info(f"Restoring from backup: {backup_path}")

        try:
            # Remove target if it exists
            if target_path.exists():
                if target_path.is_dir():
                    shutil.rmtree(target_path)
                else:
                    target_path.unlink()

            # Restore backup
            if backup_path.is_dir():
                shutil.copytree(backup_path, target_path)
            else:
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(backup_path, target_path)

            print_success(f"Restored: {target_path}")
            return True
        except Exception as e:
            print_error(f"Failed to restore backup: {e}")
            return False

    def cleanup_backup(self, backup_path: Path) -> bool:
        """Remove a backup directory.

        Args:
            backup_path: Path to backup to remove

        Returns:
            True if cleanup succeeded
        """
        if not backup_path.exists():
            return True

        try:
            if backup_path.is_dir():
                shutil.rmtree(backup_path)
            else:
                backup_path.unlink()
            print_info(f"Backup cleaned up: {backup_path}")
            return True
        except Exception as e:
            print_warning(f"Failed to cleanup backup: {e}")
            return False

    def cleanup_old_backups(self, keep_backups: bool = False) -> int:
        """Remove backups older than retention period.

        Args:
            keep_backups: If True, skip cleanup

        Returns:
            Number of backups cleaned up
        """
        if keep_backups:
            print_info("Keeping backups (cleanup disabled)")
            return 0

        cutoff_time = datetime.now() - timedelta(days=self.retention_days)
        cleaned = 0

        print_info(f"Cleaning up backups older than {self.retention_days} days...")

        try:
            for backup in self.backup_dir.glob("*.bak-*"):
                # Extract timestamp from backup name
                try:
                    # Format: session_id.bak-YYYYMMDD_HHMMSS
                    timestamp_str = backup.name.split(".bak-")[-1]
                    backup_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")

                    if backup_time < cutoff_time:
                        if self.cleanup_backup(backup):
                            cleaned += 1
                except (ValueError, IndexError):
                    # Skip backups with invalid timestamp format
                    continue

            if cleaned > 0:
                print_success(f"Cleaned up {cleaned} old backup(s)")
            else:
                print_info("No old backups to clean up")

        except Exception as e:
            print_warning(f"Error during backup cleanup: {e}")

        return cleaned


def display_archive_menu(
    archives: List[Archive],
) -> Optional[Tuple[Archive, List[str]]]:
    """Display interactive menu for archive selection with improved UI.

    Returns:
        Tuple of (selected_archive, selected_session_ids) or None if cancelled
        selected_session_ids is empty list for single-session full import,
        or contains specific session IDs for selective import from multi-session archives.
    """
    if not archives:
        print_error("No archives found to import")
        return None

    while True:
        clear_screen()

        # Print boxed header
        print_box_header("Session Import", "Select: 1-N | D=delete | Q=quit")

        print_section("AVAILABLE ARCHIVES")
        print_separator()

        # Calculate column widths
        num_width = len(str(len(archives)))
        name_width = 30
        tool_width = 6
        size_width = 8
        count_width = 6
        date_width = 16

        # Print table header
        print(
            f"  {Colors.BOLD}{'No':>{num_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Name':<{name_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Tool':<{tool_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Size':>{size_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Count':>{count_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Date':<{date_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Source':<{12}}{Colors.RESET}"
        )
        print_separator()

        # Print table rows
        for i, archive in enumerate(archives, 1):
            metadata = archive.load_metadata()
            if metadata:
                tool_label = metadata.session.tool.upper()[:tool_width]
                name_display = metadata.session.name[:name_width].ljust(name_width)
                size_display = format_size(archive.size_bytes).rjust(size_width)
                source_display = metadata.source_hostname[:12].ljust(12)

                # Get archive file modification time
                mtime = datetime.fromtimestamp(archive.archive_path.stat().st_mtime)
                date_display = mtime.strftime("%Y-%m-%d %H:%M").ljust(date_width)

                # Get session count
                session_count, session_ids, tool = get_archive_sessions_info(archive)

                # Show session count
                count_display = str(session_count).rjust(count_width)
                if session_count > 1:
                    count_display = f"{Colors.CYAN}{count_display}{Colors.RESET}"

                # Color code by tool type
                tool_color = Colors.GREEN if tool_label.startswith("C") else Colors.CYAN

                print(
                    f"  {Colors.BOLD}{i:>{num_width}}{Colors.RESET}  "
                    f"{name_display}  "
                    f"{tool_color}{tool_label:<{tool_width}}{Colors.RESET}  "
                    f"{size_display}  "
                    f"{count_display}  "
                    f"{date_display}  "
                    f"{source_display}"
                )
            else:
                name_display = archive.archive_path.name[:name_width].ljust(name_width)
                size_display = format_size(archive.size_bytes).rjust(size_width)
                mtime = datetime.fromtimestamp(archive.archive_path.stat().st_mtime)
                date_display = mtime.strftime("%Y-%m-%d %H:%M").ljust(date_width)
                print(
                    f"  {Colors.BOLD}{i:>{num_width}}{Colors.RESET}  "
                    f"{Colors.YELLOW}{name_display}{Colors.RESET}  "
                    f"{'?':<{tool_width}}  "
                    f"{size_display}  "
                    f"{'?':>{count_width}}  "
                    f"{date_display}  "
                    f"{'?':<{12}}"
                )

        print_separator()
        print(
            f"{Colors.CYAN}D{Colors.RESET} - Delete selected archives (e.g., D 1,3,5)"
        )
        print(f"{Colors.CYAN}Q{Colors.RESET} - Quit")

        # Get user input
        try:
            choice = input(
                f"\n{Colors.BOLD}Select archive (1-{len(archives)}), D to delete, Q to quit:{Colors.RESET} "
            ).strip()

            # Check for quit
            if choice.upper() == "Q":
                print_warning("\nImport cancelled")
                return None

            # Check for delete command
            if choice.upper().startswith("D"):
                # Parse indices to delete (e.g., "D 1,3,5" or "D1,3,5")
                indices_str = choice[1:].strip()
                if indices_str:
                    try:
                        # Parse comma-separated list
                        indices_to_delete: List[int] = []
                        for part in indices_str.split(","):
                            part = part.strip()
                            if "-" in part:
                                # Range support (e.g., 1-5)
                                start, end = part.split("-")
                                indices_to_delete.extend(
                                    range(int(start) - 1, int(end))
                                )
                            else:
                                indices_to_delete.append(int(part) - 1)
                        # Confirm deletion
                        print(
                            f"\n{Colors.YELLOW}About to delete {len(indices_to_delete)} archive(s):{Colors.RESET}"
                        )
                        for idx in indices_to_delete:
                            if 0 <= idx < len(archives):
                                print(f"  - {archives[idx].archive_path.name}")
                        confirm = (
                            input(
                                f"\n{Colors.BOLD}Confirm deletion? (y/N):{Colors.RESET} "
                            )
                            .strip()
                            .lower()
                        )
                        if confirm == "y":
                            deleted = delete_archives(archives, indices_to_delete)
                            print_success(f"Deleted {deleted} archive(s)")
                            # Remove deleted archives from list
                            archives = [
                                a
                                for i, a in enumerate(archives)
                                if i not in indices_to_delete
                            ]
                            if not archives:
                                print_info("No more archives available")
                                return None
                            input("\nPress Enter to continue...")
                        else:
                            print_info("Deletion cancelled")
                            input("Press Enter to continue...")
                    except ValueError:
                        print_error("Invalid format. Use: D 1,3,5 or D 1-5")
                        input("Press Enter to continue...")
                continue

            # Validate and parse selection
            try:
                index = int(choice) - 1
                if 0 <= index < len(archives):
                    selected_archive = archives[index]
                    metadata = selected_archive.load_metadata()

                    print_header(f"\n{Colors.GREEN}Selected Archive:")
                    if metadata:
                        # Get session info
                        session_count, session_ids, tool = get_archive_sessions_info(
                            selected_archive
                        )

                        print(f"  Name: {metadata.session.name}")
                        print(f"  Tool: {metadata.session.tool.upper()}")
                        print(f"  Source: {metadata.source_hostname}")
                        print(f"  Size: {format_size(selected_archive.size_bytes)}")

                        if session_count > 1:
                            print(f"  Sessions: {session_count}")

                        # Show session status
                        any_exists = check_any_session_exists(selected_archive)
                        if any_exists:
                            print(
                                f"  {Colors.YELLOW}Status: Some sessions already exist locally{Colors.RESET}"
                            )
                        else:
                            print(
                                f"  {Colors.GREEN}Status: All sessions are new{Colors.RESET}"
                            )

                        # Always show session selection menu (even for single sessions)
                        selected_session_ids = select_sessions_from_archive(
                            selected_archive, session_ids, tool
                        )
                        if not selected_session_ids:
                            print_info("Session selection cancelled")
                            input("Press Enter to continue...")
                            continue

                        print_success(
                            f"Importing {len(selected_session_ids)} selected session(s)"
                        )

                        # Final confirmation before import
                        confirm = (
                            input(
                                f"\n{Colors.BOLD}Proceed with importing {len(selected_session_ids)} session(s)? (y/N):{Colors.RESET} "
                            )
                            .strip()
                            .lower()
                        )
                        if confirm == "y":
                            return (selected_archive, selected_session_ids)
                        else:
                            print_info("Import cancelled")
                            input("Press Enter to continue...")
                            continue
                    else:
                        print(f"  File: {selected_archive.archive_path.name}")
                        confirm = (
                            input("\nProceed with import? (y/N): ").strip().lower()
                        )
                        if confirm == "y":
                            return (selected_archive, [])
                else:
                    print_error(
                        f"Invalid selection. Please enter a number between 1 and {len(archives)}"
                    )
                    input("Press Enter to continue...")
            except ValueError:
                print_error("Please enter a valid number")
                input("Press Enter to continue...")

        except (EOFError, KeyboardInterrupt):
            print_warning("\nImport cancelled")
            return None


def select_sessions_from_archive(
    archive: Archive, session_ids: List[str], tool: str
) -> List[str]:
    """Display menu for selecting individual sessions from a multi-session archive.

    Shows session details in a table format similar to the export script.
    Auto-selects sessions that don't exist locally.

    Args:
        archive: The archive object
        session_ids: List of session IDs in the archive
        tool: Tool type (claude, opencode, codex)

    Returns:
        List of selected session IDs, or empty list if cancelled
    """
    # Get detailed session information
    session_details = get_session_details_from_archive(archive)

    # If we couldn't get details, fall back to basic IDs
    if not session_details:
        session_details = [
            {
                "session_id": sid,
                "name": sid,
                "last_modified": datetime.now(),
                "size_bytes": 0,
            }
            for sid in session_ids
        ]

    # Get tool directories for existence check
    try:
        session_dir, config_dir = get_tool_directories(tool)
    except (ValueError, OSError):
        session_dir = None
        config_dir = None

    existing_codex_ids: Set[str] = set()
    if tool == "codex" and session_dir is not None and session_dir.exists():
        try:
            existing_codex_ids = {
                s.session_id
                for s in discover_sessions(
                    session_dir, tool="codex", max_sessions=200000
                )
            }
        except Exception:
            existing_codex_ids = set()

    # Pre-check which sessions exist locally and auto-select new ones
    session_exists = []
    for session in session_details:
        session_id_str = session["session_id"]
        exists_locally = False
        if tool == "claude" and config_dir is not None:
            old_session = config_dir / "sessions" / session_id_str
            new_session = config_dir / "session-env" / session_id_str
            exists_locally = old_session.exists() or new_session.exists()
        elif session_dir:
            if tool == "claude":
                old_session = session_dir.parent / "sessions" / session_id_str
                new_session = session_dir.parent / "session-env" / session_id_str
                exists_locally = old_session.exists() or new_session.exists()
            elif tool == "opencode":
                # OpenCode stores sessions directly as {session_id}.json in session_dir
                # session_dir is ~/.local/share/opencode/storage/session/global/
                session_path = session_dir / f"{session_id_str}.json"
                exists_locally = session_path.exists()
            elif tool == "codex":
                exists_locally = session_id_str in existing_codex_ids
        session_exists.append(exists_locally)

    # Auto-select sessions that DON'T exist locally (smart default)
    selected_indices: Set[int] = set()
    for i, exists in enumerate(session_exists):
        if not exists:
            selected_indices.add(i)

    while True:
        clear_screen()
        print_box_header(
            "Select Sessions to Import", "Toggle: number | C=continue | Q=quit"
        )
        print_section("SESSIONS IN ARCHIVE")
        print_separator()

        # Calculate column widths
        num_width = len(str(len(session_details)))
        name_width = 42
        id_width = 18
        modified_width = 16
        status_width = 10
        select_width = 8

        # Print table header
        print(
            f"  {Colors.BOLD}{'No':>{num_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Name':<{name_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'ID':<{id_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Modified':<{modified_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Status':<{status_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Select':>{select_width}}{Colors.RESET}"
        )
        print_separator()

        # Print session rows
        for i, session in enumerate(session_details, 1):
            idx = i - 1
            is_selected = idx in selected_indices
            exists_locally = session_exists[idx]

            session_name = session.get("name", session["session_id"])
            session_id_str = session["session_id"]

            # Format name (no color coding - we have Status column now)
            name_display = session_name[:name_width].ljust(name_width)

            # Truncate ID if too long
            id_display = (
                (session_id_str[:id_width] + "..")
                if len(session_id_str) > id_width
                else session_id_str
            )
            id_display = id_display.ljust(id_width)

            # Format modified time - use the session's actual timestamp
            last_modified = session.get("last_modified")
            if last_modified:
                if isinstance(last_modified, str):
                    try:
                        last_modified = datetime.fromisoformat(last_modified)
                    except ValueError:
                        last_modified = datetime.now()
                modified_display = last_modified.strftime("%Y-%m-%d %H:%M")[
                    :modified_width
                ].ljust(modified_width)
            else:
                modified_display = "Unknown".ljust(modified_width)

            # Status column: New (green) or Exists (yellow)
            if exists_locally:
                status_display = f"{Colors.YELLOW}Exists{Colors.RESET}".ljust(
                    status_width
                )
            else:
                status_display = f"{Colors.GREEN}New{Colors.RESET}".ljust(status_width)

            # Checkbox
            if is_selected:
                checkbox = f"{Colors.GREEN}[✓]{Colors.RESET}"
            else:
                checkbox = f"{Colors.CYAN}[ ]{Colors.RESET}"

            print(
                f"  {Colors.BOLD}{i:>{num_width}}{Colors.RESET}  "
                f"{name_display}  "
                f"{Colors.CYAN}{id_display}{Colors.RESET}  "
                f"{modified_display}  "
                f"{status_display}  "
                f"{checkbox}"
            )

        print_separator()

        # Show selection count and legend
        selected_count = len(selected_indices)
        if selected_count > 0:
            print(
                f"\n{Colors.GREEN}Selected: {selected_count}/{len(session_details)} sessions{Colors.RESET}"
            )
        else:
            print(
                f"\n{Colors.CYAN}Selected: 0/{len(session_details)} sessions{Colors.RESET}"
            )

        print(
            f"{Colors.GREEN}Green 'New' = Auto-selected (not on this machine){Colors.RESET}"
        )
        print(f"{Colors.YELLOW}Yellow 'Exists' = Already on this machine{Colors.RESET}")

        # Get user input
        try:
            choice = input(
                f"\n{Colors.BOLD}Toggle selection (1-{len(session_details)}, C=continue, Q=quit):{Colors.RESET} "
            ).strip()

            # Check for quit
            if choice.upper() == "Q":
                return []

            # Check for continue
            if not choice or choice.upper() == "C":
                if not selected_indices:
                    print_warning(
                        "No sessions selected. Please select at least one session or press Q to quit."
                    )
                    input("Press Enter to continue...")
                    continue
                return [
                    session_details[i]["session_id"] for i in sorted(selected_indices)
                ]

            # Parse as number to toggle
            try:
                num = int(choice)
                if 1 <= num <= len(session_details):
                    idx = num - 1
                    if idx in selected_indices:
                        selected_indices.remove(idx)
                    else:
                        selected_indices.add(idx)
                else:
                    print_error(
                        f"Please enter a number between 1 and {len(session_details)}"
                    )
                    input("Press Enter to continue...")
            except ValueError:
                print_error(
                    "Invalid input. Enter a number, C to continue, or Q to quit."
                )
                input("Press Enter to continue...")

        except (EOFError, KeyboardInterrupt):
            return []


def check_session_conflict(session_id: str, session_dir: Path) -> bool:
    """Check if session already exists.

    Args:
        session_id: Session ID to check
        session_dir: Sessions directory

    Returns:
        True if conflict exists
    """
    existing_session = session_dir / session_id
    return existing_session.exists()


def get_archive_sessions_info(archive: "Archive") -> Tuple[int, List[str], str]:
    """Get session information from an archive's metadata.

    For multi-session archives, returns all session IDs.
    For single-session archives, returns the single session ID.

    Args:
        archive: Archive object

    Returns:
        Tuple of (session_count, session_ids, tool)
    """
    metadata = archive.load_metadata()
    if not metadata:
        return 0, [], "unknown"

    # Try to load the full metadata dict to check for multi-session info
    try:
        import tarfile

        with tarfile.open(archive.archive_path, "r:gz") as tar:
            member = tar.getmember("metadata.json")
            file = tar.extractfile(member)
            if file:
                import os
                import tempfile

                fd, tmp_path_str = tempfile.mkstemp(suffix=".json", text=True)
                tmp_path = Path(tmp_path_str)
                try:
                    os.chmod(fd, 0o600)
                    with os.fdopen(fd, "w") as f:
                        f.write(file.read().decode("utf-8"))
                    with open(tmp_path) as f:
                        metadata_dict = json.load(f)
                    session_count = metadata_dict.get("session_count", 1)
                    all_session_ids = metadata_dict.get(
                        "all_session_ids", [metadata_dict.get("session", {}).get("id")]
                    )
                    tool = metadata_dict.get("session", {}).get("tool", "claude")
                    return session_count, all_session_ids, tool
                finally:
                    if tmp_path.exists():
                        tmp_path.unlink()
    except Exception:
        pass

    # Fallback to single session
    return 1, [metadata.session.session_id], metadata.session.tool


def get_session_details_from_archive(archive: "Archive") -> List[Dict[str, Any]]:
    """Extract detailed session information from an archive.

    Returns list of session dicts with keys: session_id, name, last_modified, size_bytes

    Args:
        archive: Archive object

    Returns:
        List of session detail dictionaries
    """
    sessions: List[Dict[str, Any]] = []
    metadata = archive.load_metadata()
    if not metadata:
        return sessions

    tool = metadata.session.tool
    _session_count, session_ids, _ = get_archive_sessions_info(archive)

    try:
        import tarfile

        with tarfile.open(archive.archive_path, "r:gz") as tar:
            if tool == "opencode":
                # For OpenCode, find all session JSON files in the archive
                for member in tar.getmembers():
                    name = member.name
                    # Look for session files at root level (ses_*.json)
                    if (
                        name.startswith("ses_")
                        and name.endswith(".json")
                        and name.count("/") == 0
                    ):
                        try:
                            file = tar.extractfile(member)
                            if file:
                                content = file.read().decode("utf-8")
                                session_data = json.loads(content)
                                # CRITICAL: Get session ID from JSON 'id' field, not filename
                                # The filename is ses_*.json but the actual session ID is in the JSON's 'id' field
                                # This must match what discover_sessions() does in core.py line 619
                                session_id = session_data.get(
                                    "id", name.replace(".json", "")
                                )
                                # Get the actual timestamp from session data
                                # Try multiple fields for the timestamp
                                timestamp_str = (
                                    session_data.get("updatedAt")
                                    or session_data.get("createdAt")
                                    or session_data.get("timestamp")
                                )
                                if timestamp_str:
                                    try:
                                        # Parse ISO format timestamp
                                        if timestamp_str.endswith("Z"):
                                            timestamp_str = (
                                                timestamp_str[:-1] + "+00:00"
                                            )
                                        last_modified = datetime.fromisoformat(
                                            timestamp_str
                                        )
                                    except ValueError:
                                        last_modified = datetime.fromtimestamp(
                                            member.mtime
                                        )
                                else:
                                    last_modified = datetime.fromtimestamp(member.mtime)

                                sessions.append(
                                    {
                                        "session_id": session_id,
                                        "name": session_data.get("title", session_id),
                                        "last_modified": last_modified,
                                        "size_bytes": member.size,
                                    }
                                )
                        except (json.JSONDecodeError, KeyError, ValueError):
                            # If we can't parse, use minimal info
                            session_id = name.replace(".json", "")
                            sessions.append(
                                {
                                    "session_id": session_id,
                                    "name": session_id,
                                    "last_modified": datetime.fromtimestamp(
                                        member.mtime
                                    ),
                                    "size_bytes": member.size,
                                }
                            )

            elif tool == "claude":
                # For Claude, sessions are in session-{id}/ directories
                # or .claude/session-env/{id}/ directories
                session_dirs = set()
                for member in tar.getmembers():
                    name = member.name
                    # Check for session directories
                    if name.startswith("session-") and "/" in name:
                        # Extract session ID from path like session-{id}/...
                        parts = name.split("/")
                        if parts[0].startswith("session-"):
                            session_id = parts[0].replace("session-", "", 1)
                            session_dirs.add(session_id)
                    # Also check for .claude/session-env/{id}/ structure
                    elif ".claude/session-env/" in name:
                        parts = name.split("/")
                        try:
                            idx = parts.index("session-env") + 1
                            if idx < len(parts):
                                session_dirs.add(parts[idx])
                        except ValueError:
                            pass

                for session_id in session_dirs:
                    # Try to find conversation.json for timestamp
                    last_modified = datetime.now()  # Default fallback
                    conv_path = f"session-{session_id}/conversation.json"
                    for member in tar.getmembers():
                        if member.name == conv_path or member.name.endswith(
                            f"/{session_id}/conversation.json"
                        ):
                            try:
                                file = tar.extractfile(member)
                                if file:
                                    content = file.read().decode("utf-8")
                                    conv_data = json.loads(content)
                                    timestamp_str = conv_data.get("timestamp")
                                    if timestamp_str:
                                        try:
                                            last_modified = datetime.fromisoformat(
                                                timestamp_str
                                            )
                                        except ValueError:
                                            last_modified = datetime.fromtimestamp(
                                                member.mtime
                                            )
                                    else:
                                        last_modified = datetime.fromtimestamp(
                                            member.mtime
                                        )
                                    break
                            except (json.JSONDecodeError, ValueError):
                                pass

                    sessions.append(
                        {
                            "session_id": session_id,
                            "name": session_id,  # Claude doesn't have session names
                            "last_modified": last_modified,
                            "size_bytes": 0,  # Unknown without full extraction
                        }
                    )

            elif tool == "codex":
                # For Codex, sessions are in year/month structure
                # We'll use the session IDs from metadata
                for session_id in session_ids:
                    sessions.append(
                        {
                            "session_id": session_id,
                            "name": session_id,
                            "last_modified": datetime.now(),
                            "size_bytes": 0,
                        }
                    )

    except Exception:
        # Fallback: use session IDs from metadata with minimal info
        for session_id in session_ids:
            sessions.append(
                {
                    "session_id": session_id,
                    "name": session_id,
                    "last_modified": datetime.now(),
                    "size_bytes": 0,
                }
            )

    return sessions


def check_any_session_exists(archive: "Archive") -> bool:
    """Check if ANY session from an archive already exists locally.

    Args:
        archive: Archive object to check

    Returns:
        True if any session from the archive already exists locally
    """
    _session_count, session_ids, tool = get_archive_sessions_info(archive)
    if not session_ids:
        return False

    try:
        session_dir, config_dir = get_tool_directories(tool)
    except (ValueError, OSError):
        return False

    if tool == "codex" and session_dir.exists():
        try:
            existing_ids = {
                s.session_id
                for s in discover_sessions(
                    session_dir, tool="codex", max_sessions=200000
                )
            }
        except Exception:
            existing_ids = set()
        return any(session_id in existing_ids for session_id in session_ids)

    # Check if any session exists locally
    for session_id in session_ids:
        if tool == "claude":
            old_session = config_dir / "sessions" / session_id
            new_session = config_dir / "session-env" / session_id
            if old_session.exists() or new_session.exists():
                return True
        elif tool == "opencode":
            # OpenCode stores sessions directly as {session_id}.json in session_dir
            # session_dir is ~/.local/share/opencode/storage/session/global/
            session_path = session_dir / f"{session_id}.json"
            if session_path.exists():
                return True
        elif tool == "codex":
            continue

    return False


def check_session_exists(archive: "Archive") -> bool:
    """Check if the session from an archive already exists locally.

    DEPRECATED: Use check_any_session_exists for multi-session archive support.
    This function is kept for backward compatibility.

    Args:
        archive: Archive object to check

    Returns:
        True if session already exists locally
    """
    return check_any_session_exists(archive)


def delete_archives(archives: List[Archive], indices: List[int]) -> int:
    """Delete selected archive files.

    Args:
        archives: List of all archives
        indices: List of indices to delete (0-based)

    Returns:
        Number of archives deleted
    """
    deleted = 0
    for idx in sorted(indices, reverse=True):
        if 0 <= idx < len(archives):
            archive = archives[idx]
            try:
                archive.archive_path.unlink()
                print_success(f"Deleted: {archive.archive_path.name}")
                deleted += 1
            except Exception as e:
                print_error(f"Failed to delete {archive.archive_path.name}: {e}")
    return deleted


def check_session_conflicts(session_ids: List[str], session_dir: Path) -> List[str]:
    """Check which sessions already exist.

    Args:
        session_ids: List of session IDs to check
        session_dir: Sessions directory

    Returns:
        List of conflicting session IDs
    """
    conflicts = []
    for session_id in session_ids:
        if (session_dir / session_id).exists():
            conflicts.append(session_id)
    return conflicts


def install_codex_sessions_from_extracted(
    extracted_root: Path,
    selected_session_ids: List[str],
    target_codex_dir: Optional[Path] = None,
) -> int:
    """Install Codex sessions from an extracted archive tree.

    Args:
        extracted_root: Root directory where the archive was extracted
        selected_session_ids: Session directory names to install (empty = all)
        target_codex_dir: Target Codex config directory (defaults to ~/.codex)
    """
    extracted_codex = extracted_root / ".codex"
    extracted_sessions_root = extracted_codex / "sessions"
    if not extracted_sessions_root.exists():
        raise OSError("No .codex/sessions found in extracted archive")

    if target_codex_dir is None:
        target_codex_dir = Path.home() / ".codex"

    target_sessions_root = target_codex_dir / "sessions"
    to_copy: List[Path] = []

    for candidate in extracted_sessions_root.rglob("*"):
        if not candidate.is_dir():
            continue
        if not list(candidate.glob("rollout-*.jsonl")):
            continue
        if selected_session_ids and candidate.name not in selected_session_ids:
            continue
        to_copy.append(candidate)

    if not to_copy:
        raise OSError("No Codex sessions found in extracted archive")

    for src_session_dir in to_copy:
        rel = src_session_dir.relative_to(extracted_sessions_root)
        dest_session_dir = target_sessions_root / rel
        dest_session_dir.parent.mkdir(parents=True, exist_ok=True)
        if dest_session_dir.exists():
            shutil.rmtree(dest_session_dir)
        shutil.copytree(src_session_dir, dest_session_dir)

    for item in extracted_codex.rglob("*"):
        if not item.is_file():
            continue
        rel_item = item.relative_to(extracted_codex)
        if rel_item.parts and rel_item.parts[0] == "sessions":
            continue
        target_item = target_codex_dir / rel_item
        target_item.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target_item)

    return len(to_copy)


def transaction_copy_sessions(
    source_session_env: Path,
    target_session_dir: Path,
    allowed_session_ids: Optional[Set[str]] = None,
) -> int:
    """Copy session directories with transaction safety.

    This function implements all-or-nothing semantics:
    1. Copy all sessions to a temporary staging directory
    2. Verify all copies succeeded
    3. Atomically move to final destination
    4. Rollback on any failure

    Args:
        source_session_env: Source directory containing session subdirectories
        target_session_dir: Target directory for sessions
        allowed_session_ids: Optional allowlist of session IDs to copy

    Returns:
        Number of sessions copied

    Raises:
        OSError: If copy fails after rollback attempt
        RuntimeError: If verification fails
    """
    added = 0
    staging_dir = None
    copied_sessions = []

    try:
        # Step 1: Create temporary staging directory
        staging_dir = Path(tempfile.mkdtemp(prefix="session_import_"))
        print_info(f"Created staging directory: {staging_dir}")

        # Step 2: Identify sessions to copy (skip existing)
        sessions_to_copy = []
        for session_path in source_session_env.iterdir():
            if session_path.is_dir():
                session_id = session_path.name
                if (
                    allowed_session_ids is not None
                    and session_id not in allowed_session_ids
                ):
                    continue
                target_session = target_session_dir / session_id

                if target_session.exists():
                    print_info(f"Skipping existing session: {session_id}")
                else:
                    sessions_to_copy.append((session_id, session_path))

        if not sessions_to_copy:
            print_info("No new sessions to copy")
            return 0

        # Step 3: Copy all sessions to staging directory
        print_info(f"Copying {len(sessions_to_copy)} session(s) to staging area...")
        for session_id, source_path in sessions_to_copy:
            staging_session = staging_dir / session_id
            try:
                shutil.copytree(source_path, staging_session)
                copied_sessions.append(session_id)
                print_info(f"Staged session: {session_id}")
            except Exception as e:
                print_error(f"Failed to copy session {session_id}: {e}")
                # Rollback: remove all staged copies
                shutil.rmtree(staging_dir)
                raise OSError(
                    f"Partial copy failure: session {session_id} failed. Staged copies rolled back."
                ) from e

        # Step 4: Verify all copies succeeded
        print_info("Verifying all copies...")
        for session_id in copied_sessions:
            staging_session = staging_dir / session_id
            if not staging_session.exists():
                shutil.rmtree(staging_dir)
                raise RuntimeError(
                    f"Verification failed: session {session_id} not found in staging directory"
                )

        # Step 5: Atomic move to final destination
        print_info("Moving sessions to final destination...")
        for session_id in copied_sessions:
            staging_session = staging_dir / session_id
            target_session = target_session_dir / session_id

            # Ensure target directory exists
            target_session_dir.mkdir(parents=True, exist_ok=True)

            # Use os.replace for atomic move (works across filesystems)
            # If target exists, it will be replaced (shouldn't happen due to skip check)
            os.replace(staging_session, target_session)
            print_info(f"Added session: {session_id}")
            added += 1

        # Step 6: Cleanup staging directory (should be empty now)
        try:
            staging_dir.rmdir()
            print_info("Staging directory cleaned up")
        except OSError as e:
            print_warning(f"Could not remove staging directory: {e}")

        return added

    except Exception:
        # Final cleanup: ensure staging directory is removed on any error
        if staging_dir and staging_dir.exists():
            try:
                shutil.rmtree(staging_dir)
                print_info("Staging directory cleaned up after error")
            except Exception as cleanup_error:
                print_warning(f"Failed to cleanup staging directory: {cleanup_error}")

        raise


def merge_claude_history(
    target_history: Path,
    archive_history: Path,
    lock_timeout: float = 30.0,
    allowed_session_ids: Optional[Set[str]] = None,
) -> Tuple[int, int]:
    """Merge archive history into target history with file locking.

    This function uses cross-platform file locking to prevent race conditions
    when multiple processes attempt to merge sessions concurrently. It uses
    atomic write operations to ensure data consistency.

    Only adds sessions that don't exist in target.

    Args:
        target_history: Path to target's history.jsonl
        archive_history: Path to archive's history.jsonl
        lock_timeout: Maximum time to wait for file lock (seconds)
        allowed_session_ids: Optional allowlist of session IDs to merge

    Returns:
        Tuple of (added_count, skipped_count)

    Raises:
        FileLockError: If lock cannot be acquired within timeout
    """
    # Create lock file path (same directory as target with .lock extension)
    lock_path = target_history.with_suffix(".lock")

    # Acquire lock FIRST to prevent TOCTOU race condition
    # The lock must be held for the entire read-modify-write cycle
    with FileLock(lock_path, timeout=lock_timeout, retry_interval=0.1):
        # Step 1: Check archive existence INSIDE the lock to prevent TOCTOU
        if not archive_history.exists():
            return 0, 0

        # Step 2: Read existing session IDs from target (still inside lock)
        existing_ids = set()
        if target_history.exists():
            try:
                with open(target_history, encoding="utf-8") as f:
                    for line_num, line in enumerate(f, 1):
                        line_stripped = line.strip()
                        if not line_stripped:
                            continue

                        # Allow comment lines (starting with #) for human-readable comments
                        if line_stripped.startswith("#"):
                            continue

                        # Validate line size before parsing
                        if not validate_json_line_size(
                            line_stripped, str(target_history), line_num
                        ):
                            continue

                        try:
                            data = json.loads(line_stripped)
                            # Validate JSON schema and sessionId
                            if validate_session_json_schema(
                                data, str(target_history), line_num
                            ):
                                if "sessionId" in data:
                                    existing_ids.add(data["sessionId"])
                        except json.JSONDecodeError as e:
                            security_logger.warning(
                                f"Invalid JSON in {target_history}:{line_num}: {e}"
                            )
                            continue
            except OSError as e:
                raise OSError(
                    f"Failed to read target history {target_history}: {e}"
                ) from e

        # Step 3: Read archive history and collect new sessions (still inside lock)
        added = 0
        skipped = 0
        new_lines = []

        try:
            with open(archive_history, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue

                    # Preserve comment lines (starting with #) for human-readable comments
                    if line_stripped.startswith("#"):
                        new_lines.append(line_stripped)
                        continue

                    # Validate line size before parsing
                    if not validate_json_line_size(
                        line_stripped, str(archive_history), line_num
                    ):
                        skipped += 1
                        continue

                    try:
                        data = json.loads(line_stripped)

                        # Validate JSON schema and sessionId
                        if not validate_session_json_schema(
                            data, str(archive_history), line_num
                        ):
                            skipped += 1
                            continue

                        session_id = data.get("sessionId")
                        if (
                            allowed_session_ids is not None
                            and session_id not in allowed_session_ids
                        ):
                            skipped += 1
                            continue
                        if session_id and session_id not in existing_ids:
                            new_lines.append(line_stripped)
                            existing_ids.add(session_id)
                            added += 1
                        else:
                            skipped += 1
                    except json.JSONDecodeError as e:
                        security_logger.warning(
                            f"Invalid JSON in {archive_history}:{line_num}: {e}"
                        )
                        # Skip malformed lines instead of crashing
                        skipped += 1
        except OSError as e:
            raise OSError(
                f"Failed to read archive history {archive_history}: {e}"
            ) from e

        # Step 4: Append new sessions to target history using manual atomic write
        # The lock is still held, ensuring atomicity of the entire operation
        if new_lines:
            try:
                # Create temporary file in same directory for atomic replace
                temp_path = target_history.with_suffix(".tmp")

                # Read existing content if it exists
                existing_lines = []
                if target_history.exists():
                    with open(target_history, encoding="utf-8") as f_read:
                        existing_lines = f_read.readlines()

                # Write combined content to temporary file
                with open(temp_path, "w", encoding="utf-8") as f:
                    # Write existing lines
                    for line in existing_lines:
                        f.write(line if line.endswith("\n") else line + "\n")

                    # Write new lines
                    for line in new_lines:
                        f.write(line + "\n")

                    # Ensure data is flushed to disk BEFORE closing
                    f.flush()
                    os.fsync(f.fileno())
                    # File will be closed automatically by context manager

                # Atomically replace target file
                # os.replace() is atomic on POSIX and Windows Vista+
                os.replace(str(temp_path), str(target_history))

            except OSError as e:
                # Clean up temp file if it exists
                temp_path = target_history.with_suffix(".tmp")
                try:
                    if temp_path.exists():
                        temp_path.unlink()
                except OSError:
                    pass
                raise OSError(
                    f"Failed to write target history {target_history}: {e}"
                ) from e

    return added, skipped


def main() -> int:
    """Main import function."""
    parser = argparse.ArgumentParser(
        description="Import AI tool session from portable archive"
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        default=Path.home()
        / "OneDrive"
        / "Desktop"
        / "Current"
        / "!SyncSessionDoNotDelete!",
        help="Archive directory (default: ~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/)",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Override tool config dir (e.g. ~/.claude, ~/.codex)",
    )
    parser.add_argument(
        "--session-dir",
        type=Path,
        default=None,
        help="Override tool session dir (e.g. ~/.claude/session-env, ~/.codex/sessions)",
    )
    args = parser.parse_args()
    archive_dir = args.archive_dir

    print_info("AI Tool Session Import")
    print_info("=" * 40)

    # Validate archive directory
    if not archive_dir.exists():
        print_error(f"Archive directory not found: {archive_dir}")
        print_info(
            "Please ensure OneDrive is configured and the Desktop/Current/!SyncSessionDoNotDelete! folder exists."
        )
        return 1

    # Discover archives
    print_info(f"Scanning for archives in {archive_dir}...")
    archives = discover_archives(archive_dir)

    if not archives:
        print_error("No archives found")
        print_info("Run export_session.py on the source machine first.")
        return 1

    # Display menu for archive selection
    selection = display_archive_menu(archives)
    if not selection:
        return 1

    selected_archive, selected_session_ids = selection

    # Load metadata
    metadata = selected_archive.load_metadata()
    if not metadata:
        print_warning("Could not load metadata from archive")
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != "y":
            print_info("Import cancelled")
            return 1

    # Get tool type and directories
    if metadata is not None:
        tool = metadata.session.tool
    else:
        archive_name = selected_archive.archive_path.name.lower()
        if archive_name.startswith("codex-"):
            tool = "codex"
        elif archive_name.startswith("opencode-"):
            tool = "opencode"
        else:
            tool = "claude"
    session_dir, config_dir = get_tool_directories(tool)
    if args.config_dir is not None:
        config_dir = args.config_dir
        if args.session_dir is None:
            if tool == "codex":
                session_dir = config_dir / "sessions"
            elif tool == "claude":
                session_env_dir = config_dir / "session-env"
                sessions_dir = config_dir / "sessions"
                session_dir = (
                    session_env_dir if session_env_dir.exists() else sessions_dir
                )
    if args.session_dir is not None:
        session_dir = args.session_dir

    # Validate checksum
    print_info("Validating archive integrity...")
    if metadata and not selected_archive.validate_checksum(metadata.checksum_sha256):
        print_error("Checksum validation failed!")
        print_warning("The archive may be corrupted or modified")
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != "y":
            print_info("Import cancelled")
            return 1

    # Check for session conflict and determine import mode
    session_id = metadata.session.session_id if metadata else "unknown"

    # For Claude Code, ask for merge vs replace mode
    merge_mode = False
    if tool == "claude":
        print("\nImport mode:")
        print("1. Merge (default) - Add only new sessions, keep existing")
        print("2. Replace - Replace all sessions with archive")
        while True:
            try:
                mode_choice = input("Enter choice (1-2, default=1): ").strip()
                if not mode_choice or mode_choice == "1":
                    merge_mode = True
                    print_info("Using merge mode - new sessions will be added")
                    break
                elif mode_choice == "2":
                    merge_mode = False
                    print_warning(
                        "Using replace mode - existing sessions will be overwritten"
                    )
                    break
                else:
                    print_error("Invalid choice, please enter 1 or 2")
            except (EOFError, KeyboardInterrupt):
                print_info("\nImport cancelled")
                return 1

    if tool == "opencode":
        # For opencode, check if the session file already exists
        session_file = session_dir / f"{session_id}.json"
        if session_file.exists():
            print_error(f"Session already exists: {session_id}")
            response = input("Overwrite existing session? (y/N): ").strip().lower()
            if response != "y":
                print_info("Import cancelled")
                return 1
            print_warning("Existing session will be overwritten")
    elif tool == "codex":
        # For codex, we need to find if the session directory exists
        # This is complex since codex uses year/month structure
        # We'll skip conflict check for codex and handle during extraction
        pass
    else:
        # For claude, check session conflicts based on mode
        if not merge_mode and check_session_conflict(session_id, session_dir):
            print_error(f"Session already exists: {session_id}")
            response = input("Overwrite existing session? (y/N): ").strip().lower()
            if response != "y":
                print_info("Import cancelled")
                return 1
            print_warning("Existing session will be overwritten")
        elif merge_mode:
            # In merge mode, we'll handle conflicts during extraction
            pass

    # Check disk space
    required_space = selected_archive.size_bytes * 3  # Decompression + extraction
    if not check_disk_space(Path.home(), required_space):
        print_error("Insufficient disk space for import")
        print_info(f"Required: {required_space:,} bytes")
        return 1

    # Ensure session directory exists
    if not ensure_directory(session_dir):
        print_error(f"Failed to create session directory: {session_dir}")
        return 1

    # Check if this is a selective import
    is_selective = len(selected_session_ids) > 0

    # Extract archive
    print_info(f"Extracting archive: {selected_archive.archive_path.name}")
    try:
        # Extract to temporary location first
        import shutil
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            extract_archive(selected_archive.archive_path, temp_path)

            # Check if this is a multi-session archive structure
            multi_session_structure = any(
                d.name.startswith("session-") for d in temp_path.iterdir() if d.is_dir()
            )

            if multi_session_structure:
                # Multi-session archive
                print_info("Multi-session archive detected")

                if is_selective:
                    print_info(
                        f"Importing {len(selected_session_ids)} selected session(s)..."
                    )

                # Get all session directories
                session_dirs = [
                    d
                    for d in temp_path.iterdir()
                    if d.is_dir() and d.name.startswith("session-")
                ]

                for session_dir_item in session_dirs:
                    session_id_from_dir = session_dir_item.name.replace(
                        "session-", "", 1
                    )

                    # Skip if selective import and this session is not selected
                    if is_selective and session_id_from_dir not in selected_session_ids:
                        continue

                    print_info(f"Processing session: {session_id_from_dir}")

                    if tool == "claude":
                        # For Claude, the session directory contains the session data
                        # Check if it's a session-env directory structure
                        session_env_dir = (
                            session_dir_item
                            / ".claude"
                            / "session-env"
                            / session_id_from_dir
                        )
                        if session_env_dir.exists():
                            # Copy to local session-env
                            target_session = session_dir / session_id_from_dir
                            if not merge_mode and target_session.exists():
                                shutil.rmtree(target_session)
                            if merge_mode and target_session.exists():
                                print_info(
                                    f"Session {session_id_from_dir} already exists, skipping"
                                )
                                continue
                            shutil.copytree(session_env_dir, target_session)
                            print_success(f"Added session: {session_id_from_dir}")

                        # Also check for history.jsonl
                        history_file = session_dir_item / ".claude" / "history.jsonl"
                        if history_file.exists():
                            target_history = config_dir / "history.jsonl"
                            target_history.parent.mkdir(parents=True, exist_ok=True)
                            if not target_history.exists():
                                target_history.write_text("")
                            added, skipped = merge_claude_history(
                                target_history,
                                history_file,
                                allowed_session_ids={session_id_from_dir},
                            )
                            if added > 0:
                                print_success(
                                    f"Merged {added} history entries for {session_id_from_dir}"
                                )

                    elif tool == "opencode":
                        # Find the session JSON file
                        session_files = list(session_dir_item.rglob("*.json"))
                        if session_files:
                            for session_file in session_files:
                                if "session" in session_file.name.lower():
                                    target_session = session_dir / session_file.name
                                    shutil.copy2(session_file, target_session)
                                    print_success(
                                        f"Added opencode session: {session_id_from_dir}"
                                    )
                                    break

                    elif tool == "codex":
                        # Copy the entire session directory to the target
                        target_path = session_dir / session_id_from_dir
                        if target_path.exists():
                            shutil.rmtree(target_path)
                        shutil.copytree(session_dir_item, target_path)
                        print_success(f"Added codex session: {session_id_from_dir}")

            elif tool == "opencode":
                # Handle opencode session (single session archive)
                extracted_session = temp_path / f"{session_id}.json"
                if not extracted_session.exists():
                    raise OSError("Session file not found in archive")

                print_info("Installing opencode session...")
                # Ensure target directory exists
                session_dir.mkdir(parents=True, exist_ok=True)
                # Copy session file
                shutil.copy2(extracted_session, session_dir / extracted_session.name)

            elif tool == "codex":
                # Handle codex session
                print_info("Installing codex session...")
                extracted_codex = temp_path / ".codex"
                extracted_sessions_root = extracted_codex / "sessions"

                if extracted_sessions_root.exists():
                    imported = install_codex_sessions_from_extracted(
                        temp_path,
                        selected_session_ids,
                        target_codex_dir=config_dir,
                    )
                    print_success(f"Imported {imported} codex session(s)")

                else:
                    extracted_session_dir = None
                    for item in temp_path.rglob("*"):
                        if item.is_dir() and list(item.glob("rollout-*.jsonl")):
                            if (
                                selected_session_ids
                                and item.name not in selected_session_ids
                            ):
                                continue
                            extracted_session_dir = item
                            break

                    if not extracted_session_dir:
                        raise OSError(
                            "Could not find codex session directory in archive"
                        )

                    from datetime import datetime

                    now = datetime.now()
                    target_path = session_dir / str(now.year) / f"{now.month:02d}"
                    target_path.mkdir(parents=True, exist_ok=True)

                    target_session = target_path / extracted_session_dir.name
                    if target_session.exists():
                        shutil.rmtree(target_session)
                    shutil.copytree(extracted_session_dir, target_session)

            else:
                # Handle claude session with merge support
                extracted_history = temp_path / ".claude" / "history.jsonl"

                if merge_mode and extracted_history.exists():
                    # Merge mode: combine history files
                    print_info("Merging sessions using merge mode...")

                    # Get target history path
                    target_history = config_dir / "history.jsonl"

                    # Ensure target directory exists
                    target_history.parent.mkdir(parents=True, exist_ok=True)

                    # Create target history if it doesn't exist
                    if not target_history.exists():
                        target_history.write_text("")

                    # Merge histories
                    allowed_ids = (
                        set(selected_session_ids) if selected_session_ids else None
                    )
                    added, skipped = merge_claude_history(
                        target_history,
                        extracted_history,
                        allowed_session_ids=allowed_ids,
                    )
                    print_info(f"Sessions added: {added}, skipped: {skipped}")

                    # Handle session-env directories (only add non-existing)
                    # CRIT-002 FIX: Use transaction-safe copy to prevent partial copy failures
                    extracted_session_env = temp_path / ".claude" / "session-env"
                    if extracted_session_env.exists():
                        print_info("Adding new session environments...")
                        try:
                            added_count = transaction_copy_sessions(
                                extracted_session_env,
                                session_dir,
                                allowed_session_ids=allowed_ids,
                            )
                            print_info(f"Successfully added {added_count} session(s)")
                        except OSError as e:
                            # Transaction copy failed with automatic rollback
                            print_error(f"Failed to import sessions: {e}")
                            # Re-raise to abort the entire import operation
                            raise

                    # Handle .claude directory (config files) - merge, don't replace
                    extracted_claude = temp_path / ".claude"
                    if extracted_claude.exists():
                        print_info("Merging .claude configuration...")
                        for item in extracted_claude.rglob("*"):
                            if item.is_file():
                                # Skip history.jsonl and session-env (already handled)
                                if "history.jsonl" in str(item) or "session-env" in str(
                                    item
                                ):
                                    continue
                                target_item = config_dir / item.relative_to(
                                    extracted_claude
                                )
                                # Only copy if target doesn't exist (merge behavior)
                                if not target_item.exists():
                                    target_item.parent.mkdir(
                                        parents=True, exist_ok=True
                                    )
                                    shutil.copy2(item, target_item)

                else:
                    # Replace mode: original logic
                    extracted_session = temp_path / f"{session_id}.json"
                    if not extracted_session.exists():
                        # Try new format location
                        extracted_session = temp_path / ".claude" / "history.jsonl"
                        if not extracted_session.exists():
                            raise OSError("Session file not found in archive")

                    print_info("Installing claude session (replace mode)...")

                    # Handle history.jsonl
                    if extracted_history.exists():
                        target_history = config_dir / "history.jsonl"
                        target_history.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(extracted_history, target_history)

                    # Handle session-env directory
                    extracted_session_env = temp_path / ".claude" / "session-env"
                    if extracted_session_env.exists():
                        for session_path_item in extracted_session_env.iterdir():
                            if session_path_item.is_dir():
                                session_id_item = session_path_item.name
                                target_session_item = session_dir / session_id_item
                                if target_session_item.exists():
                                    shutil.rmtree(target_session_item)
                                shutil.copytree(session_path_item, target_session_item)

                    # Handle .claude directory if present
                    extracted_claude = temp_path / ".claude"
                    if extracted_claude.exists():
                        print_info("Updating .claude directory...")
                        for item in extracted_claude.rglob("*"):
                            if item.is_file():
                                # Skip history.jsonl and session-env (already handled)
                                if "history.jsonl" in str(item) or "session-env" in str(
                                    item
                                ):
                                    continue
                                target_item = config_dir / item.relative_to(
                                    extracted_claude
                                )
                                target_item.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(item, target_item)

        print_success(f"Session imported: {session_id}")
        if metadata:
            print_info(f"Name: {metadata.session.name}")
            print_info(f"Tool: {tool}")
            print_info(f"Source: {metadata.source_hostname}")
            print_info(f"Exported: {metadata.export_timestamp}")
        return 0

    except Exception as e:
        print_error(f"Failed to import session: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
