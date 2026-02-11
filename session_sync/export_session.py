#!/usr/bin/env python3
"""Export AI tool session to portable archive.

This script exports sessions from various AI tools (codex, opencode, claude)
to .tgz archives that can be transferred to another machine.
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional, Set

_FILENAME_SAFE_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _sanitize_filename_component(value: str) -> str:
    value = value.replace("/", "-").replace("\\", "-")
    value = _FILENAME_SAFE_RE.sub("-", value).strip("-.")
    return value or "session"


# Graceful import error handling
try:
    from session_sync import __version__
    from session_sync.core import (
        Session,
        ToolType,
        check_disk_space,
        create_archive,
        create_archive_multiple,
        discover_sessions,
        ensure_directory,
        get_hostname,
    )
    from session_sync.ui import (
        Colors,
        clear_screen,
        format_datetime,
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
        parse_session_selection,
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
    print("   session-export")
    print()
    print("3. If installed, check your PATH includes ~/.local/bin:")
    print("   echo $PATH | grep local/bin")
    print()
    print("4. Try running with the Python interpreter directly:")
    print("   python -m session_sync.export_session")
    print()
    print(f"Import error details: {e}")
    print("=" * 60)
    sys.exit(1)


def select_tool() -> ToolType:
    """Prompt user to select AI tool with improved UI.

    Returns:
        ToolType: Selected tool type
    """
    tools = [
        ("codex", "Codex"),
        ("opencode", "OpenCode"),
        ("claude", "Claude Code"),
    ]

    while True:
        clear_screen()

        print_box_header("Session Export", "Select AI tool source | Q=quit")

        print_section("SELECT TOOL")
        print_separator()

        # Print tool options
        for i, (_tool_id, tool_name) in enumerate(tools, 1):
            print(f"  {Colors.BOLD}{i}.{Colors.RESET}  {tool_name}")

        print_separator()

        try:
            choice = input(
                f"\n{Colors.BOLD}Enter choice (1-3, Q to quit):{Colors.RESET} "
            ).strip()

            if choice.upper() == "Q":
                print_warning("\nExport cancelled")
                sys.exit(1)

            if choice == "1":
                return "codex"
            elif choice == "2":
                return "opencode"
            elif choice == "3":
                return "claude"
            else:
                print_error("Invalid choice, please enter 1, 2, or 3")
                input("Press Enter to continue...")

        except (EOFError, KeyboardInterrupt):
            print_warning("\nExport cancelled")
            sys.exit(1)


def display_session_menu(
    sessions: List[Session], batch_mode: bool = False
) -> Optional[List[Session]]:
    """Display interactive menu for session selection with toggle UI.

    Selection pattern:
    - Enter number to toggle selection (adds/removes checkbox)
    - Empty input or 'C' to continue with selected sessions
    - 'Q' to quit
    - Menu re-renders after each toggle to show updated checkboxes

    Args:
        sessions: List of available sessions
        batch_mode: If True, select all sessions without prompting

    Returns:
        List of selected sessions, or None if cancelled
    """
    if not sessions:
        print_error("No sessions found to export")
        return None

    # In batch mode, select all sessions automatically
    if batch_mode:
        print_info(f"Batch mode: auto-selecting all {len(sessions)} sessions")
        return sessions

    # Track selected indices (0-based)
    selected_indices: Set[int] = set()

    while True:
        clear_screen()

        # Print boxed header
        tool_name = sessions[0].tool.upper() if sessions else "CLAUDE"
        print_box_header(
            f"Session Export - {tool_name}",
            "Toggle: number to select | C=continue | Q=quit",
        )

        print_section("AVAILABLE SESSIONS")
        print_separator()

        # Calculate column widths
        num_width = len(str(len(sessions)))
        name_width = 40
        id_width = 18
        size_width = 8
        select_width = 8

        # Print table header
        print(
            f"  {Colors.BOLD}{'No':>{num_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Name':<{name_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'ID':<{id_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Modified':<{16}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Size':>{size_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Select':>{select_width}}{Colors.RESET}"
        )
        print_separator()

        # Print table rows with checkboxes
        for i, session in enumerate(sessions, 1):
            idx = i - 1  # 0-based index
            is_selected = idx in selected_indices

            name_display = session.name[:name_width].ljust(name_width)
            id_display = session.session_id[:id_width].ljust(id_width)
            modified_display = format_datetime(
                str(session.last_modified)[:19] if session.last_modified else None, 16
            )
            size_display = format_size(session.size_bytes).rjust(size_width)

            # Checkbox: [✓] if selected, [ ] if not
            if is_selected:
                checkbox = f"{Colors.GREEN}[✓]{Colors.RESET}"
            else:
                checkbox = f"{Colors.CYAN}[ ]{Colors.RESET}"

            print(
                f"  {Colors.BOLD}{i:>{num_width}}{Colors.RESET}  "
                f"{name_display}  "
                f"{Colors.CYAN}{id_display}{Colors.RESET}  "
                f"{modified_display}  "
                f"{size_display}  "
                f"{checkbox}"
            )

        print_separator()

        # Show selection count
        selected_count = len(selected_indices)
        if selected_count > 0:
            print(
                f"\n{Colors.GREEN}Selected: {selected_count}/{len(sessions)} sessions{Colors.RESET}"
            )
        else:
            print(f"\n{Colors.CYAN}Selected: 0/{len(sessions)} sessions{Colors.RESET}")

        # Get user input
        try:
            choice = input(
                f"\n{Colors.BOLD}Toggle selection (1-{len(sessions)}, C=continue, Q=quit):{Colors.RESET} "
            ).strip()

            # Check for quit
            if choice.upper() == "Q":
                print_warning("\nExport cancelled")
                return None

            # Check for continue (empty or 'C')
            if not choice or choice.upper() == "C":
                if not selected_indices:
                    print_warning(
                        "No sessions selected. Please select at least one session or press Q to quit."
                    )
                    input("Press Enter to continue...")
                    continue

                # Return selected sessions
                selected_sessions = [sessions[i] for i in sorted(selected_indices)]

                print_header(
                    f"\n{Colors.GREEN}Exporting {len(selected_sessions)} session(s)..."
                )
                for s in selected_sessions[:3]:
                    print(f"  - {s.name[:60]}")
                if len(selected_sessions) > 3:
                    print(f"  ... and {len(selected_sessions) - 3} more")

                return selected_sessions

            # Parse as number to toggle
            try:
                num = int(choice)
                if 1 <= num <= len(sessions):
                    idx = num - 1  # Convert to 0-based
                    if idx in selected_indices:
                        selected_indices.remove(idx)
                    else:
                        selected_indices.add(idx)
                    # Loop continues to re-render menu
                else:
                    print_error(f"Please enter a number between 1 and {len(sessions)}")
                    input("Press Enter to continue...")
            except ValueError:
                # Try parsing as selection (1,3,5 or 1-5 or all)
                indices = parse_session_selection(choice, len(sessions))
                if indices:
                    # Replace current selection with parsed selection
                    selected_indices = set(indices)
                else:
                    print_error(
                        "Invalid input. Enter a number, C to continue, or Q to quit."
                    )
                    input("Press Enter to continue...")

        except (EOFError, KeyboardInterrupt):
            print_warning("\nExport cancelled")
            return None


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Export AI tool session to portable archive",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit codes:
  0 - Success
  1 - Error occurred
  2 - Files skipped (in batch/no-clobber mode)

Examples:
  # Interactive mode (default)
  %(prog)s

  # Export all sessions without prompts
  %(prog)s --batch-mode

  # Force overwrite existing archives
  %(prog)s --force

  # Skip existing archives without prompting
  %(prog)s --no-clobber

  # Export from specific tool
  %(prog)s --tool claude --batch-mode
        """,
    )

    parser.add_argument(
        "--tool",
        choices=["codex", "opencode", "claude"],
        help="AI tool to export from (default: interactive prompt)",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help="Force overwrite existing archives without prompting",
    )

    parser.add_argument(
        "--no-clobber",
        action="store_true",
        help="Skip existing archives without prompting (exit code 2)",
    )

    parser.add_argument(
        "--batch-mode",
        action="store_true",
        help="Disable all prompts and use sensible defaults (select all sessions)",
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path.home()
        / "OneDrive"
        / "Desktop"
        / "Current"
        / "!SyncSessionDoNotDelete!",
        help="Output directory for archives (default: ~/OneDrive/Desktop/Current/!SyncSessionDoNotDelete!/)",
    )

    parser.add_argument(
        "--config-dir",
        type=Path,
        default=None,
        help="Override tool config dir (e.g. ~/.claude, ~/.codex, ~/.local/share/opencode)",
    )

    parser.add_argument(
        "--session-dir",
        type=Path,
        default=None,
        help="Override tool session dir (e.g. ~/.claude/session-env, ~/.codex/sessions)",
    )

    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    return parser.parse_args()


def main() -> int:
    """Main export function."""
    args = parse_arguments()
    output_dir = args.output_dir

    print_info("AI Tool Session Export")
    print_info("=" * 40)

    # Determine tool selection
    if args.tool:
        tool = args.tool
        print_info(f"Tool specified: {tool.upper()}")
    elif args.batch_mode:
        # Default to claude in batch mode
        tool = "claude"
        print_info(f"Batch mode: defaulting to {tool.upper()}")
    else:
        tool = select_tool()

    print_info(f"Selected tool: {tool.upper()}")

    # Get directories for selected tool
    session_dir, config_dir = get_tool_directories(tool)

    if args.config_dir is not None:
        config_dir = args.config_dir
        if args.session_dir is None:
            if tool == "opencode":
                session_dir = config_dir / "storage" / "session" / "global"
            elif tool == "codex":
                session_dir = config_dir / "sessions"
            else:
                session_env_dir = config_dir / "session-env"
                sessions_dir = config_dir / "sessions"
                session_dir = (
                    session_env_dir if session_env_dir.exists() else sessions_dir
                )

    if args.session_dir is not None:
        session_dir = args.session_dir

    # Validate session directory
    if not session_dir.exists():
        print_error(f"Session directory not found: {session_dir}")
        if tool == "opencode":
            print_info(
                "Please ensure OpenCode is installed and has been used at least once."
            )
        elif tool == "codex":
            print_info(
                "Please ensure Codex is installed and has been used at least once."
            )
        else:
            print_info(
                "Please ensure Claude Code is installed and has been used at least once."
            )
        return 1

    # Discover sessions
    print_info(f"Scanning for sessions in {session_dir}...")
    sessions = discover_sessions(session_dir, tool=tool)

    if not sessions:
        print_error("No sessions found")
        print_info(
            f"Create a session in {tool.upper()} first, then run this script again."
        )
        return 1

    # Display menu for session selection (or auto-select in batch mode)
    selected_sessions = display_session_menu(sessions, batch_mode=args.batch_mode)
    if not selected_sessions:
        return 1

    # Ensure output directory exists
    if not output_dir.exists():
        print_info(f"Creating output directory: {output_dir}")
        if not ensure_directory(output_dir):
            print_error(f"Failed to create output directory: {output_dir}")
            print_info("Please create the directory manually or check permissions.")
            return 1

    # Generate archive name based on selection
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    if len(selected_sessions) == 1:
        selected_session = selected_sessions[0]
        tool_prefix = selected_session.tool
        safe_id = _sanitize_filename_component(selected_session.session_id)
        archive_name = f"{tool_prefix}-session-{safe_id}-{timestamp}.tgz"
    else:
        tool_prefix = selected_sessions[0].tool if selected_sessions else "claude"
        if len(selected_sessions) == len(sessions):
            archive_name = f"{tool_prefix}-sessions-all-{timestamp}.tgz"
        else:
            archive_name = (
                f"{tool_prefix}-sessions-{len(selected_sessions)}-{timestamp}.tgz"
            )

    archive_path = output_dir / archive_name

    # Handle existing archive based on flags
    if archive_path.exists():
        if args.force:
            print_info(f"Archive exists, overwriting ( --force ): {archive_path}")
        elif args.no_clobber or args.batch_mode:
            print_info(
                f"Archive exists, skipping ( --no-clobber or --batch-mode ): {archive_path}"
            )
            return 2  # Exit code 2: skipped
        else:
            # Default behavior: prompt
            print_error(f"Archive already exists: {archive_path}")
            try:
                response = input("Overwrite? (y/N): ").strip().lower()
                if response != "y":
                    print_info("Export cancelled")
                    return 1
            except (EOFError, KeyboardInterrupt):
                print_info("\nExport cancelled")
                return 1

    # Estimate size and check disk space
    total_size = sum(s.size_bytes for s in selected_sessions)
    estimated_size = total_size * 2  # Account for compression overhead
    if not check_disk_space(output_dir, estimated_size):
        print_error("Insufficient disk space for archive creation")
        print_info(f"Required: {estimated_size:,} bytes")
        return 1

    # Create archive
    print_info(f"Creating archive: {archive_name}")
    try:
        hostname = get_hostname()

        if len(selected_sessions) == 1:
            # Use existing single-session export
            archive_path = create_archive(
                session=selected_sessions[0],
                config_dir=config_dir,
                output_dir=output_dir,
                hostname=hostname,
            )
        else:
            # Use new multi-session export
            archive_path = create_archive_multiple(
                sessions=selected_sessions,
                config_dir=config_dir,
                output_dir=output_dir,
                hostname=hostname,
                archive_name=archive_name,
            )

        print_success(f"Archive created: {archive_path}")
        print_info(f"Size: {archive_path.stat().st_size:,} bytes")

        if len(selected_sessions) == 1:
            s = selected_sessions[0]
            print_info(f"Session: {s.name} ({s.session_id})")
        else:
            print_info(f"Sessions: {len(selected_sessions)} exported")
            for s in selected_sessions[:3]:  # Show first 3
                print_info(f"  - {s.name} ({s.session_id})")
            if len(selected_sessions) > 3:
                print_info(f"  ... and {len(selected_sessions) - 3} more")

        print_info(f"Tool: {tool_prefix}")
        print_info(f"Source: {hostname}")
        return 0
    except Exception as e:
        print_error(f"Failed to create archive: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
