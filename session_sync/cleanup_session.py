#!/usr/bin/env python3
"""Delete AI tool sessions from local storage.

This is a destructive operation.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from session_sync.core import Session, ToolType, discover_sessions
from session_sync.file_lock import FileLock
from session_sync.ui import (
    Colors,
    clear_screen,
    format_datetime,
    format_size,
    print_box_header,
    print_error,
    print_info,
    print_section,
    print_separator,
    print_success,
    print_warning,
)
from session_sync.utils import get_tool_directories, parse_session_selection


def _remove_claude_history_entries(
    target_history: Path,
    session_ids_to_remove: set[str],
    lock_timeout: float = 30.0,
) -> tuple[int, int]:
    lock_path = target_history.with_suffix(".lock")

    removed = 0
    kept = 0

    with FileLock(lock_path, timeout=lock_timeout, retry_interval=0.1):
        if not target_history.exists():
            return 0, 0

        tmp_path = target_history.with_suffix(".tmp")
        try:
            with open(target_history, encoding="utf-8") as src, open(
                tmp_path, "w", encoding="utf-8"
            ) as dst:
                for line in src:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    if line_stripped.startswith("#"):
                        dst.write(line_stripped + "\n")
                        continue
                    try:
                        data = json.loads(line_stripped)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(data, dict):
                        continue
                    session_id_val = data.get("sessionId")
                    if session_id_val in session_ids_to_remove:
                        removed += 1
                        continue
                    dst.write(line_stripped + "\n")
                    kept += 1

            os.replace(str(tmp_path), str(target_history))
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    return removed, kept


def _safe_rmtree(path: Path, root: Path) -> None:
    root_resolved = root.resolve()
    path_resolved = path.resolve()
    try:
        path_resolved.relative_to(root_resolved)
    except ValueError as e:
        raise ValueError(f"Refusing to delete outside root: {path}") from e
    shutil.rmtree(path)


def _delete_opencode_session(session: Session, config_dir: Path, dry_run: bool) -> int:
    deleted = 0

    session_file = session.conversation_file
    message_dir = config_dir / "storage" / "message" / session.session_id
    part_dir = config_dir / "storage" / "part"
    readme_file = (
        config_dir / "storage" / "directory-readme" / f"{session.session_id}.json"
    )

    candidates: list[Path] = []
    candidates.append(session_file)
    candidates.append(readme_file)
    if message_dir.exists():
        candidates.append(message_dir)
    if part_dir.exists():
        for part_file in part_dir.glob(f"{session.session_id}*"):
            candidates.append(part_file)

    for p in candidates:
        if not p.exists():
            continue
        if dry_run:
            continue
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        deleted += 1

    return deleted


def _delete_claude_session(
    session: Session,
    config_dir: Path,
    session_dir: Path,
    dry_run: bool,
) -> int:
    deleted = 0

    history_file = config_dir / "history.jsonl"
    if history_file.exists() and not dry_run:
        removed, _kept = _remove_claude_history_entries(
            history_file, {session.session_id}
        )
        if removed > 0:
            deleted += 1

    if session.session_path.exists() and session.session_path.is_dir():
        if not dry_run:
            _safe_rmtree(session.session_path, session_dir)
        deleted += 1

    if session.conversation_file.exists() and session.conversation_file.is_file():
        if not dry_run:
            session.conversation_file.unlink()
        deleted += 1

    return deleted


def _delete_codex_session(session: Session, session_dir: Path, dry_run: bool) -> int:
    parts = [p for p in session.session_id.split("/") if p]
    target = session_dir.joinpath(*parts)
    if not target.exists():
        return 0
    if not dry_run:
        _safe_rmtree(target, session_dir)
    return 1


def _display_cleanup_menu(sessions: list[Session]) -> list[Session] | None:
    if not sessions:
        print_error("No sessions found")
        return None

    selected_indices: set[int] = set()

    while True:
        clear_screen()
        tool_name = sessions[0].tool.upper()
        print_box_header(
            f"Session Cleanup - {tool_name}",
            "Toggle: number to select | C=continue | Q=quit",
        )

        print_section("AVAILABLE SESSIONS")
        print_separator()

        num_width = len(str(len(sessions)))
        name_width = 40
        id_width = 24
        size_width = 8
        select_width = 8

        print(
            f"  {Colors.BOLD}{'No':>{num_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Name':<{name_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'ID':<{id_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Modified':<{16}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Size':>{size_width}}{Colors.RESET}  "
            f"{Colors.BOLD}{'Select':>{select_width}}{Colors.RESET}"
        )
        print_separator()

        for i, session in enumerate(sessions, 1):
            idx = i - 1
            is_selected = idx in selected_indices

            name_display = session.name[:name_width].ljust(name_width)
            id_display = session.session_id[:id_width].ljust(id_width)
            modified_display = format_datetime(
                str(session.last_modified)[:19] if session.last_modified else None, 16
            )
            size_display = format_size(session.size_bytes).rjust(size_width)

            checkbox = (
                f"{Colors.GREEN}[✓]{Colors.RESET}"
                if is_selected
                else f"{Colors.CYAN}[ ]{Colors.RESET}"
            )

            print(
                f"  {Colors.BOLD}{i:>{num_width}}{Colors.RESET}  "
                f"{name_display}  "
                f"{Colors.CYAN}{id_display}{Colors.RESET}  "
                f"{modified_display}  "
                f"{size_display}  "
                f"{checkbox}"
            )

        print_separator()

        selected_count = len(selected_indices)
        if selected_count > 0:
            print(
                f"\n{Colors.YELLOW}Selected: {selected_count}/{len(sessions)} sessions{Colors.RESET}"
            )
        else:
            print(f"\n{Colors.CYAN}Selected: 0/{len(sessions)} sessions{Colors.RESET}")

        try:
            choice = input(
                f"\n{Colors.BOLD}Toggle selection (1-{len(sessions)}, C=continue, Q=quit):{Colors.RESET} "
            ).strip()

            if choice.upper() == "Q":
                return None

            if not choice or choice.upper() == "C":
                if not selected_indices:
                    print_warning("No sessions selected")
                    input("Press Enter to continue...")
                    continue
                return [sessions[i] for i in sorted(selected_indices)]

            try:
                num = int(choice)
                if 1 <= num <= len(sessions):
                    idx = num - 1
                    if idx in selected_indices:
                        selected_indices.remove(idx)
                    else:
                        selected_indices.add(idx)
                else:
                    print_error(f"Please enter a number between 1 and {len(sessions)}")
                    input("Press Enter to continue...")
            except ValueError:
                indices = parse_session_selection(choice, len(sessions))
                if indices:
                    selected_indices = set(indices)
                else:
                    print_error("Invalid input")
                    input("Press Enter to continue...")

        except (EOFError, KeyboardInterrupt):
            return None


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Delete AI tool sessions")
    parser.add_argument(
        "--tool",
        choices=["codex", "opencode", "claude"],
        help="Tool to clean up (default: interactive)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview deletions without modifying disk",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt (destructive)",
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

    return parser.parse_args()


def _choose_tool() -> ToolType:
    tools = [
        ("claude", "Claude"),
        ("opencode", "OpenCode"),
        ("codex", "Codex"),
    ]

    while True:
        clear_screen()
        print_box_header("Session Cleanup", "Choose tool")
        for i, (_tool_id, tool_name) in enumerate(tools, 1):
            print(f"  {Colors.BOLD}{i}.{Colors.RESET}  {tool_name}")
        try:
            choice = input(f"\nSelect tool (1-{len(tools)}): ").strip()
            num = int(choice)
            if 1 <= num <= len(tools):
                return tools[num - 1][0]  # type: ignore[return-value]
        except (ValueError, EOFError, KeyboardInterrupt):
            pass


def main() -> int:
    """Main cleanup function."""
    args = parse_arguments()
    tool: ToolType = args.tool if args.tool else _choose_tool()

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

    print_info("Scanning for sessions...")
    sessions = discover_sessions(session_dir, tool=tool)
    selected = _display_cleanup_menu(sessions)
    if not selected:
        print_warning("Cleanup cancelled")
        return 1

    dry_run = bool(args.dry_run)
    if dry_run:
        print_info("Dry-run: no files will be deleted")

    if not dry_run and not args.yes:
        print_warning("This will permanently delete selected sessions")
        confirm = input("Type DELETE to confirm: ").strip()
        if confirm != "DELETE":
            print_warning("Cleanup cancelled")
            return 1

    deleted_total = 0

    for session in selected:
        if tool == "opencode":
            deleted_total += _delete_opencode_session(session, config_dir, dry_run)
        elif tool == "codex":
            deleted_total += _delete_codex_session(session, session_dir, dry_run)
        else:
            deleted_total += _delete_claude_session(
                session, config_dir, session_dir, dry_run
            )

    if dry_run:
        print_success(f"Dry-run complete for {len(selected)} session(s)")
    else:
        print_success(f"Deleted {len(selected)} session(s)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
