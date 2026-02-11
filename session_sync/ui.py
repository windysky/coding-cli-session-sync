#!/usr/bin/env python3
"""Improved UI utilities for session synchronization.

Provides boxed menu display, checkbox states, and color-coded output
similar to the agentic-cli-installer pattern.
"""

import os
import sys
from typing import Optional


# ANSI color codes
class Colors:
    """ANSI color codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bright foreground colors
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


# Box drawing characters for terminal
class BoxChars:
    """Unicode box drawing characters."""
    TL = "┌"  # Top left
    TR = "┐"  # Top right
    BL = "└"  # Bottom left
    BR = "┘"  # Bottom right
    HLINE = "─"  # Horizontal line
    VLINE = "│"  # Vertical line


def get_terminal_width(default: int = 80) -> int:
    """Get terminal width, with fallback to default."""
    try:
        import shutil
        return shutil.get_terminal_size().columns
    except Exception:
        return default


def clear_screen() -> None:
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def print_box_header(title: str, subtitle: str = "") -> None:
    """Print a boxed header with title and optional subtitle.

    Args:
        title: Main title text
        subtitle: Optional subtitle text (typically instructions)
    """
    width = get_terminal_width()
    width = min(max(width, 60), 92)  # Clamp between 60 and 92

    inner = width - 2

    print(f"{BoxChars.TL}{BoxChars.HLINE * inner}{BoxChars.TR}")
    print(f"{BoxChars.VLINE} {title:<{inner - 1}}{BoxChars.VLINE}")

    if subtitle:
        print(f"{BoxChars.VLINE} {subtitle:<{inner - 1}}{BoxChars.VLINE}")

    print(f"{BoxChars.BL}{BoxChars.HLINE * inner}{BoxChars.BR}")


def print_section(name: str) -> None:
    """Print a section header."""
    print(f"\n{Colors.BOLD}[{name}]{Colors.RESET}\n")


def print_separator() -> None:
    """Print a horizontal separator line."""
    width = get_terminal_width()
    print(f"{Colors.CYAN}{BoxChars.HLINE * width}{Colors.RESET}")


def print_header(text: str) -> None:
    """Print a styled header."""
    print(f"\n{Colors.CYAN}{Colors.BOLD}{text}{Colors.RESET}\n")


def print_success(text: str) -> None:
    """Print success message in green."""
    print(f"{Colors.GREEN}✓ {text}{Colors.RESET}")


def print_error(text: str) -> None:
    """Print error message in red."""
    print(f"{Colors.RED}✗ {text}{Colors.RESET}", file=sys.stderr)


def print_warning(text: str) -> None:
    """Print warning message in yellow."""
    print(f"{Colors.YELLOW}⚠ {text}{Colors.RESET}")


def print_info(text: str) -> None:
    """Print info message in cyan."""
    print(f"{Colors.CYAN}ℹ {text}{Colors.RESET}")


def checkbox(selected: bool, checked_char: str = "✓") -> str:
    """Return a checkbox string with selection state.

    Args:
        selected: Whether the item is selected
        checked_char: Character to show when checked (default: ✓)

    Returns:
        Formatted checkbox string with color
    """
    if selected:
        return f"{Colors.GREEN}[{checked_char}]{Colors.RESET}"
    return f"{Colors.CYAN}[ ]{Colors.RESET}"


def action_checkbox(action: str) -> str:
    """Return a checkbox string based on action type.

    Args:
        action: Action type (export, skip, import, etc.)

    Returns:
        Formatted checkbox with appropriate symbol and color
    """
    action_lower = action.lower()

    if action_lower in ("export", "import"):
        return f"{Colors.GREEN}[✓]{Colors.RESET}"
    elif action_lower in ("upgrade", "update"):
        return f"{Colors.CYAN}[↑]{Colors.RESET}"
    elif action_lower in ("skip", "none"):
        return f"{Colors.CYAN}[ ]{Colors.RESET}"
    elif action_lower in ("remove", "delete"):
        return f"{Colors.RED}[✗]{Colors.RESET}"
    else:
        return f"{Colors.CYAN}[ ]{Colors.RESET}"


def format_size(size_bytes: int) -> str:
    """Format byte size as human-readable string.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string (e.g., "1.5M", "256K")
    """
    for suffix, threshold in (
        ("G", 1024**3),
        ("M", 1024**2),
        ("K", 1024),
    ):
        if size_bytes >= threshold:
            return f"{size_bytes / threshold:.1f}{suffix}"
    return f"{size_bytes}B"


def format_datetime(dt_str: Optional[str], width: int = 16) -> str:
    """Format datetime string for display.

    Args:
        dt_str: ISO datetime string
        width: Target display width

    Returns:
        Formatted datetime string or "N/A" if None
    """
    if not dt_str:
        return "N/A".ljust(width)

    # Truncate to fit width
    return dt_str[:width].ljust(width)


def get_color_for_status(status: str) -> str:
    """Get ANSI color code for a status string.

    Args:
        status: Status string

    Returns:
        Color code (empty string for default)
    """
    status_lower = status.lower()

    if status_lower in ("ok", "success", "done", "complete", "exported", "imported"):
        return Colors.GREEN
    elif status_lower in ("error", "fail", "failed", "corrupted"):
        return Colors.RED
    elif status_lower in ("warning", "pending", "skipped"):
        return Colors.YELLOW
    elif status_lower in ("info", "progress", "processing"):
        return Colors.CYAN
    return ""


def print_table_row(
    num: int,
    name: str,
    status: str,
    size: int,
    selected: bool = False,
    name_width: int = 45,
    status_width: int = 14,
) -> None:
    """Print a single table row for session/archive listing.

    Args:
        num: Row number
        name: Item name
        status: Status string
        size: Size in bytes
        selected: Whether item is selected
        name_width: Width for name column
        status_width: Width for status column
    """
    # Format name with truncation
    name_display = name[:name_width].ljust(name_width)

    # Format status with color
    status_color = get_color_for_status(status)
    status_display = f"{status_color}{status[:status_width]:<{status_width}}{Colors.RESET}"

    # Format size
    size_display = format_size(size).rjust(8)

    # Format checkbox
    checkbox_str = checkbox(selected)

    # Print row
    print(f"  {Colors.BOLD}{num:2d}{Colors.RESET}  {name_display}  {status_display}  {size_display}  {checkbox_str}")
