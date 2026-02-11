"""Core functionality for session synchronization.

This module provides the core data structures and utilities for
exporting and importing sessions from multiple AI tools (codex, opencode).
"""

import hashlib
import json
import logging
import os
import tarfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)


# Default maximum sessions to discover per tool (configurable)
DEFAULT_MAX_SESSIONS = 1000

# Maximum history file size to prevent unbounded memory consumption (100MB)
MAX_HISTORY_FILE_SIZE = 100 * 1024 * 1024

ToolType = Literal["codex", "opencode", "claude"]

# Module-level cache for history data to avoid repeated file scans
# Key: (history_file_path, session_id), Value: history_data dict or None
# Thread-safe: All cache access must be protected by _CACHE_LOCK
_GLOBAL_HISTORY_CACHE: Dict[tuple, Optional[Dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()

# Security: Files that should NEVER be included in archives (credentials, tokens)
_AUTH_FILE_PATTERNS = [
    "auth.json",
    "auth.json.backup",
    ".auth",
    ".token",
    "token.json",
    "credentials.json",
    ".credentials",
    "api_key",
    ".api_key",
    "secret",
    ".secret",
    "session_tokens.json",
    "cookies.json",
    "local_storage.json",
]


class Session:
    """Represents a session from an AI tool (codex, opencode, claude)."""

    def __init__(
        self,
        session_id: str,
        session_path: Path,
        tool: ToolType = "claude",
        history_data: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a Session.

        Args:
            session_id: Unique session identifier
            session_path: Path to the session directory or file
            tool: Tool type (codex, opencode, claude)
            history_data: Optional pre-loaded history data for Claude sessions
        """
        self.session_id = session_id
        self.session_path = session_path
        self.tool = tool
        self._history_data = history_data  # Store for Claude sessions

        # Set conversation file based on tool type
        if tool == "opencode":
            # For opencode, the session file is directly at session_path
            self.conversation_file = session_path
        elif tool == "codex":
            # For codex, find the rollout JSONL file in the session directory
            self.conversation_file = self._find_codex_conversation()
        else:
            # For claude, check if it's the new format (history.jsonl) or old format
            # Old format: session_path is a directory containing {session_id}.json
            # New format: session_path is the session-env directory, data in history.jsonl
            old_format_file = session_path / f"{session_id}.json"
            # For new format, we also store the expected old format path
            # This maintains backward compatibility with tests
            self.conversation_file = old_format_file

    def _find_codex_conversation(self) -> Path:
        """Find the conversation file for codex sessions."""
        if self.session_path.is_dir():
            # Look for rollout-*.jsonl files
            jsonl_files = list(self.session_path.glob("rollout-*.jsonl"))
            if jsonl_files:
                # Return the most recent one
                return max(jsonl_files, key=lambda p: p.stat().st_mtime)
        # Fallback to the session path itself
        return self.session_path

    def _load_history_data(self) -> Optional[Dict[str, Any]]:
        """Load history data from history.jsonl for Claude sessions.

        Uses module-level cache to avoid repeated file scans when multiple
        Session objects are created outside of discover_sessions context.

        Thread-Safety:
            All cache access is protected by _CACHE_LOCK to prevent TOCTOU
            (Time-Of-Check-Time-Of-Use) race conditions in multi-threaded
            environments. The lock ensures atomic check-and-set operations.

        Security: Enforces MAX_HISTORY_FILE_SIZE to prevent unbounded memory
        consumption from malicious or corrupted history files.
        """
        # Check if data was provided during initialization
        if self._history_data is not None:
            return self._history_data

        if self.tool != "claude":
            return None

        # history.jsonl is in the parent of session-env directory
        history_file = self.session_path.parent.parent / "history.jsonl"
        if not history_file.exists():
            return None

        # Check file size before reading to prevent unbounded memory consumption
        try:
            file_size = history_file.stat().st_size
            if file_size > MAX_HISTORY_FILE_SIZE:
                import logging

                logging.warning(
                    f"History file {history_file} exceeds maximum size "
                    f"({file_size} > {MAX_HISTORY_FILE_SIZE} bytes). "
                    f"Skipping to prevent unbounded memory consumption."
                )
                # Cache the negative result (None) to avoid repeated size checks
                cache_key = (str(history_file), self.session_id)
                with _CACHE_LOCK:
                    _GLOBAL_HISTORY_CACHE[cache_key] = None
                return None
        except OSError:
            return None

        # Check module-level cache to avoid re-scanning the file
        cache_key = (str(history_file), self.session_id)
        # Thread-safe cache check: Use lock to prevent TOCTOU race condition
        with _CACHE_LOCK:
            if cache_key in _GLOBAL_HISTORY_CACHE:
                self._history_data = _GLOBAL_HISTORY_CACHE[cache_key]
                return self._history_data

        # Release lock before file I/O to allow concurrent reads
        try:
            with open(history_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if (
                                isinstance(data, dict)
                                and data.get("sessionId") == self.session_id
                            ):
                                self._history_data = data
                                # Cache the result for future lookups
                                # Thread-safe cache update: Use lock for atomic write
                                with _CACHE_LOCK:
                                    _GLOBAL_HISTORY_CACHE[cache_key] = data
                                return data
                        except json.JSONDecodeError:
                            continue
        except OSError:
            pass

        # Cache the negative result (None) to avoid repeated scans
        # Thread-safe cache update: Cache negative result (None)
        with _CACHE_LOCK:
            _GLOBAL_HISTORY_CACHE[cache_key] = None
        return None

    @property
    def name(self) -> str:
        """Get session name from conversation file."""
        if self.tool == "claude":
            # Check if conversation_file is a directory (new format) or file (old format)
            # conversation_file is always set to {session_path}/{session_id}.json
            # If the session_path is a directory that doesn't contain the JSON file,
            # it's new format
            if self.session_path.is_dir() and not self.conversation_file.exists():
                # New format - get name from history.jsonl 'display' field
                history_data = self._load_history_data()
                if history_data:
                    display_val = history_data.get("display")
                    display = display_val if isinstance(display_val, str) else ""
                    # Clean up the display name (remove newlines, truncate if too long)
                    display = display.replace("\n", " ").strip()
                    if len(display) > 100:
                        display = display[:97] + "..."
                    return display if display else self.session_id
                return self.session_id
            else:
                # Old format - read from JSON file
                if self.conversation_file.exists():
                    try:
                        with open(self.conversation_file) as f:
                            data = json.load(f)
                            title = (
                                data.get("title") if isinstance(data, dict) else None
                            )
                            return (
                                title
                                if isinstance(title, str) and title
                                else self.session_id
                            )
                    except (OSError, json.JSONDecodeError):
                        pass
                return self.session_id

        if not self.conversation_file.exists():
            return self.session_id

        try:
            if self.tool == "opencode":
                # OpenCode format: JSON file with 'title' field
                with open(self.conversation_file) as f:
                    data = json.load(f)
                    title = data.get("title") if isinstance(data, dict) else None
                    return (
                        title if isinstance(title, str) and title else self.session_id
                    )
            elif self.tool == "codex":
                # Codex format: JSONL file - use directory name or session ID
                # Try to get the first line as a hint
                try:
                    with open(self.conversation_file) as f:
                        first_line = f.readline().strip()
                        if first_line:
                            data = json.loads(first_line)
                            # Could use session_id from data, but directory name is clearer
                            pass
                except (OSError, json.JSONDecodeError):
                    pass
                return self.session_id
        except (OSError, json.JSONDecodeError):
            pass

        return self.session_id

    @property
    def created_at(self) -> Optional[datetime]:
        """Get session creation timestamp."""
        if self.tool == "claude":
            # Check if conversation_file exists (old format) or not (new format)
            if self.session_path.is_dir() and not self.conversation_file.exists():
                # New format - get timestamp from history.jsonl
                history_data = self._load_history_data()
                if history_data:
                    timestamp = history_data.get("timestamp")
                    if timestamp:
                        try:
                            # timestamp is in milliseconds
                            return datetime.fromtimestamp(timestamp / 1000)
                        except (ValueError, OSError):
                            pass
                # Fallback to session directory creation time
                if self.session_path.is_dir():
                    return datetime.fromtimestamp(self.session_path.stat().st_ctime)
                return None
            else:
                # Old format - use file creation time
                if self.conversation_file.exists():
                    return datetime.fromtimestamp(
                        self.conversation_file.stat().st_ctime
                    )
                return None

        if self.tool == "opencode":
            # For opencode, read from JSON file
            if self.conversation_file.exists():
                try:
                    with open(self.conversation_file) as f:
                        data = json.load(f)
                        created_at_val = (
                            data.get("createdAt") if isinstance(data, dict) else None
                        )
                        if isinstance(created_at_val, str):
                            return datetime.fromisoformat(created_at_val)
                except (OSError, json.JSONDecodeError, ValueError):
                    pass
            return None
        elif self.tool == "codex":
            # For codex, use directory creation time
            if self.session_path.is_dir():
                return datetime.fromtimestamp(self.session_path.stat().st_ctime)
            return None

    @property
    def last_modified(self) -> Optional[datetime]:
        """Get session last modified timestamp."""
        if self.tool == "claude":
            # Check if conversation_file exists (old format) or not (new format)
            if self.session_path.is_dir() and not self.conversation_file.exists():
                # New format - get timestamp from history.jsonl (same as created_at)
                return self.created_at
            else:
                # Old format - use file modification time
                if self.conversation_file.exists():
                    return datetime.fromtimestamp(
                        self.conversation_file.stat().st_mtime
                    )
                return None

        if self.tool == "opencode":
            # For opencode, read from JSON file
            if self.conversation_file.exists():
                try:
                    with open(self.conversation_file) as f:
                        data = json.load(f)
                        updated_at_val = (
                            data.get("updatedAt") if isinstance(data, dict) else None
                        )
                        if isinstance(updated_at_val, str):
                            return datetime.fromisoformat(updated_at_val)
                except (OSError, json.JSONDecodeError, ValueError):
                    pass
            # Fallback to file modification time
            if self.conversation_file.exists():
                return datetime.fromtimestamp(self.conversation_file.stat().st_mtime)
            return None
        else:
            # For codex and legacy claude, use file/directory modification time
            if self.conversation_file.exists():
                return datetime.fromtimestamp(self.conversation_file.stat().st_mtime)
            return None

    @property
    def size_bytes(self) -> int:
        """Get total size of session files in bytes."""
        total_size = 0
        if self.tool == "opencode":
            # For opencode, just the JSON file size
            if self.conversation_file.exists():
                return self.conversation_file.stat().st_size
        elif self.tool == "codex":
            # For codex, sum all files in the session directory
            if self.session_path.is_dir():
                for file in self.session_path.rglob("*"):
                    if file.is_file():
                        total_size += file.stat().st_size
        elif self.tool == "claude":
            # For Claude, the session directory may be empty
            # Size is from history.jsonl entry (estimated)
            # Use session directory size if it has content, otherwise minimal size
            if self.session_path.is_dir():
                for file in self.session_path.rglob("*"):
                    if file.is_file():
                        total_size += file.stat().st_size
            # If directory is empty, use a minimal size estimate
            if total_size == 0:
                total_size = 1024  # Minimal placeholder size
        return total_size

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for metadata."""
        return {
            "id": self.session_id,
            "name": self.name,
            "tool": self.tool,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_modified": (
                self.last_modified.isoformat() if self.last_modified else None
            ),
        }


class Metadata:
    """Metadata for a session archive."""

    VERSION = "1.0"

    def __init__(
        self,
        export_timestamp: datetime,
        source_hostname: str,
        session: Session,
        archive_filename: str,
        checksum_sha256: str,
        size_bytes: int,
        file_count: int,
    ):
        """Initialize metadata.

        Args:
            export_timestamp: When the archive was created
            source_hostname: Hostname of source machine
            session: Session being archived
            archive_filename: Name of the archive file
            checksum_sha256: SHA-256 checksum of archive
            size_bytes: Size of archive in bytes
            file_count: Number of files in archive
        """
        self.export_timestamp = export_timestamp
        self.source_hostname = source_hostname
        self.session = session
        self.archive_filename = archive_filename
        self.checksum_sha256 = checksum_sha256
        self.size_bytes = size_bytes
        self.file_count = file_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        contents = {}
        if self.session.tool == "opencode":
            contents = {
                "session_file": f"storage/session/global/{self.session.session_id}.json",
                "message_directory": f"storage/message/{self.session.session_id}/",
                "part_files": f"storage/part/{self.session.session_id}*",
                "directory_readme": f"storage/directory-readme/{self.session.session_id}.json",
                "type": "opencode_session",
            }
        elif self.session.tool == "codex":
            contents = {
                "conversation_file": str(self.session.conversation_file.name),
                "type": "codex_session",
                "session_directory": str(self.session.session_path.name),
            }
        else:
            contents = {
                "conversation_history": ".claude/history.jsonl",
                "session_env": f".claude/session-env/{self.session.session_id}/",
                "claude_directory": ".claude/",
                "type": "claude_session",
            }

        return {
            "version": self.VERSION,
            "tool": self.session.tool,
            "export_timestamp": self.export_timestamp.isoformat(),
            "source_hostname": self.source_hostname,
            "session": self.session.to_dict(),
            "archive": {
                "filename": self.archive_filename,
                "checksum_sha256": self.checksum_sha256,
                "size_bytes": self.size_bytes,
                "file_count": self.file_count,
            },
            "contents": contents,
        }

    def save(self, path: Path) -> None:
        """Save metadata to JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "Metadata":
        """Load metadata from JSON file."""
        with open(path) as f:
            data = json.load(f)

        # Get tool type from metadata (default to 'claude' for backward compatibility)
        tool = data.get("tool", "claude")

        # Recreate session object based on tool type
        if tool == "opencode":
            # For opencode, session_path should be the full path to the JSON file
            # We'll construct it during import
            session_path = Path(
                f"~/.local/share/opencode/storage/session/global/{data['session']['id']}.json"
            ).expanduser()
        elif tool == "codex":
            # For codex, we need to find the session directory
            # This will be resolved during import
            session_path = Path("~/.codex/sessions").expanduser()
        else:
            # For claude, use traditional path
            session_path = Path(
                f"~/.claude/sessions/{data['session']['id']}"
            ).expanduser()

        session = Session(data["session"]["id"], session_path, tool=tool)

        return cls(
            export_timestamp=datetime.fromisoformat(data["export_timestamp"]),
            source_hostname=data["source_hostname"],
            session=session,
            archive_filename=data["archive"]["filename"],
            checksum_sha256=data["archive"]["checksum_sha256"],
            size_bytes=data["archive"]["size_bytes"],
            file_count=data["archive"]["file_count"],
        )


class Archive:
    """Represents a session archive file."""

    def __init__(self, archive_path: Path):
        """Initialize archive.

        Args:
            archive_path: Path to the archive file
        """
        self.archive_path = archive_path
        self.metadata: Optional[Metadata] = None

    @property
    def size_bytes(self) -> int:
        """Get archive size in bytes."""
        return self.archive_path.stat().st_size

    def load_metadata(self) -> Optional[Metadata]:
        """Load metadata from archive."""
        try:
            with tarfile.open(self.archive_path, "r:gz") as tar:
                member = tar.getmember("metadata.json")
                file = tar.extractfile(member)
                if file:
                    # Create a temporary file to load metadata with secure permissions
                    import os
                    import tempfile

                    # Use mkstemp with explicit mode 0o600 for secure file creation
                    fd, tmp_path_str = tempfile.mkstemp(suffix=".json", text=True)
                    tmp_path = Path(tmp_path_str)

                    try:
                        # Set restrictive permissions (owner read/write only)
                        os.chmod(fd, 0o600)

                        # Write the file content
                        with os.fdopen(fd, "w") as f:
                            f.write(file.read().decode("utf-8"))

                        # Load metadata
                        metadata = Metadata.load(tmp_path)
                        return metadata
                    finally:
                        # Ensure cleanup even if loading fails
                        if tmp_path.exists():
                            tmp_path.unlink()
        except (KeyError, tarfile.TarError, json.JSONDecodeError):
            pass
        return None

    def validate_checksum(self, expected_checksum: str) -> bool:
        """Validate archive checksum.

        Args:
            expected_checksum: Expected SHA-256 checksum

        Returns:
            True if checksum matches
        """
        actual_checksum = calculate_checksum(self.archive_path)
        return actual_checksum == expected_checksum


def calculate_checksum(file_path: Path) -> str:
    """Calculate SHA-256 checksum of a file.

    Args:
        file_path: Path to file

    Returns:
        Hexadecimal checksum string
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def discover_sessions(
    session_dir: Path,
    tool: ToolType = "claude",
    max_sessions: int = DEFAULT_MAX_SESSIONS,
) -> List[Session]:
    """Discover all available sessions for a specific tool.

    Uses os.scandir() for improved performance on large directory trees.
    Implements depth-first search with early termination at rollout files.

    Args:
        session_dir: Path to sessions directory
        tool: Tool type (codex, opencode, claude)
        max_sessions: Maximum number of sessions to discover (default: 1000)

    Returns:
        List of Session objects, sorted by last_modified (most recent first)

    Performance Notes:
        - Codex: ~3x faster using os.scandir() vs Path.iterdir()
        - Early termination when max_sessions limit is reached
        - Depth-first search stops at valid session directories
    """
    sessions: List[Session] = []
    if not session_dir.exists():
        return sessions

    if tool == "opencode":
        # OpenCode sessions are JSON files in the global directory
        # Use os.scandir() for better performance
        try:
            with os.scandir(str(session_dir)) as entries:
                for entry in entries:
                    if len(sessions) >= max_sessions:
                        break
                    if (
                        entry.name.startswith("ses_")
                        and entry.name.endswith(".json")
                        and entry.is_file()
                    ):
                        try:
                            session_file = Path(entry.path)
                            with open(session_file) as f:
                                data = json.load(f)
                                session_id = data.get("id", session_file.stem)
                                session = Session(
                                    session_id, session_file, tool="opencode"
                                )
                                sessions.append(session)
                        except (OSError, json.JSONDecodeError):
                            continue
        except OSError:
            pass

    elif tool == "codex":
        # Codex sessions are organized by year/month in the sessions directory
        # Use os.scandir() for ~3x performance improvement vs Path.iterdir()
        try:
            with os.scandir(str(session_dir)) as year_entries:
                for year_entry in year_entries:
                    if len(sessions) >= max_sessions:
                        break
                    # Year directories are named with digits (e.g., "2024", "2025")
                    if year_entry.is_dir() and year_entry.name.isdigit():
                        try:
                            with os.scandir(year_entry.path) as month_entries:
                                for month_entry in month_entries:
                                    if len(sessions) >= max_sessions:
                                        break
                                    # Month directories are named with digits (e.g., "01", "12")
                                    if (
                                        month_entry.is_dir()
                                        and month_entry.name.isdigit()
                                    ):
                                        try:
                                            with os.scandir(
                                                month_entry.path
                                            ) as session_entries:
                                                for session_entry in session_entries:
                                                    if len(sessions) >= max_sessions:
                                                        break
                                                    # Session directories
                                                    if session_entry.is_dir():
                                                        session_path = Path(
                                                            session_entry.path
                                                        )
                                                        # Use the directory name as session_id
                                                        session = Session(
                                                            session_entry.name,
                                                            session_path,
                                                            tool="codex",
                                                        )
                                                        # Early termination: only add if conversation file exists and is a file
                                                        if session.conversation_file.is_file():
                                                            sessions.append(session)
                                        except OSError:
                                            continue
                        except OSError:
                            continue
        except OSError:
            pass

    else:
        # Claude (default) - handle both old and new formats
        # Try to detect which format we're dealing with

        # Check if history.jsonl exists (new format indicator)
        history_file = (
            session_dir.parent / "history.jsonl"
            if session_dir.name == "session-env"
            else session_dir / "history.jsonl"
        )

        # Build a mapping of sessionId -> session data from history.jsonl (new format)
        session_data_map = {}
        has_history_jsonl = False
        if history_file.exists():
            # Check file size before reading to prevent unbounded memory consumption
            try:
                file_size = history_file.stat().st_size
                if file_size > MAX_HISTORY_FILE_SIZE:
                    import logging

                    logging.warning(
                        f"History file {history_file} exceeds maximum size "
                        f"({file_size} > {MAX_HISTORY_FILE_SIZE} bytes). "
                        f"Skipping session discovery from history file."
                    )
                else:
                    has_history_jsonl = True
                    try:
                        with open(history_file) as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        data = json.loads(line)
                                        session_id = data.get("sessionId")
                                        if (
                                            session_id
                                            and session_id not in session_data_map
                                        ):
                                            # Store the first (most recent) entry for each session
                                            session_data_map[session_id] = data
                                    except json.JSONDecodeError:
                                        continue
                    except OSError:
                        pass
            except OSError:
                pass

        # Discover session directories using os.scandir() for performance
        try:
            with os.scandir(str(session_dir)) as entries:
                for entry in entries:
                    if len(sessions) >= max_sessions:
                        break
                    if entry.is_dir():
                        session_id = entry.name
                        session_path = Path(entry.path)
                        session = None

                        if has_history_jsonl and session_id in session_data_map:
                            # New format - session in session-env with data in history.jsonl
                            session = Session(
                                session_id,
                                session_path,
                                tool="claude",
                                history_data=session_data_map[session_id],
                            )
                        elif has_history_jsonl:
                            # New format session but not found in history.jsonl
                            # Pass empty dict to indicate "already checked, not found"
                            # This prevents re-scanning history.jsonl in _load_history_data
                            session = Session(
                                session_id,
                                session_path,
                                tool="claude",
                                history_data={},  # Empty dict = checked but not found
                            )
                        else:
                            # Old format - session directory with {session_id}.json file
                            conversation_file = session_path / f"{session_id}.json"
                            if conversation_file.exists():
                                session = Session(
                                    session_id, session_path, tool="claude"
                                )

                        if session:
                            sessions.append(session)
        except OSError:
            pass

    return sorted(sessions, key=lambda s: s.last_modified or datetime.min, reverse=True)


def discover_archives(archive_dir: Path) -> List[Archive]:
    """Discover all available archives.

    Uses os.scandir() for improved performance over glob().

    Args:
        archive_dir: Path to archives directory

    Returns:
        List of Archive objects, sorted by modification time (most recent first)

    Performance Notes:
        - Uses os.scandir() for better performance vs glob()
        - Filters files in C for reduced system calls
    """
    archives: List[Archive] = []
    if not archive_dir.exists():
        return archives

    # Match both old format (session-*.tgz) and new format (tool-session-*.tgz or tool-sessions-*.tgz)
    # Use os.scandir() for better performance
    try:
        with os.scandir(str(archive_dir)) as entries:
            for entry in entries:
                if (
                    entry.is_file()
                    and entry.name.endswith(".tgz")
                    and ("session-" in entry.name or "sessions-" in entry.name)
                ):
                    archive = Archive(Path(entry.path))
                    archives.append(archive)
    except OSError:
        pass

    return sorted(archives, key=lambda a: a.archive_path.stat().st_mtime, reverse=True)


def _build_archive_contents(
    tar: tarfile.TarFile,
    sessions: List[Session],
    config_dir: Path,
) -> int:
    """Add tool-specific files to a tar archive.

    This private helper function handles the file collection logic for all
    supported tools (claude, codex, opencode) and is used by both single
    and multi-session archive creation.

    Args:
        tar: Open tarfile.TarFile object (write mode)
        sessions: List of Session objects to archive
        config_dir: Path to config directory

    Returns:
        Number of files added to the archive
    """
    file_count = 0

    # Determine tool type from first session
    if not sessions:
        return file_count

    tool = sessions[0].tool

    if tool == "opencode":
        for session in sessions:
            # Add the main session JSON file
            if session.conversation_file.exists():
                tar.add(
                    session.conversation_file,
                    arcname=session.conversation_file.name,
                )
                file_count += 1

            # Add message storage directory
            message_dir = config_dir / "storage" / "message" / session.session_id
            if message_dir.exists():
                for item in message_dir.rglob("*"):
                    if item.is_file():
                        rel_path = item.relative_to(config_dir)
                        tar.add(item, arcname=f"opencode/{rel_path}")
                        file_count += 1

            # Add part files (large data files matching session ID)
            part_dir = config_dir / "storage" / "part"
            if part_dir.exists():
                for part_file in part_dir.glob(f"{session.session_id}*"):
                    rel_path = part_file.relative_to(config_dir)
                    tar.add(part_file, arcname=f"opencode/{rel_path}")
                    file_count += 1

            # Add directory-readme metadata
            readme_file = (
                config_dir
                / "storage"
                / "directory-readme"
                / f"{session.session_id}.json"
            )
            if readme_file.exists():
                rel_path = readme_file.relative_to(config_dir)
                tar.add(readme_file, arcname=f"opencode/{rel_path}")
                file_count += 1

    elif tool == "codex":
        for session in sessions:
            # Add the entire codex session directory
            if session.session_path.is_dir():
                for item in session.session_path.rglob("*"):
                    if item.is_file():
                        try:
                            rel_path = item.relative_to(config_dir)
                            tar.add(item, arcname=f".codex/{rel_path}")
                        except ValueError:
                            rel_path = item.relative_to(session.session_path)
                            tar.add(
                                item,
                                arcname=f".codex/sessions/{session.session_id}/{rel_path}",
                            )
                        file_count += 1

        # Add codex config files if available (only once for multi-session)
        # SECURITY: Only include non-auth config files
        codex_config_dir = config_dir
        if codex_config_dir.exists():
            for config_file in ["config.toml"]:
                config_path = codex_config_dir / config_file
                if config_path.exists() and not _is_auth_file(config_path):
                    tar.add(config_path, arcname=f".codex/{config_file}")
                    file_count += 1

    else:  # claude (default)
        session = sessions[0]  # For claude, primarily use first session

        # Handle both old and new formats
        # Check if it's old format (conversation_file is a JSON file)
        if session.conversation_file.exists() and session.conversation_file.is_file():
            # Old format - add the conversation JSON file
            tar.add(
                session.conversation_file,
                arcname=session.conversation_file.name,
            )
            file_count += 1
        else:
            # New format - add history.jsonl and session-env directories
            history_file = config_dir / "history.jsonl"

            # Add history.jsonl (contains all session conversations)
            if history_file.exists():
                import tempfile

                allowed_ids = {s.session_id for s in sessions}
                tmp_path = None
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="w",
                        delete=False,
                        encoding="utf-8",
                        prefix="claude-history-",
                        suffix=".jsonl",
                    ) as tmp:
                        tmp_path = Path(tmp.name)
                        with open(history_file, encoding="utf-8") as f:
                            for line in f:
                                line_stripped = line.strip()
                                if not line_stripped:
                                    continue
                                if line_stripped.startswith("#"):
                                    tmp.write(line_stripped + "\n")
                                    continue
                                try:
                                    data = json.loads(line_stripped)
                                except json.JSONDecodeError:
                                    continue
                                if (
                                    isinstance(data, dict)
                                    and data.get("sessionId") in allowed_ids
                                ):
                                    tmp.write(line_stripped + "\n")
                    tar.add(tmp_path, arcname=".claude/history.jsonl")
                    file_count += 1
                finally:
                    if tmp_path is not None:
                        try:
                            tmp_path.unlink()
                        except OSError:
                            pass

            # Add the session's environment directories from session-env
            for session in sessions:
                if session.session_path.is_dir():
                    # Add with session-env/{sessionId}/ structure
                    for item in session.session_path.rglob("*"):
                        if item.is_file():
                            rel_path = item.relative_to(config_dir)
                            tar.add(item, arcname=f".claude/{rel_path}")
                            file_count += 1

        # Add .claude directory contents (config, settings, etc.)
        # SECURITY: Exclude auth-related files (tokens, credentials, etc.)
        if config_dir.exists():
            for item in config_dir.rglob("*"):
                if item.is_file():
                    # Skip history.jsonl (already added) and session-env (already handled)
                    # Also skip old format session directories (sessions/{id}/)
                    if "history.jsonl" not in str(item) and "session-env" not in str(
                        item
                    ):
                        # Check if it's not in the old sessions directory
                        if "sessions" not in str(item.relative_to(config_dir)):
                            # SECURITY: Skip auth-related files
                            if _is_auth_file(item):
                                logger.debug(
                                    f"Excluding auth file from archive: {item.name}"
                                )
                                continue
                            # Add with relative path from .claude directory
                            arcname = f".claude/{item.relative_to(config_dir)}"
                            tar.add(item, arcname=arcname)
                            file_count += 1

    return file_count


def create_archive(
    session: Session, config_dir: Path, output_dir: Path, hostname: str
) -> Path:
    """Create a session archive.

    Args:
        session: Session to archive
        config_dir: Path to config directory (.claude, .codex, or .local/share/opencode)
        output_dir: Directory to save archive
        hostname: Hostname of source machine

    Returns:
        Path to created archive

    Raises:
        IOError: If archive creation fails
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tool_prefix = session.tool
    archive_filename = f"{tool_prefix}-session-{session.session_id}-{timestamp}.tgz"
    archive_path = output_dir / archive_filename

    import gzip
    import shutil
    import tempfile

    # Create temporary directory for archive contents
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Strategy: Create tar file first (uncompressed), add metadata, then compress once
        # This avoids double compression of the archive contents
        temp_tar = temp_path / "archive.tar"
        temp_tgz = temp_path / "archive.tgz"

        # Create uncompressed tar archive
        with tarfile.open(temp_tar, "w") as tar:
            # Use shared helper to add archive contents
            file_count = _build_archive_contents(tar, [session], config_dir)

        # Calculate checksum of the uncompressed tar
        tar_checksum = calculate_checksum(temp_tar)

        # Create metadata file with checksum
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname=hostname,
            session=session,
            archive_filename=archive_filename,
            checksum_sha256=tar_checksum,
            size_bytes=temp_tar.stat().st_size,
            file_count=file_count,
        )

        # Save metadata to temporary file
        metadata_file = temp_path / "metadata.json"
        metadata.save(metadata_file)

        # Append metadata to the tar file (tar supports appending!)
        with tarfile.open(temp_tar, "a") as tar:
            tar.add(metadata_file, arcname="metadata.json")

        # Now compress the tar file to create the final .tgz
        # This is the ONLY compression pass
        with open(temp_tar, "rb") as f_in:
            with gzip.open(temp_tgz, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Move compressed archive to final location
        shutil.move(str(temp_tgz), str(archive_path))

    return archive_path


def create_archive_multiple(
    sessions: List[Session],
    config_dir: Path,
    output_dir: Path,
    hostname: str,
    archive_name: str,
) -> Path:
    """Create a multi-session archive.

    Args:
        sessions: List of Sessions to archive
        config_dir: Path to config directory (.claude, .codex, or .local/share/opencode)
        output_dir: Directory to save archive
        hostname: Hostname of source machine
        archive_name: Name for the archive file

    Returns:
        Path to created archive

    Raises:
        IOError: If archive creation fails
    """
    archive_path = output_dir / archive_name

    import shutil
    import tempfile

    # Create temporary directory for archive contents
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)

        # Create temporary archive
        temp_archive = temp_path / "temp_archive.tgz"

        # Create archive using shared helper
        with tarfile.open(temp_archive, "w:gz") as tar:
            file_count = _build_archive_contents(tar, sessions, config_dir)

        # Move temp archive to final location
        shutil.move(str(temp_archive), str(archive_path))

        # Calculate checksum
        checksum = calculate_checksum(archive_path)

        # Create metadata with checksum (use first session as representative)
        representative_session = sessions[0]
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname=hostname,
            session=representative_session,
            archive_filename=archive_name,
            checksum_sha256=checksum,
            size_bytes=archive_path.stat().st_size,
            file_count=file_count,
        )

        # Add note about multiple sessions to metadata
        metadata_dict = metadata.to_dict()
        if len(sessions) > 1:
            metadata_dict["session_count"] = len(sessions)
            metadata_dict["all_session_ids"] = [s.session_id for s in sessions]

        # Save metadata to temporary file
        metadata_placeholder = temp_path / "metadata.json"
        with open(metadata_placeholder, "w") as f:
            json.dump(metadata_dict, f, indent=2)

        # Create final archive with metadata
        final_archive = temp_path / "final_archive.tgz"

        with tarfile.open(final_archive, "w:gz") as tar:
            # Add all files from original archive
            with tarfile.open(archive_path, "r:gz") as original_tar:
                for member in original_tar.getmembers():
                    extracted_file = original_tar.extractfile(member)
                    if extracted_file:
                        import io

                        content = extracted_file.read()
                        tarinfo = tarfile.TarInfo(name=member.name)
                        tarinfo.size = len(content)
                        tarinfo.mtime = member.mtime
                        tarinfo.mode = member.mode
                        tar.addfile(tarinfo, io.BytesIO(content))

            # Add metadata
            tar.add(metadata_placeholder, arcname="metadata.json")

        # Replace original archive with final archive
        shutil.move(str(final_archive), str(archive_path))

    return archive_path


def _is_auth_file(file_path: Path) -> bool:
    """Check if a file is an authentication/credentials file that should be excluded.

    These files should never be exported as they contain sensitive credentials
    that are machine-specific or user-specific.

    Args:
        file_path: Path to the file to check

    Returns:
        True if the file is auth-related and should be excluded
    """
    file_name = file_path.name.lower()

    # Check against known auth file patterns
    for pattern in _AUTH_FILE_PATTERNS:
        if pattern.lower() in file_name:
            return True

    # Check for files containing "token", "auth", "credential", "secret" in name
    auth_keywords = ["token", "auth", "credential", "secret", "api_key", "password"]
    for keyword in auth_keywords:
        if keyword in file_name:
            return True

    return False


def _is_safe_tar_member(member: tarfile.TarInfo, target_dir: Path) -> bool:
    """Validate that a tar archive member is safe for extraction.

    This function checks for:
    - Absolute paths (e.g., /etc/passwd)
    - Path traversal attempts (e.g., ../../../etc/passwd)
    - Suspiciously long paths (potential buffer overflow)

    Args:
        member: TarInfo object representing the archive member
        target_dir: Target directory for extraction

    Returns:
        True if the member is safe to extract, False otherwise

    Raises:
        ValueError: If the member contains malicious paths
    """
    # Check for absolute paths (security risk)
    if os.path.isabs(member.name):
        raise ValueError(
            f"Archive contains absolute path '{member.name}'. "
            "This is a security risk and could overwrite system files."
        )

    # Check for path traversal attempts
    if ".." in member.name.split(os.sep):
        raise ValueError(
            f"Archive contains path traversal attempt '{member.name}'. "
            "This could allow extraction outside the target directory."
        )

    # Resolve the full destination path
    dest_path = (target_dir / member.name).resolve()

    # Ensure the resolved path is within target_dir
    target_resolved = target_dir.resolve()
    try:
        dest_path.relative_to(target_resolved)
    except ValueError:
        raise ValueError(
            f"Archive member '{member.name}' would extract outside "
            f"target directory '{target_dir}'. This is a security risk."
        ) from None

    # Check for suspiciously long paths (potential DOS via path length)
    if len(member.name) > 255:
        raise ValueError(
            f"Archive member name exceeds maximum length (255 characters): '{member.name[:50]}...'"
        )

    # Check for symlinks that could escape the target directory
    if member.issym():
        # Get symlink target
        link_target = member.linkname

        # Check if symlink target is absolute
        if os.path.isabs(link_target):
            raise ValueError(
                f"Archive contains absolute symlink '{member.name}' -> '{link_target}'. "
                "This is a security risk."
            )

        # Check if symlink target contains path traversal
        if ".." in link_target.split(os.sep):
            raise ValueError(
                f"Archive contains symlink with path traversal '{member.name}' -> '{link_target}'. "
                "This is a security risk."
            )

        # Resolve where the symlink would ultimately point
        # The symlink will be at target_dir/member.name
        # and will point to link_target (relative to symlink location)
        symlink_dir = (target_dir / member.name).parent
        ultimate_target = (symlink_dir / link_target).resolve()

        # Ensure the ultimate target is within target_dir
        target_resolved = target_dir.resolve()
        try:
            ultimate_target.relative_to(target_resolved)
        except ValueError:
            raise ValueError(
                f"Archive symlink '{member.name}' -> '{link_target}' would point "
                f"outside target directory to '{ultimate_target}'. This is a security risk."
            ) from None

    return True


def _calculate_extraction_size(tar: tarfile.TarFile) -> int:
    """Calculate the total uncompressed size of all archive members.

    Args:
        tar: Open TarFile object

    Returns:
        Total size in bytes
    """
    total_size = 0
    for member in tar.getmembers():
        if member.isfile():
            total_size += member.size
    return total_size


def extract_archive(
    archive_path: Path, target_dir: Path, max_size_gb: float = 10.0
) -> bool:
    """Extract a session archive with security validation.

    This function performs security checks before extraction:
    - Validates all file paths (no absolute paths, no path traversal)
    - Checks maximum extraction size to prevent archive bombs
    - Iteratively extracts files with validation for each member

    Args:
        archive_path: Path to archive file
        target_dir: Target directory for extraction
        max_size_gb: Maximum uncompressed size allowed in GB (default: 10.0)

    Returns:
        True if extraction successful

    Raises:
        IOError: If extraction fails
        ValueError: If archive contains malicious paths or exceeds size limit
    """
    # Detect tool type from archive metadata or filename prefix
    tool = None
    tmp_path = None
    import tempfile

    try:
        # First pass: validate archive structure and detect tool type
        with tarfile.open(archive_path, "r:gz") as temp_tar:
            # Check total extraction size (archive bomb protection)
            total_size = _calculate_extraction_size(temp_tar)
            max_size_bytes = max_size_gb * 1024 * 1024 * 1024
            if total_size > max_size_bytes:
                raise ValueError(
                    f"Archive uncompressed size ({total_size / (1024**3):.2f} GB) "
                    f"exceeds maximum allowed size ({max_size_gb} GB). "
                    "This may be an archive bomb attack."
                )

            # Validate all members for path traversal and absolute paths
            for member in temp_tar.getmembers():
                try:
                    _is_safe_tar_member(member, target_dir)
                except ValueError as e:
                    raise ValueError(
                        f"Security validation failed for archive member '{member.name}': {e}"
                    ) from e

            # Reset to read metadata
            if temp_tar.fileobj is not None:
                temp_tar.fileobj.seek(0)
            else:
                raise OSError("Cannot seek in tar file - fileobj is None")

            try:
                metadata_json = temp_tar.extractfile("metadata.json")
                if metadata_json is not None:
                    with tempfile.NamedTemporaryFile(
                        mode="w", delete=False, suffix=".json"
                    ) as tmp:
                        tmp.write(metadata_json.read().decode("utf-8"))
                        tmp_path = Path(tmp.name)

                try:
                    if tmp_path:
                        metadata = Metadata.load(tmp_path)
                        tool = metadata.session.tool
                finally:
                    if tmp_path and tmp_path.exists():
                        tmp_path.unlink()
            except (KeyError, Exception):
                # Try to detect from filename prefix
                if "codex-session-" in archive_path.name:
                    tool = "codex"
                elif "opencode-session-" in archive_path.name:
                    tool = "opencode"
                else:
                    tool = "claude"

        # Second pass: extract with validated paths
        with tarfile.open(archive_path, "r:gz") as tar:
            if tool == "opencode":
                # For OpenCode archives, extract files to correct locations
                # Files are stored with "opencode/" prefix in archive
                opencode_storage = Path.home() / ".local" / "share" / "opencode"

                extracted_paths = []
                for member in tar.getmembers():
                    if member.name == "metadata.json":
                        # Extract metadata to target directory
                        file = tar.extractfile(member)
                        if file:
                            dest_path = target_dir / "metadata.json"
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(dest_path, "wb") as f:
                                f.write(file.read())
                            extracted_paths.append(dest_path)
                    elif member.name.startswith("opencode/"):
                        # Extract OpenCode files to their correct locations
                        # Remove "opencode/" prefix and add to opencode storage
                        file = tar.extractfile(member)
                        if file:
                            rel_path = member.name[len("opencode/") :]
                            dest_path = opencode_storage / rel_path
                            dest_path.parent.mkdir(parents=True, exist_ok=True)
                            with open(dest_path, "wb") as f:
                                f.write(file.read())
                            extracted_paths.append(dest_path)
                    elif not member.name.startswith(
                        "opencode/"
                    ) and member.name.endswith(".json"):
                        # Handle old format archives without opencode/ prefix
                        # Extract session JSON file to global session directory
                        file = tar.extractfile(member)
                        if file:
                            session_global_dir = (
                                opencode_storage / "storage" / "session" / "global"
                            )
                            session_global_dir.mkdir(parents=True, exist_ok=True)
                            dest_path = session_global_dir / member.name
                            with open(dest_path, "wb") as f:
                                f.write(file.read())
                            extracted_paths.append(dest_path)

                # Sanitize file permissions for all extracted files
                for path in extracted_paths:
                    if path.exists():
                        _sanitize_file_permissions(path)
            else:
                # For Claude and Codex, extract all files preserving permissions
                # Use iterative extraction with security validation
                extracted_paths = []
                for member in tar.getmembers():
                    # Extra validation (already validated but double-check)
                    _is_safe_tar_member(member, target_dir)

                    # Extract the member safely
                    tar.extract(member, target_dir)

                    # Track extracted path for permission sanitization
                    extracted_path = target_dir / member.name
                    extracted_paths.append(extracted_path)

                # Sanitize file permissions to prevent privilege escalation
                # Remove setuid/setgid/sticky bits and limit maximum permissions
                for path in extracted_paths:
                    if path.exists():
                        _sanitize_file_permissions(path)

                # Move files to appropriate locations
                # Session files go to ~/.claude/sessions/
                # .claude directory goes to home directory
                # This is handled by the archive structure
        return True
    except tarfile.TarError as e:
        raise OSError(f"Failed to extract archive: {e}") from e
    except ValueError as e:
        # Re-raise ValueError with context
        raise OSError(f"Archive security validation failed: {e}") from e


def _sanitize_file_permissions(path: Path) -> None:
    """Sanitize file permissions to prevent privilege escalation.

    Removes setuid/setgid/sticky bits and limits maximum permissions.
    This prevents malicious archives from setting dangerous permissions.

    Args:
        path: Path to file or directory to sanitize
    """
    import stat

    try:
        current_mode = path.stat().st_mode

        # Remove setuid, setgid, and sticky bits
        sanitized_mode = current_mode & ~(stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)

        # Limit maximum permissions
        if path.is_dir():
            # Directories: maximum 0o755 (rwxr-xr-x)
            max_mode = 0o755
        else:
            # Files: maximum 0o644 (rw-r--r--)
            max_mode = 0o644

        # Apply the more restrictive of current permissions and max
        final_mode = sanitized_mode & max_mode

        # Apply the sanitized permissions
        path.chmod(final_mode)
    except OSError:
        # If we can't read/modify permissions, log but don't fail
        # This handles cases where we don't have ownership
        pass


def get_hostname() -> str:
    """Get system hostname.

    Returns:
        Hostname string
    """
    import socket

    return socket.gethostname()


def check_disk_space(path: Path, required_bytes: int) -> bool:
    """Check if sufficient disk space is available.

    Args:
        path: Path to check
        required_bytes: Required space in bytes

    Returns:
        True if sufficient space available
    """
    stat = os.statvfs(path)
    available_bytes = stat.f_bavail * stat.f_frsize
    return available_bytes >= required_bytes


def ensure_directory(path: Path) -> bool:
    """Ensure directory exists, create if necessary.

    Args:
        path: Directory path

    Returns:
        True if directory exists or was created
    """
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True
    except OSError:
        return False
