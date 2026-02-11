"""Tests for tool-specific session handling (codex, opencode)."""

import json
import tarfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from session_sync.core import (
    Metadata,
    Session,
    create_archive,
    create_archive_multiple,
    discover_sessions,
    extract_archive,
)


class TestOpenCodeSession:
    """Test OpenCode session handling."""

    def test_opencode_session_initialization(self, tmp_path):
        """Test OpenCode session initialization."""
        session_file = tmp_path / "ses_test123.json"

        session_data = {
            "id": "ses_test123",
            "title": "Test OpenCode Session",
            "createdAt": "2025-01-15T10:30:00",
            "updatedAt": "2025-02-07T14:20:00",
        }
        session_file.write_text(json.dumps(session_data))

        session = Session("ses_test123", session_file, tool="opencode")

        assert session.session_id == "ses_test123"
        assert session.tool == "opencode"
        assert session.conversation_file == session_file

    def test_opencode_session_name(self, tmp_path):
        """Test getting OpenCode session name."""
        session_file = tmp_path / "ses_test.json"

        session_data = {"id": "ses_test", "title": "Test OpenCode Session"}
        session_file.write_text(json.dumps(session_data))

        session = Session("ses_test", session_file, tool="opencode")

        assert session.name == "Test OpenCode Session"

    def test_opencode_session_timestamps(self, tmp_path):
        """Test getting OpenCode session timestamps."""
        session_file = tmp_path / "ses_test.json"

        session_data = {
            "id": "ses_test",
            "title": "Test",
            "createdAt": "2025-01-15T10:30:00",
            "updatedAt": "2025-02-07T14:20:00",
        }
        session_file.write_text(json.dumps(session_data))

        session = Session("ses_test", session_file, tool="opencode")

        assert session.created_at == datetime(2025, 1, 15, 10, 30, 0)
        assert session.last_modified == datetime(2025, 2, 7, 14, 20, 0)

    def test_opencode_session_size(self, tmp_path):
        """Test getting OpenCode session size."""
        session_file = tmp_path / "ses_test.json"
        session_file.write_text('{"test": "data"}')

        session = Session("ses_test", session_file, tool="opencode")

        assert session.size_bytes == len('{"test": "data"}')

    def test_discover_opencode_sessions(self, tmp_path):
        """Test discovering OpenCode sessions."""
        # Create OpenCode-style session files with different timestamps
        import time

        for i in range(3):
            session_data = {
                "id": f"ses_{i:03d}",
                "title": f"Session {i}",
                "createdAt": "2025-01-15T10:30:00",
                "updatedAt": f"2025-02-07T14:{20 + i}:00",  # Different timestamps
            }
            session_file = tmp_path / f"ses_{i:03d}.json"
            session_file.write_text(json.dumps(session_data))
            time.sleep(0.01)  # Ensure different file modification times

        sessions = discover_sessions(tmp_path, tool="opencode")

        assert len(sessions) == 3
        assert all(s.tool == "opencode" for s in sessions)
        # Sessions should be sorted by last_modified (most recent first)
        assert [s.session_id for s in sessions] == ["ses_002", "ses_001", "ses_000"]


class TestCodexSession:
    """Test Codex session handling."""

    def test_codex_session_initialization(self, tmp_path):
        """Test Codex session initialization."""
        session_path = tmp_path / "2026" / "01" / "test-session"
        session_path.mkdir(parents=True)

        # Create a rollout JSONL file
        rollout_file = session_path / "rollout-test.jsonl"
        rollout_file.write_text('{"test": "data"}')

        session = Session("test-session", session_path, tool="codex")

        assert session.session_id == "test-session"
        assert session.tool == "codex"
        assert session.conversation_file == rollout_file

    def test_codex_session_name(self, tmp_path):
        """Test getting Codex session name."""
        session_path = tmp_path / "2026" / "01" / "test-session"
        session_path.mkdir(parents=True)

        rollout_file = session_path / "rollout-test.jsonl"
        rollout_file.write_text('{"test": "data"}')

        session = Session("test-session", session_path, tool="codex")

        # Codex uses session_id as name since JSONL doesn't have titles
        assert session.name == "test-session"

    def test_codex_session_size(self, tmp_path):
        """Test getting Codex session size."""
        session_path = tmp_path / "2026" / "01" / "test-session"
        session_path.mkdir(parents=True)

        # Create multiple files
        (session_path / "rollout-1.jsonl").write_text("x" * 100)
        (session_path / "rollout-2.jsonl").write_text("y" * 200)

        session = Session("test-session", session_path, tool="codex")

        assert session.size_bytes == 300

    def test_discover_codex_sessions(self, tmp_path):
        """Test discovering Codex sessions."""
        # Create Codex-style directory structure
        sessions_root = tmp_path / ".codex" / "sessions"
        for i in range(2):
            year_dir = sessions_root / "2026"
            year_dir.mkdir(parents=True, exist_ok=True)
            month_dir = year_dir / f"{i + 1:02d}"
            month_dir.mkdir()

            for j in range(2):
                session_path = month_dir / f"session-{i}-{j}"
                session_path.mkdir()
                (session_path / f"rollout-{i}-{j}.jsonl").write_text('{"test": "data"}')

        sessions = discover_sessions(sessions_root, tool="codex")

        assert len(sessions) == 4
        assert all(s.tool == "codex" for s in sessions)
        assert all("/" in s.session_id for s in sessions)


class TestToolMetadata:
    """Test metadata with different tool types."""

    def test_metadata_with_opencode_tool(self, tmp_path):
        """Test metadata for OpenCode session."""
        session_file = tmp_path / "ses_test.json"
        session_data = {
            "id": "ses_test",
            "title": "Test Session",
            "createdAt": "2025-01-15T10:30:00",
            "updatedAt": "2025-02-07T14:20:00",
        }
        session_file.write_text(json.dumps(session_data))

        session = Session("ses_test", session_file, tool="opencode")
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname="test-host",
            session=session,
            archive_filename="opencode-session-test.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=1,
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["tool"] == "opencode"
        assert metadata_dict["contents"]["type"] == "opencode_session"

    def test_metadata_with_codex_tool(self, tmp_path):
        """Test metadata for Codex session."""
        session_path = tmp_path / "2026" / "01" / "test-session"
        session_path.mkdir(parents=True)
        rollout_file = session_path / "rollout-test.jsonl"
        rollout_file.write_text('{"test": "data"}')

        session = Session("test-session", session_path, tool="codex")
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname="test-host",
            session=session,
            archive_filename="codex-session-test.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=1,
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["tool"] == "codex"
        assert metadata_dict["contents"]["type"] == "codex_session"

    def test_metadata_with_claude_tool(self, tmp_path):
        """Test metadata for Claude session (default)."""
        session_path = tmp_path / "sess-test"
        session_path.mkdir()
        conversation_file = session_path / "sess-test.json"
        conversation_file.write_text('{"title": "Test"}')

        session = Session("sess-test", session_path, tool="claude")
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname="test-host",
            session=session,
            archive_filename="claude-session-test.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=2,
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["tool"] == "claude"
        assert metadata_dict["contents"]["type"] == "claude_session"


class TestCreateArchiveWithTools:
    """Test archive creation with different tool types."""

    def test_create_opencode_archive(self, tmp_path):
        """Test creating OpenCode archive."""
        # Create OpenCode session
        session_file = tmp_path / "ses_test.json"
        session_data = {
            "id": "ses_test",
            "title": "Test OpenCode Session",
            "createdAt": "2025-01-15T10:30:00",
            "updatedAt": "2025-02-07T14:20:00",
        }
        session_file.write_text(json.dumps(session_data))

        session = Session("ses_test", session_file, tool="opencode")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive(
                session=session,
                config_dir=tmp_path,  # Not used for opencode
                output_dir=output_dir,
                hostname="test-host",
            )

        assert archive_path.exists()
        assert archive_path.name.startswith("opencode-session-ses_test-")

        # Verify archive contains the session file
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            assert "ses_test.json" in members
            assert "metadata.json" in members

    def test_create_codex_archive(self, tmp_path):
        """Test creating Codex archive."""
        # Create Codex session
        session_path = tmp_path / "2026" / "01" / "test-session"
        session_path.mkdir(parents=True)
        rollout_file = session_path / "rollout-test.jsonl"
        rollout_file.write_text('{"test": "data"}')

        session = Session("test-session", session_path, tool="codex")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create .codex config directory
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text('[test]\nkey = "value"')

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive(
                session=session,
                config_dir=codex_dir,
                output_dir=output_dir,
                hostname="test-host",
            )

        assert archive_path.exists()
        assert archive_path.name.startswith("codex-session-test-session-")

        # Verify archive contains session files and config
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            # Should contain the session directory structure
            assert any("rollout-test.jsonl" in m for m in members)
            assert "metadata.json" in members


class TestClaudeSession:
    """Test Claude Code session handling."""

    def test_claude_session_initialization(self, tmp_path):
        """Test Claude session initialization with history data."""
        session_path = tmp_path / "session-env" / "abc123-def456-ghi789"
        session_path.mkdir(parents=True)

        history_data = {
            "sessionId": "abc123-def456-ghi789",
            "display": "Test Claude Session",
            "timestamp": 1764389932342,
            "project": "/home/user/project",
        }

        session = Session(
            "abc123-def456-ghi789",
            session_path,
            tool="claude",
            history_data=history_data,
        )

        assert session.session_id == "abc123-def456-ghi789"
        assert session.tool == "claude"
        assert session.session_path == session_path

    def test_claude_session_name(self, tmp_path):
        """Test getting Claude session name from history data."""
        session_path = tmp_path / "session-env" / "test-session-id"
        session_path.mkdir(parents=True)

        history_data = {
            "sessionId": "test-session-id",
            "display": "My Claude Code Session",
            "timestamp": 1764389932342,
        }

        session = Session(
            "test-session-id", session_path, tool="claude", history_data=history_data
        )

        assert session.name == "My Claude Code Session"

    def test_claude_session_name_truncation(self, tmp_path):
        """Test that long Claude session names are truncated."""
        session_path = tmp_path / "session-env" / "test-session"
        session_path.mkdir(parents=True)

        long_display = "This is a very long session name that should be truncated " * 10
        history_data = {
            "sessionId": "test-session",
            "display": long_display,
            "timestamp": 1764389932342,
        }

        session = Session(
            "test-session", session_path, tool="claude", history_data=history_data
        )

        assert len(session.name) <= 100
        assert session.name.endswith("...")

    def test_claude_session_timestamp(self, tmp_path):
        """Test getting Claude session timestamp from history data."""
        session_path = tmp_path / "session-env" / "test-session"
        session_path.mkdir(parents=True)

        history_data = {
            "sessionId": "test-session",
            "display": "Test Session",
            "timestamp": 1764389932342,  # milliseconds since epoch
        }

        session = Session(
            "test-session", session_path, tool="claude", history_data=history_data
        )

        expected_time = datetime.fromtimestamp(1764389932342 / 1000)
        assert session.created_at == expected_time
        assert session.last_modified == expected_time

    def test_claude_session_size(self, tmp_path):
        """Test getting Claude session size."""
        session_path = tmp_path / "session-env" / "test-session"
        session_path.mkdir(parents=True)

        # Create some files in the session directory
        (session_path / "file1.txt").write_text("x" * 500)
        (session_path / "file2.txt").write_text("y" * 300)

        history_data = {
            "sessionId": "test-session",
            "display": "Test",
            "timestamp": 1764389932342,
        }

        session = Session(
            "test-session", session_path, tool="claude", history_data=history_data
        )

        assert session.size_bytes == 800

    def test_claude_session_size_empty_directory(self, tmp_path):
        """Test that empty Claude session directories return minimal size."""
        session_path = tmp_path / "session-env" / "empty-session"
        session_path.mkdir(parents=True)

        history_data = {
            "sessionId": "empty-session",
            "display": "Empty Session",
            "timestamp": 1764389932342,
        }

        session = Session(
            "empty-session", session_path, tool="claude", history_data=history_data
        )

        # Empty directories should return minimal placeholder size
        assert session.size_bytes == 1024

    def test_discover_claude_sessions(self, tmp_path, monkeypatch):
        """Test discovering Claude sessions from history.jsonl."""
        # Create session-env directory structure
        session_env_dir = tmp_path / "session-env"
        session_env_dir.mkdir()

        session_ids = ["session-001", "session-002", "session-003"]
        for sid in session_ids:
            (session_env_dir / sid).mkdir()

        # Create a mock history.jsonl file
        history_file = tmp_path / "history.jsonl"
        history_entries = []
        for i, sid in enumerate(session_ids):
            entry = {
                "sessionId": sid,
                "display": f"Session {i}",
                "timestamp": 1764389932342 + (i * 1000),
                "project": f"/project/{i}",
            }
            history_entries.append(json.dumps(entry))

        history_file.write_text("\n".join(history_entries))

        # Patch Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        sessions = discover_sessions(session_env_dir, tool="claude")

        assert len(sessions) == 3
        assert all(s.tool == "claude" for s in sessions)
        # Sessions are sorted by last_modified (timestamp) descending
        # So session-003 (latest) comes first
        assert [s.session_id for s in sessions] == [
            "session-003",
            "session-002",
            "session-001",
        ]

    def test_create_claude_archive(self, tmp_path, monkeypatch):
        """Test creating Claude archive with history.jsonl."""
        # Create session-env directory
        session_env_dir = tmp_path / "session-env"
        session_env_dir.mkdir()

        session_path = session_env_dir / "test-session-id"
        session_path.mkdir()

        # Create .claude config directory
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()

        # Create history.jsonl in the .claude directory
        history_file = claude_dir / "history.jsonl"
        history_data = {
            "sessionId": "test-session-id",
            "display": "Test Claude Session",
            "timestamp": 1764389932342,
            "project": "/home/user/project",
        }
        history_file.write_text(json.dumps(history_data))

        # Create other config files
        (claude_dir / "settings.json").write_text('{"test": "value"}')

        session = Session(
            "test-session-id", session_path, tool="claude", history_data=history_data
        )

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Patch Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive(
                session=session,
                config_dir=claude_dir,
                output_dir=output_dir,
                hostname="test-host",
            )

        assert archive_path.exists()
        assert archive_path.name.startswith("claude-session-test-session-id-")

        # Verify archive contains history.jsonl and config files
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            assert ".claude/history.jsonl" in members
            assert ".claude/settings.json" in members
            assert "metadata.json" in members

    def test_claude_metadata(self, tmp_path):
        """Test metadata for Claude session."""
        session_path = tmp_path / "session-env" / "test-session"
        session_path.mkdir(parents=True)

        history_data = {
            "sessionId": "test-session",
            "display": "Test Claude Session",
            "timestamp": 1764389932342,
        }

        session = Session(
            "test-session", session_path, tool="claude", history_data=history_data
        )
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname="test-host",
            session=session,
            archive_filename="claude-session-test.tgz",
            checksum_sha256="abc123",
            size_bytes=2048,
            file_count=3,
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["tool"] == "claude"
        assert metadata_dict["contents"]["type"] == "claude_session"
        assert "conversation_history" in metadata_dict["contents"]
        assert "session_env" in metadata_dict["contents"]


class TestMultiSessionExport:
    """Test multi-session export functionality."""

    def test_export_multiple_opencode_sessions(self, tmp_path):
        """Test exporting multiple OpenCode sessions with storage files."""
        # Create multiple OpenCode sessions
        sessions = []
        opencode_config = tmp_path / ".opencode"
        storage_dir = opencode_config / "storage"
        message_dir = storage_dir / "message"
        part_dir = storage_dir / "part"
        readme_dir = storage_dir / "directory-readme"

        for i in range(3):
            session_id = f"ses_{i:03d}"
            session_file = tmp_path / f"{session_id}.json"
            session_data = {
                "id": session_id,
                "title": f"OpenCode Session {i}",
                "createdAt": "2025-01-15T10:30:00",
                "updatedAt": f"2025-02-07T14:{20 + i}:00",
            }
            session_file.write_text(json.dumps(session_data))

            session = Session(session_id, session_file, tool="opencode")
            sessions.append(session)

            # Create message storage
            session_msg_dir = message_dir / session_id
            session_msg_dir.mkdir(parents=True)
            (session_msg_dir / "msg1.txt").write_text(f"message {i}")
            (session_msg_dir / "msg2.txt").write_text(f"message {i}b")

            # Create part files
            part_file = part_dir / f"{session_id}_part1.bin"
            part_dir.mkdir(parents=True, exist_ok=True)
            part_file.write_bytes(b"part data")

            # Create readme metadata
            readme_dir.mkdir(parents=True, exist_ok=True)
            readme_file = readme_dir / f"{session_id}.json"
            readme_file.write_text(json.dumps({"readme": f"data {i}"}))

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        archive_name = "opencode-multiple-test.tgz"

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive_multiple(
                sessions=sessions,
                config_dir=opencode_config,
                output_dir=output_dir,
                hostname="test-host",
                archive_name=archive_name,
            )

        assert archive_path.exists()

        # Verify archive contains all session data
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            # Should have session JSON files
            assert "ses_000.json" in members
            assert "ses_001.json" in members
            assert "ses_002.json" in members
            # Should have message storage
            assert any("message/ses_000" in m for m in members)
            # Should have part files
            assert any("part/ses_000" in m for m in members)
            # Should have readme files
            assert any("directory-readme/ses_000" in m for m in members)
            assert "metadata.json" in members

    def test_export_multiple_codex_sessions(self, tmp_path):
        """Test exporting multiple Codex sessions with directories."""
        sessions = []
        codex_dir = tmp_path / ".codex"
        codex_base = codex_dir / "sessions" / "2026"

        for i in range(2):
            month_dir = codex_base / f"{i + 1:02d}"
            session_path = month_dir / f"codex-session-{i}"
            session_path.mkdir(parents=True)

            # Create rollout files
            (session_path / f"rollout-{i}.jsonl").write_text(
                json.dumps({"test": f"data {i}"})
            )
            (session_path / "metadata.json").write_text(
                json.dumps({"meta": f"value {i}"})
            )

            session = Session(f"codex-session-{i}", session_path, tool="codex")
            sessions.append(session)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        archive_name = "codex-multiple-test.tgz"

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive_multiple(
                sessions=sessions,
                config_dir=codex_dir,
                output_dir=output_dir,
                hostname="test-host",
                archive_name=archive_name,
            )

        assert archive_path.exists()

        # Verify archive contains all session directories
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            # Should contain files from both sessions
            assert any("codex-session-0" in m for m in members)
            assert any("codex-session-1" in m for m in members)
            assert "metadata.json" in members

    def test_export_multiple_claude_sessions(self, tmp_path, monkeypatch):
        """Test exporting multiple Claude sessions with history.jsonl."""
        sessions = []
        claude_dir = tmp_path / ".claude"
        session_env_dir = claude_dir / "session-env"

        # Create .claude directory first
        claude_dir.mkdir(parents=True, exist_ok=True)

        # Create history.jsonl with all sessions
        history_file = claude_dir / "history.jsonl"
        history_entries = []
        for i in range(3):
            sid = f"claude-sess-{i}"
            entry = {
                "sessionId": sid,
                "display": f"Claude Session {i}",
                "timestamp": 1764389932342 + (i * 1000),
                "project": f"/project/{i}",
            }
            history_entries.append(json.dumps(entry))

            session_path = session_env_dir / sid
            session_path.mkdir(parents=True)
            (session_path / "file.txt").write_text(f"content {i}")

            sessions.append(
                Session(sid, session_path, tool="claude", history_data=entry)
            )

        history_file.write_text("\n".join(history_entries))

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        archive_name = "claude-multiple-test.tgz"

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive_multiple(
                sessions=sessions,
                config_dir=claude_dir,
                output_dir=output_dir,
                hostname="test-host",
                archive_name=archive_name,
            )

        assert archive_path.exists()

        # Verify archive contains history.jsonl and session-env
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            assert ".claude/history.jsonl" in members
            # Should contain session-env directories
            assert any("claude-sess-0" in m for m in members)
            assert "metadata.json" in members


class TestArchiveImportFallback:
    """Test archive import with fallback detection."""

    def test_import_without_metadata_fallback_opencode(self, tmp_path, monkeypatch):
        """Test importing opencode archive without metadata.json uses filename."""
        # Create archive without metadata.json
        archive_file = tmp_path / "opencode-session-test-20250207.tgz"

        with tarfile.open(archive_file, "w:gz") as tar:
            # Add a session file
            session_file = tmp_path / "ses_test.json"
            session_file.write_text(json.dumps({"title": "Test"}))
            tar.add(session_file, arcname="ses_test.json")
            session_file.unlink()

        target_dir = tmp_path / "extracted"
        target_dir.mkdir()

        # Mock opencode storage directory
        opencode_storage = tmp_path / "opencode-storage"
        opencode_storage.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Should detect 'opencode' from filename and extract correctly
        result = extract_archive(archive_file, target_dir)

        assert result is True

    def test_import_without_metadata_fallback_codex(self, tmp_path):
        """Test importing codex archive without metadata.json uses filename."""
        # Create archive without metadata.json
        archive_file = tmp_path / "codex-session-test-20250207.tgz"

        with tarfile.open(archive_file, "w:gz") as tar:
            # Add a session directory
            session_dir = tmp_path / "2026" / "01" / "test-session"
            session_dir.mkdir(parents=True)
            (session_dir / "rollout.jsonl").write_text("test")
            tar.add(session_dir, arcname="2026/01/test-session")

        target_dir = tmp_path / "extracted"
        target_dir.mkdir()

        # Should detect 'codex' from filename
        result = extract_archive(archive_file, target_dir)

        assert result is True

    def test_import_old_opencode_format(self, tmp_path, monkeypatch):
        """Test importing old opencode archive without opencode/ prefix."""
        # Create archive in old format (JSON files at root)
        archive_file = tmp_path / "opencode-session-old-20250207.tgz"

        with tarfile.open(archive_file, "w:gz") as tar:
            # Add session file without opencode/ prefix
            session_file = tmp_path / "ses_old.json"
            session_file.write_text(json.dumps({"title": "Old Format"}))
            tar.add(session_file, arcname="ses_old.json")
            session_file.unlink()

        target_dir = tmp_path / "extracted"
        target_dir.mkdir()

        # Mock opencode storage directory
        opencode_storage = tmp_path / ".local" / "share" / "opencode"
        opencode_storage.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        # Should handle old format by extracting to global session directory
        result = extract_archive(archive_file, target_dir)

        assert result is True


class TestClaudeHistoryFileReading:
    """Test Claude history.jsonl file reading."""

    def test_claude_history_file_reading(self, tmp_path, monkeypatch):
        """Test reading Claude history from actual history.jsonl file."""
        # Create session-env directory
        session_env_dir = tmp_path / "session-env"
        session_env_dir.mkdir()

        session_path = session_env_dir / "test-session-history"
        session_path.mkdir()

        # Create history.jsonl with multiple entries
        history_file = tmp_path / "history.jsonl"
        history_entries = [
            json.dumps(
                {"sessionId": "other-session", "display": "Other", "timestamp": 1000}
            ),
            json.dumps(
                {
                    "sessionId": "test-session-history",
                    "display": "History Test",
                    "timestamp": 2000,
                }
            ),
            json.dumps(
                {
                    "sessionId": "another-session",
                    "display": "Another",
                    "timestamp": 3000,
                }
            ),
        ]
        history_file.write_text("\n".join(history_entries))

        # Patch Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        session = Session("test-session-history", session_path, tool="claude")

        # Should load history data from file
        assert session.name == "History Test"

    def test_claude_history_missing_file(self, tmp_path, monkeypatch):
        """Test Claude session when history.jsonl doesn't exist."""
        session_env_dir = tmp_path / "session-env"
        session_env_dir.mkdir()

        session_path = session_env_dir / "no-history-session"
        session_path.mkdir()

        # Don't create history.jsonl
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        session = Session("no-history-session", session_path, tool="claude")

        # Should fall back to session_id
        assert session.name == "no-history-session"

    def test_claude_history_corrupted_lines(self, tmp_path, monkeypatch):
        """Test Claude session with corrupted lines in history.jsonl."""
        session_env_dir = tmp_path / "session-env"
        session_env_dir.mkdir()

        session_path = session_env_dir / "corrupted-history"
        session_path.mkdir()

        # Create history.jsonl with corrupted lines
        history_file = tmp_path / "history.jsonl"
        history_content = f"""
{json.dumps({"sessionId": "other", "display": "Other", "timestamp": 1000})}
invalid json line
{json.dumps({"sessionId": "corrupted-history", "display": "Valid Session", "timestamp": 2000})}
another invalid line
"""
        history_file.write_text(history_content)

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        session = Session("corrupted-history", session_path, tool="claude")

        # Should skip corrupted lines and find valid entry
        assert session.name == "Valid Session"

    def test_claude_old_format_fallback(self, tmp_path):
        """Test Claude session with old format (conversation file exists)."""
        session_path = tmp_path / "old-format-session"
        session_path.mkdir()

        # Create old-style conversation file
        conversation_file = session_path / "old-format-session.json"
        conversation_data = {"title": "Old Format Session"}
        conversation_file.write_text(json.dumps(conversation_data))

        session = Session("old-format-session", session_path, tool="claude")

        # Should read from conversation file, not history.jsonl
        assert session.name == "Old Format Session"

    def test_claude_conversation_file_corrupted(self, tmp_path):
        """Test Claude session with corrupted conversation file."""
        session_path = tmp_path / "corrupted-session"
        session_path.mkdir()

        # Create corrupted conversation file
        conversation_file = session_path / "corrupted-session.json"
        conversation_file.write_text("invalid json content")

        session = Session("corrupted-session", session_path, tool="claude")

        # Should fall back to session_id
        assert session.name == "corrupted-session"
