"""Tests for core session synchronization functionality."""

import json
import tarfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from session_sync.core import (
    Archive,
    Metadata,
    Session,
    calculate_checksum,
    check_disk_space,
    create_archive,
    discover_archives,
    discover_sessions,
    ensure_directory,
    extract_archive,
    get_hostname,
)


class TestSession:
    """Test Session class."""

    def test_session_initialization(self):
        """Test session object initialization."""
        session_path = Path("/test/path/sess-test123")
        session = Session("sess-test123", session_path, tool="claude")

        assert session.session_id == "sess-test123"
        assert session.session_path == session_path
        assert session.conversation_file == session_path / "sess-test123.json"
        assert session.tool == "claude"

    def test_session_name_from_conversation(self, tmp_path):
        """Test getting session name from conversation file."""
        session_id = "sess-test001"
        session_path = tmp_path / session_id
        session_path.mkdir()

        conversation_data = {"title": "Test Session Title"}
        conversation_file = session_path / f"{session_id}.json"
        conversation_file.write_text(json.dumps(conversation_data))

        session = Session(session_id, session_path, tool="claude")

        assert session.name == "Test Session Title"

    def test_session_name_fallback_to_id(self, tmp_path):
        """Test session name fallback to session ID."""
        session_id = "sess-test002"
        session_path = tmp_path / session_id
        session_path.mkdir()

        # Create conversation file without title
        conversation_file = session_path / f"{session_id}.json"
        conversation_file.write_text("{}")

        session = Session(session_id, session_path, tool="claude")

        assert session.name == session_id

    def test_session_name_missing_conversation(self, tmp_path):
        """Test session name when conversation file missing."""
        session_id = "sess-test003"
        session_path = tmp_path / session_id
        session_path.mkdir()

        session = Session(session_id, session_path, tool="claude")

        assert session.name == session_id

    def test_session_created_at(self, tmp_path):
        """Test getting session creation timestamp."""
        session_id = "sess-test004"
        session_path = tmp_path / session_id
        session_path.mkdir()

        conversation_file = session_path / f"{session_id}.json"
        conversation_file.write_text("{}")

        session = Session(session_id, session_path, tool="claude")

        assert session.created_at is not None
        assert isinstance(session.created_at, datetime)

    def test_session_last_modified(self, tmp_path):
        """Test getting session last modified timestamp."""
        session_id = "sess-test005"
        session_path = tmp_path / session_id
        session_path.mkdir()

        conversation_file = session_path / f"{session_id}.json"
        conversation_file.write_text("{}")

        session = Session(session_id, session_path, tool="claude")

        assert session.last_modified is not None
        assert isinstance(session.last_modified, datetime)

    def test_session_size_bytes(self, tmp_path):
        """Test calculating session size."""
        session_id = "sess-test006"
        session_path = tmp_path / session_id
        session_path.mkdir()

        # Create files with specific sizes
        (session_path / "file1.txt").write_text("x" * 100)
        (session_path / "file2.txt").write_text("y" * 200)

        session = Session(session_id, session_path, tool="claude")

        assert session.size_bytes == 300

    def test_session_to_dict(self, tmp_path):
        """Test converting session to dictionary."""
        session_id = "sess-test007"
        session_path = tmp_path / session_id
        session_path.mkdir()

        conversation_data = {"title": "Test Session"}
        conversation_file = session_path / f"{session_id}.json"
        conversation_file.write_text(json.dumps(conversation_data))

        session = Session(session_id, session_path, tool="claude")
        session_dict = session.to_dict()

        assert session_dict["id"] == session_id
        assert session_dict["name"] == "Test Session"
        assert session_dict["tool"] == "claude"
        assert "created_at" in session_dict
        assert "last_modified" in session_dict


class TestMetadata:
    """Test Metadata class."""

    def test_metadata_initialization(self, tmp_path):
        """Test metadata object initialization."""
        session_path = tmp_path / "sess-test"
        session = Session("sess-test", session_path)

        timestamp = datetime.now()
        metadata = Metadata(
            export_timestamp=timestamp,
            source_hostname="test-host",
            session=session,
            archive_filename="test-archive.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=5,
        )

        assert metadata.export_timestamp == timestamp
        assert metadata.source_hostname == "test-host"
        assert metadata.checksum_sha256 == "abc123"

    def test_metadata_to_dict(self, tmp_path):
        """Test converting metadata to dictionary."""
        session_path = tmp_path / "sess-test"
        session = Session("sess-test", session_path, tool="claude")

        timestamp = datetime(2025, 2, 7, 10, 30, 0)
        metadata = Metadata(
            export_timestamp=timestamp,
            source_hostname="test-host",
            session=session,
            archive_filename="test-archive.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=5,
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["version"] == "1.0"
        assert metadata_dict["tool"] == "claude"
        assert metadata_dict["export_timestamp"] == "2025-02-07T10:30:00"
        assert metadata_dict["source_hostname"] == "test-host"
        assert metadata_dict["archive"]["filename"] == "test-archive.tgz"
        assert metadata_dict["archive"]["checksum_sha256"] == "abc123"
        assert metadata_dict["archive"]["size_bytes"] == 1024
        assert metadata_dict["archive"]["file_count"] == 5
        assert metadata_dict["contents"]["type"] == "claude_session"

    def test_metadata_save_and_load(self, tmp_path):
        """Test saving and loading metadata."""
        session_path = tmp_path / "sess-test"
        session = Session("sess-test", session_path)

        timestamp = datetime.now()
        original_metadata = Metadata(
            export_timestamp=timestamp,
            source_hostname="test-host",
            session=session,
            archive_filename="test-archive.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=5,
        )

        # Save metadata
        metadata_file = tmp_path / "metadata.json"
        original_metadata.save(metadata_file)

        # Load metadata
        loaded_metadata = Metadata.load(metadata_file)

        assert loaded_metadata.export_timestamp.isoformat() == timestamp.isoformat()
        assert loaded_metadata.source_hostname == "test-host"
        assert loaded_metadata.checksum_sha256 == "abc123"


class TestArchive:
    """Test Archive class."""

    def test_archive_initialization(self):
        """Test archive object initialization."""
        archive_path = Path("/test/path/session-test.tgz")
        archive = Archive(archive_path)

        assert archive.archive_path == archive_path
        assert archive.metadata is None

    def test_archive_size_bytes(self, tmp_path):
        """Test getting archive size."""
        archive_file = tmp_path / "test-archive.tgz"
        archive_file.write_text("test content")

        archive = Archive(archive_file)

        assert archive.size_bytes == 12  # len('test content')

    def test_archive_load_metadata(self, tmp_path):
        """Test loading metadata from archive."""
        # Create test archive with metadata
        archive_file = tmp_path / "test-archive.tgz"

        # Create metadata
        session_path = tmp_path / "sess-test"
        session = Session("sess-test", session_path)
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname="test-host",
            session=session,
            archive_filename="test-archive.tgz",
            checksum_sha256="abc123",
            size_bytes=1024,
            file_count=5,
        )

        # Create archive with metadata
        with tarfile.open(archive_file, "w:gz") as tar:
            metadata_file = tmp_path / "temp-metadata.json"
            metadata.save(metadata_file)
            tar.add(metadata_file, arcname="metadata.json")
            metadata_file.unlink()

        # Load metadata from archive
        archive = Archive(archive_file)
        loaded_metadata = archive.load_metadata()

        assert loaded_metadata is not None
        assert loaded_metadata.source_hostname == "test-host"
        assert loaded_metadata.checksum_sha256 == "abc123"

    def test_archive_validate_checksum(self, tmp_path):
        """Test checksum validation."""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        # Calculate correct checksum
        correct_checksum = calculate_checksum(test_file)

        # Create archive
        archive = Archive(test_file)

        # Test with correct checksum
        assert archive.validate_checksum(correct_checksum) is True

        # Test with incorrect checksum
        assert archive.validate_checksum("wrongchecksum") is False


class TestCalculateChecksum:
    """Test checksum calculation."""

    def test_calculate_checksum_consistent(self, tmp_path):
        """Test checksum is consistent for same file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        checksum1 = calculate_checksum(test_file)
        checksum2 = calculate_checksum(test_file)

        assert checksum1 == checksum2
        assert len(checksum1) == 64  # SHA-256 produces 64 hex characters

    def test_calculate_checksum_different_files(self, tmp_path):
        """Test checksum differs for different files."""
        file1 = tmp_path / "file1.txt"
        file2 = tmp_path / "file2.txt"

        file1.write_text("content 1")
        file2.write_text("content 2")

        checksum1 = calculate_checksum(file1)
        checksum2 = calculate_checksum(file2)

        assert checksum1 != checksum2


class TestDiscoverSessions:
    """Test session discovery."""

    def test_discover_sessions_empty(self, tmp_path):
        """Test discovering sessions in empty directory."""
        sessions = discover_sessions(tmp_path)

        assert sessions == []

    def test_discover_sessions_valid(self, tmp_path):
        """Test discovering valid sessions."""
        # Create session directories with conversation files
        for i in range(3):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text("{}")

        sessions = discover_sessions(tmp_path, tool="claude")

        assert len(sessions) == 3
        assert all(isinstance(s, Session) for s in sessions)

    def test_discover_sessions_ignore_invalid(self, tmp_path):
        """Test discovering sessions ignores invalid directories."""
        # Create valid session
        valid_session = tmp_path / "sess-valid"
        valid_session.mkdir()
        (valid_session / "sess-valid.json").write_text("{}")

        # Create invalid session (no conversation file)
        invalid_session = tmp_path / "sess-invalid"
        invalid_session.mkdir()

        # Create regular file (not a directory)
        (tmp_path / "not-a-session.txt").write_text("test")

        sessions = discover_sessions(tmp_path, tool="claude")

        assert len(sessions) == 1
        assert sessions[0].session_id == "sess-valid"

    def test_discover_sessions_nonexistent_directory(self):
        """Test discovering sessions in non-existent directory."""
        sessions = discover_sessions(Path("/nonexistent/path"), tool="claude")

        assert sessions == []


class TestDiscoverArchives:
    """Test archive discovery."""

    def test_discover_archives_empty(self, tmp_path):
        """Test discovering archives in empty directory."""
        archives = discover_archives(tmp_path)

        assert archives == []

    def test_discover_archives_valid(self, tmp_path):
        """Test discovering valid archives."""
        # Create archive files with new tool-prefix format
        for i, tool in enumerate(["claude", "codex", "opencode"]):
            archive_file = tmp_path / f"{tool}-session-{i:03d}-20250207.tgz"
            archive_file.write_text("test content")

        archives = discover_archives(tmp_path)

        assert len(archives) == 3
        assert all(isinstance(a, Archive) for a in archives)

    def test_discover_archives_ignore_other_files(self, tmp_path):
        """Test discovering archives ignores other files."""
        # Create valid archive
        valid_archive = tmp_path / "claude-session-test-20250207.tgz"
        valid_archive.write_text("test")

        # Create other files
        (tmp_path / "not-an-archive.txt").write_text("test")
        (tmp_path / "other-file.json").write_text("{}")

        archives = discover_archives(tmp_path)

        assert len(archives) == 1
        assert archives[0].archive_path == valid_archive


class TestCreateArchive:
    """Test archive creation."""

    def test_create_archive_basic(self, tmp_path):
        """Test basic archive creation."""
        # Create session
        session_id = "sess-test001"
        session_path = tmp_path / "sessions" / session_id
        session_path.mkdir(parents=True)
        conversation_file = session_path / f"{session_id}.json"
        conversation_file.write_text(json.dumps({"title": "Test Session"}))

        # Create .claude directory
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "config.json").write_text("{}")

        # Create output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create archive
        session = Session(session_id, session_path, tool="claude")
        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive(
                session=session,
                config_dir=claude_dir,
                output_dir=output_dir,
                hostname="test-host",
            )

        # Verify archive created
        assert archive_path.exists()
        assert archive_path.suffix == ".tgz"
        assert archive_path.name.startswith(f"claude-session-{session_id}-")

        # Verify archive contents
        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            assert f"{session_id}.json" in members
            assert "metadata.json" in members
            assert any(".claude" in m for m in members)


class TestExtractArchive:
    """Test archive extraction."""

    def test_extract_archive_basic(self, tmp_path):
        """Test basic archive extraction."""
        # Create test archive
        archive_file = tmp_path / "test-archive.tgz"

        test_content = {"test": "data"}
        with tarfile.open(archive_file, "w:gz") as tar:
            # Create temporary file to add
            test_file = tmp_path / "test.json"
            test_file.write_text(json.dumps(test_content))
            tar.add(test_file, arcname="test.json")
            test_file.unlink()

        # Extract archive
        target_dir = tmp_path / "extracted"
        target_dir.mkdir()

        result = extract_archive(archive_file, target_dir)

        assert result is True
        assert (target_dir / "test.json").exists()

        extracted_content = json.loads((target_dir / "test.json").read_text())
        assert extracted_content == test_content


class TestGetHostname:
    """Test hostname retrieval."""

    def test_get_hostname(self):
        """Test getting system hostname."""
        hostname = get_hostname()

        assert isinstance(hostname, str)
        assert len(hostname) > 0


class TestCheckDiskSpace:
    """Test disk space checking."""

    def test_check_disk_space_sufficient(self, tmp_path):
        """Test checking sufficient disk space."""
        result = check_disk_space(tmp_path, 1)  # 1 byte

        assert result is True

    def test_check_disk_space_insufficient(self, tmp_path):
        """Test checking insufficient disk space."""
        # Request impossibly large amount
        result = check_disk_space(tmp_path, 10**18)  # 1 EB

        assert result is False


class TestEnsureDirectory:
    """Test directory creation."""

    def test_ensure_directory_creates_new(self, tmp_path):
        """Test creating new directory."""
        new_dir = tmp_path / "new" / "nested" / "directory"

        assert not new_dir.exists()

        result = ensure_directory(new_dir)

        assert result is True
        assert new_dir.exists()

    def test_ensure_directory_existing(self, tmp_path):
        """Test ensuring existing directory."""
        result = ensure_directory(tmp_path)

        assert result is True
        assert tmp_path.exists()

    @patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied"))
    def test_ensure_directory_failure(self, mock_mkdir, tmp_path):
        """Test directory creation failure."""
        new_dir = tmp_path / "new"

        result = ensure_directory(new_dir)

        assert result is False
