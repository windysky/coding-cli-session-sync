"""Tests for import script functionality."""

import json
import shutil
import tarfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from session_sync.core import Archive, Session


class TestImportScript:
    """Test import script functionality."""

    def test_import_session_exists(self):
        """Test that import script can be imported."""
        # This test verifies the module structure is correct
        script_path = Path(__file__).parent.parent / "import_session.py"
        assert script_path.exists()

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_archive_menu(self, mock_stdout, tmp_path):
        """Test archive menu display."""
        # Create test archives
        archives = []
        for i in range(3):
            archive_file = tmp_path / f"session-{i:03d}-20250207.tgz"
            archive_file.write_text("test content")
            archives.append(Archive(archive_file))

        # Import and test menu function
        from import_session import display_archive_menu

        with patch("builtins.input", side_effect=["1", "y"]):
            selected = display_archive_menu(archives)

        assert selected is not None
        selected_archive, selected_session_ids = selected
        assert selected_archive.archive_path == archives[0].archive_path
        assert isinstance(selected_session_ids, list)

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_archive_menu_empty(self, mock_stdout):
        """Test archive menu with no archives."""
        from import_session import display_archive_menu

        result = display_archive_menu([])

        assert result is None


class TestArchiveMenuWithMetadata:
    """Test archive menu with metadata."""

    def test_display_archives_with_metadata(self, tmp_path):
        """Test displaying archives with loaded metadata."""
        # Create archive with metadata
        archive_file = tmp_path / "session-test-20250207.tgz"

        # Create metadata
        session_path = tmp_path / "sess-test"
        session = Session("sess-test", session_path)

        from datetime import datetime

        from session_sync.core import Metadata

        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname="test-host",
            session=session,
            archive_filename="session-test-20250207.tgz",
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

        archive = Archive(archive_file)
        archives = [archive]

        from import_session import display_archive_menu

        with patch("builtins.input", side_effect=["1", "C", "y"]):
            selected = display_archive_menu(archives)

        assert selected is not None
        selected_archive, selected_session_ids = selected
        assert selected_archive.archive_path == archive_file
        assert isinstance(selected_session_ids, list)


class TestCheckSessionConflict:
    """Test session conflict detection."""

    def test_check_conflict_exists(self, tmp_path):
        """Test detecting existing session conflict."""
        from import_session import check_session_conflict

        session_dir = tmp_path / "sessions"
        session_dir.mkdir()

        session_id = "sess-conflict-test"
        session_path = session_dir / session_id
        session_path.mkdir()

        has_conflict = check_session_conflict(session_id, session_dir)

        assert has_conflict is True

    def test_check_no_conflict(self, tmp_path):
        """Test no conflict when session doesn't exist."""
        from import_session import check_session_conflict

        session_dir = tmp_path / "sessions"
        session_dir.mkdir()

        has_conflict = check_session_conflict("nonexistent-session", session_dir)

        assert has_conflict is False


class TestMergeClaudeHistory:
    """Test Claude Code history.jsonl merge functionality."""

    def test_merge_new_sessions_added(self, tmp_path):
        """Test that new sessions from archive are added to target."""
        from import_session import merge_claude_history

        # Create target history.jsonl with existing session
        target_history = tmp_path / "target_history.jsonl"
        target_history.write_text(
            json.dumps({"sessionId": "existing-1", "timestamp": 1000}) + "\n"
        )

        # Create archive history.jsonl with new session
        archive_history = tmp_path / "archive_history.jsonl"
        archive_history.write_text(
            json.dumps({"sessionId": "new-1", "timestamp": 2000})
            + "\n"
            + json.dumps({"sessionId": "new-2", "timestamp": 3000})
            + "\n"
        )

        added, skipped = merge_claude_history(target_history, archive_history)

        assert added == 2
        assert skipped == 0

        # Verify target has all sessions
        with open(target_history) as f:
            lines = [line.strip() for line in f if line.strip()]
        assert len(lines) == 3

    def test_merge_existing_sessions_skipped(self, tmp_path):
        """Test that existing sessions in target are not duplicated."""
        from import_session import merge_claude_history

        # Create target history.jsonl
        target_history = tmp_path / "target_history.jsonl"
        target_history.write_text(
            json.dumps({"sessionId": "shared-1", "timestamp": 1000})
            + "\n"
            + json.dumps({"sessionId": "target-only", "timestamp": 1500})
            + "\n"
        )

        # Create archive history.jsonl with overlapping session
        archive_history = tmp_path / "archive_history.jsonl"
        archive_history.write_text(
            json.dumps({"sessionId": "shared-1", "timestamp": 1000})
            + "\n"
            + json.dumps({"sessionId": "archive-only", "timestamp": 2000})
            + "\n"
        )

        added, skipped = merge_claude_history(target_history, archive_history)

        assert added == 1  # Only archive-only added
        assert skipped == 1  # shared-1 skipped

        # Verify target doesn't have duplicates
        with open(target_history) as f:
            sessions = [json.loads(line)["sessionId"] for line in f if line.strip()]
        assert sessions.count("shared-1") == 1  # No duplicate

    def test_merge_empty_target(self, tmp_path):
        """Test merging into empty target history."""
        from import_session import merge_claude_history

        # Create empty target history.jsonl
        target_history = tmp_path / "target_history.jsonl"
        target_history.write_text("")

        # Create archive history.jsonl
        archive_history = tmp_path / "archive_history.jsonl"
        archive_history.write_text(
            json.dumps({"sessionId": "new-1", "timestamp": 1000}) + "\n"
        )

        added, skipped = merge_claude_history(target_history, archive_history)

        assert added == 1
        assert skipped == 0

    def test_merge_empty_archive(self, tmp_path):
        """Test merging empty archive history."""
        from import_session import merge_claude_history

        # Create target history.jsonl
        target_history = tmp_path / "target_history.jsonl"
        target_history.write_text(
            json.dumps({"sessionId": "existing-1", "timestamp": 1000}) + "\n"
        )

        # Create empty archive history.jsonl
        archive_history = tmp_path / "archive_history.jsonl"
        archive_history.write_text("")

        added, skipped = merge_claude_history(target_history, archive_history)

        assert added == 0
        assert skipped == 0


class TestCheckSessionConflicts:
    """Test session conflict detection for multiple sessions."""

    def test_check_conflicts_multiple_sessions(self, tmp_path):
        """Test detecting conflicts for multiple sessions."""
        from import_session import check_session_conflicts

        session_dir = tmp_path / "sessions"
        session_dir.mkdir()

        # Create some existing sessions
        (session_dir / "existing-1").mkdir()
        (session_dir / "existing-2").mkdir()

        session_ids = ["existing-1", "new-1", "existing-2", "new-2"]
        conflicts = check_session_conflicts(session_ids, session_dir)

        assert conflicts == ["existing-1", "existing-2"]

    def test_check_no_conflicts(self, tmp_path):
        """Test when no conflicts exist."""
        from import_session import check_session_conflicts

        session_dir = tmp_path / "sessions"
        session_dir.mkdir()

        session_ids = ["new-1", "new-2", "new-3"]
        conflicts = check_session_conflicts(session_ids, session_dir)

        assert conflicts == []


class TestTransactionCopySessions:
    """Test transaction-safe session directory copying."""

    def test_transaction_copy_all_sessions_success(self, tmp_path):
        """Test that all sessions are copied when no failures occur."""
        from import_session import transaction_copy_sessions

        # Create source sessions
        source_session_env = tmp_path / "source_session_env"
        source_session_env.mkdir()
        (source_session_env / "session-1").mkdir()
        (source_session_env / "session-1" / "data.json").write_text('{"id": 1}')
        (source_session_env / "session-2").mkdir()
        (source_session_env / "session-2" / "data.json").write_text('{"id": 2}')
        (source_session_env / "session-3").mkdir()
        (source_session_env / "session-3" / "data.json").write_text('{"id": 3}')

        # Create target session directory
        target_session_dir = tmp_path / "target_sessions"
        target_session_dir.mkdir()

        # Copy sessions transactionally
        added = transaction_copy_sessions(source_session_env, target_session_dir)

        # Assert all sessions were copied
        assert added == 3
        assert (target_session_dir / "session-1" / "data.json").exists()
        assert (target_session_dir / "session-2" / "data.json").exists()
        assert (target_session_dir / "session-3" / "data.json").exists()

        # Verify content
        content1 = json.loads(
            (target_session_dir / "session-1" / "data.json").read_text()
        )
        assert content1 == {"id": 1}

    def test_transaction_copy_rollback_on_failure(self, tmp_path):
        """Test that all copies are rolled back on partial failure."""
        from import_session import transaction_copy_sessions

        # Create source sessions
        source_session_env = tmp_path / "source_session_env"
        source_session_env.mkdir()
        (source_session_env / "session-1").mkdir()
        (source_session_env / "session-1" / "data.json").write_text('{"id": 1}')
        (source_session_env / "session-2").mkdir()
        (source_session_env / "session-2" / "data.json").write_text('{"id": 2}')
        (source_session_env / "session-3").mkdir()
        (source_session_env / "session-3" / "data.json").write_text('{"id": 3}')

        # Create target session directory with one existing session
        target_session_dir = tmp_path / "target_sessions"
        target_session_dir.mkdir()
        (target_session_dir / "existing-session").mkdir()

        # Mock shutil.copytree to fail on session-2
        original_copytree = shutil.copytree
        copy_count = [0]

        def mock_copytree(src, dst, **kwargs):
            copy_count[0] += 1
            # Fail on second copy (session-2)
            if copy_count[0] == 2:
                raise OSError("Simulated copy failure")
            return original_copytree(src, dst, **kwargs)

        with patch("shutil.copytree", side_effect=mock_copytree):
            # This should raise an exception with rollback message
            with pytest.raises(OSError, match="Partial copy failure"):
                transaction_copy_sessions(source_session_env, target_session_dir)

        # Assert no new sessions were copied (rollback successful)
        assert not (target_session_dir / "session-1").exists()
        assert not (target_session_dir / "session-2").exists()
        assert not (target_session_dir / "session-3").exists()
        # Existing session should still be there
        assert (target_session_dir / "existing-session").exists()

    def test_transaction_copy_skips_existing_sessions(self, tmp_path):
        """Test that existing sessions are skipped without error."""
        from import_session import transaction_copy_sessions

        # Create source sessions
        source_session_env = tmp_path / "source_session_env"
        source_session_env.mkdir()
        (source_session_env / "session-1").mkdir()
        (source_session_env / "session-1" / "data.json").write_text('{"id": 1}')
        (source_session_env / "session-2").mkdir()
        (source_session_env / "session-2" / "data.json").write_text('{"id": 2}')

        # Create target session directory with existing session
        target_session_dir = tmp_path / "target_sessions"
        target_session_dir.mkdir()
        (target_session_dir / "session-1").mkdir()
        (target_session_dir / "session-1" / "old_data.json").write_text('{"old": true}')

        # Copy sessions transactionally
        added = transaction_copy_sessions(source_session_env, target_session_dir)

        # Assert only new session was copied
        assert added == 1
        # Existing session should remain unchanged
        assert (target_session_dir / "session-1" / "old_data.json").exists()
        assert not (target_session_dir / "session-1" / "data.json").exists()
        # New session should be copied
        assert (target_session_dir / "session-2" / "data.json").exists()

    def test_transaction_copy_empty_source(self, tmp_path):
        """Test that empty source is handled gracefully."""
        from import_session import transaction_copy_sessions

        # Create empty source
        source_session_env = tmp_path / "source_session_env"
        source_session_env.mkdir()

        # Create target session directory
        target_session_dir = tmp_path / "target_sessions"
        target_session_dir.mkdir()

        # Copy sessions transactionally
        added = transaction_copy_sessions(source_session_env, target_session_dir)

        # Assert no sessions were copied
        assert added == 0


class TestImportIntegration:
    """Integration tests for import functionality."""

    def test_import_validates_checksum(self, tmp_path):
        """Test that import validates archive checksum."""
        # Create test file
        test_file = tmp_path / "test.txt"
        test_file.write_text("test content")

        # Calculate checksum
        from session_sync.core import calculate_checksum

        checksum = calculate_checksum(test_file)

        # Create archive
        archive = Archive(test_file)

        # Test validation
        assert archive.validate_checksum(checksum) is True
        assert archive.validate_checksum("wrong") is False

    def test_import_extracts_archive(self, tmp_path):
        """Test that import extracts archive correctly."""
        # Create test archive
        archive_file = tmp_path / "test-archive.tgz"

        test_data = {"test": "data", "number": 123}
        with tarfile.open(archive_file, "w:gz") as tar:
            test_file = tmp_path / "test.json"
            test_file.write_text(json.dumps(test_data))
            tar.add(test_file, arcname="test.json")
            test_file.unlink()

        # Extract archive
        from session_sync.core import extract_archive

        target_dir = tmp_path / "extracted"
        target_dir.mkdir()

        result = extract_archive(archive_file, target_dir)

        assert result is True
        assert (target_dir / "test.json").exists()

        extracted_data = json.loads((target_dir / "test.json").read_text())
        assert extracted_data == test_data
