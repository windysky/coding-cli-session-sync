"""Tests for export script functionality."""

import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from session_sync.core import Session


class TestExportScript:
    """Test export script functionality."""

    def test_export_session_exists(self):
        """Test that export script can be imported."""
        # This test verifies the module structure is correct
        script_path = Path(__file__).parent.parent / "export_session.py"
        assert script_path.exists()

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu(self, mock_stdout, tmp_path):
        """Test session menu display."""
        # Create test sessions
        sessions = []
        for i in range(3):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text(
                json.dumps({"title": f"Session {i}"})
            )
            sessions.append(Session(session_id, session_path))

        # Import and test menu function
        from export_session import display_session_menu

        with patch("builtins.input", side_effect=["1", "C"]):
            selected = display_session_menu(sessions)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 1
        assert selected[0].session_id == "sess-000"

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu_empty(self, mock_stdout):
        """Test session menu with no sessions."""
        from export_session import display_session_menu

        result = display_session_menu([])

        assert result is None

    @patch("sys.stdout", new_callable=StringIO)
    @patch("builtins.input", side_effect=["invalid", "", "1", "C"])
    def test_display_session_menu_invalid_selection(
        self, mock_input, mock_stdout, tmp_path
    ):
        """Test session menu with invalid selection then valid."""
        # Create test session
        session_id = "sess-test001"
        session_path = tmp_path / session_id
        session_path.mkdir()
        (session_path / f"{session_id}.json").write_text(
            json.dumps({"title": "Test Session"})
        )
        sessions = [Session(session_id, session_path)]

        from export_session import display_session_menu

        selected = display_session_menu(sessions)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 1
        assert selected[0].session_id == session_id

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu_multiple_selection(self, mock_stdout, tmp_path):
        """Test session menu with multiple selection."""
        # Create test sessions
        sessions = []
        for i in range(5):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text(
                json.dumps({"title": f"Session {i}"})
            )
            sessions.append(Session(session_id, session_path))

        # Import and test menu function
        from export_session import display_session_menu

        with patch("builtins.input", side_effect=["1,3,5", "C"]):
            selected = display_session_menu(sessions)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 3
        assert selected[0].session_id == "sess-000"
        assert selected[1].session_id == "sess-002"
        assert selected[2].session_id == "sess-004"

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu_range_selection(self, mock_stdout, tmp_path):
        """Test session menu with range selection."""
        # Create test sessions
        sessions = []
        for i in range(5):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text(
                json.dumps({"title": f"Session {i}"})
            )
            sessions.append(Session(session_id, session_path))

        # Import and test menu function
        from export_session import display_session_menu

        with patch("builtins.input", side_effect=["1-3", "C"]):
            selected = display_session_menu(sessions)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 3
        assert selected[0].session_id == "sess-000"
        assert selected[1].session_id == "sess-001"
        assert selected[2].session_id == "sess-002"

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu_all_selection(self, mock_stdout, tmp_path):
        """Test session menu with 'all' selection."""
        # Create test sessions
        sessions = []
        for i in range(3):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text(
                json.dumps({"title": f"Session {i}"})
            )
            sessions.append(Session(session_id, session_path))

        # Import and test menu function
        from export_session import display_session_menu

        with patch("builtins.input", side_effect=["all", "C"]):
            selected = display_session_menu(sessions)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 3


class TestMultiSelectionParser:
    """Test session selection parser for multiple sessions."""

    def test_parse_single_session(self):
        """Test parsing single session selection."""
        from export_session import parse_session_selection

        selected = parse_session_selection("1", 5)
        assert selected == [0]

    def test_parse_comma_separated(self):
        """Test parsing comma-separated selection."""
        from export_session import parse_session_selection

        selected = parse_session_selection("1,3,5", 10)
        assert selected == [0, 2, 4]

    def test_parse_range(self):
        """Test parsing range selection."""
        from export_session import parse_session_selection

        selected = parse_session_selection("1-5", 10)
        assert selected == [0, 1, 2, 3, 4]

    def test_parse_all(self):
        """Test parsing 'all' selection."""
        from export_session import parse_session_selection

        selected = parse_session_selection("all", 5)
        assert selected == [0, 1, 2, 3, 4]

    def test_parse_mixed(self):
        """Test parsing mixed selection (ranges and singles)."""
        from export_session import parse_session_selection

        selected = parse_session_selection("1-3,5,7", 10)
        assert selected == [0, 1, 2, 4, 6]

    def test_parse_invalid_returns_empty(self):
        """Test that invalid input returns empty list."""
        from export_session import parse_session_selection

        selected = parse_session_selection("invalid", 5)
        assert selected == []

    def test_parse_out_of_range_clamped(self):
        """Test that out of range values are handled."""
        from export_session import parse_session_selection

        # Range extends beyond max_sessions
        selected = parse_session_selection("1-10", 5)
        assert selected == [0, 1, 2, 3, 4]


class TestExportIntegration:
    """Integration tests for export functionality."""

    def test_export_creates_archive(self, tmp_path):
        """Test that export creates a valid archive."""
        # This is a simplified integration test
        # Full integration test would require mocking file system paths

        # Create mock session
        session_id = "sess-integration-test"
        session_path = tmp_path / "sessions" / session_id
        session_path.mkdir(parents=True)
        (session_path / f"{session_id}.json").write_text(
            json.dumps({"title": "Integration Test Session"})
        )

        # Create mock .claude directory
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "config.json").write_text("{}")

        # Create mock output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create archive using core function
        from session_sync.core import create_archive

        session = Session(session_id, session_path)

        with patch("session_sync.core.get_hostname", return_value="test-host"):
            archive_path = create_archive(
                session=session,
                config_dir=claude_dir,
                output_dir=output_dir,
                hostname="test-host",
            )

        # Verify archive exists
        assert archive_path.exists()
        assert archive_path.suffix == ".tgz"

        # Verify archive is valid
        import tarfile

        with tarfile.open(archive_path, "r:gz") as tar:
            members = tar.getnames()
            assert "metadata.json" in members

    def test_export_multiple_sessions_creates_archive(self, tmp_path):
        """Test that exporting multiple sessions creates valid archive."""
        # Create mock sessions
        sessions = []
        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        (claude_dir / "config.json").write_text("{}")

        for i in range(3):
            session_id = f"sess-multi-{i}"
            session_path = tmp_path / "session-env" / session_id
            session_path.mkdir(parents=True)
            sessions.append(Session(session_id, session_path, tool="claude"))

        # Create mock output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create archive with multiple sessions
        from datetime import datetime

        from session_sync.core import create_archive_multiple

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        archive_name = f"claude-sessions-3-{timestamp}.tgz"
        with patch("session_sync.core.get_hostname", return_value="test-host"):
            result_path = create_archive_multiple(
                sessions=sessions,
                config_dir=claude_dir,
                output_dir=output_dir,
                hostname="test-host",
                archive_name=archive_name,
            )

        # Verify archive exists
        assert result_path.exists()
        assert result_path.suffix == ".tgz"


class TestCLIArguments:
    """Test CLI argument parsing for automation flags."""

    def test_parse_arguments_default(self):
        """Test default argument parsing."""
        from export_session import parse_arguments

        # Mock sys.argv for testing
        with patch.object(sys, "argv", ["export_session.py"]):
            args = parse_arguments()

            assert args.tool is None
            assert args.force is False
            assert args.no_clobber is False
            assert args.batch_mode is False

    def test_parse_arguments_tool(self):
        """Test --tool argument."""
        from export_session import parse_arguments

        with patch.object(sys, "argv", ["export_session.py", "--tool", "claude"]):
            args = parse_arguments()
            assert args.tool == "claude"

    def test_parse_arguments_force(self):
        """Test --force argument."""
        from export_session import parse_arguments

        with patch.object(sys, "argv", ["export_session.py", "--force"]):
            args = parse_arguments()
            assert args.force is True

    def test_parse_arguments_no_clobber(self):
        """Test --no-clobber argument."""
        from export_session import parse_arguments

        with patch.object(sys, "argv", ["export_session.py", "--no-clobber"]):
            args = parse_arguments()
            assert args.no_clobber is True

    def test_parse_arguments_batch_mode(self):
        """Test --batch-mode argument."""
        from export_session import parse_arguments

        with patch.object(sys, "argv", ["export_session.py", "--batch-mode"]):
            args = parse_arguments()
            assert args.batch_mode is True

    def test_parse_arguments_output_dir(self):
        """Test --output-dir argument."""
        from export_session import parse_arguments

        test_path = "/tmp/test-output"
        with patch.object(
            sys, "argv", ["export_session.py", "--output-dir", test_path]
        ):
            args = parse_arguments()
            assert str(args.output_dir) == test_path

    def test_parse_arguments_combined(self):
        """Test multiple arguments combined."""
        from export_session import parse_arguments

        with patch.object(
            sys,
            "argv",
            ["export_session.py", "--tool", "codex", "--batch-mode", "--force"],
        ):
            args = parse_arguments()
            assert args.tool == "codex"
            assert args.batch_mode is True
            assert args.force is True


class TestBatchModeBehavior:
    """Test batch mode behavior for automation."""

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu_batch_mode(self, mock_stdout, tmp_path):
        """Test that batch mode auto-selects all sessions."""
        # Create test sessions
        sessions = []
        for i in range(3):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text(
                json.dumps({"title": f"Session {i}"})
            )
            sessions.append(Session(session_id, session_path))

        from export_session import display_session_menu

        # Test batch mode - should select all without prompting
        selected = display_session_menu(sessions, batch_mode=True)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 3  # All sessions selected

    @patch("sys.stdout", new_callable=StringIO)
    def test_display_session_menu_interactive_mode(self, mock_stdout, tmp_path):
        """Test that interactive mode prompts for selection."""
        # Create test sessions
        sessions = []
        for i in range(3):
            session_id = f"sess-{i:03d}"
            session_path = tmp_path / session_id
            session_path.mkdir()
            (session_path / f"{session_id}.json").write_text(
                json.dumps({"title": f"Session {i}"})
            )
            sessions.append(Session(session_id, session_path))

        from export_session import display_session_menu

        with patch("builtins.input", side_effect=["1", "C"]):
            selected = display_session_menu(sessions, batch_mode=False)

        assert selected is not None
        assert isinstance(selected, list)
        assert len(selected) == 1  # Only first session selected
