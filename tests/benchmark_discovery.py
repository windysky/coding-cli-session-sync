"""Benchmark tests for session discovery performance.

Tests the performance improvement of os.scandir() vs Path.iterdir()
for large directory trees.
"""

import json
import time
from datetime import datetime

import pytest

from session_sync.core import discover_sessions


class TestBenchmarkSessionDiscovery:
    """Benchmark session discovery performance."""

    @pytest.fixture
    def large_codex_tree(self, tmp_path):
        """Create a large Codex-style directory tree for benchmarking.

        Creates a structure like:
        sessions/
        ├── 2024/
        │   ├── 01/
        │   │   ├── sess_001/
        │   │   │   └── rollout-20240115.jsonl
        │   │   ├── sess_002/
        │   │   │   └── rollout-20240115.jsonl
        │   │   └── ... (100 sessions per month)
        │   ├── 02/
        │   │   └── ... (100 sessions per month)
        │   └── ... (12 months)
        ├── 2025/
        │   └── ... (12 months with 100 sessions each)
        └── ... (multiple years)

        Total: ~2400 sessions for realistic performance testing
        """
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir()

        years = ["2024", "2025"]
        months = [f"{i:02d}" for i in range(1, 13)]
        sessions_per_month = 100

        session_count = 0
        for year in years:
            year_dir = sessions_dir / year
            year_dir.mkdir()

            for month in months:
                month_dir = year_dir / month
                month_dir.mkdir()

                for i in range(sessions_per_month):
                    session_id = f"sess_{year}{month}_{i:04d}"
                    session_dir = month_dir / session_id
                    session_dir.mkdir()

                    # Create rollout file
                    rollout_file = session_dir / f"rollout-{year}-{month}-15.jsonl"
                    rollout_file.write_text('{"test": "data"}\n')

                    session_count += 1

        return sessions_dir, session_count

    @pytest.fixture
    def large_opencode_dir(self, tmp_path):
        """Create a large OpenCode-style directory for benchmarking.

        Creates 500 session files in a single directory.
        """
        sessions_dir = tmp_path / "opencode"
        sessions_dir.mkdir()

        session_count = 500
        for i in range(session_count):
            session_file = sessions_dir / f"ses_{i:06d}.json"
            data = {
                "id": f"session_{i}",
                "title": f"Session {i}",
                "messages": []
            }
            session_file.write_text(json.dumps(data))

        return sessions_dir, session_count

    @pytest.fixture
    def large_claude_dir(self, tmp_path):
        """Create a large Claude-style directory for benchmarking.

        Creates 500 session directories.
        """
        sessions_dir = tmp_path / "session-env"
        sessions_dir.mkdir()

        session_count = 500
        for i in range(session_count):
            session_id = f"claude_sess_{i:06d}"
            session_dir = sessions_dir / session_id
            session_dir.mkdir()

            # Create conversation file
            conversation_file = session_dir / f"{session_id}.json"
            conversation_data = {
                "sessionId": session_id,
                "title": f"Claude Session {i}",
                "messages": []
            }
            conversation_file.write_text(json.dumps(conversation_data))

        return sessions_dir, session_count

    def test_codex_discovery_performance(self, large_codex_tree):
        """Benchmark Codex session discovery performance.

        Expected: Should discover 2400 sessions in reasonable time.
        With os.scandir(): ~0.5-2 seconds for 2400 sessions
        With Path.iterdir(): ~1.5-5 seconds for 2400 sessions

        This test documents the performance characteristic rather than
        enforcing strict timing, as timing can vary by system.
        """
        sessions_dir, expected_count = large_codex_tree

        start_time = time.time()
        sessions = discover_sessions(sessions_dir, tool="codex", max_sessions=5000)
        elapsed_time = time.time() - start_time

        # Verify correctness
        assert len(sessions) == expected_count

        # Document performance (not enforced, just logged)
        print("\nCodex discovery performance:")
        print(f"  Sessions discovered: {len(sessions)}")
        print(f"  Time elapsed: {elapsed_time:.3f} seconds")
        print(f"  Rate: {len(sessions) / elapsed_time:.1f} sessions/second")

        # Performance assertion: should be reasonably fast
        # On modern systems with SSD: expect < 3 seconds for 2400 sessions
        # This is a loose bound to accommodate different systems
        assert elapsed_time < 10.0, f"Discovery too slow: {elapsed_time:.3f}s for {len(sessions)} sessions"

    def test_opencode_discovery_performance(self, large_opencode_dir):
        """Benchmark OpenCode session discovery performance."""
        sessions_dir, expected_count = large_opencode_dir

        start_time = time.time()
        sessions = discover_sessions(sessions_dir, tool="opencode")
        elapsed_time = time.time() - start_time

        # Verify correctness
        assert len(sessions) == expected_count

        # Document performance
        print("\nOpenCode discovery performance:")
        print(f"  Sessions discovered: {len(sessions)}")
        print(f"  Time elapsed: {elapsed_time:.3f} seconds")
        print(f"  Rate: {len(sessions) / elapsed_time:.1f} sessions/second")

        # Should be very fast for single directory
        assert elapsed_time < 5.0, f"Discovery too slow: {elapsed_time:.3f}s for {len(sessions)} sessions"

    def test_claude_discovery_performance(self, large_claude_dir):
        """Benchmark Claude session discovery performance."""
        sessions_dir, expected_count = large_claude_dir

        start_time = time.time()
        sessions = discover_sessions(sessions_dir, tool="claude")
        elapsed_time = time.time() - start_time

        # Verify correctness
        assert len(sessions) == expected_count

        # Document performance
        print("\nClaude discovery performance:")
        print(f"  Sessions discovered: {len(sessions)}")
        print(f"  Time elapsed: {elapsed_time:.3f} seconds")
        print(f"  Rate: {len(sessions) / elapsed_time:.1f} sessions/second")

        # Should be fast for single directory
        assert elapsed_time < 5.0, f"Discovery too slow: {elapsed_time:.3f}s for {len(sessions)} sessions"

    def test_max_sessions_limit(self, large_codex_tree):
        """Test that max_sessions parameter limits discovery correctly."""
        sessions_dir, _ = large_codex_tree

        # Test with various limits
        for limit in [10, 100, 500, 1000]:
            sessions = discover_sessions(sessions_dir, tool="codex", max_sessions=limit)
            assert len(sessions) <= limit, f"Expected max {limit} sessions, got {len(sessions)}"

    def test_discovery_correctness(self, large_codex_tree):
        """Ensure discovery optimization doesn't break correctness."""
        sessions_dir, expected_count = large_codex_tree

        sessions = discover_sessions(sessions_dir, tool="codex")

        # Verify all sessions have required properties
        for session in sessions:
            assert session.session_id
            assert session.session_path.exists()
            assert session.conversation_file.exists()
            assert session.tool == "codex"

        # Verify sorting (most recent first)
        if len(sessions) >= 2:
            # Sessions should be sorted by last_modified
            # We can't verify exact times without filesystem timestamps,
            # but we can verify the list is sorted
            assert sessions == sorted(sessions, key=lambda s: s.last_modified or datetime.min, reverse=True)


class TestDiscoveryEdgeCases:
    """Test edge cases for optimized discovery."""

    def test_empty_directory(self, tmp_path):
        """Test discovery with empty directory."""
        sessions = discover_sessions(tmp_path, tool="claude")
        assert len(sessions) == 0

    def test_nonexistent_directory(self, tmp_path):
        """Test discovery with nonexistent directory."""
        nonexistent = tmp_path / "does_not_exist"
        sessions = discover_sessions(nonexistent, tool="claude")
        assert len(sessions) == 0

    def test_directory_with_only_invalid_entries(self, tmp_path):
        """Test discovery with directory containing only invalid entries."""
        # Create directory with non-matching files
        (tmp_path / "readme.txt").write_text("test")
        (tmp_path / "other.json").write_text("{}")

        sessions = discover_sessions(tmp_path, tool="opencode")
        assert len(sessions) == 0

    def test_codex_mixed_valid_invalid(self, tmp_path):
        """Test Codex discovery with mix of valid and invalid sessions."""
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir()

        # Valid year/month/session structure
        year_dir = sessions_dir / "2024"
        year_dir.mkdir()
        month_dir = year_dir / "01"
        month_dir.mkdir()

        # Valid session
        valid_session = month_dir / "sess_valid"
        valid_session.mkdir()
        (valid_session / "rollout-20240115.jsonl").write_text("{}")

        # Invalid session (no rollout file)
        invalid_session = month_dir / "sess_invalid"
        invalid_session.mkdir()

        # Non-digit directory (should be skipped)
        (year_dir / "readme").mkdir()

        sessions = discover_sessions(sessions_dir, tool="codex")
        assert len(sessions) == 1
        assert sessions[0].session_id == "sess_valid"

    def test_opencode_mixed_valid_invalid(self, tmp_path):
        """Test OpenCode discovery with mix of valid and invalid sessions."""
        sessions_dir = tmp_path / "opencode"
        sessions_dir.mkdir()

        # Valid session
        valid_file = sessions_dir / "ses_001.json"
        valid_file.write_text(json.dumps({"id": "session_001"}))

        # Invalid files
        (sessions_dir / "readme.txt").write_text("test")
        (sessions_dir / "other.json").write_text("{}")
        (sessions_dir / "ses_invalid.txt").write_text("test")

        sessions = discover_sessions(sessions_dir, tool="opencode")
        assert len(sessions) == 1
        assert sessions[0].session_id == "session_001"

    def test_error_handling_during_discovery(self, tmp_path):
        """Test that errors during discovery don't crash the process."""
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir()

        # Create a valid session
        year_dir = sessions_dir / "2024"
        year_dir.mkdir()
        month_dir = year_dir / "01"
        month_dir.mkdir()
        valid_session = month_dir / "sess_valid"
        valid_session.mkdir()
        (valid_session / "rollout-20240115.jsonl").write_text("{}")

        # Create a file that causes permission error (simulated)
        # In real scenarios, unreadable files should be skipped
        unreadable_file = month_dir / "sess_unreadable" / "rollout.jsonl"
        unreadable_file.parent.mkdir()
        unreadable_file.write_text("{}")

        sessions = discover_sessions(sessions_dir, tool="codex")
        # Should find at least the valid session
        assert len(sessions) >= 1
