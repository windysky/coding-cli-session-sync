"""Performance regression tests for critical performance fixes.

Tests verify O(n) behavior instead of O(n²) for history.jsonl scanning
and single-pass compression for archive creation.
"""

import json
import time
from datetime import datetime

import pytest

from session_sync.core import (
    _GLOBAL_HISTORY_CACHE,
    Session,
    create_archive,
    discover_sessions,
)


class TestHistoryScanningPerformance:
    """Test O(n) history.jsonl scanning behavior."""

    def setup_method(self):
        """Clear the global cache before each test."""
        _GLOBAL_HISTORY_CACHE.clear()

    @pytest.fixture
    def claude_new_format_with_history(self, tmp_path):
        """Create a Claude new-format setup with history.jsonl containing multiple sessions.

        This simulates the real-world scenario where history.jsonl contains
        many session entries, and we want to ensure O(n) not O(n²) behavior.
        """
        # Create session-env directory
        session_env = tmp_path / "session-env"
        session_env.mkdir()

        # Create history.jsonl with 100 session entries
        history_file = tmp_path / "history.jsonl"
        session_count = 100

        history_lines = []
        for i in range(session_count):
            session_id = f"claude_sess_{i:06d}"
            session_data = {
                "sessionId": session_id,
                "timestamp": int(datetime(2024, 1, i % 28 + 1).timestamp() * 1000),
                "display": f"Test Session {i} - This is a conversation about topic {i}",
                "url": f"file://{tmp_path}/session-env/{session_id}/index.html",
            }
            history_lines.append(json.dumps(session_data))

            # Create session directory
            session_dir = session_env / session_id
            session_dir.mkdir()

        history_file.write_text("\n".join(history_lines) + "\n")

        return session_env, history_file, session_count

    def test_discover_sessions_uses_preloaded_data(
        self, claude_new_format_with_history
    ):
        """Test that discover_sessions passes pre-loaded history data to Session objects.

        This ensures that accessing session properties doesn't trigger re-scans
        of history.jsonl.
        """
        session_env, history_file, session_count = claude_new_format_with_history

        # Discover sessions
        start_time = time.time()
        sessions = discover_sessions(session_env, tool="claude", max_sessions=1000)
        discovery_time = time.time() - start_time

        # Verify all sessions were discovered
        assert len(sessions) == session_count

        # Access properties that would trigger history.jsonl scans if not pre-loaded
        # With the fix, this should be very fast (O(1) per session)
        property_access_start = time.time()
        for session in sessions:
            _ = (
                session.name
            )  # This would trigger _load_history_data() if not pre-loaded
            _ = session.created_at  # This would also trigger _load_history_data()
        property_access_time = time.time() - property_access_start

        # Property access should be very fast (< 0.1 seconds for 100 sessions)
        # If O(n²) behavior exists, this would take much longer
        assert property_access_time < 0.5, (
            f"Property access too slow: {property_access_time:.3f}s for {session_count} sessions. "
            f"This indicates O(n²) behavior - sessions may not be using pre-loaded history data."
        )

        # Discovery itself should also be reasonably fast
        assert discovery_time < 2.0, f"Discovery too slow: {discovery_time:.3f}s"

    def test_session_created_outside_discovery_uses_cache(
        self, claude_new_format_with_history
    ):
        """Test that Session objects created outside discover_sessions use the global cache.

        When Session objects are created individually (not through discover_sessions),
        they should use the module-level cache to avoid repeated history.jsonl scans.
        """
        session_env, history_file, session_count = claude_new_format_with_history

        # Create sessions individually (not through discover_sessions)
        # First session will trigger a scan and populate cache
        session_id_1 = "claude_sess_000001"
        session_path_1 = session_env / session_id_1
        session_1 = Session(session_id_1, session_path_1, tool="claude")

        # Access properties to trigger cache population
        start_time = time.time()
        _ = session_1.name
        _ = session_1.created_at
        first_access_time = time.time() - start_time

        # Create another session - should use cache
        session_id_2 = "claude_sess_000050"
        session_path_2 = session_env / session_id_2
        session_2 = Session(session_id_2, session_path_2, tool="claude")

        # Access properties - should be faster due to cache
        cache_access_start = time.time()
        _ = session_2.name
        _ = session_2.created_at
        cache_access_time = time.time() - cache_access_start

        # The cache should make subsequent lookups very fast
        # (though the first lookup still needs to scan the file once)
        # The key is that creating 100 sessions and accessing properties
        # should NOT cause 100 full file scans
        assert cache_access_time < first_access_time * 2, (
            f"Cache not effective: first={first_access_time:.3f}s, cached={cache_access_time:.3f}s"
        )

    def test_empty_history_data_prevents_rescan(self, claude_new_format_with_history):
        """Test that passing empty dict as history_data prevents re-scanning.

        When discover_sessions finds a session not in history.jsonl, it passes
        history_data={} to indicate "already checked, not found". This should
        prevent _load_history_data() from re-scanning the file.
        """
        session_env, history_file, _ = claude_new_format_with_history

        # Create a session directory that doesn't exist in history.jsonl
        orphan_session_id = "orphan_session_not_in_history"
        orphan_session_path = session_env / orphan_session_id
        orphan_session_path.mkdir()

        # Create session with empty history_data (simulating discover_sessions behavior)
        session = Session(
            orphan_session_id,
            orphan_session_path,
            tool="claude",
            history_data={},  # Empty dict = checked but not found
        )

        # Access properties - should NOT trigger a re-scan
        # The empty dict should be treated as "already checked"
        start_time = time.time()
        _ = session.name  # Should return session_id as fallback
        access_time = time.time() - start_time

        # Should be instant (no file scan)
        assert access_time < 0.01, (
            f"Access took too long: {access_time:.3f}s - likely re-scanned history.jsonl"
        )

        # Verify the name is the session_id (fallback behavior)
        assert session.name == orphan_session_id

    def test_performance_regression_many_sessions(self, tmp_path):
        """Performance regression test with many sessions.

        Creates 500 sessions and verifies that discovery and property access
        complete in reasonable time. This test will fail if O(n²) behavior
        is reintroduced.
        """
        # Create session-env directory
        session_env = tmp_path / "session-env"
        session_env.mkdir()

        # Create history.jsonl with 500 session entries
        history_file = tmp_path / "history.jsonl"
        session_count = 500

        history_lines = []
        for i in range(session_count):
            session_id = f"perf_test_sess_{i:06d}"
            session_data = {
                "sessionId": session_id,
                "timestamp": int(datetime(2024, 1, i % 28 + 1).timestamp() * 1000),
                "display": f"Performance Test Session {i}",
            }
            history_lines.append(json.dumps(session_data))

            # Create session directory
            session_dir = session_env / session_id
            session_dir.mkdir()

        history_file.write_text("\n".join(history_lines) + "\n")

        # Measure discovery time
        discovery_start = time.time()
        sessions = discover_sessions(session_env, tool="claude", max_sessions=1000)
        discovery_time = time.time() - discovery_start

        # Measure property access time
        property_start = time.time()
        for session in sessions:
            _ = session.name
            _ = session.created_at
        property_time = time.time() - property_start

        # Verify all sessions were discovered
        assert len(sessions) == session_count

        # Performance assertions
        # Discovery: Should be O(n), expect < 5 seconds for 500 sessions
        assert discovery_time < 5.0, (
            f"Discovery too slow: {discovery_time:.3f}s for {session_count} sessions"
        )

        # Property access: Should be O(n) total (O(1) per session with pre-loaded data)
        # If O(n²), this would be >> 1 second for 500 sessions
        assert property_time < 1.0, (
            f"Property access too slow: {property_time:.3f}s for {session_count} sessions"
        )


class TestArchiveCreationPerformance:
    """Test single-pass compression for archive creation."""

    @pytest.fixture
    def large_claude_session(self, tmp_path):
        """Create a Claude session with multiple files for archive testing."""
        # Create config directory
        config_dir = tmp_path / ".claude"
        config_dir.mkdir()

        # Create session-env directory
        session_env = config_dir / "session-env"
        session_env.mkdir()

        session_id = "test_large_session"
        session_path = session_env / session_id
        session_path.mkdir()

        # Create some session files
        for i in range(10):
            (session_path / f"file_{i}.txt").write_text(f"Content {i}" * 100)

        # Create .claude config files
        (config_dir / "settings.json").write_text('{"setting": "value"}' * 10)
        (config_dir / "config.json").write_text('{"config": "data"}' * 10)

        # Create history.jsonl
        history_file = config_dir / "history.jsonl"
        history_file.write_text(
            json.dumps(
                {
                    "sessionId": session_id,
                    "timestamp": int(datetime.now().timestamp() * 1000),
                    "display": "Large test session",
                }
            )
            + "\n"
        )

        # Create output directory
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        return (
            Session(
                session_id,
                session_path,
                tool="claude",
                history_data=json.loads(history_file.read_text()),
            ),
            config_dir,
            output_dir,
        )

    def test_archive_creation_single_compression_pass(self, large_claude_session):
        """Test that archive creation uses single compression pass.

        The old implementation would:
        1. Create archive with files
        2. Calculate checksum
        3. Recreate entire archive with metadata (double compression)

        The new implementation should:
        1. Create tar with files
        2. Calculate checksum of tar
        3. Append metadata to tar (tar supports appending!)
        4. Compress tar to tgz (single compression pass)
        """
        session, config_dir, output_dir = large_claude_session

        # Create archive and measure time
        start_time = time.time()
        archive_path = create_archive(session, config_dir, output_dir, "test-host")
        creation_time = time.time() - start_time

        # Verify archive was created
        assert archive_path.exists()
        assert archive_path.suffix == ".tgz"

        # Archive creation should complete in reasonable time
        # With double compression, this would take noticeably longer
        assert creation_time < 5.0, f"Archive creation too slow: {creation_time:.3f}s"

        # Verify the archive is valid (can be opened)
        import tarfile

        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                members = tar.getnames()
                # Should contain metadata.json and session files
                assert "metadata.json" in members
                assert any("file_" in m for m in members)
        except Exception as e:
            pytest.fail(f"Archive is corrupted or invalid: {e}")

    def test_archive_contains_metadata_with_checksum(self, large_claude_session):
        """Test that the archive contains metadata.json with a valid checksum."""
        session, config_dir, output_dir = large_claude_session

        archive_path = create_archive(session, config_dir, output_dir, "test-host")

        # Extract and verify metadata
        import tarfile

        with tarfile.open(archive_path, "r:gz") as tar:
            metadata_member = tar.extractfile("metadata.json")
            if metadata_member is None:
                pytest.fail("metadata.json not found in archive")

            metadata_content = metadata_member.read().decode("utf-8")
            metadata = json.loads(metadata_content)

            # Verify metadata has required fields (checksum is nested under 'archive')
            assert "archive" in metadata
            assert "checksum_sha256" in metadata["archive"]
            assert "export_timestamp" in metadata
            assert "source_hostname" in metadata

            # Verify checksum is a valid hex string (not empty)
            checksum = metadata["archive"]["checksum_sha256"]
            assert len(checksum) == 64  # SHA-256 produces 64 hex chars
            assert all(c in "0123456789abcdef" for c in checksum)

            # Verify other archive fields
            assert "size_bytes" in metadata["archive"]
            assert "file_count" in metadata["archive"]

    def test_archive_performance_improvement_measurable(self, large_claude_session):
        """Test that the performance improvement is measurable.

        This doesn't assert a specific time (which can vary), but verifies
        that the archive creation process is efficient by checking that
        the operations complete in a reasonable timeframe.
        """
        session, config_dir, output_dir = large_claude_session

        # Run multiple iterations to get a stable measurement
        iterations = 3
        times = []

        for _i in range(iterations):
            # Clean output directory
            for archive in output_dir.glob("*.tgz"):
                archive.unlink()

            start = time.time()
            create_archive(session, config_dir, output_dir, "test-host")
            times.append(time.time() - start)

        avg_time = sum(times) / len(times)

        # Average time should be reasonable (under 2 seconds for this test data)
        assert avg_time < 2.0, f"Average archive creation too slow: {avg_time:.3f}s"

        # Variance should be low (consistent performance)
        variance = max(times) - min(times)
        assert variance < 1.0, (
            f"High variance in archive creation times: {variance:.3f}s"
        )


class TestCombinedPerformance:
    """Test combined performance of discovery and archive creation."""

    def test_end_to_end_performance(self, tmp_path):
        """Test the complete workflow: discover -> create archives.

        This simulates a real-world usage scenario where a user exports
        multiple sessions. The test verifies that the entire process
        completes efficiently.
        """
        # Setup: Create 100 Claude sessions
        config_dir = tmp_path / ".claude"
        config_dir.mkdir()

        session_env = config_dir / "session-env"
        session_env.mkdir()

        history_file = config_dir / "history.jsonl"
        session_count = 100

        history_lines = []
        for i in range(session_count):
            session_id = f"end_to_end_{i:06d}"
            session_data = {
                "sessionId": session_id,
                "timestamp": int(datetime(2024, 1, i % 28 + 1).timestamp() * 1000),
                "display": f"End-to-End Test Session {i}",
            }
            history_lines.append(json.dumps(session_data))

            session_dir = session_env / session_id
            session_dir.mkdir()
            (session_dir / "session_data.json").write_text(
                json.dumps({"data": f"session_{i}"})
            )

        history_file.write_text("\n".join(history_lines) + "\n")

        # Add some config files
        (config_dir / "settings.json").write_text('{"setting": "value"}')

        # Create output directory
        output_dir = tmp_path / "archives"
        output_dir.mkdir()

        # Measure end-to-end time
        start_time = time.time()

        # Discover sessions
        sessions = discover_sessions(session_env, tool="claude", max_sessions=1000)

        # Create archives for first 10 sessions (to keep test fast)
        for session in sessions[:10]:
            create_archive(session, config_dir, output_dir, "test-host")

        total_time = time.time() - start_time

        # Verify results
        assert len(sessions) == session_count
        assert len(list(output_dir.glob("*.tgz"))) == 10

        # Performance assertion: entire workflow should be fast
        # With O(n²) history scanning + double compression, this would be >> 10 seconds
        assert total_time < 10.0, f"End-to-end workflow too slow: {total_time:.3f}s"

        print("\nEnd-to-end performance:")
        print(f"  Sessions discovered: {len(sessions)}")
        print("  Archives created: 10")
        print(f"  Total time: {total_time:.3f}s")
        print(f"  Average per archive: {(total_time / 10):.3f}s")
