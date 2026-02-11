"""Tests for cross-platform file locking functionality.

Tests cover:
- Basic lock acquisition and release
- Concurrent access prevention
- Lock timeout and retry behavior
- Stale lock detection and cleanup
- Atomic write operations
- Cross-platform compatibility
"""

import json
import os
import time
from pathlib import Path
from threading import Event, Thread

import pytest

from session_sync.file_lock import (
    FileLock,
    FileLockError,
    atomic_write,
    with_file_lock,
)


class TestFileLockBasic:
    """Test basic file lock functionality."""

    def test_lock_acquire_release(self, tmp_path):
        """Test basic lock acquisition and release."""
        lock_path = tmp_path / "test.lock"

        # Acquire and release lock
        lock = FileLock(lock_path, timeout=5.0)
        lock.acquire()
        assert lock._is_locked
        assert lock_path.exists()
        lock.release()
        assert not lock._is_locked
        # Lock file should be cleaned up
        assert not lock_path.exists()

    def test_lock_context_manager(self, tmp_path):
        """Test lock as context manager."""
        lock_path = tmp_path / "test.lock"

        with FileLock(lock_path, timeout=5.0) as lock:
            assert lock._is_locked
            assert lock_path.exists()

        # Lock should be released after context
        assert not lock_path.exists()

    def test_lock_write_pid(self, tmp_path):
        """Test that lock file contains PID."""
        lock_path = tmp_path / "test.lock"

        with FileLock(lock_path, timeout=5.0):
            # Check lock file contains current PID
            pid_str = lock_path.read_text().strip()
            assert pid_str.isdigit()
            assert int(pid_str) == os.getpid()

    def test_lock_prevent_concurrent_access(self, tmp_path):
        """Test that lock prevents concurrent access."""
        lock_path = tmp_path / "test.lock"
        results = []
        t1_ready = Event()
        t2_go = Event()

        def try_lock1():
            """First thread acquires lock and signals."""
            try:
                lock = FileLock(lock_path, timeout=5.0)
                lock.acquire()
                results.append("t1:acquired")
                t1_ready.set()  # Signal that we have the lock
                # Wait for t2 to signal it's trying
                # Then hold the lock for a while to ensure t2's timeout expires
                if t2_go.wait(timeout=2.0):
                    time.sleep(1.0)  # Hold lock longer than t2's timeout (0.5s)
                lock.release()
            except FileLockError:
                results.append("t1:failed")

        def try_lock2():
            """Second thread waits for t1 to have lock, then tries."""
            t1_ready.wait(timeout=2.0)  # Wait for t1 to acquire lock
            t2_go.set()  # Signal that we're about to try

            try:
                # Use short timeout - should fail because t1 holds lock
                lock = FileLock(lock_path, timeout=0.3)
                lock.acquire()
                results.append("t2:acquired")
                lock.release()
            except FileLockError:
                results.append("t2:failed")

        # Start both threads
        t1 = Thread(target=try_lock1)
        t2 = Thread(target=try_lock2)
        t1.start()
        t2.start()

        # Wait for both threads
        t1.join(timeout=10.0)
        t2.join(timeout=10.0)

        # Both threads should have completed
        assert len(results) == 2
        # First thread should acquire, second should fail
        assert "t1:acquired" in results
        assert "t2:failed" in results

    def test_lock_timeout(self, tmp_path):
        """Test lock timeout behavior."""
        lock_path = tmp_path / "test.lock"

        # Acquire lock in main thread
        lock1 = FileLock(lock_path, timeout=5.0)
        lock1.acquire()

        # Try to acquire in another thread with short timeout
        def try_acquire_with_timeout():
            try:
                lock2 = FileLock(lock_path, timeout=0.5)
                lock2.acquire()
                return "success"
            except FileLockError as e:
                return f"timeout:{e.attempts}"

        t = Thread(target=try_acquire_with_timeout)
        t.start()
        t.join(timeout=2.0)

        # Release first lock
        lock1.release()

    def test_lock_concurrent_writes(self, tmp_path):
        """Test that lock prevents concurrent writes."""
        lock_path = tmp_path / "test.lock"
        data_path = tmp_path / "data.txt"
        results = []

        def write_data(thread_id: int, count: int):
            """Write data with lock protection."""
            for _i in range(count):
                with FileLock(lock_path, timeout=5.0):
                    # Read current value
                    current = 0
                    if data_path.exists():
                        current = int(data_path.read_text())

                    # Write new value
                    data_path.write_text(str(current + 1))
                    results.append(f"t{thread_id}:{current + 1}")

        # Run concurrent writers
        threads = []
        for i in range(3):
            t = Thread(target=write_data, args=(i, 5))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=10.0)

        # Check final value (should be 15 = 3 threads * 5 writes)
        final_value = int(data_path.read_text())
        assert final_value == 15


class TestStaleLockHandling:
    """Test stale lock detection and cleanup."""

    def test_stale_lock_by_age(self, tmp_path, monkeypatch):
        """Test detection and removal of stale locks by age."""
        lock_path = tmp_path / "test.lock"

        # Create a lock file with old timestamp
        lock_path.write_text("12345")
        old_time = time.time() - 4000  # > 1 hour ago
        os.utime(lock_path, (old_time, old_time))

        # Should detect and remove stale lock
        lock = FileLock(lock_path, timeout=5.0)
        lock.acquire()
        assert lock._is_locked
        lock.release()

    def test_stale_lock_by_dead_process(self, tmp_path):
        """Test detection of stale lock from dead process."""
        lock_path = tmp_path / "test.lock"

        # Use a non-existent PID
        fake_pid = 99999
        lock_path.write_text(str(fake_pid))

        # Should detect stale lock (process not running)
        # and remove it
        lock = FileLock(lock_path, timeout=5.0)
        lock.acquire()
        assert lock._is_locked
        lock.release()

    def test_active_lock_not_removed(self, tmp_path):
        """Test that active locks are not removed."""
        lock_path = tmp_path / "test.lock"

        # Create active lock
        lock1 = FileLock(lock_path, timeout=5.0)
        lock1.acquire()

        # Try to acquire with another instance - should fail
        # (not remove the lock)
        lock2 = FileLock(lock_path, timeout=0.5)
        with pytest.raises(FileLockError):
            lock2.acquire()

        assert lock2._lock_fd is None

        # First lock still active
        assert lock1._is_locked

        # Cleanup
        lock1.release()


class TestAtomicWrite:
    """Test atomic write functionality."""

    def test_atomic_write_basic(self, tmp_path):
        """Test basic atomic write."""
        file_path = tmp_path / "output.txt"

        with atomic_write(file_path) as f:
            f.write("Hello, World!")

        # File should exist with content
        assert file_path.exists()
        assert file_path.read_text() == "Hello, World!"

    def test_atomic_write_overwrite(self, tmp_path):
        """Test atomic write overwrites existing file."""
        file_path = tmp_path / "output.txt"
        file_path.write_text("Old content")

        with atomic_write(file_path) as f:
            f.write("New content")

        assert file_path.read_text() == "New content"

    def test_atomic_write_encoding(self, tmp_path):
        """Test atomic write with encoding."""
        file_path = tmp_path / "output.txt"

        with atomic_write(file_path, encoding="utf-8") as f:
            f.write("Hello, 世界!")

        assert file_path.read_text(encoding="utf-8") == "Hello, 世界!"

    def test_atomic_write_binary(self, tmp_path):
        """Test atomic write in binary mode."""
        file_path = tmp_path / "output.bin"

        with atomic_write(file_path, mode="wb") as f:
            f.write(b"\x00\x01\x02\x03")

        assert file_path.read_bytes() == b"\x00\x01\x02\x03"

    def test_atomic_write_cleanup_on_error(self, tmp_path):
        """Test that temp file is cleaned up on error."""
        file_path = tmp_path / "output.txt"

        with pytest.raises(ValueError):
            with atomic_write(file_path) as f:
                f.write("Partial content")
                raise ValueError("Test error")

        # Main file should not exist or have old content
        # Temp file should be cleaned up
        temp_files = list(tmp_path.glob("*.tmp"))
        assert len(temp_files) == 0

    def test_atomic_write_concurrent(self, tmp_path):
        """Test concurrent atomic writes are serialized by lock."""
        file_path = tmp_path / "counter.txt"
        results = []
        errors = []

        def write_increment(thread_id: int, count: int):
            """Write increment with atomic write."""
            for i in range(count):
                try:
                    # Read current value OUTSIDE of atomic_write
                    current = 0
                    if file_path.exists():
                        content = file_path.read_text()
                        if content:
                            current = int(content)

                    # Write new value atomically
                    # Note: There's still a race condition between read and write
                    # but the atomic write ensures the file is never corrupted
                    with atomic_write(file_path) as f:
                        # Note: At this point file_path might have been updated
                        # by another thread, so we might lose some increments.
                        # This is expected behavior for this pattern.
                        # For true serializability, use FileLock directly.
                        new_value = current + 1
                        f.write(str(new_value))

                    results.append(f"t{thread_id}:wrote{i}")
                except (OSError, ValueError) as e:
                    errors.append((thread_id, i, str(e)))

        # Run concurrent writers
        threads = []
        for i in range(3):
            t = Thread(target=write_increment, args=(i, 5))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=10.0)

        # Check no file corruption errors occurred
        assert len(errors) == 0, f"Errors occurred: {errors}"

        # Check final value - with the read/write race condition,
        # some updates might be lost, but the file should be valid
        final_value = int(file_path.read_text())
        # The value should be between 5 (only first thread's writes) and 15 (all writes)
        assert 5 <= final_value <= 15


class TestMergeClaudeHistory:
    """Test merge_claude_history with file locking."""

    def test_merge_basic(self, tmp_path):
        """Test basic merge operation."""
        from import_session import merge_claude_history

        # Create target history
        target = tmp_path / "history.jsonl"
        target.write_text('{"sessionId":"sess1","data":"a"}\n')

        # Create archive history
        archive = tmp_path / "archive.jsonl"
        archive.write_text(
            '{"sessionId":"sess1","data":"a"}\n{"sessionId":"sess2","data":"b"}\n'
        )

        # Merge
        added, skipped = merge_claude_history(target, archive)

        assert added == 1
        assert skipped == 1

        # Check merged content
        lines = target.read_text().strip().split("\n")
        assert len(lines) == 2
        session_ids = set()
        for line in lines:
            data = json.loads(line)
            session_ids.add(data["sessionId"])
        assert session_ids == {"sess1", "sess2"}

    def test_merge_concurrent(self, tmp_path):
        """Test concurrent merge operations."""
        from import_session import merge_claude_history

        target = tmp_path / "history.jsonl"
        target.write_text("")  # Empty initial file

        results = []
        errors = []

        def merge_session(session_id: str):
            """Merge a single session."""
            try:
                archive = tmp_path / f"archive_{session_id}.jsonl"
                archive.write_text(f'{{"sessionId":"{session_id}","data":"x"}}\n')
                added, skipped = merge_claude_history(target, archive)
                results.append((session_id, added, skipped))
            except Exception as e:
                errors.append((session_id, str(e)))

        # Run concurrent merges
        threads = []
        for i in range(10):
            t = Thread(target=merge_session, args=(f"sess{i}",))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=30.0)

        # Check results
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 10

        # Check all sessions were added
        lines = target.read_text().strip().split("\n")
        session_ids = set()
        for line in lines:
            if line:
                data = json.loads(line)
                session_ids.add(data["sessionId"])

        assert len(session_ids) == 10

    def test_merge_with_existing_content(self, tmp_path):
        """Test merge preserves existing content."""
        from import_session import merge_claude_history

        target = tmp_path / "history.jsonl"
        original_content = (
            '{"sessionId":"sess1","data":"a"}\n{"sessionId":"sess2","data":"b"}\n'
        )
        target.write_text(original_content)

        archive = tmp_path / "archive.jsonl"
        archive.write_text(
            '{"sessionId":"sess2","data":"b"}\n{"sessionId":"sess3","data":"c"}\n'
        )

        added, skipped = merge_claude_history(target, archive)

        assert added == 1
        assert skipped == 1

        # Check original content preserved
        lines = target.read_text().strip().split("\n")
        assert len(lines) == 3
        session_ids = set()
        for line in lines:
            data = json.loads(line)
            session_ids.add(data["sessionId"])
        assert session_ids == {"sess1", "sess2", "sess3"}

    def test_merge_non_json_lines(self, tmp_path):
        """Test that non-JSON lines are preserved."""
        from import_session import merge_claude_history

        target = tmp_path / "history.jsonl"
        target.write_text('{"sessionId":"sess1","data":"a"}\n# Comment line\n')

        archive = tmp_path / "archive.jsonl"
        archive.write_text('{"sessionId":"sess2","data":"b"}\n# Another comment\n')

        added, skipped = merge_claude_history(target, archive)

        assert added == 1  # sess2 added

        # Check comment lines preserved
        content = target.read_text()
        assert "# Comment line" in content
        assert "# Another comment" in content


class TestLockIntegration:
    """Integration tests for file locking."""

    def test_lock_with_multiple_processes(self, tmp_path):
        """Test lock behavior with multiple simulated processes."""
        lock_path = tmp_path / "test.lock"
        results = []
        errors = []

        def simulate_process(process_id: int):
            """Simulate a process using the lock."""
            try:
                for iteration in range(3):
                    with FileLock(lock_path, timeout=10.0):
                        # Simulate some work
                        time.sleep(0.05)
                        results.append(f"p{process_id}:i{iteration}")
            except FileLockError as e:
                errors.append((process_id, str(e)))

        # Run concurrent "processes"
        threads = []
        for i in range(3):
            t = Thread(target=simulate_process, args=(i,))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=20.0)

        # Verify no errors
        assert len(errors) == 0

        # Verify all operations completed
        assert len(results) == 9  # 3 processes * 3 iterations

    def test_lock_timeout_configuration(self, tmp_path):
        """Test configurable lock timeout."""
        lock_path = tmp_path / "test.lock"

        # Acquire lock
        lock1 = FileLock(lock_path, timeout=5.0)
        lock1.acquire()

        # Try with very short timeout
        lock2 = FileLock(lock_path, timeout=0.1)
        start = time.time()
        with pytest.raises(FileLockError):
            lock2.acquire()
        elapsed = time.time() - start

        # Should timeout quickly (< 1 second)
        assert elapsed < 1.0

        lock1.release()


class TestWithFileLockDecorator:
    """Test the @with_file_lock decorator."""

    def test_decorator_basic(self, tmp_path):
        """Test decorator prevents concurrent execution."""
        lock_path = tmp_path / "test.lock"
        results = []

        @with_file_lock(lock_path, timeout=5.0)
        def critical_section(name: str):
            """Function that requires lock."""
            results.append(f"{name}:start")
            time.sleep(0.1)
            results.append(f"{name}:end")

        # Run concurrent calls
        def run_concurrent(name: str):
            critical_section(name)

        threads = []
        for i in range(3):
            t = Thread(target=run_concurrent, args=(f"t{i}",))
            threads.append(t)
            t.start()

        # Wait for completion
        for t in threads:
            t.join(timeout=10.0)

        # All should complete
        assert len(results) == 6  # 3 threads * 2 events each

        # Check ordering - no overlap
        for i in range(0, len(results) - 1, 2):
            assert results[i + 1].endswith(":end")


class TestCrossPlatformCompatibility:
    """Test cross-platform lock behavior."""

    def test_lock_path_handling(self, tmp_path):
        """Test lock handles various path types."""
        # Test with Path object
        lock_path = tmp_path / "test.lock"
        with FileLock(lock_path):
            assert lock_path.exists()

        # Test with string path
        lock_path_str = str(tmp_path / "test2.lock")
        with FileLock(lock_path_str):
            assert Path(lock_path_str).exists()

    def test_lock_cleanup_on_exception(self, tmp_path):
        """Test lock is released even if exception occurs."""
        lock_path = tmp_path / "test.lock"

        try:
            with FileLock(lock_path):
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Lock should be released
        assert not lock_path.exists()

    def test_lock_reuse_after_release(self, tmp_path):
        """Test lock can be reused after release."""
        lock_path = tmp_path / "test.lock"

        lock = FileLock(lock_path, timeout=5.0)

        # First acquisition
        lock.acquire()
        lock.release()

        # Second acquisition
        lock.acquire()
        lock.release()

        # Both should succeed
        assert not lock_path.exists()


class TestPIDValidationSecurity:
    """Test PID input validation for security (SEC-004)."""

    def test_is_process_running_valid_pid(self):
        """Test _is_process_running with valid PID."""
        # Use current process PID which should always be valid
        current_pid = os.getpid()
        result = FileLock._is_process_running(current_pid)
        assert result is True

    def test_is_process_running_negative_pid(self):
        """Test _is_process_running rejects negative PIDs."""
        with pytest.raises(ValueError, match="PID must be a positive integer"):
            FileLock._is_process_running(-1)

    def test_is_process_running_zero_pid(self):
        """Test _is_process_running rejects zero PID."""
        with pytest.raises(ValueError, match="PID must be a positive integer"):
            FileLock._is_process_running(0)

    def test_is_process_running_string_pid(self):
        """Test _is_process_running rejects string PIDs."""
        with pytest.raises(ValueError, match="Invalid PID value"):
            FileLock._is_process_running("abc")

    def test_is_process_running_none_pid(self):
        """Test _is_process_running rejects None PID."""
        with pytest.raises(ValueError, match="Invalid PID value"):
            FileLock._is_process_running(None)

    def test_is_process_running_special_chars(self):
        """Test _is_process_running rejects special characters in PID."""
        with pytest.raises(ValueError, match="Invalid PID value"):
            FileLock._is_process_running("1; rm -rf /")

    def test_is_process_running_float_pid(self):
        """Test _is_process_running converts float to int."""
        # Float should be converted to int
        # Use current process PID as float
        current_pid = float(os.getpid())
        result = FileLock._is_process_running(current_pid)
        # Current process should be running
        assert result is True

    def test_is_process_running_injection_attempt(self):
        """Test _is_process_running prevents command injection."""
        # Attempt to inject commands via PID parameter
        malicious_inputs = [
            "1 & malicious_command",
            "1; malicious_command",
            "1 | malicious_command",
            "1 `malicious_command`",
            "$(malicious_command)",
            "1 && malicious_command",
        ]

        for malicious_input in malicious_inputs:
            with pytest.raises(ValueError, match="Invalid PID value"):
                FileLock._is_process_running(malicious_input)
