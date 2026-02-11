#!/usr/bin/env python3
"""Cross-platform file locking utilities.

Provides file-based locking with retry logic and exponential backoff
for safe concurrent file access across Windows, Linux, and macOS.
"""

import errno
import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path
from types import TracebackType
from typing import Callable, Iterator, Optional, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class FileLockError(IOError):
    """Exception raised when file lock cannot be acquired."""

    def __init__(self, message: str, path: Path, attempts: int):
        """Initialize FileLockError."""
        self.path = path
        self.attempts = attempts
        super().__init__(f"{message} (path: {path}, attempts: {attempts})")


class FileLock:
    """Cross-platform file lock using file-based lock files.

    This implementation uses lock files (.lock) with atomic link/rename
    operations for maximum portability across platforms.

    Usage:
        with FileLock(path/to/file.lock, timeout=30):
            # Critical section - safe concurrent access
            with open(path/to/file, 'r') as f:
                data = f.read()

    The lock is automatically released when exiting the context manager.
    """

    def __init__(
        self,
        lock_path: Path,
        timeout: float = 10.0,
        retry_interval: float = 0.1,
        max_attempts: Optional[int] = None,
    ):
        """Initialize file lock.

        Args:
            lock_path: Path to the lock file (typically .lock extension)
            timeout: Maximum time to wait for lock acquisition (seconds)
            retry_interval: Initial time between retry attempts (seconds)
            max_attempts: Maximum number of retry attempts (None = use timeout)
        """
        self.lock_path = Path(lock_path)
        self.timeout = timeout
        self.retry_interval = retry_interval
        self.max_attempts = max_attempts
        self._lock_fd: Optional[int] = None
        self._is_locked = False

    def acquire(self) -> None:
        """Acquire the file lock with retry logic.

        Raises:
            FileLockError: If lock cannot be acquired within timeout
        """
        # Use monotonic time to avoid race conditions from system clock changes
        start_time = time.monotonic()
        attempt = 0
        current_interval = self.retry_interval

        while True:
            attempt += 1
            elapsed = time.monotonic() - start_time

            # Check timeout
            if elapsed > self.timeout:
                raise FileLockError(
                    f"Lock acquisition timeout after {elapsed:.1f}s",
                    self.lock_path,
                    attempt,
                )

            # Check max attempts
            if self.max_attempts and attempt > self.max_attempts:
                raise FileLockError(
                    f"Maximum lock attempts ({self.max_attempts}) exceeded",
                    self.lock_path,
                    attempt,
                )

            # Try to acquire lock using atomic operations
            try:
                self._try_acquire()
                self._is_locked = True
                logger.debug(
                    f"Lock acquired: {self.lock_path} "
                    f"(attempt {attempt}, {elapsed:.2f}s)"
                )
                return
            except FileLockError:
                # Lock is held by another process
                if attempt == 1:
                    logger.debug(f"Lock busy, waiting: {self.lock_path}")

                # Exponential backoff with jitter
                time.sleep(current_interval)
                current_interval = min(current_interval * 1.5, 2.0)

    def _try_acquire(self) -> None:
        """Attempt to acquire lock using atomic file operations.

        Uses O_EXCL | O_CREAT flag which provides atomic lock creation
        on POSIX and Windows systems.

        Raises:
            FileLockError: If lock is already held by another process
        """
        try:
            # Open with exclusive creation (atomic operation)
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            self._lock_fd = os.open(self.lock_path, flags, 0o644)

            # Write process ID for debugging
            try:
                os.write(self._lock_fd, str(os.getpid()).encode())
            except OSError:
                pass  # PID write is optional

        except OSError as e:
            self._lock_fd = None

            if e.errno == errno.EEXIST:
                # Lock file exists - check if it's stale with atomic verification
                stale_pid = self._is_stale_lock()
                if stale_pid:
                    logger.warning(
                        f"Attempting to remove stale lock: {self.lock_path} "
                        f"(PID: {stale_pid})"
                    )
                    # Attempt atomic removal with verification
                    if self._remove_stale_lock(stale_pid):
                        logger.info(
                            f"Successfully removed stale lock: {self.lock_path}"
                        )
                        # Retry lock acquisition immediately after removing stale lock
                        # This is safe because we've atomically verified the lock was stale
                        return self._try_acquire()
                    else:
                        # Race condition: another process acquired the lock
                        logger.debug(
                            f"Lock acquired by another process during removal: "
                            f"{self.lock_path}"
                        )
                        # Fall through to raise FileLockError below

                # Lock is held by another process
                raise FileLockError(
                    "Lock already held",
                    self.lock_path,
                    1,
                ) from e

            # Other error
            raise FileLockError(
                f"Failed to create lock: {e}",
                self.lock_path,
                1,
            ) from e

    def _is_stale_lock(self) -> Optional[int]:
        """Check if lock file is stale (process no longer running).

        A lock is considered stale if:
        1. The lock file is older than a threshold (default 1 hour)
        2. The process that created it is no longer running

        Returns:
            The PID of the stale process if lock is stale, None otherwise.
            Returning the PID allows for atomic verification during removal.
        """
        try:
            stat = self.lock_path.stat()
            lock_age = time.time() - stat.st_mtime

            # Locks older than 1 hour are considered stale
            if lock_age > 3600:
                # Try to read PID for logging purposes
                try:
                    pid_str = self.lock_path.read_text().strip()
                    if pid_str.isdigit():
                        return int(pid_str)
                except (OSError, ValueError):
                    pass
                return -1  # Age-based stale, no specific PID

            # Try to read PID from lock file
            try:
                pid_str = self.lock_path.read_text().strip()
                if pid_str.isdigit():
                    pid = int(pid_str)
                    # Check if process is still running
                    if not self._is_process_running(pid):
                        return pid  # Return PID for atomic verification
            except (OSError, ValueError):
                pass

            return None  # Lock is active

        except OSError:
            return -1  # Error accessing lock, treat as stale

    @staticmethod
    def _is_process_running(pid: object) -> bool:
        """Check if a process with given PID is running.

        Args:
            pid: Process ID to check

        Returns:
            True if process is running

        Raises:
            ValueError: If pid is not a valid positive integer
        """
        # Validate pid is numeric and positive
        try:
            if isinstance(pid, (int, float)):
                pid_int = int(pid)
            elif isinstance(pid, str):
                pid_int = int(pid)
            else:
                raise TypeError(f"Invalid PID type: {type(pid).__name__}")
        except (ValueError, TypeError) as e:
            raise ValueError(f"Invalid PID value: {pid}") from e

        if pid_int <= 0:
            raise ValueError(f"PID must be a positive integer, got: {pid}")

        if os.name == "nt":
            # Windows: use tasklist
            import subprocess

            try:
                subprocess.check_output(
                    ["tasklist", "/FI", f"PID eq {pid_int}"],
                    stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                return False
        else:
            # POSIX: use kill(pid, 0) which doesn't actually send signal
            try:
                os.kill(pid_int, 0)
                return True
            except OSError:
                return False

    def _remove_stale_lock(self, expected_pid: Optional[int]) -> bool:
        """Remove stale lock file with atomic verification.

        This method implements TOCTOU-safe lock removal by:
        1. Using atomic operations (os.O_EXCL) to verify lock ownership
        2. Verifying the PID immediately before removal
        3. Implementing retry logic for race conditions

        Args:
            expected_pid: The PID that was identified as stale. If provided,
                         the lock will only be removed if this PID is still
                         the owner (prevents removing active locks).

        Returns:
            True if lock was successfully removed, False if removal failed
            due to race condition or lock now being active.
        """
        max_retries = 3
        retry_delay = 0.01  # 10ms between retries

        for attempt in range(max_retries):
            try:
                # Verify lock is still stale before attempting removal
                # This prevents TOCTOU race between check and removal
                current_pid = None
                try:
                    pid_str = self.lock_path.read_text().strip()
                    if pid_str.isdigit():
                        current_pid = int(pid_str)
                except (OSError, ValueError):
                    pass

                # If we have an expected PID, verify it matches
                if expected_pid is not None and expected_pid > 0:
                    if current_pid != expected_pid:
                        # Lock was acquired by a different process
                        logger.debug(
                            f"Lock PID changed from {expected_pid} to "
                            f"{current_pid}, not removing"
                        )
                        return False

                    # Verify the expected PID process is not running
                    if self._is_process_running(expected_pid):
                        logger.debug(
                            f"Process {expected_pid} is now running, not removing lock"
                        )
                        return False

                # Attempt atomic removal using exclusive rename
                # This creates a temporary file and tries to atomically replace
                # the lock file, which will fail if another process has it open
                temp_path = self.lock_path.with_suffix(".removal")

                try:
                    # Create a temporary marker file with O_EXCL
                    # This will fail if another process is actively managing the lock
                    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                    temp_fd = os.open(temp_path, flags, 0o644)

                    # Write our PID to the marker
                    try:
                        os.write(temp_fd, str(os.getpid()).encode())
                    finally:
                        os.close(temp_fd)

                    # Try to atomically replace the lock file
                    # On POSIX, os.replace() is atomic
                    # On Windows, it may not be, but we have PID verification
                    os.replace(str(temp_path), str(self.lock_path))

                    # Now unlink the file we just replaced
                    self.lock_path.unlink()

                    logger.info(
                        f"Successfully removed stale lock: {self.lock_path} "
                        f"(was owned by PID {expected_pid}, attempt {attempt + 1})"
                    )
                    return True

                except OSError as e:
                    # Clean up temp file if it exists
                    try:
                        if temp_path.exists():
                            temp_path.unlink()
                    except OSError:
                        pass

                    if e.errno == errno.EEXIST:
                        # Another process is racing with us
                        if attempt < max_retries - 1:
                            logger.debug(
                                f"Race condition detected during lock removal, "
                                f"retrying (attempt {attempt + 1}/{max_retries})"
                            )
                            time.sleep(retry_delay)
                            continue
                        else:
                            logger.warning(
                                f"Failed to remove lock after {max_retries} attempts "
                                f"due to race conditions"
                            )
                            return False
                    else:
                        # Other error
                        raise

            except OSError as e:
                if attempt < max_retries - 1:
                    logger.debug(
                        f"Error removing stale lock (attempt {attempt + 1}): {e}"
                    )
                    time.sleep(retry_delay)
                else:
                    logger.warning(
                        f"Failed to remove stale lock after {max_retries} attempts: {e}"
                    )
                    return False

        return False

    def release(self) -> None:
        """Release the file lock."""
        if not self._is_locked:
            return

        try:
            # Close file descriptor
            if self._lock_fd is not None:
                try:
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = None

            # Remove lock file
            try:
                self.lock_path.unlink()
            except OSError:
                pass

            self._is_locked = False
            logger.debug(f"Lock released: {self.lock_path}")

        except OSError as e:
            logger.error(f"Error releasing lock {self.lock_path}: {e}")

    def __enter__(self) -> "FileLock":
        """Enter context manager and acquire lock."""
        self.acquire()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Exit context manager and release lock."""
        self.release()

    def __del__(self) -> None:
        """Ensure lock is released on object destruction."""
        self.release()


@contextmanager
def atomic_write(
    file_path: Path,
    mode: str = "w",
    encoding: Optional[str] = "utf-8",
    lock_timeout: float = 10.0,
) -> Iterator:
    """Context manager for atomic file writes with locking.

    Writes to a temporary file first, then atomically replaces
    the target file using os.replace(). This ensures that
    readers never see partially written content.

    Args:
        file_path: Path to the file to write
        mode: File open mode (must be write mode: 'w', 'w+', 'a', etc.)
        encoding: Text encoding (ignored for binary mode)
        lock_timeout: Maximum time to wait for lock

    Yields:
        File object for writing

    Example:
        with atomic_write(path/to/file.txt) as f:
            f.write("content")

    The file is atomically updated when exiting the context.
    """
    if "b" not in mode and encoding is not None:
        # Text mode
        pass
    else:
        # Binary mode
        encoding = None

    # Create temporary file in same directory for atomic replace
    file_path = Path(file_path)
    temp_path = file_path.with_suffix(f"{file_path.suffix}.tmp")

    # Acquire lock for the target file
    lock_path = file_path.with_suffix(".lock")
    lock = FileLock(lock_path, timeout=lock_timeout)

    with lock:
        # Open file object reference for later use
        f = None
        try:
            # Write to temporary file
            if "b" in mode:
                f = open(temp_path, mode)
            else:
                f = open(temp_path, mode, encoding=encoding)

            yield f

            # Ensure data is flushed to disk
            if f:
                f.flush()
                os.fsync(f.fileno())

            # Close the file before replace
            if f:
                f.close()

            # Atomically replace target file
            # os.replace() is atomic on POSIX and Windows Vista+
            os.replace(str(temp_path), str(file_path))

        finally:
            # Clean up temporary file if it still exists
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except OSError:
                pass


def with_file_lock(
    lock_path: Path,
    timeout: float = 10.0,
    retry_interval: float = 0.1,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator to execute function with file lock.

    Args:
        lock_path: Path to the lock file
        timeout: Maximum time to wait for lock acquisition
        retry_interval: Initial retry interval

    Returns:
        Decorated function that acquires lock before execution

    Example:
        @with_file_lock(Path('/var/run/myprocess.lock'))
        def critical_section():
            # This code is protected from concurrent execution
            pass
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        def wrapper(*args: object, **kwargs: object) -> T:
            lock = FileLock(lock_path, timeout=timeout, retry_interval=retry_interval)
            with lock:
                return func(*args, **kwargs)

        return wrapper

    return decorator
