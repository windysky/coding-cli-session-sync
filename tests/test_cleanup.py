"""Tests for session cleanup helpers."""

import json

from session_sync.cleanup_session import (
    _delete_codex_session,
    _remove_claude_history_entries,
)
from session_sync.core import Session, discover_sessions


def test_codex_discovery_uses_relative_id(tmp_path):
    """Codex sessions should be identified by relative path under sessions root."""
    sessions_root = tmp_path / ".codex" / "sessions"
    session_dir = sessions_root / "2026" / "02" / "10"
    session_dir.mkdir(parents=True)
    (session_dir / "rollout-1.jsonl").write_text("test")

    sessions = discover_sessions(sessions_root, tool="codex")
    assert len(sessions) == 1
    assert sessions[0].session_id == "2026/02/10"


def test_cleanup_deletes_codex_session_dir(tmp_path):
    """Cleanup helper should delete the resolved Codex session directory."""
    sessions_root = tmp_path / ".codex" / "sessions"
    session_dir = sessions_root / "2026" / "02" / "10"
    session_dir.mkdir(parents=True)
    (session_dir / "rollout-1.jsonl").write_text("test")

    session = Session("2026/02/10", session_dir, tool="codex")
    deleted = _delete_codex_session(session, sessions_root, dry_run=False)
    assert deleted == 1
    assert not session_dir.exists()


def test_remove_claude_history_entries(tmp_path):
    """Claude history removal should delete matching sessionId lines."""
    history = tmp_path / "history.jsonl"
    history.write_text(
        "\n".join(
            [
                json.dumps({"sessionId": "keep", "timestamp": 1}),
                json.dumps({"sessionId": "remove", "timestamp": 2}),
            ]
        )
        + "\n"
    )

    removed, kept = _remove_claude_history_entries(history, {"remove"})
    assert removed == 1
    assert kept == 1
    text = history.read_text()
    assert "remove" not in text
    assert "keep" in text
