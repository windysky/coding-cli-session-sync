"""Tests for Claude selective export/import behaviors."""

import json
import tarfile
from unittest.mock import patch

from session_sync.core import Session, create_archive_multiple
from session_sync.import_session import merge_claude_history


def test_claude_export_filters_history_jsonl(tmp_path):
    """Exported Claude archives should include only selected sessionIds in history.jsonl."""
    claude_dir = tmp_path / ".claude"
    session_env_dir = claude_dir / "session-env"
    claude_dir.mkdir(parents=True)

    session_a = "sess-a"
    session_b = "sess-b"

    (session_env_dir / session_a).mkdir(parents=True)
    (session_env_dir / session_a / "a.txt").write_text("a")
    (session_env_dir / session_b).mkdir(parents=True)
    (session_env_dir / session_b / "b.txt").write_text("b")

    history_entries = [
        {"sessionId": session_a, "display": "A", "timestamp": 1},
        {"sessionId": session_b, "display": "B", "timestamp": 2},
    ]
    (claude_dir / "history.jsonl").write_text(
        "\n".join(json.dumps(e) for e in history_entries)
    )

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    sessions = [Session(session_a, session_env_dir / session_a, tool="claude")]

    with patch("session_sync.core.get_hostname", return_value="test-host"):
        archive_path = create_archive_multiple(
            sessions=sessions,
            config_dir=claude_dir,
            output_dir=output_dir,
            hostname="test-host",
            archive_name="claude-selective.tgz",
        )

    with tarfile.open(archive_path, "r:gz") as tar:
        history_member = tar.extractfile(".claude/history.jsonl")
        assert history_member is not None
        content = history_member.read().decode("utf-8")

    assert session_a in content
    assert session_b not in content


def test_merge_claude_history_respects_allowlist(tmp_path):
    """merge_claude_history should filter by allowed_session_ids when provided."""
    target = tmp_path / "history-target.jsonl"
    archive = tmp_path / "history-archive.jsonl"

    target.write_text("")
    archive.write_text(
        "\n".join(
            [
                json.dumps({"sessionId": "keep", "display": "Keep", "timestamp": 1}),
                json.dumps({"sessionId": "drop", "display": "Drop", "timestamp": 2}),
            ]
        )
        + "\n"
    )

    added, skipped = merge_claude_history(target, archive, allowed_session_ids={"keep"})
    assert added == 1
    assert skipped >= 1
    assert "keep" in target.read_text()
    assert "drop" not in target.read_text()
