"""Tests for Codex archive path preservation and install behavior."""

import tarfile
from pathlib import Path
from unittest.mock import patch

from session_sync.core import Session, create_archive_multiple
from session_sync.import_session import install_codex_sessions_from_extracted


def test_codex_export_uses_dot_codex_sessions_prefix(tmp_path):
    """Codex exports should preserve sessions under .codex/sessions/ in the archive."""
    codex_dir = tmp_path / ".codex"
    session_dir = codex_dir / "sessions" / "2026" / "01" / "test-session"
    session_dir.mkdir(parents=True)
    (session_dir / "rollout-1.jsonl").write_text("test")

    output_dir = tmp_path / "out"
    output_dir.mkdir()

    sessions = [Session("test-session", session_dir, tool="codex")]

    with patch("session_sync.core.get_hostname", return_value="test-host"):
        archive_path = create_archive_multiple(
            sessions=sessions,
            config_dir=codex_dir,
            output_dir=output_dir,
            hostname="test-host",
            archive_name="codex-one.tgz",
        )

    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getnames()

    assert any(
        m.endswith(".codex/sessions/2026/01/test-session/rollout-1.jsonl")
        or m == ".codex/sessions/2026/01/test-session/rollout-1.jsonl"
        for m in members
    )


def test_codex_install_from_extracted_preserves_year_month(tmp_path, monkeypatch):
    """Codex import should restore sessions preserving YYYY/MM structure."""
    extracted_root = tmp_path / "extracted"
    extracted_sessions = (
        extracted_root / ".codex" / "sessions" / "2026" / "01" / "test-session"
    )
    extracted_sessions.mkdir(parents=True)
    (extracted_sessions / "rollout-1.jsonl").write_text("test")
    (extracted_root / ".codex" / "config.toml").write_text("[config]\n")

    temp_home = tmp_path / "home"
    temp_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: temp_home)

    imported = install_codex_sessions_from_extracted(
        extracted_root,
        selected_session_ids=["test-session"],
        target_codex_dir=temp_home / ".codex",
    )
    assert imported == 1

    restored = (
        temp_home
        / ".codex"
        / "sessions"
        / "2026"
        / "01"
        / "test-session"
        / "rollout-1.jsonl"
    )
    assert restored.exists()

    restored_config = temp_home / ".codex" / "config.toml"
    assert restored_config.exists()
