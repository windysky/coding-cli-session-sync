"""Tests for comprehensive OpenCode export/import including all session data.

This test suite verifies that OpenCode archives include:
- Main session JSON file from storage/session/global/
- Message storage from storage/message/{sessionId}/
- Part files from storage/part/{sessionId}*
- Directory-readme metadata from storage/directory-readme/{sessionId}.json
"""

import json
import tarfile
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

from session_sync.core import (
    Metadata,
    Session,
    create_archive,
    extract_archive,
)


class TestOpenCodeFullExport:
    """Test OpenCode export with all session data."""

    def test_export_includes_message_directory(self, tmp_path):
        """Test that export includes message storage directory."""
        # Create OpenCode config directory structure
        config_dir = tmp_path / '.local' / 'share' / 'opencode'
        config_dir.mkdir(parents=True)

        # Create main session file
        session_file = config_dir / 'storage' / 'session' / 'global' / 'ses_test123.json'
        session_file.parent.mkdir(parents=True)
        session_data = {
            'id': 'ses_test123',
            'title': 'Test OpenCode Session',
            'createdAt': '2025-01-15T10:30:00',
            'updatedAt': '2025-02-07T14:20:00'
        }
        session_file.write_text(json.dumps(session_data))

        # Create message storage directory with files
        message_dir = config_dir / 'storage' / 'message' / 'ses_test123'
        message_dir.mkdir(parents=True)
        (message_dir / 'msg_001.json').write_text('{"role": "user", "content": "Hello"}')
        (message_dir / 'msg_002.json').write_text('{"role": "assistant", "content": "Hi there"}')

        session = Session('ses_test123', session_file, tool='opencode')

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with patch('session_sync.core.get_hostname', return_value='test-host'):
            archive_path = create_archive(
                session=session,
                config_dir=config_dir,
                output_dir=output_dir,
                hostname='test-host'
            )

        # Verify archive exists and contains message files
        assert archive_path.exists()

        with tarfile.open(archive_path, 'r:gz') as tar:
            members = tar.getnames()
            # Check for message files with opencode/ prefix
            assert any('opencode/storage/message/ses_test123/msg_001.json' in m for m in members)
            assert any('opencode/storage/message/ses_test123/msg_002.json' in m for m in members)

    def test_export_includes_part_files(self, tmp_path):
        """Test that export includes part files (large data files)."""
        # Create OpenCode config directory structure
        config_dir = tmp_path / '.local' / 'share' / 'opencode'
        config_dir.mkdir(parents=True)

        # Create main session file
        session_file = config_dir / 'storage' / 'session' / 'global' / 'ses_parttest.json'
        session_file.parent.mkdir(parents=True)
        session_data = {
            'id': 'ses_parttest',
            'title': 'Session with Part Files',
            'createdAt': '2025-01-15T10:30:00'
        }
        session_file.write_text(json.dumps(session_data))

        # Create part storage directory with part files
        part_dir = config_dir / 'storage' / 'part'
        part_dir.mkdir(parents=True)
        (part_dir / 'ses_parttest_001.bin').write_bytes(b'\x00' * 1000)
        (part_dir / 'ses_parttest_002.bin').write_bytes(b'\x00' * 2000)
        # This file should NOT be included (different session ID)
        (part_dir / 'ses_other_001.bin').write_bytes(b'\x00' * 500)

        session = Session('ses_parttest', session_file, tool='opencode')

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with patch('session_sync.core.get_hostname', return_value='test-host'):
            archive_path = create_archive(
                session=session,
                config_dir=config_dir,
                output_dir=output_dir,
                hostname='test-host'
            )

        # Verify archive contains correct part files
        with tarfile.open(archive_path, 'r:gz') as tar:
            members = tar.getnames()
            assert any('opencode/storage/part/ses_parttest_001.bin' in m for m in members)
            assert any('opencode/storage/part/ses_parttest_002.bin' in m for m in members)
            # Other session part files should not be included
            assert not any('ses_other_001.bin' in m for m in members)

    def test_export_includes_directory_readme(self, tmp_path):
        """Test that export includes directory-readme metadata."""
        # Create OpenCode config directory structure
        config_dir = tmp_path / '.local' / 'share' / 'opencode'
        config_dir.mkdir(parents=True)

        # Create main session file
        session_file = config_dir / 'storage' / 'session' / 'global' / 'ses_readme.json'
        session_file.parent.mkdir(parents=True)
        session_data = {
            'id': 'ses_readme',
            'title': 'Session with Directory Readme',
            'createdAt': '2025-01-15T10:30:00'
        }
        session_file.write_text(json.dumps(session_data))

        # Create directory-readme metadata file
        readme_dir = config_dir / 'storage' / 'directory-readme'
        readme_dir.mkdir(parents=True)
        readme_file = readme_dir / 'ses_readme.json'
        readme_data = {
            'sessionId': 'ses_readme',
            'directories': ['src/', 'tests/'],
            'lastUpdated': '2025-02-07T14:20:00'
        }
        readme_file.write_text(json.dumps(readme_data))

        session = Session('ses_readme', session_file, tool='opencode')

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with patch('session_sync.core.get_hostname', return_value='test-host'):
            archive_path = create_archive(
                session=session,
                config_dir=config_dir,
                output_dir=output_dir,
                hostname='test-host'
            )

        # Verify archive contains directory-readme
        with tarfile.open(archive_path, 'r:gz') as tar:
            members = tar.getnames()
            assert any('opencode/storage/directory-readme/ses_readme.json' in m for m in members)

    def test_export_full_session_all_components(self, tmp_path):
        """Test export with all session components."""
        # Create complete OpenCode session structure
        config_dir = tmp_path / '.local' / 'share' / 'opencode'
        config_dir.mkdir(parents=True)

        session_id = 'ses_complete'
        session_file = config_dir / 'storage' / 'session' / 'global' / f'{session_id}.json'
        session_file.parent.mkdir(parents=True)

        session_data = {
            'id': session_id,
            'title': 'Complete Session',
            'createdAt': '2025-01-15T10:30:00',
            'updatedAt': '2025-02-07T14:20:00'
        }
        session_file.write_text(json.dumps(session_data))

        # Create message storage
        message_dir = config_dir / 'storage' / 'message' / session_id
        message_dir.mkdir(parents=True)
        (message_dir / 'conversation.jsonl').write_text('{"messages": []}')

        # Create part files
        part_dir = config_dir / 'storage' / 'part'
        part_dir.mkdir(parents=True)
        (part_dir / f'{session_id}_data.bin').write_bytes(b'data')

        # Create directory-readme
        readme_dir = config_dir / 'storage' / 'directory-readme'
        readme_dir.mkdir(parents=True)
        (readme_dir / f'{session_id}.json').write_text('{"dirs": []}')

        session = Session(session_id, session_file, tool='opencode')

        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with patch('session_sync.core.get_hostname', return_value='test-host'):
            archive_path = create_archive(
                session=session,
                config_dir=config_dir,
                output_dir=output_dir,
                hostname='test-host'
            )

        # Verify all components are in archive
        with tarfile.open(archive_path, 'r:gz') as tar:
            members = tar.getnames()
            # Main session file
            assert f'{session_id}.json' in members
            # Message storage
            assert any(f'opencode/storage/message/{session_id}/conversation.jsonl' in m for m in members)
            # Part files
            assert any(f'opencode/storage/part/{session_id}_data.bin' in m for m in members)
            # Directory-readme
            assert any(f'opencode/storage/directory-readme/{session_id}.json' in m for m in members)
            # Metadata
            assert 'metadata.json' in members

    def test_metadata_lists_all_opencode_components(self, tmp_path):
        """Test that metadata lists all OpenCode session data locations."""
        session_file = tmp_path / 'ses_test.json'
        session_data = {
            'id': 'ses_test',
            'title': 'Test Session',
            'createdAt': '2025-01-15T10:30:00'
        }
        session_file.write_text(json.dumps(session_data))

        session = Session('ses_test', session_file, tool='opencode')
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname='test-host',
            session=session,
            archive_filename='opencode-session-test.tgz',
            checksum_sha256='abc123',
            size_bytes=1024,
            file_count=5
        )

        metadata_dict = metadata.to_dict()

        # Verify all components are listed in metadata
        contents = metadata_dict['contents']
        assert contents['type'] == 'opencode_session'
        assert 'session_file' in contents
        assert 'message_directory' in contents
        assert 'part_files' in contents
        assert 'directory_readme' in contents

        # Verify paths are correct
        assert contents['session_file'] == 'storage/session/global/ses_test.json'
        assert contents['message_directory'] == 'storage/message/ses_test/'
        assert contents['part_files'] == 'storage/part/ses_test*'
        assert contents['directory_readme'] == 'storage/directory-readme/ses_test.json'


class TestOpenCodeFullImport:
    """Test OpenCode import with all session data."""

    def test_import_restores_message_files(self, tmp_path, monkeypatch):
        """Test that import restores message files to correct location."""
        # Create a test archive with message files
        archive_file = tmp_path / 'opencode-session-test.tgz'

        # Create metadata
        session_file = tmp_path / 'ses_test.json'
        session_data = {
            'id': 'ses_test',
            'title': 'Test Session'
        }
        session_file.write_text(json.dumps(session_data))

        session = Session('ses_test', session_file, tool='opencode')
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname='test-host',
            session=session,
            archive_filename='opencode-session-test.tgz',
            checksum_sha256='abc123',
            size_bytes=1024,
            file_count=3
        )

        # Create archive with message files
        with tarfile.open(archive_file, 'w:gz') as tar:
            # Add metadata
            metadata_json = tmp_path / 'temp_metadata.json'
            metadata.save(metadata_json)
            tar.add(metadata_json, arcname='metadata.json')
            metadata_json.unlink()

            # Add main session file (old format for backward compat)
            tar.add(session_file, arcname='ses_test.json')

            # Add message files with opencode/ prefix
            msg_file = tmp_path / 'msg_001.json'
            msg_file.write_text('{"role": "user"}')
            tar.add(msg_file, arcname='opencode/storage/message/ses_test/msg_001.json')
            msg_file.unlink()

        # Set up temporary home directory for extraction
        temp_home = tmp_path / 'home'
        temp_home.mkdir()
        monkeypatch.setattr(Path, 'home', lambda: temp_home)

        # Extract archive
        target_dir = tmp_path / 'extracted'
        target_dir.mkdir()
        result = extract_archive(archive_file, target_dir)

        assert result is True

        # Verify message file was restored to correct location
        opencode_storage = temp_home / '.local' / 'share' / 'opencode'
        restored_msg = opencode_storage / 'storage' / 'message' / 'ses_test' / 'msg_001.json'
        assert restored_msg.exists()
        assert json.loads(restored_msg.read_text()) == {"role": "user"}

    def test_import_restores_part_files(self, tmp_path, monkeypatch):
        """Test that import restores part files to correct location."""
        archive_file = tmp_path / 'opencode-session-test.tgz'

        # Create metadata
        session_file = tmp_path / 'ses_part.json'
        session_data = {'id': 'ses_part', 'title': 'Part Session'}
        session_file.write_text(json.dumps(session_data))

        session = Session('ses_part', session_file, tool='opencode')
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname='test-host',
            session=session,
            archive_filename='opencode-session-test.tgz',
            checksum_sha256='abc123',
            size_bytes=1024,
            file_count=2
        )

        # Create archive with part files
        with tarfile.open(archive_file, 'w:gz') as tar:
            # Add metadata
            metadata_json = tmp_path / 'temp_metadata.json'
            metadata.save(metadata_json)
            tar.add(metadata_json, arcname='metadata.json')
            metadata_json.unlink()

            # Add part files with opencode/ prefix
            part_file = tmp_path / 'ses_part_data.bin'
            part_file.write_bytes(b'\x00' * 1000)
            tar.add(part_file, arcname='opencode/storage/part/ses_part_data.bin')
            part_file.unlink()

        # Set up temporary home directory
        temp_home = tmp_path / 'home'
        temp_home.mkdir()
        monkeypatch.setattr(Path, 'home', lambda: temp_home)

        # Extract archive
        target_dir = tmp_path / 'extracted'
        target_dir.mkdir()
        result = extract_archive(archive_file, target_dir)

        assert result is True

        # Verify part file was restored
        opencode_storage = temp_home / '.local' / 'share' / 'opencode'
        restored_part = opencode_storage / 'storage' / 'part' / 'ses_part_data.bin'
        assert restored_part.exists()
        assert len(restored_part.read_bytes()) == 1000

    def test_import_restores_directory_readme(self, tmp_path, monkeypatch):
        """Test that import restores directory-readme to correct location."""
        archive_file = tmp_path / 'opencode-session-test.tgz'

        # Create metadata
        session_file = tmp_path / 'ses_readme.json'
        session_data = {'id': 'ses_readme', 'title': 'Readme Session'}
        session_file.write_text(json.dumps(session_data))

        session = Session('ses_readme', session_file, tool='opencode')
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname='test-host',
            session=session,
            archive_filename='opencode-session-test.tgz',
            checksum_sha256='abc123',
            size_bytes=1024,
            file_count=2
        )

        # Create archive with directory-readme
        with tarfile.open(archive_file, 'w:gz') as tar:
            # Add metadata
            metadata_json = tmp_path / 'temp_metadata.json'
            metadata.save(metadata_json)
            tar.add(metadata_json, arcname='metadata.json')
            metadata_json.unlink()

            # Add directory-readme with opencode/ prefix
            readme_file = tmp_path / 'ses_readme.json'
            readme_data = {'sessionId': 'ses_readme', 'dirs': ['src/', 'tests/']}
            readme_file.write_text(json.dumps(readme_data))
            tar.add(readme_file, arcname='opencode/storage/directory-readme/ses_readme.json')
            readme_file.unlink()

        # Set up temporary home directory
        temp_home = tmp_path / 'home'
        temp_home.mkdir()
        monkeypatch.setattr(Path, 'home', lambda: temp_home)

        # Extract archive
        target_dir = tmp_path / 'extracted'
        target_dir.mkdir()
        result = extract_archive(archive_file, target_dir)

        assert result is True

        # Verify directory-readme was restored
        opencode_storage = temp_home / '.local' / 'share' / 'opencode'
        restored_readme = opencode_storage / 'storage' / 'directory-readme' / 'ses_readme.json'
        assert restored_readme.exists()
        assert json.loads(restored_readme.read_text())['dirs'] == ['src/', 'tests/']

    def test_import_backward_compatible_old_format(self, tmp_path, monkeypatch):
        """Test that import handles old format archives without opencode/ prefix."""
        archive_file = tmp_path / 'opencode-session-old.tgz'

        # Create metadata (old format)
        session_file = tmp_path / 'ses_old.json'
        session_data = {'id': 'ses_old', 'title': 'Old Format Session'}
        session_file.write_text(json.dumps(session_data))

        session = Session('ses_old', session_file, tool='opencode')
        metadata = Metadata(
            export_timestamp=datetime.now(),
            source_hostname='test-host',
            session=session,
            archive_filename='opencode-session-old.tgz',
            checksum_sha256='abc123',
            size_bytes=1024,
            file_count=1
        )

        # Create old format archive (no opencode/ prefix, just session file)
        with tarfile.open(archive_file, 'w:gz') as tar:
            # Add metadata
            metadata_json = tmp_path / 'temp_metadata.json'
            metadata.save(metadata_json)
            tar.add(metadata_json, arcname='metadata.json')
            metadata_json.unlink()

            # Add session file directly (old format)
            tar.add(session_file, arcname='ses_old.json')

        # Set up temporary home directory
        temp_home = tmp_path / 'home'
        temp_home.mkdir()
        monkeypatch.setattr(Path, 'home', lambda: temp_home)

        # Extract archive
        target_dir = tmp_path / 'extracted'
        target_dir.mkdir()
        result = extract_archive(archive_file, target_dir)

        assert result is True

        # Verify session file was restored to global session directory
        opencode_storage = temp_home / '.local' / 'share' / 'opencode'
        restored_session = opencode_storage / 'storage' / 'session' / 'global' / 'ses_old.json'
        assert restored_session.exists()
        assert json.loads(restored_session.read_text())['id'] == 'ses_old'


class TestOpenCodeExportImportRoundTrip:
    """Test full round-trip export and import."""

    def test_full_round_trip_preserves_all_data(self, tmp_path, monkeypatch):
        """Test that export then import preserves all session data."""
        # Create complete OpenCode session
        config_dir = tmp_path / '.local' / 'share' / 'opencode'
        config_dir.mkdir(parents=True)

        session_id = 'ses_roundtrip'
        session_file = config_dir / 'storage' / 'session' / 'global' / f'{session_id}.json'
        session_file.parent.mkdir(parents=True)

        session_data = {
            'id': session_id,
            'title': 'Round Trip Test Session',
            'createdAt': '2025-01-15T10:30:00',
            'updatedAt': '2025-02-07T14:20:00',
            'messages': ['msg1', 'msg2', 'msg3']
        }
        session_file.write_text(json.dumps(session_data))

        # Create message storage
        message_dir = config_dir / 'storage' / 'message' / session_id
        message_dir.mkdir(parents=True)
        (message_dir / 'msg_001.json').write_text('{"role": "user", "content": "Hello"}')
        (message_dir / 'msg_002.json').write_text('{"role": "assistant", "content": "Hi"}')

        # Create part files
        part_dir = config_dir / 'storage' / 'part'
        part_dir.mkdir(parents=True)
        (part_dir / f'{session_id}_data.bin').write_bytes(b'\x01\x02\x03\x04\x05')

        # Create directory-readme
        readme_dir = config_dir / 'storage' / 'directory-readme'
        readme_dir.mkdir(parents=True)
        readme_data = {'sessionId': session_id, 'directories': ['src/', 'tests/']}
        (readme_dir / f'{session_id}.json').write_text(json.dumps(readme_data))

        session = Session(session_id, session_file, tool='opencode')

        # Export session
        output_dir = tmp_path / 'output'
        output_dir.mkdir()

        with patch('session_sync.core.get_hostname', return_value='test-host'):
            archive_path = create_archive(
                session=session,
                config_dir=config_dir,
                output_dir=output_dir,
                hostname='test-host'
            )

        assert archive_path.exists()

        # Set up fresh home directory for import
        import_home = tmp_path / 'import_home'
        import_home.mkdir()
        monkeypatch.setattr(Path, 'home', lambda: import_home)

        # Import session
        extract_dir = tmp_path / 'extracted'
        extract_dir.mkdir()
        result = extract_archive(archive_path, extract_dir)

        assert result is True

        # Verify all data was restored
        opencode_storage = import_home / '.local' / 'share' / 'opencode'

        # Check main session file
        restored_session = opencode_storage / 'storage' / 'session' / 'global' / f'{session_id}.json'
        assert restored_session.exists()
        restored_data = json.loads(restored_session.read_text())
        assert restored_data['title'] == 'Round Trip Test Session'
        assert restored_data['messages'] == ['msg1', 'msg2', 'msg3']

        # Check message files
        restored_msg1 = opencode_storage / 'storage' / 'message' / session_id / 'msg_001.json'
        restored_msg2 = opencode_storage / 'storage' / 'message' / session_id / 'msg_002.json'
        assert restored_msg1.exists()
        assert restored_msg2.exists()
        assert json.loads(restored_msg1.read_text())['role'] == 'user'
        assert json.loads(restored_msg2.read_text())['role'] == 'assistant'

        # Check part file
        restored_part = opencode_storage / 'storage' / 'part' / f'{session_id}_data.bin'
        assert restored_part.exists()
        assert restored_part.read_bytes() == b'\x01\x02\x03\x04\x05'

        # Check directory-readme
        restored_readme = opencode_storage / 'storage' / 'directory-readme' / f'{session_id}.json'
        assert restored_readme.exists()
        restored_readme_data = json.loads(restored_readme.read_text())
        assert restored_readme_data['directories'] == ['src/', 'tests/']
