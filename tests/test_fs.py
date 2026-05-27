import unittest
from unittest.mock import MagicMock, patch
import os
import shutil
import tempfile
import base64

from src.config import config
from src.fs import file_dispatch, _read_remote_file_bytes, _write_remote_file_bytes
from src.utils import make_cache_dirs

class TestFS(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dirs = make_cache_dirs(self.test_dir)
        
        # Reset and mock global config
        config.PROJECT_ROOT = self.test_dir
        config.PROJECT_TAG = "test_project"
        config.CACHE_DIRS = self.cache_dirs
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_manager(self):
        mock_manager = MagicMock()
        mock_session = MagicMock()
        mock_manager.get_session.return_value = mock_session
        mock_manager.ensure_session.return_value = mock_session
        mock_session.ensure_alive.return_value = None
        mock_session.id = 1
        mock_session.name = "test_session"
        return mock_manager, mock_session

    def test_file_read_binary_detection(self):
        manager, session = self._create_mock_manager()
        
        # Mock file read function to return binary data containing null bytes
        binary_data = b"Some text\x00\x01\x02More binary data"
        with patch('src.fs._read_remote_file_bytes') as mock_read:
            mock_read.return_value = {
                "success": True,
                "data": binary_data,
                "method": "sftp",
                "truncated": False
            }
            
            # Execute read dispatch
            args = {"action": "read", "path": "/bin/echo", "max_chars": 100}
            res = file_dispatch(args, manager)
            
            self.assertTrue(res["success"])
            self.assertEqual(res["mode"], "binary_hidden")
            self.assertIn("File is binary", res["message"])
            self.assertEqual(res["size"], len(binary_data))

    def test_file_read_middle_truncation(self):
        manager, session = self._create_mock_manager()
        
        # Generate 100 lines of text
        lines = [f"Line {i} content" for i in range(1, 101)]
        long_text = "\n".join(lines)
        
        with patch('src.fs._read_remote_file_bytes') as mock_read:
            mock_read.return_value = {
                "success": True,
                "data": long_text.encode('utf-8'),
                "method": "sftp",
                "truncated": False
            }
            
            # Request reading with max_chars = 60
            args = {"action": "read", "path": "/var/log/syslog", "max_chars": 60}
            res = file_dispatch(args, manager)
            
            self.assertTrue(res["success"])
            self.assertTrue(res["truncated"])
            content = res["content"]
            
            # Should have the system warning in the middle
            self.assertIn("SYSTEM WARNING: Output truncated", content)
            # Should show start and end
            self.assertTrue(content.startswith("Line 1"))
            self.assertTrue(content.endswith("content"))

    def test_file_edit_ambiguous_matches(self):
        manager, session = self._create_mock_manager()
        
        file_content = (
            "def hello():\n"
            "    print('world')\n"
            "\n"
            "def goodbye():\n"
            "    print('world')\n"
        )
        
        with patch('src.fs._read_remote_file_bytes') as mock_read:
            mock_read.return_value = {
                "success": True,
                "data": file_content.encode('utf-8'),
                "method": "sftp",
                "truncated": False
            }
            
            # Try to edit "print('world')" without replace_all - it occurs twice!
            args = {
                "action": "edit",
                "path": "test.py",
                "edits": [
                    {
                        "old_text": "    print('world')",
                        "new_text": "    print('everyone')",
                        "replace_all": False
                    }
                ]
            }
            res = file_dispatch(args, manager)
            
            # Should fail due to ambiguity and return snippets with line numbers
            self.assertFalse(res["success"])
            self.assertIn("ambiguous old_text", res["error"])
            self.assertIn("Line 2:", res["error"])
            self.assertIn("Line 5:", res["error"])

    def test_file_edit_similarity_hints(self):
        manager, session = self._create_mock_manager()
        
        file_content = (
            "def calculate_total(price, tax):\n"
            "    return price + price * tax\n"
        )
        
        with patch('src.fs._read_remote_file_bytes') as mock_read:
            mock_read.return_value = {
                "success": True,
                "data": file_content.encode('utf-8'),
                "method": "sftp",
                "truncated": False
            }
            
            # Typo: "calculate_totals" instead of "calculate_total"
            args = {
                "action": "edit",
                "path": "test.py",
                "edits": [
                    {
                        "old_text": "def calculate_totals(price, tax):",
                        "new_text": "def get_total(price, tax):"
                    }
                ]
            }
            res = file_dispatch(args, manager)
            
            # Should fail with custom similarity diagnostic
            self.assertFalse(res["success"])
            self.assertIn("old_text not found", res["error"])
            self.assertIn("Did you mean one of these similar lines", res["error"])
            self.assertIn("Line 1: 'def calculate_total(price, tax):'", res["error"])

    def test_file_sandbox_readonly(self):
        manager, session = self._create_mock_manager()
        config.READ_ONLY = True
        
        # 1. Blocks write action
        args_write = {"action": "write", "path": "file.txt", "content": "hello"}
        res = file_dispatch(args_write, manager)
        self.assertFalse(res["success"])
        self.assertIn("blocked in read-only sandbox mode", res["error"])
        
        # 2. Blocks edit action
        args_edit = {"action": "edit", "path": "file.txt", "edits": [{"old_text": "a", "new_text": "b"}]}
        res = file_dispatch(args_edit, manager)
        self.assertFalse(res["success"])
        self.assertIn("blocked in read-only sandbox mode", res["error"])

        # 3. Blocks upload action
        args_upload = {"action": "upload", "path": "file.txt", "local_path": "local.txt"}
        res = file_dispatch(args_upload, manager)
        self.assertFalse(res["success"])
        self.assertIn("blocked in read-only sandbox mode", res["error"])

        # 4. Allows read/list actions
        with patch('src.fs._read_remote_file_bytes') as mock_read:
            mock_read.return_value = {"success": True, "data": b"content", "method": "sftp"}
            args_read = {"action": "read", "path": "file.txt"}
            res = file_dispatch(args_read, manager)
            self.assertTrue(res["success"])

if __name__ == "__main__":
    unittest.main()
