import unittest
from unittest.mock import MagicMock, patch
import os
import shutil
import tempfile
import base64

from src.config import config
from src.fs import file_dispatch, _read_remote_file_bytes, _write_remote_file_bytes, _download_remote_to_path
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
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_manager(self):
        mock_manager = MagicMock()
        mock_node = MagicMock()
        mock_session = MagicMock()
        mock_node.alias = "default"
        mock_node.server_config.read_only = False
        mock_node.get_session.return_value = mock_session
        mock_node.ensure_session.return_value = mock_session
        mock_session.ensure_alive.return_value = None
        mock_session.is_busy.return_value = False
        mock_session.is_dead = False
        mock_session.death_reason = None
        mock_session.id = 1
        mock_session.name = "test_session"
        mock_manager.resolve_target_for_args.return_value = (mock_node, 1, False, None)
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
        self.assertIn("blocked in read-only guardrail mode", res["error"])
        
        # 2. Blocks edit action
        args_edit = {"action": "edit", "path": "file.txt", "edits": [{"old_text": "a", "new_text": "b"}]}
        res = file_dispatch(args_edit, manager)
        self.assertFalse(res["success"])
        self.assertIn("blocked in read-only guardrail mode", res["error"])

        # 3. Blocks upload action
        args_upload = {"action": "upload", "path": "file.txt", "local_path": "local.txt"}
        res = file_dispatch(args_upload, manager)
        self.assertFalse(res["success"])
        self.assertIn("blocked in read-only guardrail mode", res["error"])

        # 4. Allows read/list actions
        with patch('src.fs._read_remote_file_bytes') as mock_read:
            mock_read.return_value = {"success": True, "data": b"content", "method": "sftp"}
            args_read = {"action": "read", "path": "file.txt"}
            res = file_dispatch(args_read, manager)
            self.assertTrue(res["success"])

    def test_resolve_local_path_sandboxing_and_drive_handling(self):
        from src.utils import resolve_local_path
        
        # Valid path inside project_root
        valid_file = os.path.join(self.test_dir, "test.txt")
        self.assertEqual(resolve_local_path(valid_file), os.path.abspath(valid_file))

        # System temp is denied by default (shared/world-writable), allowed with the flag
        temp_file = os.path.join(tempfile.gettempdir(), "test_mcp_temp.txt")
        self.assertEqual(resolve_local_path(temp_file), "")
        previous_temp = config.ALLOW_SYSTEM_TEMP
        try:
            config.ALLOW_SYSTEM_TEMP = True
            self.assertEqual(resolve_local_path(temp_file), os.path.abspath(temp_file))
        finally:
            config.ALLOW_SYSTEM_TEMP = previous_temp
        
        # Invalid path outside both project_root and system temp
        outside_file = os.path.abspath(os.path.join(tempfile.gettempdir(), "..", "outside_forbidden.txt"))
        self.assertEqual(resolve_local_path(outside_file), "")

        # Windows different drive error handling: simulate ValueError from commonpath
        with patch('os.path.commonpath', side_effect=ValueError("Paths don't have the same drive")):
            self.assertEqual(resolve_local_path("C:\\some\\file.txt"), "")

    def test_gateway_dir_and_gateway_files_are_protected(self):
        """T0.1/F2: the gateway's own code must never be rewritten through the file tool."""
        from src.utils import resolve_local_path
        previous_root = config.PROJECT_ROOT
        previous_flag = config.ALLOW_GATEWAY_DIR
        try:
            config.PROJECT_ROOT = config.GATEWAY_ROOT
            config.ALLOW_GATEWAY_DIR = False
            src_file = os.path.join(config.GATEWAY_ROOT, "src", "utils.py")
            entry = os.path.join(config.GATEWAY_ROOT, "mcp-server.py")
            doc_file = os.path.join(config.GATEWAY_ROOT, "PLAN.md")
            self.assertEqual(resolve_local_path(src_file), "")
            self.assertEqual(resolve_local_path(entry), "")
            self.assertEqual(resolve_local_path(doc_file), "")
            config.ALLOW_GATEWAY_DIR = True
            # the flag opens the repo, but never the gateway's executable parts
            self.assertEqual(resolve_local_path(doc_file), os.path.realpath(doc_file))
            self.assertEqual(resolve_local_path(src_file), "")
            self.assertEqual(resolve_local_path(entry), "")
        finally:
            config.PROJECT_ROOT = previous_root
            config.ALLOW_GATEWAY_DIR = previous_flag

    def test_cache_inside_gateway_dir_is_allowed(self):
        """The default layout keeps .ssh-cache inside the install dir - the cache is the
        gateway's own scratch space and must beat the gateway-dir deny."""
        from src.utils import resolve_local_path
        previous_root = config.PROJECT_ROOT
        previous_cache = config.CACHE_DIRS
        cache = os.path.join(config.GATEWAY_ROOT, ".ssh-cache")
        try:
            config.PROJECT_ROOT = config.GATEWAY_ROOT
            config.CACHE_DIRS = {"cache_root": cache}
            inside = os.path.join(cache, "tmp", "x.bin")
            self.assertEqual(resolve_local_path(inside), os.path.realpath(inside))
            # ordinary gateway files stay refused for writes
            self.assertEqual(resolve_local_path(os.path.join(config.GATEWAY_ROOT, "PLAN.md")), "")
        finally:
            config.PROJECT_ROOT = previous_root
            config.CACHE_DIRS = previous_cache

    def test_mcp_config_files_are_protected_anywhere(self):
        """T0.1/F2: mcp.json / mcp-server.py hold commands and secrets - never writable."""
        from src.utils import resolve_local_path
        for name in ("mcp.json", "mcp-server.py"):
            blocked = os.path.join(self.test_dir, name)
            self.assertEqual(resolve_local_path(blocked), "", name)

    def test_upload_allows_reading_project_files_in_gateway_dir(self):
        """resolve_local_path(..., for_write=False) allows reading project scripts for upload."""
        from src.utils import resolve_local_path
        previous_root = config.PROJECT_ROOT
        try:
            config.PROJECT_ROOT = config.GATEWAY_ROOT
            src_file = os.path.join(config.GATEWAY_ROOT, "src", "utils.py")
            # for_write=False (upload) is allowed
            self.assertEqual(resolve_local_path(src_file, for_write=False), os.path.realpath(src_file))
            # for_write=True (download) is blocked
            self.assertEqual(resolve_local_path(src_file, for_write=True), "")
        finally:
            config.PROJECT_ROOT = previous_root

    def test_upload_blocks_credential_files_even_on_read(self):
        """Credential files (id_rsa, servers.json) are denied even with for_write=False."""
        from src.utils import resolve_local_path
        key_file = os.path.join(self.test_dir, "id_rsa")
        self.assertEqual(resolve_local_path(key_file, for_write=False), "")
        cfg_file = os.path.join(self.test_dir, "servers.json")
        self.assertEqual(resolve_local_path(cfg_file, for_write=False), "")

    def test_cache_root_is_allowed_when_project_root_is_empty(self):
        """T0.1/F2: the gateway-private cache stays usable even without a project root."""
        from src.utils import resolve_local_path
        previous_root = config.PROJECT_ROOT
        previous_cache = config.CACHE_DIRS
        cache = os.path.join(self.test_dir, "gw-cache")
        os.makedirs(cache, exist_ok=True)
        try:
            config.PROJECT_ROOT = ""
            config.CACHE_DIRS = {"cache_root": cache}
            inside = os.path.join(cache, "tmp", "x.bin")
            self.assertEqual(resolve_local_path(inside), os.path.realpath(inside))
            self.assertEqual(resolve_local_path(os.path.join(self.test_dir, "outside.bin")), "")
        finally:
            config.PROJECT_ROOT = previous_root
            config.CACHE_DIRS = previous_cache

    def test_read_remote_file_bytes_closes_channels_in_finally(self):
        """Verify _read_remote_file_bytes closes stdin, stdout, stderr streams even on error."""
        session = MagicMock()
        session.open_sftp.return_value = None  # force fallback to exec_command
        session.client = MagicMock()

        m_stdin = MagicMock()
        m_stdout = MagicMock()
        m_stderr = MagicMock()

        m_stdout.read.side_effect = RuntimeError("Socket dropped")
        session.client.exec_command.return_value = (m_stdin, m_stdout, m_stderr)

        with patch('src.fs._sync_shell', return_value={"success": False, "error": "fallback failed"}):
            res = _read_remote_file_bytes(session, "/tmp/foo", max_bytes=1000)

        self.assertTrue(m_stdin.close.called)
        self.assertTrue(m_stdout.close.called)
        self.assertTrue(m_stderr.close.called)

    def test_write_remote_file_bytes_closes_channels_in_finally(self):
        """Verify _write_remote_file_bytes closes all streams in finally block."""
        session = MagicMock()
        session.open_sftp.return_value = None  # force fallback to exec_command
        session.client = MagicMock()

        m_stdin_dir = MagicMock()
        m_stdout_dir = MagicMock()
        m_stderr_dir = MagicMock()

        m_stdin = MagicMock()
        m_stdout = MagicMock()
        m_stderr = MagicMock()

        m_stdin.write.side_effect = IOError("Pipe broke")
        session.client.exec_command.side_effect = [
            (m_stdin_dir, m_stdout_dir, m_stderr_dir),
            (m_stdin, m_stdout, m_stderr)
        ]

        with patch('src.fs._sync_shell', return_value={"success": False, "error": "fallback failed"}):
            res = _write_remote_file_bytes(session, "/tmp/test.txt", b"hello")

        self.assertTrue(m_stdin_dir.close.called)
        self.assertTrue(m_stdout_dir.close.called)
        self.assertTrue(m_stderr_dir.close.called)
        self.assertTrue(m_stdin.close.called)
        self.assertTrue(m_stdout.close.called)
        self.assertTrue(m_stderr.close.called)

    def test_shell_path_injection_defense(self):
        """Verify remote shell command construction safely escapes single quotes."""
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()

        m_stdin = MagicMock()
        m_stdout = MagicMock()
        m_stderr = MagicMock()
        m_stdout.read.return_value = b"data"
        m_stdout.channel.recv_exit_status.return_value = 0
        session.client.exec_command.return_value = (m_stdin, m_stdout, m_stderr)

        malicious_path = "/tmp/test'; rm -rf /; '"
        _read_remote_file_bytes(session, malicious_path, max_bytes=1000)

        called_cmd = session.client.exec_command.call_args[0][0]
        # Command should contain escaped quotes and not a naked unescaped injection
        self.assertIn("/tmp/test'\\''", called_cmd)
        self.assertNotIn("cat '/tmp/test'; rm -rf /; ''", called_cmd)

    def test_exec_cat_sets_channel_timeout(self):
        """Verify exec_command channel timeout is configured to prevent worker thread hang (Fix C2)."""
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()

        m_stdin = MagicMock()
        m_stdout = MagicMock()
        m_stderr = MagicMock()
        m_stdout.read.return_value = b"test content"
        m_stdout.channel.recv_exit_status.return_value = 0
        session.client.exec_command.return_value = (m_stdin, m_stdout, m_stderr)

        _read_remote_file_bytes(session, "/tmp/timeout_test.txt", max_bytes=100)
        m_stdout.channel.settimeout.assert_called_with(30.0)

    def test_write_remote_file_bytes_heredoc_delimiter_collision_safe(self):
        """Verify fallback shell heredoc uses dynamic delimiter avoiding EOF collisions (Fix H4)."""
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()
        # Force exec_command to fail so it drops into shell fallback
        session.client.exec_command.side_effect = RuntimeError("exec disabled")

        captured_commands = []
        def mock_sync(s, cmd, **kwargs):
            captured_commands.append(cmd)
            # Simulate failure of base64 decode so it tries heredoc
            if "base64 -d" in cmd:
                return {"success": False}
            import re
            m = re.search(r"echo '(MCP_HD_OK_\w+)'", cmd)
            if m:
                return {"success": True, "output": m.group(1)}
            return {"success": True}

        content = b"first line\nEOF\nsecond line\nMCP_HEREDOC_\nfinal line"
        with patch('src.fs._sync_shell', side_effect=mock_sync):
            res = _write_remote_file_bytes(session, "/tmp/heredoc_test.txt", content)

        self.assertTrue(res["success"])
        self.assertEqual(res["method"], "shell_cat_heredoc")
        # Ensure cat << does not use plain 'EOF'
        heredoc_cmds = [c for c in captured_commands if "cat <<" in c]
        self.assertTrue(len(heredoc_cmds) >= 1)
        self.assertNotIn("cat << 'EOF'", heredoc_cmds[-1])
        self.assertIn("MCP_HEREDOC_", heredoc_cmds[-1])

    def test_write_remote_file_bytes_heredoc_preserves_single_quotes(self):
        """Verify quoted heredoc cat << 'DELIM' does not escape single quotes to '\\''."""
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()
        session.client.exec_command.side_effect = RuntimeError("exec disabled")

        captured_commands = []
        def mock_sync(s, cmd, **kwargs):
            captured_commands.append(cmd)
            if "base64 -d" in cmd:
                return {"success": False}
            import re
            m = re.search(r"echo '(MCP_HD_OK_\w+)'", cmd)
            if m:
                return {"success": True, "output": m.group(1)}
            return {"success": True}

        raw_script = b"VAR='hello world'\nif [ '$VAR' = 'foo' ]; then echo 'yes'; fi"
        with patch('src.fs._sync_shell', side_effect=mock_sync):
            res = _write_remote_file_bytes(session, "/tmp/script.sh", raw_script)

        self.assertTrue(res["success"])
        heredoc_cmds = [c for c in captured_commands if "cat <<" in c]
        self.assertTrue(len(heredoc_cmds) >= 1)
        target_cmd = heredoc_cmds[-1]
        # In quoted heredoc, content should contain literal 'hello world', NOT 'hello world'\''
        self.assertIn("VAR='hello world'", target_cmd)
        self.assertNotIn("VAR='\\''hello world'\\''", target_cmd)

    def test_file_dispatch_sandbox_explicit_error(self):
        """Verify file_dispatch returns explicit error when local_path violates project sandbox."""
        manager, session = self._create_mock_manager()
        outside_path = os.path.abspath(os.path.join(tempfile.gettempdir(), "..", "forbidden.txt"))
        args = {"action": "read", "path": "/etc/motd", "local_path": outside_path}
        res = file_dispatch(args, manager)
        self.assertFalse(res["success"])
        self.assertIn("Security: Local path", res["error"])
        self.assertIn("outside project sandbox", res["error"])

    def test_file_dispatch_edit_flexible_newline_crlf(self):
        """Verify file edit successfully matches CRLF files when LLM sends LF (Fix 2.2)."""
        manager, session = self._create_mock_manager()
        crlf_content = b"def foo():\r\n    x = 1\r\n    return x\r\n"

        with patch("src.fs._read_remote_file_bytes", return_value={"success": True, "data": crlf_content, "method": "sftp"}), \
             patch("src.fs._write_remote_file_bytes", return_value={"success": True, "method": "sftp"}):
            # Model sends old_text with \n (LF), file has \r\n (CRLF)
            args = {
                "action": "edit",
                "path": "/app/test.py",
                "edits": [
                    {
                        "old_text": "def foo():\n    x = 1\n    return x",
                        "new_text": "def foo():\n    x = 42\n    return x"
                    }
                ]
            }
            res = file_dispatch(args, manager)
            self.assertTrue(res["success"])
            self.assertEqual(res["replacements"], 1)

    def test_write_remote_file_bytes_binary_fallback_rejected(self):
        """Verify binary file write fails gracefully without corrupting bytes via heredoc fallback (Fix 5.4)."""
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()
        session.client.exec_command.side_effect = RuntimeError("exec disabled")

        def mock_sync(s, cmd, **kwargs):
            if "base64 -d" in cmd:
                return {"success": False, "output": "base64: command not found"}
            return {"success": False}

        binary_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        with patch("src.fs._sync_shell", side_effect=mock_sync):
            res = _write_remote_file_bytes(session, "/tmp/binary_app", binary_payload)
            self.assertFalse(res["success"])
            self.assertIn("Binary file cannot be written safely", res["error"])

    def test_sftp_write_atomic_tmp_rename_and_mode(self):
        """T2.1/F6: SFTP write must go through a sibling temp + rename and keep permissions."""
        class FakeSFTP:
            def __init__(self):
                self.written = {}
                self.calls = []
                self.removed = []

            class _H:
                def __init__(self, outer, path):
                    self.outer, self.path = outer, path

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def write(self, data):
                    self.outer.written[self.path] = data

            def stat(self, path):
                m = MagicMock()
                m.st_mode = 0o100755
                return m

            def file(self, path, mode):
                self.calls.append(("file", path, mode))
                return FakeSFTP._H(self, path)

            def posix_rename(self, src, dst):
                self.calls.append(("posix_rename", src, dst))
                self.written[dst] = self.written.pop(src, None)

            def chmod(self, path, mode):
                self.calls.append(("chmod", path, mode))

            def remove(self, path):
                self.removed.append(path)

            def close(self):
                self.calls.append(("close",))

        sftp = FakeSFTP()
        session = MagicMock()
        session.open_sftp.return_value = sftp
        res = _write_remote_file_bytes(session, "/etc/rc.local", b"payload")
        self.assertTrue(res["success"], res)
        self.assertEqual(res["method"], "sftp")
        self.assertEqual(sftp.written.get("/etc/rc.local"), b"payload")
        renames = [c for c in sftp.calls if c[0] == "posix_rename"]
        self.assertEqual(len(renames), 1)
        self.assertTrue(renames[0][1].startswith("/etc/rc.local.mcp_tmp."), renames)
        self.assertEqual(renames[0][2], "/etc/rc.local")
        self.assertIn(("chmod", "/etc/rc.local", 0o755), sftp.calls)
        # the destination itself must never be opened for writing (truncate risk)
        self.assertFalse([c for c in sftp.calls if c[0] == "file" and c[1] == "/etc/rc.local"])

    def test_sftp_write_failure_leaves_original_and_removes_tmp(self):
        """T2.1/F6: a failed write must clean its temp file and never touch the target."""
        class FailingSFTP:
            def __init__(self):
                self.removed = []

            def stat(self, path):
                m = MagicMock()
                m.st_mode = 0o100644
                return m

            def file(self, path, mode):
                raise IOError("disk full")

            def remove(self, path):
                self.removed.append(path)

            def close(self):
                pass

        sftp = FailingSFTP()
        session = MagicMock()
        session.open_sftp.return_value = sftp
        session.client = MagicMock()
        session.client.exec_command.side_effect = RuntimeError("exec disabled")
        with patch("src.fs._sync_shell", return_value={"success": False, "error": "no shell"}):
            res = _write_remote_file_bytes(session, "/etc/rc.local", b"payload")
        self.assertFalse(res["success"])
        self.assertEqual(len(sftp.removed), 1, sftp.removed)
        self.assertTrue(sftp.removed[0].startswith("/etc/rc.local.mcp_tmp."))

    def test_shell_write_restores_mode_after_mv(self):
        """T2.1/F6: tmp+mv resets permissions - the shell fallback must restore them."""
        import re
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()
        session.client.exec_command.side_effect = RuntimeError("exec disabled")
        captured = []

        def mock_sync(s, cmd, **kwargs):
            captured.append(cmd)
            if "stat -c %a" in cmd:
                return {"success": True, "output": "755"}
            m = re.search(r"echo '(MCP_[A-Z0-9_]+)'", cmd)
            if m:
                return {"success": True, "output": m.group(1)}
            return {"success": True, "output": ""}

        with patch("src.fs._sync_shell", side_effect=mock_sync):
            res = _write_remote_file_bytes(session, "/etc/init.d/rc.local", b"#!/bin/sh\n")
        self.assertTrue(res["success"], res)
        chmods = [c for c in captured if c.startswith("chmod 755 ")]
        self.assertEqual(len(chmods), 1, captured)
        self.assertIn("'/etc/init.d/rc.local'", chmods[0])

    def test_edit_conflict_on_expected_sha_mismatch(self):
        """T2.2/F6: expected_sha256 precondition must refuse to write on mismatch."""
        manager, session = self._create_mock_manager()
        with patch("src.fs._read_remote_file_bytes", return_value={"success": True, "data": b"abc\n", "method": "sftp"}), \
             patch("src.fs._write_remote_file_bytes") as write_mock:
            res = file_dispatch({
                "action": "edit", "path": "/app/x", "expected_sha256": "deadbeef",
                "edits": [{"old_text": "abc", "new_text": "xyz"}],
            }, manager)
        self.assertFalse(res["success"])
        self.assertEqual(res.get("error_code"), "conflict")
        self.assertIn("refusing to overwrite", res["error"])
        write_mock.assert_not_called()

    def test_edit_conflict_when_file_changed_between_read_and_write(self):
        """T2.2/F6: a concurrent edit between read and write must conflict, not clobber."""
        from src.utils import _sha256_hex
        manager, session = self._create_mock_manager()
        first = b"original content\n"
        second = b"someone else edited\n"
        with patch("src.fs._read_remote_file_bytes", side_effect=[
                {"success": True, "data": first, "method": "sftp"},
                {"success": True, "data": second, "method": "sftp"}]), \
             patch("src.fs._write_remote_file_bytes") as write_mock:
            res = file_dispatch({
                "action": "edit", "path": "/app/x",
                "edits": [{"old_text": "original", "new_text": "mine"}],
            }, manager)
        self.assertFalse(res["success"])
        self.assertEqual(res.get("error_code"), "conflict")
        self.assertEqual(res.get("actual_sha256"), _sha256_hex(second))
        write_mock.assert_not_called()

    def test_edit_dry_run_is_not_reported_as_written(self):
        """T2.2/F9: dry_run must never look like a successful write to the model."""
        from src.server import project_tool_result
        manager, session = self._create_mock_manager()
        with patch("src.fs._read_remote_file_bytes", return_value={"success": True, "data": b"abc\n", "method": "sftp"}), \
             patch("src.fs._write_remote_file_bytes") as write_mock:
            res = file_dispatch({
                "action": "edit", "path": "/app/x", "dry_run": True,
                "edits": [{"old_text": "abc", "new_text": "xyz"}],
            }, manager)
        self.assertTrue(res["success"])
        self.assertTrue(res.get("dry_run"))
        self.assertTrue(res.get("changed"))
        write_mock.assert_not_called()
        projected = project_tool_result("file", res)
        self.assertIn("dry run", projected["message"].lower())
        self.assertTrue(projected["dry_run"])
        self.assertTrue(projected["changed"])
        self.assertEqual(projected["replacements"], 0 + res["replacements"])

    def test_write_remote_file_bytes_atomic_mv_and_cleanup(self):
        """Verify _write_remote_file_bytes writes to a temporary file and atomically moves it via mv -f."""
        import re
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()
        session.client.exec_command.side_effect = RuntimeError("exec disabled")

        captured_commands = []
        def mock_sync(s, cmd, **kwargs):
            captured_commands.append(cmd)
            m = re.search(r"echo '(MCP_[A-Z0-9_]+)'", cmd)
            if m:
                return {"success": True, "output": m.group(1)}
            return {"success": True, "output": ""}

        test_bytes = b"Hello, world! This is a test for atomic file write."
        with patch("src.fs._sync_shell", side_effect=mock_sync):
            res = _write_remote_file_bytes(session, "/tmp/my_app.conf", test_bytes)

        self.assertTrue(res["success"])
        # Ensure temporary file was used
        tmp_writes = [c for c in captured_commands if ".mcp_tmp." in c]
        self.assertTrue(len(tmp_writes) >= 1)
        # Ensure mv -f was executed to move tmp file to target destination
        mv_cmds = [c for c in captured_commands if "mv -f" in c and "/tmp/my_app.conf" in c]
        self.assertTrue(len(mv_cmds) >= 1)

    def test_write_remote_file_bytes_base64_chunking(self):
        """Verify shell_base64_write breaks base64 payload into lines of at most 76 characters."""
        import re
        session = MagicMock()
        session.open_sftp.return_value = None
        session.client = MagicMock()
        session.client.exec_command.side_effect = RuntimeError("exec disabled")

        captured_commands = []
        def mock_sync(s, cmd, **kwargs):
            captured_commands.append(cmd)
            m = re.search(r"echo '(MCP_[A-Z0-9_]+)'", cmd)
            if m:
                return {"success": True, "output": m.group(1)}
            return {"success": True, "output": ""}

        # Create a large payload that generates many base64 characters
        large_bytes = b"A" * 5000
        with patch("src.fs._sync_shell", side_effect=mock_sync):
            res = _write_remote_file_bytes(session, "/tmp/large.txt", large_bytes)

        self.assertTrue(res["success"])
        base64_cat_cmds = [c for c in captured_commands if "cat << 'MCP_B64_" in c]
        self.assertTrue(len(base64_cat_cmds) >= 1)
        heredoc_body = base64_cat_cmds[0]
        # Extract lines between heredoc delimiters
        lines = heredoc_body.splitlines()
        payload_lines = [l for l in lines if not l.startswith("cat <<") and not l.startswith("MCP_B64_")]
        self.assertTrue(len(payload_lines) > 5)
        for line in payload_lines:
            self.assertLessEqual(len(line), 76)

    def test_file_read_filtering_applied_before_pagination(self):
        """Verify file_dispatch applies contains/regex filters to full text before line pagination."""
        manager, session = self._create_mock_manager()
        raw_lines = [
            "line 1: skip",
            "line 2: match 1",
            "line 3: skip",
            "line 4: match 2",
            "line 5: skip",
            "line 6: match 3",
            "line 7: skip",
        ]
        file_content = "\n".join(raw_lines).encode("utf-8")

        with patch("src.fs._read_remote_file_bytes", return_value={"success": True, "data": file_content, "method": "sftp"}):
            # Filtering for 'match', with pagination offset_line=2, limit_lines=1
            args = {
                "action": "read",
                "path": "/var/log/app.log",
                "contains": "match",
                "offset_line": 2,
                "limit_lines": 1
            }
            res = file_dispatch(args, manager)
            self.assertTrue(res["success"])
            self.assertEqual(res["total_lines"], 3)
            self.assertEqual(res["line_start"], 2)
            self.assertEqual(res["line_end"], 2)
            self.assertEqual(res["content"].strip(), "line 4: match 2")

    def test_dispute_channel_file_close_is_not_channel_close(self):
        session = MagicMock()
        session.id = 1
        session.name = "t"
        session.open_sftp.return_value = None
        session.client = MagicMock()
        channel = MagicMock()

        def make_stream():
            stream = MagicMock()
            stream.channel = channel
            stream.close.side_effect = lambda: None
            return stream

        def exec_read(cmd, get_pty=False):
            stdin, stdout, stderr = make_stream(), make_stream(), make_stream()
            stdout.read.return_value = b"hostname"
            stderr.read.return_value = b""
            channel.recv_exit_status.return_value = 0
            return stdin, stdout, stderr

        session.client.exec_command.side_effect = exec_read
        read_result = _read_remote_file_bytes(session, "/etc/hostname", max_bytes=100)
        self.assertTrue(read_result["success"])
        channel.close.assert_called()

        channel.reset_mock()
        channel.recv_exit_status.side_effect = [0, 1, 0]

        def exec_write(cmd, get_pty=False):
            stdin, stdout, stderr = make_stream(), make_stream(), make_stream()
            stderr.read.return_value = b"fail" if "cat >" in cmd else b""
            return stdin, stdout, stderr

        session.client.exec_command.side_effect = exec_write
        write_result = _write_remote_file_bytes(session, "/tmp/a", b"hi")
        self.assertFalse(write_result["success"])
        channel.close.assert_called()

    def test_dispute_download_does_not_load_whole_file(self):
        session = MagicMock()
        sftp = MagicMock()
        handle = MagicMock()
        chunks = [b"a" * 80, b"b" * 80]

        def read(n=None):
            if n is None:
                raise AssertionError("unbounded read")
            if not chunks:
                return b""
            return chunks.pop(0)

        handle.read.side_effect = read
        wrapped = MagicMock()
        wrapped.__enter__.return_value = handle
        wrapped.__exit__.return_value = False
        sftp.file.return_value = wrapped
        session.open_sftp.return_value = sftp
        local_path = os.path.join(self.test_dir, "download.bin")
        with patch("src.fs.MAX_DOWNLOAD_BYTES", 100):
            result = _download_remote_to_path(session, "/remote/big", local_path)
        self.assertFalse(result["success"])
        self.assertIn("download exceeds", result["error"])
        self.assertIn("download in chunks", result["error"])
        self.assertFalse(os.path.exists(local_path))

    def test_download_stages_via_temp_and_leaves_no_part(self):
        """T2.3/F2: happy path - bytes arrive through a temp file which must not survive."""
        session = MagicMock()
        sftp = MagicMock()
        handle = MagicMock()
        chunks = [b"hello ", b"world"]

        def read(n=None):
            if n is None:
                raise AssertionError("unbounded read")
            return chunks.pop(0) if chunks else b""

        handle.read.side_effect = read
        wrapped = MagicMock()
        wrapped.__enter__.return_value = handle
        wrapped.__exit__.return_value = False
        sftp.file.return_value = wrapped
        session.open_sftp.return_value = sftp
        local_path = os.path.join(self.test_dir, "staged.bin")
        result = _download_remote_to_path(session, "/remote/x", local_path)
        self.assertTrue(result["success"], result)
        self.assertEqual(result["size"], 11)
        with open(local_path, "rb") as fh:
            self.assertEqual(fh.read(), b"hello world")
        leftovers = [n for n in os.listdir(self.test_dir) if ".part-" in n]
        self.assertEqual(leftovers, [])

    def test_download_refuses_when_path_fails_revalidation(self):
        """T2.3/F2: if the validated path stops resolving to itself, refuse the replace."""
        session = MagicMock()
        sftp = MagicMock()
        handle = MagicMock()
        handle.read.side_effect = [b"data", b"", b"data", b""]
        wrapped = MagicMock()
        wrapped.__enter__.return_value = handle
        wrapped.__exit__.return_value = False
        sftp.file.return_value = wrapped
        session.open_sftp.return_value = sftp
        local_path = os.path.join(self.test_dir, "reval.bin")
        # case 1: the path now resolves somewhere else (parent swapped for a symlink)
        with patch("src.fs.resolve_local_path", return_value=os.path.join(self.test_dir, "swapped.bin")):
            result = _download_remote_to_path(session, "/remote/x", local_path)
        self.assertFalse(result["success"])
        self.assertIn("revalidation", result["error"])
        self.assertFalse(os.path.exists(local_path))
        # case 2: the path no longer resolves at all (now outside the sandbox)
        with patch("src.fs.resolve_local_path", return_value=""):
            result = _download_remote_to_path(session, "/remote/x", local_path)
        self.assertFalse(result["success"])
        self.assertIn("revalidation", result["error"])
        self.assertFalse(os.path.exists(local_path))
        leftovers = [n for n in os.listdir(self.test_dir) if ".part-" in n]
        self.assertEqual(leftovers, [], "staged bytes must be dropped")

    def test_download_refuses_symlink_target(self):
        """T2.3/F2: a symlink target would redirect the write - refuse it."""
        session = MagicMock()
        sftp = MagicMock()
        handle = MagicMock()
        handle.read.side_effect = [b"data", b""]
        wrapped = MagicMock()
        wrapped.__enter__.return_value = handle
        wrapped.__exit__.return_value = False
        sftp.file.return_value = wrapped
        session.open_sftp.return_value = sftp
        local_path = os.path.join(self.test_dir, "link.bin")
        with patch("os.path.islink", return_value=True):
            result = _download_remote_to_path(session, "/remote/x", local_path)
        self.assertFalse(result["success"])
        self.assertIn("symlink", result["error"])
        self.assertFalse(os.path.exists(local_path))

    def test_file_dispatch_refuses_busy_session(self):
        manager, session = self._create_mock_manager()
        session.is_busy.return_value = True
        result = file_dispatch({"action": "list", "path": "/tmp"}, manager)
        self.assertFalse(result["success"])
        self.assertIn("busy", result["error"].lower())
        session.open_sftp.assert_not_called()

    def test_dispute_blacklist_does_not_block_sftp_write(self):
        from src.config import ServerTargetConfig
        manager, session = self._create_mock_manager()
        node = manager.resolve_target_for_args.return_value[0]
        cfg = ServerTargetConfig(alias="default", host="10.0.0.1", user="u", command_blacklist=["rm"], read_only=False)
        node.server_config = cfg
        session.server_config = cfg
        session.is_busy.return_value = False
        sftp = MagicMock()
        handle = MagicMock()
        wrapped = MagicMock()
        wrapped.__enter__.return_value = handle
        wrapped.__exit__.return_value = False
        sftp.file.return_value = wrapped
        session.open_sftp.return_value = sftp
        allowed = file_dispatch({"action": "write", "path": "/tmp/a", "content": "hi"}, manager)
        self.assertTrue(allowed["success"], allowed)
        self.assertEqual(allowed["method"], "sftp")

        node.server_config = ServerTargetConfig(alias="default", host="10.0.0.1", user="u", read_only=True)
        blocked = file_dispatch({"action": "write", "path": "/tmp/a", "content": "hi"}, manager)
        self.assertFalse(blocked["success"])
        self.assertIn("read-only", blocked["error"].lower())

    def test_newline_in_remote_path_is_rejected(self):
        from src.fs import _read_remote_file_bytes
        session = MagicMock()
        session.id = 1
        session.open_sftp.return_value = None
        session.client = MagicMock()
        result = _read_remote_file_bytes(session, "/tmp/a\nid", max_bytes=10)
        self.assertFalse(result["success"])
        self.assertIn("newline", result["error"].lower())
        session.client.exec_command.assert_not_called()

    def test_heredoc_fallback_rejects_control_bytes(self):
        session = MagicMock()
        session.id = 1
        session.open_sftp.return_value = None
        session.client.exec_command.side_effect = RuntimeError("no exec")
        with patch("src.fs._sync_shell", return_value={"success": False, "output": ""}) as sync:
            result = _write_remote_file_bytes(session, "/tmp/a", b"\x03hideme")
        self.assertFalse(result["success"])
        self.assertIn("control bytes", result["error"])
        for call in sync.call_args_list:
            self.assertNotIn("\x03", str(call.args[1]))

    def test_close_exec_streams_closes_every_channel(self):
        from src.fs import _close_exec_streams
        first, second = MagicMock(), MagicMock()
        mkdir_out, cat_out = MagicMock(), MagicMock()
        mkdir_out.channel = first
        cat_out.channel = second
        _close_exec_streams(mkdir_out, cat_out)
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_local_path_write_does_not_read_whole_file(self):
        manager, session = self._create_mock_manager()
        session.is_busy.return_value = False
        local_path = os.path.join(self.test_dir, "big.bin")
        with open(local_path, "wb") as handle:
            handle.write(b"z")
        read_sizes = []

        class _Handle:
            def __init__(self):
                self.pos = 0
            def read(self, n=None):
                if n is None:
                    raise AssertionError("unbounded read")
                read_sizes.append(n)
                take = min(n, 500 - self.pos)
                self.pos += take
                return b"z" * take
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        with patch("src.fs.MAX_INLINE_WRITE_BYTES", 100), patch("src.fs.open", return_value=_Handle()):
            result = file_dispatch({"action": "write", "path": "/tmp/a", "local_path": local_path}, manager)
        self.assertFalse(result["success"])
        self.assertIn("too large", result["error"])
        self.assertLess(sum(read_sizes), 500)
        session.open_sftp.assert_not_called()

    def test_sftp_read_does_not_clear_state_lost(self):
        from src.session import SSHSession
        from src.manager import ServerNode
        from src.config import ServerTargetConfig
        session = SSHSession(1, "t", self.cache_dirs, "test")
        session.state_lost = True
        session.ensure_alive = lambda: None
        handle = MagicMock()
        handle.read.return_value = b"hello"
        wrapped = MagicMock()
        wrapped.__enter__.return_value = handle
        wrapped.__exit__.return_value = False
        sftp = MagicMock()
        sftp.file.return_value = wrapped
        session.open_sftp = lambda: sftp
        cfg = ServerTargetConfig(alias="default", host="10.0.0.1", user="u")
        node = ServerNode(cfg, self.cache_dirs, "test")
        node.sessions[1] = session
        node.current_session_id = 1
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)
        result = file_dispatch({"action": "read", "path": "/etc/hostname"}, manager)
        self.assertTrue(result["success"], result)
        self.assertTrue(session.state_lost)

    def test_file_op_marks_session_busy_until_done(self):
        from src.session import SSHSession
        from src.manager import ServerNode
        from src.config import ServerTargetConfig
        session = SSHSession(1, "t", self.cache_dirs, "test")
        session.ensure_alive = lambda: None
        seen = {}

        def open_sftp():
            seen["busy"] = session.is_busy()
            return None

        session.open_sftp = open_sftp
        cfg = ServerTargetConfig(alias="default", host="10.0.0.1", user="u")
        node = ServerNode(cfg, self.cache_dirs, "test")
        node.sessions[1] = session
        node.current_session_id = 1
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)
        with patch("src.fs._sync_shell", return_value={"success": True, "output": "ok"}):
            result = file_dispatch({"action": "list", "path": "/tmp"}, manager)
        self.assertTrue(result["success"], result)
        self.assertTrue(seen["busy"])
        self.assertFalse(session.is_busy())

    def test_edit_rejects_invalid_utf8_without_write(self):
        manager, _session = self._create_mock_manager()
        with patch("src.fs._read_remote_file_bytes") as mock_read, patch("src.fs._write_remote_file_bytes") as mock_write:
            mock_read.return_value = {"success": True, "data": b"\xff", "method": "sftp", "truncated": False}
            result = file_dispatch(
                {"action": "edit", "path": "bin.dat", "edits": [{"old_text": "a", "new_text": "b"}]},
                manager,
            )
        self.assertFalse(result["success"])
        self.assertIn("UTF-8", result["error"])
        mock_write.assert_not_called()

    def test_file_on_busy_session_returns_busy_error(self):
        from src.session import SSHSession
        from src.manager import ServerNode
        from src.config import ServerTargetConfig
        busy = SSHSession(1, "main", self.cache_dirs, "test")
        busy.ensure_alive = lambda: None
        self.assertTrue(busy.begin_file_op())
        cfg = ServerTargetConfig(alias="default", host="10.0.0.1", user="u")
        node = ServerNode(cfg, self.cache_dirs, "test")
        node.sessions[1] = busy
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)
        try:
            result = file_dispatch({"action": "read", "path": "/tmp/a", "session_id": "default/1"}, manager)
            self.assertFalse(result["success"])
            self.assertIn("busy", result["error"].lower())
        finally:
            busy.end_file_op()
            node.close_all()

    def test_file_write_keenetic_exec_cat_stdout_detection(self):
        """Verify that NDM CLI errors printed to stdout with exit 0 trigger fallback to sync_shell."""
        from src.fs import _write_remote_file_bytes
        session = MagicMock()
        session.server_alias = "keenetic"
        session.id = 1
        session.name = "test"
        session.cache_dirs = self.cache_dirs

        # Mock exec_command channel for stdout returning NDM CLI error
        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b"Command::Base error: no such command: cat\n"

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_stdin = MagicMock()

        session.open_sftp.return_value = None
        session.client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        with patch("src.fs._sync_shell") as mock_sync:
            def fake_sync(sess, cmd, **kwargs):
                if "base64" in cmd and "MCP_B64_OK" in cmd:
                    # extract marker_ok
                    for token in cmd.split():
                        if "MCP_B64_OK_" in token:
                            marker = token.strip("';\"")
                            return {"success": True, "output": marker}
                return {"success": True, "output": ""}
            mock_sync.side_effect = fake_sync
            res = _write_remote_file_bytes(session, "/opt/test.txt", b"hello world")
            self.assertTrue(res["success"], res)
            self.assertEqual(res["method"], "shell_base64_write")

    def test_file_dispatch_explicit_session_not_found_no_fallback(self):
        """Verify that explicit session_id that does not exist returns error without fallback."""
        mock_node = MagicMock()
        mock_node.alias = "alpha"
        mock_node.server_config.read_only = False
        mock_node.get_session.return_value = None
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (mock_node, 99, False, None)

        result = file_dispatch({"action": "read", "path": "/etc/hosts", "session_id": "alpha/99"}, manager)
        self.assertFalse(result["success"])
        self.assertIn("Session 99 not found on server 'alpha'", result["error"])
        mock_node.ensure_session.assert_not_called()

    def test_extract_between_markers_rejects_pty_echo_and_accepts_clean_lines(self):
        """Verify _extract_between_markers does not match markers within an echoed command line in PTY."""
        from src.fs import _extract_between_markers
        start = "MCP_BEGIN_123"
        end = "MCP_END_123"

        # PTY echo where both markers are on the command line, and command failed so no standalone lines
        pty_echo_only = (
            f"if [ -f '/nonexistent' ]; then echo '{start}'; base64 '/nonexistent'; echo '{end}'; else echo 'MCP_ERR_123'; fi\r\n"
            "MCP_ERR_123\r\n"
            "~ # "
        )
        self.assertIsNone(_extract_between_markers(pty_echo_only, start, end))

        # Real success with echoed command line followed by real output on standalone lines
        pty_real_output = (
            f"if [ -f '/opt/file.txt' ]; then echo '{start}'; base64 '/opt/file.txt'; echo '{end}'; fi\r\n"
            f"{start}\r\n"
            "SGVsbG8gd29ybGQ=\r\n"
            f"{end}\r\n"
            "~ # "
        )
        extracted = _extract_between_markers(pty_real_output, start, end)
        self.assertEqual(extracted, "SGVsbG8gd29ybGQ=")

    def test_read_remote_file_bytes_nonexistent_keenetic_returns_clear_error(self):
        """Verify reading a non-existent file on Keenetic returns a missing-file error, NOT base64 decode error."""
        session = MagicMock()
        session.server_alias = "keenetic"
        session.id = 1
        session.name = "test"
        session.open_sftp.return_value = None

        with patch("src.fs._sync_shell") as mock_sync:
            def fake_sync(sess, cmd, **kwargs):
                import re
                m_err = re.search(r"MCP_ERR_\w+", cmd)
                err_token = m_err.group(0) if m_err else "MCP_ERR_0"
                # Shell echoes the command line and then prints the error marker on a standalone line
                output = f"{cmd}\r\n{err_token}\r\n~ # "
                return {"success": True, "output": output}
            mock_sync.side_effect = fake_sync

            res = _read_remote_file_bytes(session, "/opt/nonexistent_file.txt", max_bytes=1000)
            self.assertFalse(res["success"], res)
            self.assertIn("remote file is not readable or missing", res["error"])
            self.assertNotIn("base64", res["error"].lower())

    def test_file_write_keenetic_silent_exec_cat_falls_back_to_sync_shell(self):
        """Verify when Keenetic NDM CLI returns exit 0 with empty stdout, exec_cat is rejected and falls back to sync_shell."""
        session = MagicMock()
        session.server_alias = "keenetic"
        session.id = 1
        session.name = "test"
        session.open_sftp.return_value = None

        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b""  # Silent NDM CLI behavior!

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_stdin = MagicMock()
        session.client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        with patch("src.fs._sync_shell") as mock_sync:
            def fake_sync(sess, cmd, **kwargs):
                if "base64" in cmd and "MCP_B64_OK" in cmd:
                    for token in cmd.split():
                        if "MCP_B64_OK_" in token:
                            marker = token.strip("';\"")
                            return {"success": True, "output": f"\r\n{marker}\r\n"}
                return {"success": True, "output": ""}
            mock_sync.side_effect = fake_sync

            res = _write_remote_file_bytes(session, "/opt/test.txt", b"new content")
            self.assertTrue(res["success"], res)
            self.assertEqual(res["method"], "shell_base64_write")

    def test_file_write_keenetic_fails_cleanly_when_sync_shell_fails(self):
        """Verify write returns success: False if both exec_cat and sync_shell fail, never falsely reporting success."""
        session = MagicMock()
        session.server_alias = "keenetic"
        session.id = 1
        session.name = "test"
        session.open_sftp.return_value = None

        mock_stdout = MagicMock()
        mock_stdout.channel.recv_exit_status.return_value = 0
        mock_stdout.read.return_value = b""  # Silent NDM CLI

        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        mock_stdin = MagicMock()
        session.client.exec_command.return_value = (mock_stdin, mock_stdout, mock_stderr)

        with patch("src.fs._sync_shell") as mock_sync:
            mock_sync.return_value = {"success": True, "output": "command not found\r\n"}
            res = _write_remote_file_bytes(session, "/opt/test.txt", b"binary \x00 data")
            self.assertFalse(res["success"], res)
            self.assertIn("cannot be written safely", res["error"])

if __name__ == "__main__":
    unittest.main()
