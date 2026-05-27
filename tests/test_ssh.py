import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import shutil
import tempfile
import time
import json
import re

from src.config import config
from src.ssh import SSHSession, RunState, set_buffer_limit_checkers
from src.utils import make_cache_dirs, json_line

class TestSSH(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dirs = make_cache_dirs(self.test_dir)
        
        # Reset and mock global config
        config.PROJECT_ROOT = self.test_dir
        config.PROJECT_TAG = "test_project"
        config.CACHE_DIRS = self.cache_dirs
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        
        set_buffer_limit_checkers(lambda size: True, lambda: 0)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_mock_session(self):
        # Create a session with mocked paramiko client
        mock_client = MagicMock()
        mock_channel = MagicMock()
        mock_client.invoke_shell.return_value = mock_channel
        mock_channel.recv_ready.return_value = False
        
        session = SSHSession(session_id=1, name="test_session", cache_dirs=self.cache_dirs, project_tag="test_project")
        session.client = mock_client
        session.channel = mock_channel
        session.in_shell = True
        
        # Avoid health/connection checks during unit tests
        session.ensure_alive = MagicMock(return_value=None)
        session.check_health = MagicMock(return_value=True)
        return session, mock_client, mock_channel

    def _run_cmd(self, session, command, background=False):
        return session.run_command(
            command=command,
            mode="sync",
            shell=True,
            wait_timeout=1.0,
            startup_wait=0.1,
            hard_timeout=0.0,
            completion_hint="either",
            quiet_complete_timeout=0.5,
            background=background
        )

    def test_run_command_blacklist(self):
        session, _, _ = self._create_mock_session()
        config.COMMAND_BLACKLIST = ["reboot", "rm -rf"]

        # 1. Block reboot
        res = self._run_cmd(session, "reboot")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 2. Block rm -rf
        res = self._run_cmd(session, "sudo rm -rf /")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 3. Allow ls
        with patch.object(session, '_start_reader_thread') as mock_start:
            self._run_cmd(session, "ls -la", background=True)
            self.assertTrue(mock_start.called)

    def test_run_command_readonly_sandbox(self):
        session, _, _ = self._create_mock_session()
        config.READ_ONLY = True

        # 1. Block filesystem write command
        res = self._run_cmd(session, "mkdir test")
        self.assertFalse(res["success"])
        self.assertIn("Security: Write command is blocked", res["error"])

        # 2. Block echo append/redirection
        res = self._run_cmd(session, "echo hello > test.txt")
        self.assertFalse(res["success"])
        self.assertIn("Security: Write command is blocked", res["error"])

        # 3. Block rm
        res = self._run_cmd(session, "rm file")
        self.assertFalse(res["success"])

        # 4. Allow safe commands
        with patch.object(session, '_start_reader_thread') as mock_start:
            self._run_cmd(session, "cat file.txt", background=True)
            self.assertTrue(mock_start.called)

    def test_pagination_detected_via_regexes(self):
        session, _, mock_channel = self._create_mock_session()
        
        # We will test the reader loop. We will call _reader_loop directly or simulate.
        run = RunState(
            run_id=1, session_id=1, command="test", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1,
            hard_timeout=0.0, max_buffer_chars=2000,
            run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test.log")
        )
        run.completion_hint = "either"
        run.quiet_complete_timeout = 0.5

        # We set up mock_channel.recv to return '-- More --' on first call, then empty.
        mock_channel.recv.side_effect = [
            b"first line of text\r\n-- More --",
            b""
        ]
        
        # Safe stateful side effect for recv_ready
        recv_ready_calls = [True]
        def mock_recv_ready():
            if recv_ready_calls:
                recv_ready_calls.pop()
                return True
            return False
        mock_channel.recv_ready.side_effect = mock_recv_ready
        
        # Start _reader_loop in a background thread to prevent hang
        import threading
        t = threading.Thread(target=session._reader_loop, args=(run,), daemon=True)
        t.start()
        
        # Wait up to 1 second for the loop to run
        time.sleep(0.1)
        
        # Stop loop cleanly
        run.done_event.set()
        t.join(timeout=1.0)
        
        # Check if space " " was sent to mock_channel
        mock_channel.send.assert_any_call(" ")
        
        # Verify log contains pagination event
        with open(run.run_log_path, "r", encoding="utf-8") as f:
            log_content = f.read()
            self.assertIn("pagination_detected_sending_space", log_content)

    def test_interactive_hangs_protection(self):
        session, _, mock_channel = self._create_mock_session()
        
        run = RunState(
            run_id=2, session_id=1, command="sudo apt install nodejs", mode="sync",
            started_at=time.time() - 10.0, wait_timeout=1.0, startup_wait=0.1,
            hard_timeout=0.0, max_buffer_chars=2000,
            run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test2.log")
        )
        run.completion_hint = "either"
        run.quiet_complete_timeout = 0.05 # Very fast quiet timeout for test
        run.last_data_at = time.time() - 0.2

        # Simulate buffer ending with interactive prompt
        run.output_buffer = "Do you want to continue? [Y/n] "
        run.total_received_chars = len(run.output_buffer)

        # Recv has no data, so it hits the timeout/quiet event check
        mock_channel.recv_ready.return_value = False

        # Run reader loop in background
        import threading
        with patch.object(session, '_send_ctrl_c_raw') as mock_ctrl_c:
            t = threading.Thread(target=session._reader_loop, args=(run,), daemon=True)
            t.start()
            
            # Wait up to 1 second for the loop to trigger interactive hang abort
            t.join(timeout=1.0)
            
            # Should have triggered Ctrl+C raw due to interactive prompt detection
            self.assertTrue(mock_ctrl_c.called)
            self.assertTrue(run.interrupt_sent)
            self.assertEqual(run.status, "failed")
            self.assertIn("Interactive prompt detected", run.error)

    def test_restore_run_from_disk(self):
        session, _, _ = self._create_mock_session()
        
        # Let's generate a mock log file manually to simulate a run that completed but got garbage collected
        run_id = 99
        stamp = "20260526_120000"
        log_filename = f"{session.project_tag}__s{session.id}__r{run_id}__{stamp}.log"
        log_path = os.path.join(self.cache_dirs["runs_dir"], log_filename)
        
        # Write created, output, and done logs
        events = [
            {"ts": "2026-05-26T12:00:00.000", "dir": "SYS", "event": "run_created", "command": "cat secrets.txt", "mode": "sync", "started_at": time.time(), "wait_timeout": 20.0, "startup_wait": 2.0, "hard_timeout": 0.0},
            {"ts": "2026-05-26T12:00:01.000", "dir": "OUT", "chunk": "super_secret_key_123\n"},
            {"ts": "2026-05-26T12:00:02.000", "dir": "SYS", "event": "run_done", "run_id": run_id, "status": "completed", "reason": "prompt detected", "error": "", "completion_method": "prompt_detected", "exit_status": 0, "finished_at": time.time()}
        ]
        
        for ev in events:
            json_line(log_path, ev)
            
        # Verify the run is NOT in memory
        self.assertNotIn(run_id, session.runs)
        
        # Try to read it - this should transparently trigger recovery
        res = session.read_run(run_id=run_id, offset=None, max_lines=10, max_chars=1000)
        
        self.assertTrue(res["success"])
        self.assertEqual(res["run_id"], run_id)
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["output"], "super_secret_key_123")
        
        # Run should now be cached in memory
        self.assertIn(run_id, session.runs)
        self.assertEqual(session.runs[run_id].command, "cat secrets.txt")

if __name__ == "__main__":
    unittest.main()
