import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import shutil
import socket
import tempfile
import time
import json
import re
import threading
import inspect

from src.config import config
from src.session import SSHSession, set_buffer_limit_checkers, format_export_path
from src.ssh_state import RunState
from src.utils import make_cache_dirs, json_line, find_prompt, parse_exit_marker, cleanup_old_logs, StreamCleaner

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

        # 2. Block rm -rf standard
        res = self._run_cmd(session, "sudo rm -rf /")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 2b. Block rm -rf with multiple spaces (whitespace bypass fix)
        res = self._run_cmd(session, "rm  -rf /var/log")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 2c. Block rm -rf with tabs
        res = self._run_cmd(session, "rm\t-rf /var/log")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 2d. Block chained commands with reboot
        res = self._run_cmd(session, "echo ok; reboot")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        res = self._run_cmd(session, "echo ok && reboot")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        res = self._run_cmd(session, "$(reboot)")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 2e. Block backtick injection
        res = self._run_cmd(session, "`reboot`")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        res = self._run_cmd(session, "echo `reboot`")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])

        # 3. Allow command with substring like 'reboot' in word (e.g. echo rebooting)
        with patch.object(session, '_start_reader_thread') as mock_start:
            res = self._run_cmd(session, "echo rebooting_server", background=True)
            self.assertTrue(mock_start.called)
            self.assertTrue(res["success"])

        # Mark run as completed so session is no longer busy
        with session.lock:
            if session.active_run_id:
                session.runs[session.active_run_id].mark_done("completed")
                session.active_run_id = None

        # 4. Allow ls
        with patch.object(session, '_start_reader_thread') as mock_start:
            res = self._run_cmd(session, "ls -la", background=True)
            self.assertTrue(mock_start.called)
            self.assertTrue(res["success"])

    def test_run_command_readonly_sandbox(self):
        session, _, _ = self._create_mock_session()
        config.READ_ONLY = True

        # 1. Block filesystem write command
        res = self._run_cmd(session, "mkdir test")
        self.assertFalse(res["success"])
        self.assertIn("Security: Write command is blocked", res["error"])

        # 1b. Block tee / truncate / shred
        res = self._run_cmd(session, "cat foo | tee /tmp/bar")
        self.assertFalse(res["success"])
        self.assertIn("Security: Write command is blocked", res["error"])

        res = self._run_cmd(session, "truncate -s 0 /tmp/bar")
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

    def test_run_output_without_live_feed_reaches_canvas(self):
        """A run whose text only ever reached its own buffer (mocked reader, restored
        run) must still land in the tab canvas - the single unread stream (m01215)."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=99, session_id=session.id, command="cat secrets.txt", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "mirror.log"),
        )
        run.append_output("super_secret_key_123\n")
        run.mark_done("completed", completion_method="prompt_detected")
        session.runs[99] = run

        res = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertTrue(res["success"])
        self.assertEqual(res["output"], "super_secret_key_123\n")
        self.assertEqual(res["has_more"], 0)
        # Mirrored exactly once: a second read has nothing left.
        again = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertEqual(again["output"], "")

    def test_state_lost_warning(self):
        session, _, _ = self._create_mock_session()
        session.state_lost = True

        res = self._run_cmd(session, "echo hello", background=False)
        self.assertFalse(res["success"])
        self.assertIn("Connection for session", res["error"])
        self.assertIn("was lost and auto-recovered", res["error"])
        # Flag should be reset
        self.assertFalse(session.state_lost)

    def test_run_state_append_output_stores_cleaned_text(self):
        log_path = os.path.join(self.cache_dirs["runs_dir"], "test_run.log")
        run = RunState(
            run_id=1,
            session_id=1,
            command="echo",
            mode="sync",
            started_at=time.time(),
            wait_timeout=10.0,
            startup_wait=1.0,
            hard_timeout=0.0,
            max_buffer_chars=1000,
            run_log_path=log_path
        )
        end = run.append_output("line 1\r\n\x1b[31mline 2\x1b[0m\r\n")
        self.assertEqual(run.output_buffer, "line 1\nline 2\n")
        # The returned end offset is what the canvas mirror records for this chunk.
        self.assertEqual(end, len("line 1\nline 2\n"))
        self.assertEqual(run.output_end(), len("line 1\nline 2\n"))

    def test_concurrent_run_command_busy_race(self):
        """Verify atomic busy reservation: concurrent calls on same session allow exactly 1 to run."""
        import concurrent.futures
        session, _, _ = self._create_mock_session()

        results = []
        with patch.object(session, '_start_reader_thread'):
            def run_worker():
                return session.run_command(
                    command="sleep 10",
                    mode="sync",
                    shell=True,
                    wait_timeout=1.0,
                    startup_wait=0.1,
                    hard_timeout=0.0,
                    completion_hint="either",
                    quiet_complete_timeout=0.5,
                    background=True
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                futures = [ex.submit(run_worker) for _ in range(8)]
                results = [f.result() for f in futures]

        success_count = sum(1 for r in results if r.get("success") is True)
        busy_count = sum(1 for r in results if not r.get("success") and "busy" in r.get("error", "").lower())

        self.assertEqual(success_count, 1, "Exactly one command must succeed")
        self.assertEqual(busy_count, 7, "All 7 concurrent callers must be rejected with busy error")

    def test_trimmed_run_buffer_reports_lost_output(self):
        """A run buffer trimmed before its text reached the canvas is reported as
        dropped_data instead of silently swallowing the lost output (D5)."""
        from src.config import MAX_BUFFER_CHARS
        session, _, _ = self._create_mock_session()

        chunk_size = 100000
        num_chunks = 25  # 2,500,000 chars total, MAX_BUFFER_CHARS is 2,000,000
        total_chars = chunk_size * num_chunks

        run = RunState(
            run_id=999, session_id=session.id, command="cat big", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=MAX_BUFFER_CHARS, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "big.log"),
        )
        for _ in range(num_chunks):
            run.append_output("x" * chunk_size)
        run.mark_done("completed", completion_method="exit_status")
        session.runs[999] = run

        # Memory stays bounded and the trim point is tracked in absolute offsets.
        self.assertEqual(run.total_received_chars, total_chars)
        self.assertEqual(len(run.output_buffer), MAX_BUFFER_CHARS)
        self.assertEqual(run.buffer_base_offset, total_chars - MAX_BUFFER_CHARS)

        res = session.read_canvas(limit=0, max_chars=200000, wait_timeout=0.0)
        self.assertTrue(res["success"])
        self.assertTrue(res.get("dropped_data"), "trimmed-away output must be reported")

    def test_striped_locks_json_line_concurrency(self):
        """Verify striped locks prevent log file corruption under high thread contention."""
        import concurrent.futures
        file1 = os.path.join(self.test_dir, "conc1.log")
        file2 = os.path.join(self.test_dir, "conc2.log")
        file3 = os.path.join(self.test_dir, "conc3.log")
        files = [file1, file2, file3]

        def writer_task(worker_id):
            for i in range(30):
                target_file = files[(worker_id + i) % len(files)]
                payload = {
                    "worker": worker_id,
                    "seq": i,
                    "text": f"message-{worker_id}-{i}-" + ("A" * 200)
                }
                json_line(target_file, payload)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            futures = [ex.submit(writer_task, wid) for wid in range(16)]
            for f in futures:
                f.result()

        # Verify every line in each file is valid uncorrupted JSON
        total_lines = 0
        for fpath in files:
            self.assertTrue(os.path.exists(fpath))
            with open(fpath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parsed = json.loads(line)
                        self.assertIn("worker", parsed)
                        self.assertIn("text", parsed)
                        total_lines += 1

        self.assertEqual(total_lines, 16 * 30)

    def test_security_shell_path_escape(self):
        """Verify escape_shell_path neutralizes injection vectors in single-quoted shell strings."""
        from src.security import escape_shell_path
        self.assertEqual(escape_shell_path("simple.txt"), "simple.txt")
        self.assertEqual(escape_shell_path("foo'bar.txt"), "foo'\\''bar.txt")
        self.assertEqual(escape_shell_path("foo'; rm -rf /; 'bar"), "foo'\\''; rm -rf /; '\\''bar")
        self.assertEqual(escape_shell_path("`reboot`"), "`reboot`")  # Inside '...', backticks are literal

    def test_session_close_marks_dead_and_unblocks_runs(self):
        """Verify SSHSession.close() sets is_dead=True and gracefully marks active runs as done (Fix C4, M5)."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=1, session_id=1, command="sleep 100", mode="sync",
            started_at=time.time(), wait_timeout=10.0, startup_wait=0.1,
            hard_timeout=0.0, max_buffer_chars=1000,
            run_log_path=os.path.join(self.cache_dirs["runs_dir"], "close_test.log")
        )
        session.runs[1] = run
        session.active_run_id = 1

        self.assertFalse(session.is_dead)
        session.close()

        self.assertTrue(session.is_dead)
        self.assertEqual(session.death_reason, "session closed")
        self.assertTrue(run.done_event.is_set())
        self.assertEqual(run.status, "dead")

    def test_check_health_invoke_shell_timeout_fails_gracefully(self):
        """Verify check_health does not hang if invoke_shell blocks (Fix C3)."""
        session, mock_client, mock_channel = self._create_mock_session()
        # Restore unmocked check_health
        del session.check_health
        mock_channel.closed = True
        session.channel = mock_channel

        # Simulate invoke_shell hanging/raising TimeoutError
        with patch.object(session, '_invoke_shell_with_timeout', side_effect=TimeoutError("invoke_shell timed out after 15s")):
            is_healthy = session.check_health()

        self.assertFalse(is_healthy)
        self.assertTrue(session.is_dead)
        self.assertIn("invoke_shell timed out", session.death_reason)

    def test_apply_text_filters_regex_cached(self):
        """Verify apply_text_filters regex compilation is cached via lru_cache (Fix L3)."""
        from src.utils import apply_text_filters, _compile_filter_regex
        _compile_filter_regex.cache_clear()

        text = "alpha\nbeta\ngamma"
        res1 = apply_text_filters(text, regex="^b.*")
        self.assertTrue(res1["filtered"])
        self.assertEqual(res1["output"], "beta")

        res2 = apply_text_filters(text, regex="^b.*")
        self.assertEqual(res2["output"], "beta")

        # Cache should have 1 hit and 1 miss
        info = _compile_filter_regex.cache_info()
        self.assertEqual(info.hits, 1)
        self.assertEqual(info.misses, 1)

    def test_connect_resets_is_dead_and_sets_socket_timeout(self):
        """Verify connect() resets is_dead=False and sets DEFAULT_SOCKET_TIMEOUT on transport socket."""
        from src.config import ServerTargetConfig, DEFAULT_SOCKET_TIMEOUT
        cfg = ServerTargetConfig(alias="test_conn", host="10.0.0.1", user="u")
        session = SSHSession(1, "s1", self.cache_dirs, "test", server_config=cfg)
        session.is_dead = True
        session.death_reason = "previously dead"

        mock_client = MagicMock()
        mock_transport = MagicMock()
        mock_sock = MagicMock()
        mock_transport.sock = mock_sock
        mock_transport.is_active.return_value = True
        mock_client.get_transport.return_value = mock_transport
        mock_channel = MagicMock()
        mock_channel.recv_ready.return_value = False

        with patch('paramiko.SSHClient', return_value=mock_client), \
             patch.object(session, '_invoke_shell_with_timeout', return_value=mock_channel), \
             patch.object(session, '_setup_environment'):
            success = session.connect()

        self.assertTrue(success)
        self.assertFalse(session.is_dead)
        self.assertEqual(session.death_reason, "")
        self.assertTrue(session.is_alive())
        mock_sock.settimeout.assert_called_with(DEFAULT_SOCKET_TIMEOUT)

    def test_connect_failure_keeps_real_death_reason(self):
        """T0.2/F8: a failed connect must report WHY, not the generic teardown reason."""
        import paramiko
        from src.config import ServerTargetConfig
        cfg = ServerTargetConfig(alias="bad_auth", host="192.0.2.10", user="admin", password="wrong")
        session = SSHSession(1, "", self.cache_dirs, "test", server_config=cfg)
        with patch('paramiko.SSHClient.connect', side_effect=paramiko.AuthenticationException("Authentication failed.")):
            self.assertFalse(session.connect())
        self.assertIn("authentication failed", session.death_reason.lower())
        self.assertNotEqual(session.death_reason, "session closed")

    def test_interactive_hang_detection_with_ansi_codes(self):
        """Verify reader loop detects interactive prompts colored with ANSI escape sequences."""
        session, _, mock_channel = self._create_mock_session()
        run = RunState(
            run_id=20, session_id=1, command="apt-get install pkg", mode="sync",
            started_at=time.time() - 10.0, wait_timeout=1.0, startup_wait=0.1,
            hard_timeout=0.0, max_buffer_chars=2000,
            run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test_ansi.log")
        )
        run.completion_hint = "either"
        run.quiet_complete_timeout = 0.05
        run.last_data_at = time.time() - 0.2

        # Colored prompt with ANSI codes: \x1b[33mDo you want to continue? [Y/n]\x1b[0m
        run.output_buffer = "\x1b[33mDo you want to continue? [Y/n]\x1b[0m "
        run.total_received_chars = len(run.output_buffer)
        mock_channel.recv_ready.return_value = False

        import threading
        with patch.object(session, '_send_ctrl_c_raw') as mock_ctrl_c:
            t = threading.Thread(target=session._reader_loop, args=(run,), daemon=True)
            t.start()
            t.join(timeout=1.0)

            self.assertTrue(mock_ctrl_c.called)
            self.assertTrue(run.interrupt_sent)
            self.assertEqual(run.status, "failed")
            self.assertIn("Interactive prompt detected", run.error)

    def test_find_prompt_no_false_positive_on_dollar_hash_greater(self):
        """Verify find_prompt does not falsely match text ending with $, #, > unless it's a prompt."""
        from src.utils import find_prompt
        # False positives that must NOT match
        self.assertIsNone(find_prompt("The total price is 50$"))
        self.assertIsNone(find_prompt("Item count #5"))
        self.assertIsNone(find_prompt("if a > b then"))
        self.assertIsNone(find_prompt("SELECT * FROM t WHERE val > 0\n"))

        # True prompts that MUST match
        self.assertIsNotNone(find_prompt("user@host:~$ "))
        self.assertIsNotNone(find_prompt("root@server:~# "))
        self.assertIsNotNone(find_prompt("router (config)> "))
        self.assertIsNotNone(find_prompt("/opt/home # "))
        self.assertIsNotNone(find_prompt("\n$ "))
        self.assertIsNotNone(find_prompt("\n> "))

    def test_find_prompt_no_comment_false_positive(self):
        """Verify find_prompt does not treat script comments (#) as prompts (Fix 5.2)."""
        from src.utils import find_prompt
        self.assertIsNone(find_prompt("#\n"))
        self.assertIsNone(find_prompt("#"))
        self.assertIsNone(find_prompt("echo 'hello'\n#\n"))
        self.assertIsNone(find_prompt("bash script running\n# some comment\n#\n"))

    def test_health_check_ignores_closed_channel_when_exec_run_active(self):
        """Verify check_health does not kill session when run is on exec_channel and main channel is closed (Fix 3.3)."""
        session, mock_client, mock_channel = self._create_mock_session()
        del session.check_health
        mock_channel.closed = True
        session.channel = mock_channel

        # Simulate active run using exec_channel (PTY-less mode)
        run = RunState(
            run_id=99, session_id=session.id, command="long_script.sh", mode="sync",
            started_at=time.time(), wait_timeout=10.0, startup_wait=0.1, hard_timeout=30.0,
            max_buffer_chars=2000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test_exec.log")
        )
        mock_exec_ch = MagicMock()
        mock_exec_ch.closed = False
        run.exec_channel = mock_exec_ch
        session.runs[99] = run
        session.active_run_id = 99

        new_shell_ch = MagicMock()
        new_shell_ch.closed = False
        with patch.object(session, '_invoke_shell_with_timeout', return_value=new_shell_ch), \
             patch.object(session, '_setup_environment'):
            healthy = session.check_health()

        self.assertTrue(healthy)
        self.assertFalse(session.is_dead)

    def test_exit_shell_skips_exit_on_native_linux_shell(self):
        """Verify _exit_shell does NOT send 'exit' on standard Linux VPS login shells (Fix 3.4)."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = False  # Native shell on Linux VPS

        success = session._exit_shell()
        self.assertTrue(success)
        # Ensure 'exit\n' was NOT sent to the channel
        mock_channel.send.assert_not_called()

    def test_connect_failure_calls_close_to_free_sockets(self):
        """Verify connect() failure calls self.close() to prevent socket leaks (Fix 4.1)."""
        from src.config import ServerTargetConfig
        cfg = ServerTargetConfig(alias="leak_test", host="10.0.0.1", user="u")
        session = SSHSession(1, "s1", self.cache_dirs, "test", server_config=cfg)

        mock_client = MagicMock()
        with patch('paramiko.SSHClient', return_value=mock_client), \
             patch.object(session, '_invoke_shell_with_timeout', side_effect=TimeoutError("shell timeout")), \
             patch.object(session, 'close', wraps=session.close) as mock_close:
            success = session.connect()

        self.assertFalse(success)
        self.assertTrue(session.is_dead)
        # Called at start of connect and on exception in except block
        self.assertTrue(mock_close.call_count >= 1)
        self.assertIsNone(session.client)

    def test_send_signal_stdin_and_eof_blocked_without_active_run(self):
        """Verify send_signal blocks stdin and eof actions if there is no active run."""
        session, _, mock_channel = self._create_mock_session()
        session.active_run_id = None

        res_stdin = session.send_signal(action="stdin", text="hello\n")
        self.assertFalse(res_stdin["success"])
        self.assertIn("No active command", res_stdin["error"])
        mock_channel.send.assert_not_called()

        res_eof = session.send_signal(action="eof")
        self.assertFalse(res_eof["success"])
        self.assertIn("No active command", res_eof["error"])

    def test_send_signal_stdin_security_check_blocks_blacklisted_cmd(self):
        """Verify send_signal validates text against command blacklist when action='stdin'."""
        session, _, mock_channel = self._create_mock_session()
        session.active_run_id = 42
        run = RunState(
            run_id=42, session_id=session.id, command="cat", mode="sync",
            started_at=time.time(), wait_timeout=10.0, startup_wait=0.1, hard_timeout=30.0,
            max_buffer_chars=2000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test_signal.log")
        )
        session.runs[42] = run
        config.COMMAND_BLACKLIST = ["rm -rf"]

        res = session.send_signal(action="stdin", text="rm -rf /tmp\n")
        self.assertFalse(res["success"])
        self.assertIn("Security: Command is blocked", res["error"])
        mock_channel.send.assert_not_called()

    def test_exec_channel_closed_in_finally_block(self):
        """Verify _exec_reader_loop guarantees channel and streams closure in finally block."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=77, session_id=session.id, command="sleep 1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=2.0,
            max_buffer_chars=2000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test_exec_close.log")
        )
        mock_exec_ch = MagicMock()
        mock_exec_ch.recv_ready.side_effect = [False]
        mock_exec_ch.exit_status_ready.side_effect = [True]
        mock_exec_ch.recv_exit_status.return_value = 0

        mock_stdout = MagicMock()
        mock_stdout.channel = mock_exec_ch
        mock_stdout.read.return_value = b"done\n"
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b""

        run.exec_channel = mock_exec_ch
        run.exec_stdout = mock_stdout
        run.exec_stderr = mock_stderr
        session.runs[77] = run

        session._exec_reader_loop(run)

        self.assertTrue(mock_exec_ch.close.called)
        self.assertTrue(mock_stdout.close.called)
        self.assertTrue(mock_stderr.close.called)

    def test_quiet_event_speedup_in_run_command(self):
        """Verify run_command unblocks quickly when quiet_event is set in sync mode with completion_hint='quiet'."""
        session, _, _ = self._create_mock_session()
        session.in_shell = False

        def trigger_quiet():
            time.sleep(0.05)
            with session.lock:
                run = session.runs.get(1)
            if run:
                run.quiet_event.set()

        threading.Thread(target=trigger_quiet, daemon=True).start()

        start = time.time()
        res = session.run_command(
            command="echo test",
            mode="sync",
            shell=False,
            wait_timeout=5.0,
            startup_wait=0.1,
            hard_timeout=0.0,
            completion_hint="quiet",
            quiet_complete_timeout=0.2
        )
        elapsed = time.time() - start

        self.assertTrue(res["success"])
        # Should finish much faster than wait_timeout (5.0s)
        self.assertLess(elapsed, 2.0)

    def test_reader_loop_drain_on_buffer_limit(self):
        """Over the memory limit the reader must not recv and must not grow the buffer."""
        session, _, mock_channel = self._create_mock_session()
        run = RunState(
            run_id=88, session_id=session.id, command="big_stream", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=2.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test_drain.log")
        )
        session.runs[88] = run
        session.active_run_id = 88

        # Mock channel to return data twice, then raise exception to terminate loop
        mock_channel.recv.side_effect = [b"chunk1_data", b"chunk2_data", EOFError("stream done")]
        mock_channel.recv_ready.side_effect = [True, True, True]

        # Force memory checker to return False (limit exceeded)
        set_buffer_limit_checkers(lambda size: False, lambda: 10000000)

        try:
            session._reader_loop(run)
        except EOFError:
            pass
        finally:
            set_buffer_limit_checkers(lambda size: True, lambda: 0)

        # Over the memory limit the reader must not pull bytes off the socket.
        self.assertNotIn("chunk1_data", run.output_buffer)
        self.assertNotIn("chunk2_data", run.output_buffer)
        self.assertFalse(mock_channel.recv.called)
        self.assertTrue(run.recv_paused)

    def test_dispute_prompt_does_not_match_embedded_gt(self):
        for sample in ("a > b", "Usage: foo >", "$50", "item #5"):
            self.assertIsNone(find_prompt(sample))
        self.assertIsNotNone(find_prompt("\n> "))
        self.assertIsNotNone(find_prompt("\n(config)> "))

    def test_dispute_pty_send_timeout_does_not_hang_worker(self):
        session, _, channel = self._create_mock_session()
        calls = {"n": 0}

        def send(data):
            calls["n"] += 1
            if calls["n"] == 1:
                raise socket.timeout("window")
            return len(data)

        channel.send.side_effect = send
        started = time.time()
        res = self._run_cmd(session, "echo timeout", background=True)
        elapsed = time.time() - started
        session.close()
        self.assertTrue(res["success"])
        self.assertLess(elapsed, 5.0)
        self.assertGreaterEqual(calls["n"], 2)

    def test_dispute_internal_bypass_stays_for_maintenance(self):
        session, _, channel = self._create_mock_session()
        session.server_config.read_only = True
        config.READ_ONLY = True
        try:
            allowed = session.run_command(
                command="rm -f /tmp/x", mode="sync", shell=True, wait_timeout=1.0,
                startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
                quiet_complete_timeout=0.5, background=True, internal=True,
            )
            self.assertNotIn("Security", allowed.get("error", ""))
            self.assertTrue(allowed["success"])
            blocked = session.run_command(
                command="rm -f /tmp/x", mode="sync", shell=True, wait_timeout=1.0,
                startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
                quiet_complete_timeout=0.5, background=True, internal=False,
            )
            self.assertFalse(blocked["success"])
            self.assertIn("Security", blocked["error"])
        finally:
            config.READ_ONLY = False
            session.close()

    def test_dispute_session_logs_are_local_cache(self):
        session = SSHSession(1, "logs", self.cache_dirs, "test_project")
        sessions_dir = os.path.realpath(self.cache_dirs["sessions_dir"])
        self.assertTrue(os.path.realpath(session.session_log_path).startswith(sessions_dir))
        source = inspect.getsource(cleanup_old_logs)
        self.assertIn("sessions_dir", source)
        self.assertNotIn("sftp", source.lower())
        old_log = os.path.join(self.cache_dirs["sessions_dir"], "ancient.log")
        with open(old_log, "w", encoding="utf-8") as handle:
            handle.write("old\n")
        old_stamp = time.time() - (10 * 86400)
        os.utime(old_log, (old_stamp, old_stamp))
        outside = os.path.join(self.test_dir, "remote-looking.log")
        with open(outside, "w", encoding="utf-8") as handle:
            handle.write("keep\n")
        os.utime(outside, (old_stamp, old_stamp))
        cleanup_old_logs(self.cache_dirs, max_age_seconds=7 * 86400, max_files=500)
        self.assertFalse(os.path.exists(old_log))
        self.assertTrue(os.path.exists(outside))

    def test_dispute_state_lost_is_one_shot(self):
        session, _, channel = self._create_mock_session()
        session.state_lost = True
        first = self._run_cmd(session, "echo hello", background=False)
        self.assertFalse(first["success"])
        self.assertIn("reset", first["error"].lower())
        self.assertFalse(session.state_lost)
        channel.send.reset_mock()
        second = self._run_cmd(session, "echo hello", background=True)
        session.close()
        self.assertTrue(second["success"])
        self.assertTrue(channel.send.called)

    def test_dispute_state_lost_parallel_at_least_one_reject(self):
        session, _, _ = self._create_mock_session()
        session.state_lost = True
        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            res = self._run_cmd(session, "echo parallel", background=True)
            with lock:
                results.append(res)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)
        session.close()
        self.assertEqual(len(results), 2)
        rejects = [
            item for item in results
            if not item.get("success") and "reset" in str(item.get("error", "")).lower()
        ]
        self.assertGreaterEqual(len(rejects), 1)

    def test_dispute_pty_send_delivers_full_payload(self):
        session, _, channel = self._create_mock_session()
        order = []
        received = bytearray()
        original_start = session._start_reader_thread

        def start_reader(run):
            order.append("reader")
            return original_start(run)

        def send(data):
            self.assertEqual(order[:1], ["reader"])
            chunk = data[:100]
            received.extend(chunk)
            return len(chunk)

        session._start_reader_thread = start_reader
        channel.send.side_effect = send
        command = "Z" * 1000
        res = self._run_cmd(session, command, background=True)
        session.close()
        self.assertTrue(res["success"])
        self.assertIn(command.encode("utf-8"), bytes(received))
        self.assertGreater(channel.send.call_count, 1)

    def test_dispute_close_does_not_reconnect(self):
        session = SSHSession(1, "closed", self.cache_dirs, "test_project")
        with patch("paramiko.SSHClient") as ssh_client:
            session.close(permanent=True)
            error = session.ensure_alive()
            self.assertIsNotNone(error)
            self.assertIn("closed", error.lower())
            self.assertFalse(session.connect())
            ssh_client.assert_not_called()
            self.assertTrue(session._permanently_closed)

    def test_dispute_extra_path_is_single_quoted(self):
        injected = format_export_path("/opt/bin;id")
        self.assertEqual(injected, "export PATH='/opt/bin;id':$PATH 2>/dev/null\n")
        outside = re.sub(r"'(?:\\'|[^'])*'", "", injected)
        self.assertNotIn(";id", outside)
        quoted = format_export_path("/opt/a'b")
        self.assertTrue(quoted.startswith("export PATH='"))
        self.assertIn("'\\''", quoted)

    def test_dispute_memory_limit_does_not_recv(self):
        session, _, mock_channel = self._create_mock_session()
        run = RunState(
            run_id=91, session_id=session.id, command="stream", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=2.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "pause.log"),
        )
        session.runs[91] = run
        session.active_run_id = 91
        mock_channel.recv.side_effect = AssertionError("recv while paused")
        mock_channel.recv_ready.side_effect = [True, True, StopIteration()]
        set_buffer_limit_checkers(lambda size: False, lambda: 10000000)
        try:
            session._reader_loop(run)
        except StopIteration:
            pass
        finally:
            set_buffer_limit_checkers(lambda size: True, lambda: 0)
        self.assertEqual(mock_channel.recv.call_count, 0)
        self.assertNotIn("paused-bytes", run.output_buffer)
        self.assertTrue(run.recv_paused)

    def test_dispute_shell_marker_not_on_router_cli(self):
        router, _, router_channel = self._create_mock_session()
        router.in_shell = False
        sent = []

        def capture(data):
            sent.append(data if isinstance(data, bytes) else str(data).encode())
            return len(data)

        router_channel.send.side_effect = capture
        router_res = router.run_command(
            command="show version", mode="sync", shell=False, wait_timeout=1.0,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
            quiet_complete_timeout=0.5, background=True, use_pty=True,
        )
        router.close()
        self.assertTrue(router_res["success"])
        self.assertNotIn(b"__MCP_EC_", b"".join(sent))

        shell, _, shell_channel = self._create_mock_session()
        shell_sent = []
        shell_channel.send.side_effect = lambda data: shell_sent.append(
            data if isinstance(data, bytes) else str(data).encode()
        ) or len(data)
        shell_res = self._run_cmd(shell, "echo hi", background=True)
        shell.close()
        self.assertTrue(shell_res["success"])
        blob = b"".join(shell_sent)
        self.assertIn(b"__MCP_EC_", blob)
        token = re.search(br"__MCP_EC_([0-9a-f]+)_", blob).group(1).decode()
        echo = f"echo hi; printf '%s\\n' \"__MCP_EC_{token}_$?\""
        self.assertIsNone(parse_exit_marker(echo, token))
        self.assertEqual(parse_exit_marker(echo + f"\n__MCP_EC_{token}_0\n", token), 0)
        trailed = echo + f"\n__MCP_EC_{token}_0\nroot@vps:~# "
        self.assertEqual(parse_exit_marker(trailed, token), 0)

    def test_ctrl_c_does_not_clear_a_newer_run(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        first = RunState(
            run_id=1, session_id=1, command="sleep", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "c1.log"),
        )
        second = RunState(
            run_id=2, session_id=1, command="echo", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "c2.log"),
        )
        exec_channel = MagicMock()
        exec_channel.closed = False
        first.exec_channel = exec_channel
        session.runs[1] = first
        session.runs[2] = second
        session.active_run_id = 1

        class _SwapLock:
            def __init__(self, inner):
                self.inner = inner
                self.entries = 0

            def __enter__(self):
                self.entries += 1
                if self.entries == 2:
                    session.active_run_id = 2
                return self.inner.__enter__()

            def __exit__(self, exc_type, exc, tb):
                return self.inner.__exit__(exc_type, exc, tb)

        session.lock = _SwapLock(session.lock)
        result = session.send_signal("ctrl_c")
        self.assertTrue(result["success"])
        self.assertEqual(session.active_run_id, 2)
        self.assertTrue(first.done_event.is_set())
        self.assertFalse(second.done_event.is_set())

    def test_stdin_fragments_are_checked_together(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        session.server_config.read_only = True
        config.READ_ONLY = True
        run = RunState(
            run_id=1, session_id=1, command="cat", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "frag.log"),
        )
        session.runs[1] = run
        session.active_run_id = 1
        try:
            first = session.send_signal("stdin", "r", press_enter=False)
            self.assertTrue(first["success"])
            self.assertFalse(channel.send.called)
            self.assertEqual(session._pending_stdin, "r")
            second = session.send_signal("stdin", "m -rf /", press_enter=True)
            self.assertFalse(second["success"])
            self.assertIn("Security", second["error"])
            self.assertEqual(channel.send.call_count, 0)
            self.assertEqual(session._pending_stdin, "")
            third = session.send_signal("stdin", "m -rf /", press_enter=True)
            self.assertTrue(third["success"])
            self.assertEqual(channel.send.call_count, 1)
            sent = channel.send.call_args[0][0]
            self.assertTrue(sent.startswith(b"m -rf /"))
            self.assertFalse(sent.startswith(b"rm"))
        finally:
            config.READ_ONLY = False

    def test_invoke_shell_timeout_closes_late_channel(self):
        session = SSHSession(1, "late", self.cache_dirs, "test_project")
        closed = []

        def invoke_shell(**_kwargs):
            time.sleep(0.35)
            channel = MagicMock()
            channel.close.side_effect = lambda: closed.append(True)
            return channel

        session.client = MagicMock()
        session.client.invoke_shell.side_effect = invoke_shell
        with self.assertRaises(TimeoutError):
            session._invoke_shell_with_timeout(timeout=0.05)
        time.sleep(0.45)
        self.assertTrue(closed)

    def test_exec_stdin_is_closed_immediately(self):
        session, mock_client, _ = self._create_mock_session()
        stdin = MagicMock()
        stdout = MagicMock()
        channel = MagicMock()
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = False
        stdout.channel = channel
        stdin.channel = channel
        mock_client.exec_command.return_value = (stdin, stdout, MagicMock())
        result = session.run_command(
            command="cat", mode="sync", shell=False, wait_timeout=1.0,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="prompt",
            quiet_complete_timeout=0.5, background=True, use_pty=False,
        )
        self.assertTrue(result["success"])
        channel.shutdown_write.assert_called()
        rejected = session.send_signal("stdin", "hello", press_enter=True)
        session.close()
        self.assertFalse(rejected["success"])
        self.assertIn("exec channel stdin is closed", rejected["error"])

    def test_read_reports_dropped_data(self):
        """Unread canvas text that was trimmed away before the cursor reached it is
        reported instead of silently skipped (D5)."""
        session, _, _ = self._create_mock_session()
        session.scrollback.append("kept")
        # Simulate eviction: the canvas now starts at an absolute offset the unread
        # cursor never reached.
        session.scrollback.base_offset = 20
        session.scrollback_cursor = 0
        result = session.read_canvas(limit=10, max_chars=100, wait_timeout=0.0)
        self.assertTrue(result["dropped_data"])
        self.assertEqual(result["output"], "kept")

    def test_channel_eof_marks_session_dead(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        run = RunState(
            run_id=3, session_id=1, command="true", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "eof.log"),
        )
        session.runs[3] = run
        session.active_run_id = 3
        channel.recv_ready.side_effect = [True, False]
        channel.recv.return_value = b""
        session._reader_loop(run)
        self.assertEqual(run.status, "dead")
        self.assertEqual(run.completion_method, "eof")
        self.assertTrue(session.is_dead)

    def test_internal_shell_read_keeps_more_than_200_lines(self):
        from src.fs import _sync_shell
        from src.config import MAX_BUFFER_CHARS
        session, _, channel = self._create_mock_session()
        channel.closed = False
        channel.recv_ready.return_value = False

        def fill(run):
            payload = "\n".join(["A" * 76] * 250)
            run.append_output(f"MCP_BEGIN_x\n{payload}\nMCP_END_x\n")
            run.exit_status = 0
            run.mark_done("completed", completion_method="exit_marker")

        session._start_reader_thread = fill
        result = _sync_shell(session, "base64 /tmp/f", timeout=2.0, max_chars=MAX_BUFFER_CHARS)
        self.assertIn("MCP_END_x", result.get("output", ""))

    def test_posix_banner_sets_in_shell_keenetic_does_not(self):
        from src.session import banner_sets_posix_shell
        self.assertTrue(banner_sets_posix_shell("root@vps:~# "))
        self.assertTrue(banner_sets_posix_shell("$"))
        self.assertTrue(banner_sets_posix_shell("Hardware Model: OpenStack Nova\n$"))
        self.assertTrue(banner_sets_posix_shell("/ # "))
        self.assertTrue(banner_sets_posix_shell("user@host:~$ "))
        self.assertFalse(banner_sets_posix_shell("\n> "))
        self.assertFalse(banner_sets_posix_shell("(config)> "))

        def connect_with(banner: bytes):
            session = SSHSession(1, "banner", self.cache_dirs, "test")
            channel = MagicMock()
            channel.closed = False
            channel.recv_ready.side_effect = [True, False, False, False]
            channel.recv.return_value = banner
            with patch("paramiko.SSHClient") as ssh_client, patch("src.session.time.sleep"):
                client = MagicMock()
                ssh_client.return_value = client
                transport = MagicMock()
                transport.is_active.return_value = True
                client.get_transport.return_value = transport
                session._invoke_shell_with_timeout = MagicMock(return_value=channel)
                self.assertTrue(session.connect())
            return session

        self.assertTrue(connect_with(b"root@vps:~# ").in_shell)
        self.assertTrue(connect_with(b"Hardware Model: OpenStack Nova\n$").in_shell)
        self.assertFalse(connect_with(b"\n> ").in_shell)

    def test_background_keeps_session_busy(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        with patch.object(session, "_start_reader_thread"):
            result = self._run_cmd(session, "sleep 1", background=True)
        self.assertTrue(result["success"], result)
        self.assertIsNotNone(session.active_run_id)
        self.assertTrue(session.is_busy())

    def test_second_check_health_does_not_open_another_shell(self):
        session, client, channel = self._create_mock_session()
        del session.check_health
        channel.closed = True
        transport = MagicMock()
        transport.is_active.return_value = True
        client.get_transport.return_value = transport
        calls = []

        def invoke(*args, **kwargs):
            calls.append(1)
            time.sleep(0.05)
            opened = MagicMock()
            opened.closed = False
            opened.recv_ready.return_value = False
            return opened

        with patch.object(session, "_invoke_shell_with_timeout", side_effect=invoke), \
             patch.object(session, "_setup_environment", return_value=""), \
             patch("src.session.time.sleep"):
            results = []

            def run():
                results.append(session.check_health())

            first = threading.Thread(target=run)
            second = threading.Thread(target=run)
            first.start()
            second.start()
            first.join(2)
            second.join(2)
        self.assertEqual(calls, [1])
        self.assertEqual(results, [True, True])

    def test_evict_completed_buffers_without_recv(self):
        from src.manager import MultiServerManager, ServerNode
        from src.config import ServerTargetConfig
        manager = MultiServerManager(self.cache_dirs, "evict", config_path="")
        try:
            cfg = ServerTargetConfig(alias="box", host="10.0.0.1", user="u")
            node = ServerNode(cfg, self.cache_dirs, "evict")
            session, _, channel = self._create_mock_session()
            channel.recv.side_effect = AssertionError("recv while over limit")
            node.sessions[session.id] = session
            node.current_session_id = session.id
            manager.nodes[cfg.alias] = node
            done = RunState(
                run_id=1, session_id=session.id, command="old", mode="sync",
                started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
                max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "old.log"),
            )
            done.output_buffer = "x" * 30
            done.mark_done("completed")
            active = RunState(
                run_id=2, session_id=session.id, command="live", mode="sync",
                started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=2.0,
                max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "live.log"),
            )
            active.output_buffer = "y" * 50
            session.runs[1] = done
            session.runs[2] = active
            session.active_run_id = 2
            channel.recv_ready.side_effect = [True, StopIteration()]
            set_buffer_limit_checkers(manager.can_accept_more_buffer, manager.total_buffer_chars)
            with patch("src.manager.MAX_TOTAL_BUFFER_CHARS", 40):
                try:
                    session._reader_loop(active)
                except StopIteration:
                    pass
            self.assertEqual(done.output_buffer, "")
            self.assertEqual(active.output_buffer, "y" * 50)
            self.assertEqual(channel.recv.call_count, 0)
            self.assertTrue(active.recv_paused)
        finally:
            set_buffer_limit_checkers(lambda size: True, lambda: 0)
            manager.close_all()

    def test_shell_ctrl_c_holds_until_prompt(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        run = RunState(
            run_id=1, session_id=1, command="sleep", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "hold.log"),
        )
        session.runs[1] = run
        session.active_run_id = 1
        result = session.send_signal("ctrl_c")
        self.assertTrue(result["success"])
        self.assertTrue(run.interrupt_sent)
        self.assertFalse(run.done_event.is_set())
        self.assertEqual(session.active_run_id, 1)

        channel.recv_ready.side_effect = [True]
        channel.recv.return_value = b"\n> "
        session._reader_loop(run)
        self.assertEqual(run.status, "interrupted")
        self.assertIsNone(session.active_run_id)

    def test_shell_interrupt_quiet_releases_without_prompt(self):
        session, _, channel = self._create_mock_session()
        channel.recv_ready.return_value = False
        run = RunState(
            run_id=3, session_id=1, command="sleep", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "quiet-int.log"),
        )
        run.interrupt_sent = True
        run.interrupt_at = time.time() - 5
        run.quiet_complete_timeout = 0.05
        session.runs[3] = run
        session.active_run_id = 3
        session._reader_loop(run)
        self.assertEqual(run.status, "interrupted")
        self.assertIsNone(session.active_run_id)

    def test_invalidate_pty_closes_channel_and_flags_state(self):
        """T1.2/F4: unknown PTY boundary must kill the channel and warn about state loss."""
        session, _, channel = self._create_mock_session()
        channel.closed = False
        session.in_shell = True
        session._invalidate_pty("partial command send")
        self.assertIsNone(session.channel)
        self.assertTrue(channel.close.called)
        self.assertTrue(session.state_lost)
        self.assertFalse(session.in_shell)

    def test_partial_send_invalidates_pty_and_reports_failure(self):
        """T1.2/F4: a partial PTY send leaves a dirty remote line - the channel must die,
        otherwise the NEXT command's text gets appended to the half-typed one."""
        session, _, _ = self._create_mock_session()

        class PartialSendChannel:
            """Accepts 5 bytes once (a half-typed remote line), then dies."""
            def __init__(self):
                self.closed = False
                self.delivered = b""

            def send(self, data):
                if not self.delivered:
                    self.delivered += data[:5]
                    return 5
                raise OSError("broken pipe")

            def settimeout(self, timeout):
                pass

            def gettimeout(self):
                return 1.0

            def recv_ready(self):
                return False

            def close(self):
                self.closed = True

        channel = PartialSendChannel()
        session.channel = channel
        session.in_shell = True
        with patch.object(session, "_start_reader_thread"):
            res = session.run_command(
                command="rm -rf /var/log && echo done",
                mode="sync", shell=True, wait_timeout=0.5, startup_wait=0.1,
                hard_timeout=0.0, completion_hint="either", quiet_complete_timeout=0.5,
            )
        self.assertFalse(res["success"])
        self.assertEqual(len(channel.delivered), 5, "scenario is a PARTIAL send")
        self.assertTrue(channel.closed, "dirty PTY must be killed")
        self.assertIsNone(session.channel)
        self.assertTrue(session.state_lost)
        self.assertIsNone(session.active_run_id)

    def test_shell_interrupt_quiet_bound_invalidates_pty(self):
        """T1.2/F4: interrupt without a prompt must not leave the PTY reusable."""
        session, _, channel = self._create_mock_session()
        channel.recv_ready.return_value = False
        channel.closed = False
        run = RunState(
            run_id=3, session_id=1, command="sleep", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "quiet-inv.log"),
        )
        run.interrupt_sent = True
        run.interrupt_at = time.time() - 5
        run.quiet_complete_timeout = 0.05
        session.runs[3] = run
        session.active_run_id = 3
        session._reader_loop(run)
        self.assertEqual(run.status, "interrupted")
        self.assertIsNone(session.channel)
        self.assertTrue(channel.close.called)
        self.assertTrue(session.state_lost)

    def test_exec_eof_does_not_kill_session(self):
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=4, session_id=1, command="true", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "exec-eof.log"),
        )
        channel = MagicMock()
        channel.closed = True
        channel.recv_ready.return_value = True
        channel.recv.return_value = b""
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = False
        run.exec_channel = channel
        session._exec_reader_loop(run)
        self.assertFalse(session.is_dead)
        self.assertNotEqual(run.status, "completed")
        self.assertEqual(run.status, "failed")

    def test_exec_silence_sets_quiet_event(self):
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=5, session_id=1, command="true", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.05, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "exec-quiet.log"),
        )
        channel = MagicMock()
        channel.closed = False
        channel.recv_ready.return_value = False
        channel.recv_stderr_ready.return_value = False
        channel.exit_status_ready.return_value = False
        run.exec_channel = channel

        def stop_later():
            deadline = time.time() + 0.35
            while time.time() < deadline and not run.quiet_event.is_set():
                time.sleep(0.02)
            run.mark_done("failed")

        threading.Thread(target=stop_later, daemon=True).start()
        session._exec_reader_loop(run)
        self.assertFalse(run.quiet_event.is_set())
        self.assertFalse(session.is_dead)

    def test_parallel_stdin_rejects_joined_rm(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        session.server_config.read_only = True
        config.READ_ONLY = True
        run = RunState(
            run_id=1, session_id=1, command="cat", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "race.log"),
        )
        session.runs[1] = run
        session.active_run_id = 1
        release = threading.Event()
        started = threading.Event()
        original = session._check_security

        def slow_check(command):
            if command == "r":
                started.set()
                release.wait(2)
            return original(command)

        session._check_security = slow_check
        holder = []

        def send_fragment():
            holder.append(session.send_signal("stdin", "r", press_enter=False))

        worker = threading.Thread(target=send_fragment)
        worker.start()
        self.assertTrue(started.wait(2))
        rejected = session.send_signal("stdin", "m -rf /", press_enter=True)
        release.set()
        worker.join(2)
        self.assertTrue(holder[0]["success"])
        self.assertFalse(rejected["success"])
        self.assertEqual(channel.send.call_count, 0)

    def test_run_is_busy_during_file_op(self):
        session, _, _ = self._create_mock_session()
        self.assertTrue(session.begin_file_op())
        stdout = MagicMock()
        stdout.channel = MagicMock()
        stdout.channel.closed = False
        stdout.channel.recv_ready.return_value = False
        stdout.channel.recv_stderr_ready.return_value = False
        stdout.channel.exit_status_ready.return_value = False
        session.client.exec_command.return_value = (MagicMock(), stdout, MagicMock())
        internal = session.run_command(
            command="mkdir -p /tmp/mcp", mode="sync", shell=False, wait_timeout=1.0,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
            quiet_complete_timeout=0.5, background=True, internal=True, use_pty=False,
        )
        self.assertTrue(internal["success"], internal)
        self.assertNotIn("busy", internal.get("error", "").lower())
        rid = session.active_run_id
        if rid is not None and rid in session.runs:
            session.runs[rid].mark_done("completed")
        with session.lock:
            if session.active_run_id == rid:
                session.active_run_id = None
        result = self._run_cmd(session, "echo hi")
        self.assertFalse(result["success"])
        self.assertIn("busy", result["error"].lower())
        session.end_file_op()

    def test_internal_run_does_not_consume_state_lost(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        session.state_lost = True
        internal = session.run_command(
            command="mkdir -p /tmp/mcp", mode="sync", shell=True, wait_timeout=1.0,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
            quiet_complete_timeout=0.5, background=True, internal=True,
        )
        self.assertNotIn("was lost", internal.get("error", ""))
        self.assertTrue(session.state_lost)
        rid = session.active_run_id
        if rid is not None and rid in session.runs:
            session.runs[rid].mark_done("completed")
        with session.lock:
            if session.active_run_id == rid:
                session.active_run_id = None
        user = self._run_cmd(session, "echo hi")
        self.assertFalse(user["success"])
        self.assertIn("was lost", user["error"])
        self.assertFalse(session.state_lost)

    def test_read_reports_recv_paused(self):
        """A tab whose receiver is paused reports why it went quiet on read."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=9, session_id=1, command="yes", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "paused.log"),
        )
        run.set_recv_paused(True, "memory_limit")
        session.runs[9] = run
        session.active_run_id = 9
        result = session.read_canvas(limit=50, max_chars=1000, wait_timeout=0.0)
        self.assertTrue(result["recv_paused"])
        self.assertEqual(result["pause_reason"], "memory_limit")

    def test_exec_command_exception_closes_channel(self):
        session, client, _ = self._create_mock_session()
        channel = MagicMock()
        channel.settimeout.side_effect = RuntimeError("boom")
        stdin = MagicMock()
        stdout = MagicMock()
        stdout.channel = channel
        stderr = MagicMock()
        client.exec_command.return_value = (stdin, stdout, stderr)
        result = session.run_command(
            command="echo hi", mode="sync", shell=False, wait_timeout=1.0,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
            quiet_complete_timeout=0.5, use_pty=False,
        )
        self.assertFalse(result["success"])
        channel.close.assert_called()
        stdin.close.assert_called()
        stdout.close.assert_called()
        stderr.close.assert_called()

    def test_multiline_exit_marker_starts_on_its_own_line(self):
        from src.session import wrap_posix_exit_marker
        wrapped, token = wrap_posix_exit_marker("cat << 'MCP_B64_x' > /tmp/x\nYQ==\nMCP_B64_x")
        lines = wrapped.splitlines()
        self.assertEqual(lines[-2], "MCP_B64_x")
        self.assertNotIn("printf", lines[-2])
        self.assertIn(token, lines[-1])
        self.assertIn("printf", lines[-1])
        single, _ = wrap_posix_exit_marker("echo hi")
        self.assertNotIn("\n", single)
        self.assertIn("; printf", single)

    def test_explicit_secret_disables_agent_and_default_keys(self):
        from src.config import ServerTargetConfig
        captured = {}

        def connect(**kwargs):
            captured.update(kwargs)
            raise RuntimeError("stop")

        client = MagicMock()
        client.connect.side_effect = connect
        with_password = ServerTargetConfig(
            alias="box", host="10.0.0.1", user="u", password="secret", verify_host=False,
        )
        session = SSHSession(1, "", self.cache_dirs, "test_project", server_config=with_password)
        with patch("src.session.paramiko.SSHClient", return_value=client):
            session.connect()
        self.assertFalse(captured["allow_agent"])
        self.assertFalse(captured["look_for_keys"])

        captured.clear()
        with_key = ServerTargetConfig(
            alias="box", host="10.0.0.1", user="u", key_path="C:/keys/id", verify_host=False,
        )
        session = SSHSession(2, "", self.cache_dirs, "test_project", server_config=with_key)
        with patch("src.session.paramiko.SSHClient", return_value=client):
            session.connect()
        self.assertFalse(captured["allow_agent"])
        self.assertFalse(captured["look_for_keys"])

        captured.clear()
        bare = ServerTargetConfig(alias="box", host="10.0.0.1", user="u", verify_host=False)
        session = SSHSession(3, "", self.cache_dirs, "test_project", server_config=bare)
        with patch("src.session.paramiko.SSHClient", return_value=client):
            session.connect()
        self.assertTrue(captured["allow_agent"])
        self.assertTrue(captured["look_for_keys"])

    def test_drain_ready_stops_after_the_byte_cap(self):
        session, _, channel = self._create_mock_session()
        channel.recv_ready.return_value = True
        channel.recv.return_value = b"x" * 80_000
        text = session._drain_ready(channel, limit=100_000)
        self.assertLessEqual(channel.recv.call_count, 2)
        self.assertGreater(len(text), 0)

    def test_resolve_local_path_denies_servers_json_and_git(self):
        from src.utils import resolve_local_path
        servers = os.path.join(self.test_dir, "servers.json")
        git_file = os.path.join(self.test_dir, ".git", "config")
        normal = os.path.join(self.test_dir, "notes.txt")
        os.makedirs(os.path.dirname(git_file), exist_ok=True)
        for path in (servers, git_file, normal):
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("x")
        previous = config.SERVERS_CONFIG_PATH
        config.SERVERS_CONFIG_PATH = servers
        try:
            self.assertEqual(resolve_local_path(servers), "")
            self.assertEqual(resolve_local_path(git_file), "")
            self.assertTrue(resolve_local_path(normal))
        finally:
            config.SERVERS_CONFIG_PATH = previous

    def test_resolve_local_path_denies_ssh_keys_and_registry_keys(self):
        from src.utils import resolve_local_path
        from src.config import ServerTargetConfig
        # Test default key names: id_rsa, id_ed25519, id_ecdsa, id_dsa, key.ppk
        for key_name in ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "mykey.ppk", "ID_RSA"]:
            key_path = os.path.join(self.test_dir, key_name)
            with open(key_path, "w", encoding="utf-8") as f:
                f.write("key")
            self.assertEqual(resolve_local_path(key_path), "", f"Failed to deny {key_name}")

        # Test custom key_path registered in config.registry
        custom_key = os.path.join(self.test_dir, "custom_secret.pem")
        with open(custom_key, "w", encoding="utf-8") as f:
            f.write("secret")
        cfg = ServerTargetConfig(alias="srv_key", host="10.0.0.1", user="u", key_path=custom_key)
        config.registry.register(cfg)
        try:
            self.assertEqual(resolve_local_path(custom_key), "")
        finally:
            config.registry.unregister("srv_key")

    def test_wrap_posix_exit_marker_with_comment_places_marker_on_newline(self):
        from src.session import wrap_posix_exit_marker
        cmd_with_comment = "echo 123 # this is a comment"
        wrapped, token = wrap_posix_exit_marker(cmd_with_comment)
        lines = wrapped.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], cmd_with_comment)
        self.assertTrue(lines[1].startswith("printf "))
        self.assertIn(token, lines[1])

        # Also test with newlines
        cmd_multiline = "echo 1\necho 2"
        wrapped2, token2 = wrap_posix_exit_marker(cmd_multiline)
        lines2 = wrapped2.splitlines()
        self.assertEqual(len(lines2), 3)
        self.assertTrue(lines2[2].startswith("printf "))

    def test_check_health_closes_dead_session_immediately(self):
        session, _, channel = self._create_mock_session()
        del session.check_health
        channel.closed = False
        transport = MagicMock()
        transport.is_active.return_value = False
        session.client.get_transport.return_value = transport

        with patch.object(session, "close", wraps=session.close) as mock_close:
            session.check_health()
            self.assertTrue(session.is_dead)
            mock_close.assert_called_with(permanent=False)

    def test_marker_silence_waits_for_the_marker(self):
        session, _, channel = self._create_mock_session()
        session.in_shell = True
        channel.closed = False
        channel.send_ready.return_value = True
        phase = {"n": 0, "sent": False, "t0": 0.0, "payload": b""}

        def send(data):
            raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
            phase["payload"] += bytes(raw)
            phase["sent"] = True
            if phase["t0"] == 0.0:
                phase["t0"] = time.time()
            return len(raw)

        def recv_ready():
            if not phase["sent"]:
                return False
            if phase["n"] == 0:
                return True
            return (time.time() - phase["t0"]) >= 1.0

        def recv(_n):
            phase["n"] += 1
            if phase["n"] == 1:
                return b"echo hi\r\n"
            match = re.search(br"__MCP_EC_([0-9a-f]+)_", phase["payload"])
            token = match.group(1).decode()
            return f"__MCP_EC_{token}_0\n".encode()

        channel.send.side_effect = send
        channel.recv_ready.side_effect = recv_ready
        channel.recv.side_effect = recv
        started = time.time()
        result = session.run_command(
            command="echo hi", mode="sync", shell=True, wait_timeout=3.0,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
            quiet_complete_timeout=0.2,
        )
        elapsed = time.time() - started
        self.assertTrue(result["success"], result)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["still_running"])
        self.assertGreaterEqual(elapsed, 0.8)
        self.assertLess(elapsed, 2.5)

    def test_either_silence_returns_stalled_and_stays_busy(self):
        # A6: PTY silent-from-zero is honest stalled (quiet idle, no marker), not
        # a full-wait running. The tab stays busy either way: a second command
        # must fail with a busy error until the first is reaped.
        session, _, channel = self._create_mock_session()
        session.in_shell = False
        channel.closed = False
        channel.recv_ready.return_value = False
        channel.send_ready.return_value = True
        result = session.run_command(
            command="ping -c 4", mode="sync", shell=False, wait_timeout=0.45,
            startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
            quiet_complete_timeout=0.15,
        )
        try:
            self.assertTrue(result["success"], result)
            self.assertEqual(result["status"], "stalled")
            self.assertTrue(result["unconfirmed_completion"])
            self.assertNotIn("run_id", result.get("hint", ""))
            run = session.runs[result["run_id"]]
            self.assertTrue(run.quiet_event.is_set())
            self.assertEqual(session.active_run_id, result["run_id"])
            second = session.run_command(
                command="echo hi", mode="sync", shell=False, wait_timeout=0.3,
                startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
                quiet_complete_timeout=0.1,
            )
            self.assertFalse(second["success"])
            self.assertIn("busy", second["error"].lower())
        finally:
            run = session.runs.get(result.get("run_id"))
            if run is not None:
                run.mark_done("completed")

    def test_memory_pause_ctrl_c_finishes_without_recv(self):
        session, _, channel = self._create_mock_session()
        channel.closed = False
        channel.recv_ready.return_value = False
        channel.send_ready.return_value = True
        set_buffer_limit_checkers(lambda _size: False, lambda: 10 ** 9)
        try:
            started = session.run_command(
                command="yes", mode="sync", shell=True, wait_timeout=1.0,
                startup_wait=0.1, hard_timeout=0.0, completion_hint="either",
                quiet_complete_timeout=0.05, background=True,
            )
            self.assertTrue(started["success"], started)
            channel.recv_ready.return_value = True
            run = session.runs[started["run_id"]]
            run.interrupt_sent = True
            run.interrupt_at = time.time() - 5
            self.assertTrue(run.done_event.wait(2))
            self.assertEqual(run.status, "interrupted")
            channel.recv.assert_not_called()
        finally:
            set_buffer_limit_checkers(lambda _size: True, lambda: 0)

    def test_read_canvas_rewind_keeps_history_readable(self):
        """Reading does not consume the canvas: offset=0 rewinds and returns the same
        window again (the unread cursor only moves on a paging read)."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=3, session_id=1, command="yes", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "slice.log"),
        )
        run.output_buffer = ("A" * 50) + ("B" * 150)
        session.runs[3] = run
        result = session.read_canvas(limit=50, max_chars=100, wait_timeout=0.0)
        self.assertEqual(result["output"], ("A" * 50) + ("B" * 50))
        self.assertTrue(result["has_more"], "the rest of the canvas is still unread")
        # Rewind: the history is intact, the same window comes back.
        reread = session.read_canvas(limit=50, offset=0, max_chars=100, wait_timeout=0.0)
        self.assertEqual(reread["output"], ("A" * 50) + ("B" * 50))

    def test_exit_marker_resilience(self):
        token = "a1b2c3d4e5f60718"
        # Bare exit marker
        self.assertEqual(parse_exit_marker(f"output\n__MCP_EC_{token}_0\n", token), 0)
        # SberCloud / prompt without space
        self.assertEqual(parse_exit_marker(f"output\n__MCP_EC_{token}_0\n$", token), 0)
        # Prompt with space
        self.assertEqual(parse_exit_marker(f"output\n__MCP_EC_{token}_0\n$ ", token), 0)
        # Linux standard prompt
        self.assertEqual(parse_exit_marker(f"output\n__MCP_EC_{token}_1\nuser@vps:~$ ", token), 1)
        # Exit code 127
        self.assertEqual(parse_exit_marker(f"output\n__MCP_EC_{token}_127\nroot@box:~# ", token), 127)
        # Echo line must NOT match (it contains _$?)
        self.assertIsNone(parse_exit_marker(f"echo hi; printf '%s\\n' \"__MCP_EC_{token}_$?\"\n", token))

    def test_strip_internal_framing_removes_echo_and_marker(self):
        from src.utils import strip_internal_framing
        token = "c5b472bf1f93d509"
        raw = (
            f"ls -la /opt/naiveproxy; printf '%s\\n' \"__MCP_EC_{token}_$?\"\n"
            "/opt/naiveproxy:\n"
            "total 60\n"
            f"__MCP_EC_{token}_0\n"
            "$ "
        )
        cleaned = strip_internal_framing(raw)
        self.assertNotIn("__MCP_EC_", cleaned)
        self.assertNotIn("printf", cleaned)
        self.assertIn("/opt/naiveproxy:", cleaned)
        self.assertIn("total 60", cleaned)

    def test_strip_internal_framing_removes_split_marker_fragment(self):
        from src.utils import strip_internal_framing
        # A canvas window can end mid-marker: the fragment must not leak either.
        cleaned = strip_internal_framing("real output\n__MCP_EC_c5b472bf\nmore")
        self.assertEqual(cleaned, "real output\nmore")

    def test_strip_internal_framing_preserves_plain_output(self):
        from src.utils import strip_internal_framing
        # No framing -> byte-for-byte identity (blank lines and whitespace included),
        # so canvas cursor / has_more arithmetic can never be shifted by the sanitiser.
        raw = "first\n\n  spaced  \nlast\n"
        self.assertEqual(strip_internal_framing(raw), raw)

    def test_read_canvas_never_exposes_exit_marker(self):
        session, _, _ = self._create_mock_session()
        token = "fb70ca1f3860fafa"
        session.append_scrollback(
            f"sed -n '30,31p' /etc/hosts; printf '%s\\n' \"__MCP_EC_{token}_$?\"\n"
            "127.0.0.1 localhost\n"
            f"__MCP_EC_{token}_0\n"
            "$ "
        )
        res = session.read_canvas(limit=100, max_chars=100000, wait_timeout=0.0)
        self.assertNotIn("__MCP_EC_", res["output"])
        self.assertNotIn("printf", res["output"])
        self.assertIn("127.0.0.1 localhost", res["output"])

    def test_async_start_wait_timeout_zero(self):
        session, _, _ = self._create_mock_session()
        channel = MagicMock()
        channel.recv_ready.return_value = False
        channel.send_ready.return_value = True
        channel.gettimeout.return_value = 0.5
        session.channel = channel
        session.in_shell = True

        res = session.run_command(
            command="sleep 100",
            mode="sync",
            shell=True,
            wait_timeout=0.0,
            startup_wait=0.1,
            hard_timeout=0.0,
            completion_hint="either",
            quiet_complete_timeout=1.0,
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "running")
        self.assertTrue(res["still_running"])
        self.assertIn("run_id", res)

    def test_informative_busy_error_message(self):
        session, _, _ = self._create_mock_session()
        channel = MagicMock()
        session.channel = channel
        run = RunState(
            run_id=5, session_id=1, command="long_process.sh", mode="sync",
            started_at=time.time(), wait_timeout=5.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "busy.log"),
        )
        session.runs[5] = run
        session.active_run_id = 5

        res = session.run_command(
            command="echo hi",
            mode="sync",
            shell=True,
            wait_timeout=5.0,
            startup_wait=0.1,
            hard_timeout=0.0,
            completion_hint="either",
            quiet_complete_timeout=1.0,
        )
        self.assertFalse(res["success"])
        self.assertIn("busy", res["error"].lower())
        self.assertIn("long_process.sh", res["error"])
        self.assertIn("single shell terminal", res["error"])
        self.assertIn("new_session=true", res["error"])

    def test_state_lost_relaxed_on_shell_false(self):
        session, _, _ = self._create_mock_session()
        channel = MagicMock()
        channel.recv_ready.return_value = False
        channel.send_ready.return_value = True
        channel.gettimeout.return_value = 0.5
        session.channel = channel

        # shell=False on router CLI must NOT reject on state_lost
        session.state_lost = True
        res_router = session.run_command(
            command="show version",
            mode="sync",
            shell=False,
            wait_timeout=0.0,
            startup_wait=0.1,
            hard_timeout=0.0,
            completion_hint="either",
            quiet_complete_timeout=1.0,
        )
        self.assertTrue(res_router["success"], res_router)
        self.assertFalse(session.state_lost)

        # Mark first run finished so session is idle
        with session.lock:
            if session.active_run_id:
                session.runs[session.active_run_id].mark_done("completed")
                session.active_run_id = None

        # shell=True on Linux shell MUST reject on state_lost
        session.state_lost = True
        res_linux = session.run_command(
            command="ls -la",
            mode="sync",
            shell=True,
            wait_timeout=0.0,
            startup_wait=0.1,
            hard_timeout=0.0,
            completion_hint="either",
            quiet_complete_timeout=1.0,
        )
        self.assertFalse(res_linux["success"])
        self.assertIn("Warning: Connection for session", res_linux["error"])
        self.assertIn("reset", res_linux["error"].lower())

    def test_evicted_runs_are_mirrored_before_buffers_are_freed(self):
        """Eviction frees old run buffers; their not-yet-mirrored text must reach the
        canvas first, otherwise unread output would disappear without a trace."""
        session, _, _ = self._create_mock_session()
        for rid in range(1, 16):
            run = RunState(
                run_id=rid, session_id=session.id, command=f"echo {rid}", mode="sync",
                started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
                max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], f"evict{rid}.log"),
            )
            run.append_output(f"output_{rid}\n")
            run.mark_done("completed", completion_method="exit_status")
            session.runs[rid] = run
            session._cleanup_old_runs()

        with session.lock:
            self.assertLessEqual(len(session.runs), 10)
            self.assertNotIn(1, session.runs)
            self.assertIn(15, session.runs)
        # Evicted output is not lost: it was mirrored into the single unread stream.
        res = session.read_canvas(limit=100, max_chars=8192, wait_timeout=0.0)
        self.assertIn("output_1\n", res["output"])
        self.assertIn("output_15\n", res["output"])

    def test_resolve_local_path_windows_drive_case_normalization(self):
        """Verify resolve_local_path handles different drive letter casing on Windows without throwing ValueError."""
        from src.utils import resolve_local_path
        sample_file = os.path.join(self.test_dir, "test_file.txt")
        with open(sample_file, "w") as f:
            f.write("content")

        drive, rest = os.path.splitdrive(sample_file)
        if drive:
            inverted_drive = drive.lower() if drive.isupper() else drive.upper()
            alt_path = inverted_drive + rest
            res = resolve_local_path(alt_path)
            self.assertTrue(res, f"Expected {alt_path} to resolve successfully")
            self.assertEqual(os.path.normcase(res), os.path.normcase(sample_file))

    def test_log_policy_meta_drops_output_chunks_but_keeps_commands(self):
        """T2.5/F7: default 'meta' policy must not store raw output chunks (secrets/IO)."""
        from src.config import config as cfg
        log_file = os.path.join(self.cache_dirs["runs_dir"], "policy.log")
        run = RunState(
            run_id=1, session_id=1, command="cat secret.conf", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=log_file,
        )
        session, _, _ = self._create_mock_session()
        previous = cfg.LOG_OUTPUT
        try:
            cfg.LOG_OUTPUT = "meta"
            session._log_run(run, "OUT", {"chunk": "raw output with password=hunter2"})
            session._log_run(run, "ERR", {"chunk": "raw stderr"})
            session._log_run(run, "SYS", {"event": "reader_started"})
            with open(log_file, encoding="utf-8") as fh:
                body = fh.read()
            self.assertNotIn("raw output", body)
            self.assertNotIn("raw stderr", body)
            self.assertIn("reader_started", body)

            cfg.LOG_OUTPUT = "full"
            session._log_run(run, "OUT", {"chunk": "raw output kept"})
            with open(log_file, encoding="utf-8") as fh:
                body = fh.read()
            self.assertIn("raw output kept", body)

            cfg.LOG_OUTPUT = "off"
            json_line(log_file, {"dir": "SYS", "event": "should_not_appear"})
            with open(log_file, encoding="utf-8") as fh:
                body = fh.read()
            self.assertNotIn("should_not_appear", body)
        finally:
            cfg.LOG_OUTPUT = previous

    def test_mask_secrets_hides_credentials_in_text(self):
        """T2.5/F7: command text and diagnostics must not persist obvious secrets."""
        from src.utils import mask_secrets
        masked = mask_secrets("mysql -h db --password=hunter2 -e 'select 1' && curl -H 'Authorization: Bearer abc123'")
        self.assertNotIn("hunter2", masked)
        self.assertIn("******", masked)

    def test_cleanup_old_logs_respects_byte_budget(self):
        """T2.5/F7: disk usage must be bounded by bytes, not by file count."""
        runs_dir = self.cache_dirs["runs_dir"]
        for i, size in enumerate((900, 900, 300)):
            path = os.path.join(runs_dir, f"budget_{i}.log")
            with open(path, "wb") as fh:
                fh.write(b"x" * size)
            stamp = time.time() - (30 - i)  # budget_0 oldest, budget_2 newest
            os.utime(path, (stamp, stamp))
        deleted = cleanup_old_logs(self.cache_dirs, max_age_seconds=7 * 86400, max_files=500, max_total_bytes=1500)
        self.assertGreaterEqual(deleted, 1)
        self.assertFalse(os.path.exists(os.path.join(runs_dir, "budget_0.log")))
        self.assertTrue(os.path.exists(os.path.join(runs_dir, "budget_2.log")))

    def test_json_line_caps_at_max_log_file_bytes(self):
        """Verify json_line drops OUT/ERR chunks when file exceeds MAX_LOG_FILE_BYTES but preserves SYS events."""
        log_file = os.path.join(self.test_dir, "capped_run.log")
        with patch("src.utils.MAX_LOG_FILE_BYTES", 500):
            json_line(log_file, {"dir": "SYS", "event": "run_created", "command": "yes"})
            json_line(log_file, {"dir": "OUT", "chunk": "A" * 600})
            size_after_large = os.path.getsize(log_file)
            self.assertGreaterEqual(size_after_large, 500)

            # Subsequent OUT chunks must be dropped
            json_line(log_file, {"dir": "OUT", "chunk": "B" * 200})
            self.assertEqual(os.path.getsize(log_file), size_after_large)

            # SYS event (like run_done) must NOT be dropped
            json_line(log_file, {"dir": "SYS", "event": "run_done", "status": "completed"})
            self.assertGreater(os.path.getsize(log_file), size_after_large)
            with open(log_file, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("run_done", content)
            self.assertNotIn("B" * 200, content)

    def test_invoke_shell_timeout_closes_transport(self):
        """Verify _invoke_shell_with_timeout closes the transport on timeout to unblock hanging worker thread."""
        session, _, _ = self._create_mock_session()
        mock_transport = MagicMock()
        session.client.get_transport.return_value = mock_transport

        def hang_invoke(*args, **kwargs):
            time.sleep(1.0)
            return MagicMock()

        session.client.invoke_shell = hang_invoke
        with self.assertRaises(TimeoutError):
            session._invoke_shell_with_timeout(timeout=0.1)

        mock_transport.close.assert_called_once()

    def test_read_run_wait_timeout_waits_for_completion(self):
        """read_run waits for the run to finish while the stream is silent.

        Nothing is buffered, so the read has nothing to hand back and must block
        until done_event (review R6: only 'finish OR produce output' ends the
        wait - the mirror case is test_read_run_returns_immediately_when_output_is_waiting).
        """
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=5, session_id=session.id, command="sleep 0.1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test.log")
        )
        session.runs[5] = run
        session.active_run_id = 5

        # Background thread sets done_event after 0.05s
        def finish():
            time.sleep(0.05)
            run.exit_status = 0
            run.completion_method = "exit_marker"
            run.done_event.set()

        t = threading.Thread(target=finish)
        t.start()

        started = time.time()
        res = session.read_canvas(limit=100, max_chars=1000, wait_timeout=1.0)
        elapsed = time.time() - started
        t.join()

        self.assertTrue(res["success"])
        # It must really have waited for the done_event, not returned at once.
        self.assertGreaterEqual(elapsed, 0.04)
        self.assertEqual(res["status"], "completed")
        self.assertFalse(res["still_running"])
        self.assertEqual(res["exit_status"], 0)

    def test_read_run_returns_immediately_when_output_is_waiting(self):
        """A poll that already has unread output must not burn wait_timeout (R6).

        The tool describes wait_timeout as 'finish or produce output'; waiting the
        whole window while bytes are sitting in the buffer made every poll of a
        long-running command cost DEFAULT_WAIT_TIMEOUT seconds.
        """
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=6, session_id=session.id, command="tail -f /var/log/syslog", mode="sync",
            started_at=time.time(), wait_timeout=30.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test.log")
        )
        run.output_buffer = "line-1\n"
        session.runs[6] = run
        session.active_run_id = 6

        started = time.time()
        res = session.read_canvas(limit=100, max_chars=1000, wait_timeout=1.0)
        elapsed = time.time() - started

        self.assertTrue(res["success"])
        self.assertLess(elapsed, 0.5)
        self.assertEqual(res["output"], "line-1\n")
        self.assertEqual(res["status"], "running")
        self.assertTrue(res["still_running"])

    def test_fully_consumed_run_buffer_can_be_freed_from_the_canvas(self):
        """The canvas is the source of truth: freeing a run buffer keeps its text.

        Review #2 D5: the old path freed the buffer and then reported the whole output
        as lost, so rewind had nothing left to hand back. Now the text is mirrored into
        the tab canvas first, and discarding the run buffer only frees memory."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=7, session_id=1, command="echo x", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "free.log"),
        )
        run.output_buffer = "payload\n"
        run.mark_done("completed")
        session.runs[7] = run
        res = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0)
        self.assertEqual(res["output"].strip(), "payload")
        self.assertEqual(res["has_more"], 0, "the only line was handed back")
        with run.lock:
            run.discard_all_output()
        self.assertEqual(run.buffer_len, 0, "the run buffer can be freed once mirrored")
        rewind = session.read_canvas(limit=100, offset=0, max_chars=1000, wait_timeout=0)
        self.assertEqual(rewind["output"].strip(), "payload", "the canvas still holds the text")

    def test_run_display_status_resolver(self):
        """_run_display_status: one resolver for run/read/scrollback (P3 stalled symmetry)."""
        from src.session import _run_display_status
        mk = lambda: RunState(
            run_id=1, session_id=1, command="c", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.05, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "resolver.log"),
        )
        # done + prompt -> completed
        r = mk(); r.completion_hint = "either"; r.mark_done("completed", completion_method="prompt_detected"); r.exit_status = 0
        self.assertEqual(_run_display_status(r), "completed")
        # done + exit non-zero -> completed_nonzero
        r = mk(); r.completion_hint = "either"; r.mark_done("completed_nonzero", completion_method="exit_status"); r.exit_status = 1
        self.assertEqual(_run_display_status(r), "completed_nonzero")
        # done + interrupt -> interrupted
        r = mk(); r.completion_hint = "either"; r.mark_done("interrupted", completion_method="interrupted")
        self.assertEqual(_run_display_status(r), "interrupted")
        # unfinished + PTY quiet idle -> stalled
        r = mk(); r.completion_hint = "either"; r.quiet_event.set()
        self.assertEqual(_run_display_status(r), "stalled")
        # unfinished + explicit quiet hint + quiet idle -> stalled
        r = mk(); r.completion_hint = "quiet"; r.quiet_event.set()
        self.assertEqual(_run_display_status(r), "stalled")
        # unfinished + exit marker token -> running (marker expected, not idle fallback)
        r = mk(); r.completion_hint = "either"; r.exit_marker_token = "MCP_ABC"; r.quiet_event.set()
        self.assertEqual(_run_display_status(r), "running")
        # unfinished + exec channel -> running even when quiet fired (exit_status authoritative)
        r = mk(); r.completion_hint = "either"; r.exec_channel = MagicMock(); r.quiet_event.set()
        self.assertEqual(_run_display_status(r), "running")
        # unfinished + no quiet -> running
        r = mk(); r.completion_hint = "either"
        self.assertEqual(_run_display_status(r), "running")

    def test_stalled_hint_shape(self):
        """_stalled_hint carries the resume recipe with run_id + offset (P3)."""
        from src.session import _stalled_hint
        run = RunState(
            run_id=7, session_id=1, command="c", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.05, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "hint.log"),
        )
        run.completion_hint = "either"; run.quiet_complete_timeout = 0.5
        hint = _stalled_hint("keenetic", 1, run)
        self.assertNotIn("run_id", hint)
        self.assertIn("read(session_id='keenetic/1')", hint)
        self.assertIn("No completion marker seen", hint)
        self.assertIn("new_session=true", hint)

    def test_run_line_limit_zero_means_all(self):
        """line_limit=0 means all lines (P4): 300 lines survive (default 200 would cut)."""
        session, _, channel = self._create_mock_session()
        channel.closed = False
        channel.recv_ready.return_value = False
        session.in_shell = True
        big = "".join(f"line-{i:04d}\n" for i in range(300))
        def fill(run):
            run.append_output(big)
            run.mark_done("completed", completion_method="prompt_detected")
        session._start_reader_thread = fill
        res = session.run_command(
            command="seq 1 300", mode="sync", shell=True,
            wait_timeout=2.0, startup_wait=0.05, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5,
            line_limit=0,
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "completed")
        self.assertIn("line-0000", res["output"])
        self.assertIn("line-0299", res["output"])
        self.assertEqual(res["output"].count("line-"), 300)

    def test_exit_shell_slow_ndm_prompt_still_recovers(self):
        """P0 live repro: NDM answers AFTER the old 0.8s window (~1.2s). Must still exit."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = True
        # silence for ~1.2s, then the NDM prompt arrives late
        calls = {"n": 0}
        def ready():
            calls["n"] += 1
            return calls["n"] > 24  # 24 * 0.05s ~= 1.2s
        mock_channel.recv_ready.side_effect = ready
        session._drain_ready = MagicMock(return_value="(config)> ")
        self.assertTrue(session._exit_shell())
        self.assertFalse(session.in_shell)

    def test_exit_shell_loose_ndm_tail_recovers(self):
        """P0: late NDM banner without strict prompt shape still counts as exited."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = True
        mock_channel.recv_ready.side_effect = [True, False]
        session._drain_ready = MagicMock(return_value="leaving shell\n(config) stuff")
        self.assertTrue(session._exit_shell())
        self.assertFalse(session.in_shell)

    def test_exit_shell_unknown_interpreter_invalidates_pty(self):
        """P0: exit failure = UNKNOWN interpreter. PTY invalidated, no trusted in_shell."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = True
        mock_channel.recv_ready.return_value = False
        start = time.time()
        self.assertFalse(session._exit_shell())
        self.assertLess(time.time() - start, 7.5)
        # the lie is gone: in_shell is NOT trusted anymore (PTY killed)
        self.assertFalse(session.in_shell)
        self.assertIsNone(session.channel)
        # shell=false in this fresh-unknown session is refused deterministically with the
        # recipe: the command must not run (no silent POSIX-into-NDM with in_shell trusted).
        session.ensure_alive = MagicMock(return_value=None)
        res = session.run_command(
            command="show version", mode="sync", shell=False,
            wait_timeout=2.0, startup_wait=0.05, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5,
        )
        self.assertFalse(res["success"])
        self.assertIn("new_session=true", res["error"])
        expected_failure_keys = {"success", "error", "status", "server", "session_id", "numeric_session_id", "in_shell", "mode"}
        self.assertEqual(set(res.keys()), expected_failure_keys)
        self.assertEqual(res.get("status"), "failed")

        # The real (unmocked) ensure_alive gives the same recipe on the second attempt.
        del session.ensure_alive
        res_real = session.run_command(
            command="show version", mode="sync", shell=False,
            wait_timeout=2.0, startup_wait=0.05, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5,
        )
        self.assertFalse(res_real["success"])
        self.assertIn("new_session=true", res_real["error"])

    def test_exit_shell_ok_clears_sticky(self):
        """A successful 'exit' exits the Linux subshell and returns to NDM CLI."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = True
        mock_channel.recv_ready.side_effect = [True, False]
        session._drain_ready = MagicMock(return_value="(config)> ")
        self.assertTrue(session._exit_shell())
        self.assertFalse(session.in_shell)
        self.assertFalse(session._is_subshell)

    def test_read_on_dead_session_returns_buffered_output(self):
        """Buffered output of a dead/closed session must stay readable (mirrored to canvas)."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=1, session_id=session.id, command="echo dead", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "dead.log")
        )
        run.output_buffer = "output before death\n"
        run.exit_status = 0
        run.completion_method = "exit_status"
        run.done_event.set()
        session.runs[1] = run
        session.last_run_id = 1  # read_canvas reports the newest run's status/exit_status

        # Session dies
        session.close(permanent=True)
        self.assertTrue(session.is_dead)

        # Output must still be readable!
        res = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0)
        self.assertTrue(res["success"])
        self.assertEqual(res["output"].strip(), "output before death")
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["exit_status"], 0)

    def test_terminal_tab_canvas_rewind_peek_and_paging(self):
        """The tab canvas is one line-based stream: rewind (offset=0), peek (offset<0), paging.

        Review m01215: rewind(session_id, offset=0) reads history from the very first
        line and leaves the cursor at the end of the returned window; a NEGATIVE offset
        is the non-consuming peek; plain reads continue from the single unread cursor."""
        session, _, _ = self._create_mock_session()

        # Simulate terminal activity across multiple sequential commands
        cmd1 = "$ echo first\n" + ("first line output " * 10) + "\n"
        cmd2 = "$ echo second\n" + ("second line output " * 10) + "\n"
        cmd3 = "$ echo third\n" + ("third line output " * 10) + "\n"
        session.append_scrollback(cmd1)
        session.append_scrollback(cmd2)
        session.append_scrollback(cmd3)

        # 1. Peek beginning (offset=0) to solve agent context loss / amnesia: inspects whole history without moving cursor
        res_rewind = session.read_canvas(limit=1000, offset=0, max_chars=50000)
        expected_rewind_keys = {
            "success", "session_id", "numeric_session_id", "server",
            "status", "output", "has_more", "still_running", "in_shell", "mode"
        }
        self.assertEqual(set(res_rewind.keys()), expected_rewind_keys)
        self.assertTrue(res_rewind["success"])
        self.assertIn("first line output", res_rewind["output"])
        self.assertIn("second line output", res_rewind["output"])
        self.assertIn("third line output", res_rewind["output"])
        self.assertEqual(res_rewind["has_more"], 6, "peek from start does not consume unread lines")

        # 2. Paging over the whole canvas, one line per page: advances the cursor
        page1 = session.read_canvas(limit=1, max_chars=50000)
        self.assertTrue(page1["success"])
        self.assertEqual(page1["has_more"], 5, "five lines are still unread")
        page2 = session.read_canvas(limit=1, max_chars=50000)
        self.assertEqual(page2["has_more"], 4)
        self.assertNotEqual(page1["output"], page2["output"], "each page advances the cursor")

        # 3. Peek negative (offset=-2): inspect lines above cursor without consuming
        res_peek = session.read_canvas(limit=2, offset=-2, max_chars=50000)
        self.assertTrue(res_peek["success"])
        self.assertEqual(res_peek["has_more"], 4, "a peek consumes nothing")

        # 4. Continuation resumes exactly at page3 (4 unread lines left)
        page3 = session.read_canvas(limit=1, max_chars=50000)
        self.assertEqual(page3["has_more"], 3)

    def test_find_prompt_keenetic_and_router_prompts(self):
        """Bug A repro: find_prompt must recognize Keenetic top-level prompts like Keenetic-Giga> and router>."""
        from src.utils import find_prompt
        # The captured text IS the contract: the match must be the prompt itself, not an
        # arbitrary substring (nine bare assertIsNotNone proved nothing - review 6).
        for prompt in (
            "Keenetic-Giga> ",                  # standard Keenetic prompts
            "Keenetic> ",
            "router> ",
            "admin> ",
            "Keenetic (config)> ",
            "Keenetic-Ultra (config-if)> ",
            "root# ",                           # busybox / root / prompt variants
            "root@switch# ",
            "[admin@router /opt]# ",
        ):
            self.assertEqual(find_prompt(prompt), prompt, f"{prompt!r} must be recognized as prompt")

    def test_paging_after_a_second_command_never_repeats_the_first(self):
        """Review m01215: one canvas cursor means paging past command 1 lands in command 2.

        Review #2 Bug B was an offset-space mismatch: read() continued in the scrollback
        offset space while the hint came from the run buffer. Both are now the same
        stream, so the first page of command 2 is the next unread line, not command 1."""
        session, _, _ = self._create_mock_session()
        session.in_shell = True

        # Run 1: 500 chars of output. The canvas gets the chunk in the SAME call that
        # appends it to the run buffer, so the mirror does not copy it a second time.
        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r1.log")
        )
        out1 = "COMMAND_ONE_OUTPUT_" * 25
        mirrored1 = r1.append_output(out1)
        session.append_scrollback(f"$ cmd1\n{out1}", run=r1, mirrored_to=mirrored1)
        r1.mark_done("completed", completion_method="prompt_detected")
        session.last_run_id = 1

        # Run 2: 500 chars of output.
        r2 = session.runs[2] = RunState(
            run_id=2, session_id=session.id, command="cmd2", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r2.log")
        )
        out2 = "COMMAND_TWO_OUTPUT_" * 25
        mirrored2 = r2.append_output(out2)
        session.append_scrollback(f"$ cmd2\n{out2}", run=r2, mirrored_to=mirrored2)
        r2.mark_done("completed", completion_method="prompt_detected")
        session.last_run_id = 2

        # First page ends inside command 1 and says how much is left.
        first = session.read_canvas(limit=200, max_chars=100, wait_timeout=0.0)
        self.assertTrue(first["has_more"] > 0, "unread output must be advertised for paging")

        # Continue with the single cursor: the very next unread lines, no offset math.
        paged = session.read_canvas(limit=200, max_chars=8192, wait_timeout=0.0)
        self.assertIn("COMMAND_TWO", paged["output"], "the page must reach command 2!")

        # Rewind and compare: pages concatenated must equal the whole stream exactly.
        everything = session.read_canvas(limit=0, offset=0, max_chars=100000, wait_timeout=0.0)
        self.assertEqual(first["output"] + paged["output"], everything["output"])
        self.assertEqual(everything["output"].count("COMMAND_ONE_OUTPUT_"), 25)
        self.assertEqual(everything["output"].count("COMMAND_TWO_OUTPUT_"), 25)

    def test_exit_shell_failure_blocks_false_state_lost_autorecovery(self):
        """Bug repro: PTY invalidation on _exit_shell must not trigger misleading state_lost auto-recovery advice."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = True
        mock_channel.recv_ready.return_value = False

        # 1. Trigger _exit_shell failure -> invalidates PTY
        res1 = session.run_command(
            command="show version", mode="sync", shell=False,
            wait_timeout=1.0, startup_wait=0.05, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5
        )
        self.assertFalse(res1["success"])
        self.assertIn("new_session=true", res1["error"])
        self.assertIn("session_close", res1["error"])
        self.assertEqual(res1.get("mode"), "unknown")
        self.assertIsNone(res1.get("in_shell"))

        # 2. Subsequent command on this invalidated session
        res2 = session.run_command(
            command="ls -la", mode="sync", shell=True,
            wait_timeout=1.0, startup_wait=0.05, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5
        )
        self.assertFalse(res2["success"])
        self.assertNotIn("was lost and auto-recovered", res2["error"])
        self.assertNotIn("cd <dir>", res2["error"])
        self.assertIn("new_session=true", res2["error"])
        self.assertIn("session_close", res2["error"])

    def test_exit_shell_slow_ndm_prompt_at_3_2s(self):
        """Review Bug 1 repro: Keenetic 'exit' taking 3.2s must send exactly ONE exit and succeed."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        session._is_subshell = True
        mock_channel.send = MagicMock()
        calls = {"n": 0}
        def ready():
            calls["n"] += 1
            # 64 calls * 0.05s ~= 3.2s
            return calls["n"] > 64
        mock_channel.recv_ready.side_effect = ready
        session._drain_ready = MagicMock(return_value="Keenetic-Giga> ")
        self.assertTrue(session._exit_shell(), "_exit_shell must succeed when Keenetic responds after 3.2s!")
        self.assertFalse(session.in_shell)
        self.assertEqual(mock_channel.send.call_count, 1, "Must send exactly ONE exit command, never duplicate retry!")
        mock_channel.send.assert_called_once_with("exit\n")

    def test_trimmed_run_buffer_is_reported_as_dropped(self):
        """Review Bug 3(a): a run whose start was trimmed must not pretend the loss away.

        mirrored_upto (the old per-run shared cursor) is compared with buffer_base_offset:
        anything below the base is gone, and the read admits it instead of silently
        starting in the middle."""
        session, _, _ = self._create_mock_session()
        r = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="big_cmd", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r3a.log")
        )
        session.append_scrollback("$ big_cmd\nSCROLLBACK_HISTORY")
        # Simulate a run where 1000 bytes were previously discarded from the start
        r.buffer_base_offset = 1000
        r.append_output("REMAINING_BUFFER_OUTPUT")
        session.last_run_id = 1
        r.mark_done("completed", completion_method="prompt_detected")

        # The canvas holds the surviving text; the trimmed prefix is reported as lost.
        res = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0.0)
        self.assertIn("REMAINING_BUFFER_OUTPUT", res["output"])
        self.assertIn("SCROLLBACK_HISTORY", res["output"], "the canvas is one stream - history comes first")
        self.assertTrue(res.get("dropped_data"), "text trimmed below the retained base must be reported")

    def test_read_at_end_of_stream_returns_nothing_not_history(self):
        """Review Bug 3(b,c): a read at the end of the stream is EOF, never a history dump.

        The whole tab is ONE stream now: the first read hands back history plus the run
        output in order, and the read after it returns nothing at all."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("$ old_cmd\nOLD_SCROLLBACK_HISTORY\n")
        r = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r3bc.log")
        )
        r.append_output("CMD1_OUTPUT\n")
        r.mark_done("completed", completion_method="prompt_detected")
        session.last_run_id = 1

        first = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0.0)
        self.assertEqual(first["output"], "$ old_cmd\nOLD_SCROLLBACK_HISTORY\nCMD1_OUTPUT\n")
        self.assertEqual(first["has_more"], 0, "everything unread was handed back")

        eof = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0.0)
        self.assertEqual(eof["output"], "", "at the end of the stream there is nothing to hand back")
        self.assertEqual(eof["has_more"], 0)
        self.assertNotIn("OLD_SCROLLBACK_HISTORY", eof["output"], "history must not be replayed at EOF")

    def test_paginated_read_preserves_newline_and_indentation(self):
        """P0: paging across a char boundary must not lose a newline or leading indentation."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("A" * 99 + "\n  port forward 123")

        page1 = session.read_canvas(limit=0, max_chars=100, wait_timeout=0.0)
        self.assertEqual(page1["output"], "A" * 99 + "\n", "the page must stop at the char cap")
        self.assertTrue(page1["has_more"] > 0, "the rest of the line is still unread")

        page2 = session.read_canvas(limit=0, max_chars=10000, wait_timeout=0.0)
        reconstructed = page1["output"] + page2["output"]
        self.assertIn("\n  port forward 123", reconstructed)

        # Single-page read of the same text:
        whole = session.read_canvas(limit=0, offset=0, max_chars=10000, wait_timeout=0.0)
        self.assertEqual(reconstructed, whole["output"], "paging must not drop newline or indentation!")

    def test_paging_across_cleaned_ansi_and_crlf_matches_single_output(self):
        """P0: ANSI/CRLF are cleaned once on the way into the canvas, so paging cannot split them."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("0123456789" + "\x1b[31mRed\x1b[0m\r\nNextLine\n")

        whole = session.read_canvas(offset=0, wait_timeout=0.0)
        self.assertEqual(whole["output"], "0123456789Red\nNextLine\n")
        self.assertNotIn("[31m", whole["output"], "ANSI must never reach the caller as raw text")

        # Page 1 line, then continue
        page1 = session.read_canvas(line_limit=1, wait_timeout=0.0)
        page2 = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertEqual(page1["output"] + page2["output"], whole["output"],
                         "concatenated pages must equal the single cleaned output")

    def test_paging_keeps_reading_the_canvas_not_the_last_run(self):
        """Paging over the tab canvas must never switch to the last run's private buffer."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("HIST_PAGE1_HIST_PAGE2\n")
        # Run 1 exists and is finished; its output is a plain canvas append.
        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r1.log")
        )
        mirrored = r1.append_output("RUN1_OUTPUT\n")
        session.append_scrollback("RUN1_OUTPUT\n", run=r1, mirrored_to=mirrored)
        r1.mark_done("completed", completion_method="prompt_detected")
        session.last_run_id = 1

        # Read canvas page 1, then continue with the single unread cursor.
        page1 = session.read_canvas(line_limit=1, wait_timeout=0.0)
        self.assertEqual(page1["output"], "HIST_PAGE1_HIST_PAGE2\n", "the first page starts at the beginning of the stream")
        self.assertTrue(page1["has_more"] > 0)

        page2 = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertIn("RUN1_OUTPUT", page2["output"],
                      "the run output joins the same stream, in order - it is not a second view")
        self.assertEqual(
            page1["output"] + page2["output"], "HIST_PAGE1_HIST_PAGE2\nRUN1_OUTPUT\n",
            "paging must resume exactly where the previous page stopped",
        )

    def test_stalled_zero_output_read_reports_stalled_and_unread_history(self):
        """P1: a stalled active run reports the honest status and the unread tab history."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("OLD_HISTORY_LINE_1\nOLD_HISTORY_LINE_2\n")
        # Active run 2 is running, 0 bytes produced so far, quiet event set (stalled)
        r2 = session.runs[2] = RunState(
            run_id=2, session_id=session.id, command="sleep 60", mode="sync",
            started_at=time.time(), wait_timeout=0.1, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r2.log")
        )
        r2.quiet_event.set()
        session.active_run_id = 2

        # The run produced nothing, so the unread history is all there is to hand back.
        res = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertEqual(res["status"], "stalled", "a quiet unfinished run is honestly uncertain")
        self.assertEqual(res["output"], "OLD_HISTORY_LINE_1\nOLD_HISTORY_LINE_2\n")
        self.assertEqual(res["has_more"], 0)
        self.assertTrue(res["still_running"])
        self.assertTrue(res["unconfirmed_completion"])

    def test_first_read_reports_overflow_loss(self):
        """P0: the first read of a buffer that overflowed before it was read reports dropped_data."""
        session, _, _ = self._create_mock_session()
        r = session.runs[1] = RunState(
            run_id=1, session_id=1, command="flood", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=10, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "t_flood.log")
        )
        r.append_output("1234567890EXTRA")  # 15 chars, cap is 10, drops the first 5 chars
        r.mark_done("completed", completion_method="prompt_detected")
        self.assertEqual(r.buffer_base_offset, 5)
        self.assertEqual(r.total_received_chars, 15)

        # The buffer keeps the LAST 10 chars of the 15 fed in: '12345' was dropped.
        self.assertEqual(r.output_buffer, "67890EXTRA")
        self.assertEqual(r.output_end(), 15)

        res = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertEqual(res["output"], "67890EXTRA")
        self.assertTrue(res["dropped_data"], "the first read MUST report that unread text was dropped!")
        self.assertEqual(r.buffer_base_offset, 5)
        self.assertEqual(r.total_received_chars, 15)

        # Reported exactly once: the canvas already gave up those chars (D6).
        second = session.read_canvas(line_limit=10, wait_timeout=0.0)
        self.assertFalse(second.get("dropped_data", False))

    def test_invalidated_pty_is_broken_not_idle_ndm(self):
        """P0: Invalidated PTY session must report broken/unknown and not be treated as idle NDM."""
        session, _, _ = self._create_mock_session()
        session._invalidate_pty("exit failed")
        self.assertTrue(session._pty_invalidated)
        self.assertFalse(session.is_alive())

        # Check node list_sessions representation
        from src.manager import ServerNode
        cfg = MagicMock()
        cfg.alias = "test_server"
        node = ServerNode(cfg, cache_dirs=self.cache_dirs, project_tag="test_p")
        node.sessions[session.id] = session

        sessions = node.list_sessions()
        self.assertEqual(len(sessions), 1)
        s_info = sessions[0]
        self.assertEqual(s_info["status"], "broken")
        self.assertEqual(s_info["mode"], "unknown")
        self.assertIsNone(node._find_first_idle_alive_session_locked())

        # Mutation-K pin (src/manager.py:284): the flag is authoritative even when the
        # transport still answers is_alive()=True. Without the clause session 1 reads "idle".
        def fake_session(sid, invalidated, busy):
            s = MagicMock(id=sid, is_dead=False, is_busy=lambda: busy, in_shell=True, _pty_invalidated=invalidated)
            s.is_alive = lambda: True
            s.info.return_value = {"dead": False, "alive": True, "in_shell": True}
            return s

        node2 = ServerNode(cfg, cache_dirs=self.cache_dirs, project_tag="test_p")
        node2.sessions[1] = fake_session(1, invalidated=True, busy=False)
        node2.sessions[2] = fake_session(2, invalidated=False, busy=False)
        rows = {row["numeric_session_id"]: row for row in node2.list_sessions()}
        self.assertEqual(rows[1]["status"], "broken")
        self.assertEqual(rows[1]["mode"], "unknown")
        self.assertEqual(rows[2]["status"], "idle")
        self.assertEqual(rows[2]["mode"], "linux_shell")

    def test_trailing_space_data_line_is_not_ndm_prompt(self):
        """P1/F: data lines ending in '>' or '#' must never be read as a prompt."""
        from src.utils import find_prompt
        # Ordinary output (with and without a trailing space) is not a prompt:
        for data_line in (
            "Memory usage: Total> ",
            "Data stream chunk more> ",
            "build# ",
            "Total>",
            "more>",
            "build#",
            "status#",
        ):
            self.assertIsNone(find_prompt(data_line), f"{data_line!r} must not be treated as a prompt")
        # Legitimate prompts on the same surface must match verbatim:
        for raw, expected in (
            ("Keenetic-Giga> ", "Keenetic-Giga> "),
            ("Keenetic> ", "Keenetic> "),
            ("router (config)> ", "router (config)> "),
            ("> ", "> "),
        ):
            self.assertEqual(find_prompt(raw), expected, f"{raw!r} must be recognized as prompt")

    def test_known_ndm_prompt_without_trailing_space_completes(self):
        """P1/F: standalone '>' matches verbatim, but data lines ending in '>' must not (mutation F)."""
        from src.utils import find_prompt
        self.assertEqual(find_prompt("\n>"), ">")
        self.assertEqual(find_prompt("\n> "), "> ")
        # The pre-fix pattern set accepted ordinary output ending in '>' as a prompt:
        self.assertIsNone(find_prompt("Memory usage: Total> "))
        self.assertIsNone(find_prompt("Data stream chunk more> "))

    def test_cancelled_old_request_cannot_interrupt_new_exec_run(self):
        """P0: Cancellation of an old request must not kill a newer run on the session."""
        session, _, _ = self._create_mock_session()
        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r1.log"),
            req_id="req_1"
        )
        session.inflight_by_req["req_1"] = 1
        session.active_run_id = 1

        # Run 1 completes
        r1.mark_done("completed")

        # Run 2 starts with different request
        r2 = session.runs[2] = RunState(
            run_id=2, session_id=session.id, command="cmd2", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r2.log"),
            req_id="req_2"
        )
        mock_exec_channel = MagicMock()
        mock_exec_channel.closed = False
        r2.exec_channel = mock_exec_channel
        session.inflight_by_req["req_2"] = 2
        session.active_run_id = 2

        # Old cancellation arrives for req_1: it must be a no-op - not even a signal attempt.
        with patch.object(session, "send_signal", wraps=session.send_signal) as send_spy:
            cancel_res = session.cancel_run_for_request("req_1")
        send_spy.assert_not_called()
        self.assertTrue(cancel_res["success"])
        self.assertEqual(cancel_res.get("message"), "nothing to cancel: request already finished")
        self.assertEqual(session.active_run_id, 2, "The newer run must stay the active one!")
        self.assertFalse(r2.done_event.is_set(), "New run must not be interrupted by old cancellation!")
        self.assertFalse(mock_exec_channel.close.called, "New exec channel must not be closed!")

    def test_old_reader_finally_does_not_replace_new_last_run_id(self):
        """P1: Old reader thread finally must NOT overwrite last_run_id if a newer run was reserved."""
        session, _, _ = self._create_mock_session()
        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r1.log")
        )
        r2 = session.runs[2] = RunState(
            run_id=2, session_id=session.id, command="cmd2", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r2.log")
        )
        # Reservation of run 2 has set last_run_id = 2 and active_run_id = 2
        session.active_run_id = 2
        session.last_run_id = 2

        # Reader 1 runs and terminates (r1 is marked done immediately)
        r1.mark_done("completed")
        session._reader_loop(r1)
        self.assertEqual(session.last_run_id, 2, "last_run_id must remain 2 after reader 1 terminates!")

    def test_pending_stdin_cannot_cross_run_boundary(self):
        """P1: Pending uncommitted stdin from run 1 must not be sent to run 2."""
        session, _, mock_channel = self._create_mock_session()
        mock_channel.send = MagicMock()
        mock_channel.closed = False

        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r1.log")
        )
        session.active_run_id = 1
        # Send buffered input with press_enter=False
        res = session.send_signal("stdin", text="STALE", press_enter=False)
        self.assertTrue(res["success"])

        # Run 1 finishes and Run 2 starts
        r1.mark_done("completed")
        r2 = session.runs[2] = RunState(
            run_id=2, session_id=session.id, command="cmd2", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r2.log")
        )
        session.active_run_id = 2

        # Send fresh input with press_enter=True
        session.send_signal("stdin", text="fresh", press_enter=True)
        # Exactly one payload, and it is the fresh one - the stale buffer never crosses runs.
        mock_channel.send.assert_called_once_with(b"fresh\n")

    def test_queued_worker_after_shutdown_does_not_connect_or_recreate_nodes(self):
        """P1: after close_all() a queued worker must not reconnect, recreate nodes or take work."""
        from src.manager import MultiServerManager
        cfg = MagicMock()
        cfg.alias = "srv1"
        cfg.max_sessions = 10
        mgr = MultiServerManager(registry=MagicMock(), cache_dirs=self.cache_dirs, project_tag="p")
        mgr.registry.get.return_value = cfg
        node = mgr.get_or_create_node(cfg)
        self.assertIsNotNone(node)

        mgr.close_all()

        # 1. A worker resolving its node after shutdown gets nothing (no reconnect, no new node)
        self.assertIsNone(mgr.get_or_create_node(cfg), "get_or_create_node after close_all must return None!")
        self.assertEqual(len(mgr.nodes), 0)

        # 2. A worker holding a node handle from before shutdown is rejected without touching SSH
        with patch("src.manager.SSHSession") as session_cls:
            res = node.open_session(name="queued_work")
        self.assertFalse(res["success"])
        self.assertIn("closed", res["error"])
        session_cls.assert_not_called()

    def test_read_line_based_unread_paging_and_has_more(self):
        """Line-based unread pagination: default read returns next lines and tracks has_more count."""
        session, _, _ = self._create_mock_session()
        # 500 lines
        lines = [f"line_{i:03d}" for i in range(500)]
        full_text = "\n".join(lines) + "\n"

        session.append_scrollback(full_text)
        # Session canvas now has 500 lines.
        # Page 1: read default (limit=200)
        p1 = session.read_canvas(limit=200)
        p1_lines = p1["output"].splitlines()
        self.assertEqual(len(p1_lines), 200)
        self.assertEqual(p1_lines[0], "line_000")
        self.assertEqual(p1_lines[-1], "line_199")
        self.assertTrue(p1["has_more"], "300 lines are still unread")

        # Page 2: read next 200 lines
        p2 = session.read_canvas(limit=200)
        p2_lines = p2["output"].splitlines()
        self.assertEqual(len(p2_lines), 200)
        self.assertEqual(p2_lines[0], "line_200")
        self.assertEqual(p2_lines[-1], "line_399")
        self.assertTrue(p2["has_more"], "100 lines are still unread")

        # Page 3: read remaining 100 lines
        p3 = session.read_canvas(limit=200)
        p3_lines = p3["output"].splitlines()
        self.assertEqual(len(p3_lines), 100)
        self.assertEqual(p3_lines[0], "line_400")
        self.assertEqual(p3_lines[-1], "line_499")
        self.assertFalse(p3["has_more"], "the canvas is fully read")

        # Page 4: subsequent read is empty, has_more is false
        p4 = session.read_canvas(limit=200)
        self.assertEqual(p4["output"], "")
        self.assertFalse(p4["has_more"])

        # Reconstructed text exactly equals original!
        reconstructed = p1["output"] + p2["output"] + p3["output"]
        self.assertEqual(reconstructed, full_text)

    def test_virtual_lines_chunking_1024_chars_preserves_original_stream(self):
        """Virtual lines: lines > 1024 chars without \\n are counted as virtual lines without buffer mutation."""
        session, _, _ = self._create_mock_session()
        raw_stream = "A" * 3000
        session.append_scrollback(raw_stream)

        # 3000 chars without \n = 2 full virtual lines of 1024 + 1 partial line of 952 = 3 lines total.
        # Read limit=2 virtual lines -> 2048 chars, more stays unread
        p1 = session.read_canvas(limit=2)
        self.assertEqual(len(p1["output"]), 2048)
        self.assertEqual(p1["output"], "A" * 2048)
        self.assertTrue(p1["has_more"])

        # Read next -> remaining 952 chars, nothing left
        p2 = session.read_canvas(limit=2)
        self.assertEqual(len(p2["output"]), 952)
        self.assertEqual(p2["output"], "A" * 952)
        self.assertFalse(p2["has_more"])

        # Exact lossless reconstruction without any injected newlines!
        self.assertEqual(p1["output"] + p2["output"], raw_stream)

    def test_read_tail_advances_cursor_to_end(self):
        """tail parameter reads last N lines and moves unread cursor to end."""
        session, _, _ = self._create_mock_session()
        lines = [f"line_{i:03d}" for i in range(100)]
        session.append_scrollback("\n".join(lines) + "\n")

        tail_res = session.read_canvas(tail=20)
        tail_lines = tail_res["output"].splitlines()
        self.assertEqual(len(tail_lines), 20)
        self.assertEqual(tail_lines[0], "line_080")
        self.assertEqual(tail_lines[-1], "line_099")
        self.assertFalse(tail_res["has_more"])

        # Cursor is now at the end: next default read returns empty
        next_res = session.read_canvas()
        self.assertEqual(next_res["output"], "")
        self.assertFalse(next_res["has_more"])

    def test_read_negative_offset_peeks_history_without_moving_cursor(self):
        """Negative offset peeks N lines back from cursor without moving the unread cursor."""
        session, _, _ = self._create_mock_session()
        lines = [f"line_{i:03d}" for i in range(100)]
        session.append_scrollback("\n".join(lines) + "\n")

        # Read all 100 lines so cursor reaches end
        all_read = session.read_canvas(limit=100)
        self.assertFalse(all_read["has_more"])

        # Peek 30 lines back from cursor, take 10 lines
        peek = session.read_canvas(offset=-30, limit=10)
        peek_lines = peek["output"].splitlines()
        self.assertEqual(len(peek_lines), 10)
        self.assertEqual(peek_lines[0], "line_070")
        self.assertEqual(peek_lines[-1], "line_079")

        # Unread cursor did NOT move: normal read still returns empty
        fresh = session.read_canvas()
        self.assertEqual(fresh["output"], "")
        self.assertFalse(fresh["has_more"])

    def test_read_offset_is_peek_and_never_advances_cursor(self):
        """Any offset (offset=0, positive or negative) is a non-consuming peek: it inspects history without moving the unread cursor."""
        session, _, _ = self._create_mock_session()
        lines = [f"line_{i:03d}" for i in range(100)]
        session.append_scrollback("\n".join(lines) + "\n")

        # 1. Read the first 50 lines: unread cursor advances to line 50, leaving 50 unread lines.
        first = session.read_canvas(limit=50)
        self.assertEqual(first["output"].splitlines()[:3], ["line_000", "line_001", "line_002"])
        self.assertEqual(first["has_more"], 50)

        # 2. Peek beginning (offset=0): inspect first 5 lines from start of history.
        # MUST NOT move the cursor: unread count stays 50!
        peek_start = session.read_canvas(offset=0, limit=5)
        self.assertEqual(peek_start["output"].splitlines(), ["line_000", "line_001", "line_002", "line_003", "line_004"])
        self.assertEqual(peek_start["has_more"], 50, "peek from start must not consume or reset the unread backlog")

        # 3. Peek arbitrary line (offset=20): inspect 5 lines from line 20.
        # MUST NOT move the cursor: unread count stays 50!
        peek_mid = session.read_canvas(offset=20, limit=5)
        self.assertEqual(peek_mid["output"].splitlines(), ["line_020", "line_021", "line_022", "line_023", "line_024"])
        self.assertEqual(peek_mid["has_more"], 50, "peek from line 20 must not consume unread lines")

        # 4. Peek negative (offset=-5): 5 lines above cursor (lines 45..49).
        peek_neg = session.read_canvas(offset=-5, limit=5)
        self.assertEqual(peek_neg["output"].splitlines(), ["line_045", "line_046", "line_047", "line_048", "line_049"])
        self.assertEqual(peek_neg["has_more"], 50, "negative peek must not consume unread lines")

        # 5. Normal unread read resumes EXACTLY from line 50!
        nxt = session.read_canvas(limit=5)
        self.assertEqual(nxt["output"].splitlines(), ["line_050", "line_051", "line_052", "line_053", "line_054"])
        self.assertEqual(nxt["has_more"], 45, "paging continues from line 50 where the cursor was left")

    def test_stream_cleaner_keeps_streaming_after_lone_escape(self):
        """D1: a stray ESC must not mute the tab stream for the rest of the session."""
        cleaner = StreamCleaner()
        self.assertEqual(cleaner.feed("BEFORE\x1b"), "BEFORE")
        # ESC c (RIS) is a generic two-byte sequence: the pending ESC resolves with
        # the next character and the rest of the stream keeps flowing.
        self.assertEqual(cleaner.feed("cTAIL-ONE\nMORE-TAIL\n"), "TAIL-ONE\nMORE-TAIL\n")

        # A string sequence (ESC X payload) is held while it may still be completed,
        # but never without bound: past the cap it is flushed instead of swallowing
        # the rest of the session forever.
        stuck = StreamCleaner()
        self.assertEqual(stuck.feed("\x1bXpayload"), "")
        self.assertEqual(stuck.feed("P" * 4096), "")
        self.assertEqual(stuck.feed("AFTER-CAP\n"), "AFTER-CAP\n", "A held escape must not mute the stream forever!")

    def test_stream_cleaner_joins_escapes_split_across_chunks(self):
        """D1/D3: CSI, OSC and DCS sequences split across feeds are still stripped."""
        csi = StreamCleaner()
        self.assertEqual(csi.feed("x\x1b[3"), "x")
        self.assertEqual(csi.feed("2mY\x1b[0m"), "Y")

        osc = StreamCleaner()
        self.assertEqual(osc.feed("\x1b]0;my-title"), "")
        self.assertEqual(osc.feed("\x07hello\n"), "hello\n")

        dcs = StreamCleaner()
        self.assertEqual(dcs.feed("\x1bPsome payload"), "")
        self.assertEqual(dcs.feed("\x1b\\tail"), "tail")

    def test_stream_cleaner_finalize_flushes_cr_and_drops_partial_escape(self):
        """F7: finalize() turns a held CR into a newline and drops an unfinished escape."""
        cr = StreamCleaner()
        self.assertEqual(cr.feed("abc\r"), "abc")
        self.assertEqual(cr.finalize(), "\n")
        self.assertEqual(cr.finalize(), "", "finalize() must be idempotent")

        partial = StreamCleaner()
        self.assertEqual(partial.feed("more\x1b["), "more")
        self.assertEqual(partial.finalize(), "", "An unfinished escape is dropped, not emitted")

    def test_read_canvas_max_chars_caps_the_window(self):
        """R4: a line-based canvas read must respect max_chars, not dump megabytes."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("".join(("B" * 400) + "\n" for _ in range(20)))

        res = session.read_canvas(limit=20, max_chars=100)
        self.assertEqual(len(res["output"]), 100)
        self.assertTrue(res["has_more"], "unread text must still be reported as has_more")
        self.assertIn("truncated", res.get("hint", ""), "a cut window must say so")

    def test_read_canvas_peek_reports_unread_lines_not_window_tail(self):
        """R1: has_more of a peek is what is still unread, not what follows the window."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("".join("line-%03d\n" % i for i in range(100)))

        first = session.read_canvas(limit=10)
        self.assertTrue(first["has_more"])

        peek = session.read_canvas(offset=-10, limit=5)
        self.assertEqual(peek["output"].count("\n"), 5)
        self.assertTrue(peek["has_more"], "A peek must report unread output, not what follows the window!")

    def test_read_canvas_tail_reports_dropped_data(self):
        """R2: jumping to the tail with unread output must admit the loss."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("".join("line-%03d\n" % i for i in range(50)))
        session.read_canvas(limit=10)

        res = session.read_canvas(tail=5)
        self.assertEqual(res["output"].count("\n"), 5)
        self.assertTrue(res.get("dropped_data"), "Skipped unread output must be reported!")
        self.assertFalse(res["has_more"], "tail= jumped to the end of the buffer")

    def test_scrollback_cursor_is_absolute_after_eviction(self):
        """D2: the unread cursor is an absolute stream offset, never a relative index."""
        session, _, _ = self._create_mock_session()
        session.scrollback.max_chars = 1000
        session.append_scrollback("A" * 1000)
        session.append_scrollback("B" * 500)
        self.assertEqual(session.scrollback.base_offset, 500, "Setup: 500 chars must be evicted")

        # The cursor is clamped to the live buffer start, so the window opens at the
        # 500-char mark of the stream (buffer start), not at the buffer's zero index.
        page = session.read_canvas(limit=1, max_chars=100)
        self.assertEqual(page["output"], "A" * 100)
        self.assertEqual(session.scrollback_cursor, 600, "Cursor must be absolute (base_offset + window end)!")

        nxt = session.read_canvas(limit=0, max_chars=50)
        self.assertEqual(nxt["output"], "A" * 50, "The unread read must continue from the canvas cursor, not from the buffer start!")

    def test_run_history_is_backfilled_into_scrollback_only_once(self):
        """D7: a cleared canvas must not silently refill from run buffers again."""
        session, _, _ = self._create_mock_session()
        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="history", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "hist.log")
        )
        r1.append_output("RUN-1-HISTORY")
        r1.mark_done("completed", completion_method="prompt_detected")
        session.last_run_id = 1

        first = session.read_canvas(limit=10)
        self.assertIn("RUN-1-HISTORY", first["output"])

        session.scrollback.clear()
        session.scrollback_cursor = 0
        second = session.read_canvas(limit=10)
        self.assertEqual(second["output"], "", "Run buffers must be backfilled exactly once (D7)!")

    def test_finalize_scrollback_flushes_held_tail_once(self):
        """D8/F10: the tab-stream cleaner is finalized when the session ends."""
        session, _, _ = self._create_mock_session()
        session.append_scrollback("abc\r")
        self.assertEqual(session.read_canvas(offset=0, limit=10)["output"], "abc")

        session._finalize_scrollback()
        self.assertEqual(session.read_canvas(offset=0, limit=10)["output"], "abc\n")

        session._finalize_scrollback()
        self.assertEqual(session.read_canvas(offset=0, limit=10)["output"], "abc\n", "finalize must be idempotent!")

    def test_pending_stdin_limit_refuses_unbounded_growth(self):
        """F5: buffered stdin without press_enter must not grow forever."""
        session, _, _ = self._create_mock_session()
        session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cat", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "stdin.log")
        )
        session.active_run_id = 1

        res = session.send_signal("stdin", "x" * 70000, press_enter=False)
        self.assertFalse(res["success"])
        self.assertIn("65536", res["error"])
        self.assertEqual(session._pending_stdin, "", "A refused buffer must be dropped, not kept")

    def test_cancellation_identity_race_with_handoff_lock(self):
        """§5.1: cancel_run_for_request must not interrupt newer run if old run finished before lock."""
        session, _, mock_channel = self._create_mock_session()
        r1 = session.runs[1] = RunState(
            run_id=1, session_id=session.id, command="cmd1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r1.log"),
            req_id="req_1"
        )
        session.inflight_by_req["req_1"] = 1
        session.active_run_id = 1

        r2 = session.runs[2] = RunState(
            run_id=2, session_id=session.id, command="cmd2", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r2.log"),
            req_id="req_2"
        )
        mock_exec_channel = MagicMock()
        mock_exec_channel.closed = False
        r2.exec_channel = mock_exec_channel

        # Simulate race: right after cancel_run_for_request checks req_1 / run 1,
        # but before send_signal delivers the signal, run 1 finishes and run 2 becomes active.
        orig_ensure_alive = session.ensure_alive
        def race_trigger(*args, **kwargs):
            r1.mark_done("completed")
            session.active_run_id = 2
            return orig_ensure_alive(*args, **kwargs)

        with patch.object(session, "ensure_alive", side_effect=race_trigger):
            cancel_res = session.cancel_run_for_request("req_1")

        self.assertFalse(r2.done_event.is_set(), "Run 2 must NOT be marked done by late cancellation of req_1!")
        self.assertFalse(mock_exec_channel.close.called, "Run 2 exec channel must NOT be closed!")

    def test_interactive_prompt_abort_invalidates_pty(self):
        """§5.7: Aborting on interactive prompt (Password:) must invalidate the PTY."""
        session, _, mock_channel = self._create_mock_session()
        session.in_shell = True
        run = RunState(
            run_id=10, session_id=session.id, command="sudo su", mode="sync",
            started_at=time.time() - 2.0, wait_timeout=5.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "r10.log")
        )
        run.completion_hint = "either"
        run.quiet_complete_timeout = 0.1
        run.append_output("Password: ")
        run.last_data_at = time.time() - 1.0  # quiet after output
        session.runs[10] = run
        session.active_run_id = 10

        # Run reader loop step for interactive check
        # Mock channel.recv_ready as False
        mock_channel.recv_ready.return_value = False

        # The reader loop must finish on its own: no data + quiet timeout => interactive abort.
        # A bounded join proves it terminates; no time.sleep side effect is needed to break out.
        reader = threading.Thread(target=session._reader_loop, args=(run,), daemon=True)
        reader.start()
        reader.join(timeout=5.0)
        self.assertFalse(reader.is_alive(), "reader loop must terminate after the interactive abort")

        self.assertEqual(run.status, "failed")
        self.assertEqual(run.finish_reason, "interactive_prompt_detected")
        self.assertTrue(session._pty_invalidated, "PTY must be invalidated when interactive prompt is aborted!")
        self.assertFalse(session.is_alive())
        self.assertEqual(session.get_mode(), "unknown")

    def test_append_output_updates_accounting_for_partial_escape_or_cr(self):
        """F3: append_output must update total_received_chars and clear quiet_event even if cleaned is empty."""
        run = RunState(
            run_id=1, session_id=1, command="cmd", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "rf3.log")
        )
        run.quiet_event.set()
        run.last_data_at = time.time() - 5.0
        stale_timestamp = run.last_data_at

        # Feed incomplete escape sequence "\x1b["
        run.append_output("\x1b[")
        self.assertEqual(run.total_received_chars, 2, "total_received_chars must increase by raw chunk length!")
        self.assertFalse(run.quiet_event.is_set(), "quiet_event must be cleared!")
        self.assertGreater(
            run.last_data_at, stale_timestamp,
            "last_data_at must be refreshed even when StreamCleaner withholds the partial escape!",
        )
        self.assertEqual(len(run._buf), 0, "the incomplete escape must not reach the visible buffer yet")

    def test_session_get_mode_returns_unknown_when_pty_invalidated(self):
        """F6: get_mode() must return 'unknown' when PTY is invalidated instead of claiming 'ndm_cli'."""
        session, _, _ = self._create_mock_session()
        session.in_shell = False
        self.assertEqual(session.get_mode(), "ndm_cli")

        session.in_shell = True
        self.assertEqual(session.get_mode(), "linux_shell")

        session._invalidate_pty("test invalidation")
        self.assertEqual(session.get_mode(), "unknown")

class TestScrollbackEvictionSemantics(unittest.TestCase):
    """D5/D6 and cover gaps from review #2: eviction must be reported, not hidden."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dirs = make_cache_dirs(self.test_dir)
        config.PROJECT_ROOT = self.test_dir
        config.PROJECT_TAG = "test_project"
        config.CACHE_DIRS = self.cache_dirs
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        set_buffer_limit_checkers(lambda size: True, lambda: 0)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run_state(self, max_buffer_chars=100000, log_name="evict.log"):
        return RunState(
            run_id=1, session_id=1, command="cmd", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=max_buffer_chars,
            run_log_path=os.path.join(self.cache_dirs["runs_dir"], log_name)
        )

    def _mock_session(self):
        mock_client = MagicMock()
        mock_channel = MagicMock()
        mock_client.invoke_shell.return_value = mock_channel
        mock_channel.recv_ready.return_value = False
        session = SSHSession(session_id=1, name="evict_session", cache_dirs=self.cache_dirs, project_tag="test_project")
        session.client = mock_client
        session.channel = mock_channel
        session.in_shell = True
        session.ensure_alive = MagicMock(return_value=None)
        session.check_health = MagicMock(return_value=True)
        return session

    def test_discarded_unread_output_is_reported_as_dropped(self):
        """D5: evicting a run with unread output must admit the loss once.

        The run buffer is only a staging area for the tab canvas. When it is freed
        before its text ever reached the canvas, the read has to say that unread
        output was lost instead of quietly starting later."""
        run = self._run_state()
        run.append_output("STILL-UNREAD")
        run.mark_done("completed", completion_method="prompt_detected")
        with run.lock:
            run.discard_all_output()

        session = self._mock_session()
        session.runs[1] = run
        res = session.read_canvas(limit=0, max_chars=100, wait_timeout=0.0)
        self.assertTrue(res["dropped_data"], "Unread output dropped by eviction must be reported, not hidden!")
        self.assertEqual(res["output"], "", "the discarded bytes are gone - no phantom text")
        # ... and only once: the following read is clean.
        self.assertFalse(
            session.read_canvas(limit=0, max_chars=100, wait_timeout=0.0).get("dropped_data"),
            "the loss must be reported exactly once",
        )

    def test_dropped_data_is_reported_once(self):
        """D6: the sticky loss flag must not survive a later valid read."""
        run = self._run_state(max_buffer_chars=1000, log_name="d6.log")
        run.append_output("A" * 1000)
        run.append_output("B" * 500)
        self.assertEqual(run.buffer_base_offset, 500)
        self.assertEqual(run.buffer_len, 1000)

        session = self._mock_session()
        session.runs[1] = run
        first = session.read_canvas(limit=0, max_chars=10, wait_timeout=0.0)
        self.assertTrue(first["dropped_data"], "Reading below the retained base must report the eviction!")
        self.assertEqual(first["output"], "A" * 10)
        second = session.read_canvas(limit=0, max_chars=10, wait_timeout=0.0)
        self.assertFalse(second.get("dropped_data"), "A valid read must not repeat a stale drop flag!")
        self.assertEqual(second["output"], "A" * 10)

    def test_read_canvas_reports_evicted_unread_data(self):
        """A canvas window that starts below the retained base must admit the loss."""
        session = self._mock_session()
        session.append_scrollback("ABCDEFGHIJ")
        dropped = session.scrollback.drop(6)
        self.assertEqual(dropped, 6)
        self.assertEqual(session.scrollback.base_offset, 6)
        session.scrollback_cursor = 0

        res = session.read_canvas(limit=0, max_chars=100, wait_timeout=0.0)
        self.assertTrue(res["success"])
        self.assertTrue(res["dropped_data"], "Evicted scrollback must be reported as dropped_data!")
        self.assertEqual(res["output"], "GHIJ")


class TestReadStateContract(unittest.TestCase):
    """The read answer reports state, not bookkeeping (contract m01215).

    A read/run answer carries exactly two state fields: has_more - the NUMBER of
    unread LINES still left in the tab stream (0 = all caught up) - and still_running
    (the command is still in flight). Positional bookkeeping (next_offset,
    base_offset, total_chars, total_lines, next_line, limited, next_cursor) must
    never reach the agent surface: it is plumbing the caller did not ask for.
    """

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dirs = make_cache_dirs(self.test_dir)
        config.PROJECT_ROOT = self.test_dir
        config.PROJECT_TAG = "test_project"
        config.CACHE_DIRS = self.cache_dirs
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        set_buffer_limit_checkers(lambda size: True, lambda: 0)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _mock_session(self):
        mock_client = MagicMock()
        mock_channel = MagicMock()
        mock_client.invoke_shell.return_value = mock_channel
        mock_channel.recv_ready.return_value = False
        session = SSHSession(session_id=1, name="state_session", cache_dirs=self.cache_dirs, project_tag="test_project")
        session.client = mock_client
        session.channel = mock_channel
        session.in_shell = True
        session.ensure_alive = MagicMock(return_value=None)
        session.check_health = MagicMock(return_value=True)
        return session

    def _new_run(self, session, run_id, text="", log_name="state.log"):
        run = RunState(
            run_id=run_id, session_id=session.id, command="cmd", mode="sync",
            started_at=time.time(), wait_timeout=30.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], log_name)
        )
        run.output_buffer = text
        session.runs[run_id] = run
        session.active_run_id = run_id
        return run

    def _assert_state_only(self, res):
        expected_keys = {
            "success", "session_id", "numeric_session_id", "server",
            "status", "output", "has_more", "still_running", "in_shell", "mode"
        }
        self.assertEqual(set(res.keys()) - {"dropped_data", "exit_status", "hint", "recv_paused", "pause_reason", "run_id"}, expected_keys)
        unread = res["has_more"]
        self.assertIsInstance(unread, int, "has_more must be an int of unread LINES")
        self.assertNotIsInstance(unread, bool, "has_more is a LINE COUNT, not a flag (m01215)")
        self.assertGreaterEqual(unread, 0, "has_more counts unread lines and never goes negative")
        self.assertIsInstance(res["still_running"], bool, "still_running must be a plain boolean")

    def test_read_canvas_answer_is_state_only(self):
        session = self._mock_session()
        session.append_scrollback("".join("line-%03d\n" % i for i in range(10)))

        res = session.read_canvas(limit=5)
        self._assert_state_only(res)
        self.assertEqual(res["has_more"], 5, "5 of 10 lines stay unread")
        self.assertFalse(res["still_running"], "no command is running")

        rest = session.read_canvas(limit=50)
        self._assert_state_only(rest)
        self.assertEqual(rest["has_more"], 0, "nothing is left unread")

    def test_read_canvas_has_more_runs_out_when_everything_is_read(self):
        session = self._mock_session()
        text = "".join("row-%03d\n" % i for i in range(100))
        session.append_scrollback(text)

        collected = []
        counts = []
        for _ in range(20):
            res = session.read_canvas(limit=30)
            self._assert_state_only(res)
            collected.append(res["output"])
            counts.append(res["has_more"])
            if not res["has_more"]:
                break
        else:
            self.fail("has_more never reached 0 - the loop would read the canvas forever")
        self.assertEqual("".join(collected), text)
        self.assertEqual(counts, sorted(counts, reverse=True), "the unread count must only go down")
        self.assertEqual(counts[-1], 0, "the last read leaves nothing unread")

    def test_read_canvas_peek_does_not_consume_unread(self):
        session = self._mock_session()
        text = "".join("row-%03d\n" % i for i in range(20))
        session.append_scrollback(text)

        first = session.read_canvas(limit=3)
        self.assertEqual(first["has_more"], 17, "three of twenty lines were consumed")

        # A NEGATIVE offset is the peek: it re-reads lines above the cursor and
        # leaves the unread backlog untouched (offset=0 would be a rewind).
        peek = session.read_canvas(offset=-3, limit=2)
        self._assert_state_only(peek)
        self.assertEqual(peek["output"].splitlines(), ["row-000", "row-001"])
        self.assertEqual(peek["has_more"], 17, "a peek must not consume the unread backlog")

        nxt = session.read_canvas(limit=50)
        self.assertEqual(nxt["output"], "".join("row-%03d\n" % i for i in range(3, 20)),
                         "the unread read still starts at the cursor")

    def test_read_canvas_tail_leaves_nothing_unread(self):
        session = self._mock_session()
        session.append_scrollback("".join("row-%03d\n" % i for i in range(50)))

        res = session.read_canvas(tail=5)
        self._assert_state_only(res)
        self.assertEqual(res["output"].count("\n"), 5)
        self.assertEqual(res["has_more"], 0, "the cursor jumped to the end of the buffer")
        self.assertTrue(res.get("dropped_data"), "skipped unread output must be admitted")

    def test_read_answer_is_state_only_and_tracks_completion(self):
        session = self._mock_session()
        run = self._new_run(session, 11, text="one\ntwo\n")

        first = session.read_canvas(limit=100, max_chars=4, wait_timeout=0)
        self._assert_state_only(first)
        self.assertEqual(first["output"], "one\n")
        self.assertEqual(first["has_more"], 1, "the second line is still unread")
        self.assertTrue(first["still_running"], "the command has not finished")

        rest = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0)
        self._assert_state_only(rest)
        self.assertEqual(rest["output"], "two\n")
        self.assertEqual(rest["has_more"], 0, "everything buffered was handed back")
        self.assertTrue(rest["still_running"])

        run.exit_status = 0
        run.mark_done("completed", completion_method="prompt_detected")
        final = session.read_canvas(limit=100, max_chars=1000, wait_timeout=0)
        self._assert_state_only(final)
        self.assertFalse(final["still_running"], "a finished command is not running")
        self.assertEqual(final["status"], "completed")

    def test_run_tool_answer_is_state_only(self):
        """The run tool answers with the same two flags - no paging bookkeeping."""
        session = self._mock_session()

        def fill(run):
            run.append_output("first line\nsecond line\n")

        session._start_reader_thread = fill
        res = session.run_command(
            command="seq 1 2", mode="sync", shell=True,
            wait_timeout=0.05, startup_wait=0.05, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5,
            max_chars=6,
        )
        self._assert_state_only(res)
        self.assertEqual(res["output"], "first ")
        self.assertEqual(res["has_more"], 2, "the window was cut - two lines remain unread")
        self.assertTrue(res["still_running"], "the run was never completed")

    def test_read_page_and_peek_answers_are_state_only(self):
        session = self._mock_session()
        session.append_scrollback("first\nsecond\n")

        page = session.read_canvas(limit=1, max_chars=1000)
        self._assert_state_only(page)
        self.assertEqual(page["output"], "first\n")
        self.assertEqual(page["has_more"], 1, "one unread line is left")

        peek = session.read_canvas(offset=-1, limit=1, max_chars=1000)
        self._assert_state_only(peek)
        self.assertEqual(peek["output"], "first\n", "the peek re-reads above the cursor")
        self.assertEqual(peek["has_more"], 1, "a peek consumes nothing")

        full = session.read_canvas(limit=100, max_chars=1000)
        self._assert_state_only(full)
        self.assertEqual(full["output"], "second\n")
        self.assertEqual(full["has_more"], 0)


if __name__ == "__main__":
    unittest.main()
