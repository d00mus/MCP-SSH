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
from src.utils import make_cache_dirs, json_line, find_prompt, parse_exit_marker, cleanup_old_logs

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

    def test_state_lost_warning(self):
        session, _, _ = self._create_mock_session()
        session.state_lost = True

        res = self._run_cmd(session, "echo hello", background=False)
        self.assertFalse(res["success"])
        self.assertIn("Connection for session", res["error"])
        self.assertIn("was lost and auto-recovered", res["error"])
        # Flag should be reset
        self.assertFalse(session.state_lost)

    def test_run_state_read_slice_cleans_output(self):
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
        run.append_output("line 1\r\n\x1b[31mline 2\x1b[0m\r\n")
        res = run.read_slice(offset=0, max_lines=10, max_chars=100)
        self.assertEqual(res["output"], "line 1\nline 2")
        self.assertEqual(res["next_offset"], len("line 1\r\n\x1b[31mline 2\x1b[0m\r\n"))

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

    def test_restore_run_from_disk_huge_log_bounded(self):
        """Verify memory bounded restoration from huge log files (> MAX_BUFFER_CHARS)."""
        from src.config import MAX_BUFFER_CHARS
        session, _, _ = self._create_mock_session()

        run_id = 999
        stamp = time.strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(self.cache_dirs["runs_dir"], f"test_project__default__s1__r{run_id}__{stamp}.log")

        chunk_size = 100000
        num_chunks = 25  # 2,500,000 chars total, MAX_BUFFER_CHARS is 2,000,000
        total_chars = chunk_size * num_chunks

        with open(log_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"ts": "2026-09-20T00:00:00Z", "dir": "SYS", "event": "run_created", "command": "cat big"}) + "\n")
            for i in range(num_chunks):
                f.write(json.dumps({"ts": "2026-09-20T00:00:00Z", "dir": "OUT", "chunk": "x" * chunk_size}) + "\n")
            f.write(json.dumps({"ts": "2026-09-20T00:00:01Z", "dir": "SYS", "event": "run_done", "status": "completed", "reason": "ok"}) + "\n")

        run = session._restore_run_from_disk(run_id)
        self.assertIsNotNone(run)
        self.assertEqual(run.status, "completed")
        self.assertEqual(run.total_received_chars, total_chars)
        self.assertLessEqual(len(run.output_buffer), MAX_BUFFER_CHARS)
        self.assertEqual(len(run.output_buffer), MAX_BUFFER_CHARS)
        self.assertEqual(run.buffer_base_offset, total_chars - MAX_BUFFER_CHARS)

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

    def test_clean_output_preserves_parentheses_lines(self):
        """Verify PROMPT_ONLY_LINE does not strip valid text lines enclosed in parentheses."""
        from src.utils import clean_output
        text = "header\n(1)\n(DEBUG: initializing)\n(config)>\n#"
        cleaned = clean_output(text)
        self.assertIn("(1)", cleaned)
        self.assertIn("(DEBUG: initializing)", cleaned)
        self.assertNotIn("(config)>", cleaned)

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

    def test_read_run_reports_dropped_data(self):
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=5, session_id=1, command="yes", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "drop.log"),
        )
        run.output_buffer = "kept"
        run.buffer_base_offset = 20
        run.mark_done("completed", completion_method="exit_status")
        run.exit_status = 0
        session.runs[5] = run
        result = session.read_run(5, offset=0, max_lines=10, max_chars=100)
        self.assertTrue(result["dropped_data"])

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

    def test_read_run_reports_recv_paused(self):
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=9, session_id=1, command="yes", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "paused.log"),
        )
        run.set_recv_paused(True, "memory_limit")
        session.runs[9] = run
        result = session.read_run(9, 0, 50, 1000)
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

    def test_either_silence_returns_running_and_stays_busy(self):
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
            self.assertEqual(result["status"], "running")
            self.assertTrue(result["still_running"])
            run = session.runs[result["run_id"]]
            self.assertFalse(run.quiet_event.is_set())
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

    def test_read_run_retains_buffer_for_rewind(self):
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=3, session_id=1, command="yes", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "slice.log"),
        )
        run.output_buffer = ("A" * 50) + ("B" * 150)
        session.runs[3] = run
        result = session.read_run(3, 0, 50, 100)
        self.assertEqual(result["output"], ("A" * 50) + ("B" * 50))
        # Buffer is NOT discarded on read: base offset remains 0 so client can re-read or rewind
        self.assertEqual(run.buffer_base_offset, 0)
        self.assertEqual(run.output_buffer, ("A" * 50) + ("B" * 150))
        # Re-reading from offset 0 still works!
        reread = session.read_run(3, 0, 50, 100)
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

    def test_clean_output_removes_exit_marker(self):
        from src.utils import clean_output
        text = "Hello world\n__MCP_EC_0123456789abcdef_0\n"
        cleaned = clean_output(text)
        self.assertEqual(cleaned, "Hello world")
        self.assertNotIn("__MCP_EC_", cleaned)

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

    def test_restore_run_from_disk_evicts_old_runs(self):
        """Verify that restoring multiple runs from disk evicts older runs to respect the 10-run limit."""
        session, _, _ = self._create_mock_session()
        stamp = "20260922_120000"
        
        # Create 15 run logs on disk
        for rid in range(1, 16):
            log_filename = f"{session.project_tag}__{session.server_alias}__s{session.id}__r{rid}__{stamp}.log"
            log_path = os.path.join(self.cache_dirs["runs_dir"], log_filename)
            events = [
                {"ts": "2026-09-22T12:00:00.000", "dir": "SYS", "event": "run_created", "command": f"echo {rid}"},
                {"ts": "2026-09-22T12:00:01.000", "dir": "OUT", "chunk": f"output_{rid}\n"},
                {"ts": "2026-09-22T12:00:02.000", "dir": "SYS", "event": "run_done", "status": "completed", "exit_status": 0}
            ]
            for ev in events:
                json_line(log_path, ev)

        # Restore all 15 runs one by one
        for rid in range(1, 16):
            res = session.read_run(run_id=rid, offset=None, max_lines=10, max_chars=100)
            self.assertTrue(res["success"])
            self.assertEqual(res["run_id"], rid)

        # In-memory runs must be bounded to at most 10
        with session.lock:
            self.assertLessEqual(len(session.runs), 10)
            self.assertNotIn(1, session.runs)
            self.assertNotIn(2, session.runs)
            self.assertIn(15, session.runs)

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
        """Verify read_run with wait_timeout waits for running command done_event."""
        session, _, _ = self._create_mock_session()
        run = RunState(
            run_id=5, session_id=session.id, command="sleep 0.1", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.01, hard_timeout=0.0,
            max_buffer_chars=1000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "test.log")
        )
        run.output_buffer = "hello\n"
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

        res = session.read_run(run_id=5, offset=None, max_lines=100, max_chars=1000, wait_timeout=1.0)
        t.join()

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "completed")
        self.assertFalse(res["still_running"])
        self.assertEqual(res["exit_status"], 0)

    def test_read_run_on_dead_session_returns_buffered_output(self):
        """Verify that read_run can read outputs from dead/closed sessions."""
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

        # Session dies
        session.close(permanent=True)
        self.assertTrue(session.is_dead)

        # Output must still be readable!
        res = session.read_run(run_id=1, offset=None, max_lines=100, max_chars=1000, wait_timeout=0)
        self.assertTrue(res["success"])
        self.assertEqual(res["output"].strip(), "output before death")
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["exit_status"], 0)

    def test_terminal_tab_scrollback_and_amnesia_rewind(self):
        """Verify unified tab scrollback: rewind to start (offset=0), negative offset (tail), and pagination without run_id."""
        session, _, _ = self._create_mock_session()

        # Simulate terminal activity across multiple sequential commands
        cmd1 = "$ echo first\n" + ("first line output " * 10) + "\n"
        cmd2 = "$ echo second\n" + ("second line output " * 10) + "\n"
        cmd3 = "$ echo third\n" + ("third line output " * 10) + "\n"
        session.append_scrollback(cmd1)
        session.append_scrollback(cmd2)
        session.append_scrollback(cmd3)

        # 1. Full rewind (offset=0) to solve agent context loss / amnesia
        res_rewind = session.read_run(run_id=None, offset=0, max_lines=1000, max_chars=50000)
        self.assertTrue(res_rewind["success"])
        self.assertNotIn("run_id", res_rewind)
        self.assertIn("first line output", res_rewind["output"])
        self.assertIn("second line output", res_rewind["output"])
        self.assertIn("third line output", res_rewind["output"])

        # 2. Negative offset (tail buffer)
        res_tail = session.read_run(run_id=None, offset=-50, max_lines=1000, max_chars=50000)
        self.assertTrue(res_tail["success"])
        self.assertNotIn("run_id", res_tail)
        self.assertIn("third line output", res_tail["output"])
        self.assertNotIn("first line output", res_tail["output"])

        # 3. Pagination across pages using next_offset
        page1 = session.read_run(run_id=None, offset=0, max_lines=1000, max_chars=100)
        self.assertTrue(page1["success"])
        self.assertTrue(page1["limited"])
        self.assertEqual(page1["next_offset"], 100)

        page2 = session.read_run(run_id=None, offset=page1["next_offset"], max_lines=1000, max_chars=50000)
        self.assertTrue(page2["success"])
        self.assertIn("second line output", page2["output"])
        self.assertIn("third line output", page2["output"])

if __name__ == "__main__":
    unittest.main()
