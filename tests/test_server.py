import ast
import glob
import inspect
import json
import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from src.config import ServerTargetConfig, ServersRegistry, config
from src.manager import MultiServerManager
from src.security import check_command_security
from src.server import (
    project_tool_result, handle_request, tools_list, run_dispatch,
    read_dispatch, signal_dispatch
)
from src.session import SSHSession
from src.ssh_state import RunState
from src.utils import apply_text_filters, make_cache_dirs, resolve_local_path

class TestServer(unittest.TestCase):
    def test_project_tool_result_mcp_level_errors(self):
        # Test non-object return
        res = project_tool_result("run", "not-a-dict")
        self.assertFalse(res["success"])
        self.assertEqual(res["error"], "tool returned non-object result")

        # Test success = False (MCP error)
        raw_err = {"success": False, "error": "connection timeout", "session_id": 42}
        res = project_tool_result("run", raw_err)
        self.assertFalse(res["success"])
        self.assertEqual(res["session_id"], 42)
        self.assertEqual(res["error"], "connection timeout")

    def test_project_tool_result_completed_nonzero(self):
        # Non-zero exit status should be wrapped in loud warnings
        raw = {
            "success": True,
            "status": "completed_nonzero",
            "exit_status": 127,
            "output": "bash: command not found",
            "session_id": 1,
            "run_id": 5
        }
        res = project_tool_result("run", raw)
        self.assertEqual(res["session_id"], 1)
        self.assertNotIn("run_id", res)
        self.assertEqual(res["status"], "completed_nonzero")
        self.assertIn("Command failed with exit status 127", res["error"])
        self.assertIn("[WARNING: Command execution failed", res["output"])

    def test_project_tool_result_file_read_download(self):
        # File download action
        raw = {
            "success": True,
            "action": "read",
            "mode": "download",
            "local_path": "/tmp/local.txt",
            "size": 100
        }
        res = project_tool_result("file", raw)
        self.assertIn("Downloaded to /tmp/local.txt", res["message"])
        self.assertEqual(res["size"], 100)

    def test_project_tool_result_file_list(self):
        # File list action
        raw = {
            "success": True,
            "action": "list",
            "files": [{"name": "test.txt", "size": 10, "is_dir": False}]
        }
        res = project_tool_result("file", raw)
        self.assertEqual(len(res["files"]), 1)

    def test_handle_request_initialize(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 123,
            "method": "initialize",
            "params": {}
        }
        res = handle_request(req, mock_manager)
        self.assertEqual(res["id"], 123)
        self.assertEqual(res["result"]["protocolVersion"], "2024-11-05")
        self.assertFalse(mock_manager.ensure_session.called)

    def test_handle_request_tools_list(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 456,
            "method": "tools/list",
            "params": {}
        }
        res = handle_request(req, mock_manager)
        self.assertEqual(res["id"], 456)
        self.assertIn("tools", res["result"])

    def test_handle_request_unknown_method(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 789,
            "method": "unknown_method"
        }
        res = handle_request(req, mock_manager)
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32601)

    def test_handle_request_tool_session_list(self):
        mock_manager = MagicMock()
        mock_manager.list_all_sessions.return_value = {
            "success": True,
            "sessions": [{"session_id": 1, "name": "active"}]
        }
        mock_manager.list_sessions.return_value = {
            "success": True,
            "sessions": [{"session_id": 1, "name": "active"}]
        }
        
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "session_list",
                "arguments": {"include_name": True}
            }
        }
        res = handle_request(req, mock_manager)
        text_content = res["result"]["content"][0]["text"]
        self.assertEqual(json.loads(text_content), {
            "sessions": [{"session_id": 1, "name": "active"}]
        })

    def test_run_tool_filtering_contains_and_regex(self):
        from src.manager import ResolveResult
        mock_manager = MagicMock()
        mock_node = MagicMock()
        mock_session = MagicMock()
        mock_session.id = 1
        mock_session.ensure_alive.return_value = None
        mock_session.is_busy.return_value = False
        mock_session.run_command.return_value = {
            "success": True,
            "session_id": "srv/1",
            "server": "srv",
            "run_id": 1,
            "status": "completed",
            "output": "line 1: apple\nline 2: banana\nline 3: apricot\nline 4: cherry",
            "next_offset": 50
        }
        mock_node.get_session.return_value = mock_session
        mock_manager.resolve_target.return_value = ResolveResult(node=mock_node, numeric_sid=1, is_new_requested=False, error=None)
        mock_manager.resolve_target_for_args.return_value = (mock_node, 1, False, None)

        req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "run",
                "arguments": {
                    "server": "srv",
                    "command": "cat fruits.txt"
                }
            }
        }
        res = handle_request(req, mock_manager)
        content = json.loads(res["result"]["content"][0]["text"])
        self.assertEqual(content["output"], "line 1: apple\nline 2: banana\nline 3: apricot\nline 4: cherry")
        # Direct utility filtering test
        from src.utils import apply_text_filters
        filt = apply_text_filters(content["output"], contains="ap")
        self.assertEqual(filt["output"], "line 1: apple\nline 3: apricot")
        self.assertEqual(filt["matched_lines"], 2)

    def test_parallel_request_processing(self):
        import concurrent.futures
        mock_manager = MagicMock()
        mock_manager.list_all_servers.return_value = {
            "success": True,
            "servers": [{"alias": "srv1", "host": "1.1.1.1:22", "user": "u", "status": "connected", "sessions": 1, "description": "", "read_only": False}]
        }

        def worker(req_id):
            req = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": "server_list", "arguments": {}}
            }
            return handle_request(req, mock_manager)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futures = [ex.submit(worker, i) for i in range(1, 21)]
            results = [f.result() for f in futures]

        self.assertEqual(len(results), 20)
        for i, res in enumerate(results, 1):
            self.assertEqual(res["id"], i)
            self.assertNotIn("error", res)
            self.assertIn("result", res)

    def test_process_line_parse_error(self):
        from src.main import process_line
        captured_responses = []

        def mock_writer(resp):
            captured_responses.append(resp)

        mock_manager = MagicMock()
        # Send broken JSON
        process_line("not a valid json {{{", mock_manager, write_fn=mock_writer)

        self.assertEqual(len(captured_responses), 1)
        resp = captured_responses[0]
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertIsNone(resp["id"])
        self.assertEqual(resp["error"]["code"], -32700)
        self.assertIn("Parse error", resp["error"]["message"])

    def test_server_add_invalid_alias_rejected(self):
        """Verify server_add rejects aliases with slashes or invalid characters."""
        from src.server import server_add_dispatch
        mock_manager = MagicMock()
        mock_manager.registry.get.return_value = None

        res_slash = server_add_dispatch({"alias": "bad/server", "host": "1.2.3.4", "user": "u"}, mock_manager)
        self.assertFalse(res_slash["success"])
        self.assertIn("Invalid server alias", res_slash["error"])

        res_space = server_add_dispatch({"alias": "bad server", "host": "1.2.3.4", "user": "u"}, mock_manager)
        self.assertFalse(res_space["success"])
        self.assertIn("Invalid server alias", res_space["error"])

    def test_from_dict_handles_null_port_and_max_sessions(self):
        """Verify ServerTargetConfig.from_dict gracefully defaults null port and null max_sessions."""
        from src.config import ServerTargetConfig
        data = {
            "host": "10.0.0.1",
            "port": None,
            "user": "root",
            "max_sessions": None
        }
        cfg = ServerTargetConfig.from_dict("srv", data)
        self.assertEqual(cfg.port, 22)
        self.assertEqual(cfg.max_sessions, 10)

    def test_apply_text_filters_redos_timeout(self):
        """Verify apply_text_filters terminates with error on ReDoS catastrophic backtracking."""
        from src.utils import apply_text_filters
        catastrophic_input = "a" * 26 + "!"
        evil_regex = r"^(a+)+$"

        start = time.time()
        res = apply_text_filters(catastrophic_input, regex=evil_regex)
        elapsed = time.time() - start

        self.assertFalse(res["success"])
        self.assertIn("nested quantifiers", res["error"].lower())
        self.assertLess(elapsed, 0.5)

    def test_apply_text_filters_max_length_exceeded(self):
        """Verify apply_text_filters rejects regex longer than 500 characters."""
        from src.utils import apply_text_filters
        huge_regex = "a" * 501
        res = apply_text_filters("hello", regex=huge_regex)
        self.assertFalse(res["success"])
        self.assertIn("exceeds maximum allowed length", res["error"])

    def test_project_tool_result_pagination_and_exit_status(self):
        """Verify project_tool_result forwards line pagination and exit_status in lean mode."""
        from src.server import project_tool_result
        read_payload = {
            "success": True,
            "action": "read",
            "content": "line 10\nline 11",
            "line_start": 10,
            "line_end": 11,
            "total_lines": 100,
            "truncated": True,
            "exit_status": 0
        }
        proj = project_tool_result("file", read_payload)
        self.assertEqual(proj["line_start"], 10)
        self.assertEqual(proj["line_end"], 11)
        self.assertEqual(proj["total_lines"], 100)
        self.assertTrue(proj["truncated"])
        self.assertEqual(proj["exit_status"], 0)

    def test_server_add_persists_when_servers_is_list(self):
        """Verify server_add handles servers.json formatted as a list or with servers list."""
        from src.server import server_add_dispatch
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "servers.json")
            # Write list-format servers.json
            initial_data = [
                {"alias": "srv1", "host": "1.1.1.1", "user": "root"}
            ]
            with open(cfg_path, "w") as f:
                json.dump(initial_data, f)

            mock_manager = MagicMock()
            mock_manager.config_path = cfg_path
            mock_manager.registry.get.return_value = None
            mock_manager.registry.count.return_value = 1

            args = {
                "alias": "srv2",
                "host": "2.2.2.2",
                "user": "ubuntu",
                "password": "p2"
            }
            res = server_add_dispatch(args, mock_manager)
            self.assertTrue(res["success"])

            # Verify saved file is valid JSON and contains srv2
            with open(cfg_path, "r") as f:
                saved = json.load(f)
            self.assertIsInstance(saved, list)
            aliases = [s["alias"] for s in saved]
            self.assertIn("srv1", aliases)
            self.assertIn("srv2", aliases)
            if os.name != "nt":
                self.assertEqual(os.stat(cfg_path).st_mode & 0o777, 0o600)

    def test_server_add_max_servers_limit(self):
        """Verify server_add enforces MAX_SERVERS limit."""
        from src.server import server_add_dispatch
        from src.config import MAX_SERVERS

        mock_manager = MagicMock()
        mock_manager.registry.count.return_value = MAX_SERVERS
        mock_manager.registry.get.return_value = None

        args = {"alias": "over_limit", "host": "1.2.3.4", "user": "root"}
        res = server_add_dispatch(args, mock_manager)
        self.assertFalse(res["success"])
        self.assertIn("Maximum server limit", res["error"])

    def test_server_add_rejects_duplicate_alias_atomically(self):
        """Verify server_add rejects duplicate alias in both memory registry and file."""
        from src.server import server_add_dispatch

        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_path = os.path.join(tmpdir, "servers.json")
            with open(cfg_path, "w") as f:
                json.dump([{"alias": "existing_srv", "host": "1.1.1.1", "user": "root"}], f)

            mock_manager = MagicMock()
            mock_manager.config_path = cfg_path
            mock_manager.registry.count.return_value = 1
            mock_manager.registry.get.return_value = None  # in memory not yet synced

            # File already has existing_srv
            res = server_add_dispatch({"alias": "existing_srv", "host": "2.2.2.2", "user": "root"}, mock_manager)
            self.assertFalse(res["success"])
            self.assertIn("already exists", res["error"])

    def test_security_redirection_dev_null_allowed_and_file_blocked(self):
        """Verify WRITE_COMMAND_PATTERN allows safe /dev/null & 2>&1 redirections while blocking files."""
        from src.security import check_command_security

        # Safe stderr/stdout redirections in read-only mode should be permitted
        err_dev_null = check_command_security("cat /etc/hosts 2>/dev/null", "srv", 1, server_read_only=True)
        self.assertIsNone(err_dev_null)

        err_amp1 = check_command_security("cat /etc/hosts 2>&1", "srv", 1, server_read_only=True)
        self.assertIsNone(err_amp1)

        err_dev_null_space = check_command_security("grep 'foo' /var/log/syslog > /dev/null", "srv", 1, server_read_only=True)
        self.assertIsNone(err_dev_null_space)

        # Destructive output file redirection in read-only mode must be blocked
        err_out = check_command_security("cat /etc/hosts > /tmp/output.txt", "srv", 1, server_read_only=True)
        self.assertIsNotNone(err_out)
        self.assertIn("read-only", err_out["error"].lower())

    def test_dispute_max_workers_comes_from_config(self):
        import src.main as main_mod
        source = inspect.getsource(main_mod.main)
        self.assertIn("max_workers=MAX_WORKERS", source)
        self.assertNotIn("max_workers=16", source)

    def test_dispute_busybox_rm_is_blocked(self):
        err = check_command_security("busybox rm -rf /", "srv", 1, server_read_only=True)
        self.assertIsNotNone(err)
        self.assertIn("read-only", err["error"].lower())

    def test_dispute_readonly_allows_python_print(self):
        self.assertIsNone(check_command_security("python3 -c 'print(1)'", "srv", 1, server_read_only=True))
        self.assertIsNone(check_command_security("perl -e 'print 1'", "srv", 1, server_read_only=True))

    def test_dispute_readonly_blocks_cp_sed_tar_force_redirect(self):
        blocked = [
            "cp a b",
            "rsync a b",
            "sed -i 's/a/b/' f",
            "tar -xzf a.tgz",
            "echo x >| /tmp/x",
        ]
        for command in blocked:
            err = check_command_security(command, "srv", 1, server_read_only=True)
            self.assertIsNotNone(err, command)
        blocked.extend([
            "echo x >./file",
            "sed -e 's/a/b/' -i f",
            "tar -f a.tgz -x",
            "wget --output-document=f",
        ])
        for command in blocked[-4:]:
            err = check_command_security(command, "srv", 1, server_read_only=True)
            self.assertIsNotNone(err, command)
        allowed = [
            "tar -tzf a.tgz",
            "sed -n '1p' f",
            "cat x > /dev/null",
            "scp a b",
        ]
        for command in allowed:
            self.assertIsNone(check_command_security(command, "srv", 1, server_read_only=True), command)

    def _tools_call(self, tool_name, arguments, result):
        manager = MagicMock()
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
        dispatch_name = {
            "run": "src.server.run_dispatch",
            "signal": "src.server.signal_dispatch",
        }[tool_name]
        with patch(dispatch_name, return_value=result):
            return handle_request(request, manager)

    def test_dispute_nonzero_and_interrupt_are_mcp_errors(self):
        for status in ("completed_nonzero", "hard_timeout", "failed", "dead"):
            response = self._tools_call("run", {"command": "false", "server": "srv"}, {
                "success": True,
                "status": status,
                "exit_status": 1 if status == "completed_nonzero" else None,
                "output": "nope",
                "session_id": "srv/1",
                "server": "srv",
            })
            self.assertTrue(response["result"].get("isError"), status)
            body = json.loads(response["result"]["content"][0]["text"])
            self.assertEqual(body.get("status"), status)
            self.assertIn("nope", body.get("output", ""))
        for status in ("interrupted", "stalled", "running", "completed"):
            response = self._tools_call("run", {"command": "true", "server": "srv"}, {
                "success": True,
                "status": status,
                "output": "ok",
                "session_id": "srv/1",
                "server": "srv",
            })
            self.assertFalse(response["result"].get("isError"), status)
        projected = project_tool_result("run", {
            "success": True,
            "status": "running",
            "output": "",
            "message": "Command started in background",
            "session_recovered": True,
            "selection_reason": "current session died",
            "created_session_id": "srv/2",
            "recv_paused": True,
            "session_id": "srv/2",
        })
        self.assertEqual(projected["message"], "Command started in background")
        self.assertTrue(projected["session_recovered"])
        self.assertEqual(projected["selection_reason"], "current session died")
        self.assertEqual(projected["created_session_id"], "srv/2")
        self.assertTrue(projected["recv_paused"])

    def test_dispute_long_line_regex_returns_immediately(self):
        started = time.time()
        result = apply_text_filters("a" * 4097, regex=r"^(a+)+$")
        self.assertLess(time.time() - started, 0.5)
        self.assertFalse(result["success"])
        self.assertIn("line too long", result["error"])

    def test_dispute_regex_worker_cap_refuses_third(self):
        import src.utils as utils_mod
        previous = utils_mod._regex_workers_alive
        utils_mod._regex_workers_alive = 2
        try:
            result = apply_text_filters("hello", regex="h")
        finally:
            utils_mod._regex_workers_alive = previous
        self.assertFalse(result["success"])
        self.assertIn("too many regex workers are still running", result["error"])

    def test_dispute_run_filter_strips_ansi_under_lock(self):
        root = tempfile.mkdtemp()
        cache_dirs = make_cache_dirs(root)
        registry_cfg = ServerTargetConfig(alias="filt", host="10.9.8.7", user="u")
        manager = MultiServerManager(cache_dirs, "filt", registry=ServersRegistry())
        try:
            manager.registry.register(registry_cfg)
            node = manager.get_or_create_node(registry_cfg)
            session = SSHSession(1, "s", cache_dirs, "filt", server_config=registry_cfg)
            session.ensure_alive = MagicMock(return_value=None)
            session.client = MagicMock()
            ansi = "\x1b[31mhello\x1b[0m"
            run = RunState(
                run_id=7, session_id=1, command="echo", mode="sync",
                started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
                max_buffer_chars=1000, run_log_path=os.path.join(cache_dirs["runs_dir"], "filt.log"),
            )
            run.output_buffer = ansi

            class _LockProbe:
                def __init__(self, inner):
                    self.inner = inner
                    self.entries = 0

                def __enter__(self):
                    self.entries += 1
                    return self.inner.__enter__()

                def __exit__(self, exc_type, exc, tb):
                    return self.inner.__exit__(exc_type, exc, tb)

            probe = _LockProbe(run.lock)
            run.lock = probe
            session.runs[7] = run
            session.run_command = MagicMock(return_value={
                "success": True,
                "output": ansi,
                "run_id": 7,
                "status": "completed",
                "session_id": "filt/1",
                "server": "filt",
            })
            node.sessions[1] = session
            result = run_dispatch({"server": "filt", "session_id": "filt/1", "command": "echo"}, manager)
            self.assertTrue(result["success"])
            from src.utils import clean_output
            cleaned = clean_output(result["output"])
            self.assertNotIn("\x1b", cleaned)
            self.assertEqual(probe.entries, 0)
        finally:
            manager.close_all()

    def test_dispute_recovery_refuses_first_command(self):
        root = tempfile.mkdtemp()
        cache_dirs = make_cache_dirs(root)
        cfg = ServerTargetConfig(alias="rec", host="10.2.2.2", user="u", max_sessions=5)
        manager = MultiServerManager(cache_dirs, "rec", registry=ServersRegistry())
        created = []

        def fake_connect(self):
            channel = MagicMock()
            channel.recv_ready.return_value = False
            channel.closed = False
            channel.gettimeout.return_value = 1.0
            channel.send.side_effect = lambda data: len(data)
            self.client = MagicMock()
            self.client.get_transport.return_value.is_active.return_value = True
            self.channel = channel
            self.in_shell = False
            self.is_dead = False
            created.append(self)
            return True

        try:
            manager.registry.register(cfg)
            node = manager.get_or_create_node(cfg)
            dead = SSHSession(1, "old", cache_dirs, "rec", server_config=cfg)
            dead.ensure_alive = MagicMock(return_value="transport dead")
            dead.is_dead = False
            node.sessions[1] = dead
            node.next_session_id = 2
            with patch.object(SSHSession, "connect", fake_connect), patch.object(SSHSession, "ensure_alive", return_value=None):
                recovered = run_dispatch({
                    "server": "rec",
                    "session_id": "rec/1",
                    "command": "echo hi",
                    "background": True,
                }, manager)
            self.assertFalse(recovered["success"])
            self.assertIn("closed or disconnected", recovered["error"].lower())
            self.assertEqual(len(created), 0)

            created.clear()
            busy = SSHSession(1, "busy", cache_dirs, "rec", server_config=cfg)
            busy.ensure_alive = MagicMock(return_value=None)
            busy.is_busy = MagicMock(return_value=True)
            busy.busy_info = MagicMock(return_value={"type": "run", "id": 1})
            node.sessions = {1: busy}
            node.next_session_id = 2
            with patch.object(SSHSession, "connect", fake_connect), patch.object(SSHSession, "ensure_alive", return_value=None):
                busy_res = run_dispatch({
                    "server": "rec",
                    "session_id": "rec/1",
                    "command": "echo hi",
                    "background": True,
                }, manager)
            self.assertFalse(busy_res["success"])
            self.assertIn("busy", busy_res["error"].lower())
            self.assertEqual(len(created), 0)
        finally:
            manager.close_all()

    def test_dispute_project_root_filesystem_root_denies_path(self):
        previous = config.PROJECT_ROOT
        project = tempfile.mkdtemp()
        try:
            config.PROJECT_ROOT = "C:\\" if os.name == "nt" else "/"
            outside = "C:\\Windows\\notepad.exe" if os.name == "nt" else "/etc/passwd"
            self.assertEqual(resolve_local_path(outside), "")
            temp_file = os.path.join(tempfile.gettempdir(), "mcp_dispute_allow.txt")
            self.assertTrue(resolve_local_path(temp_file))
            config.PROJECT_ROOT = project
            inside = os.path.join(project, "owned.txt")
            self.assertEqual(resolve_local_path(inside), os.path.realpath(inside))
        finally:
            config.PROJECT_ROOT = previous

    def test_dispute_src_ssh_session_is_not_imported(self):
        src_dir = os.path.join(os.path.dirname(__file__), "..", "src")
        for path in glob.glob(os.path.join(src_dir, "*.py")):
            with open(path, encoding="utf-8") as handle:
                tree = ast.parse(handle.read(), filename=path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertFalse(
                            alias.name == "src.ssh" or alias.name.startswith("src.ssh."),
                            path,
                        )
                elif isinstance(node, ast.ImportFrom) and node.module:
                    self.assertFalse(
                        node.module == "src.ssh" or node.module.startswith("src.ssh."),
                        path,
                    )
        self.assertFalse(os.path.exists(os.path.join(src_dir, "ssh.py")))

    def test_nested_quantifiers_do_not_occupy_a_worker(self):
        import src.utils as utils_mod
        before = utils_mod._regex_workers_alive
        started = time.time()
        result = apply_text_filters("a" * 20 + "!", regex=r"^(a+)+$")
        self.assertLess(time.time() - started, 0.5)
        self.assertFalse(result["success"])
        self.assertIn("nested quantifiers", result["error"])
        self.assertEqual(utils_mod._regex_workers_alive, before)
        self.assertTrue(apply_text_filters("foo", regex="(foo|bar)+")["success"])
        self.assertTrue(apply_text_filters("aaa", regex="a+")["success"])

    def test_empty_project_root_denies_path(self):
        previous = config.PROJECT_ROOT
        try:
            config.PROJECT_ROOT = ""
            outside = "C:\\Windows\\notepad.exe" if os.name == "nt" else "/etc/passwd"
            self.assertEqual(resolve_local_path(outside), "")
            temp_file = os.path.join(tempfile.gettempdir(), "mcp_empty_root.txt")
            self.assertTrue(resolve_local_path(temp_file))
        finally:
            config.PROJECT_ROOT = previous

    def test_project_tool_result_shows_dropped_data(self):
        projected = project_tool_result("read", {
            "success": True,
            "status": "completed",
            "output": "kept",
            "dropped_data": True,
            "session_id": "srv/1",
        })
        self.assertTrue(projected["dropped_data"])

    def test_channel_eof_is_mcp_error(self):
        response = self._tools_call("run", {"command": "true", "server": "srv"}, {
            "success": True,
            "status": "dead",
            "error": "channel EOF",
            "output": "",
            "session_id": "srv/1",
            "server": "srv",
        })
        self.assertTrue(response["result"].get("isError"))

    def test_run_regex_output_is_paged(self):
        import threading
        from src.config import DEFAULT_READ_MAX_CHARS
        session = MagicMock()
        session.ensure_alive.return_value = None
        session.is_busy.return_value = False
        session.busy_info.return_value = {"busy": False}
        session.lock = threading.Lock()
        run = RunState(
            run_id=1, session_id=1, command="yes", mode="sync",
            started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=2_000_000, run_log_path=os.devnull,
        )
        page = "\n".join(["hit"] * 8000)
        run.output_buffer = page + "\nONLY_IN_BUFFER"
        session.runs = {1: run}
        session.run_command.return_value = {
            "success": True,
            "output": page,
            "run_id": 1,
            "status": "completed",
            "still_running": False,
            "limited": True,
            "next_offset": 48000,
            "session_id": "box/1",
            "server": "box",
        }
        node = MagicMock()
        node.get_session.return_value = session
        node.alias = "box"
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)
        result = run_dispatch({"command": "yes", "session_id": "box/1", "regex": "hit"}, manager)
        self.assertTrue(result["success"], result)
        self.assertLessEqual(len(result["output"]), DEFAULT_READ_MAX_CHARS)
        self.assertTrue(result["limited"])
        self.assertEqual(result["next_offset"], 48000)
        self.assertNotEqual(result["next_offset"], len(result["output"]))
        self.assertNotIn("ONLY_IN_BUFFER", result["output"])
        projected = project_tool_result("run", result)
        self.assertTrue(projected.get("limited"))
        self.assertIn("next_offset", projected)
        self.assertIn("still_running", projected)

    def test_run_tool_description_and_schema(self):
        tools = tools_list()["result"]["tools"]
        run_tool = next(tool for tool in tools if tool["name"] == "run")
        description = run_tool["description"]
        self.assertIn("single terminal process", description)
        self.assertIn("new_session=true", description)
        self.assertIn("5.0", description)
        props = run_tool["inputSchema"]["properties"]
        self.assertNotIn("background", props)
        self.assertNotIn("contains", props)
        self.assertNotIn("regex", props)
        self.assertNotIn("tail_lines", props)

    def test_read_and_session_list_schemas_hide_internal_run_ids(self):
        tools = tools_list()["result"]["tools"]
        read_tool = next(tool for tool in tools if tool["name"] == "read")
        self.assertIn("terminal tab", read_tool["description"])
        self.assertIn("offset=0 to rewind", read_tool["description"])
        read_props = read_tool["inputSchema"]["properties"]
        self.assertNotIn("run_id", read_props)

        session_list_tool = next(tool for tool in tools if tool["name"] == "session_list")
        session_props = session_list_tool["inputSchema"]["properties"]
        self.assertNotIn("include_active_ids", session_props)

        # Ensure project_tool_result never leaks run_id for read or run
        raw = {"success": True, "output": "ok", "session_id": "srv/1", "run_id": 42, "status": "completed"}
        projected_read = project_tool_result("read", raw)
        self.assertNotIn("run_id", projected_read)
        projected_run = project_tool_result("run", raw)
        self.assertNotIn("run_id", projected_run)

    def test_shutdown_closes_sessions_before_the_pool(self):
        import src.main as main_mod
        text = inspect.getsource(main_mod.main)
        self.assertLess(text.find("manager.close_all()"), text.find("executor.shutdown"))
        self.assertIn("Sync run holds a worker", text)

    def test_explicit_session_id_not_found_no_fallback(self):
        """Verify that explicit session_id that does not exist returns error and NEVER falls back to ensure_session."""
        node = MagicMock()
        node.alias = "srv1"
        node.get_session.return_value = None
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 99, False, None)

        # 1. read_dispatch
        res_read = read_dispatch({"session_id": "srv1/99"}, manager)
        self.assertFalse(res_read["success"])
        self.assertIn("Session 99 not found on server 'srv1'", res_read["error"])
        node.ensure_session.assert_not_called()

        # 2. signal_dispatch
        res_signal = signal_dispatch({"session_id": "srv1/99", "action": "ctrl_c"}, manager)
        self.assertFalse(res_signal["success"])
        self.assertIn("Session 99 not found on server 'srv1'", res_signal["error"])
        node.ensure_session.assert_not_called()

    def test_run_dispatch_without_session_id_always_opens_new_session(self):
        """Test that calling run without session_id always opens a new session and sets session_created=True."""
        node = MagicMock()
        node.alias = "srv1"
        node.open_session.return_value = {
            "success": True,
            "session_id": "srv1/1",
            "numeric_session_id": 1,
            "server": "srv1",
            "name": ""
        }
        mock_sess = MagicMock()
        mock_sess.run_command.return_value = {
            "success": True,
            "session_id": "srv1/1",
            "server": "srv1",
            "output": "ok",
            "status": "completed"
        }
        node.get_session.return_value = mock_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, None, False, None)

        res = run_dispatch({"server": "srv1", "command": "echo 1"}, manager)
        self.assertTrue(res["success"])
        self.assertTrue(res.get("session_created"))
        self.assertEqual(res.get("session_selection"), "new_session")
        self.assertEqual(res.get("created_session_id"), "srv1/1")
        node.open_session.assert_called_once()

    def test_read_dispatch_wait_timeout_passes_to_session(self):
        """Test that wait_timeout is parsed and passed to session.read_run."""
        node = MagicMock()
        node.alias = "srv1"
        mock_sess = MagicMock()
        mock_sess.read_run.return_value = {"success": True, "output": "done", "status": "completed"}
        node.get_session.return_value = mock_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)

        res = read_dispatch({"server": "srv1", "session_id": "srv1/1", "wait_timeout": 3.5}, manager)
        self.assertTrue(res["success"])
        mock_sess.read_run.assert_called_once_with(
            run_id=None, offset=None, max_lines=1000, max_chars=50000, wait_timeout=3.5
        )

    def test_security_case_insensitive_blacklist_and_readonly(self):
        """Test that blacklist and readonly checks in check_command_security are case-insensitive."""
        from src.security import check_command_security

        # Blacklist check
        blocked = check_command_security(
            command="REBOOT",
            server_alias="test_srv",
            numeric_sid=1,
            server_blacklist=["reboot"]
        )
        self.assertIsNotNone(blocked)
        self.assertFalse(blocked["success"])
        self.assertIn("blocked by command blacklist", blocked["error"])

        # Read-only check
        blocked_ro = check_command_security(
            command="RM -RF /tmp/foo",
            server_alias="test_srv",
            numeric_sid=1,
            server_read_only=True
        )
        self.assertIsNotNone(blocked_ro)
        self.assertFalse(blocked_ro["success"])
        self.assertIn("blocked in read-only sandbox mode", blocked_ro["error"])

    def test_cleanup_dead_session_logs_retention_and_cascade(self):
        """Test cleanup_dead_session_logs retains logs < 2 hours, caps older to 20, and cascades to runs_dir."""
        import tempfile
        import time
        from src.utils import cleanup_dead_session_logs, make_cache_dirs

        root = tempfile.mkdtemp()
        try:
            cache_dirs = make_cache_dirs(root)
            sessions_dir = cache_dirs["sessions_dir"]
            runs_dir = cache_dirs["runs_dir"]
            now = time.time()

            # Create 25 old session logs (> 2 hours old) for server 'vps1'
            old_time = now - 10000
            for i in range(1, 26):
                s_path = os.path.join(sessions_dir, f"proj__vps1__s{i}__unnamed__20260101_000000.log")
                with open(s_path, "w") as f:
                    f.write("test\n")
                # Set mtime staggered
                os.utime(s_path, (old_time + i, old_time + i))
                # Corresponding run log in runs_dir
                r_path = os.path.join(runs_dir, f"proj__vps1__s{i}__r1__20260101_000000.log")
                with open(r_path, "w") as f:
                    f.write("run test\n")
                os.utime(r_path, (old_time + i, old_time + i))

            # Create 5 fresh session logs (< 2 hours old) for 'vps1'
            for i in range(26, 31):
                s_path = os.path.join(sessions_dir, f"proj__vps1__s{i}__unnamed__20260101_000000.log")
                with open(s_path, "w") as f:
                    f.write("fresh test\n")

            # Run cleanup with limit 20
            deleted = cleanup_dead_session_logs(cache_dirs, server_alias="vps1", max_logs_per_server=20, min_retention_seconds=7200)
            
            # The 5 oldest from the first 25 should be deleted, plus their 5 run logs = 10 deleted
            self.assertEqual(deleted, 10)
            remaining_s = [f for f in os.listdir(sessions_dir) if f.endswith(".log")]
            self.assertEqual(len(remaining_s), 25)  # 20 old + 5 fresh
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
