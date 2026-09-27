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
from src.utils import apply_text_filters, make_cache_dirs, resolve_local_path, StreamCleaner

class TestServer(unittest.TestCase):
    def test_project_tool_result_mcp_level_errors(self):
        # Test non-object return
        res = project_tool_result("run", "not-a-dict")
        self.assertEqual(res, {"success": False, "error": "tool returned non-object result"})

        # Test success = False (MCP error)
        raw_err = {"success": False, "error": "connection timeout", "session_id": 42}
        res = project_tool_result("run", raw_err)
        expected = {
            "success": False,
            "error": "connection timeout",
            "session_id": 42,
        }
        self.assertEqual(res, expected)

    def test_project_tool_result_completed_nonzero(self):
        # A known non-zero exit status is a normal result, not a tool error:
        # no synthesized "error", honest status + exit_status, raw output kept.
        # run_id is internal (session tabs only): stripped from the agent surface.
        raw = {
            "success": True,
            "status": "completed_nonzero",
            "exit_status": 127,
            "output": "bash: command not found",
            "session_id": 1,
            "run_id": 5
        }
        res = project_tool_result("run", raw)
        expected = {
            "output": "bash: command not found",
            "session_id": 1,
            "status": "completed_nonzero",
            "exit_status": 127,
        }
        self.assertEqual(res, expected)

    def test_project_tool_result_never_invents_exit_status(self):
        """T3.3/F9: an unknown exit code must stay unknown - no fabricated 'exit status 1'."""
        raw = {
            "success": True,
            "status": "failed",
            "error": "channel EOF",
            "output": "partial output\n",
            "session_id": 1,
        }
        res = project_tool_result("run", raw)
        expected = {
            "error": "channel EOF",
            "output": "partial output\n",
            "session_id": 1,
            "status": "failed",
        }
        self.assertEqual(res, expected)

    def test_project_tool_result_keeps_hint(self):
        """T3.3/F9: recovery hints travel to the model instead of decorative banners."""
        raw = {
            "success": True, "status": "interrupted", "output": "",
            "process_stopped": False, "hint": "the remote process may still be running",
            "session_id": 1,
        }
        res = project_tool_result("run", raw)
        expected = {
            "output": "",
            "process_stopped": False,
            "hint": "the remote process may still be running",
            "session_id": 1,
            "status": "interrupted",
        }
        self.assertEqual(res, expected)

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
        expected = {
            "message": "Downloaded to /tmp/local.txt",
            "size": 100,
        }
        self.assertEqual(res, expected)

    def test_project_tool_result_file_list(self):
        # File list action
        raw = {
            "success": True,
            "action": "list",
            "files": [{"name": "test.txt", "size": 10, "is_dir": False}]
        }
        res = project_tool_result("file", raw)
        expected = {
            "files": [{"name": "test.txt", "size": 10, "is_dir": False}],
        }
        self.assertEqual(res, expected)

    def test_handle_request_initialize(self):
        mock_manager = MagicMock()
        req = {
            "jsonrpc": "2.0",
            "id": 123,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"}
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
            self.assertEqual(res["jsonrpc"], "2.0")
            self.assertIn("result", res)
            self.assertEqual(list(res.keys()), ["jsonrpc", "id", "result"])

    def test_control_request_routing(self):
        """T1.3/F5: cheap control calls must run on the control lane, never behind long runs."""
        from src.server import is_control_request
        for name in ("signal", "session_close", "session_update", "session_list", "server_list", "last_command_details"):
            self.assertTrue(is_control_request({"method": "tools/call", "params": {"name": name}}), name)
        for name in ("run", "read", "file"):
            self.assertFalse(is_control_request({"method": "tools/call", "params": {"name": name}}), name)
        self.assertTrue(is_control_request({"method": "initialize"}))
        self.assertTrue(is_control_request({"method": "tools/list"}))
        self.assertFalse(is_control_request("not a dict"))

    def test_submit_request_busy_when_saturated(self):
        """T1.3/F5: past the in-flight cap the caller gets an immediate busy answer, not a queue."""
        import threading
        import json as json_mod
        from src.main import submit_request
        written = []
        pending = threading.BoundedSemaphore(1)
        self.assertTrue(pending.acquire(blocking=False))  # saturate the cap
        main_executor = MagicMock()
        control_executor = MagicMock()
        submit_request(
            json_mod.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                            "params": {"name": "run", "arguments": {"command": "x"}}}),
            MagicMock(), written.append, main_executor, control_executor, pending,
        )
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0]["id"], 7)
        self.assertEqual(written[0]["error"]["code"], -32000)
        self.assertIn("busy", written[0]["error"]["message"])
        main_executor.submit.assert_not_called()
        self.assertEqual(pending._value, 0, "busy path must not release the slot it never took")

    def test_submit_request_control_lane_ignores_saturated_cap(self):
        """T1.3/F5: Ctrl+C and friends must get through even when the main pool is saturated."""
        import threading
        import json as json_mod
        from src.main import submit_request
        written = []
        pending = threading.BoundedSemaphore(1)
        self.assertTrue(pending.acquire(blocking=False))
        main_executor = MagicMock()
        control_executor = MagicMock()
        submit_request(
            json_mod.dumps({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                            "params": {"name": "signal", "arguments": {"action": "ctrl_c"}}}),
            MagicMock(), written.append, main_executor, control_executor, pending,
        )
        self.assertEqual(written, [])
        control_executor.submit.assert_called_once()
        main_executor.submit.assert_not_called()

    def test_submit_request_rejects_oversized_lines(self):
        """T1.3/F5: a huge request line must be refused before parsing (memory DoS)."""
        from src.main import submit_request
        written = []
        pending = __import__("threading").BoundedSemaphore(4)
        with patch("src.main.MAX_REQUEST_LINE_BYTES", 10):
            submit_request("x" * 50, MagicMock(), written.append, MagicMock(), MagicMock(), pending)
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0]["error"]["code"], -32600)
        self.assertIn("too large", written[0]["error"]["message"])

    def test_ping_and_protocol_version(self):
        """T1.4/F12: ping must answer with request id, initialize must negotiate supported protocol version."""
        resp = handle_request({"jsonrpc": "2.0", "id": 5, "method": "ping"}, MagicMock())
        self.assertEqual(resp["result"], {})
        self.assertEqual(resp["id"], 5)

        # Ping as notification (no id) must return None (no response)
        resp_notify = handle_request({"jsonrpc": "2.0", "method": "ping"}, MagicMock())
        self.assertIsNone(resp_notify, "id-less notification ping must return no response!")

        # Initialize with supported version
        init = handle_request({"jsonrpc": "2.0", "id": 6, "method": "initialize",
                               "params": {"protocolVersion": "2024-11-05"}}, MagicMock())
        self.assertEqual(init["result"]["protocolVersion"], "2024-11-05")

        # Initialize with unsupported arbitrary client version negotiates supported default
        init_unsupported = handle_request({"jsonrpc": "2.0", "id": 7, "method": "initialize",
                                           "params": {"protocolVersion": "9999-99-99"}}, MagicMock())
        self.assertEqual(init_unsupported["result"]["protocolVersion"], "2024-11-05")

    def test_invalid_json_rpc_array_gets_invalid_request_id_null(self):
        """P2: Non-dict request shape gets JSON-RPC -32600 with id: null."""
        from src.main import process_line
        captured = []
        process_line("[]", MagicMock(), write_fn=captured.append)
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["jsonrpc"], "2.0")
        self.assertIsNone(captured[0]["id"])
        self.assertEqual(captured[0]["error"]["code"], -32600)

    def test_cancelled_notification_returns_no_response(self):
        """T1.4/F12: notifications get no response, but cancellation must be forwarded."""
        manager = MagicMock()
        manager.cancel_request.return_value = {"success": True}
        resp = handle_request({"jsonrpc": "2.0", "method": "notifications/cancelled",
                               "params": {"requestId": 9}}, manager)
        self.assertIsNone(resp)
        manager.cancel_request.assert_called_once_with(9)

    def test_run_dispatch_passes_req_id_to_run_command(self):
        """T1.4/F12: the JSON-RPC id must reach run_command so cancel can find the run."""
        node = MagicMock()
        node.alias = "srv1"
        mock_sess = MagicMock()
        mock_sess.run_command.return_value = {
            "success": True, "session_id": "srv1/7", "server": "srv1", "output": "ok", "status": "completed"
        }
        node.find_first_idle_alive_session.return_value = mock_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, None, False, None)

        res = run_dispatch({"server": "srv1", "command": "echo 1"}, manager, req_id=77)
        self.assertTrue(res["success"])
        self.assertEqual(mock_sess.run_command.call_args.kwargs.get("req_id"), 77)

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

    def test_from_dict_unresolved_secret_env_raises(self):
        """T0.3/F13: a ${VAR} secret that cannot resolve must fail loudly, not become the password."""
        with self.assertRaises(ValueError) as ctx:
            ServerTargetConfig.from_dict("prod", {
                "host": "10.0.0.1", "user": "u", "password": "${DEFINITELY_NOT_SET_VAR_12345}",
            })
        self.assertIn("DEFINITELY_NOT_SET_VAR_12345", str(ctx.exception))

    def test_from_dict_rejects_bash_default_syntax_in_secrets(self):
        """${VAR:-default} is bash-only: it must fail loudly, not become the literal password."""
        with self.assertRaises(ValueError) as ctx:
            ServerTargetConfig.from_dict("prod", {
                "host": "10.0.0.1", "user": "u", "password": "${SOME_VAR_XYZ:-admin123}",
            })
        self.assertIn("unresolvable secret reference", str(ctx.exception))

    def test_from_dict_resolves_secret_env(self):
        """T0.3/F13: resolvable ${VAR} secrets still interpolate."""
        os.environ["MCP_TEST_SECRET_PW"] = "s3cret"
        try:
            cfg = ServerTargetConfig.from_dict("prod", {
                "host": "10.0.0.1", "user": "u", "password": "${MCP_TEST_SECRET_PW}",
            })
            self.assertEqual(cfg.password, "s3cret")
        finally:
            del os.environ["MCP_TEST_SECRET_PW"]

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
        expected = {
            "output": "line 10\nline 11",
            "line_start": 10,
            "line_end": 11,
            "total_lines": 100,
            "truncated": True,
            "exit_status": 0,
        }
        self.assertEqual(proj, expected)

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

    def test_dispute_transport_failures_set_mcp_error_flag(self):
        # completed_nonzero is a normal process result (grep/ipset test/diff -> 1),
        # not a tool error: isError stays false. Only transport/tool failures
        # (hard_timeout/failed/dead) set isError.
        for status in ("hard_timeout", "failed", "dead"):
            response = self._tools_call("run", {"command": "false", "server": "srv"}, {
                "success": True,
                "status": status,
                "exit_status": 1 if status in ("failed", "dead", "hard_timeout") else None,
                "output": "nope",
                "session_id": "srv/1",
                "server": "srv",
            })
            self.assertTrue(response["result"].get("isError"), status)
            body = json.loads(response["result"]["content"][0]["text"])
            self.assertEqual(body.get("status"), status)
            self.assertIn("nope", body.get("output", ""))
        for status in ("interrupted", "stalled", "running", "completed", "completed_nonzero"):
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
            "status": "interrupted",
            "output": "",
            "message": "Command started in background",
            "session_reused": True,
            "process_stopped": False,
            "hint": "the remote process may still be running",
            "created_session_id": "srv/2",
            "recv_paused": True,
            "session_id": "srv/2",
        })
        expected_projected = {
            "output": "",
            "message": "Command started in background",
            "session_reused": True,
            "process_stopped": False,
            "hint": "the remote process may still be running",
            "created_session_id": "srv/2",
            "recv_paused": True,
            "session_id": "srv/2",
            "status": "interrupted",
        }
        self.assertEqual(projected, expected_projected)

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

    def test_run_projection_strips_internal_framing_under_lock(self):
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
            raw_output = (
                "echo; printf '%s\\n' \"__MCP_EC_0123456789abcdef_$?\"\n"
                "\x1b[31mhello\x1b[0m\n"
                "__MCP_EC_0123456789abcdef_0"
            )
            run = RunState(
                run_id=7, session_id=1, command="echo", mode="sync",
                started_at=time.time(), wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
                max_buffer_chars=1000, run_log_path=os.path.join(cache_dirs["runs_dir"], "filt.log"),
            )
            run.output_buffer = raw_output

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
                "output": raw_output,
                "run_id": 7,
                "status": "completed",
                "session_id": "filt/1",
                "server": "filt",
            })
            node.sessions[1] = session
            result = run_dispatch({"server": "filt", "session_id": "filt/1", "command": "echo"}, manager)
            self.assertTrue(result["success"])
            # The SERVER projection (not the test) must strip internal framing:
            # cleaning here instead hid the regression for a whole release.
            projected = project_tool_result("run", result)
            self.assertNotIn("__MCP_EC_", projected["output"])
            self.assertNotIn("printf", projected["output"])
            # The payload survives; ANSI removal is the stream cleaner's job, which
            # runs upstream when the PTY bytes enter the canvas.
            self.assertEqual(StreamCleaner().feed(projected["output"]), "hello")
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
            with patch.object(SSHSession, "connect", fake_connect):
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
            # system temp is opt-in now
            self.assertEqual(resolve_local_path(temp_file), "")
            previous_temp = config.ALLOW_SYSTEM_TEMP
            try:
                config.ALLOW_SYSTEM_TEMP = True
                self.assertTrue(resolve_local_path(temp_file))
            finally:
                config.ALLOW_SYSTEM_TEMP = previous_temp
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
            # system temp is opt-in now
            self.assertEqual(resolve_local_path(temp_file), "")
            previous_temp = config.ALLOW_SYSTEM_TEMP
            try:
                config.ALLOW_SYSTEM_TEMP = True
                self.assertTrue(resolve_local_path(temp_file))
            finally:
                config.ALLOW_SYSTEM_TEMP = previous_temp
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
        expected = {
            "output": "kept",
            "session_id": "srv/1",
            "status": "completed",
            "dropped_data": True,
        }
        self.assertEqual(projected, expected)

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
            "output": page[:DEFAULT_READ_MAX_CHARS],
            "run_id": 1,
            "status": "completed",
            "still_running": False,
            "has_more": True,
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
        self.assertEqual(len(result["output"]), DEFAULT_READ_MAX_CHARS)
        self.assertEqual(result["output"], page[:DEFAULT_READ_MAX_CHARS])
        self.assertTrue(result["has_more"], "a cut window must advertise unread output")
        projected = project_tool_result("run", result)
        expected_projected = {
            "output": page[:DEFAULT_READ_MAX_CHARS],
            "server": "box",
            "session_id": "box/1",
            "status": "completed",
            "still_running": False,
            "has_more": True,
            "hint": "unread output remains - read again with read(session_id)",
        }
        self.assertEqual(projected, expected_projected)

    def test_run_tool_description_and_schema(self):
        tools = tools_list()["result"]["tools"]
        run_tool = next(tool for tool in tools if tool["name"] == "run")
        description = run_tool["description"]
        # T3.1/F10: descriptions stay compact - every char is paid per request
        self.assertLessEqual(len(description), 500, "run description must stay compact for small models")
        props = run_tool["inputSchema"]["properties"]
        self.assertEqual(run_tool["inputSchema"]["required"], ["command"])
        expected_props = {
            "server", "command", "session_id", "wait_timeout", "hard_timeout",
            "shell", "new_session", "session_name", "use_pty", "line_limit"
        }
        self.assertEqual(set(props.keys()), expected_props)
        self.assertEqual(props["line_limit"]["type"], "integer")
        self.assertEqual(props["new_session"]["type"], "boolean")
        self.assertEqual(props["wait_timeout"]["type"], "number")

    def test_tool_profile_lean_shows_only_everyday_tools(self):
        """T3.2/F10: the lean catalog keeps small-model prompts small."""
        from src.config import config as cfg
        from src.server import LEAN_TOOLS
        previous = cfg.TOOL_PROFILE
        try:
            cfg.TOOL_PROFILE = "lean"
            names = {t["name"] for t in tools_list()["result"]["tools"]}
            self.assertEqual(names, LEAN_TOOLS)
            cfg.TOOL_PROFILE = "full"
            self.assertEqual(len(tools_list()["result"]["tools"]), 10)
        finally:
            cfg.TOOL_PROFILE = previous

    def test_read_schema_hides_run_id_session_tabs_only(self):
        # run_id is internal (one session = one terminal tab, sequential runs).
        # The agent pages the session: read(session_id, limit/tail/offset), one cursor.
        tools = tools_list()["result"]["tools"]
        read_tool = next(tool for tool in tools if tool["name"] == "read")
        read_props = read_tool["inputSchema"]["properties"]
        expected_read_props = {"server", "session_id", "line_limit", "tail", "offset", "wait_timeout"}
        self.assertEqual(set(read_props.keys()), expected_read_props)
        self.assertEqual(read_props["line_limit"]["type"], "integer")
        # Continuation contract: every offset is a LINE number (m01215) - the tab is
        # ONE stream read through one line-based cursor, so has_more counts lines.
        self.assertIn("LINE number", read_props["offset"]["description"])
        self.assertIn("NUMBER of unread LINES", read_tool["description"])
        self.assertIn("scrollback", read_tool["description"])

        session_list_tool = next(tool for tool in tools if tool["name"] == "session_list")
        session_props = session_list_tool["inputSchema"]["properties"]
        self.assertEqual(set(session_props.keys()), {"server", "include_name", "include_last_command"})

        # Ensure project_tool_result strips run_id from the agent surface and formats full expected JSON
        raw = {"success": True, "output": "ok", "session_id": "srv/1", "run_id": 42, "status": "completed"}
        expected_projected = {
            "output": "ok",
            "session_id": "srv/1",
            "status": "completed",
        }
        self.assertEqual(project_tool_result("read", raw), expected_projected)
        self.assertEqual(project_tool_result("run", raw), expected_projected)

    def test_lean_server_list_exposes_live_session_ids_and_modes(self):
        """P1: server_list under lean profile derives active_sessions from the live session state."""
        import threading
        from src.manager import MultiServerManager, ServerNode

        cfg = MagicMock(alias="srv1", host="1.2.3.4", port=22, user="root", description="", read_only=False)
        with tempfile.TemporaryDirectory() as tmp:
            cache_dirs = make_cache_dirs(tmp)
            # Real ServerNode.list_sessions computes status/mode; only the sessions are fakes.
            node = ServerNode(cfg, cache_dirs, "test_p")
            s1 = MagicMock(id=1, is_dead=False, is_alive=lambda: True, is_busy=lambda: False, in_shell=False, _pty_invalidated=False)
            s1.info.return_value = {"dead": False, "alive": True, "in_shell": False}
            s2 = MagicMock(id=2, is_dead=False, is_alive=lambda: True, is_busy=lambda: True, in_shell=True, _pty_invalidated=False)
            s2.info.return_value = {"dead": False, "alive": True, "in_shell": True}
            s3 = MagicMock(id=3, is_dead=True, is_alive=lambda: False, is_busy=lambda: False, in_shell=False, _pty_invalidated=False)
            s3.info.return_value = {"dead": True, "alive": False, "in_shell": False}
            node.sessions = {1: s1, 2: s2, 3: s3}
            self.assertEqual(
                [row["status"] for row in node.list_sessions()], ["idle", "busy", "broken"],
            )

            manager = MagicMock()
            manager.registry.list_all.return_value = [cfg]
            manager.registry.find_by_prefix.return_value = [cfg]
            manager.nodes = {"srv1": node}
            manager.lock = threading.Lock()
            manager.check_reload.return_value = {}

            resp = MultiServerManager.list_all_servers(manager, reload=False)

        self.assertTrue(resp["success"])
        srv_entry = resp["servers"][0]
        self.assertEqual(srv_entry["sessions"], 3)
        self.assertIn("active_sessions", srv_entry)
        # The broken/dead session must be reported in the count but kept out of active_sessions.
        self.assertEqual(len(srv_entry["active_sessions"]), 2)
        self.assertEqual(srv_entry["active_sessions"][0], {"session_id": "srv1/1", "status": "idle", "mode": "ndm_cli"})
        self.assertEqual(srv_entry["active_sessions"][1], {"session_id": "srv1/2", "status": "busy", "mode": "linux_shell"})

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

    def test_run_dispatch_rejects_empty_command(self):
        """T0.4/F10: an empty command must fail loudly, not run a bare exit marker as success."""
        manager = MagicMock()
        node = MagicMock()
        node.alias = "srv1"
        manager.resolve_target_for_args.return_value = (node, 1, False, None)
        for bad in ("", "   ", None):
            res = run_dispatch({"server": "srv1", "session_id": "srv1/1", "command": bad}, manager)
            self.assertFalse(res["success"])
            self.assertIn("command", res["error"].lower())
        manager.resolve_target_for_args.assert_not_called()

    def test_run_dispatch_without_session_id_reuses_idle_session(self):
        """T1.1/F3: run without session_id must REUSE an idle session, not open a new SSH connection."""
        node = MagicMock()
        node.alias = "srv1"
        mock_sess = MagicMock()
        mock_sess.run_command.return_value = {
            "success": True,
            "session_id": "srv1/7",
            "server": "srv1",
            "output": "ok",
            "status": "completed"
        }
        node.find_first_idle_alive_session.return_value = mock_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, None, False, None)

        res = run_dispatch({"server": "srv1", "command": "echo 1"}, manager)
        self.assertTrue(res["success"])
        self.assertTrue(res.get("session_reused"))
        self.assertFalse(res.get("session_created"))
        node.open_session.assert_not_called()
        mock_sess.run_command.assert_called_once()

    def test_run_dispatch_new_session_true_always_opens_new(self):
        """T1.1/F3: new_session=true must still force a clean session."""
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

        res = run_dispatch({"server": "srv1", "command": "echo 1", "new_session": True}, manager)
        self.assertTrue(res["success"])
        self.assertTrue(res.get("session_created"))
        self.assertFalse(res.get("session_reused"))
        self.assertEqual(res.get("session_selection"), "new_session")
        self.assertEqual(res.get("created_session_id"), "srv1/1")
        node.open_session.assert_called_once()
        node.find_first_idle_alive_session.assert_not_called()

    def test_run_dispatch_opens_new_when_none_idle(self):
        """T1.1/F3: with no idle session a fresh one is created (old behaviour preserved)."""
        node = MagicMock()
        node.alias = "srv1"
        node.find_first_idle_alive_session.return_value = None
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

    def test_run_dispatch_busy_reused_session_retries_on_new_session(self):
        """T1.1/F3: losing the idle-session race must retry once on a fresh session."""
        node = MagicMock()
        node.alias = "srv1"
        busy_sess = MagicMock()
        busy_sess.run_command.return_value = {
            "success": False,
            "error": "Session 1 is busy running 'x'.",
            "session_id": "srv1/1",
            "server": "srv1",
        }
        fresh_sess = MagicMock()
        fresh_sess.run_command.return_value = {
            "success": True,
            "session_id": "srv1/2",
            "server": "srv1",
            "output": "ok",
            "status": "completed"
        }
        node.find_first_idle_alive_session.return_value = busy_sess
        node.open_session.return_value = {
            "success": True, "session_id": "srv1/2", "numeric_session_id": 2, "server": "srv1", "name": ""
        }
        node.get_session.return_value = fresh_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, None, False, None)

        res = run_dispatch({"server": "srv1", "command": "echo 1"}, manager)
        self.assertTrue(res["success"], res)
        self.assertEqual(res.get("session_selection"), "retry_new_session")
        self.assertTrue(res.get("session_created"))
        self.assertFalse(res.get("session_reused"))
        self.assertEqual(res.get("created_session_id"), "srv1/2")
        node.open_session.assert_called_once()

    def test_read_dispatch_wait_timeout_passes_to_session(self):
        """Test that wait_timeout is parsed and passed to session.read_canvas."""
        node = MagicMock()
        node.alias = "srv1"
        mock_sess = MagicMock()
        mock_sess.read_canvas.return_value = {"success": True, "output": "done", "status": "completed"}
        node.get_session.return_value = mock_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)

        res = read_dispatch({"server": "srv1", "session_id": "srv1/1", "wait_timeout": 3.5}, manager)
        self.assertTrue(res["success"])
        # One stream, one cursor: the tab canvas is the only read path (m01215).
        mock_sess.read_canvas.assert_called_once_with(
            line_limit=200, tail=None, offset=None, wait_timeout=3.5
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
        self.assertIn("blocked in read-only guardrail mode", blocked_ro["error"])

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

    def test_project_tool_result_keeps_shell_context_on_error(self):
        """P1: success=false keeps in_shell/mode/status (exit_shell recipe keys off them)."""
        raw = {"success": False, "error": "exit stuck", "session_id": "keenetic/1",
               "in_shell": True, "mode": "linux_shell", "run_id": 3,
               "status": "failed", "completion_method": "failed"}
        res = project_tool_result("run", raw)
        expected = {
            "error": "exit stuck",
            "success": False,
            "session_id": "keenetic/1",
            "in_shell": True,
            "mode": "linux_shell",
            "status": "failed",
            "completion_method": "failed",
        }
        self.assertEqual(res, expected)

    def test_project_tool_result_keeps_unconfirmed_completion(self):
        """P1: stalled uncertainty flag survives the lean projection."""
        raw = {"success": True, "output": "uptime...", "session_id": "keenetic/1",
               "run_id": 7, "status": "stalled", "unconfirmed_completion": True,
               "hint": "No completion marker seen"}
        res = project_tool_result("run", raw)
        expected = {
            "output": "uptime...",
            "hint": "No completion marker seen",
            "session_id": "keenetic/1",
            "status": "stalled",
            "unconfirmed_completion": True,
        }
        self.assertEqual(res, expected)

    def test_run_line_limit_zero_is_passed_through_unclamped(self):
        """P4/P7: line_limit=0 means 'no line cap' and must reach the session unclamped."""
        node = MagicMock()
        node.alias = "srv1"
        mock_sess = MagicMock()
        mock_sess.ensure_alive.return_value = None
        mock_sess.is_dead = False
        mock_sess.is_busy.return_value = False
        mock_sess.run_command.return_value = {
            "success": True, "output": "all lines", "status": "completed", "session_id": "srv1/1",
        }
        node.get_session.return_value = mock_sess
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)

        res = run_dispatch({"server": "srv1", "command": "cat big", "line_limit": 0}, manager)
        self.assertTrue(res["success"], res)
        self.assertEqual(mock_sess.run_command.call_args.kwargs["line_limit"], 0)

    def test_project_tool_result_hard_timeout_has_error_text(self):
        """A2: hard_timeout isError=true must carry an error line, not an empty shell."""
        raw = {"success": True, "status": "hard_timeout", "output": "partial...",
               "session_id": "srv/1", "server": "srv"}
        res = project_tool_result("run", raw)
        expected = {
            "error": "Command hit hard timeout (see hard_timeout params) and was interrupted; partial output kept - re-run with a bigger hard_timeout or in background.",
            "output": "partial...",
            "server": "srv",
            "session_id": "srv/1",
            "status": "hard_timeout",
        }
        self.assertEqual(res, expected)

    def test_project_tool_result_file_mode_survives(self):
        """A1: the file tool's own mode (binary_hidden/download) is never overwritten."""
        raw = {"success": True, "action": "read", "mode": "binary_hidden",
               "message": "File is binary. Content hidden.", "size": 10,
               "sha256": "abc", "in_shell": True}
        res = project_tool_result("file", raw)
        expected = {
            "mode": "binary_hidden",
            "message": "File is binary. Content hidden.",
            "size": 10,
            "sha256": "abc",
        }
        self.assertEqual(res, expected)

    def test_completed_nonzero_exit_one_is_not_mcp_error_and_hard_timeout_is(self):
        """P0: exit status 1 (completed_nonzero) is a normal completed result, not MCP error."""
        raw_exit_1 = {
            "success": True, "output": "file not found", "session_id": "srv/1",
            "server": "srv", "status": "completed_nonzero", "exit_status": 1
        }
        res_exit_1 = project_tool_result("run", raw_exit_1)
        expected_exit_1 = {
            "output": "file not found",
            "server": "srv",
            "session_id": "srv/1",
            "status": "completed_nonzero",
            "exit_status": 1,
        }
        self.assertEqual(res_exit_1, expected_exit_1)

        raw_timeout = {
            "success": True, "output": "partial", "session_id": "srv/1",
            "server": "srv", "status": "hard_timeout"
        }
        res_timeout = project_tool_result("run", raw_timeout)
        expected_timeout = {
            "error": "Command hit hard timeout (see hard_timeout params) and was interrupted; partial output kept - re-run with a bigger hard_timeout or in background.",
            "output": "partial",
            "server": "srv",
            "session_id": "srv/1",
            "status": "hard_timeout",
        }
        self.assertEqual(res_timeout, expected_timeout)

    def test_completed_zero_exit_is_protected(self):
        """A8: success=True + completed + exit_status=1 stays a normal result (intent lock)."""
        res = project_tool_result("run", {
            "success": True, "status": "completed", "exit_status": 1,
            "output": "x", "session_id": "srv/1", "server": "srv",
        })
        expected = {
            "output": "x",
            "server": "srv",
            "session_id": "srv/1",
            "status": "completed",
            "exit_status": 1,
        }
        self.assertEqual(res, expected)

    def test_run_schema_has_no_run_id(self):
        """Agent surface: run takes no run_id; paging is session-level."""
        tools = tools_list()["result"]["tools"]
        run_tool = next(tool for tool in tools if tool["name"] == "run")
        expected_run_props = {
            "server", "command", "session_id", "wait_timeout", "hard_timeout",
            "shell", "new_session", "session_name", "use_pty", "line_limit"
        }
        self.assertEqual(set(run_tool["inputSchema"]["properties"].keys()), expected_run_props)

    def test_read_dispatch_rejects_removed_cursor_parameter(self):
        """Opaque cursors are gone: read(session_id) continues with unread output instead."""
        node = MagicMock()
        node.alias = "srv1"
        node.get_session.return_value = MagicMock()
        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, 1, False, None)

        res = read_dispatch({"cursor": "abc123"}, manager)
        expected = {
            "success": False,
            "error": "The 'cursor' parameter was removed - read again with read(session_id) to continue with unread output",
        }
        self.assertEqual(res, expected)
        node.get_session.assert_not_called()

    def test_read_projection_reports_state_not_bookkeeping(self):
        """The agent surface carries has_more/still_running, never offsets or cursors."""
        raw = {
            "success": True, "status": "running", "output": "tail -f output",
            "session_id": "srv/1", "server": "srv",
            "has_more": True, "still_running": True,
            "next_offset": 10, "base_offset": 0, "total_chars": 100, "total_lines": 5,
            "next_line": 2, "limited": True, "next_cursor": "b3BhcXVl",
        }
        res = project_tool_result("read", raw)
        expected = {
            "output": "tail -f output",
            "server": "srv",
            "session_id": "srv/1",
            "status": "running",
            "has_more": True,
            "hint": "unread output remains - read again with read(session_id)",
            "still_running": True,
        }
        self.assertEqual(res, expected)

    def test_read_schema_documents_state(self):
        """The schema must describe line_limit and state flags."""
        tools = tools_list()["result"]["tools"]
        read_tool = next(tool for tool in tools if tool["name"] == "read")
        props = read_tool["inputSchema"]["properties"]
        expected_props = {"server", "session_id", "line_limit", "tail", "offset", "wait_timeout"}
        self.assertEqual(set(props.keys()), expected_props)
        desc = read_tool["description"]
        self.assertIn("has_more", desc)
        self.assertIn("still_running", desc)

    def test_run_and_read_schema_and_response_consistency(self):
        """Verify run and read have matching line_limit schemas and consistent projected responses."""
        tools = tools_list()["result"]["tools"]
        run_tool = next(tool for tool in tools if tool["name"] == "run")
        read_tool = next(tool for tool in tools if tool["name"] == "read")

        run_limit = run_tool["inputSchema"]["properties"]["line_limit"]
        read_limit = read_tool["inputSchema"]["properties"]["line_limit"]
        self.assertEqual(run_limit["type"], "integer")
        self.assertEqual(read_limit["type"], "integer")
        self.assertIn("200", run_limit["description"])
        self.assertIn("200", read_limit["description"])

        # Simulated response from run and read
        mock_raw = {
            "success": True,
            "output": "line 1\nline 2",
            "session_id": "srv/1",
            "server": "srv",
            "status": "completed",
            "still_running": False,
            "has_more": 0,
            "exit_status": 0,
            "in_shell": True,
            "mode": "linux_shell",
        }
        res_run = project_tool_result("run", mock_raw)
        res_read = project_tool_result("read", mock_raw)

        expected_res = {
            "output": "line 1\nline 2",
            "server": "srv",
            "session_id": "srv/1",
            "status": "completed",
            "still_running": False,
            "has_more": 0,
            "exit_status": 0,
            "in_shell": True,
            "mode": "linux_shell",
        }
        self.assertEqual(res_run, expected_res)
        self.assertEqual(res_read, expected_res)

    def test_coerce_int_arg_normalises_numbers(self):
        """R9: -0.5 floors to -1, 0.5 truncates to 0, bools/NaN/Inf are rejected as None."""
        from src.server import coerce_int_arg
        self.assertEqual(coerce_int_arg(-0.5), -1)
        self.assertEqual(coerce_int_arg(0.5), 0)
        self.assertEqual(coerce_int_arg("5"), 5)
        self.assertEqual(coerce_int_arg(" -3 "), -3)
        self.assertIsNone(coerce_int_arg(True))
        self.assertIsNone(coerce_int_arg("abc"))
        self.assertIsNone(coerce_int_arg(float("nan")))
        self.assertIsNone(coerce_int_arg(float("inf")))

if __name__ == "__main__":
    unittest.main()
