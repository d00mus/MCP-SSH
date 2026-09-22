import unittest
from unittest.mock import MagicMock, patch
import json
import tempfile
import os
import shutil
import time
import threading

from src.config import ServerTargetConfig, ServersRegistry, config
from src.manager import MultiServerManager, ServerNode
from src.session import SSHSession
from src.server import handle_request, tools_list, project_tool_result
from src.fs import file_dispatch

class TestMultiServer(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dirs = {
            "cache_root": self.test_dir,
            "sessions_dir": os.path.join(self.test_dir, "sessions"),
            "runs_dir": os.path.join(self.test_dir, "runs"),
            "locks_dir": os.path.join(self.test_dir, "locks"),
        }
        for d in self.cache_dirs.values():
            os.makedirs(d, exist_ok=True)
            
        self.registry = ServersRegistry()
        self.cfg1 = ServerTargetConfig(
            alias="keenetic",
            host="192.168.1.1",
            port=22,
            user="admin",
            password="secret_password",
            description="Keenetic Ultra router",
            read_only=False,
            command_blacklist=["reboot"]
        )
        self.cfg2 = ServerTargetConfig(
            alias="nas",
            host="192.168.1.10",
            port=22,
            user="storage",
            description="TrueNAS storage",
            read_only=False
        )
        self.cfg3 = ServerTargetConfig(
            alias="vps",
            host="203.0.113.5",
            port=2222,
            user="ubuntu",
            description="Cloud VPS",
            read_only=True,
            command_blacklist=["rm -rf"]
        )
        self.registry.register(self.cfg1)
        self.registry.register(self.cfg2)
        self.registry.register(self.cfg3)
        
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        self.manager = MultiServerManager(
            cache_dirs=self.cache_dirs,
            project_tag="test_multiserver",
            registry=self.registry
        )

    def tearDown(self):
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        self.manager.close_all()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_registry_lookup_and_prefix(self):
        # Lookup by alias (case-insensitive)
        self.assertEqual(self.registry.get("KEENETIC"), self.cfg1)
        # Lookup by host IP
        self.assertEqual(self.registry.get("192.168.1.10"), self.cfg2)
        # Lookup nonexistent
        self.assertIsNone(self.registry.get("unknown"))
        # Prefix matching
        matched = self.registry.find_by_prefix("keen")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0].alias, "keenetic")
        # Prefix matching on host
        matched_ip = self.registry.find_by_prefix("192.168.1")
        self.assertEqual(len(matched_ip), 2)

    def test_resolve_target_composite_session_id(self):
        # Format: <server>/<id>
        node, sid, new_req, err = self.manager.resolve_target(session_id="keenetic/2")
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.alias, "keenetic")
        self.assertEqual(sid, 2)
        self.assertFalse(new_req)

    def test_resolve_target_server_as_session_id(self):
        # Passing server name as session_id routes to that server without forcing a redundant new session
        res = self.manager.resolve_target(session_id="nas")
        self.assertIsNone(res.error)
        self.assertIsNotNone(res.node)
        self.assertEqual(res.node.alias, "nas")
        self.assertIsNone(res.numeric_sid)
        self.assertFalse(res.is_new_requested)

        # Also supports tuple unpacking for backward compatibility
        node, sid, new_req, err = self.manager.resolve_target(session_id="nas")
        self.assertEqual(node.alias, "nas")
        self.assertIsNone(sid)
        self.assertFalse(new_req)

    def test_resolve_target_explicit_server_and_numeric_sid(self):
        node, sid, new_req, err = self.manager.resolve_target(server="vps", session_id=3)
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.alias, "vps")
        self.assertEqual(sid, 3)
        self.assertFalse(new_req)

    def test_resolve_target_server_by_ip(self):
        node, sid, new_req, err = self.manager.resolve_target(server="192.168.1.1", session_id=1)
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.alias, "keenetic")
        self.assertEqual(sid, 1)

    def test_resolve_target_missing_server_error(self):
        node, sid, new_req, err = self.manager.resolve_target(session_id=1)
        self.assertIsNone(node)
        self.assertIsNotNone(err)
        self.assertIn("Target server is required", err)
        self.assertIn("Available servers: [keenetic, nas, vps]", err)

    def test_resolve_target_unknown_server_error(self):
        node, sid, new_req, err = self.manager.resolve_target(server="nonexistent")
        self.assertIsNone(node)
        self.assertIsNotNone(err)
        self.assertIn("Server 'nonexistent' not found", err)

    def test_resolve_target_conflicting_server_error(self):
        node, sid, new_req, err = self.manager.resolve_target(server="nas", session_id="keenetic/1")
        self.assertIsNone(node)
        self.assertIsNotNone(err)
        self.assertIn("Conflicting server parameters", err)

    def test_list_all_servers_lean_and_no_secrets(self):
        res = self.manager.list_all_servers()
        self.assertTrue(res["success"])
        servers = res["servers"]
        self.assertEqual(len(servers), 3)
        for s in servers:
            self.assertIn("alias", s)
            self.assertIn("host", s)
            self.assertIn("user", s)
            self.assertIn("status", s)
            self.assertIn("sessions", s)
            self.assertNotIn("password", s)
            self.assertNotIn("secret_password", str(s))

    def test_session_list_filter_by_prefix(self):
        node1 = self.manager.get_or_create_node(self.cfg1)
        node2 = self.manager.get_or_create_node(self.cfg2)
        
        s1 = SSHSession(1, "k1", self.cache_dirs, "test", server_config=self.cfg1)
        s1.client = MagicMock()
        s1.channel = MagicMock()
        s1.ensure_alive = MagicMock(return_value=None)
        s1.check_health = MagicMock(return_value=True)
        s1.is_alive = MagicMock(return_value=True)
        node1.sessions[1] = s1
        node1.current_session_id = 1

        s2 = SSHSession(2, "k2", self.cache_dirs, "test", server_config=self.cfg1)
        s2.client = MagicMock()
        s2.channel = MagicMock()
        s2.ensure_alive = MagicMock(return_value=None)
        s2.check_health = MagicMock(return_value=True)
        s2.is_alive = MagicMock(return_value=True)
        node1.sessions[2] = s2

        s3 = SSHSession(1, "n1", self.cache_dirs, "test", server_config=self.cfg2)
        s3.client = MagicMock()
        s3.channel = MagicMock()
        s3.ensure_alive = MagicMock(return_value=None)
        s3.check_health = MagicMock(return_value=True)
        s3.is_alive = MagicMock(return_value=True)
        node2.sessions[1] = s3
        node2.current_session_id = 1

        # 1. No filter -> returns all sessions from both servers with composite IDs
        all_res = self.manager.list_all_sessions()
        self.assertEqual(len(all_res["sessions"]), 3)
        sids = [row["session_id"] for row in all_res["sessions"]]
        self.assertIn("keenetic/1", sids)
        self.assertIn("keenetic/2", sids)
        self.assertIn("nas/1", sids)

        # 2. Filter by prefix "keen" -> only keenetic sessions, ALL of them
        filtered_res = self.manager.list_all_sessions(server_filter="keen")
        self.assertEqual(len(filtered_res["sessions"]), 2)
        filtered_sids = [row["session_id"] for row in filtered_res["sessions"]]
        self.assertIn("keenetic/1", filtered_sids)
        self.assertIn("keenetic/2", filtered_sids)

        # 3. Filter by "nas"
        nas_res = self.manager.list_all_sessions(server_filter="nas")
        self.assertEqual(len(nas_res["sessions"]), 1)
        self.assertEqual(nas_res["sessions"][0]["session_id"], "nas/1")

    def test_per_server_security_constraints(self):
        node_vps = self.manager.get_or_create_node(self.cfg3)
        node_keenetic = self.manager.get_or_create_node(self.cfg1)

        s_vps = SSHSession(1, "vps1", self.cache_dirs, "test", server_config=self.cfg3)
        s_vps.client = MagicMock()
        s_vps.channel = MagicMock()
        s_vps.ensure_alive = MagicMock(return_value=None)
        s_vps.check_health = MagicMock(return_value=True)
        node_vps.sessions[1] = s_vps

        s_keen = SSHSession(1, "k1", self.cache_dirs, "test", server_config=self.cfg1)
        s_keen.client = MagicMock()
        s_keen.channel = MagicMock()
        s_keen.ensure_alive = MagicMock(return_value=None)
        s_keen.check_health = MagicMock(return_value=True)
        node_keenetic.sessions[1] = s_keen

        # VPS is read_only
        res = s_vps.run_command("touch /tmp/test", mode="sync", shell=True, wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0, completion_hint="either", quiet_complete_timeout=0.5)
        self.assertFalse(res["success"])
        self.assertIn("read-only sandbox mode on server 'vps'", res["error"])

        # Keenetic has blacklist ["reboot"]
        res_rb = s_keen.run_command("reboot", mode="sync", shell=True, wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0, completion_hint="either", quiet_complete_timeout=0.5)
        self.assertFalse(res_rb["success"])
        self.assertIn("blocked by command blacklist on server 'keenetic'", res_rb["error"])

    def test_json_rpc_server_list_and_run_dispatch(self):
        # 1. tools/list contains 10 tools (including server_list and server_add)
        res = handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}, self.manager)
        tools = res["result"]["tools"]
        self.assertEqual(len(tools), 10)
        tool_names = [t["name"] for t in tools]
        self.assertIn("server_list", tool_names)
        self.assertIn("server_add", tool_names)

        # 2. server_list call
        res_sl = handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "server_list", "arguments": {}}}, self.manager)
        content = json.loads(res_sl["result"]["content"][0]["text"])
        self.assertIn("servers", content)
        self.assertEqual(len(content["servers"]), 3)

        # 3. run call without server -> returns error
        res_run_err = handle_request({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run", "arguments": {"command": "ls"}}}, self.manager)
        self.assertTrue(res_run_err["result"]["isError"])
        err_content = json.loads(res_run_err["result"]["content"][0]["text"])
        self.assertIn("Target server is required", err_content["error"])

    def test_file_dispatch_multiserver_readonly(self):
        # 1. file write on read_only server 'vps' is blocked
        res_write_vps = file_dispatch({"action": "write", "path": "/test.txt", "content": "data", "server": "vps"}, self.manager)
        self.assertFalse(res_write_vps["success"])
        self.assertIn("blocked in read-only sandbox mode on server 'vps'", res_write_vps["error"])

        # 2. file write on non-readonly server 'nas' reaches session
        node_nas = self.manager.get_or_create_node(self.cfg2)
        s_nas = SSHSession(1, "nas1", self.cache_dirs, "test", server_config=self.cfg2)
        s_nas.client = MagicMock()
        s_nas.channel = MagicMock()
        s_nas.ensure_alive = MagicMock(return_value=None)
        s_nas.check_health = MagicMock(return_value=True)
        node_nas.sessions[1] = s_nas
        node_nas.current_session_id = 1

        with patch('src.fs._write_remote_file_bytes') as mock_write:
            mock_write.return_value = {"success": True, "method": "sftp"}
            res_write_nas = file_dispatch({"action": "write", "path": "/test.txt", "content": "data", "server": "nas"}, self.manager)
            self.assertTrue(res_write_nas["success"])
            self.assertEqual(res_write_nas["server"], "nas")
            self.assertEqual(res_write_nas["session_id"], "nas/1")

    def test_lazy_connection(self):
        # Check that creating MultiServerManager does not instantiate any SSH connections
        reg = ServersRegistry()
        reg.register(ServerTargetConfig(alias="srv1", host="192.0.2.1", user="u1"))
        reg.register(ServerTargetConfig(alias="srv2", host="192.0.2.2", user="u2"))
        mgr = MultiServerManager(cache_dirs=self.cache_dirs, project_tag="test_lazy", registry=reg)
        try:
            # Nodes dictionary is empty at start
            self.assertEqual(len(mgr.nodes), 0)
            # listing all servers does not connect to anything
            sl = mgr.list_all_servers()
            self.assertEqual(len(sl["servers"]), 2)
            for s in sl["servers"]:
                self.assertEqual(s["status"], "configured")
                self.assertEqual(s["sessions"], 0)
            # Nodes still not created or have 0 sessions
            for node in mgr.nodes.values():
                self.assertEqual(len(node.sessions), 0)
        finally:
            mgr.close_all()

    def test_json_config_loading_from_file(self):
        config_path = os.path.join(self.test_dir, "test_servers.json")
        sample_data = {
            "servers": {
                "router": {
                    "host": "192.168.1.1",
                    "port": 222,
                    "user": "root",
                    "description": "Main router",
                    "read_only": False
                },
                "backup": {
                    "host": "10.0.0.5",
                    "port": 22,
                    "user": "bak",
                    "read_only": True
                }
            }
        }
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(sample_data, f)

        loaded_reg = ServersRegistry()
        loaded_reg.load_from_file(config_path)
        self.assertEqual(loaded_reg.count(), 2)
        r_cfg = loaded_reg.get("router")
        self.assertIsNotNone(r_cfg)
        self.assertEqual(r_cfg.port, 222)
        self.assertEqual(r_cfg.user, "root")
        b_cfg = loaded_reg.get("backup")
        self.assertIsNotNone(b_cfg)
        self.assertTrue(b_cfg.read_only)

    def test_mcp_servers_format_loading(self):
        mcp_data = {
            "mcpServers": {
                "keenetic_mcp": {
                    "command": "python",
                    "args": ["mcp-server.py", "--host", "192.168.220.1", "--user", "admin", "--port", "22", "--no-verify-host"],
                    "env": {"SSH_PASSWORD": "SecretPassword123"}
                }
            }
        }
        loaded_reg = ServersRegistry()
        loaded_reg.load_from_dict(mcp_data)
        self.assertEqual(loaded_reg.count(), 1)
        cfg = loaded_reg.get("keenetic_mcp")
        self.assertIsNotNone(cfg)
        self.assertEqual(cfg.host, "192.168.220.1")
        self.assertEqual(cfg.user, "admin")
        self.assertEqual(cfg.password, "SecretPassword123")
        self.assertFalse(cfg.verify_host)

    def test_session_close_and_update_multiserver(self):
        node = self.manager.get_or_create_node(self.cfg1)
        s1 = SSHSession(1, "s1", self.cache_dirs, "test", server_config=self.cfg1)
        s1.client = MagicMock()
        s1.channel = MagicMock()
        s1.ensure_alive = MagicMock(return_value=None)
        s1.check_health = MagicMock(return_value=True)
        node.sessions[1] = s1
        node.current_session_id = 1

        # 1. Update session name
        res_upd = self.manager.update_session(server="keenetic", session_id=1, name="renamed_session")
        self.assertTrue(res_upd["success"])
        self.assertEqual(s1.name, "renamed_session")

        # 2. Close session using composite id
        res_close = self.manager.close_session(session_id="keenetic/1")
        self.assertTrue(res_close["success"])
        self.assertNotIn(1, node.sessions)

    def test_env_var_interpolation_in_config(self):
        os.environ["TEST_SSH_PASS"] = "interpolated_pass_123"
        os.environ["TEST_SSH_HOST"] = "10.20.30.40"
        try:
            sample_data = {
                "servers": {
                    "env_target": {
                        "host": "${TEST_SSH_HOST}",
                        "user": "env_user",
                        "password": "${TEST_SSH_PASS}",
                        "key_path": "~/.ssh/${TEST_SSH_USER:-id_rsa}"
                    }
                }
            }
            reg = ServersRegistry()
            reg.load_from_dict(sample_data)
            cfg = reg.get("env_target")
            self.assertIsNotNone(cfg)
            self.assertEqual(cfg.host, "10.20.30.40")
            self.assertEqual(cfg.password, "interpolated_pass_123")
        finally:
            os.environ.pop("TEST_SSH_PASS", None)
            os.environ.pop("TEST_SSH_HOST", None)

    def test_run_command_security_readonly_and_blacklist(self):
        sec_cfg = ServerTargetConfig(
            alias="vps_sec",
            host="10.0.0.1",
            read_only=True,
            command_blacklist=["reboot", "poweroff"]
        )
        s2 = SSHSession(1, "s2", self.cache_dirs, "test", server_config=sec_cfg)
        s2.client = MagicMock()
        s2.ensure_alive = MagicMock(return_value=None)
        s2.is_busy = MagicMock(return_value=False)

        # 1. Command blocked by read_only
        res_rm = s2.run_command(
            command="rm -rf /tmp/data", mode="sync", shell=True,
            wait_timeout=10.0, startup_wait=1.0, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5
        )
        self.assertFalse(res_rm["success"])
        self.assertIn("blocked in read-only sandbox mode", res_rm["error"])

        # 2. Command blocked by command_blacklist
        res_reb = s2.run_command(
            command="reboot", mode="sync", shell=True,
            wait_timeout=10.0, startup_wait=1.0, hard_timeout=0.0,
            completion_hint="either", quiet_complete_timeout=0.5
        )
        self.assertFalse(res_reb["success"])
        self.assertIn("blocked by command blacklist", res_reb["error"])

    def test_command_blacklist_union_merging(self):
        orig_global = list(config.COMMAND_BLACKLIST)
        try:
            config.COMMAND_BLACKLIST = ["global_forbidden_tool"]
            sec_cfg = ServerTargetConfig(
                alias="server_bl",
                host="10.0.0.1",
                read_only=False,
                command_blacklist=["server_bad_cmd"]
            )
            s = SSHSession(1, "s", self.cache_dirs, "test", server_config=sec_cfg)
            s.ensure_alive = MagicMock(return_value=None)

            # Blocked by server-specific blacklist
            res_server = s.run_command(command="server_bad_cmd --opt", mode="sync", shell=False, wait_timeout=10, startup_wait=1, hard_timeout=0, completion_hint="either", quiet_complete_timeout=2)
            self.assertFalse(res_server["success"])
            self.assertIn("blocked by command blacklist", res_server["error"])

            # Blocked by global blacklist (union behavior)
            res_global = s.run_command(command="global_forbidden_tool --flag", mode="sync", shell=False, wait_timeout=10, startup_wait=1, hard_timeout=0, completion_hint="either", quiet_complete_timeout=2)
            self.assertFalse(res_global["success"])
            self.assertIn("blocked by command blacklist", res_global["error"])
        finally:
            config.COMMAND_BLACKLIST = orig_global

    def test_hot_reload_lifecycle(self):
        cfg_file = os.path.join(self.test_dir, "hot_reload_servers.json")
        initial_data = {
            "servers": {
                "alpha": {"host": "1.1.1.1", "user": "u1", "port": 22},
                "beta": {"host": "2.2.2.2", "user": "u2", "port": 22, "read_only": False}
            }
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(initial_data, f)

        reg = ServersRegistry()
        reg.load_from_file(cfg_file)
        mgr = MultiServerManager(self.cache_dirs, "hot_test", registry=reg, config_path=cfg_file)
        try:
            node_alpha = mgr.get_or_create_node(reg.get("alpha"))
            s_alpha = SSHSession(1, "s1", self.cache_dirs, "test", server_config=reg.get("alpha"))
            s_alpha.client = MagicMock()
            s_alpha.ensure_alive = MagicMock(return_value=None)
            node_alpha.sessions[1] = s_alpha

            node_beta = mgr.get_or_create_node(reg.get("beta"))
            s_beta = SSHSession(1, "s1", self.cache_dirs, "test", server_config=reg.get("beta"))
            s_beta.client = MagicMock()
            s_beta.ensure_alive = MagicMock(return_value=None)
            node_beta.sessions[1] = s_beta

            # 1. Update config on disk:
            # - add "gamma"
            # - modify "alpha" credentials (port 22 -> 2222) -> alpha sessions should reset
            # - modify "beta" metadata only (read_only False -> True) -> beta session should survive
            # Let time advance to ensure mtime changes
            time.sleep(0.05)
            updated_data = {
                "servers": {
                    "alpha": {"host": "1.1.1.1", "user": "u1", "port": 2222},
                    "beta": {"host": "2.2.2.2", "user": "u2", "port": 22, "read_only": True},
                    "gamma": {"host": "3.3.3.3", "user": "u3", "port": 22}
                }
            }
            with open(cfg_file, "w", encoding="utf-8") as f:
                json.dump(updated_data, f)

            reload_res = mgr.check_reload(force=True)
            self.assertTrue(reload_res["reloaded"])
            self.assertIn("gamma", reload_res["added"])
            self.assertIn("alpha", reload_res["modified"])
            self.assertIn("beta", reload_res["modified"])

            # Verify alpha's sessions were closed due to credential change
            self.assertEqual(len(node_alpha.sessions), 0)

            # Verify beta's sessions survived zero-downtime metadata reload
            self.assertEqual(len(node_beta.sessions), 1)
            self.assertTrue(node_beta.server_config.read_only)

            # Verify gamma is in registry and can be resolved
            gamma_res = mgr.resolve_target(server="gamma")
            self.assertIsNotNone(gamma_res.node)
            self.assertEqual(gamma_res.node.alias, "gamma")

            # 2. Remove "alpha" from config
            time.sleep(0.05)
            del updated_data["servers"]["alpha"]
            with open(cfg_file, "w", encoding="utf-8") as f:
                json.dump(updated_data, f)

            reload_res2 = mgr.check_reload(force=True)
            self.assertTrue(reload_res2["reloaded"])
            self.assertIn("alpha", reload_res2["removed"])
            self.assertIsNone(mgr.registry.get("alpha"))
        finally:
            mgr.close_all()

    def test_server_add_append_only(self):
        cfg_file = os.path.join(self.test_dir, "append_servers.json")
        initial_data = {
            "servers": {
                "existing_host": {"host": "10.0.0.1", "user": "root", "port": 22}
            }
        }
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump(initial_data, f)

        reg = ServersRegistry()
        reg.load_from_file(cfg_file)
        mgr = MultiServerManager(self.cache_dirs, "append_test", registry=reg, config_path=cfg_file)
        try:
            # 1. Add new server via server_add -> succeeds
            req_add = {
                "jsonrpc": "2.0", "id": 10, "method": "tools/call",
                "params": {
                    "name": "server_add",
                    "arguments": {
                        "alias": "new_edge",
                        "host": "10.0.0.2",
                        "user": "admin",
                        "port": 2200,
                        "description": "Edge node"
                    }
                }
            }
            res_add = handle_request(req_add, mgr)
            content = json.loads(res_add["result"]["content"][0]["text"])
            self.assertTrue(content["success"])
            self.assertIn("added successfully", content["message"])
            self.assertIsNotNone(mgr.registry.get("new_edge"))

            # 2. Attempt to add existing server -> fails with forbidden modification
            req_dup = {
                "jsonrpc": "2.0", "id": 11, "method": "tools/call",
                "params": {
                    "name": "server_add",
                    "arguments": {
                        "alias": "new_edge",
                        "host": "10.0.0.99",
                        "user": "hacker"
                    }
                }
            }
            res_dup = handle_request(req_dup, mgr)
            self.assertTrue(res_dup["result"]["isError"])
            err_content = json.loads(res_dup["result"]["content"][0]["text"])
            self.assertIn("already exists", err_content["error"])
            self.assertIn("Modifying or deleting existing servers via MCP is forbidden", err_content["error"])

            # Verify existing server wasn't modified
            cfg_edge = mgr.registry.get("new_edge")
            self.assertEqual(cfg_edge.host, "10.0.0.2")
        finally:
            mgr.close_all()

    def test_find_first_idle_alive_session_thread_safe(self):
        node = self.manager.get_or_create_node(self.cfg1)
        s1 = SSHSession(1, "s1", self.cache_dirs, "test", server_config=self.cfg1)
        s1.client = MagicMock()
        s1.ensure_alive = MagicMock(return_value=None)
        s1.is_busy = MagicMock(return_value=False)
        node.sessions[1] = s1

        # Simulate concurrent deletion while finding session
        def delete_session():
            time.sleep(0.001)
            with node.lock:
                node.sessions.pop(1, None)

        t = threading.Thread(target=delete_session)
        t.start()
        # Should not throw KeyError
        res = node.find_first_idle_alive_session()
        t.join()
        # Result is either s1 or None, but never KeyError
        self.assertTrue(res is s1 or res is None)

    def test_max_sessions_limit(self):
        cfg = ServerTargetConfig(alias="test_lim", host="10.0.0.1", user="u", max_sessions=2)
        self.manager.registry.register(cfg)
        node = self.manager.get_or_create_node(cfg)
        with patch.object(SSHSession, 'connect', return_value=True):
            r1 = node.open_session("s1")
            self.assertTrue(r1["success"])
            r2 = node.open_session("s2")
            self.assertTrue(r2["success"])
            r3 = node.open_session("s3")
            self.assertFalse(r3["success"])
            self.assertIn("Max sessions limit (2) reached", r3["error"])

    def test_hot_reload_throttling(self):
        cfg_file = os.path.join(self.test_dir, "servers.json")
        with open(cfg_file, "w") as f:
            json.dump({"servers": {"s1": {"host": "1.1.1.1", "user": "u"}}}, f)

        mgr = MultiServerManager(self.cache_dirs, "test_proj", config_path=cfg_file)
        try:
            # First check reload: config file hasn't changed since __init__
            res1 = mgr.check_reload()
            self.assertFalse(res1["reloaded"])
            self.assertEqual(res1.get("reason"), "mtime_unchanged")

            # Immediate second check should be throttled
            res2 = mgr.check_reload()
            self.assertFalse(res2["reloaded"])
            self.assertEqual(res2.get("reason"), "throttled")

            # Force check should bypass throttle and force reload (adds s1 since it wasn't in registry yet)
            res3 = mgr.check_reload(force=True)
            self.assertTrue(res3["reloaded"])
            self.assertIn("s1", res3["added"])
        finally:
            mgr.close_all()

    def test_concurrent_check_reload_thread_safety(self):
        """Verify concurrent calls to check_reload(force=True) are serialized by _reload_lock."""
        cfg_file = os.path.join(self.test_dir, "concurrent_reload_servers.json")
        with open(cfg_file, "w") as f:
            json.dump({"servers": {"host0": {"host": "10.0.0.1", "user": "u"}}}, f)

        mgr = MultiServerManager(self.cache_dirs, "test_proj", config_path=cfg_file)
        try:
            results = []
            errors = []

            def worker(worker_id):
                try:
                    res = mgr.check_reload(force=True)
                    results.append((worker_id, res))
                except Exception as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(errors), 0, f"Errors during concurrent reload: {errors}")
            self.assertEqual(len(results), 10)
            added_counts = sum(1 for _, r in results if "host0" in r.get("added", []))
            self.assertEqual(added_counts, 1)
        finally:
            mgr.close_all()

    def test_servers_registry_thread_safety(self):
        reg = ServersRegistry()
        stop_event = threading.Event()
        errors = []

        def writer():
            idx = 0
            while not stop_event.is_set():
                alias = f"srv_{idx % 20}"
                reg.register(ServerTargetConfig(alias=alias, host=f"10.0.0.{idx % 20}", user="u"))
                if idx % 5 == 0:
                    reg.unregister(f"srv_{(idx + 1) % 20}")
                idx += 1
                time.sleep(0.0001)

        def reader():
            while not stop_event.is_set():
                try:
                    _ = reg.list_all()
                    _ = reg.find_by_prefix("srv")
                    _ = reg.aliases()
                    _ = reg.get("srv_1")
                except Exception as exc:
                    errors.append(exc)
                time.sleep(0.0001)

        threads = [
            threading.Thread(target=writer),
            threading.Thread(target=reader),
            threading.Thread(target=reader)
        ]
        for t in threads:
            t.start()

        time.sleep(0.2)
        stop_event.set()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])

    def test_apply_config_diff_closes_nodes_outside_lock(self):
        mgr = MultiServerManager(self.cache_dirs, "test_proj")
        try:
            cfg = ServerTargetConfig(alias="old_host", host="10.0.0.1", user="u")
            mgr.registry.register(cfg)
            node = mgr.get_or_create_node(cfg)
            node.close_all = MagicMock()

            # Apply diff where old_host is removed
            new_data = {
                "servers": {
                    "new_host": {"host": "10.0.0.2", "user": "u"}
                }
            }
            res = mgr._apply_config_diff(new_data)
            self.assertIn("old_host", res["removed"])
            self.assertIn("new_host", res["added"])
            # Node should have been closed
            node.close_all.assert_called_once()
        finally:
            mgr.close_all()

    def test_registry_as_dict(self):
        reg = ServersRegistry()
        cfg1 = ServerTargetConfig(alias="a", host="1.1.1.1", user="u")
        cfg2 = ServerTargetConfig(alias="b", host="2.2.2.2", user="u")
        reg.register(cfg1)
        reg.register(cfg2)
        d = reg.as_dict()
        self.assertEqual(len(d), 2)
        self.assertIn("a", d)
        self.assertIn("b", d)
        self.assertIs(d["a"], cfg1)

    def test_total_buffer_chars(self):
        node = self.manager.get_or_create_node(self.cfg1)
        s1 = SSHSession(1, "s1", self.cache_dirs, "test", server_config=self.cfg1)
        s1.runs[1] = MagicMock(output_buffer="12345")
        s1.runs[2] = MagicMock(output_buffer="6789")
        node.sessions[1] = s1

        total = node.total_buffer_chars()
        self.assertEqual(total, 9)

    def test_max_sessions_concurrent_race(self):
        """Verify atomic pending reservation prevents exceeding max_sessions during concurrent connections."""
        import concurrent.futures
        cfg = ServerTargetConfig(alias="race_srv", host="10.0.0.1", user="u", max_sessions=3)
        node = ServerNode(cfg, self.cache_dirs, "test_proj")

        def mock_connect(session_self):
            time.sleep(0.02)
            return True

        with patch.object(SSHSession, 'connect', mock_connect):
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                futures = [ex.submit(node.open_session) for _ in range(10)]
                results = [f.result() for f in futures]

        successes = [r for r in results if r.get("success") is True]
        failures = [r for r in results if not r.get("success") and "Max sessions limit" in r.get("error", "")]

        self.assertEqual(len(successes), 3, "Only 3 sessions must be created")
        self.assertEqual(len(failures), 7, "7 sessions must be rejected by session cap")
        self.assertEqual(len(node.sessions), 3)

    def test_find_first_idle_alive_session_uses_is_alive(self):
        """Verify idle alive search uses lightweight is_alive check without invoking reconnect."""
        cfg = ServerTargetConfig(alias="idle_test", host="10.0.0.1", user="u")
        node = ServerNode(cfg, self.cache_dirs, "test_proj")

        s1 = SSHSession(1, "s1", self.cache_dirs, "test", server_config=cfg)
        s1.is_dead = True

        s2 = SSHSession(2, "s2", self.cache_dirs, "test", server_config=cfg)
        s2.is_dead = False
        s2.is_alive = MagicMock(return_value=False)
        s2.reconnect = MagicMock()

        s3 = SSHSession(3, "s3", self.cache_dirs, "test", server_config=cfg)
        s3.is_dead = False
        s3.is_alive = MagicMock(return_value=True)
        s3.is_busy = MagicMock(return_value=False)

        node.sessions = {1: s1, 2: s2, 3: s3}

        found = node.find_first_idle_alive_session()
        self.assertIs(found, s3)
        s2.reconnect.assert_not_called()

    def test_resolve_target_for_args_comprehensive(self):
        """Verify resolve_target_for_args handles all routing parameter combinations."""
        mgr = MultiServerManager(self.cache_dirs, "test_proj", registry=self.registry)
        try:
            # 1. Missing target server
            node, sid, new_req, err = mgr.resolve_target_for_args({})
            self.assertIsNotNone(err)
            self.assertIn("Target server is required", err["error"])

            # 2. Valid server alias
            node, sid, new_req, err = mgr.resolve_target_for_args({"server": "keenetic"})
            self.assertIsNone(err)
            self.assertIsNotNone(node)
            self.assertEqual(node.alias, "keenetic")
            self.assertIsNone(sid)

            # 3. Composite server/session_id
            node, sid, new_req, err = mgr.resolve_target_for_args({"session_id": "vps/4"})
            self.assertIsNone(err)
            self.assertIsNotNone(node)
            self.assertEqual(node.alias, "vps")
            self.assertEqual(sid, 4)

            # 4. Conflicting server and composite session_id
            node, sid, new_req, err = mgr.resolve_target_for_args({"server": "keenetic", "session_id": "vps/4"})
            self.assertIsNotNone(err)
            self.assertIn("Conflicting server parameters", err["error"])

            # 5. Nonexistent server
            node, sid, new_req, err = mgr.resolve_target_for_args({"server": "ghost"})
            self.assertIsNotNone(err)
            self.assertIn("Server 'ghost' not found", err["error"])
        finally:
            mgr.close_all()

    def test_hot_reload_credential_change_pops_node(self):
        """Verify credential modifications pop old node from nodes dict (Fix H1)."""
        mgr = MultiServerManager(self.cache_dirs, "test_proj")
        try:
            cfg_old = ServerTargetConfig(alias="vps1", host="1.1.1.1", user="root", port=22)
            mgr.registry.register(cfg_old)
            old_node = mgr.get_or_create_node(cfg_old)
            old_node.close_all = MagicMock()

            # Modify credentials (host changed)
            new_data = {
                "servers": {
                    "vps1": {"host": "1.1.1.2", "user": "root", "port": 22}
                }
            }
            res = mgr._apply_config_diff(new_data)
            self.assertIn("vps1", res["modified"])

            # Old node should be closed
            old_node.close_all.assert_called_once()

            # Old node is no longer in mgr.nodes
            self.assertNotIn("vps1", mgr.nodes)

            # Subsequent call creates fresh node with new host
            new_node = mgr.get_node("vps1")
            self.assertIsNot(new_node, old_node)
            self.assertEqual(new_node.server_config.host, "1.1.1.2")
        finally:
            mgr.close_all()

    def test_server_add_concurrent_race(self):
        """Verify concurrent server_add calls from multiple threads do not corrupt config (Fix H2)."""
        import concurrent.futures
        cfg_file = os.path.join(self.test_dir, "concurrent_servers.json")
        with open(cfg_file, "w", encoding="utf-8") as f:
            json.dump({"servers": {}}, f)

        reg = ServersRegistry()
        mgr = MultiServerManager(self.cache_dirs, "test_proj", registry=reg, config_path=cfg_file)
        try:
            from src.server import server_add_dispatch

            def add_worker(idx):
                args = {
                    "alias": f"srv_{idx}",
                    "host": f"10.0.0.{idx}",
                    "user": "root",
                    "port": 22
                }
                return server_add_dispatch(args, mgr)

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                futures = [ex.submit(add_worker, i) for i in range(10)]
                results = [f.result() for f in futures]

            successes = [r for r in results if r.get("success") is True]
            self.assertEqual(len(successes), 10)

            with open(cfg_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(len(saved["servers"]), 10)
        finally:
            mgr.close_all()

    def test_hot_reload_propagates_security_to_active_sessions(self):
        """Verify modifying security settings in hot-reload propagates to active sessions."""
        mgr = MultiServerManager(self.cache_dirs, "test_proj")
        try:
            cfg = ServerTargetConfig(alias="srv_sec", host="10.0.0.1", user="u", command_blacklist=[])
            mgr.registry.register(cfg)
            node = mgr.get_or_create_node(cfg)
            s = SSHSession(1, "s1", mgr.cache_dirs, "test", server_config=cfg)
            s.ensure_alive = MagicMock(return_value=None)
            node.sessions[1] = s

            # Initially curl is permitted
            res_before = s.run_command(command="curl http://example.com", mode="sync", shell=False, wait_timeout=1, startup_wait=0.1, hard_timeout=0, completion_hint="either", quiet_complete_timeout=0.1)
            # Fails on missing client, not blacklist
            self.assertNotIn("blocked by command blacklist", res_before.get("error", ""))

            # Reload with blacklist containing curl
            new_data = {
                "servers": {
                    "srv_sec": {
                        "host": "10.0.0.1",
                        "user": "u",
                        "port": 22,
                        "command_blacklist": ["curl"]
                    }
                }
            }
            res_diff = mgr._apply_config_diff(new_data)
            self.assertIn("srv_sec", res_diff["modified"])

            # Verify active session config was updated
            self.assertIn("curl", s.server_config.command_blacklist)
            # Now curl must be blocked by security check on that active session!
            res_after = s.run_command(command="curl http://example.com", mode="sync", shell=False, wait_timeout=1, startup_wait=0.1, hard_timeout=0, completion_hint="either", quiet_complete_timeout=0.1)
            self.assertFalse(res_after["success"])
            self.assertIn("blocked by command blacklist", res_after["error"])
        finally:
            mgr.close_all()

    def test_purge_dead_sessions_at_limit(self):
        """Verify dead sessions are purged when max_sessions is reached."""
        cfg = ServerTargetConfig(alias="auto_test", host="10.0.0.1", user="u", max_sessions=2)
        self.manager.registry.register(cfg)
        node = self.manager.get_or_create_node(cfg)
        node.next_session_id = 3

        s1 = SSHSession(1, "main_s", self.cache_dirs, "test", server_config=cfg)
        s1.connect = MagicMock(return_value=True)
        s1.is_dead = False
        s1.is_alive = MagicMock(return_value=True)
        node.sessions[1] = s1

        s2 = SSHSession(2, "dead_s", self.cache_dirs, "test", server_config=cfg)
        s2.connect = MagicMock(return_value=True)
        s2.is_dead = True
        s2.is_alive = MagicMock(return_value=False)
        node.sessions[2] = s2

        # Both slots are full (len=2 == max_sessions).
        # Opening a 3rd session should purge dead session s2!
        with patch.object(SSHSession, 'connect', return_value=True):
            res = node.open_session(name="fresh_session", make_current=False)
            self.assertTrue(res["success"])
            self.assertEqual(res["numeric_session_id"], 3)
            # Session 2 was purged, Session 1 was kept
            self.assertNotIn(2, node.sessions)
            self.assertIn(1, node.sessions)
            self.assertIn(3, node.sessions)

    def test_close_session_cleans_last_tool_result_cache(self):
        """Verify last_tool_result_by_session is cleared on close_session (Fix 4.4)."""
        cfg = ServerTargetConfig(alias="clean_test", host="10.0.0.1", user="u")
        self.manager.registry.register(cfg)
        node = self.manager.get_or_create_node(cfg)
        s = SSHSession(1, "s1", self.cache_dirs, "test", server_config=cfg)
        s.close = MagicMock()
        node.sessions[1] = s
        node.last_tool_result_by_session[1] = {"output": "heavy memory payload"}

        node.close_session(1)
        self.assertNotIn(1, node.last_tool_result_by_session)

    def test_write_command_pattern_security_filter(self):
        """Verify WRITE_COMMAND_PATTERN avoids false positives on awk comparisons and log names (Fix 5.3)."""
        from src.security import WRITE_COMMAND_PATTERN
        # False positives that must NOT match
        self.assertIsNone(WRITE_COMMAND_PATTERN.search("awk '$1 > 10'"))
        self.assertIsNone(WRITE_COMMAND_PATTERN.search("find . -size +10M"))
        self.assertIsNone(WRITE_COMMAND_PATTERN.search("cat install.log"))
        self.assertIsNone(WRITE_COMMAND_PATTERN.search("which install"))
        self.assertIsNone(WRITE_COMMAND_PATTERN.search("grep '>>' text.txt"))

        # True writes that MUST match
        self.assertIsNotNone(WRITE_COMMAND_PATTERN.search("echo hello > test.txt"))
        self.assertIsNotNone(WRITE_COMMAND_PATTERN.search("echo hello >> test.txt"))
        self.assertIsNotNone(WRITE_COMMAND_PATTERN.search("mkdir /tmp/new_dir"))
        self.assertIsNotNone(WRITE_COMMAND_PATTERN.search("make install"))
        self.assertIsNotNone(WRITE_COMMAND_PATTERN.search("install -m 755 binary /usr/bin/"))
        self.assertIsNotNone(WRITE_COMMAND_PATTERN.search("install foo /bin"))

    def test_project_tool_result_binary_hidden(self):
        """Verify project_tool_result preserves binary_hidden message and size (Fix 5.1)."""
        from src.server import project_tool_result
        raw_res = {
            "success": True,
            "action": "read",
            "mode": "binary_hidden",
            "message": "File is binary. Content hidden.",
            "size": 1024,
            "sha256": "abcdef123456"
        }
        projected = project_tool_result("file", raw_res)
        self.assertEqual(projected["mode"], "binary_hidden")
        self.assertEqual(projected["size"], 1024)
        self.assertEqual(projected["message"], "File is binary. Content hidden.")
        self.assertEqual(projected["sha256"], "abcdef123456")

    def test_run_dispatch_target_sid_busy_fails_clearly(self):
        """Verify run_dispatch fails clearly when session is busy without silent fallback."""
        from src.server import run_dispatch
        node = self.manager.get_or_create_node(self.cfg1)
        s1 = SSHSession(1, "s1", self.cache_dirs, "test", server_config=self.cfg1)
        s1.ensure_alive = MagicMock(return_value=None)
        s1.is_busy = MagicMock(return_value=True)
        s1.busy_info = MagicMock(return_value={"type": "run", "id": 10})
        node.sessions[1] = s1

        args = {"server": self.cfg1.alias, "session_id": f"{self.cfg1.alias}/1", "command": "ls"}
        res = run_dispatch(args, self.manager)
        self.assertFalse(res["success"])
        self.assertIn("busy", res["error"].lower())

    def test_total_buffer_chars_caching(self):
        """Verify MultiServerManager.total_buffer_chars caches results for fast repeated calls."""
        mgr = MultiServerManager(self.cache_dirs, "test_cache")
        try:
            mgr.registry.register(self.cfg1)
            node = mgr.get_or_create_node(self.cfg1)
            node.total_buffer_chars = MagicMock(return_value=500)

            # First call computes and caches
            c1 = mgr.total_buffer_chars()
            self.assertEqual(c1, 500)
            self.assertEqual(node.total_buffer_chars.call_count, 1)

            # Second call within 250ms uses cache without calling node.total_buffer_chars again
            c2 = mgr.total_buffer_chars()
            self.assertEqual(c2, 500)
            self.assertEqual(node.total_buffer_chars.call_count, 1)
        finally:
            mgr.close_all()

    def test_server_node_epoch_closes_connecting_session_if_node_closed(self):
        """Verify ServerNode.open_session detects node closure / epoch change and prevents zombie sessions."""
        node = self.manager.get_or_create_node(self.cfg1)

        def mock_connect_that_closes_node(self_session):
            # Simulate node.close_all() being called while connect is in progress
            node.close_all()
            return True

        with patch.object(SSHSession, 'connect', mock_connect_that_closes_node), \
             patch.object(SSHSession, 'close') as mock_close:
            res = node.open_session("test_epoch")
            self.assertFalse(res["success"])
            self.assertIn("closed", res["error"].lower())
            # Ensure session.close() was called to prevent zombie
            self.assertTrue(mock_close.called)
            # Ensure no sessions are in node.sessions
            self.assertEqual(len(node.sessions), 0)

    def test_cleanup_old_logs_removes_aged_files(self):
        """Verify cleanup_old_logs deletes files older than threshold."""
        from src.utils import cleanup_old_logs

        runs_dir = self.cache_dirs["runs_dir"]
        old_file = os.path.join(runs_dir, "test_old.log")
        fresh_file = os.path.join(runs_dir, "test_fresh.log")

        with open(old_file, "w") as f:
            f.write("old log content\n")
        with open(fresh_file, "w") as f:
            f.write("fresh log content\n")

        # Set old_file modification time to 10 days ago
        ten_days_ago = time.time() - (10 * 86400)
        os.utime(old_file, (ten_days_ago, ten_days_ago))

        # Run cleanup with max_age_seconds = 7 days
        cleaned = cleanup_old_logs(self.cache_dirs, max_age_seconds=7 * 86400)
        self.assertGreaterEqual(cleaned, 1)
        self.assertFalse(os.path.exists(old_file))
        self.assertTrue(os.path.exists(fresh_file))

    def test_record_tool_result_sanitizes_passwords_and_truncates(self):
        """Verify record_tool_result masks sensitive credentials and limits huge outputs."""
        sensitive_args = {
            "server": "keenetic",
            "password": "super_secret_pw",
            "key_passphrase": "secret_key_pass",
            "key_path": "/home/user/.ssh/id_rsa",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            "key_file": "secret.pem",
            "normal_arg": "value"
        }
        res_payload = {
            "success": True,
            "password": "plain_text_pw",
            "key_path": "/root/.ssh/id_ed25519",
            "output": "X" * 20000
        }

        self.manager.record_tool_result("keenetic", "server_add", sensitive_args, res_payload)
        last_details = self.manager.get_last_tool_result("keenetic", 1)

        # Ensure secrets are masked in args
        self.assertEqual(last_details["args"]["password"], "******")
        self.assertEqual(last_details["args"]["key_passphrase"], "******")
        self.assertEqual(last_details["args"]["key_path"], "******")
        self.assertEqual(last_details["args"]["private_key"], "******")
        self.assertEqual(last_details["args"]["key_file"], "******")
        self.assertEqual(last_details["args"]["normal_arg"], "value")

        # Ensure secrets in result are masked and large output truncated
        self.assertEqual(last_details["result"]["password"], "******")
        self.assertEqual(last_details["result"]["key_path"], "******")
        self.assertLess(len(last_details["result"]["output"]), 20000)
        self.assertIn("[truncated", last_details["result"]["output"])

    def test_dispute_epoch_still_drops_inflight_session(self):
        node = self.manager.get_or_create_node(self.cfg1)

        def connect_and_close(self_session):
            node.close_all()
            return True

        with patch.object(SSHSession, "connect", connect_and_close):
            result = node.open_session("inflight")
        self.assertFalse(result["success"])
        self.assertNotIn(result.get("numeric_session_id"), node.sessions)
        self.assertEqual(len(node.sessions), 0)

    def test_dispute_removed_server_is_not_resurrected(self):
        cfg = ServerTargetConfig(alias="gone", host="10.8.8.8", user="u")
        self.manager.registry.register(cfg)
        self.manager.registry.unregister("gone")
        self.assertIsNone(self.manager.get_or_create_node(cfg))
        self.assertNotIn("gone", self.manager.nodes)

    def test_dispute_purge_clears_dead_session(self):
        cfg = ServerTargetConfig(alias="purge_cur", host="10.1.1.1", user="u", max_sessions=1)
        self.manager.registry.register(cfg)
        node = self.manager.get_or_create_node(cfg)
        dead = SSHSession(1, "old", self.cache_dirs, "test", server_config=cfg)
        dead.is_dead = True
        dead.close = MagicMock()
        node.sessions[1] = dead
        node.next_session_id = 2
        with patch.object(SSHSession, "connect", return_value=True):
            result = node.open_session(name="fresh", make_current=False)
        self.assertTrue(result["success"])
        self.assertNotIn(1, node.sessions)
        dead.close.assert_called()

    def test_dispute_max_sessions_fails_without_waiting(self):
        cfg = ServerTargetConfig(alias="no_queue", host="10.3.3.3", user="u", max_sessions=1)
        self.manager.registry.register(cfg)
        node = self.manager.get_or_create_node(cfg)
        held = SSHSession(1, "held", self.cache_dirs, "test", server_config=cfg)
        held.is_dead = False
        held.close = MagicMock()
        node.sessions[1] = held
        node.current_session_id = 1
        node.next_session_id = 2
        started = time.time()
        result = node.open_session(name="another", make_current=False)
        elapsed = time.time() - started
        self.assertFalse(result["success"])
        self.assertIn("Max sessions", result["error"])
        self.assertLess(elapsed, 0.3)

    def test_cli_host_survives_hot_reload(self):
        cfg = ServerTargetConfig(alias="legacy", host="10.4.4.4", user="u", origin="cli")
        self.manager.registry.register(cfg)
        node = self.manager.get_or_create_node(cfg)
        node.close_all = MagicMock()
        diff = self.manager._apply_config_diff({
            "servers": {"other": {"host": "10.5.5.5", "user": "u"}}
        })
        self.assertNotIn("legacy", diff["removed"])
        self.assertIsNotNone(self.manager.registry.get("legacy"))
        self.assertIn("legacy", self.manager.nodes)
        node.close_all.assert_not_called()

    def test_ensure_session_does_not_open_two(self):
        cfg = ServerTargetConfig(alias="one", host="10.0.0.1", user="u")
        node = ServerNode(cfg, self.cache_dirs, "ensure")
        started = threading.Event()
        release = threading.Event()
        calls = []

        def slow_connect(session):
            calls.append(1)
            started.set()
            release.wait(2)
            session.is_dead = False
            session.client = MagicMock()
            session.channel = MagicMock()
            session.channel.closed = False
            return True

        try:
            with patch.object(SSHSession, "connect", slow_connect):
                results = []

                def worker():
                    results.append(node.ensure_session())

                first = threading.Thread(target=worker)
                second = threading.Thread(target=worker)
                first.start()
                self.assertTrue(started.wait(2))
                second.start()
                time.sleep(0.05)
                release.set()
                first.join(2)
                second.join(2)
            self.assertEqual(calls, [1])
            self.assertEqual(len(results), 2)
            self.assertIsNotNone(results[0])
            self.assertIsNotNone(results[1])
            self.assertEqual(results[0].id, results[1].id)
        finally:
            node.close_all()

    def test_ensure_session_waits_longer_than_two_seconds(self):
        cfg = ServerTargetConfig(alias="slow", host="10.0.0.8", user="u")
        node = ServerNode(cfg, self.cache_dirs, "slow")
        started = threading.Event()
        release = threading.Event()

        def slow_connect(session):
            started.set()
            release.wait(5)
            session.is_dead = False
            session.client = MagicMock()
            session.channel = MagicMock()
            session.channel.closed = False
            return True

        try:
            with patch.object(SSHSession, "connect", slow_connect):
                results = []

                def worker():
                    results.append(node.ensure_session())

                first = threading.Thread(target=worker)
                second = threading.Thread(target=worker)
                first.start()
                self.assertTrue(started.wait(2))
                second.start()
                time.sleep(2.2)
                release.set()
                first.join(5)
                second.join(5)
            self.assertEqual(len(results), 2)
            self.assertIsNotNone(results[0])
            self.assertIsNotNone(results[1])
            self.assertEqual(results[0].id, results[1].id)
            self.assertEqual(len(node.sessions), 1)
        finally:
            node.close_all()

    def test_purge_drops_cached_result_and_idle_auto_sessions(self):
        cfg = ServerTargetConfig(alias="box", host="10.9.9.9", user="u", max_sessions=1)
        node = ServerNode(cfg, self.cache_dirs, "purge")
        dead = SSHSession(1, "old-name", self.cache_dirs, "purge")
        dead.is_dead = True
        node.sessions[1] = dead
        node.next_session_id = 2
        node.last_tool_result_by_session[1] = {"tool": "read"}
        try:
            with patch.object(SSHSession, "connect", return_value=True):
                node.open_session(name="fresh", make_current=False)
            self.assertNotIn(1, node.sessions)
            self.assertIn(2, node.sessions)
            self.assertNotIn(1, node.last_tool_result_by_session)
        finally:
            node.close_all()

    def test_same_ip_different_ports_need_an_alias(self):
        registry = ServersRegistry()
        first = ServerTargetConfig(alias="a", host="10.1.1.1", port=22, user="u")
        second = ServerTargetConfig(alias="b", host="10.1.1.1", port=2222, user="u")
        registry.register(first)
        registry.register(second)
        self.assertIsNone(registry.get("10.1.1.1"))
        self.assertIs(registry.get("a"), first)
        alone = ServersRegistry()
        only = ServerTargetConfig(alias="only", host="10.2.2.2", port=22, user="u")
        alone.register(only)
        self.assertIs(alone.get("10.2.2.2"), only)

    def test_cold_run_dispatch_single_flights_ensure(self):
        from src.server import run_dispatch
        cfg = ServerTargetConfig(alias="cold", host="10.0.0.9", user="u", password="p")
        node = ServerNode(cfg, self.cache_dirs, "cold")
        started = threading.Event()
        release = threading.Event()
        calls = []

        def slow_connect(session):
            calls.append(session.name)
            if not started.is_set():
                started.set()
                release.wait(2)
            session.is_dead = False
            session.client = MagicMock()
            session.channel = MagicMock()
            session.channel.closed = False
            session.channel.recv_ready.return_value = False
            session.channel.send_ready.return_value = True
            return True

        manager = MagicMock()
        manager.resolve_target_for_args.return_value = (node, None, False, None)
        try:
            with patch.object(SSHSession, "connect", slow_connect):
                results = []

                def worker():
                    results.append(run_dispatch({
                        "command": "echo hi",
                        "server": "cold",
                        "background": True,
                        "wait_timeout": 1,
                    }, manager))

                first = threading.Thread(target=worker)
                second = threading.Thread(target=worker)
                first.start()
                self.assertTrue(started.wait(2))
                second.start()
                time.sleep(0.05)
                release.set()
                first.join(3)
                second.join(3)
            # Under explicit session model, each run without session_id opens its own clean session
            unnamed = [s for s in node.sessions.values() if s.name == ""]
            self.assertEqual(len(unnamed), 2, [s.name for s in node.sessions.values()])
            self.assertEqual(calls[0], "")
            self.assertTrue(all(item.get("success") for item in results), results)
        finally:
            node.close_all()

    def test_finished_run_buffer_is_evicted_active_is_kept(self):
        from src.ssh_state import RunState
        node = self.manager.get_or_create_node(self.cfg1)
        session = SSHSession(91, "keep", self.cache_dirs, "test_multiserver", server_config=self.cfg1)
        finished = RunState(
            run_id=1, session_id=91, command="cat", mode="sync", started_at=time.time(),
            wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "evict-done.log"),
        )
        finished.output_buffer = "x" * 1000
        finished.mark_done("completed")
        active = RunState(
            run_id=2, session_id=91, command="cat", mode="sync", started_at=time.time(),
            wait_timeout=1.0, startup_wait=0.1, hard_timeout=0.0,
            max_buffer_chars=100000, run_log_path=os.path.join(self.cache_dirs["runs_dir"], "evict-live.log"),
        )
        active.output_buffer = "y" * 1000
        active.mark_done("completed")
        session.runs[1] = finished
        session.runs[2] = active
        session.active_run_id = 2
        with node.lock:
            node.sessions[91] = session
        self.manager._cached_total_buffer_time = 0
        node._cached_total_buffer_time = 0
        with patch("src.manager.MAX_TOTAL_BUFFER_CHARS", 10):
            freed = self.manager.evict_completed_run_buffers()
        self.assertEqual(finished.output_buffer, "")
        self.assertEqual(active.output_buffer, "y" * 1000)
        self.assertGreaterEqual(freed, 1000)

    def test_server_node_ensure_session_prefers_idle_session(self):
        """Verify ensure_session picks an existing idle session when another session is busy."""
        node = self.manager.get_or_create_node(self.cfg1)
        s1 = MagicMock()
        s1.is_dead = False
        s1.is_alive.return_value = True
        s1.is_busy.return_value = True

        s2 = MagicMock()
        s2.is_dead = False
        s2.is_alive.return_value = True
        s2.is_busy.return_value = False

        with node.lock:
            node.sessions[1] = s1
            node.sessions[2] = s2

        chosen = node.ensure_session()
        self.assertIs(chosen, s2)

    def test_protected_local_write_blocks_servers_json_unconditionally(self):
        """Verify servers.json and servers.json.example are protected even without SERVERS_CONFIG_PATH."""
        from src.utils import _protected_local_write
        from src import config
        old_cfg = getattr(config, "SERVERS_CONFIG_PATH", None)
        try:
            config.SERVERS_CONFIG_PATH = None
            self.assertTrue(_protected_local_write("servers.json"))
            self.assertTrue(_protected_local_write("SERVERS.JSON"))
            self.assertTrue(_protected_local_write("servers.json.example"))
            self.assertTrue(_protected_local_write("/some/path/servers.json"))
            self.assertTrue(_protected_local_write(r"C:\workspace\servers.json"))
            self.assertFalse(_protected_local_write("other_file.txt"))
        finally:
            config.SERVERS_CONFIG_PATH = old_cfg

if __name__ == "__main__":
    unittest.main()
