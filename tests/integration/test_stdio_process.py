"""The real thing: the gateway as a child process, spoken to over stdio like an MCP client does."""

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

from tests.integration.support import SSH_PASSWORD, SSH_USER, SshdTestCase

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def start_gateway(workdir: str, servers: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, os.path.join(ROOT, "mcp-server.py"), "--servers-config", servers,
         "--cache-dir", os.path.join(workdir, "cache"), "--project-root", workdir],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")


class StdioProcess(SshdTestCase):
    flavor = "debian"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        servers = os.path.join(tmp.name, "servers.json")
        with open(servers, "w", encoding="utf-8") as handle:
            json.dump({"servers": {"box": {"host": "127.0.0.1", "port": self.container.port, "user": SSH_USER,
                                           "password": SSH_PASSWORD, "verify_host": False}}}, handle)
        self.process = start_gateway(tmp.name, servers)
        self.addCleanup(self.stop)
        self._id = 0

    def stop(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(15)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.process.stdout.close()
        self.process.stderr.close()

    def rpc(self, method, params=None):
        self._id += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                                             "params": params or {}}) + "\n")
        self.process.stdin.flush()
        response = json.loads(self.process.stdout.readline())
        self.assertEqual(response["id"], self._id)
        return response

    def test_a_client_session_from_handshake_to_command(self):
        init = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "0"}})
        self.assertEqual(init["result"]["serverInfo"]["name"], "mcp-ssh")
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        names = [t["name"] for t in self.rpc("tools/list")["result"]["tools"]]
        self.assertEqual(names, ["server_list", "run", "read", "signal", "session_close", "file"])
        call = self.rpc("tools/call", {"name": "run", "arguments": {"command": "echo привет"}})
        payload = json.loads(call["result"]["content"][0]["text"])
        self.assertEqual((payload["output"], payload["exit_code"], payload["session_id"]),
                         ("$ echo привет\nпривет\n", 0, "box/1"))

    def test_closing_stdin_ends_the_process_cleanly(self):
        self.rpc("ping")
        self.process.stdin.close()
        self.assertEqual(self.process.wait(20), 0)


def _json_object(line: str):
    try:
        value = json.loads(line)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


class StdoutBelongsToTheProtocol(unittest.TestCase):
    """A stray line on stdout makes a strict MCP client drop the server. No SSH host is needed."""

    def test_a_servers_file_broken_while_running_is_reported_on_stderr(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        servers = os.path.join(tmp.name, "servers.json")
        with open(servers, "w", encoding="utf-8") as handle:
            json.dump({"servers": {"box": {"host": "127.0.0.1", "user": "u", "password": "p"}}}, handle)
        process = start_gateway(tmp.name, servers)
        watchdog = threading.Timer(60, process.kill)
        watchdog.start()
        self.addCleanup(watchdog.cancel)

        def send(request_id, method, params=None):
            process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method,
                                            "params": params or {}}) + "\n")
            process.stdin.flush()

        send(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "test", "version": "0"}})
        self.assertEqual(_json_object(process.stdout.readline())["id"], 1)
        with open(servers, "w", encoding="utf-8") as handle:
            handle.write("{ this is not json")
        send(2, "tools/call", {"name": "server_list", "arguments": {}})

        lines = []
        while True:
            line = process.stdout.readline()
            self.assertTrue(line, "the gateway closed stdout without answering")
            lines.append(line)
            answer = _json_object(line)
            if answer and answer.get("id") == 2:
                break
        process.stdin.close()
        process.wait(20)
        lines += process.stdout.read().splitlines()
        stderr = process.stderr.read()
        process.stdout.close()
        process.stderr.close()

        self.assertEqual([line for line in lines if _json_object(line) is None], [])
        self.assertIn("servers.json was not reloaded", stderr)


class StartupIsQuiet(unittest.TestCase):
    """stderr ends up in the MCP client's log, so it should hold the gateway's own lines only."""

    def test_a_dependency_deprecation_warning_does_not_greet_the_user_at_every_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            servers = os.path.join(tmp, "servers.json")
            with open(servers, "w", encoding="utf-8") as handle:
                json.dump({"servers": {"box": {"host": "127.0.0.1", "user": "u", "password": "p"}}}, handle)
            process = start_gateway(tmp, servers)
            _, stderr = process.communicate(timeout=60)  # closing stdin ends the gateway
        self.assertIn("started", stderr)
        self.assertNotIn("Warning", stderr)
