"""Shared fixtures for integration tests against a real OpenSSH server in Docker.

The unit tests use scripted fakes, so they cannot tell whether the gateway understands
what a real shell prints back. These tests can: every image here runs a real sshd,
and the gateway is driven through the same JSON-RPC entry point an MCP client uses.

Skipped automatically when Docker is unavailable; set MCP_SSH_IT=0 to skip on purpose.
"""

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, Optional

from mcp_ssh_gateway.config import ServerTargetConfig, ServersRegistry, Settings
from mcp_ssh_gateway.manager import MultiServerManager
from mcp_ssh_gateway.server import Gateway as Harness, handle_request

IMAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "images")
SSH_USER = "tester"
SSH_PASSWORD = "testpass"


def docker_available() -> bool:
    if os.environ.get("MCP_SSH_IT") == "0" or shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=20
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _docker(*args: str, timeout: float = 300) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def body(output: str) -> str:
    """The answer without its leading "$ <command>" console line and trailing newline."""
    lines = output.split("\n")
    if lines and lines[0].startswith("$ "):
        lines = lines[1:]
    return "\n".join(lines).rstrip("\n")


class SshdContainer:
    """One disposable sshd container built from tests/integration/images/<flavor>."""

    def __init__(self, flavor: str) -> None:
        self.flavor = flavor
        self.image = f"mcp-ssh-it-{flavor}"
        self.container_id = ""
        self.port = 0

    def start(self) -> None:
        _docker("build", "-q", "-t", self.image, os.path.join(IMAGES_DIR, self.flavor))
        self.container_id = _docker("run", "-d", "--rm", "-p", "127.0.0.1::22", self.image)
        mapping = _docker("port", self.container_id, "22/tcp").splitlines()[0]
        self.port = int(mapping.rsplit(":", 1)[1])
        self._wait_for_banner()

    def _wait_for_banner(self, timeout: float = 30.0) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
                    sock.settimeout(2)
                    if sock.recv(64).startswith(b"SSH-"):
                        return
            except OSError:
                pass
            time.sleep(0.3)
        raise RuntimeError(f"sshd in {self.image} did not come up")

    def exec(self, command: str) -> str:
        """Run a command inside the container (out-of-band, not through the gateway)."""
        return _docker("exec", self.container_id, "sh", "-c", command)

    def stop(self) -> None:
        if self.container_id:
            try:
                _docker("kill", self.container_id, timeout=30)
            except RuntimeError:
                pass
            self.container_id = ""


class Gateway:
    """The real gateway stack (registry, manager, JSON-RPC handler) with one host."""

    def __init__(self, container: SshdContainer, alias: str = "host", verify_host: bool = False,
                 user: str = SSH_USER, target_options: Optional[Dict[str, Any]] = None, **settings: Any) -> None:
        self.alias = alias
        self.workdir = os.path.realpath(tempfile.mkdtemp(prefix="mcp-ssh-it-"))
        registry = ServersRegistry()
        registry.register(ServerTargetConfig(
            alias=alias, host="127.0.0.1", port=container.port,
            user=user, password=SSH_PASSWORD, verify_host=verify_host, **(target_options or {}),
        ))
        self.settings = Settings(project_root=self.workdir, cache_root=os.path.join(self.workdir, "cache"),
                                 log_policy="full", **settings)
        self.manager = MultiServerManager(self.settings, registry)
        self.server = Harness(self.manager)
        self._next_id = 0

    def call_raw(self, tool: str, **arguments: Any) -> Dict[str, Any]:
        self._next_id += 1
        response = handle_request(
            {"jsonrpc": "2.0", "id": self._next_id, "method": "tools/call",
             "params": {"name": tool, "arguments": arguments}},
            self.server,
        )
        assert response is not None and "result" in response, response
        result = response["result"]
        payload = json.loads(result["content"][0]["text"])
        return {"payload": payload, "is_error": bool(result.get("isError"))}

    def call(self, tool: str, **arguments: Any) -> Dict[str, Any]:
        return self.call_raw(tool, **arguments)["payload"]

    def run(self, command: str, **arguments: Any) -> Dict[str, Any]:
        """run() plus read() until the command is done; returns the last payload
        with the whole output concatenated in "output"."""
        arguments.setdefault("server", self.alias)
        first = self.call("run", command=command, **arguments)
        output = first.get("output", "")
        current = first
        deadline = time.time() + 60
        while (current.get("status") == "running" or current.get("has_more")) and time.time() < deadline:
            current = self.call("read", session_id=first["session_id"], wait=2)
            output += current.get("output", "")
        current = dict(current)
        current["output"] = output
        current.setdefault("session_id", first.get("session_id"))
        return current

    def close(self) -> None:
        self.manager.close_all()
        shutil.rmtree(self.workdir, ignore_errors=True)


class SshdTestCase(unittest.TestCase):
    """Base class: one container per test class, a fresh gateway per test."""

    flavor = "debian"
    container: Optional[SshdContainer] = None

    @classmethod
    def setUpClass(cls) -> None:
        if not docker_available():
            raise unittest.SkipTest("Docker is not available (set MCP_SSH_IT=0 to skip on purpose)")
        cls.container = SshdContainer(cls.flavor)
        cls.container.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.container is not None:
            cls.container.stop()

    def setUp(self) -> None:
        self.gw = Gateway(self.container)
        self.addCleanup(self.gw.close)
