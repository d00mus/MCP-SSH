"""The SSH connection behind one or more sessions (paramiko)."""

import os
import threading
from typing import Any, Optional

import paramiko

from mcp_ssh_gateway.config import ServerTargetConfig
from mcp_ssh_gateway.session import SessionError

CONNECT_TIMEOUT = 10
CHANNEL_TIMEOUT = 15
KEEPALIVE_SECONDS = 30


class ConnectionFailed(SessionError):
    """The SSH connection could not be made; the message is written for the agent."""


class AcceptNewHostKeys(paramiko.MissingHostKeyPolicy):
    """OpenSSH's ``StrictHostKeyChecking=accept-new``: trust a host on first contact, remember
    its key, and refuse it if the key ever changes."""

    def __init__(self, known_hosts_path: Optional[str]) -> None:
        self._path = known_hosts_path

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        client.get_host_keys().add(hostname, key.get_name(), key)
        if self._path:
            try:
                os.makedirs(os.path.dirname(self._path), exist_ok=True)
                client.get_host_keys().save(self._path)
            except OSError:
                pass  # trusting for this connection still works


class Connection:
    """One authenticated SSH connection, opened lazily and reopened after a loss."""

    def __init__(self, target: ServerTargetConfig, known_hosts_path: Optional[str] = None) -> None:
        self.target = target
        self._known_hosts_path = known_hosts_path
        self._client: Optional[paramiko.SSHClient] = None
        self._lock = threading.RLock()

    def is_active(self) -> bool:
        client = self._client
        transport = client.get_transport() if client else None
        return bool(transport and transport.is_active())

    def open_channel(self, cols: int = 220, rows: int = 50) -> Any:
        """A new PTY shell channel; connects first when there is no live connection."""
        with self._lock:
            transport = self._live_client().get_transport()
            try:
                channel = transport.open_session(timeout=CHANNEL_TIMEOUT)
                channel.get_pty(width=cols, height=rows)
                channel.invoke_shell()
            except paramiko.ChannelException as exc:
                # The server answered "no" to one more channel; the connection and its other shells are fine.
                raise ConnectionFailed(
                    f"{self.target.alias} refused another shell ({exc}). The server limits the sessions of one "
                    f"connection (sshd MaxSessions, 10 by default): close shells you no longer need."
                ) from exc
            except (paramiko.SSHException, EOFError, OSError) as exc:
                self._drop_client()
                raise ConnectionFailed(f"Could not open a shell on {self.target.alias}: {exc}") from exc
            return channel

    def sftp(self) -> paramiko.SFTPClient:
        with self._lock:
            return self._live_client().open_sftp()

    def close(self) -> None:
        with self._lock:
            self._drop_client()

    # ------------------------------------------------------------------

    def _live_client(self) -> paramiko.SSHClient:
        """The connected client; connects first when there is no live connection."""
        client = self._client
        if client is None or not self.is_active():
            client = self._connect()
        return client

    def _connect(self) -> paramiko.SSHClient:
        target = self.target
        self._drop_client()
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self._known_hosts_path and os.path.isfile(self._known_hosts_path):
            try:
                client.load_host_keys(self._known_hosts_path)
            except Exception as exc:  # paramiko raises anything from a damaged entry
                raise ConnectionFailed(
                    f"The known_hosts file {self._known_hosts_path} is damaged ({exc}). "
                    "Delete it (or the broken line); it is rebuilt on the next connection.") from exc
        client.set_missing_host_key_policy(
            AcceptNewHostKeys(self._known_hosts_path) if target.verify_host else paramiko.AutoAddPolicy())
        explicit_credentials = bool(target.password or target.key_path)
        options = {
            "hostname": target.host,
            "port": target.port,
            "username": target.user,
            "timeout": CONNECT_TIMEOUT,
            "banner_timeout": 15,
            "auth_timeout": 20,
            "allow_agent": not explicit_credentials,
            "look_for_keys": not explicit_credentials,
        }
        if target.password:
            options["password"] = target.password
        if target.key_path:
            options["key_filename"] = os.path.expanduser(target.key_path)
            if target.key_passphrase:
                options["passphrase"] = target.key_passphrase
        try:
            client.connect(**options)
        except Exception as exc:
            client.close()
            raise ConnectionFailed(describe_connect_error(exc, target.host, target.port)) from exc
        client.get_transport().set_keepalive(KEEPALIVE_SECONDS)
        self._client = client
        return client

    def _drop_client(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def describe_connect_error(exc: Exception, host: str, port: int) -> str:
    """A connection exception as an actionable message."""
    detail = f"Detail: {exc}"
    text = str(exc).lower()
    if isinstance(exc, paramiko.BadHostKeyException):
        return (f"The host key of {host}:{port} CHANGED since it was first trusted. This can be an attack "
                f"or a reinstalled host. If the change is expected, remove the old entry from known_hosts. {detail}")
    if isinstance(exc, paramiko.AuthenticationException):
        return (f"SSH authentication failed for {host}:{port}. Check the user name, password or key "
                f"in the server configuration. {detail}")
    if "not found in known_hosts" in text or "unknown server" in text:
        return (f"The host key of {host}:{port} is not trusted. Set \"verify_host\": false for this server "
                f"or add the host to known_hosts. {detail}")
    if isinstance(exc, TimeoutError) or "timed out" in text:
        return f"Connecting to {host}:{port} timed out: the host is unreachable, filtered or overloaded. {detail}"
    if "refused" in text:
        return f"{host}:{port} refused the connection: is sshd running and is the port right? {detail}"
    if "no route" in text or "unreachable" in text:
        return f"Cannot reach {host}:{port}: check the network and the address. {detail}"
    if "getaddrinfo" in text or "name or service not known" in text or "nodename nor servname" in text:
        return f"The name {host} does not resolve: check the host name. {detail}"
    return f"SSH connection to {host}:{port} failed. {detail}"
