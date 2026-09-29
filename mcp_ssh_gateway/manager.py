"""Servers, their connections and their sessions.

Lock order: ``MultiServerManager._lock`` -> ``ServerNode.lock``. Connecting to a host
takes seconds, so it happens under ``ServerNode.open_lock`` only, never under the two
locks above; that lock also keeps the session limit exact when requests open shells at
the same time.
"""

import hashlib
import json
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from mcp_ssh_gateway.config import ServerTargetConfig, ServersRegistry, Settings
from mcp_ssh_gateway.logs import LogStore
from mcp_ssh_gateway.session import Session, SessionError
from mcp_ssh_gateway.transport import Connection

RELOAD_CHECK_SECONDS = 5.0
PRUNE_CHECK_SECONDS = 3600.0


class UsageError(SessionError):
    """The request names something that does not exist or cannot be combined."""


@dataclass
class ServerNode:
    """The connection and the sessions of one server."""
    target: ServerTargetConfig
    connection: Any
    sessions: Dict[int, Session] = field(default_factory=dict)
    next_id: int = 1
    lock: threading.Lock = field(default_factory=threading.Lock)
    open_lock: threading.Lock = field(default_factory=threading.Lock)


class MultiServerManager:
    def __init__(self, settings: Settings, registry: ServersRegistry,
                 connection_factory: Callable[..., Any] = Connection) -> None:
        self.settings = settings
        self.registry = registry
        self._connection_factory = connection_factory
        self._logs = LogStore(settings.cache_root, settings.log_policy)
        self._nodes: Dict[str, ServerNode] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._inflight: Dict[Any, Session] = {}
        self._config_fingerprint = self._fingerprint()
        self._last_reload_check = 0.0
        self._last_prune = 0.0
        self.prune_logs()

    # ------------------------------------------------------------------ resolving

    def session_for(self, server: Optional[str] = None, session_id: Optional[str] = None,
                    shell: Optional[bool] = None) -> Session:
        """The session a request talks to: the one ``session_id`` names, or a new one when it is left out.

        There is no default session: a shell has state (cwd, variables), so a request may only land in a
        shell it named."""
        self._housekeeping()
        node, number = self._locate(server, session_id)
        if number is None:
            return self._open(node, shell)
        session = self._existing(node, number)
        self._check_mode(session, shell)
        return session

    def existing_session(self, session_id: Optional[str], server: Optional[str] = None) -> Session:
        """A session that must already exist (read, signal, session_close)."""
        if not session_id:
            raise UsageError("session_id is required, for example 'web/1'. It is returned by every run.")
        self._housekeeping()
        node, number = self._locate(server, session_id)
        return self._existing(node, number)

    def close_session(self, session_id: Optional[str], server: Optional[str] = None) -> str:
        session = self.existing_session(session_id, server)
        node = self._node(session.alias)
        with node.lock:
            node.sessions.pop(session.id, None)
        session.close()
        return session.sid

    def server_alias(self, server: Optional[str], session_id: Optional[str]) -> str:
        """The server a request is about, from 'server' and/or the server part of session_id."""
        return self._locate(server, session_id)[0].target.alias

    def target(self, alias: str) -> ServerTargetConfig:
        """The server's settings as sessions see them (gateway-wide guardrails included)."""
        return self._node(alias).target

    def track(self, request_id: Any, session: Optional[Session]) -> None:
        """Remember which session a pending request is waiting on (for cancellation)."""
        if request_id is None:
            return
        with self._lock:
            if session is None:
                self._inflight.pop(request_id, None)
            else:
                self._inflight[request_id] = session

    def cancel(self, request_id: Any) -> bool:
        """The client cancelled a pending request: stop what it started."""
        with self._lock:
            session = self._inflight.pop(request_id, None)
        if session is None or not session.busy:
            return False
        try:
            session.signal("ctrl_c", wait=0)
        except SessionError:
            return False
        return True

    def connection(self, server: str) -> Any:
        """The SSH connection of a server (the file tool uses it for SFTP)."""
        target = self.registry.get(server)
        if target is None:
            raise UsageError(self._unknown_server(server))
        return self._node(target.alias).connection

    def list_servers(self) -> List[Dict[str, Any]]:
        self.reload_if_changed(force=True)
        rows = []
        for target in self.registry.all():
            row: Dict[str, Any] = {"server": target.alias, "host": f"{target.host}:{target.port}",
                                   "user": target.user}
            if target.description:
                row["description"] = target.description
            if target.read_only:
                row["read_only"] = True
            node = self._nodes.get(target.alias.lower())
            if node is not None:
                with node.lock:
                    sessions = [s.describe() for _, s in sorted(node.sessions.items())]
                if sessions:
                    row["sessions"] = sessions
            rows.append(row)
        return rows

    def add_server(self, alias: str, data: Dict[str, Any]) -> ServerTargetConfig:
        """Register a server and write it to servers.json (only offered with --allow-add-server)."""
        path = self.settings.servers_path
        if not path:
            raise UsageError("No servers.json is configured, so a new server cannot be saved.")
        if self.registry.get(alias):
            raise UsageError(f"A server named '{alias}' already exists.")
        target = ServerTargetConfig.from_dict(alias, data)
        if not target.host:
            raise UsageError("'host' is required.")
        document: Dict[str, Any] = {"servers": {}}
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as handle:
                document = json.load(handle)
        document.setdefault("servers", {})[alias] = data
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False)
        os.replace(temporary, path)
        self._config_fingerprint = self._fingerprint()
        self.registry.register(target)
        return target

    def close_all(self) -> None:
        with self._lock:
            self._closed = True
            nodes = list(self._nodes.values())
            self._nodes.clear()
        for node in nodes:
            self._close_node(node)

    # ------------------------------------------------------------------ hot reload

    def reload_if_changed(self, force: bool = False) -> bool:
        """Apply changes of servers.json without dropping connections that did not change."""
        path = self.settings.servers_path
        now = time.monotonic()
        if not path or (not force and now - self._last_reload_check < RELOAD_CHECK_SECONDS):
            return False
        self._last_reload_check = now
        fingerprint = self._fingerprint()
        if fingerprint == self._config_fingerprint:
            return False
        try:
            fresh = ServersRegistry()
            fresh.load_file(path)
        except (OSError, ValueError) as exc:
            print(f"[SSH-MCP] servers.json was not reloaded: {exc}", file=sys.stderr, flush=True)
            return False
        self._config_fingerprint = fingerprint
        self._apply(fresh)
        return True

    def _apply(self, fresh: ServersRegistry) -> None:
        wanted = {t.alias.lower(): t for t in fresh.all()}
        dropped: List[ServerNode] = []
        with self._lock:
            for target in self.registry.all():
                key = target.alias.lower()
                if target.imported or key in wanted:
                    continue
                self.registry.unregister(key)
                node = self._nodes.pop(key, None)
                if node:
                    dropped.append(node)
            for key, target in wanted.items():
                old = self.registry.get(key)
                self.registry.register(target)
                node = self._nodes.get(key)
                if node is None or old is None:
                    continue
                if old.connection_key() != target.connection_key():
                    dropped.append(self._nodes.pop(key))
                else:
                    self._update_target(node, target)
        for node in dropped:
            self._close_node(node)

    def _update_target(self, node: ServerNode, target: ServerTargetConfig) -> None:
        effective = target.with_policy(self.settings.read_only, self.settings.command_blacklist)
        with node.lock:
            node.target = effective
            node.connection.target = effective
            for session in node.sessions.values():
                session.target = effective

    def _fingerprint(self) -> Optional[str]:
        path = self.settings.servers_path
        if not path:
            return None
        try:
            with open(path, "rb") as handle:
                return hashlib.sha256(handle.read()).hexdigest()
        except OSError:
            return None

    # ------------------------------------------------------------------ logs

    def _housekeeping(self) -> None:
        """What a long-running gateway does between requests, each at most once per interval."""
        self.reload_if_changed()
        self.prune_logs()

    def prune_logs(self) -> None:
        now = time.monotonic()
        if self._last_prune and now - self._last_prune < PRUNE_CHECK_SECONDS:
            return
        self._last_prune = now or 1e-9
        try:
            self._logs.prune()
        except OSError as exc:
            print(f"[SSH-MCP] log cleanup failed: {exc}", file=sys.stderr, flush=True)

    # ------------------------------------------------------------------ internals

    def _locate(self, server: Optional[str], session_id: Optional[str]):
        """(node, session number or None) for the arguments of a request."""
        sid = str(session_id).strip() if session_id not in (None, "") else ""
        named = str(server).strip() if server not in (None, "") else ""
        number: Optional[int] = None
        if sid:
            head, slash, tail = sid.rpartition("/")
            try:
                number = int(tail)
            except ValueError:
                raise self._bad_session_id(sid) from None
            if slash:
                if named and self._alias_of(named) != self._alias_of(head):
                    raise UsageError(f"'server' is '{named}' but session_id belongs to '{head}'.")
                named = head
            elif not named and self.registry.count() > 1:
                raise self._bad_session_id(sid)
        target = self._pick_server(named)
        return self._node(target.alias), number

    @staticmethod
    def _bad_session_id(sid: str) -> UsageError:
        return UsageError(
            f"Bad session_id '{sid}'. It looks like 'web/1' (server name, slash, number) "
            "and is returned by every run.")

    def _alias_of(self, name: str) -> str:
        target = self.registry.get(name)
        return target.alias if target else name

    def _pick_server(self, name: str) -> ServerTargetConfig:
        if name:
            target = self.registry.get(name)
            if target is None:
                raise UsageError(self._unknown_server(name))
            return target
        if self.registry.count() == 1:
            return self.registry.all()[0]
        if self.registry.count() == 0:
            raise UsageError("No servers are configured. Create servers.json (see servers.json.example).")
        raise UsageError(
            f"Say which server: 'server' is required. Configured: {', '.join(self.registry.aliases())}.")

    def _unknown_server(self, name: str) -> str:
        return f"Unknown server '{name}'. Configured: {', '.join(self.registry.aliases()) or 'none'}."

    def _node(self, alias: str) -> ServerNode:
        key = alias.lower()
        with self._lock:
            if self._closed:
                raise UsageError("The gateway is shutting down.")
            node = self._nodes.get(key)
            if node is None:
                target = self.registry.get(alias)
                if target is None:
                    raise UsageError(self._unknown_server(alias))
                effective = target.with_policy(self.settings.read_only, self.settings.command_blacklist)
                connection = self._connection_factory(effective, self.settings.known_hosts_path)
                node = self._nodes[key] = ServerNode(effective, connection)
            return node

    def _existing(self, node: ServerNode, number: int) -> Session:
        with node.lock:
            session = node.sessions.get(number)
            open_ids = sorted(node.sessions)
        if session is None:
            listing = ", ".join(f"{node.target.alias}/{i}" for i in open_ids) or "none"
            raise UsageError(
                f"Session {node.target.alias}/{number} does not exist (closed?). Open sessions: {listing}.")
        return session

    def _check_mode(self, session: Session, shell: Optional[bool]) -> None:
        if shell is None or session.mode == ("shell" if shell else "cli"):
            return
        kind = "Linux shell" if session.mode == "shell" else "router CLI"
        raise UsageError(
            f"Session {session.sid} is a {kind} session, but shell={str(shell).lower()} asks for the other "
            "kind. Leave out session_id to open a new one.")

    def _open(self, node: ServerNode, shell: Optional[bool]) -> Session:
        with node.open_lock:
            with node.lock:
                for number in [n for n, s in node.sessions.items() if s.closed]:
                    del node.sessions[number]
                if len(node.sessions) >= node.target.max_sessions:
                    raise UsageError(self._limit_reached(node))
                number = node.next_id
                node.next_id += 1
            session = Session(number, node.target, node.connection, self._logs, shell=shell)
            try:
                session.start()
            except Exception:
                session.close()
                raise
            with node.lock:
                node.sessions[number] = session
            return session

    @staticmethod
    def _limit_reached(node: ServerNode) -> str:
        """Every run without session_id opens a shell, so this is the normal way to learn about the limit."""
        rows = [s.describe() for _, s in sorted(node.sessions.items())]
        open_ones = ", ".join(
            f"{row['session_id']} {row['state']}" + (f": {row['running']}" if "running" in row else "")
            for row in rows)
        return (f"{node.target.alias} already has {len(rows)} sessions (the limit is {node.target.max_sessions}): "
                f"{open_ones}. Continue in one of them with session_id, or free a slot with session_close.")

    @staticmethod
    def _close_node(node: ServerNode) -> None:
        with node.lock:
            sessions = list(node.sessions.values())
            node.sessions.clear()
        for session in sessions:
            session.close()
        node.connection.close()
