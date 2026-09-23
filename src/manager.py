"""
Multi-server manager and cluster routing.

Lock Hierarchy (Strict DAG - never acquire in reverse order):
    MultiServerManager.lock -> ServerNode.lock -> SSHSession.lock -> RunState.lock / PipelineState.lock
"""

import os
import time
import json
import hashlib
import threading
from typing import Any, Dict, Optional, List, Tuple, NamedTuple, Set

from src.config import (
    CONNECT_TIMEOUT, HEALTH_CHECK_INTERVAL, MAX_TOTAL_BUFFER_CHARS, MAX_LOG_TOTAL_BYTES,
    ServerTargetConfig, ServersRegistry, config
)
from src.utils import log_error, iso_now, safe_name, cleanup_old_logs, cleanup_dead_session_logs, mask_secrets
from src.session import SSHSession
from src.ssh_state import CHARS_ACCOUNT


def _sanitize_tool_data(data: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "..."
    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            if any(s in str(k).lower() for s in ("password", "passphrase", "secret", "token", "key_pass", "key_path", "private_key", "key_file")):
                clean[k] = "******"
            elif isinstance(v, str) and len(v) > 10000:
                clean[k] = mask_secrets(v[:10000]) + "... [truncated in last_command_details]"
            else:
                clean[k] = _sanitize_tool_data(v, depth + 1)
        return clean
    elif isinstance(data, list):
        return [_sanitize_tool_data(x, depth + 1) for x in data[:100]]
    elif isinstance(data, str):
        # Secret-looking fragments (password=..., --token ...) stay out of diagnostics
        if len(data) > 10000:
            return mask_secrets(data[:10000]) + "... [truncated in last_command_details]"
        return mask_secrets(data)
    return data


class ServerNode:
    """Manages sessions and state for a single target SSH server."""
    def __init__(self, server_config: ServerTargetConfig, cache_dirs: Dict[str, str], project_tag: str):
        self.server_config = server_config
        self.alias = server_config.alias
        self.cache_dirs = cache_dirs
        self.project_tag = project_tag

        self.sessions: Dict[int, SSHSession] = {}
        self._pending_sids: Set[int] = set()
        self.next_session_id = 1
        self.lock = threading.Lock()
        self._ensure_cv = threading.Condition(self.lock)
        self._closed = False
        self._epoch = 0
        self._cached_total_buffer: int = 0
        self._cached_total_buffer_time: float = 0.0
        self._buffer_cache_lock = threading.Lock()
        self._ensuring = False

        self.last_tool_result_by_session: Dict[int, Dict[str, Any]] = {}
        self.last_tool_result_server: Optional[Dict[str, Any]] = None

    def record_tool_result(self, tool_name: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        snapshot = {
            "timestamp": iso_now(),
            "server": self.alias,
            "tool": tool_name,
            "args": _sanitize_tool_data(dict(args)),
            "result": _sanitize_tool_data(dict(result))
        }
        numeric_sid = result.get("numeric_session_id")
        if numeric_sid is None:
            sid_val = result.get("session_id")
            if isinstance(sid_val, int):
                numeric_sid = sid_val
            elif isinstance(sid_val, str) and "/" in sid_val:
                try:
                    numeric_sid = int(sid_val.split("/", 1)[1])
                except Exception:
                    pass
            elif isinstance(sid_val, str):
                try:
                    numeric_sid = int(sid_val)
                except Exception:
                    pass
        with self.lock:
            self.last_tool_result_server = snapshot
            if numeric_sid is not None:
                self.last_tool_result_by_session[numeric_sid] = snapshot

    def get_last_tool_result(self, numeric_session_id: Optional[int]) -> Dict[str, Any]:
        with self.lock:
            if numeric_session_id is not None and numeric_session_id in self.last_tool_result_by_session:
                return {"success": True, **self.last_tool_result_by_session[numeric_session_id]}
            if self.last_tool_result_server:
                return {"success": True, **self.last_tool_result_server}
            return {"success": False, "error": f"No recorded result for server {self.alias}"}

    def _find_first_idle_alive_session_locked(self) -> Optional[SSHSession]:
        sessions = [self.sessions[sid] for sid in sorted(self.sessions.keys()) if sid in self.sessions]
        for s in sessions:
            if not s.is_dead and s.is_alive() and not s.is_busy():
                return s
        return None

    def ensure_session(self) -> Optional[SSHSession]:
        with self.lock:
            idle = self._find_first_idle_alive_session_locked()
            if idle:
                return idle
            max_s = getattr(self.server_config, "max_sessions", 10) or 10
            alive_count = sum(1 for s in self.sessions.values() if not s.is_dead and s.is_alive())
            if alive_count >= max_s:
                for s in self.sessions.values():
                    if not s.is_dead and s.is_alive():
                        return s
            while self._ensuring:
                self._ensure_cv.wait(CONNECT_TIMEOUT + 20.0)
                idle = self._find_first_idle_alive_session_locked()
                if idle:
                    return idle
                for s in self.sessions.values():
                    if not s.is_dead and s.is_alive():
                        return s
            self._ensuring = True
        try:
            created = self.open_session(name="")
            if not created.get("success"):
                with self.lock:
                    return self._find_first_idle_alive_session_locked() or next((s for s in self.sessions.values() if not s.is_dead and s.is_alive()), None)
            with self.lock:
                return self.sessions.get(created["numeric_session_id"])
        finally:
            with self.lock:
                self._ensuring = False
                self._ensure_cv.notify_all()

    def open_session(self, name: str = "", make_current: bool = False) -> Dict[str, Any]:
        dead_to_close = []
        limit_error = None
        sid = None
        current_epoch = None
        with self.lock:
            if self._closed:
                return {
                    "success": False,
                    "error": f"Server '{self.alias}' is closed.",
                    "server": self.alias
                }
            max_s = getattr(self.server_config, "max_sessions", 10) or 10
            # Auto-purge dead sessions if reaching limit
            if (len(self.sessions) + len(self._pending_sids)) >= max_s:
                dead_sids = [s_id for s_id, s in self.sessions.items() if s.is_dead]
                for dsid in dead_sids:
                    dead_s = self.sessions.pop(dsid, None)
                    self.last_tool_result_by_session.pop(dsid, None)
                    if dead_s:
                        dead_to_close.append(dead_s)

            if (len(self.sessions) + len(self._pending_sids)) >= max_s:
                limit_error = {
                    "success": False,
                    "error": (
                        f"Max sessions limit ({max_s}) reached for server '{self.alias}'. "
                        "Please close unused sessions using 'session_close' or reuse existing sessions."
                    ),
                    "server": self.alias
                }
            else:
                current_epoch = self._epoch
                sid = self.next_session_id
                self.next_session_id += 1
                self._pending_sids.add(sid)

        # Close purged sessions outside the node lock.
        for ds in dead_to_close:
            try:
                ds.close(permanent=True)
                ds.free_buffers()
            except Exception as e:
                log_error(f"Error closing purged dead session: {e}")

        if limit_error is not None:
            return limit_error

        s = SSHSession(sid, name or "", self.cache_dirs, self.project_tag, server_config=self.server_config)
        reject_reason = None
        try:
            connected = s.connect()

            with self.lock:
                if self._closed or self._epoch != current_epoch:
                    reject_reason = f"Server '{self.alias}' was closed during connection"
                elif not connected:
                    reject_reason = s.death_reason or f"failed to connect session {self.alias}/{sid}"
                else:
                    self.sessions[sid] = s
                    return {
                        "success": True,
                        "session_id": f"{self.alias}/{sid}",
                        "numeric_session_id": sid,
                        "server": self.alias,
                        "name": s.name
                    }
        except Exception as exc:
            try:
                s.close(permanent=True)
            except Exception:
                pass
            return {"success": False, "error": str(exc), "server": self.alias}
        finally:
            with self.lock:
                self._pending_sids.discard(sid)

        try:
            s.close(permanent=True)
        except Exception as e:
            log_error(f"Error closing rejected session: {e}")
        return {"success": False, "error": reject_reason or "session open failed", "server": self.alias}

    def close_session(self, session_id: int) -> Dict[str, Any]:
        with self.lock:
            s = self.sessions.pop(session_id, None)
            self.last_tool_result_by_session.pop(session_id, None)
            if not s:
                return {"success": False, "error": f"session {self.alias}/{session_id} not found", "server": self.alias}
        s.close(permanent=True)
        s.free_buffers()
        return {"success": True, "server": self.alias, "closed_session_id": f"{self.alias}/{session_id}"}

    def update_session(self, session_id: int, name: Optional[str], make_current: Optional[bool] = None) -> Dict[str, Any]:
        with self.lock:
            s = self.sessions.get(session_id)
            if not s:
                return {"success": False, "error": f"session {self.alias}/{session_id} not found", "server": self.alias}
            if name:
                s.name = name
        return {
            "success": True,
            "session_id": f"{self.alias}/{session_id}",
            "numeric_session_id": session_id,
            "server": self.alias
        }

    def get_session(self, session_id: Optional[int]) -> Optional[SSHSession]:
        with self.lock:
            if session_id is not None:
                return self.sessions.get(session_id)
            return None

    def total_buffer_chars(self) -> int:
        """Exact sum of buffered chars for this node (runs + scrollback). Cheap:
        ChunkBuffer reports its length without materialising the text (F7)."""
        with self.lock:
            sessions = list(self.sessions.values())
        total = 0
        for s in sessions:
            with s.lock:
                runs = list(s.runs.values())
                total += len(s.scrollback) if hasattr(s, "scrollback") else 0
            for r in runs:
                with r.lock:
                    size = getattr(r, "buffer_len", None)
                    total += size if isinstance(size, int) else len(r.output_buffer)
        return total

    def find_first_idle_alive_session(self) -> Optional[SSHSession]:
        with self.lock:
            return self._find_first_idle_alive_session_locked()

    def list_sessions(self, include_name: bool = False, include_last_command: bool = False, include_active_ids: bool = False) -> List[Dict[str, Any]]:
        rows = []
        with self.lock:
            items = list(self.sessions.items())
        for sid, s in items:
            info = s.info()
            status = "broken" if (info["dead"] or not info["alive"]) else ("busy" if s.is_busy() else "idle")
            row = {
                "session_id": f"{self.alias}/{sid}",
                "numeric_session_id": sid,
                "server": self.alias,
                "status": status,
            }
            if include_name:
                row["name"] = info.get("name")
            if include_last_command:
                row["last_command"] = info.get("last_command")
            if include_active_ids:
                row["active_run_id"] = info.get("active_run_id")
            rows.append(row)
        rows.sort(key=lambda x: x["numeric_session_id"])
        return rows

    def check_health_all(self) -> None:
        with self.lock:
            sessions = list(self.sessions.values())
        for s in sessions:
            if not s.is_dead:
                try:
                    s.check_health()
                except Exception as e:
                    log_error(f"Health check failed for session {s.id}: {e}")

    def close_all(self) -> None:
        with self.lock:
            self._closed = True
            self._epoch += 1
            sessions = list(self.sessions.values())
            self.sessions.clear()
            self._pending_sids.clear()
            self.last_tool_result_server = None
            self.last_tool_result_by_session.clear()
        for s in sessions:
            try:
                s.close(permanent=True)
                s.free_buffers()
            except Exception as e:
                log_error(f"Error closing session {s.id}: {e}")

    def get_status(self) -> str:
        with self.lock:
            if not self.sessions:
                return "configured"
            sessions = list(self.sessions.values())
        any_alive = any(s.is_alive() for s in sessions)
        if any_alive:
            return "connected"
        return "disconnected"


class ResolveResult(NamedTuple):
    node: Optional[ServerNode] = None
    numeric_sid: Optional[int] = None
    is_new_requested: bool = False
    error: Optional[str] = None


class MultiServerManager:
    def __init__(self, cache_dirs: Dict[str, str], project_tag: str, registry: Optional[ServersRegistry] = None, config_path: Optional[str] = None):
        self.cache_dirs = cache_dirs
        self.project_tag = project_tag
        self.registry = registry or config.registry
        self.config_path = config_path or config.SERVERS_CONFIG_PATH
        self.last_config_mtime: float = 0.0
        self.last_config_size: int = 0
        self.last_config_sha256: str = ""
        self.last_reload_check: float = 0.0
        self._reload_lock = threading.Lock()
        if self.config_path and os.path.isfile(self.config_path):
            try:
                self.last_config_mtime = os.path.getmtime(self.config_path)
                self.last_config_size = os.path.getsize(self.config_path)
                with open(self.config_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.last_config_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
            except Exception as e:
                log_error(f"Failed to read initial config from '{self.config_path}': {e}")
        self.nodes: Dict[str, ServerNode] = {}
        self.lock = threading.RLock()
        self.last_tool_result_global: Optional[Dict[str, Any]] = None
        self._cached_total_buffer: int = 0
        self._cached_total_buffer_time: float = 0.0
        self._buffer_cache_lock = threading.Lock()
        self.health_stop_event = threading.Event()
        try:
            cleanup_dead_session_logs(self.cache_dirs)
        except Exception as e:
            log_error(f"Initial log cleanup error: {e}")
        self.health_thread = threading.Thread(target=self._health_loop, daemon=True)
        self.health_thread.start()

    def check_reload(self, force: bool = False) -> Dict[str, Any]:
        """
        Checks if configuration file changed on disk (mtime & sha256).
        Performs hot-reload with zero downtime for unchanged servers.
        Throttled to once every 5 seconds unless force=True.
        """
        path = self.config_path or config.SERVERS_CONFIG_PATH
        if not path or not os.path.isfile(path):
            return {"reloaded": False, "reason": "no_config_file"}

        with self._reload_lock:
            now = time.time()
            if not force and (now - self.last_reload_check) < 5.0:
                return {"reloaded": False, "reason": "throttled"}
            self.last_reload_check = now

            try:
                current_mtime = os.path.getmtime(path)
                current_size = os.path.getsize(path)
            except OSError:
                return {"reloaded": False, "reason": "mtime_error"}

            if (
                not force
                and current_mtime == self.last_config_mtime
                and current_size == self.last_config_size
                and self.last_config_mtime > 0
            ):
                return {"reloaded": False, "reason": "mtime_unchanged"}

            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                current_sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
            except Exception as e:
                log_error(f"Failed to read servers config for reload: {e}")
                return {"reloaded": False, "error": str(e)}

            if not force and current_sha == self.last_config_sha256 and self.last_config_sha256:
                self.last_config_mtime = current_mtime
                self.last_config_size = current_size
                return {"reloaded": False, "reason": "content_unchanged"}

            try:
                data = json.loads(content)
            except Exception as e:
                log_error(f"Failed to parse JSON for hot-reload from '{path}': {e}")
                return {"reloaded": False, "error": f"Invalid JSON: {e}"}

            diff = self._apply_config_diff(data)
            self.last_config_mtime = current_mtime
            self.last_config_size = current_size
            self.last_config_sha256 = current_sha
            return {"reloaded": True, **diff}

    def _apply_config_diff(self, data: Dict[str, Any]) -> Dict[str, Any]:
        temp_reg = ServersRegistry()
        temp_reg.load_from_dict(data)
        new_servers = temp_reg.as_dict()

        added = []
        removed = []
        modified = []
        unchanged = []
        nodes_to_close = []

        with self.lock:
            current_servers = self.registry.as_dict()
            current_keys = set(current_servers.keys())
            new_keys = set(new_servers.keys())

            # 1. Added servers
            for alias_key in new_keys - current_keys:
                cfg = new_servers[alias_key]
                self.registry.register(cfg)
                added.append(cfg.alias)

            # 2. Removed servers. CLI-only hosts are not in servers.json and stay.
            for alias_key in current_keys - new_keys:
                old_cfg = current_servers[alias_key]
                if getattr(old_cfg, "origin", "file") == "cli":
                    continue
                node = self.nodes.pop(alias_key, None)
                if node:
                    nodes_to_close.append(node)
                self.registry.unregister(alias_key)
                removed.append(alias_key)

            # 3. Existing servers: modified or unchanged
            for alias_key in current_keys & new_keys:
                old_cfg = current_servers[alias_key]
                new_cfg = new_servers[alias_key]
                if old_cfg == new_cfg:
                    unchanged.append(new_cfg.alias)
                else:
                    self.registry.register(new_cfg)
                    node = self.nodes.get(alias_key)
                    if node:
                        creds_changed = (
                            old_cfg.host != new_cfg.host or
                            old_cfg.port != new_cfg.port or
                            old_cfg.user != new_cfg.user or
                            old_cfg.password != new_cfg.password or
                            old_cfg.key_path != new_cfg.key_path or
                            old_cfg.key_passphrase != new_cfg.key_passphrase or
                            old_cfg.verify_host != new_cfg.verify_host
                        )
                        if creds_changed:
                            # Pop node so subsequent requests get a fresh node with new credentials (Fix H1)
                            popped = self.nodes.pop(alias_key, None)
                            if popped:
                                nodes_to_close.append(popped)
                        else:
                            # Update config under node.lock and propagate to active sessions (Fix M3, Sec Hot-reload)
                            with node.lock:
                                node.server_config = new_cfg
                                for s in node.sessions.values():
                                    with s.lock:
                                        s.server_config = new_cfg
                    modified.append(new_cfg.alias)

        # Close SSH connections outside MultiServerManager.lock to prevent blocking concurrent requests
        for node in nodes_to_close:
            try:
                node.close_all()
            except Exception as e:
                log_error(f"Error closing removed/modified node: {e}")

        log_error(f"Hot-reload applied: added={added}, modified={modified}, removed={removed}, unchanged={unchanged}")
        return {
            "added": added,
            "modified": modified,
            "removed": removed,
            "unchanged": unchanged,
            "total_servers": self.registry.count()
        }

    def get_or_create_node(self, server_cfg: ServerTargetConfig) -> Optional[ServerNode]:
        key = server_cfg.alias.lower()
        with self.lock:
            current = self.registry.get(key)
            if current is None:
                return None
            node = self.nodes.get(key)
            if node is None:
                node = ServerNode(current, self.cache_dirs, self.project_tag)
                self.nodes[key] = node
            return node

    def get_node(self, name_or_ip: Optional[str]) -> Optional[ServerNode]:
        cfg = self.registry.get(name_or_ip)
        if not cfg:
            return None
        return self.get_or_create_node(cfg)

    def resolve_target(
        self,
        server: Optional[str] = None,
        session_id: Any = None
    ) -> ResolveResult:
        """
        Resolves the target ServerNode and numeric session ID.
        Returns ResolveResult with attributes (node, numeric_sid, is_new_requested, error).
        """
        target_server_str = str(server).strip() if server is not None and str(server).strip() else None
        target_sid_str = str(session_id).strip() if session_id is not None and str(session_id).strip() else None
        numeric_sid: Optional[int] = None
        new_session_requested = False

        # Case 1: session_id contains a slash: "<server>/<session_id>"
        if target_sid_str and "/" in target_sid_str:
            server_part, id_part = target_sid_str.split("/", 1)
            server_part = server_part.strip()
            id_part = id_part.strip()

            if target_server_str and target_server_str.lower() != server_part.lower():
                cfg_from_srv = self.registry.get(target_server_str)
                cfg_from_sid = self.registry.get(server_part)
                if cfg_from_srv != cfg_from_sid:
                    return ResolveResult(error=(
                        f"Conflicting server parameters: 'server' is '{target_server_str}', "
                        f"but 'session_id' specifies '{server_part}'."
                    ))

            target_server_str = server_part
            try:
                numeric_sid = int(id_part)
            except ValueError:
                return ResolveResult(error=f"Invalid session number '{id_part}' in session_id '{target_sid_str}'")

        # Case 2: session_id is provided without slash
        elif target_sid_str:
            cfg_match = self.registry.get(target_sid_str)
            if cfg_match:
                if target_server_str and target_server_str.lower() != cfg_match.alias.lower() and target_server_str.lower() != cfg_match.host.lower():
                    return ResolveResult(error=(
                        f"Conflicting server parameters: 'server' is '{target_server_str}', "
                        f"but 'session_id' is '{target_sid_str}'."
                    ))
                target_server_str = cfg_match.alias
                numeric_sid = None
                new_session_requested = False
            else:
                try:
                    numeric_sid = int(target_sid_str)
                except ValueError:
                    return ResolveResult(error=(
                        f"Invalid session_id '{target_sid_str}'. Expected '<server_name>/<id>' (e.g. 'keenetic/1') "
                        f"or server name. Available servers: [{', '.join(self.registry.aliases())}]."
                    ))

        # Target server resolution
        if not target_server_str:
            # Fallback for single-server mode if only 1 server exists
            if self.registry.count() == 1:
                single_cfg = self.registry.list_all()[0]
                node = self.get_or_create_node(single_cfg)
                if node is None:
                    return ResolveResult(error="Server is no longer configured.")
                return ResolveResult(node=node, numeric_sid=numeric_sid, is_new_requested=new_session_requested)

            available = self.registry.aliases()
            if not available:
                return ResolveResult(error="No SSH servers configured. Please check your servers configuration.")
            return ResolveResult(error=(
                f"Target server is required. Available servers: [{', '.join(available)}]. "
                f"Specify 'server': '<name>' or 'session_id': '<name>/<id>'. Call 'server_list' to view servers."
            ))

        server_cfg = self.registry.get(target_server_str)
        if not server_cfg:
            available = self.registry.aliases()
            return ResolveResult(error=(
                f"Server '{target_server_str}' not found. Available servers: [{', '.join(available)}]. "
                f"Call 'server_list' to view configured servers."
            ))

        node = self.get_or_create_node(server_cfg)
        if node is None:
            return ResolveResult(error=f"Server '{target_server_str}' is no longer configured.")
        return ResolveResult(node=node, numeric_sid=numeric_sid, is_new_requested=new_session_requested)

    def resolve_target_for_args(self, args: Dict[str, Any]) -> Tuple[Optional[ServerNode], Optional[int], bool, Optional[Dict[str, Any]]]:
        """
        Unified resolver helper for tool dispatchers.
        Extracts 'server' and 'session_id' from args, calls resolve_target.
        Returns: (node, numeric_sid, is_new_requested, error_response_dict)
        If error_response_dict is not None, dispatcher immediately returns it.
        """
        server = args.get("server")
        session_id = args.get("session_id")
        res = self.resolve_target(server=server, session_id=session_id)
        if res.error:
            return None, None, False, {"success": False, "error": str(res.error)}
        if not res.node:
            return None, None, False, {"success": False, "error": "Target server could not be resolved"}
        return res.node, res.numeric_sid, res.is_new_requested, None

    def record_tool_result(self, server_alias: Optional[str], tool_name: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        if server_alias:
            node = self.get_node(server_alias)
            if node:
                node.record_tool_result(tool_name, args, result)
        snapshot = {
            "timestamp": iso_now(),
            "server": server_alias,
            "tool": tool_name,
            "args": _sanitize_tool_data(dict(args)),
            "result": _sanitize_tool_data(dict(result))
        }
        with self.lock:
            self.last_tool_result_global = snapshot

    def get_last_tool_result(self, server: Optional[str] = None, session_id: Any = None) -> Dict[str, Any]:
        node, num_sid, _, _ = self.resolve_target(server=server, session_id=session_id)
        if node:
            return node.get_last_tool_result(num_sid)
        with self.lock:
            if self.last_tool_result_global:
                return {"success": True, **self.last_tool_result_global}
        return {"success": False, "error": "No recorded result"}

    def cancel_request(self, req_id: Any) -> Dict[str, Any]:
        """Cancel an in-flight run by JSON-RPC request id (notifications/cancelled)."""
        if req_id is None:
            return {"success": False, "error": "notifications/cancelled has no requestId"}
        with self.lock:
            nodes = list(self.nodes.values())
        for node in nodes:
            with node.lock:
                sessions = list(node.sessions.values())
            for session in sessions:
                with session.lock:
                    tracked = req_id in session.inflight_by_req
                if tracked:
                    return session.cancel_run_for_request(req_id)
        return {"success": True, "message": "nothing to cancel: request unknown or already finished"}

    def _health_loop(self) -> None:
        while not self.health_stop_event.wait(HEALTH_CHECK_INTERVAL):
            if self.health_stop_event.is_set():
                break
            try:
                self.check_reload()
                cleanup_old_logs(self.cache_dirs, max_total_bytes=MAX_LOG_TOTAL_BYTES)
                cleanup_dead_session_logs(self.cache_dirs)
                with self.lock:
                    nodes = list(self.nodes.values())
                for node in nodes:
                    if self.health_stop_event.is_set():
                        break
                    node.check_health_all()
            except Exception as e:
                log_error(f"Health check loop error: {e}")

    def list_all_servers(self, reload: bool = False) -> Dict[str, Any]:
        reload_result = self.check_reload(force=True) if reload else {}
        servers_info = []
        for cfg in self.registry.list_all():
            with self.lock:
                node = self.nodes.get(cfg.alias.lower())
            active_sessions = 0
            status = "configured"
            if node:
                with node.lock:
                    active_sessions = len(node.sessions)
                status = node.get_status()
            servers_info.append({
                "alias": cfg.alias,
                "host": f"{cfg.host}:{cfg.port}",
                "user": cfg.user,
                "status": status,
                "sessions": active_sessions,
                "description": cfg.description,
                "read_only": cfg.read_only,
            })
        resp = {"success": True, "servers": servers_info}
        if reload_result.get("reloaded"):
            resp["reload"] = reload_result
        return resp

    def list_all_sessions(
        self,
        server_filter: Optional[str] = None,
        include_name: bool = False,
        include_last_command: bool = False,
        include_active_ids: bool = False
    ) -> Dict[str, Any]:
        all_sessions = []
        if server_filter:
            matched_cfgs = self.registry.find_by_prefix(server_filter)
        else:
            matched_cfgs = self.registry.list_all()

        for cfg in matched_cfgs:
            with self.lock:
                node = self.nodes.get(cfg.alias.lower())
            if node:
                all_sessions.extend(node.list_sessions(
                    include_name=include_name,
                    include_last_command=include_last_command,
                    include_active_ids=include_active_ids
                ))

        return {"success": True, "sessions": all_sessions}

    def ensure_session(self) -> Optional[SSHSession]:
        if self.registry.count() > 0:
            first_cfg = self.registry.list_all()[0]
            node = self.get_or_create_node(first_cfg)
            if node is None:
                return None
            return node.ensure_session()
        return None

    def get_session(self, session_id: Any) -> Optional[SSHSession]:
        node, num_sid, _, _ = self.resolve_target(session_id=session_id)
        if node and num_sid is not None:
            return node.get_session(num_sid)
        return None

    def open_session(self, name: str = "", make_current: bool = False) -> Dict[str, Any]:
        if self.registry.count() > 0:
            first_cfg = self.registry.list_all()[0]
            node = self.get_or_create_node(first_cfg)
            if node is None:
                return {"success": False, "error": "Server is no longer configured"}
            return node.open_session(name=name, make_current=make_current)
        return {"success": False, "error": "No servers configured"}

    def close_session(self, session_id: Any, server: Optional[str] = None) -> Dict[str, Any]:
        node, num_sid, _, err = self.resolve_target(server=server, session_id=session_id)
        if err or not node:
            return {"success": False, "error": err or "server not resolved"}
        if num_sid is None:
            return {"success": False, "error": "session_id is required for session_close"}
        return node.close_session(num_sid)

    def update_session(self, session_id: Any, name: Optional[str] = None, make_current: Optional[bool] = None, server: Optional[str] = None) -> Dict[str, Any]:
        node, num_sid, _, err = self.resolve_target(server=server, session_id=session_id)
        if err or not node:
            return {"success": False, "error": err or "server not resolved"}
        if num_sid is None:
            return {"success": False, "error": "session_id is required for session_update"}
        return node.update_session(num_sid, name, make_current)

    def list_sessions(self, include_name: bool = False, include_last_command: bool = False, include_active_ids: bool = False, server_filter: Optional[str] = None) -> Dict[str, Any]:
        return self.list_all_sessions(
            server_filter=server_filter,
            include_name=include_name,
            include_last_command=include_last_command,
            include_active_ids=include_active_ids
        )

    def total_buffer_chars(self) -> int:
        """Live process-wide total (runs + scrollback). The old 250 ms cache let
        several readers pass the limit check on stale data (F7)."""
        return CHARS_ACCOUNT.total

    def evict_completed_run_buffers(self) -> int:
        """Drop output of finished runs until the process is under the global cap. The active run is kept."""
        with self.lock:
            nodes = list(self.nodes.values())
        victims = []
        for node in nodes:
            with node.lock:
                sessions = list(node.sessions.values())
            for session in sessions:
                with session.lock:
                    active = session.active_run_id
                    runs = list(session.runs.items())
                for rid, run in runs:
                    if rid == active or not run.done_event.is_set():
                        continue
                    with run.lock:
                        size = getattr(run, "buffer_len", None)
                        if not isinstance(size, int):
                            size = len(run.output_buffer)
                        finished = run.finished_at or 0.0
                    if size:
                        victims.append((finished, run))
        victims.sort(key=lambda item: item[0])
        freed = 0
        total = self.total_buffer_chars()
        for _finished, obj in victims:
            if total <= MAX_TOTAL_BUFFER_CHARS:
                break
            with obj.lock:
                cleared = obj.discard_all_output()
            if not cleared:
                continue
            freed += cleared
            total -= cleared
        return freed

    def can_accept_more_buffer(self, incoming: int = 0) -> bool:
        # Exact, live accounting (F7): decide on real numbers, not a cached sum.
        total = self.total_buffer_chars()
        if total + incoming > MAX_TOTAL_BUFFER_CHARS:
            self.evict_completed_run_buffers()
            total = self.total_buffer_chars()
        return (total + incoming) <= MAX_TOTAL_BUFFER_CHARS

    def close_all(self) -> None:
        self.health_stop_event.set()
        if hasattr(self, "health_thread") and self.health_thread.is_alive():
            self.health_thread.join(timeout=5.0)
            if self.health_thread.is_alive():
                log_error("Warning: health thread did not terminate within 5.0s during shutdown")
        with self.lock:
            nodes = list(self.nodes.values())
            self.nodes.clear()
        for node in nodes:
            node.close_all()
