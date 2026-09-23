"""
SSH Session management and execution engine.

Lock Hierarchy (Strict DAG - never acquire in reverse order):
    MultiServerManager.lock -> ServerNode.lock -> SSHSession.lock -> RunState.lock / PipelineState.lock
    SSHSession._connect_lock is outside SSHSession.lock. It serializes connect, reconnect,
    close, and shell spawn. Readers must not acquire it.
"""

import os
import time
import json
import socket
import secrets
import threading
import codecs
import re
import glob
from datetime import datetime
from typing import Any, Dict, Optional, List, Tuple
import paramiko

from src.config import (
    CONNECT_TIMEOUT, KEEPALIVE_INTERVAL, BUFFER_SIZE, DRAIN_BUFFER_SIZE, DEFAULT_SOCKET_TIMEOUT,
    DEFAULT_WAIT_TIMEOUT, MAX_WAIT_TIMEOUT, DEFAULT_STARTUP_WAIT, MAX_STARTUP_WAIT,
    DEFAULT_HARD_TIMEOUT, MAX_HARD_TIMEOUT, MAX_BUFFER_CHARS,
    DEFAULT_READ_MAX_LINES, DEFAULT_READ_MAX_CHARS, MAX_READ_MAX_LINES, MAX_READ_MAX_CHARS,
    DEFAULT_QUIET_COMPLETE_TIMEOUT, MAX_QUIET_COMPLETE_TIMEOUT, MAX_DOWNLOAD_BYTES,
    config, DEFAULT_PATH,
    COMPILED_PAGER_REGEXES, COMPILED_INTERACTIVE_PATTERNS, ServerTargetConfig, ANSI_ESCAPE
)
from src.utils import (
    log_error, clamp_float, clamp_int, iso_now, json_line, safe_name,
    find_prompt, parse_exit_marker, cleanup_dead_session_logs, clean_output
)
from src.security import check_command_security, escape_shell_path
from src.ssh_state import RunState, ChunkBuffer, CHARS_ACCOUNT

_buffer_checker = None
_total_buffer_getter = None

_ROUTER_CLI_PROMPT_LINE = re.compile(r"^(?:[a-zA-Z0-9._-]*\([^)\r\n]*\)|[a-zA-Z0-9._-]*)>[ \t]*$")
_KEENETIC_PROMPT_LINE = _ROUTER_CLI_PROMPT_LINE
_POSIX_PROMPT_LINE = re.compile(r"^(?:.*[#$]|[#$])[ \t]*$")


def banner_sets_posix_shell(text: Any) -> bool:
    """True when the drained login banner ends in a POSIX prompt, not an NDM `>` prompt."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", errors="replace")
    if not isinstance(text, str) or not text:
        return False
    clean = ANSI_ESCAPE.sub("", text).replace("\r", "")
    lines = [ln.strip() for ln in clean.split("\n") if ln.strip()]
    if not lines:
        return False
    last = lines[-1]
    if _KEENETIC_PROMPT_LINE.match(last):
        return False
    return _POSIX_PROMPT_LINE.match(last) is not None

def set_buffer_limit_checkers(checker_func, getter_func=None):
    global _buffer_checker, _total_buffer_getter
    _buffer_checker = checker_func
    _total_buffer_getter = getter_func

def set_buffer_limit_checker(checker_func):
    global _buffer_checker
    _buffer_checker = checker_func

def format_export_path(path: str) -> Optional[str]:
    """Single-quote a PATH value so metacharacters cannot run as shell."""
    if not path or any(ch in path for ch in ("\n", "\r", "\x00")):
        return None
    return f"export PATH='{escape_shell_path(path)}':$PATH 2>/dev/null\n"

def wrap_posix_exit_marker(command: str) -> tuple:
    """Append an exit-code marker. Multiline commands or commands with comments (#) get it on a new line."""
    token = secrets.token_hex(8)
    marker = f"printf '%s\\n' \"__MCP_EC_{token}_$?\""
    if "\n" in command or "#" in command:
        sep = "\n" if not command.endswith("\n") else ""
        wrapped = command + sep + marker
    else:
        wrapped = command + "; " + marker
    return wrapped, token


def _silence_may_finish(run) -> bool:
    """Quiet completion is only for an explicit quiet hint with no end-of-command marker."""
    if getattr(run, "completion_hint", "either") != "quiet":
        return False
    if getattr(run, "exit_marker_token", None):
        return False
    return True

def _describe_connect_error(exc: Exception, host: str, port: int) -> str:
    """Convert a connection exception into a clear, actionable error message."""
    msg = str(exc)
    exc_type = type(exc).__name__

    if "Authentication failed" in msg or "AuthenticationException" in exc_type or "No existing session" in msg:
        return (
            f"SSH authentication failed for {host}:{port}. "
            "Check your username, password or SSH key. "
            f"Detail: {msg}"
        )
    if "not found in known_hosts" in msg or "Unknown server" in msg or "HostKeys" in exc_type:
        return (
            f"SSH host key verification failed for {host}:{port}. "
            "Use --no-verify-host to skip (insecure) or add the host to known_hosts. "
            f"Detail: {msg}"
        )
    if "timed out" in msg.lower() or exc_type in ("TimeoutError", "socket.timeout"):
        return (
            f"SSH connection to {host}:{port} timed out. "
            "Host may be unreachable, blocked by firewall, or overloaded. "
            f"Detail: {msg}"
        )
    if "Connection refused" in msg or "ECONNREFUSED" in msg:
        return (
            f"SSH connection refused by {host}:{port}. "
            "Check that SSH is running on the host and the port is correct. "
            f"Detail: {msg}"
        )
    if "No route to host" in msg or "Network unreachable" in msg or "ENETUNREACH" in msg:
        return (
            f"Cannot reach {host}:{port}. "
            "Check network connectivity and that the host IP is correct. "
            f"Detail: {msg}"
        )
    if "Name or service not known" in msg or "getaddrinfo failed" in msg or "nodename nor servname" in msg:
        return (
            f"DNS resolution failed for {host}. "
            "Check that the hostname is correct. "
            f"Detail: {msg}"
        )
    return f"SSH connect failed to {host}:{port}: {msg}"


def _interrupt_fields_for(run: Any) -> Dict[str, Any]:
    """Honest metadata for an interrupted run. Only a returned prompt proves the
    command is gone; anything else must NOT claim the remote process stopped (F4)."""
    confirmed = str(getattr(run, "finish_reason", "") or "").startswith("prompt detected after interrupt")
    if confirmed:
        return {"process_stopped": True, "hint": "prompt returned after Ctrl+C - the shell is ready again"}
    return {
        "process_stopped": False,
        "hint": (
            "Ctrl+C was sent but no prompt confirmed the stop - the remote process may still "
            "be running. The shell boundary was reset (a fresh shell is created for the next "
            "command, so cwd/env are gone)."
        ),
    }


class SSHSession:
    def __init__(self, session_id: int, name: str, cache_dirs: Dict[str, str], project_tag: str, server_config: Optional[ServerTargetConfig] = None):
        self.id = session_id
        self.name = name
        self.cache_dirs = cache_dirs
        self.project_tag = project_tag
        self.server_config = server_config or ServerTargetConfig(
            alias="default",
            host=config.SSH_HOST or "localhost",
            port=config.SSH_PORT or 22,
            user=config.SSH_USER or "",
            password=config.SSH_PASSWORD,
            key_path=config.SSH_KEY_PATH,
            key_passphrase=config.SSH_KEY_PASSPHRASE,
            verify_host=config.SSH_VERIFY_HOST_KEY,
            extra_path=config.EXTRA_PATH,
            read_only=config.READ_ONLY,
            command_blacklist=config.COMMAND_BLACKLIST,
        )
        self.server_alias = self.server_config.alias

        self.client: Optional[paramiko.SSHClient] = None
        self.channel: Optional[paramiko.Channel] = None

        self.created_at = datetime.now()
        self.is_dead = False
        self._permanently_closed = False
        self.death_reason = ""
        self.death_time: Optional[datetime] = None
        self.in_shell = False
        self._is_subshell = False
        self.state_lost = False
        self._pending_stdin = ""
        self._file_op_active = False

        self.last_command = ""
        self.last_command_time: Optional[datetime] = None

        self.active_run_id: Optional[int] = None
        self.last_run_id: Optional[int] = None
        self.run_counter = 1
        self.runs: Dict[int, RunState] = {}
        self.reader_threads: Dict[int, threading.Thread] = {}
        # req_id -> run_id, for MCP notifications/cancelled (bounded FIFO, see T1.4)
        self.inflight_by_req: Dict[Any, int] = {}

        self.scrollback = ChunkBuffer(MAX_BUFFER_CHARS, account=CHARS_ACCOUNT)
        self.scrollback_cursor: int = 0

        self.lock = threading.Lock()
        self._connect_lock = threading.RLock()
        self._stdin_lock = threading.Lock()

        self.session_log_path = self._build_session_log_path()
        json_line(
            self.session_log_path,
            {
                "ts": iso_now(),
                "dir": "SYS",
                "event": "session_created",
                "session_id": f"{self.server_alias}/{self.id}",
                "server": self.server_alias,
                "numeric_session_id": self.id,
                "name": self.name,
            },
        )

    def _build_session_log_path(self) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.project_tag}__{safe_name(self.server_alias)}__s{self.id}__{safe_name(self.name)}__{stamp}.log"
        return os.path.join(self.cache_dirs["sessions_dir"], filename)

    def _build_run_log_path(self, run_id: int) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.project_tag}__{safe_name(self.server_alias)}__s{self.id}__r{run_id}__{stamp}.log"
        return os.path.join(self.cache_dirs["runs_dir"], filename)

    def _log_session(self, direction: str, payload: Dict[str, Any]) -> None:
        data = {"ts": iso_now(), "dir": direction, "session_id": f"{self.server_alias}/{self.id}", "server": self.server_alias, "numeric_session_id": self.id}
        data.update(payload)
        json_line(self.session_log_path, data)

    def _log_run(self, run: Any, direction: str, payload: Dict[str, Any]) -> None:
        if direction in ("OUT", "ERR") and getattr(config, "LOG_OUTPUT", "meta") != "full":
            # Raw output chunks are the main source of secrets and disk I/O (T2.5/F7):
            # the default 'meta' policy keeps lifecycle events and command text only.
            return
        run_id = getattr(run, "run_id", None)
        data = {"ts": iso_now(), "dir": direction, "session_id": f"{self.server_alias}/{self.id}", "server": self.server_alias, "numeric_session_id": self.id}
        if run_id is not None:
            data["run_id"] = run_id
        data.update(payload)
        json_line(run.run_log_path, data)

    def append_scrollback(self, chunk: str) -> None:
        if not chunk:
            return
        with self.lock:
            self.scrollback.append(chunk)
            if self.scrollback_cursor < self.scrollback.base_offset:
                self.scrollback_cursor = self.scrollback.base_offset

    def read_scrollback(
        self,
        offset: Optional[int],
        max_lines: int,
        max_chars: int,
    ) -> Dict[str, Any]:
        with self.lock:
            if not len(self.scrollback) and self.runs:
                for r in sorted(self.runs.values(), key=lambda x: x.run_id):
                    with r.lock:
                        self.scrollback.append(r.output_buffer)

            total_len = len(self.scrollback)
            base_offset = self.scrollback.base_offset
            use_cursor = offset is None

            if offset is None:
                offset = self.scrollback_cursor
            elif offset < 0:
                chars_from_end = abs(offset)
                offset = max(base_offset, base_offset + total_len - chars_from_end)

            dropped_data = False
            if offset < base_offset:
                offset = base_offset
                dropped_data = True

            relative = max(0, offset - base_offset)
            available = max(0, total_len - relative)
            char_cap = max(1, max_chars)
            limited = available > char_cap
            data = self.scrollback.window(relative, char_cap)

            if max_lines > 0:
                lines = data.splitlines(keepends=True)
                if len(lines) > max_lines:
                    data = "".join(lines[:max_lines])
                    limited = True

            next_offset = offset + len(data)
            if use_cursor:
                self.scrollback_cursor = next_offset

            active_r = self.runs.get(self.active_run_id) if self.active_run_id is not None else None
            last_r = self.runs.get(self.last_run_id) if self.last_run_id is not None else None

            if active_r and not active_r.done_event.is_set():
                status = "running"
                still_running = True
                exit_status = None
            elif last_r:
                still_running = not last_r.done_event.is_set()
                exit_status = last_r.exit_status
                if last_r.done_event.is_set():
                    if last_r.completion_method == "prompt_detected":
                        status = "completed"
                    elif last_r.completion_method == "interrupted":
                        status = "interrupted"
                    elif last_r.completion_method in {"exit_marker", "exit_status"}:
                        status = "completed" if last_r.exit_status == 0 else "completed_nonzero"
                    else:
                        status = last_r.status
                else:
                    status = "running"
            else:
                status = "completed"
                still_running = False
                exit_status = None

        cleaned_output = clean_output(data)
        res = {
            "success": True,
            "session_id": f"{self.server_alias}/{self.id}",
            "numeric_session_id": self.id,
            "server": self.server_alias,
            "status": status,
            "output": cleaned_output,
            "next_offset": next_offset,
            "base_offset": base_offset,
            "limited": limited,
            "still_running": still_running,
        }
        if exit_status is not None:
            res["exit_status"] = exit_status
        if dropped_data:
            res["dropped_data"] = True
        if status == "interrupted":
            res.update(_interrupt_fields_for(last_r))
        return res

    def _invoke_shell_with_timeout(self, width: int = 220, height: int = 50, timeout: float = 15.0) -> paramiko.Channel:
        """Invokes SSH shell in a separate worker thread with strict timeout to avoid infinite hangs."""
        if not self.client:
            raise RuntimeError("No SSH client available")
        holder_lock = threading.Lock()
        channel_holder = [None]
        exc_holder = [None]
        timed_out = [False]

        def _open_shell():
            try:
                ch = self.client.invoke_shell(width=width, height=height)
                with holder_lock:
                    if timed_out[0]:
                        try:
                            ch.close()
                        except Exception:
                            pass
                    else:
                        channel_holder[0] = ch
            except Exception as e:
                exc_holder[0] = e

        def _take_late_channel():
            with holder_lock:
                late = channel_holder[0]
                channel_holder[0] = None
            if late is not None:
                try:
                    late.close()
                except Exception:
                    pass

        sh_thread = threading.Thread(target=_open_shell, daemon=True)
        sh_thread.start()
        sh_thread.join(timeout=timeout)
        if sh_thread.is_alive():
            with holder_lock:
                timed_out[0] = True
            try:
                transport = self.client.get_transport() if self.client else None
                if transport:
                    transport.close()
            except Exception:
                pass
            _take_late_channel()
            sh_thread.join(0.2)
            _take_late_channel()
            raise TimeoutError(f"invoke_shell timed out after {timeout}s")
        if exc_holder[0]:
            raise exc_holder[0]
        return channel_holder[0]

    def connect(self) -> bool:
        with self._connect_lock:
            if self._permanently_closed:
                return False
            if self.is_alive():
                return True
            try:
                self.close(permanent=False)
                # A fresh connect attempt supersedes any earlier death verdict:
                # otherwise "session closed" from the teardown above would stick and
                # hide the real reason of this failure (F8).
                with self.lock:
                    self.is_dead = False
                    self.death_reason = ""
                    self.death_time = None
                self.client = paramiko.SSHClient()

                if self.server_config.verify_host:
                    self.client.load_system_host_keys()
                else:
                    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                connect_kwargs = {
                    "hostname": self.server_config.host,
                    "port": self.server_config.port,
                    "username": self.server_config.user,
                    "timeout": CONNECT_TIMEOUT,
                    "banner_timeout": 15,
                    "auth_timeout": 20,
                    "allow_agent": not (self.server_config.password or self.server_config.key_path),
                    "look_for_keys": not (self.server_config.password or self.server_config.key_path),
                }
                if self.server_config.password:
                    connect_kwargs["password"] = self.server_config.password
                if self.server_config.key_path:
                    key_path = os.path.expanduser(self.server_config.key_path)
                    connect_kwargs["key_filename"] = key_path
                    if self.server_config.key_passphrase:
                        connect_kwargs["passphrase"] = self.server_config.key_passphrase

                self.client.connect(**connect_kwargs)

                transport = self.client.get_transport()
                if transport:
                    transport.set_keepalive(KEEPALIVE_INTERVAL)
                    try:
                        if hasattr(transport, "sock") and transport.sock:
                            transport.sock.settimeout(DEFAULT_SOCKET_TIMEOUT)
                    except Exception:
                        pass

                self.channel = self._invoke_shell_with_timeout(width=220, height=50, timeout=15.0)

                self.channel.settimeout(1.0)
                time.sleep(0.4)

                banner = self._recv_ready_text()
                extra = self._setup_environment()
                if isinstance(extra, str):
                    banner += extra
                if banner_sets_posix_shell(banner):
                    self.in_shell = True
                if self._permanently_closed:
                    try:
                        if self.channel:
                            self.channel.close()
                    except Exception:
                        pass
                    self.channel = None
                    try:
                        if self.client:
                            self.client.close()
                    except Exception:
                        pass
                    self.client = None
                    self._mark_dead("session closed")
                    return False
                with self.lock:
                    self.is_dead = False
                    self.death_reason = ""
                    self.death_time = None
                self._log_session("SYS", {"event": "connected", "host": self.server_config.host, "port": self.server_config.port})
                return True
            except Exception as exc:
                reason = _describe_connect_error(exc, self.server_config.host, self.server_config.port)
                # Record the real reason BEFORE close(): close() tears down with the
                # generic "session closed" and would otherwise mask it (F8).
                self._mark_dead(reason)
                self.close()
                self._log_session("SYS", {"event": "connect_failed", "error": reason})
                return False

    def _path_value(self) -> str:
        if self.server_config.extra_path:
            return self.server_config.extra_path
        if config.EXTRA_PATH:
            return config.EXTRA_PATH
        return DEFAULT_PATH

    def _send_export_path(self) -> None:
        if not self.channel:
            return
        cmd = format_export_path(self._path_value())
        if not cmd:
            self._log_session("SYS", {"event": "env_setup_skipped", "error": "path contains newline or NUL"})
            return
        self.channel.send(cmd)

    def _recv_ready_text(self) -> str:
        """Drain bytes that are already waiting. recv_ready must be exactly True so test doubles do not spin."""
        if not self.channel:
            return ""
        parts: List[str] = []
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        try:
            while self.channel.recv_ready() is True:
                raw = self.channel.recv(DRAIN_BUFFER_SIZE)
                if isinstance(raw, (bytes, bytearray)):
                    if not raw:
                        break
                    parts.append(decoder.decode(raw))
                elif isinstance(raw, str):
                    if not raw:
                        break
                    parts.append(raw)
                else:
                    break
        except Exception:
            pass
        return "".join(parts)

    def _setup_environment(self) -> str:
        try:
            if not self.channel:
                return ""
            self._send_export_path()
            time.sleep(0.2)
            return self._recv_ready_text()
        except Exception as exc:
            self._log_session("SYS", {"event": "env_setup_warning", "error": str(exc)})
            return ""

    def _send_payload(self, channel, payload: bytes, deadline: float) -> Optional[str]:
        """Send every byte. socket.timeout retries until deadline. Non-int send() (test doubles) counts as the rest."""
        offset = 0
        while offset < len(payload):
            if time.time() > deadline:
                return "command send timed out"
            try:
                n = channel.send(payload[offset:])
            except socket.timeout:
                time.sleep(0.05)
                continue
            except Exception as exc:
                return str(exc)
            if isinstance(n, int):
                if n > 0:
                    offset += n
                else:
                    time.sleep(0.05)
            else:
                offset = len(payload)
        return None

    def _drain_ready(self, channel, limit: int = 1_000_000) -> str:
        """Read at most `limit` bytes already waiting on the channel. Further output stays in the SSH window."""
        taken = 0
        parts = []
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        while channel is not None and channel.recv_ready() and taken < limit:
            chunk = channel.recv(BUFFER_SIZE)
            if not isinstance(chunk, (bytes, bytearray)) or not chunk:
                break
            taken += len(chunk)
            parts.append(decoder.decode(chunk))
        return "".join(parts)

    def _mark_dead(self, reason: str) -> None:
        with self.lock:
            if self.is_dead:
                return
            self.is_dead = True
            self.death_reason = reason
            self.death_time = datetime.now()
        self._log_session("SYS", {"event": "session_dead", "reason": reason})
        try:
            cleanup_dead_session_logs(self.cache_dirs, server_alias=self.server_alias)
        except Exception:
            pass

    def is_alive(self) -> bool:
        if self.is_dead:
            return False
        if not self.client:
            return False
        try:
            transport = self.client.get_transport()
            return bool(transport and transport.is_active())
        except Exception:
            return False

    def check_health(self) -> bool:
        if self._permanently_closed or self.is_dead:
            return False
        if not self.client:
            self._mark_dead("no client")
            return False
        try:
            transport = self.client.get_transport()
            if not transport or not transport.is_active():
                self._mark_dead("transport disconnected")
                self.close(permanent=False)
                return False

            if not self.channel or self.channel.closed:
                with self.lock:
                    active_r = self.runs.get(self.active_run_id) if self.active_run_id else None
                if active_r and not active_r.exec_channel and not active_r.done_event.is_set():
                    self._mark_dead("channel closed during active run")
                    self.close(permanent=False)
                    return False
                with self._connect_lock:
                    if self.channel and not self.channel.closed:
                        return True
                    self.channel = self._invoke_shell_with_timeout(timeout=15.0)
                    self.channel.settimeout(1.0)
                    self.in_shell = False
                    time.sleep(0.2)
                    banner = self._recv_ready_text()
                    extra = self._setup_environment()
                    if isinstance(extra, str):
                        banner += extra
                    if banner_sets_posix_shell(banner):
                        self.in_shell = True
            return True
        except Exception as exc:
            self._mark_dead(f"health check failed: {exc}")
            self.close(permanent=False)
            return False

    def reconnect(self) -> bool:
        if self._permanently_closed:
            return False
        self._log_session("SYS", {"event": "reconnecting"})
        with self._connect_lock:
            if self._permanently_closed:
                return False
            with self.lock:
                self.is_dead = False
                self.death_reason = ""
                self.in_shell = False
                self.state_lost = True
                if self.active_run_id is not None:
                    r = self.runs.get(self.active_run_id)
                    if r:
                        r.mark_done("failed", reason="session reconnected", completion_method="reconnect")
                    self.active_run_id = None
            return self.connect()

    def ensure_alive(self) -> Optional[str]:
        if self._permanently_closed:
            return (
                f"Session {self.server_alias}/{self.id} is closed. "
                "Open a new session instead of reconnecting this one."
            )
        if self.is_dead or not self.check_health():
            log_error(f"Session {self.id} is dead. Attempting to reconnect...")
            if not self.reconnect():
                return f"Session {self.id} is DEAD: {self.death_reason}. Close it with session_close."
        return None

    def _enter_shell(self) -> bool:
        with self._connect_lock:
            if self.in_shell:
                return True
            if not self.channel:
                return False

            try:
                self._drain_ready(self.channel)

                # Non-invasive check: send newline and see if we are already in a standard shell
                self.channel.send("\n")
                time.sleep(0.2)
                if self.channel.recv_ready():
                    output = self._drain_ready(self.channel)
                    if "BusyBox" in output or re.search(r"[#$]\s*$", output.rstrip()) or re.search(r"^[#$]\s*$", output.strip()):
                        self.in_shell = True
                        self._is_subshell = False
                        self._send_export_path()
                        time.sleep(0.2)
                        self._drain_ready(self.channel)
                        self._log_session("SYS", {"event": "already_in_shell_detected"})
                        return True

                # If not already in shell, try to enter it
                for cmd in ["shell", "exec sh"]:
                    self.channel.send(f"{cmd}\n")
                    time.sleep(0.3)
                    output = ""
                    start = time.time()
                    while time.time() - start < 2.0:
                        if self.channel.recv_ready():
                            output += self._drain_ready(self.channel)
                            if "BusyBox" in output or re.search(r"[#$]\s*$", output.rstrip()):
                                self.in_shell = True
                                self._is_subshell = True
                                self._send_export_path()
                                time.sleep(0.2)
                                self._drain_ready(self.channel)
                                self._log_session("SYS", {"event": "enter_shell_ok", "method": cmd})
                                return True
                        time.sleep(0.05)

                self._log_session("SYS", {"event": "enter_shell_failed", "output_tail": output[-200:]})
                return False
            except Exception as exc:
                self._log_session("SYS", {"event": "enter_shell_error", "error": str(exc)})
                return False

    def _send_ctrl_c_raw(self) -> None:
        if self.channel and not self.channel.closed:
            self.channel.send("\x03")

    def _invalidate_pty(self, reason: str) -> None:
        """The command boundary on the PTY is unknown (partial send, interrupt without
        a prompt): a half-typed remote line would swallow the NEXT command's text.
        Kill the channel so that cannot happen (F4) and flag the state loss - a new
        shell means cwd/env are gone, which the next command is told about once.
        """
        with self.lock:
            if self.in_shell or self._is_subshell:
                self.state_lost = True
            self.in_shell = False
            self._is_subshell = False
            channel, self.channel = self.channel, None
        try:
            if channel is not None:
                channel.close()
        except Exception as e:
            log_error(f"Error closing invalidated PTY on session {self.id}: {e}")
        self._log_session("SYS", {"event": "pty_invalidated", "reason": reason})

    def _start_reader_thread(self, run: RunState):
        thread = threading.Thread(target=self._reader_loop, args=(run,), daemon=True)
        with self.lock:
            self.reader_threads[run.run_id] = thread
        thread.start()

    def _start_exec_reader_thread(self, run: RunState):
        thread = threading.Thread(target=self._exec_reader_loop, args=(run,), daemon=True)
        with self.lock:
            self.reader_threads[run.run_id] = thread
        thread.start()

    def _exit_shell(self) -> bool:
        with self._connect_lock:
            if not self.in_shell:
                return True
            if not self.channel:
                return False
            if not getattr(self, "_is_subshell", False):
                # Native login shell on standard Linux VPS — do not send 'exit' as that terminates the SSH session!
                return True
            try:
                self._drain_ready(self.channel)

                for _ in range(3):
                    self.channel.send("exit\n")
                    time.sleep(0.3)
                    output = ""
                    start = time.time()
                    while time.time() - start < 2.0:
                        if self.channel.recv_ready():
                            output += self._drain_ready(self.channel)
                            if re.search(r"(\(.*\))?>\s*$", output.rstrip()) or re.search(r"^[>#]\s*$", output.strip()):
                                self.in_shell = False
                                self._is_subshell = False
                                self._log_session("SYS", {"event": "exit_shell_ok"})
                                return True
                        time.sleep(0.05)

                self.in_shell = False
                self._log_session("SYS", {"event": "exit_shell_timeout_assumed_ok"})
                return True
            except Exception as exc:
                self._log_session("SYS", {"event": "exit_shell_error", "error": str(exc)})
                self.in_shell = False
                return False

    def _reader_loop(self, run: RunState) -> None:
        self._log_run(run, "SYS", {"event": "reader_started"})
        hard_deadline = (run.started_at + run.hard_timeout) if run.hard_timeout > 0 else None
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        try:
            while not run.done_event.is_set():
                if self.is_dead:
                    run.mark_done("dead", reason=self.death_reason, error=self.death_reason, completion_method="dead")
                    break

                if hard_deadline is not None and time.time() >= hard_deadline and not run.interrupt_sent:
                    run.interrupt_sent = True
                    run.interrupt_at = time.time()
                    self._send_ctrl_c_raw()

                if self.channel and self.channel.recv_ready():
                    if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                        # Do not recv to discard. An acknowledged SSH window lets the remote command
                        # keep producing data we would throw away. Leaving the window full blocks the
                        # remote write. read drops only the prefix the client already took; the unread
                        # tail stays, because dropping it would look like a short successful output.
                        # Ctrl+C leaves this branch on the quiet bound without reading the socket.
                        # hard_timeout defaults to 0, so without Ctrl+C or a read the pause lasts
                        # until the client reads or closes the session.
                        run.set_recv_paused(True, "memory_limit")
                        if run.interrupt_sent and getattr(run, "interrupt_at", None) is not None:
                            quiet_timeout = getattr(run, "quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)
                            if time.time() - run.interrupt_at >= quiet_timeout:
                                run.mark_done(
                                    "interrupted",
                                    reason="interrupted by ctrl_c",
                                    completion_method="interrupted",
                                )
                                with self.lock:
                                    if self.active_run_id == run.run_id:
                                        self.active_run_id = None
                                # No prompt confirmed the stop: the next command must not
                                # land in a still-running process (F4).
                                self._invalidate_pty("interrupted without prompt")
                                break
                        time.sleep(0.05)
                        continue
                    if run.recv_paused:
                        run.set_recv_paused(False)

                    try:
                        chunk_bytes = self.channel.recv(BUFFER_SIZE)
                    except socket.timeout:
                        continue
                    if not chunk_bytes:
                        self._log_run(run, "SYS", {"event": "channel_eof_detected"})
                        self._mark_dead("channel EOF")
                        run.mark_done("dead", reason="channel EOF", error="channel EOF", completion_method="eof")
                        break

                    chunk = decoder.decode(chunk_bytes)
                    run.append_output(chunk)
                    self.append_scrollback(chunk)
                    self._log_run(run, "OUT", {"chunk": chunk})

                    # Read tail under lock to prevent race condition
                    with run.lock:
                        tail = run.tail_locked(500)
                        curr_buffer = run.tail_locked(2000)

                    # Pagination detection (configurable regexes)
                    found_pager = False
                    for pattern in COMPILED_PAGER_REGEXES:
                        if pattern.search(tail):
                            found_pager = True
                            break
                    if found_pager:
                        self.channel.send(" ")
                        self._log_run(run, "SYS", {"event": "pagination_detected_sending_space"})

                    token = getattr(run, "exit_marker_token", None)
                    if token:
                        code = parse_exit_marker(curr_buffer, token)
                        if code is not None:
                            run.exit_status = code
                            done_status = "completed" if code == 0 else "completed_nonzero"
                            run.mark_done(done_status, reason=f"exit marker {code}", completion_method="exit_marker")
                            break
                    else:
                        prompt = find_prompt(curr_buffer)
                        if prompt:
                            run.prompt_detected = True
                            run.prompt_line = prompt
                            if re.search(r"[#$][ \t]*$", prompt):
                                self.in_shell = True
                            if run.interrupt_sent:
                                run.mark_done(
                                    "interrupted",
                                    reason=f"prompt detected after interrupt: {prompt}",
                                    completion_method="interrupted",
                                )
                            else:
                                run.mark_done(
                                    "completed",
                                    reason=f"prompt detected: {prompt}",
                                    completion_method="prompt_detected",
                                )
                            break
                else:
                    if run.interrupt_sent and getattr(run, "interrupt_at", None) is not None:
                        quiet_timeout = getattr(run, "quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)
                        if time.time() - run.interrupt_at >= quiet_timeout:
                            # Do not wait forever for a prompt after Ctrl+C. A shell that
                            # ignores SIGINT would keep the session busy until session_close.
                            # The quiet bound releases it - and since nothing proved the
                            # process stopped, the boundary is invalid (F4): the next
                            # command must not land inside that process.
                            run.mark_done(
                                "interrupted",
                                reason="interrupted by ctrl_c",
                                completion_method="interrupted",
                            )
                            with self.lock:
                                if self.active_run_id == run.run_id:
                                    self.active_run_id = None
                            self._invalidate_pty("interrupted without prompt")
                            break
                    if run.mode == "sync":
                        hint = getattr(run, "completion_hint", "either")
                        quiet_timeout = getattr(run, "quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)
                        stdin_recent = False
                        if run.last_stdin_at is not None:
                            stdin_recent = (time.time() - run.last_stdin_at) < quiet_timeout

                        if run.total_received_chars > 0 and (time.time() - run.last_data_at) >= quiet_timeout and not stdin_recent:
                            if hint in ("quiet", "either"):
                                # Interactive hang check
                                with run.lock:
                                    tail = run.tail_locked(200)
                                clean_tail = ANSI_ESCAPE.sub("", tail)
                                is_interactive = False
                                for pattern in COMPILED_INTERACTIVE_PATTERNS:
                                    if pattern.search(clean_tail):
                                        is_interactive = True
                                        break
                                if is_interactive:
                                    run.interrupt_sent = True
                                    self._send_ctrl_c_raw()
                                    run.mark_done(
                                        "failed",
                                        reason="interactive_prompt_detected",
                                        error=(
                                            "Interactive prompt detected. Command was aborted to prevent hang. "
                                            "Please execute the command using non-interactive flags (e.g., -y, --force, "
                                            "DEBIAN_FRONTEND=noninteractive) or pass input through signal:stdin."
                                        ),
                                        completion_method="aborted_interactive"
                                    )
                                    break
                                elif _silence_may_finish(run) and not run.quiet_event.is_set():
                                    run.quiet_event.set()
                    time.sleep(0.05)
        except Exception as exc:
            run.mark_done("failed", reason="reader exception", error=str(exc), completion_method="failed")
        finally:
            with self.lock:
                if self.active_run_id == run.run_id:
                    self.active_run_id = None
                self.last_run_id = run.run_id

    def _exec_reader_loop(self, run: RunState) -> None:
        self._log_run(run, "SYS", {"event": "exec_reader_started"})
        hard_deadline = (run.started_at + run.hard_timeout) if run.hard_timeout > 0 else None
        decoder_out = codecs.getincrementaldecoder("utf-8")(errors="replace")
        decoder_err = codecs.getincrementaldecoder("utf-8")(errors="replace")

        try:
            channel = run.exec_channel
            while not run.done_event.is_set():
                if self.is_dead:
                    run.mark_done("dead", reason=self.death_reason, error=self.death_reason, completion_method="dead")
                    break

                if hard_deadline is not None and time.time() >= hard_deadline:
                    run.interrupt_sent = True
                    try:
                        if channel:
                            channel.close()
                    except Exception as e:
                        log_error(f"Error closing exec channel on timeout: {e}")
                    run.mark_done("hard_timeout", reason="hard timeout reached", completion_method="hard_timeout")
                    break

                has_data = False
                if channel and (channel.recv_ready() or channel.recv_stderr_ready()):
                    if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                        run.set_recv_paused(True, "memory_limit")
                        time.sleep(0.05)
                        continue
                    if run.recv_paused:
                        run.set_recv_paused(False)

                if channel and channel.recv_ready():
                    try:
                        chunk_bytes = channel.recv(BUFFER_SIZE)
                    except socket.timeout:
                        chunk_bytes = None
                    if chunk_bytes == b"":
                        if channel.exit_status_ready():
                            run.exit_status = channel.recv_exit_status()
                            run.mark_done(
                                "completed" if run.exit_status == 0 else "completed_nonzero",
                                reason=f"exit status {run.exit_status}",
                                completion_method="exit_status",
                            )
                            break
                        if getattr(channel, "closed", False) is True:
                            self._log_run(run, "SYS", {"event": "exec_stdout_eof"})
                            run.mark_done("failed", reason="channel EOF", error="channel EOF", completion_method="eof")
                            break
                        time.sleep(0.02)
                    elif chunk_bytes:
                        chunk = decoder_out.decode(chunk_bytes)
                        run.append_output(chunk)
                        self.append_scrollback(chunk)
                        self._log_run(run, "OUT", {"chunk": chunk})
                        has_data = True

                if channel and channel.recv_stderr_ready():
                    try:
                        chunk_bytes = channel.recv_stderr(BUFFER_SIZE)
                    except socket.timeout:
                        chunk_bytes = None
                    if chunk_bytes == b"":
                        if channel.exit_status_ready():
                            run.exit_status = channel.recv_exit_status()
                            run.mark_done(
                                "completed" if run.exit_status == 0 else "completed_nonzero",
                                reason=f"exit status {run.exit_status}",
                                completion_method="exit_status",
                            )
                            break
                        if getattr(channel, "closed", False) is True:
                            self._log_run(run, "SYS", {"event": "exec_stderr_eof"})
                            run.mark_done("failed", reason="channel EOF", error="channel EOF", completion_method="eof")
                            break
                        time.sleep(0.02)
                    elif chunk_bytes:
                        chunk = decoder_err.decode(chunk_bytes)
                        run.append_output(chunk)
                        self.append_scrollback(chunk)
                        self._log_run(run, "ERR", {"chunk": chunk})
                        has_data = True

                if channel and channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    run.exit_status = channel.recv_exit_status()
                    run.mark_done("completed" if run.exit_status == 0 else "completed_nonzero", reason=f"exit status {run.exit_status}", completion_method="exit_status")
                    break

                if not has_data:
                    if (
                        _silence_may_finish(run)
                        and run.total_received_chars == 0
                        and (time.time() - run.started_at) >= run.startup_wait
                        and not run.quiet_event.is_set()
                    ):
                        run.quiet_event.set()
                    if run.mode == "sync":
                        quiet_timeout = getattr(run, "quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)
                        if run.total_received_chars > 0 and (time.time() - run.last_data_at) >= quiet_timeout:
                            with run.lock:
                                tail = run.tail_locked(200)
                            clean_tail = ANSI_ESCAPE.sub("", tail)
                            is_interactive = False
                            for pattern in COMPILED_INTERACTIVE_PATTERNS:
                                if pattern.search(clean_tail):
                                    is_interactive = True
                                    break
                            if is_interactive:
                                run.interrupt_sent = True
                                try:
                                    if channel:
                                        channel.close()
                                except Exception as e:
                                    log_error(f"Error closing exec channel on interactive hang: {e}")
                                run.mark_done(
                                    "failed",
                                    reason="interactive_prompt_detected",
                                    error=(
                                        "Interactive prompt detected. Command was aborted to prevent hang. "
                                        "Please execute the command using non-interactive flags (e.g., -y, --force, "
                                        "DEBIAN_FRONTEND=noninteractive) or pass input through signal:stdin."
                                    ),
                                    completion_method="aborted_interactive"
                                )
                                break
                            elif _silence_may_finish(run) and not run.quiet_event.is_set():
                                run.quiet_event.set()
                    time.sleep(0.05)
        except Exception as exc:
            run.mark_done("failed", reason="reader exception", error=str(exc), completion_method="failed")
        finally:
            try:
                if run.exec_stdin:
                    run.exec_stdin.close()
                if channel:
                    channel.close()
                if run.exec_stdout:
                    run.exec_stdout.close()
                if run.exec_stderr:
                    run.exec_stderr.close()
            except Exception as e:
                log_error(f"Error closing exec channel in reader finally: {e}")
            with self.lock:
                if self.active_run_id == run.run_id:
                    self.active_run_id = None
                self.last_run_id = run.run_id

    def _cleanup_old_runs(self) -> None:
        to_clean_runs = []
        with self.lock:
            # Cleanup runs
            run_ids = sorted(self.runs.keys())
            if len(run_ids) > 10:
                for rid in run_ids[:-10]:
                    r = self.runs.get(rid)
                    if r and rid != self.active_run_id and r.done_event.is_set():
                        to_clean_runs.append(self.runs.pop(rid))
                        self.reader_threads.pop(rid, None)

        for r in to_clean_runs:
            with r.lock:
                r.discard_all_output()

    def _check_security(self, command: str) -> Optional[Dict[str, Any]]:
        return check_command_security(
            command=command,
            server_alias=self.server_alias,
            numeric_sid=self.id,
            server_blacklist=self.server_config.command_blacklist,
            global_blacklist=config.COMMAND_BLACKLIST,
            server_read_only=bool(self.server_config.read_only),
            global_read_only=bool(config.READ_ONLY),
        )

    def run_command(
        self,
        command: str,
        mode: str,
        shell: bool,
        wait_timeout: float,
        startup_wait: float,
        hard_timeout: float,
        completion_hint: str,
        quiet_complete_timeout: float,
        max_chars: Optional[int] = None,
        max_lines: Optional[int] = None,
        background: bool = False,
        use_pty: bool = True,
        internal: bool = False,
        req_id: Any = None,
    ) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error:
            return {"success": False, "error": error, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}

        mode = (mode or "sync").lower().strip()
        if background or mode == "async":
            wait_timeout = 0.0
        wait_timeout = clamp_float(wait_timeout, DEFAULT_WAIT_TIMEOUT, 0.0, MAX_WAIT_TIMEOUT)
        startup_wait = clamp_float(startup_wait, DEFAULT_STARTUP_WAIT, 0.1, MAX_STARTUP_WAIT)
        hard_timeout = clamp_float(hard_timeout, DEFAULT_HARD_TIMEOUT, 0.0, MAX_HARD_TIMEOUT)
        quiet_complete_timeout = clamp_float(quiet_complete_timeout, DEFAULT_QUIET_COMPLETE_TIMEOUT, 0.1, MAX_QUIET_COMPLETE_TIMEOUT)

        # internal=True is only for gateway-built maintenance (mkdir, rm of our temp
        # file, heredoc). The read-only gate already ran in file_dispatch. Passing
        # these strings through the server blacklist would strand a temp file on a
        # host whose blacklist contains rm. Do not use internal=True for text that
        # came from the model.
        if not internal:
            sec_err = self._check_security(command)
            if sec_err:
                return sec_err

        # Atomic busy check + reservation
        with self.lock:
            if self._file_op_active and not internal:
                return {
                    "success": False,
                    "error": (
                        f"Session {self.server_alias}/{self.id} is busy with a file operation. "
                        "An SSH session is a single terminal process (PTY) and cannot run commands in parallel. "
                        "Use 'new_session=true' to run concurrently in a new session, or wait for the operation to complete."
                    ),
                    "session_id": f"{self.server_alias}/{self.id}",
                    "numeric_session_id": self.id,
                    "server": self.server_alias,
                }
            if self.active_run_id is not None:
                r = self.runs.get(self.active_run_id)
                if r and not r.done_event.is_set():
                    active_cmd = r.command or self.last_command or ""
                    cmd_info = f" running '{active_cmd}'" if active_cmd else ""
                    return {
                        "success": False,
                        "error": (
                            f"Session {self.server_alias}/{self.id} is busy{cmd_info}. "
                            "An SSH session is a single shell terminal and cannot run commands in parallel. "
                            "Use 'new_session=true' to execute concurrently in a new session, or wait for the active command to finish (or send signal 'ctrl_c')."
                        ),
                        "session_id": f"{self.server_alias}/{self.id}",
                        "numeric_session_id": self.id,
                        "server": self.server_alias
                    }

            if self.state_lost and not internal:
                self.state_lost = False  # One-shot: the next command may run
                # For router CLI (shell is False), commands are stateless (e.g. show version),
                # so do not reject the command. Only reject for Linux bash/sh sessions where cd/env were lost.
                if shell is not False:
                    return {
                        "success": False,
                        "error": (
                            f"Warning: Connection for session {self.server_alias}/{self.id} was lost and auto-recovered! "
                            "Your interactive shell state (working directory, env variables, etc.) has been reset. "
                            f"To prevent errors or damage, your command '{command}' was NOT executed. "
                            "Please run your environment setup commands again (e.g. 'cd <dir>') and then repeat your command."
                        ),
                        "session_id": f"{self.server_alias}/{self.id}",
                        "numeric_session_id": self.id,
                        "server": self.server_alias,
                        "status": "failed"
                    }

            run_id = self.run_counter
            self.run_counter += 1
            run = RunState(
                run_id=run_id, session_id=self.id, command=command, mode=mode,
                started_at=time.time(), wait_timeout=wait_timeout, startup_wait=startup_wait,
                hard_timeout=hard_timeout, max_buffer_chars=MAX_BUFFER_CHARS,
                run_log_path=self._build_run_log_path(run_id)
            )
            run.completion_hint = completion_hint
            run.quiet_complete_timeout = quiet_complete_timeout

            self.runs[run_id] = run
            self.active_run_id = run_id
            self.last_run_id = run_id
            if req_id is not None:
                run.req_id = req_id
                self.inflight_by_req[req_id] = run_id
                # bounded FIFO: stale entries are harmless (cancel checks active_run_id)
                while len(self.inflight_by_req) > 256:
                    self.inflight_by_req.pop(next(iter(self.inflight_by_req)))

        self._cleanup_old_runs()

        # Log run creation to run log file
        try:
            json_line(run.run_log_path, {
                "ts": iso_now(),
                "dir": "SYS",
                "event": "run_created",
                "command": command,
                "mode": mode,
                "started_at": run.started_at,
                "wait_timeout": wait_timeout,
                "startup_wait": startup_wait,
                "hard_timeout": hard_timeout
            })
        except Exception as e:
            log_error(f"Failed to write run_created log: {e}")

        self.last_command = command
        self.last_command_time = datetime.now()

        if use_pty:
            if shell is True and not self.in_shell:
                if not self._enter_shell():
                    with self.lock:
                        if self.active_run_id == run_id:
                            self.active_run_id = None
                    run.mark_done("failed", error=f"Failed to enter system shell on server '{self.server_alias}'")
                    return {"success": False, "error": f"Failed to enter system shell on server '{self.server_alias}'", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}
            elif shell is False and self.in_shell:
                if not self._exit_shell():
                    with self.lock:
                        if self.active_run_id == run_id:
                            self.active_run_id = None
                    run.mark_done("failed", error=f"Failed to exit system shell on server '{self.server_alias}'")
                    return {"success": False, "error": f"Failed to exit system shell on server '{self.server_alias}'", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}

            if self.channel:
                old_t = self.channel.gettimeout()
                self.channel.settimeout(0.1)
                try:
                    self._drain_ready(self.channel)
                except Exception:
                    pass
                self.channel.settimeout(old_t)

        wire_command = command
        # The marker is a POSIX printf of $?. Keenetic NDM treats that text as a CLI
        # command, so shell=false must not send it. A banner that is only '>' or
        # '(config)>' does not set in_shell. A POSIX banner (user@host, ~$ / ~#) does,
        # and then this same condition sends the marker even when the tool default
        # is shell=false.
        if use_pty and (shell is True or (shell is None and self.in_shell)):
            wire_command, marker_token = wrap_posix_exit_marker(command)
            run.exit_marker_token = marker_token

        try:
            if use_pty:
                if not self.channel:
                    with self.lock:
                        if self.active_run_id == run_id:
                            self.active_run_id = None
                    run.mark_done("failed", error="No channel")
                    return {"success": False, "error": "No channel", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}
                # Reader must be running before send so a large payload cannot fill the window.
                self._start_reader_thread(run)
                send_deadline = time.time() + 30.0
                if hard_timeout and hard_timeout > 30.0:
                    send_deadline = time.time() + hard_timeout
                send_err = self._send_payload(self.channel, (wire_command + "\n").encode("utf-8", errors="replace"), send_deadline)
                if send_err:
                    with self.lock:
                        if self.active_run_id == run_id:
                            self.active_run_id = None
                    run.mark_done("failed", error=send_err, completion_method="failed")
                    # A partial send leaves a half-typed line open on the remote shell:
                    # the next command would be appended to it. Kill the PTY (F4).
                    self._invalidate_pty(f"command send failed: {send_err}")
                    return {"success": False, "error": send_err, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias, "run_id": run_id}
            else:
                if not self.client:
                    with self.lock:
                        if self.active_run_id == run_id:
                            self.active_run_id = None
                    run.mark_done("failed", error="No client")
                    return {"success": False, "error": "No client", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}
                run.exec_stdin, run.exec_stdout, run.exec_stderr = self.client.exec_command(command, get_pty=False)
                run.exec_channel = run.exec_stdout.channel
                run.exec_stdin_closed = False
                if run.exec_channel:
                    run.exec_channel.settimeout(DEFAULT_SOCKET_TIMEOUT)
                if run.exec_stdin is not None:
                    try:
                        run.exec_stdin.channel.shutdown_write()
                        run.exec_stdin_closed = True
                    except Exception as exc:
                        log_error(f"Error closing exec stdin: {exc}")
                self.append_scrollback(f"$ {command}\n")
                self._start_exec_reader_thread(run)
        except Exception as exc:
            for stream in (run.exec_stdin, run.exec_stdout, run.exec_stderr):
                try:
                    if stream is not None:
                        stream.close()
                except Exception:
                    pass
            if run.exec_channel is not None:
                try:
                    run.exec_channel.close()
                except Exception:
                    pass
            with self.lock:
                if self.active_run_id == run_id:
                    self.active_run_id = None
            run.mark_done("failed", error=str(exc))
            return {"success": False, "error": str(exc), "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}

        if wait_timeout == 0.0:
            # Confirmed async start: wait up to 0.5s for initial activity or fast completion
            start_wait = time.time()
            while time.time() - start_wait < 0.5:
                if run.done_event.wait(timeout=0.05):
                    break
                if run.total_received_chars > 0:
                    break
        elif mode == "sync" and completion_hint in ("quiet", "either"):
            start_wait = time.time()
            while time.time() - start_wait < wait_timeout:
                if run.done_event.wait(timeout=0.1):
                    break
                if _silence_may_finish(run) and run.quiet_event.is_set():
                    break
        else:
            wait_for = wait_timeout if mode == "sync" else startup_wait
            run.done_event.wait(wait_for)

        char_ceiling = MAX_BUFFER_CHARS if internal else MAX_READ_MAX_CHARS
        read_chars = clamp_int(max_chars, DEFAULT_READ_MAX_CHARS, 100, char_ceiling) if max_chars is not None else DEFAULT_READ_MAX_CHARS
        slice_lines = DEFAULT_READ_MAX_LINES if max_lines is None else max(0, int(max_lines))
        snapshot = run.read_slice(offset=None, max_lines=slice_lines, max_chars=read_chars)

        status = snapshot["status"]
        if snapshot["output_complete"]:
            if run.completion_method == "prompt_detected":
                status = "completed"
            elif run.completion_method == "interrupted":
                status = "interrupted"
            elif run.completion_method in {"exit_status", "exit_marker"}:
                status = "completed" if run.exit_status == 0 else "completed_nonzero"
        elif _silence_may_finish(run) and run.quiet_event.is_set():
            status = "stalled"
        elif not snapshot["output_complete"]:
            status = "running"

        resp = {
            "success": True,
            "session_id": f"{self.server_alias}/{self.id}",
            "numeric_session_id": self.id,
            "server": self.server_alias,
            "run_id": run_id,
            "status": status,
            "output": snapshot["output"],
            "next_offset": snapshot["next_offset"],
            "limited": snapshot["limited"],
            "still_running": snapshot["still_running"],
            "total_chars": snapshot["total_received_chars"],
        }
        if snapshot.get("recv_paused"):
            resp["recv_paused"] = True
            resp["pause_reason"] = snapshot.get("pause_reason") or ""
        if background:
            resp["message"] = f"Command started in background on session {self.server_alias}/{self.id}"
        if status == "dead" and snapshot.get("error"):
            resp["error"] = snapshot["error"]
        if run.exit_status is not None:
            resp["exit_status"] = run.exit_status
        if status == "interrupted":
            resp.update(_interrupt_fields_for(run))
        return resp

    def _restore_run_from_disk(self, run_id: int) -> Optional[RunState]:
        pattern = os.path.join(self.cache_dirs["runs_dir"], f"{self.project_tag}__{safe_name(self.server_alias)}__s{self.id}__r{run_id}__*.log")
        files = glob.glob(pattern)
        if not files:
            pattern_old = os.path.join(self.cache_dirs["runs_dir"], f"{self.project_tag}__s{self.id}__r{run_id}__*.log")
            files = glob.glob(pattern_old)
        if not files:
            return None

        files.sort(key=os.path.getmtime)
        filepath = files[-1]

        try:
            started_at = os.path.getctime(filepath)
        except OSError:
            started_at = time.time()

        run = RunState(
            run_id=run_id,
            session_id=self.id,
            command="",
            mode="sync",
            started_at=started_at,
            wait_timeout=20.0,
            startup_wait=2.0,
            hard_timeout=0.0,
            max_buffer_chars=MAX_BUFFER_CHARS,
            run_log_path=filepath
        )

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                        direction = evt.get("dir")
                        if direction in ("OUT", "ERR"):
                            chunk = evt.get("chunk", "")
                            if chunk:
                                run.append_output(chunk)
                        elif direction == "SYS":
                            event = evt.get("event")
                            if event == "run_created":
                                run.command = evt.get("command", "")
                                run.mode = evt.get("mode", "sync")
                                run.started_at = evt.get("started_at", run.started_at)
                                run.wait_timeout = evt.get("wait_timeout", run.wait_timeout)
                                run.startup_wait = evt.get("startup_wait", run.startup_wait)
                                run.hard_timeout = evt.get("hard_timeout", run.hard_timeout)
                            elif event == "run_done":
                                run.status = evt.get("status", "completed")
                                run.finish_reason = evt.get("reason", "")
                                run.error = evt.get("error", "")
                                run.exit_status = evt.get("exit_status")
                                run.completion_method = evt.get("completion_method", "")
                                run.finished_at = evt.get("finished_at")
                                run.done_event.set()
                    except Exception as e:
                        log_error(f"Error parsing line in run log {filepath}: {e}")
        except Exception as exc:
            log_error(f"Failed to read log file for run {run_id}: {exc}")
            return None

        if not run.done_event.is_set():
            run.status = "interrupted"
            run.finish_reason = "restored_incomplete_log"
            run.done_event.set()

        with self.lock:
            self.runs[run_id] = run
        self._cleanup_old_runs()

        return run

    def read_run(self, run_id: Optional[int], offset: Optional[int], max_lines: int, max_chars: int, wait_timeout: float = 5.0) -> Dict[str, Any]:
        max_lines = clamp_int(max_lines, DEFAULT_READ_MAX_LINES, 1, MAX_READ_MAX_LINES)
        max_chars = clamp_int(max_chars, DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)

        # 1. Explicit run_id provided (internal callers / backward-compat unit tests)
        if run_id is not None:
            selected = None
            with self.lock:
                selected = self.runs.get(run_id)

            if not selected:
                selected = self._restore_run_from_disk(run_id)

            if not selected:
                return {"success": False, "error": "No run found", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}

            if not selected.done_event.is_set() and wait_timeout and wait_timeout > 0:
                selected.done_event.wait(timeout=wait_timeout)

            snapshot = selected.read_slice(offset=offset, max_lines=max_lines, max_chars=max_chars)
            # T2.4/F7: a fully-consumed buffer goes back to the pool (discard_through
            # used to be dead code). A later rewind then honestly reports dropped_data;
            # tab-level history (scrollback) still supports offset=0.
            if snapshot["next_offset"] >= selected.buffer_base_offset + selected.buffer_len:
                selected.discard_through(snapshot["next_offset"])
            status = selected.status
            if selected.done_event.is_set():
                if selected.completion_method == "prompt_detected":
                    status = "completed"
                elif selected.completion_method == "interrupted":
                    status = "interrupted"
                elif selected.completion_method in {"exit_marker", "exit_status"}:
                    status = "completed" if selected.exit_status == 0 else "completed_nonzero"
            elif selected.quiet_event.is_set():
                status = "stalled"
            elif not selected.done_event.is_set():
                status = "running"

            result = {
                "success": True,
                "session_id": f"{self.server_alias}/{self.id}",
                "numeric_session_id": self.id,
                "server": self.server_alias,
                "run_id": selected.run_id,
                "status": status,
                "output": snapshot["output"],
                "next_offset": snapshot["next_offset"],
                "limited": snapshot["limited"],
                "still_running": not selected.done_event.is_set(),
                "total_chars": snapshot["total_received_chars"],
            }
            if selected.exit_status is not None:
                result["exit_status"] = selected.exit_status
            if snapshot.get("recv_paused"):
                result["recv_paused"] = True
                result["pause_reason"] = snapshot.get("pause_reason") or ""
            if snapshot.get("dropped_data"):
                result["dropped_data"] = True
            if status == "interrupted":
                result.update(_interrupt_fields_for(selected))
            return result

        # 2. run_id is None -> Tab-level read
        active_r = None
        with self.lock:
            if self.active_run_id is not None:
                active_r = self.runs.get(self.active_run_id)

        if active_r is not None and not active_r.done_event.is_set() and wait_timeout and wait_timeout > 0:
            active_r.done_event.wait(timeout=wait_timeout)

        if offset is None:
            target_r = active_r
            if target_r is None:
                with self.lock:
                    if self.last_run_id is not None:
                        target_r = self.runs.get(self.last_run_id)

            if target_r is not None and target_r.shared_cursor < target_r.buffer_len:
                snapshot = target_r.read_slice(offset=None, max_lines=max_lines, max_chars=max_chars)
                status = target_r.status
                if target_r.done_event.is_set():
                    if target_r.completion_method == "prompt_detected":
                        status = "completed"
                    elif target_r.completion_method == "interrupted":
                        status = "interrupted"
                    elif target_r.completion_method in {"exit_marker", "exit_status"}:
                        status = "completed" if target_r.exit_status == 0 else "completed_nonzero"
                elif target_r.quiet_event.is_set():
                    status = "stalled"
                elif not target_r.done_event.is_set():
                    status = "running"

                result = {
                    "success": True,
                    "session_id": f"{self.server_alias}/{self.id}",
                    "numeric_session_id": self.id,
                    "server": self.server_alias,
                    "status": status,
                    "output": snapshot["output"],
                    "next_offset": snapshot["next_offset"],
                    "limited": snapshot["limited"],
                    "still_running": not target_r.done_event.is_set(),
                    "total_chars": snapshot["total_received_chars"],
                }
                if target_r.exit_status is not None:
                    result["exit_status"] = target_r.exit_status
                if snapshot.get("recv_paused"):
                    result["recv_paused"] = True
                    result["pause_reason"] = snapshot.get("pause_reason") or ""
                if snapshot.get("dropped_data"):
                    result["dropped_data"] = True
                if status == "interrupted":
                    result.update(_interrupt_fields_for(target_r))
                return result

        return self.read_scrollback(offset=offset, max_lines=max_lines, max_chars=max_chars)

    def cancel_run_for_request(self, req_id: Any) -> Dict[str, Any]:
        """MCP notifications/cancelled: interrupt the run started by that request.
        Only acts while the request's run is still active AND unfinished, so a late
        cancellation can never kill an unrelated newer command (T1.4)."""
        with self.lock:
            run_id = self.inflight_by_req.get(req_id)
            run = self.runs.get(run_id) if run_id is not None else None
            active = self.active_run_id
        if run_id is None or active != run_id or run is None or run.done_event.is_set():
            return {"success": True, "message": "nothing to cancel: request already finished"}
        return self.send_signal("ctrl_c")

    def begin_file_op(self) -> bool:
        with self.lock:
            if self._file_op_active:
                return False
            if self.active_run_id is not None:
                r = self.runs.get(self.active_run_id)
                if r and not r.done_event.is_set():
                    return False
            self._file_op_active = True
            return True

    def end_file_op(self) -> None:
        with self.lock:
            self._file_op_active = False

    def busy_info(self) -> Dict[str, Any]:
        with self.lock:
            if self._file_op_active:
                return {"busy": True, "type": "file"}
            if self.active_run_id is not None:
                r = self.runs.get(self.active_run_id)
                if r and not r.done_event.is_set():
                    return {"busy": True, "type": "run", "id": r.run_id}
        return {"busy": False}

    def is_busy(self) -> bool:
        return bool(self.busy_info().get("busy"))

    def send_signal(self, action: str, text: str = "", press_enter: bool = True) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error:
            return {"success": False, "error": error, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}

        target_channel = self.channel
        with self.lock:
            r = self.runs.get(self.active_run_id) if self.active_run_id else None
            if r and r.exec_channel:
                target_channel = r.exec_channel

        if action == "ctrl_c":
            shell_target = target_channel is not None and target_channel is self.channel
            if shell_target:
                if not target_channel.closed:
                    self._send_ctrl_c_raw()
                if r is not None:
                    r.interrupt_sent = True
                    if getattr(r, "interrupt_at", None) is None:
                        r.interrupt_at = time.time()
                return {"success": True, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias, "status": "interrupted", "message": "SIGINT (Ctrl+C) sent"}
            if target_channel and not target_channel.closed:
                try:
                    target_channel.close()
                except Exception as e:
                    log_error(f"Error closing target channel on ctrl_c: {e}")
            with self.lock:
                if r is not None and self.active_run_id == r.run_id:
                    self.active_run_id = None
            if r:
                r.interrupt_sent = True
                r.mark_done("interrupted", reason="interrupted by ctrl_c", completion_method="interrupted")
            return {"success": True, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias, "status": "interrupted", "message": "SIGINT (Ctrl+C) sent"}

        if action in ("stdin", "eof"):
            if not r:
                return {
                    "success": False,
                    "error": "No active command to receive input. Send commands using 'run' instead.",
                    "session_id": f"{self.server_alias}/{self.id}",
                    "numeric_session_id": self.id,
                    "server": self.server_alias
                }

        if action == "eof":
            if target_channel and not target_channel.closed:
                try:
                    target_channel.send("\x04")
                except Exception as e:
                    log_error(f"Error sending EOF to channel: {e}")
            return {"success": True, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias, "message": "EOF sent"}

        if action == "stdin":
            if r is not None and r.exec_stdin_closed:
                return {
                    "success": False,
                    "error": "exec channel stdin is closed",
                    "session_id": f"{self.server_alias}/{self.id}",
                    "numeric_session_id": self.id,
                    "server": self.server_alias,
                }
            with self._stdin_lock:
                pending = self._pending_stdin + text
                sec_err = self._check_security(pending)
                if sec_err:
                    self._pending_stdin = ""
                    return sec_err
                if not press_enter:
                    self._pending_stdin = pending
                    return {
                        "success": True,
                        "session_id": f"{self.server_alias}/{self.id}",
                        "numeric_session_id": self.id,
                        "server": self.server_alias,
                        "message": "stdin buffered",
                    }
                self._pending_stdin = ""
                if not target_channel or target_channel.closed:
                    return {"success": False, "error": "Channel closed", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}
                payload = (pending + "\n").encode("utf-8", errors="replace")
                send_err = self._send_payload(target_channel, payload, time.time() + 30.0)
                if send_err:
                    return {"success": False, "error": send_err, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}
            if r and not r.done_event.is_set():
                r.register_stdin()
            return {"success": True, "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias, "message": "stdin sent"}

        return {"success": False, "error": f"Unknown signal action '{action}'", "session_id": f"{self.server_alias}/{self.id}", "numeric_session_id": self.id, "server": self.server_alias}

    def open_sftp(self) -> Optional[paramiko.SFTPClient]:
        if not self.client or self.ensure_alive() is not None:
            return None
        try:
            return self.client.open_sftp()
        except Exception as e:
            log_error(f"Failed to open SFTP client on session {self.id}: {e}")
            return None

    def close(self, permanent: bool = False) -> None:
        with self._connect_lock:
            self._close_locked(permanent)

    def _close_locked(self, permanent: bool) -> None:
        if permanent:
            with self.lock:
                self._permanently_closed = True
        self._mark_dead("session closed")

        with self.lock:
            active_r = self.runs.get(self.active_run_id) if self.active_run_id else None
            threads_to_join = list(self.reader_threads.values())
            all_runs = list(self.runs.values())

        if active_r and not active_r.done_event.is_set():
            active_r.mark_done("dead", reason="session closed", error="session closed", completion_method="dead")

        # NOTE: buffered output stays readable after death on purpose (read_run on a
        # dead session is a feature). Freeing happens in free_buffers() when the
        # session leaves its node and can no longer be read at all.

        for r in all_runs:
            try:
                if r.exec_stdin:
                    r.exec_stdin.close()
                if r.exec_channel:
                    r.exec_channel.close()
                if r.exec_stdout:
                    r.exec_stdout.close()
                if r.exec_stderr:
                    r.exec_stderr.close()
            except Exception:
                pass

        try:
            if self.channel:
                self.channel.close()
        except Exception as e:
            log_error(f"Error closing channel in session {self.id}: {e}")
        self.channel = None

        try:
            if self.client:
                self.client.close()
        except Exception as e:
            log_error(f"Error closing client in session {self.id}: {e}")
        self.client = None

        for th in threads_to_join:
            if th.is_alive() and th != threading.current_thread():
                th.join(timeout=1.5)

    def free_buffers(self) -> None:
        """Release buffered output and its char accounting. Called when the session
        leaves its node (closed/purged): after that it cannot be read anymore (F7)."""
        with self.lock:
            for r in list(self.runs.values()):
                try:
                    with r.lock:
                        r.discard_all_output()
                except Exception:
                    pass
            self.scrollback.clear()

    def info(self) -> Dict[str, Any]:
        with self.lock:
            active = self.active_run_id
        return {
            "id": self.id,
            "session_id": f"{self.server_alias}/{self.id}",
            "numeric_session_id": self.id,
            "server": self.server_alias,
            "name": self.name,
            "alive": not self.is_dead and self.is_alive(),
            "dead": self.is_dead,
            "in_shell": self.in_shell,
            "active_run_id": active,
            "last_command": self.last_command
        }
