import os
import time
import threading
import base64
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, List
import paramiko
import codecs

from src.config import (
    CONNECT_TIMEOUT, KEEPALIVE_INTERVAL, BUFFER_SIZE, HEALTH_CHECK_INTERVAL,
    DEFAULT_WAIT_TIMEOUT, MAX_WAIT_TIMEOUT, DEFAULT_STARTUP_WAIT, MAX_STARTUP_WAIT,
    DEFAULT_HARD_TIMEOUT, MAX_HARD_TIMEOUT, MAX_BUFFER_CHARS, MAX_TOTAL_BUFFER_CHARS,
    DEFAULT_READ_MAX_LINES, DEFAULT_READ_MAX_CHARS, MAX_READ_MAX_LINES, MAX_READ_MAX_CHARS,
    DEFAULT_QUIET_COMPLETE_TIMEOUT, MAX_QUIET_COMPLETE_TIMEOUT, config, DEFAULT_PATH
)
from src.utils import (
    log_error, clamp_float, clamp_int, iso_now, json_line, safe_name,
    clean_output, find_prompt, has_prompt
)

_buffer_checker = None
_total_buffer_getter = None

def set_buffer_limit_checkers(checker_func, getter_func):
    global _buffer_checker, _total_buffer_getter
    _buffer_checker = checker_func
    _total_buffer_getter = getter_func


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
    # Generic fallback
    return f"SSH connect failed to {host}:{port}: {msg}"

@dataclass
class RunState:
    run_id: int
    session_id: int
    command: str
    mode: str
    started_at: float
    wait_timeout: float
    startup_wait: float
    hard_timeout: float
    max_buffer_chars: int
    run_log_path: str

    lock: threading.Lock = field(default_factory=threading.Lock)
    done_event: threading.Event = field(default_factory=threading.Event)
    status: str = "running"
    finish_reason: str = ""
    finished_at: Optional[float] = None
    error: str = ""
    output_buffer: str = ""
    buffer_base_offset: int = 0
    shared_cursor: int = 0
    total_received_chars: int = 0
    last_data_at: float = field(default_factory=time.time)
    prompt_detected: bool = False
    interrupt_sent: bool = False
    recv_paused: bool = False
    pause_reason: str = ""
    completion_method: str = ""
    stdin_writes: int = 0
    last_stdin_at: Optional[float] = None
    quiet_event: threading.Event = field(default_factory=threading.Event)
    prompt_line: str = ""

    def append_output(self, chunk: str) -> None:
        if not chunk:
            return
        # Log all output events immediately to prevent internal tool timeouts
        # if the buffer is being filled very fast
        with self.lock:
            self.output_buffer += chunk
            self.total_received_chars += len(chunk)
            self.last_data_at = time.time()

            overflow = len(self.output_buffer) - self.max_buffer_chars
            if overflow > 0:
                self.output_buffer = self.output_buffer[overflow:]
                self.buffer_base_offset += overflow
                if self.shared_cursor < self.buffer_base_offset:
                    self.shared_cursor = self.buffer_base_offset

    def mark_done(
        self,
        status: str,
        reason: str = "",
        error: str = "",
        completion_method: str = "",
    ) -> None:
        with self.lock:
            if self.done_event.is_set():
                return
            self.status = status
            self.finish_reason = reason
            self.error = error
            self.completion_method = completion_method
            self.finished_at = time.time()
            self.done_event.set()

    def set_recv_paused(self, paused: bool, reason: str = "") -> None:
        with self.lock:
            self.recv_paused = paused
            self.pause_reason = reason if paused else ""

    def register_stdin(self) -> None:
        with self.lock:
            self.stdin_writes += 1
            self.last_stdin_at = time.time()

    def read_slice(
        self,
        offset: Optional[int],
        max_lines: int,
        max_chars: int,
    ) -> Dict[str, Any]:
        with self.lock:
            use_shared_cursor = offset is None
            if offset is None:
                offset = self.shared_cursor

            dropped_data = False
            if offset < self.buffer_base_offset:
                offset = self.buffer_base_offset
                dropped_data = True

            relative = max(0, offset - self.buffer_base_offset)
            data = self.output_buffer[relative:]

            limited = False
            if len(data) > max_chars:
                data = data[:max_chars]
                limited = True

            if max_lines > 0:
                lines = data.splitlines(keepends=True)
                if len(lines) > max_lines:
                    data = "".join(lines[:max_lines])
                    limited = True

            next_offset = offset + len(data)
            if use_shared_cursor:
                self.shared_cursor = next_offset

            return {
                "offset_start": offset,
                "next_offset": next_offset,
                "base_offset": self.buffer_base_offset,
                "output": clean_output(data),
                "limited": limited,
                "dropped_data": dropped_data,
                "status": self.status,
                "still_running": not self.done_event.is_set(),
                "output_complete": self.done_event.is_set(),
                "finish_reason": self.finish_reason,
                "error": self.error,
                "total_received_chars": self.total_received_chars,
                "recv_paused": self.recv_paused,
                "pause_reason": self.pause_reason,
                "completion_method": self.completion_method,
            }

@dataclass
class PipelineState:
    pipeline_id: int
    session_id: int
    command: str
    mode: str
    started_at: float
    wait_timeout: float
    startup_wait: float
    hard_timeout: float
    local_stdout_path: str
    local_stdin_path: str
    include_stderr: bool
    append_stdout: bool
    max_buffer_chars: int
    run_log_path: str

    lock: threading.Lock = field(default_factory=threading.Lock)
    done_event: threading.Event = field(default_factory=threading.Event)
    status: str = "running"
    finish_reason: str = ""
    error: str = ""
    finished_at: Optional[float] = None
    exit_status: Optional[int] = None
    completion_method: str = ""
    recv_paused: bool = False
    pause_reason: str = ""

    bytes_written: int = 0
    bytes_sent: int = 0
    last_data_at: float = field(default_factory=time.time)

    preview_buffer: str = ""
    preview_base_offset: int = 0
    shared_preview_cursor: int = 0
    
    decoder: Any = field(default_factory=lambda: codecs.getincrementaldecoder("utf-8")(errors="replace"))

    def append_remote_bytes(self, chunk: bytes) -> None:
        if not chunk:
            return
        preview = self.decoder.decode(chunk)
        with self.lock:
            self.bytes_written += len(chunk)
            self.last_data_at = time.time()
            self.preview_buffer += preview

            overflow = len(self.preview_buffer) - self.max_buffer_chars
            if overflow > 0:
                self.preview_buffer = self.preview_buffer[overflow:]
                self.preview_base_offset += overflow
                if self.shared_preview_cursor < self.preview_base_offset:
                    self.shared_preview_cursor = self.preview_base_offset

    def add_sent_bytes(self, sent_len: int) -> None:
        if sent_len <= 0:
            return
        with self.lock:
            self.bytes_sent += sent_len
            self.last_data_at = time.time()

    def mark_done(
        self,
        status: str,
        reason: str = "",
        error: str = "",
        exit_status: Optional[int] = None,
        completion_method: str = "",
    ) -> None:
        with self.lock:
            if self.done_event.is_set():
                return
            self.status = status
            self.finish_reason = reason
            self.error = error
            self.exit_status = exit_status
            self.completion_method = completion_method
            self.finished_at = time.time()
            self.done_event.set()

    def set_recv_paused(self, paused: bool, reason: str = "") -> None:
        with self.lock:
            self.recv_paused = paused
            self.pause_reason = reason if paused else ""

    def read_preview(self, offset: Optional[int], max_chars: int) -> Dict[str, Any]:
        with self.lock:
            use_shared_cursor = offset is None
            if offset is None:
                offset = self.shared_preview_cursor

            dropped_data = False
            if offset < self.preview_base_offset:
                offset = self.preview_base_offset
                dropped_data = True

            relative = max(0, offset - self.preview_base_offset)
            preview = self.preview_buffer[relative:]
            limited = False
            if len(preview) > max_chars:
                preview = preview[:max_chars]
                limited = True

            next_offset = offset + len(preview)
            if use_shared_cursor:
                self.shared_preview_cursor = next_offset

            return {
                "preview": clean_output(preview, remove_echo=False),
                "offset_start": offset,
                "next_offset": next_offset,
                "base_offset": self.preview_base_offset,
                "limited": limited,
                "dropped_data": dropped_data,
                "status": self.status,
                "still_running": not self.done_event.is_set(),
                "output_complete": self.done_event.is_set(),
                "finish_reason": self.finish_reason,
                "error": self.error,
                "exit_status": self.exit_status,
                "bytes_written": self.bytes_written,
                "bytes_sent": self.bytes_sent,
                "completion_method": self.completion_method,
                "recv_paused": self.recv_paused,
                "pause_reason": self.pause_reason,
            }

class SSHSession:
    def __init__(self, session_id: int, name: str, cache_dirs: Dict[str, str], project_tag: str):
        self.id = session_id
        self.name = name
        self.cache_dirs = cache_dirs
        self.project_tag = project_tag

        self.client: Optional[paramiko.SSHClient] = None
        self.channel: Optional[paramiko.Channel] = None

        self.created_at = datetime.now()
        self.is_dead = False
        self.death_reason = ""
        self.death_time: Optional[datetime] = None
        self.in_shell = False

        self.last_command = ""
        self.last_command_time: Optional[datetime] = None

        self.active_run_id: Optional[int] = None
        self.last_run_id: Optional[int] = None
        self.run_counter = 1
        self.runs: Dict[int, RunState] = {}
        self.reader_threads: Dict[int, threading.Thread] = {}

        self.active_pipeline_id: Optional[int] = None
        self.last_pipeline_id: Optional[int] = None
        self.pipeline_counter = 1
        self.pipelines: Dict[int, PipelineState] = {}
        self.pipeline_threads: Dict[int, threading.Thread] = {}

        self.lock = threading.Lock()

        self.session_log_path = self._build_session_log_path()
        json_line(
            self.session_log_path,
            {
                "ts": iso_now(),
                "dir": "SYS",
                "event": "session_created",
                "session_id": self.id,
                "name": self.name,
            },
        )

    def _build_session_log_path(self) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.project_tag}__s{self.id}__{safe_name(self.name)}__{stamp}.log"
        return os.path.join(self.cache_dirs["sessions_dir"], filename)

    def _build_run_log_path(self, run_id: int) -> str:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.project_tag}__s{self.id}__r{run_id}__{stamp}.log"
        return os.path.join(self.cache_dirs["runs_dir"], filename)

    def _log_session(self, direction: str, payload: Dict[str, Any]) -> None:
        data = {"ts": iso_now(), "dir": direction, "session_id": self.id}
        data.update(payload)
        json_line(self.session_log_path, data)

    def _log_run(self, run: Any, direction: str, payload: Dict[str, Any]) -> None:
        run_id = getattr(run, "run_id", None)
        pipeline_id = getattr(run, "pipeline_id", None)
        data = {"ts": iso_now(), "dir": direction, "session_id": self.id}
        if run_id is not None:
            data["run_id"] = run_id
        if pipeline_id is not None:
            data["pipeline_id"] = pipeline_id
        data.update(payload)
        json_line(run.run_log_path, data)

    def connect(self) -> bool:
        try:
            self.close()
            self.client = paramiko.SSHClient()
            
            if config.SSH_VERIFY_HOST_KEY:
                self.client.load_system_host_keys()
            else:
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": config.SSH_HOST,
                "port": config.SSH_PORT,
                "username": config.SSH_USER,
                "timeout": CONNECT_TIMEOUT,
                "banner_timeout": 15,
                "auth_timeout": 20,
                "allow_agent": True,
                "look_for_keys": True,
            }
            if config.SSH_PASSWORD:
                connect_kwargs["password"] = config.SSH_PASSWORD
            if config.SSH_KEY_PATH:
                connect_kwargs["key_filename"] = config.SSH_KEY_PATH
                if config.SSH_KEY_PASSPHRASE:
                    connect_kwargs["passphrase"] = config.SSH_KEY_PASSPHRASE

            self.client.connect(**connect_kwargs)

            transport = self.client.get_transport()
            if transport:
                transport.set_keepalive(KEEPALIVE_INTERVAL)

            # invoke_shell has no built-in timeout — run in thread to avoid infinite hang
            channel_holder = [None]
            exc_holder = [None]
            def _open_shell():
                try:
                    channel_holder[0] = self.client.invoke_shell(width=220, height=50)
                except Exception as e:
                    exc_holder[0] = e
            sh_thread = threading.Thread(target=_open_shell, daemon=True)
            sh_thread.start()
            sh_thread.join(timeout=15)
            if sh_thread.is_alive():
                raise TimeoutError("invoke_shell timed out after 15s")
            if exc_holder[0]:
                raise exc_holder[0]
            self.channel = channel_holder[0]

            self.channel.settimeout(1.0)
            time.sleep(0.4)

            if self.channel.recv_ready():
                self.channel.recv(65535)

            self._setup_environment()
            self._log_session("SYS", {"event": "connected", "host": config.SSH_HOST, "port": config.SSH_PORT})
            return True
        except Exception as exc:
            reason = _describe_connect_error(exc, config.SSH_HOST, config.SSH_PORT)
            self._mark_dead(reason)
            self._log_session("SYS", {"event": "connect_failed", "error": reason})
            return False

    def _setup_environment(self) -> None:
        try:
            if not self.channel:
                return
            path = config.EXTRA_PATH if config.EXTRA_PATH else DEFAULT_PATH
            self.channel.send(f"export PATH={path}:$PATH 2>/dev/null\n")
            time.sleep(0.2)
            while self.channel.recv_ready():
                self.channel.recv(BUFFER_SIZE)
        except Exception as exc:
            self._log_session("SYS", {"event": "env_setup_warning", "error": str(exc)})

    def _mark_dead(self, reason: str) -> None:
        if self.is_dead:
            return
        self.is_dead = True
        self.death_reason = reason
        self.death_time = datetime.now()
        self._log_session("SYS", {"event": "session_dead", "reason": reason})

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
        if self.is_dead:
            return False
        if not self.client:
            self._mark_dead("no client")
            return False
        try:
            transport = self.client.get_transport()
            if not transport or not transport.is_active():
                self._mark_dead("transport disconnected")
                return False

            if not self.channel or self.channel.closed:
                if self.active_run_id is not None:
                    self._mark_dead("channel closed during active run")
                    return False
                self.channel = self.client.invoke_shell()
                self.channel.settimeout(1.0)
                self.in_shell = False
                time.sleep(0.2)
                if self.channel.recv_ready():
                    self.channel.recv(65535)
                self._setup_environment()
            return True
        except Exception as exc:
            self._mark_dead(f"health check failed: {exc}")
            return False

    def ensure_alive(self) -> Optional[str]:
        if self.is_dead:
            return f"Session {self.id} is DEAD: {self.death_reason}. Close it with session_close."
        if not self.check_health():
            return f"Session {self.id} is DEAD: {self.death_reason}. Close it with session_close."
        return None

    def _enter_shell(self) -> bool:
        if self.in_shell:
            return True
        if not self.channel:
            return False

        try:
            while self.channel.recv_ready():
                self.channel.recv(BUFFER_SIZE)

            for cmd in ["sh", "system", "shell"]:
                self.channel.send(f"{cmd}\n")
                time.sleep(0.3)
                output = ""
                start = time.time()
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                while time.time() - start < 2.0:
                    if self.channel.recv_ready():
                        chunk_bytes = self.channel.recv(BUFFER_SIZE)
                        chunk = decoder.decode(chunk_bytes)
                        output += chunk
                        if "BusyBox" in output or re.search(r"[#$]\s*$", output.rstrip()):
                            self.in_shell = True
                            path = config.EXTRA_PATH if config.EXTRA_PATH else DEFAULT_PATH
                            self.channel.send(f"export PATH={path}:$PATH 2>/dev/null\n")
                            time.sleep(0.2)
                            while self.channel.recv_ready():
                                self.channel.recv(BUFFER_SIZE)
                            self._log_session("SYS", {"event": "enter_shell_ok", "method": cmd})
                            return True
                    time.sleep(0.05)
            
            self.channel.send("exec sh\n")
            time.sleep(0.5)
            output = ""
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            if self.channel.recv_ready():
                output = decoder.decode(self.channel.recv(BUFFER_SIZE))
            if "BusyBox" in output or re.search(r"[#$]\s*$", output.rstrip()):
                self.in_shell = True
                self._log_session("SYS", {"event": "enter_shell_ok", "method": "exec sh"})
                return True

            self._log_session("SYS", {"event": "enter_shell_failed", "output_tail": output[-200:]})
            return False
        except Exception as exc:
            self._log_session("SYS", {"event": "enter_shell_error", "error": str(exc)})
            return False

    def _send_ctrl_c_raw(self) -> None:
        if self.channel and not self.channel.closed:
            self.channel.send("\x03")

    def _start_reader_thread(self, run: RunState):
        thread = threading.Thread(target=self._reader_loop, args=(run,), daemon=True)
        self.reader_threads[run.run_id] = thread
        thread.start()

    def _exit_shell(self) -> bool:
        if not self.in_shell:
            return True
        if not self.channel:
            return False
        try:
            while self.channel.recv_ready():
                self.channel.recv(BUFFER_SIZE)
            
            for _ in range(3):
                self.channel.send("exit\n")
                time.sleep(0.3)
                output = ""
                start = time.time()
                decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                while time.time() - start < 2.0:
                    if self.channel.recv_ready():
                        chunk = decoder.decode(self.channel.recv(BUFFER_SIZE))
                        output += chunk
                        if re.search(r"(\(.*\))?>\s*$", output.rstrip()) or re.search(r"^[>#]\s*$", output.strip()):
                            self.in_shell = False
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

                if hard_deadline is not None and time.time() >= hard_deadline:
                    run.interrupt_sent = True
                    self._send_ctrl_c_raw()
                    run.mark_done("hard_timeout", reason="hard timeout reached", completion_method="hard_timeout")
                    break

                if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                    run.set_recv_paused(True, "memory_limit")
                    time.sleep(0.1)
                    continue
                else:
                    if run.recv_paused:
                        run.set_recv_paused(False)

                if self.channel and self.channel.recv_ready():
                    chunk_bytes = self.channel.recv(BUFFER_SIZE)
                    chunk = decoder.decode(chunk_bytes)
                    run.append_output(chunk)
                    self._log_run(run, "OUT", {"chunk": chunk})

                    if "More" in chunk:
                        tail = run.output_buffer[-500:]
                        if re.search(r"--\s*More\s*--", tail) or re.search(r"More\.\.\.", tail):
                            self.channel.send(" ") 
                            self._log_run(run, "SYS", {"event": "pagination_detected_sending_space"})

                    prompt = find_prompt(run.output_buffer)
                    if prompt:
                        run.prompt_detected = True
                        run.prompt_line = prompt
                        completion_method = "interrupted" if run.interrupt_sent else "prompt_detected"
                        run.mark_done("completed", reason=f"prompt detected: {prompt}", completion_method=completion_method)
                        break
                else:
                    if run.mode == "sync":
                        hint = getattr(run, "completion_hint", "either")
                        quiet_timeout = getattr(run, "quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)
                        stdin_recent = False
                        if run.last_stdin_at is not None:
                            stdin_recent = (time.time() - run.last_stdin_at) < quiet_timeout
                        
                        if hint in {"quiet", "either"} and run.total_received_chars > 0 and not stdin_recent:
                            if (time.time() - run.last_data_at) >= quiet_timeout:
                                if not run.quiet_event.is_set():
                                    run.quiet_event.set()
                    time.sleep(0.05)
        except Exception as exc:
            run.mark_done("failed", reason="reader exception", error=str(exc), completion_method="failed")
        finally:
            with self.lock:
                if self.active_run_id == run.run_id:
                    self.active_run_id = None
                self.last_run_id = run.run_id

    def _cleanup_old_runs(self) -> None:
        with self.lock:
            # Cleanup runs
            run_ids = sorted(self.runs.keys())
            if len(run_ids) > 10:
                for rid in run_ids[:-10]:
                    r = self.runs[rid]
                    if rid != self.active_run_id and r.done_event.is_set():
                        # To free up memory completely
                        with r.lock:
                            r.output_buffer = ""
                        del self.runs[rid]
                        self.reader_threads.pop(rid, None)
            
            # Cleanup pipelines
            pipe_ids = sorted(self.pipelines.keys())
            if len(pipe_ids) > 10:
                for pid in pipe_ids[:-10]:
                    p = self.pipelines[pid]
                    if pid != self.active_pipeline_id and p.done_event.is_set():
                        with p.lock:
                            p.preview_buffer = ""
                        del self.pipelines[pid]
                        self.pipeline_threads.pop(pid, None)

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
    ) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error:
            return {"success": False, "error": error, "session_id": self.id}

        mode = (mode or "sync").lower().strip()
        wait_timeout = clamp_float(wait_timeout, DEFAULT_WAIT_TIMEOUT, 0.1, MAX_WAIT_TIMEOUT)
        startup_wait = clamp_float(startup_wait, DEFAULT_STARTUP_WAIT, 0.1, MAX_STARTUP_WAIT)
        hard_timeout = clamp_float(hard_timeout, DEFAULT_HARD_TIMEOUT, 0.0, MAX_HARD_TIMEOUT)
        quiet_complete_timeout = clamp_float(quiet_complete_timeout, DEFAULT_QUIET_COMPLETE_TIMEOUT, 0.1, MAX_QUIET_COMPLETE_TIMEOUT)

        busy = self.busy_info()
        if busy.get("busy"):
            return {"success": False, "error": f"Session {self.id} is busy", "session_id": self.id}

        if shell and not self.in_shell:
            if not self._enter_shell():
                return {"success": False, "error": "Failed to enter system shell", "session_id": self.id}
        elif not shell and self.in_shell:
            if not self._exit_shell():
                return {"success": False, "error": "Failed to exit system shell", "session_id": self.id}

        if self.channel:
            old_t = self.channel.gettimeout()
            self.channel.settimeout(0.1)
            try:
                while self.channel.recv_ready():
                    self.channel.recv(BUFFER_SIZE)
            except: pass
            self.channel.settimeout(old_t)

        run_id = self.run_counter
        self.run_counter += 1
        self._cleanup_old_runs()
        run = RunState(
            run_id=run_id, session_id=self.id, command=command, mode=mode,
            started_at=time.time(), wait_timeout=wait_timeout, startup_wait=startup_wait,
            hard_timeout=hard_timeout, max_buffer_chars=MAX_BUFFER_CHARS,
            run_log_path=self._build_run_log_path(run_id)
        )
        run.completion_hint = completion_hint
        run.quiet_complete_timeout = quiet_complete_timeout

        with self.lock:
            self.runs[run_id] = run
            self.active_run_id = run_id
            self.last_run_id = run_id

        self.last_command = command
        self.last_command_time = datetime.now()

        try:
            if not self.channel: return {"success": False, "error": "No channel", "session_id": self.id}
            self.channel.send(command + "\n")
        except Exception as exc:
            run.mark_done("failed", error=str(exc))
            return {"success": False, "error": str(exc), "session_id": self.id}

        self._start_reader_thread(run)

        if mode == "sync":
            start_wait = time.time()
            completed_within_wait = False
            while time.time() - start_wait < wait_timeout:
                if run.done_event.wait(0.1):
                    completed_within_wait = True
                    break
                if run.quiet_event.is_set():
                    break
            
            if not completed_within_wait and not run.quiet_event.is_set():
                pass # Just return what we have, reader continues in background
        else:
            run.done_event.wait(startup_wait)

        snapshot_max = max_chars if max_chars is not None else MAX_READ_MAX_CHARS
        snapshot = run.read_slice(offset=run.buffer_base_offset, max_lines=MAX_READ_MAX_LINES, max_chars=snapshot_max)

        status = run.status
        if run.done_event.is_set():
            if run.completion_method in {"prompt_detected", "interrupted"}: status = "completed"
            elif run.completion_method == "hard_timeout": status = "failed"
        elif run.quiet_event.is_set(): status = "stalled"
        else: status = "running"

        return {
            "success": True, "session_id": self.id, "run_id": run_id, "status": status,
            "output": snapshot["output"], "next_offset": snapshot["next_offset"]
        }

    def read_run(self, run_id: Optional[int], offset: Optional[int], max_lines: int, max_chars: int) -> Dict[str, Any]:
        max_lines = clamp_int(max_lines, DEFAULT_READ_MAX_LINES, 1, MAX_READ_MAX_LINES)
        max_chars = clamp_int(max_chars, DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)
        selected = None
        with self.lock:
            if run_id is not None: selected = self.runs.get(run_id)
            elif self.active_run_id is not None: selected = self.runs.get(self.active_run_id)
            elif self.last_run_id is not None: selected = self.runs.get(self.last_run_id)
        if not selected: return {"success": False, "error": "No run found", "session_id": self.id}
        snapshot = selected.read_slice(offset=offset, max_lines=max_lines, max_chars=max_chars)
        status = selected.status
        if selected.done_event.is_set():
            if selected.completion_method in {"prompt_detected", "interrupted"}: status = "completed"
        elif selected.quiet_event.is_set(): status = "stalled"
        return {
            "success": True, "session_id": self.id, "run_id": selected.run_id, "status": status,
            "output": snapshot["output"], "next_offset": snapshot["next_offset"]
        }

    def busy_info(self) -> Dict[str, Any]:
        with self.lock:
            if self.active_run_id is not None:
                r = self.runs.get(self.active_run_id)
                if r and not r.done_event.is_set(): return {"busy": True, "type": "run", "id": r.run_id}
            if self.active_pipeline_id is not None:
                p = self.pipelines.get(self.active_pipeline_id)
                if p and not p.done_event.is_set(): return {"busy": True, "type": "pipeline", "id": p.pipeline_id}
        return {"busy": False}

    def is_busy(self) -> bool: return bool(self.busy_info().get("busy"))

    def _start_pipeline_thread(self, pipeline: PipelineState) -> None:
        thread = threading.Thread(target=self._pipeline_worker, args=(pipeline,), daemon=True)
        self.pipeline_threads[pipeline.pipeline_id] = thread
        thread.start()

    def _pipeline_worker(self, pipeline: PipelineState) -> None:
        stdin_stream = stdout_stream = stderr_stream = input_file = output_file = channel = None
        hard_deadline = (pipeline.started_at + pipeline.hard_timeout) if pipeline.hard_timeout > 0 else None
        try:
            if not self.client: return
            stdin_stream, stdout_stream, stderr_stream = self.client.exec_command(pipeline.command, get_pty=False)
            channel = stdout_stream.channel
            if pipeline.local_stdin_path: input_file = open(pipeline.local_stdin_path, "rb")
            if pipeline.local_stdout_path: output_file = open(pipeline.local_stdout_path, "ab" if pipeline.append_stdout else "wb")
            input_done = input_file is None
            while not pipeline.done_event.is_set():
                if self.is_dead:
                    pipeline.mark_done("dead", reason=self.death_reason, error=self.death_reason, completion_method="dead")
                    break
                if hard_deadline and time.time() >= hard_deadline:
                    try: channel.close()
                    except: pass
                    pipeline.mark_done("hard_timeout", reason="hard timeout reached", completion_method="hard_timeout")
                    break
                has_prog = False
                if not input_done and channel and channel.send_ready():
                    chunk = input_file.read(BUFFER_SIZE)
                    if chunk:
                        sent = channel.send(chunk)
                        if sent > 0:
                            if sent < len(chunk): input_file.seek(input_file.tell() - (len(chunk) - sent))
                            pipeline.add_sent_bytes(sent)
                            has_prog = True
                    else:
                        try: channel.shutdown_write()
                        except: pass
                        input_done = True
                        has_prog = True
                if channel and channel.recv_ready():
                    if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                        pipeline.set_recv_paused(True, "memory_limit")
                        time.sleep(0.1)
                    else:
                        if pipeline.recv_paused: pipeline.set_recv_paused(False)
                        data = channel.recv(BUFFER_SIZE)
                        if data:
                            if output_file: output_file.write(data)
                            pipeline.append_remote_bytes(data)
                            has_prog = True
                if pipeline.include_stderr and channel and channel.recv_stderr_ready():
                    err_data = channel.recv_stderr(BUFFER_SIZE)
                    if err_data:
                        if output_file: output_file.write(err_data)
                        pipeline.append_remote_bytes(err_data)
                        has_prog = True
                if channel and channel.exit_status_ready() and input_done and not channel.recv_ready():
                    exit_code = channel.recv_exit_status()
                    pipeline.mark_done("completed" if exit_code == 0 else "completed_nonzero", exit_status=exit_code, completion_method="exit_status")
                    break
                if not has_prog: time.sleep(0.02)
        except Exception as exc:
            pipeline.mark_done("failed", error=str(exc), completion_method="failed")
        finally:
            for f in [output_file, input_file, stdin_stream, stdout_stream, stderr_stream]:
                try: 
                    if f: f.close()
                except: pass
            with self.lock:
                if self.active_pipeline_id == pipeline.pipeline_id: self.active_pipeline_id = None
                self.last_pipeline_id = pipeline.pipeline_id

    def run_pipeline(self, command: str, mode: str, wait_timeout: float, startup_wait: float, hard_timeout: float, local_stdout_path: str, local_stdin_path: str, include_stderr: bool, append_stdout: bool) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error: return {"success": False, "error": error, "session_id": self.id}
        if self.is_busy(): return {"success": False, "error": f"Session {self.id} is busy", "session_id": self.id}
        if not self.in_shell:
            if not self._enter_shell(): return {"success": False, "error": "Failed to enter shell", "session_id": self.id}
        pipeline_id = self.pipeline_counter
        self.pipeline_counter += 1
        self._cleanup_old_runs()
        p = PipelineState(
            pipeline_id=pipeline_id, session_id=self.id, command=command, mode=mode, started_at=time.time(),
            wait_timeout=wait_timeout, startup_wait=startup_wait, hard_timeout=hard_timeout,
            local_stdout_path=local_stdout_path, local_stdin_path=local_stdin_path,
            include_stderr=include_stderr, append_stdout=append_stdout, max_buffer_chars=MAX_BUFFER_CHARS,
            run_log_path=self._build_run_log_path(pipeline_id)
        )
        with self.lock:
            self.pipelines[pipeline_id] = p
            self.active_pipeline_id = pipeline_id
            self.last_pipeline_id = pipeline_id
        self._start_pipeline_thread(p)
        wait_for = wait_timeout if mode == "sync" else startup_wait
        p.done_event.wait(wait_for)
        snapshot = p.read_preview(offset=p.preview_base_offset, max_chars=MAX_READ_MAX_CHARS)
        return {
            "success": True, "session_id": self.id, "pipeline_id": pipeline_id, "status": p.status,
            "preview": snapshot["preview"], "next_offset": snapshot["next_offset"]
        }

    def pipeline_status(self, pipeline_id: Optional[int], offset: Optional[int], max_chars: int) -> Dict[str, Any]:
        max_chars = clamp_int(max_chars, DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)
        selected = None
        with self.lock:
            if pipeline_id is not None: selected = self.pipelines.get(pipeline_id)
            elif self.active_pipeline_id is not None: selected = self.pipelines.get(self.active_pipeline_id)
            elif self.last_pipeline_id is not None: selected = self.pipelines.get(self.last_pipeline_id)
        if not selected: return {"success": False, "error": "No pipeline found", "session_id": self.id}
        snapshot = selected.read_preview(offset=offset, max_chars=max_chars)
        return {
            "success": True, "session_id": self.id, "pipeline_id": selected.pipeline_id, "status": selected.status,
            "preview": snapshot["preview"], "next_offset": snapshot["next_offset"]
        }

    def send_signal(self, action: str, text: str = "", press_enter: bool = True) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error: return {"success": False, "error": error, "session_id": self.id}
        if action == "ctrl_c":
            self._send_ctrl_c_raw()
            with self.lock:
                r = self.runs.get(self.active_run_id) if self.active_run_id else None
                if r: r.interrupt_sent = True
            return {"success": True, "session_id": self.id, "message": "Ctrl+C sent"}
        data = text + ("\n" if press_enter else "")
        if not self.channel: return {"success": False, "error": "No channel", "session_id": self.id}
        self.channel.send(data)
        with self.lock:
            r = self.runs.get(self.active_run_id) if self.active_run_id else None
            if r and not r.done_event.is_set(): r.register_stdin()
        return {"success": True, "session_id": self.id, "message": "stdin sent"}

    def open_sftp(self) -> Optional[paramiko.SFTPClient]:
        if not self.client or self.ensure_alive(): return None
        try: return self.client.open_sftp()
        except: return None

    def close(self) -> None:
        try: 
            if self.channel: self.channel.close()
        except: pass
        self.channel = None
        try: 
            if self.client: self.client.close()
        except: pass
        self.client = None

    def info(self) -> Dict[str, Any]:
        with self.lock:
            active = self.active_run_id
            active_p = self.active_pipeline_id
        return {
            "id": self.id, "name": self.name, "alive": not self.is_dead and self.is_alive(),
            "dead": self.is_dead, "in_shell": self.in_shell, "active_run_id": active,
            "active_pipeline_id": active_p, "last_command": self.last_command
        }

class SessionManager:
    def __init__(self, cache_dirs: Dict[str, str], project_tag: str):
        self.cache_dirs = cache_dirs
        self.project_tag = project_tag
        self.sessions: Dict[int, SSHSession] = {}
        self.current_session_id: Optional[int] = None
        self.next_session_id = 1
        self.lock = threading.Lock()
        self.last_tool_result_by_session: Dict[int, Dict[str, Any]] = {}
        self.last_tool_result_global: Optional[Dict[str, Any]] = None
        self.health_thread_stop = False
        self.health_thread = threading.Thread(target=self._health_loop, daemon=True)
        self.health_thread.start()

    def record_tool_result(self, tool_name: str, args: Dict[str, Any], result: Dict[str, Any]) -> None:
        snapshot = {"timestamp": iso_now(), "tool": tool_name, "args": dict(args), "result": dict(result)}
        session_id = result.get("session_id")
        if session_id is None:
            try: session_id = int(args.get("session_id"))
            except: pass
        with self.lock:
            self.last_tool_result_global = snapshot
            if session_id is not None: self.last_tool_result_by_session[session_id] = snapshot

    def get_last_tool_result(self, session_id: Optional[int]) -> Dict[str, Any]:
        with self.lock:
            sid = session_id if session_id is not None else self.current_session_id
            if sid in self.last_tool_result_by_session: return {"success": True, **self.last_tool_result_by_session[sid]}
            if self.last_tool_result_global: return {"success": True, **self.last_tool_result_global}
            return {"success": False, "error": "No recorded result"}

    def _health_loop(self) -> None:
        while not self.health_thread_stop:
            time.sleep(HEALTH_CHECK_INTERVAL)
            try:
                with self.lock: sessions = list(self.sessions.values())
                for s in sessions:
                    if not s.is_dead: s.check_health()
            except: pass

    def ensure_session(self) -> Optional[SSHSession]:
        with self.lock:
            if self.current_session_id in self.sessions: return self.sessions[self.current_session_id]
        created = self.open_session(name="", make_current=True)
        if not created.get("success"): return None
        with self.lock: return self.sessions.get(created["session_id"])

    def open_session(self, name: str, make_current: bool) -> Dict[str, Any]:
        with self.lock:
            sid = self.next_session_id
            self.next_session_id += 1
        s = SSHSession(sid, name or "", self.cache_dirs, self.project_tag)
        if not s.connect():
            reason = s.death_reason or f"failed to connect session {sid}"
            return {"success": False, "error": reason}
        with self.lock:
            self.sessions[sid] = s
            if make_current or self.current_session_id is None: self.current_session_id = sid
        return {"success": True, "session_id": sid, "name": s.name}

    def close_session(self, session_id: int) -> Dict[str, Any]:
        with self.lock:
            s = self.sessions.pop(session_id, None)
            if not s: return {"success": False, "error": "not found"}
        s.close()
        with self.lock:
            if self.current_session_id == session_id:
                self.current_session_id = sorted(self.sessions.keys())[0] if self.sessions else None
        return {"success": True}

    def update_session(self, session_id: int, name: Optional[str], make_current: Optional[bool]) -> Dict[str, Any]:
        with self.lock:
            s = self.sessions.get(session_id)
            if not s: return {"success": False, "error": "not found"}
            if name: s.name = name
            if make_current: self.current_session_id = session_id
        return {"success": True, "session_id": session_id}

    def get_session(self, session_id: Optional[int]) -> Optional[SSHSession]:
        with self.lock: return self.sessions.get(session_id if session_id is not None else self.current_session_id)

    def set_current_session(self, session_id: int) -> None:
        with self.lock:
            if session_id in self.sessions: self.current_session_id = session_id

    def total_buffer_chars(self) -> int:
        total = 0
        with self.lock: sessions = list(self.sessions.values())
        for s in sessions:
            with s.lock:
                for r in s.runs.values():
                    with r.lock: total += len(r.output_buffer)
                for p in s.pipelines.values():
                    with p.lock: total += len(p.preview_buffer)
        return total

    def can_accept_more_buffer(self, incoming: int = 0) -> bool:
        return (self.total_buffer_chars() + incoming) <= MAX_TOTAL_BUFFER_CHARS

    def find_first_idle_alive_session(self) -> Optional[SSHSession]:
        with self.lock: sids = sorted(self.sessions.keys())
        for sid in sids:
            s = self.sessions[sid]
            if not s.is_dead and not s.ensure_alive() and not s.is_busy(): return s
        return None

    def list_sessions(self, include_name: bool = False, include_last_command: bool = False, include_active_ids: bool = False) -> Dict[str, Any]:
        with self.lock:
            rows = []
            for sid, s in self.sessions.items():
                if not s.is_dead: s.check_health()
                info = s.info()
                status = "broken" if (info["dead"] or not info["alive"]) else ("busy" if s.is_busy() else "idle")
                row = {"id": sid, "status": status, "is_current": sid == self.current_session_id}
                if include_name: row["name"] = info["name"]
                if include_last_command: row["last_command"] = info["last_command"]
                rows.append(row)
            rows.sort(key=lambda x: x["id"])
            return {"success": True, "sessions": rows, "current_session": self.current_session_id}

    def close_all(self) -> None:
        self.health_thread_stop = True
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for s in sessions: s.close()
