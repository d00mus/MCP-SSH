import os
import time
import threading
import base64
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional, List
import paramiko

from src.config import (
    CONNECT_TIMEOUT, KEEPALIVE_INTERVAL, BUFFER_SIZE, HEALTH_CHECK_INTERVAL,
    DEFAULT_WAIT_TIMEOUT, MAX_WAIT_TIMEOUT, DEFAULT_STARTUP_WAIT, MAX_STARTUP_WAIT,
    DEFAULT_HARD_TIMEOUT, MAX_HARD_TIMEOUT, MAX_BUFFER_CHARS, MAX_TOTAL_BUFFER_CHARS,
    DEFAULT_READ_MAX_LINES, DEFAULT_READ_MAX_CHARS, MAX_READ_MAX_LINES, MAX_READ_MAX_CHARS,
    DEFAULT_QUIET_COMPLETE_TIMEOUT, MAX_QUIET_COMPLETE_TIMEOUT, DEFAULT_PATH,
    SSH_HOST, SSH_USER, SSH_PASSWORD, SSH_PORT, EXTRA_PATH
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

    def append_remote_bytes(self, chunk: bytes) -> None:
        if not chunk:
            return
        preview = chunk.decode("utf-8", errors="replace")
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
        from src.config import (
            SSH_HOST, SSH_USER, SSH_PASSWORD, SSH_PORT,
            SSH_KEY_PATH, SSH_KEY_PASSPHRASE, SSH_VERIFY_HOST_KEY
        )
        try:
            self.close()
            self.client = paramiko.SSHClient()
            
            if SSH_VERIFY_HOST_KEY:
                self.client.load_system_host_keys()
                # If we want to strictly verify, we should probably set some policy
                # but paramiko defaults to RejectPolicy if no policy is set and host keys are loaded.
                # However, many users might not have the key in system_host_keys yet.
            else:
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs = {
                "hostname": SSH_HOST,
                "port": SSH_PORT,
                "username": SSH_USER,
                "timeout": CONNECT_TIMEOUT,
                "allow_agent": True,
                "look_for_keys": True,
            }
            if SSH_PASSWORD:
                connect_kwargs["password"] = SSH_PASSWORD
            if SSH_KEY_PATH:
                connect_kwargs["key_filename"] = SSH_KEY_PATH
                if SSH_KEY_PASSPHRASE:
                    connect_kwargs["passphrase"] = SSH_KEY_PASSPHRASE

            self.client.connect(**connect_kwargs)

            transport = self.client.get_transport()
            if transport:
                transport.set_keepalive(KEEPALIVE_INTERVAL)

            self.channel = self.client.invoke_shell()
            self.channel.settimeout(1.0)
            time.sleep(0.4)

            if self.channel.recv_ready():
                self.channel.recv(65535)

            self._setup_environment()
            self._log_session("SYS", {"event": "connected", "host": SSH_HOST, "port": SSH_PORT})
            return True
        except Exception as exc:
            self._mark_dead(f"connect failed: {exc}")
            self._log_session("SYS", {"event": "connect_failed", "error": str(exc)})
            return False

    def _setup_environment(self) -> None:
        from src.config import EXTRA_PATH, DEFAULT_PATH
        try:
            if not self.channel:
                return
            path = EXTRA_PATH if EXTRA_PATH else DEFAULT_PATH
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
        from src.config import EXTRA_PATH, DEFAULT_PATH
        if self.in_shell:
            return True
        if not self.channel:
            return False

        try:
            # Clear buffer
            while self.channel.recv_ready():
                self.channel.recv(BUFFER_SIZE)

            # Try common commands to enter shell
            for cmd in ["sh", "system", "shell"]:
                self.channel.send(f"{cmd}\n")
                time.sleep(0.3)
                output = ""
                start = time.time()
                while time.time() - start < 2.0:
                    if self.channel.recv_ready():
                        chunk = self.channel.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
                        output += chunk
                        if "BusyBox" in output or re.search(r"[#$]\s*$", output.rstrip()):
                            self.in_shell = True
                            path = EXTRA_PATH if EXTRA_PATH else DEFAULT_PATH
                            self.channel.send(f"export PATH={path}:$PATH 2>/dev/null\n")
                            time.sleep(0.2)
                            while self.channel.recv_ready():
                                self.channel.recv(BUFFER_SIZE)
                            self._log_session("SYS", {"event": "enter_shell_ok", "method": cmd})
                            return True
                    time.sleep(0.05)
            
            # Last resort: exec sh
            self.channel.send("exec sh\n")
            time.sleep(0.5)
            output = ""
            if self.channel.recv_ready():
                output = self.channel.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
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
            # Clear buffer
            while self.channel.recv_ready():
                self.channel.recv(BUFFER_SIZE)
            
            self.channel.send("exit\n")
            time.sleep(0.3)
            output = ""
            start = time.time()
            # Wait for native CLI prompt (usually ends with > or #)
            while time.time() - start < 2.0:
                if self.channel.recv_ready():
                    chunk = self.channel.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
                    output += chunk
                    # Simple heuristic for native CLI prompt
                    if re.search(r"[>#]\s*$", output.rstrip()):
                        self.in_shell = False
                        self._log_session("SYS", {"event": "exit_shell_ok"})
                        return True
                time.sleep(0.05)
            
            # If no prompt detected, assume we exited or just force it
            self.in_shell = False
            self._log_session("SYS", {"event": "exit_shell_timeout_assumed_ok"})
            return True
        except Exception as exc:
            self._log_session("SYS", {"event": "exit_shell_error", "error": str(exc)})
            self.in_shell = False # Reset anyway
            return False

    def _reader_loop(self, run: RunState) -> None:
        self._log_run(run, "SYS", {"event": "reader_started"})
        hard_deadline = (run.started_at + run.hard_timeout) if run.hard_timeout > 0 else None

        try:
            while not run.done_event.is_set():
                if self.is_dead:
                    run.mark_done("dead", reason=self.death_reason, error=self.death_reason, completion_method="dead")
                    break

                if hard_deadline is not None and time.time() >= hard_deadline:
                    run.interrupt_sent = True
                    self._send_ctrl_c_raw()
                    run.mark_done("hard_timeout", reason="hard timeout reached", completion_method="hard_timeout")
                    self._log_run(run, "SYS", {"event": "hard_timeout", "seconds": run.hard_timeout})
                    break

                if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                    run.set_recv_paused(True, "memory_limit")
                    if run.status == "running":
                        run.status = "recv_paused_by_memory_limit"
                    self._log_run(
                        run,
                        "SYS",
                        {
                            "event": "recv_paused",
                            "reason": "memory_limit",
                            "memory_total_chars": _total_buffer_getter() if _total_buffer_getter else 0,
                            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
                        },
                    )
                    time.sleep(0.1)
                    continue
                else:
                    if run.recv_paused:
                        run.set_recv_paused(False)
                        if run.status == "recv_paused_by_memory_limit":
                            run.status = "running"
                        self._log_run(run, "SYS", {"event": "recv_resumed"})

                if self.channel and self.channel.recv_ready():
                    chunk = self.channel.recv(BUFFER_SIZE).decode("utf-8", errors="replace")
                    run.append_output(chunk)
                    self._log_run(run, "OUT", {"chunk": chunk})

                    # Command completion in interactive shell is prompt appearance.
                    prompt = find_prompt(run.output_buffer)
                    if prompt:
                        run.prompt_detected = True
                        run.prompt_line = prompt
                        completion_method = "interrupted" if run.interrupt_sent else "prompt_detected"
                        reason = f"prompt detected: {prompt}"
                        run.mark_done("completed", reason=reason, completion_method=completion_method)
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
                                    self._log_run(run, "SYS", {"event": "quiet_point_reached", "timeout": quiet_timeout})
                    time.sleep(0.05)
        except Exception as exc:
            run.mark_done("failed", reason="reader exception", error=str(exc), completion_method="failed")
            self._log_run(run, "SYS", {"event": "reader_error", "error": str(exc)})
        finally:
            with self.lock:
                if self.active_run_id == run.run_id:
                    self.active_run_id = None
                self.last_run_id = run.run_id
            self._log_run(
                run,
                "SYS",
                {
                    "event": "reader_finished",
                    "status": run.status,
                    "reason": run.finish_reason,
                    "error": run.error,
                },
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
    ) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error:
            return {"success": False, "error": error, "session_id": self.id}

        mode = (mode or "sync").lower().strip()
        if mode not in {"sync", "async", "stream"}:
            return {"success": False, "error": "mode must be one of: sync, async, stream", "session_id": self.id}

        if not command or not command.strip():
            return {"success": False, "error": "command is required", "session_id": self.id}

        wait_timeout = clamp_float(wait_timeout, DEFAULT_WAIT_TIMEOUT, 0.1, MAX_WAIT_TIMEOUT)
        startup_wait = clamp_float(startup_wait, DEFAULT_STARTUP_WAIT, 0.1, MAX_STARTUP_WAIT)
        hard_timeout = clamp_float(hard_timeout, DEFAULT_HARD_TIMEOUT, 0.0, MAX_HARD_TIMEOUT)
        quiet_complete_timeout = clamp_float(
            quiet_complete_timeout,
            DEFAULT_QUIET_COMPLETE_TIMEOUT,
            0.1,
            MAX_QUIET_COMPLETE_TIMEOUT,
        )
        completion_hint = (completion_hint or "either").strip().lower()
        if completion_hint not in {"prompt", "quiet", "either"}:
            return {
                "success": False,
                "error": "completion_hint must be one of: prompt, quiet, either",
                "session_id": self.id,
            }

        busy = self.busy_info()
        if busy.get("busy"):
            if busy.get("type") == "run":
                return {
                    "success": False,
                    "error": (
                        f"Requested session {self.id} is busy "
                        f"(run id={busy.get('id')})."
                    ),
                    "session_id": self.id,
                    "busy_id": busy.get("id"),
                }
            return {
                "success": False,
                "error": (
                    f"Session {self.id} has active pipeline "
                    f"(pipeline_id={busy.get('id')})."
                ),
                "session_id": self.id,
                "pipeline_id": busy.get("id"),
            }

        if shell and not self.in_shell:
            if not self._enter_shell():
                return {
                    "success": False,
                    "error": "Failed to enter system shell. Try run(..., shell=true) again or reconnect session.",
                    "session_id": self.id,
                }
        elif not shell and self.in_shell:
            # shell=false requested, but we are in shell.
            # On some devices (like Keenetic), we must exit shell to use native CLI commands.
            if not self._exit_shell():
                return {
                    "success": False,
                    "error": "Failed to exit system shell back to native CLI. Try run(..., shell=false) again.",
                    "session_id": self.id,
                }

        # Flush pending channel data before new command.
        if self.channel:
            old_timeout = self.channel.gettimeout()
            self.channel.settimeout(0.1)
            try:
                while True:
                    if not self.channel.recv(BUFFER_SIZE):
                        break
            except Exception:
                pass
            self.channel.settimeout(old_timeout)

        run_id = self.run_counter
        self.run_counter += 1
        run = RunState(
            run_id=run_id,
            session_id=self.id,
            command=command,
            mode=mode,
            started_at=time.time(),
            wait_timeout=wait_timeout,
            startup_wait=startup_wait,
            hard_timeout=hard_timeout,
            max_buffer_chars=MAX_BUFFER_CHARS,
            run_log_path=self._build_run_log_path(run_id),
        )
        run.completion_method = ""
        run.completion_hint = completion_hint
        run.quiet_complete_timeout = quiet_complete_timeout

        with self.lock:
            self.runs[run_id] = run
            self.active_run_id = run_id
            self.last_run_id = run_id

        self.last_command = command
        self.last_command_time = datetime.now()
        self._log_session(
            "IN",
            {
                "event": "run_start",
                "run_id": run_id,
                "mode": mode,
                "shell": shell,
                "command": command,
                "wait_timeout": wait_timeout,
                "startup_wait": startup_wait,
                "hard_timeout": hard_timeout,
                "completion_hint": completion_hint,
                "quiet_complete_timeout": quiet_complete_timeout,
            },
        )
        self._log_run(
            run,
            "IN",
            {
                "event": "command_sent",
                "command": command,
                "mode": mode,
                "shell": shell,
            },
        )

        try:
            if not self.channel:
                return {"success": False, "error": "No active channel", "session_id": self.id}
            self.channel.send(command + "\n")
        except Exception as exc:
            run.mark_done("failed", reason="send failed", error=str(exc))
            with self.lock:
                if self.active_run_id == run_id:
                    self.active_run_id = None
            return {"success": False, "error": f"failed to send command: {exc}", "session_id": self.id}

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
        else:
            completed_within_wait = run.done_event.wait(startup_wait)

        snapshot_max_chars = max_chars if max_chars is not None else MAX_READ_MAX_CHARS
        snapshot = run.read_slice(offset=run.buffer_base_offset, max_lines=MAX_READ_MAX_LINES, max_chars=snapshot_max_chars)

        timed_out = (mode == "sync") and (not completed_within_wait) and (not run.quiet_event.is_set())
        output_complete = run.done_event.is_set()
        still_running = not run.done_event.is_set()

        completion_status = "unknown"
        if run.done_event.is_set():
            if run.completion_method in {"prompt_detected", "interrupted"}:
                status = "completed"
            elif run.completion_method == "hard_timeout":
                status = "failed"
                run.error = "hard timeout reached"
            elif run.completion_method == "dead":
                status = "dead"
            else:
                status = run.status
        else:
            if run.quiet_event.is_set():
                status = "stalled"
            else:
                status = "running"

        return {
            "success": True,
            "session_id": self.id,
            "session_name": self.name,
            "run_id": run_id,
            "status": status,
            "error": run.error if status == "failed" else "",
            "output": snapshot["output"],
            "next_offset": snapshot["next_offset"],
            "message": (
                f"Command is {status}."
            ),
            # Keep these for last_command_details
            "mode": mode,
            "timed_out": timed_out,
            "still_running": not run.done_event.is_set(),
            "quiet_point": run.quiet_event.is_set(),
            "finish_reason": run.finish_reason,
            "completion_method": run.completion_method,
            "wait_timeout": wait_timeout,
            "startup_wait": startup_wait,
            "hard_timeout": hard_timeout,
            "completion_hint": completion_hint,
            "quiet_complete_timeout": quiet_complete_timeout,
            "offset_start": snapshot["offset_start"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": _total_buffer_getter() if _total_buffer_getter else 0,
        }

    def read_run(
        self,
        run_id: Optional[int],
        offset: Optional[int],
        max_lines: int,
        max_chars: int,
    ) -> Dict[str, Any]:
        max_lines = clamp_int(max_lines, DEFAULT_READ_MAX_LINES, 1, MAX_READ_MAX_LINES)
        max_chars = clamp_int(max_chars, DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)

        selected: Optional[RunState] = None
        with self.lock:
            if run_id is not None:
                selected = self.runs.get(run_id)
            elif self.active_run_id is not None:
                selected = self.runs.get(self.active_run_id)
            elif self.last_run_id is not None:
                selected = self.runs.get(self.last_run_id)

        if not selected:
            return {
                "success": False,
                "error": f"No run found in session {self.id}. Start with run() first.",
                "session_id": self.id,
            }

        snapshot = selected.read_slice(offset=offset, max_lines=max_lines, max_chars=max_chars)
        
        if selected.done_event.is_set():
            if selected.completion_method in {"prompt_detected", "interrupted"}:
                status = "completed"
            elif selected.completion_method == "hard_timeout":
                status = "failed"
                selected.error = "hard timeout reached"
            elif selected.completion_method == "dead":
                status = "dead"
            else:
                status = selected.status
        else:
            if selected.quiet_event.is_set():
                status = "stalled"
            else:
                status = "running"

        return {
            "success": True,
            "session_id": self.id,
            "session_name": self.name,
            "run_id": selected.run_id,
            "status": status,
            "error": selected.error if status == "failed" else "",
            "output": snapshot["output"],
            "next_offset": snapshot["next_offset"],
            # Keep these for last_command_details
            "still_running": not selected.done_event.is_set(),
            "quiet_point": selected.quiet_event.is_set(),
            "finish_reason": snapshot["finish_reason"],
            "offset_start": snapshot["offset_start"],
            "base_offset": snapshot["base_offset"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "total_received_chars": snapshot["total_received_chars"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "completion_method": snapshot["completion_method"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": _total_buffer_getter() if _total_buffer_getter else 0,
        }

    def busy_info(self) -> Dict[str, Any]:
        with self.lock:
            if self.active_run_id is not None:
                run = self.runs.get(self.active_run_id)
                if run and not run.done_event.is_set():
                    return {"busy": True, "type": "run", "id": run.run_id}
            if self.active_pipeline_id is not None:
                pipeline = self.pipelines.get(self.active_pipeline_id)
                if pipeline and not pipeline.done_event.is_set():
                    return {"busy": True, "type": "pipeline", "id": pipeline.pipeline_id}
        return {"busy": False}

    def is_busy(self) -> bool:
        return bool(self.busy_info().get("busy"))

    def _start_pipeline_thread(self, pipeline: PipelineState) -> None:
        thread = threading.Thread(target=self._pipeline_worker, args=(pipeline,), daemon=True)
        self.pipeline_threads[pipeline.pipeline_id] = thread
        thread.start()

    def _pipeline_worker(self, pipeline: PipelineState) -> None:
        stdin_stream = None
        stdout_stream = None
        stderr_stream = None
        input_file = None
        output_file = None
        channel = None
        hard_deadline = (pipeline.started_at + pipeline.hard_timeout) if pipeline.hard_timeout > 0 else None

        try:
            if not self.client:
                pipeline.mark_done("failed", reason="no client", error="no client")
                return

            stdin_stream, stdout_stream, stderr_stream = self.client.exec_command(pipeline.command, get_pty=False)
            channel = stdout_stream.channel
            self._log_run(
                pipeline,
                "SYS",
                {"event": "pipeline_exec_started", "command": pipeline.command, "include_stderr": pipeline.include_stderr},
            )

            if pipeline.local_stdin_path:
                input_file = open(pipeline.local_stdin_path, "rb")
            if pipeline.local_stdout_path:
                mode = "ab" if pipeline.append_stdout else "wb"
                output_file = open(pipeline.local_stdout_path, mode)

            input_done = input_file is None

            while not pipeline.done_event.is_set():
                if self.is_dead:
                    pipeline.mark_done("dead", reason=self.death_reason, error=self.death_reason, completion_method="dead")
                    break

                if hard_deadline is not None and time.time() >= hard_deadline:
                    try:
                        channel.close()
                    except Exception:
                        pass
                    pipeline.mark_done("hard_timeout", reason="hard timeout reached", completion_method="hard_timeout")
                    self._log_run(pipeline, "SYS", {"event": "pipeline_hard_timeout", "seconds": pipeline.hard_timeout})
                    break

                has_progress = False

                if not input_done and channel and channel.send_ready():
                    chunk = input_file.read(BUFFER_SIZE)
                    if chunk:
                        sent = channel.send(chunk)
                        if sent > 0:
                            if sent < len(chunk):
                                input_file.seek(input_file.tell() - (len(chunk) - sent))
                            pipeline.add_sent_bytes(sent)
                            has_progress = True
                    else:
                        try:
                            channel.shutdown_write()
                        except Exception:
                            pass
                        input_done = True
                        has_progress = True

                if channel and channel.recv_ready():
                    if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                        pipeline.set_recv_paused(True, "memory_limit")
                        if pipeline.status == "running":
                            pipeline.status = "recv_paused_by_memory_limit"
                        self._log_run(
                            pipeline,
                            "SYS",
                            {
                                "event": "recv_paused",
                                "reason": "memory_limit",
                                "memory_total_chars": _total_buffer_getter() if _total_buffer_getter else 0,
                                "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
                            },
                        )
                        time.sleep(0.1)
                    else:
                        if pipeline.recv_paused:
                            pipeline.set_recv_paused(False)
                            if pipeline.status == "recv_paused_by_memory_limit":
                                pipeline.status = "running"
                            self._log_run(pipeline, "SYS", {"event": "recv_resumed"})
                        data = channel.recv(BUFFER_SIZE)
                        if data:
                            if output_file:
                                output_file.write(data)
                            pipeline.append_remote_bytes(data)
                            self._log_run(pipeline, "OUT", {"chunk_b64": base64.b64encode(data).decode("ascii")})
                            has_progress = True

                if pipeline.include_stderr and channel and channel.recv_stderr_ready():
                    if _buffer_checker and not _buffer_checker(BUFFER_SIZE):
                        pipeline.set_recv_paused(True, "memory_limit")
                        if pipeline.status == "running":
                            pipeline.status = "recv_paused_by_memory_limit"
                        time.sleep(0.1)
                    else:
                        err_data = channel.recv_stderr(BUFFER_SIZE)
                        if err_data:
                            if output_file:
                                output_file.write(err_data)
                            pipeline.append_remote_bytes(err_data)
                            self._log_run(pipeline, "ERR", {"chunk_b64": base64.b64encode(err_data).decode("ascii")})
                            has_progress = True

                if (
                    channel
                    and channel.exit_status_ready()
                    and input_done
                    and not channel.recv_ready()
                    and (not pipeline.include_stderr or not channel.recv_stderr_ready())
                ):
                    exit_code = channel.recv_exit_status()
                    pipeline.mark_done(
                        "completed" if exit_code == 0 else "completed_nonzero",
                        reason=f"exit_status={exit_code}",
                        exit_status=exit_code,
                        completion_method="exit_status",
                    )
                    break

                if not has_progress:
                    time.sleep(0.02)

        except Exception as exc:
            pipeline.mark_done("failed", reason="pipeline exception", error=str(exc), completion_method="failed")
            self._log_run(pipeline, "SYS", {"event": "pipeline_error", "error": str(exc)})
        finally:
            try:
                if output_file:
                    output_file.flush()
                    output_file.close()
            except Exception:
                pass
            try:
                if input_file:
                    input_file.close()
            except Exception:
                pass
            try:
                if stdin_stream:
                    stdin_stream.close()
            except Exception:
                pass
            try:
                if stdout_stream:
                    stdout_stream.close()
            except Exception:
                pass
            try:
                if stderr_stream:
                    stderr_stream.close()
            except Exception:
                pass

            with self.lock:
                if self.active_pipeline_id == pipeline.pipeline_id:
                    self.active_pipeline_id = None
                self.last_pipeline_id = pipeline.pipeline_id

            self._log_run(
                pipeline,
                "SYS",
                {
                    "event": "pipeline_finished",
                    "status": pipeline.status,
                    "reason": pipeline.finish_reason,
                    "error": pipeline.error,
                    "exit_status": pipeline.exit_status,
                    "bytes_written": pipeline.bytes_written,
                    "bytes_sent": pipeline.bytes_sent,
                },
            )

    def run_pipeline(
        self,
        command: str,
        mode: str,
        wait_timeout: float,
        startup_wait: float,
        hard_timeout: float,
        local_stdout_path: str,
        local_stdin_path: str,
        include_stderr: bool,
        append_stdout: bool,
    ) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error:
            return {"success": False, "error": error, "session_id": self.id}

        mode = (mode or "sync").lower().strip()
        if mode not in {"sync", "async"}:
            return {"success": False, "error": "mode must be one of: sync, async", "session_id": self.id}

        if not command or not command.strip():
            return {"success": False, "error": "command is required", "session_id": self.id}

        if not local_stdout_path and not local_stdin_path:
            return {
                "success": False,
                "error": "Provide at least one path: local_stdout_path and/or local_stdin_path",
                "session_id": self.id,
            }

        if local_stdin_path and (not os.path.isfile(local_stdin_path)):
            return {"success": False, "error": f"local_stdin_path not found: {local_stdin_path}", "session_id": self.id}

        if local_stdout_path:
            parent_dir = os.path.dirname(local_stdout_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

        wait_timeout = clamp_float(wait_timeout, DEFAULT_WAIT_TIMEOUT, 0.1, MAX_WAIT_TIMEOUT)
        startup_wait = clamp_float(startup_wait, DEFAULT_STARTUP_WAIT, 0.1, MAX_STARTUP_WAIT)
        hard_timeout = clamp_float(hard_timeout, DEFAULT_HARD_TIMEOUT, 0.0, MAX_HARD_TIMEOUT)

        busy = self.busy_info()
        if busy.get("busy"):
            if busy.get("type") == "pipeline":
                return {
                    "success": False,
                    "error": (
                        f"Session {self.id} already has running pipeline "
                        f"(pipeline_id={busy.get('id')})."
                    ),
                    "session_id": self.id,
                    "pipeline_id": busy.get("id"),
                }
            return {
                "success": False,
                "error": (
                    f"Session {self.id} has active run "
                    f"(run_id={busy.get('id')})."
                ),
                "session_id": self.id,
                "run_id": busy.get("id"),
            }

        # Pipeline always uses system shell
        if not self.in_shell:
            if not self._enter_shell():
                return {
                    "success": False,
                    "error": "Failed to enter system shell for pipeline. Try reconnecting session.",
                    "session_id": self.id,
                }

        pipeline_id = self.pipeline_counter
        self.pipeline_counter += 1
        pipeline = PipelineState(
            pipeline_id=pipeline_id,
            session_id=self.id,
            command=command,
            mode=mode,
            started_at=time.time(),
            wait_timeout=wait_timeout,
            startup_wait=startup_wait,
            hard_timeout=hard_timeout,
            local_stdout_path=local_stdout_path,
            local_stdin_path=local_stdin_path,
            include_stderr=include_stderr,
            append_stdout=append_stdout,
            max_buffer_chars=MAX_BUFFER_CHARS,
            run_log_path=self._build_run_log_path(pipeline_id),
        )

        with self.lock:
            self.pipelines[pipeline_id] = pipeline
            self.active_pipeline_id = pipeline_id
            self.last_pipeline_id = pipeline_id

        self.last_command = command
        self.last_command_time = datetime.now()
        self._log_session(
            "IN",
            {
                "event": "pipeline_start",
                "pipeline_id": pipeline_id,
                "mode": mode,
                "command": command,
                "local_stdout_path": local_stdout_path,
                "local_stdin_path": local_stdin_path,
                "include_stderr": include_stderr,
                "append_stdout": append_stdout,
                "wait_timeout": wait_timeout,
                "startup_wait": startup_wait,
                "hard_timeout": hard_timeout,
            },
        )

        self._start_pipeline_thread(pipeline)

        wait_for = wait_timeout if mode == "sync" else startup_wait
        completed_within_wait = pipeline.done_event.wait(wait_for)
        snapshot = pipeline.read_preview(offset=pipeline.preview_base_offset, max_chars=MAX_READ_MAX_CHARS)

        timed_out = (mode == "sync") and (not completed_within_wait)
        
        if pipeline.done_event.is_set():
            if pipeline.completion_method == "hard_timeout":
                status = "failed"
                pipeline.error = "hard timeout reached"
            elif pipeline.completion_method == "dead":
                status = "dead"
            else:
                status = pipeline.status
        else:
            status = "running"

        return {
            "success": True,
            "session_id": self.id,
            "session_name": self.name,
            "pipeline_id": pipeline_id,
            "status": status,
            "error": pipeline.error if status == "failed" else "",
            "preview": snapshot["preview"],
            "next_offset": snapshot["next_offset"],
            "bytes_written": snapshot["bytes_written"],
            "bytes_sent": snapshot["bytes_sent"],
            # Keep these for last_command_details
            "mode": mode,
            "timed_out": timed_out,
            "still_running": not pipeline.done_event.is_set(),
            "exit_status": pipeline.exit_status,
            "completion_method": pipeline.completion_method,
            "offset_start": snapshot["offset_start"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": _total_buffer_getter() if _total_buffer_getter else 0,
            "local_stdout_path": local_stdout_path,
            "local_stdin_path": local_stdin_path,
            "message": f"Pipeline is {status}.",
        }

    def pipeline_status(self, pipeline_id: Optional[int], offset: Optional[int], max_chars: int) -> Dict[str, Any]:
        max_chars = clamp_int(max_chars, DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)

        selected: Optional[PipelineState] = None
        with self.lock:
            if pipeline_id is not None:
                selected = self.pipelines.get(pipeline_id)
            elif self.active_pipeline_id is not None:
                selected = self.pipelines.get(self.active_pipeline_id)
            elif self.last_pipeline_id is not None:
                selected = self.pipelines.get(self.last_pipeline_id)

        if not selected:
            return {
                "success": False,
                "error": f"No pipeline found in session {self.id}. Start with run_pipeline() first.",
                "session_id": self.id,
            }

        snapshot = selected.read_preview(offset=offset, max_chars=max_chars)
        
        if selected.done_event.is_set():
            if selected.completion_method == "hard_timeout":
                status = "failed"
                selected.error = "hard timeout reached"
            elif selected.completion_method == "dead":
                status = "dead"
            else:
                status = selected.status
        else:
            status = "running"

        return {
            "success": True,
            "session_id": self.id,
            "session_name": self.name,
            "pipeline_id": selected.pipeline_id,
            "status": status,
            "error": selected.error if status == "failed" else "",
            "preview": snapshot["preview"],
            "next_offset": snapshot["next_offset"],
            "bytes_written": snapshot["bytes_written"],
            "bytes_sent": snapshot["bytes_sent"],
            # Keep these for last_command_details
            "still_running": not selected.done_event.is_set(),
            "exit_status": snapshot["exit_status"],
            "completion_method": snapshot["completion_method"],
            "offset_start": snapshot["offset_start"],
            "base_offset": snapshot["base_offset"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": _total_buffer_getter() if _total_buffer_getter else 0,
        }

    def send_signal(self, action: str, text: str = "", press_enter: bool = True) -> Dict[str, Any]:
        error = self.ensure_alive()
        if error:
            return {"success": False, "error": error, "session_id": self.id}

        action = (action or "ctrl_c").lower().strip()
        if action not in {"ctrl_c", "stdin"}:
            return {"success": False, "error": "action must be ctrl_c or stdin", "session_id": self.id}

        try:
            if action == "ctrl_c":
                self._send_ctrl_c_raw()
                active_run = None
                with self.lock:
                    if self.active_run_id is not None:
                        active_run = self.runs.get(self.active_run_id)
                if active_run:
                    active_run.interrupt_sent = True
                self._log_session("IN", {"event": "signal_ctrl_c"})
                return {"success": True, "session_id": self.id, "message": f"Ctrl+C sent to session {self.id}"}

            data = text + ("\n" if press_enter else "")
            if not self.channel:
                return {"success": False, "error": "No active channel", "session_id": self.id}
            self.channel.send(data)
            with self.lock:
                if self.active_run_id is not None:
                    active_run = self.runs.get(self.active_run_id)
                    if active_run and not active_run.done_event.is_set():
                        active_run.register_stdin()
            self._log_session("IN", {"event": "signal_stdin", "text": text, "press_enter": press_enter})
            return {
                "success": True,
                "session_id": self.id,
                "message": f"stdin sent to session {self.id}",
            }
        except Exception as exc:
            return {"success": False, "error": str(exc), "session_id": self.id}

    def open_sftp(self) -> Optional[paramiko.SFTPClient]:
        error = self.ensure_alive()
        if error:
            return None
        if not self.client:
            return None
        try:
            return self.client.open_sftp()
        except Exception as exc:
            self._log_session("SYS", {"event": "sftp_open_failed", "error": str(exc)})
            return None

    def close(self) -> None:
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

    def info(self) -> Dict[str, Any]:
        with self.lock:
            active = self.active_run_id
            active_pipeline = self.active_pipeline_id
        return {
            "id": self.id,
            "name": self.name,
            "alive": not self.is_dead and self.is_alive(),
            "dead": self.is_dead,
            "death_reason": self.death_reason if self.is_dead else "",
            "in_shell": self.in_shell,
            "active_run_id": active,
            "last_run_id": self.last_run_id,
            "active_pipeline_id": active_pipeline,
            "last_pipeline_id": self.last_pipeline_id,
            "last_command": self.last_command,
            "last_command_time": self.last_command_time.isoformat() if self.last_command_time else None,
            "created_at": self.created_at.isoformat(),
            "session_log_path": self.session_log_path,
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
        snapshot = {
            "timestamp": iso_now(),
            "tool": tool_name,
            "args": dict(args),
            "result": dict(result),
        }
        session_id = result.get("session_id")
        if session_id is None:
            raw_session_id = args.get("session_id")
            if raw_session_id is not None:
                try:
                    session_id = int(raw_session_id)
                except Exception:
                    session_id = None
        if session_id is not None:
            snapshot["session_id"] = session_id

        with self.lock:
            self.last_tool_result_global = snapshot
            if session_id is not None:
                self.last_tool_result_by_session[session_id] = snapshot

    def get_last_tool_result(self, session_id: Optional[int]) -> Dict[str, Any]:
        with self.lock:
            sid = session_id if session_id is not None else self.current_session_id
            if sid is not None and sid in self.last_tool_result_by_session:
                snapshot = dict(self.last_tool_result_by_session[sid])
                return {
                    "success": True,
                    "session_id": sid,
                    "tool": snapshot.get("tool"),
                    "timestamp": snapshot.get("timestamp"),
                    "args": snapshot.get("args", {}),
                    "result": snapshot.get("result", {}),
                }

            if self.last_tool_result_global:
                snapshot = dict(self.last_tool_result_global)
                return {
                    "success": True,
                    "session_id": snapshot.get("session_id"),
                    "tool": snapshot.get("tool"),
                    "timestamp": snapshot.get("timestamp"),
                    "args": snapshot.get("args", {}),
                    "result": snapshot.get("result", {}),
                }

            return {
                "success": False,
                "error": "No recorded command result yet. Run any tool first.",
            }

    def _health_loop(self) -> None:
        while not self.health_thread_stop:
            time.sleep(HEALTH_CHECK_INTERVAL)
            try:
                with self.lock:
                    sessions = list(self.sessions.values())
                for session in sessions:
                    if not session.is_dead:
                        session.check_health()
            except Exception as exc:
                log_error(f"health loop error: {exc}")

    def ensure_session(self) -> Optional[SSHSession]:
        with self.lock:
            if self.current_session_id is not None and self.current_session_id in self.sessions:
                return self.sessions[self.current_session_id]
        created = self.open_session(name="", make_current=True)
        if not created.get("success"):
            return None
        sid = created["session_id"]
        with self.lock:
            return self.sessions.get(sid)

    def open_session(self, name: str, make_current: bool) -> Dict[str, Any]:
        with self.lock:
            sid = self.next_session_id
            self.next_session_id += 1

        session = SSHSession(sid, name or "", self.cache_dirs, self.project_tag)
        if not session.connect():
            return {"success": False, "error": f"failed to connect new session {sid}"}

        with self.lock:
            self.sessions[sid] = session
            if make_current or self.current_session_id is None:
                self.current_session_id = sid
        return {
            "success": True,
            "session_id": sid,
            "name": session.name,
            "current_session": self.current_session_id,
            "session_info": session.info(),
            "message": f"Session {sid} created",
        }

    def close_session(self, session_id: int) -> Dict[str, Any]:
        with self.lock:
            session = self.sessions.pop(session_id, None)
            if not session:
                return {"success": False, "error": f"session {session_id} not found"}

        session.close()
        with self.lock:
            if self.current_session_id == session_id:
                if self.sessions:
                    self.current_session_id = sorted(self.sessions.keys())[0]
                else:
                    self.current_session_id = None
        return {
            "success": True,
            "message": f"Session {session_id} closed",
            "current_session": self.current_session_id,
            "status": "completed"
        }

    def update_session(self, session_id: int, name: Optional[str], make_current: Optional[bool]) -> Dict[str, Any]:
        with self.lock:
            session = self.sessions.get(session_id)
            if not session:
                return {"success": False, "error": f"session {session_id} not found"}
            if name is not None:
                session.name = name
            if make_current is True:
                self.current_session_id = session_id
            current_id = self.current_session_id
        return {
            "success": True,
            "session_id": session_id,
            "name": session.name,
            "current_session": current_id,
            "session_info": session.info(),
            "message": f"Session {session_id} updated",
            "status": "completed"
        }

    def get_session(self, session_id: Optional[int]) -> Optional[SSHSession]:
        with self.lock:
            if session_id is not None:
                return self.sessions.get(session_id)
            if self.current_session_id is None:
                return None
            return self.sessions.get(self.current_session_id)

    def set_current_session(self, session_id: int) -> None:
        with self.lock:
            if session_id in self.sessions:
                self.current_session_id = session_id

    def total_buffer_chars(self) -> int:
        with self.lock:
            sessions = list(self.sessions.values())

        total = 0
        for session in sessions:
            with session.lock:
                for run in session.runs.values():
                    with run.lock:
                        total += len(run.output_buffer)
                for pipeline in session.pipelines.values():
                    with pipeline.lock:
                        total += len(pipeline.preview_buffer)
        return total

    def can_accept_more_buffer(self, incoming_chars: int = 0) -> bool:
        return (self.total_buffer_chars() + max(0, incoming_chars)) <= MAX_TOTAL_BUFFER_CHARS

    def find_first_idle_alive_session(self) -> Optional[SSHSession]:
        with self.lock:
            snapshot = [self.sessions[sid] for sid in sorted(self.sessions.keys())]

        for session in snapshot:
            if session.is_dead:
                continue
            if session.ensure_alive() is not None:
                continue
            if session.is_busy():
                continue
            return session
        return None

    def list_sessions(
        self,
        include_name: bool = False,
        include_last_command: bool = False,
        include_active_ids: bool = False,
    ) -> Dict[str, Any]:
        with self.lock:
            rows = []
            for sid, session in self.sessions.items():
                if not session.is_dead:
                    session.check_health()
                info = session.info()
                is_busy = session.is_busy()

                if info.get("dead") or not info.get("alive"):
                    status = "broken"
                elif is_busy:
                    status = "busy"
                else:
                    status = "idle"

                row = {
                    "id": sid,
                    "status": status,
                    "is_current": sid == self.current_session_id,
                    "current": sid == self.current_session_id,
                }
                if include_name and info.get("name"):
                    row["name"] = info.get("name")
                if include_last_command and info.get("last_command"):
                    row["last_command"] = info.get("last_command")
                if include_active_ids:
                    row["active_run_id"] = info.get("active_run_id")
                    row["active_pipeline_id"] = info.get("active_pipeline_id")
                rows.append(row)
            rows.sort(key=lambda item: item["id"])
            return {
                "success": True,
                "sessions": rows,
                "current_session": self.current_session_id,
                "total": len(rows),
                "status": "completed"
            }

    def close_all(self) -> None:
        self.health_thread_stop = True
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.close()
