#!/usr/bin/env python3
"""
Compact SSH MCP server (vNext).

Goals:
- Fewer tools for simpler agents
- Unified command execution model (run/read/signal)
- Anti-hang wait timeout for MCP call itself (without killing session/command)
- Background output collection even when agent is not polling
- Session and run logs in .ssh-cache
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

import paramiko


# ========= Static config =========
CONNECT_TIMEOUT = 10
KEEPALIVE_INTERVAL = 30
BUFFER_SIZE = 4096
HEALTH_CHECK_INTERVAL = 30

DEFAULT_WAIT_TIMEOUT = 20.0
MAX_WAIT_TIMEOUT = 120.0
DEFAULT_STARTUP_WAIT = 2.0
MAX_STARTUP_WAIT = 10.0
DEFAULT_HARD_TIMEOUT = 0.0  # 0 means disabled
MAX_HARD_TIMEOUT = 3600.0

MAX_BUFFER_CHARS = 200000
MAX_TOTAL_BUFFER_CHARS = 200_000_000
DEFAULT_READ_MAX_LINES = 200
DEFAULT_READ_MAX_CHARS = 20000
MAX_READ_MAX_LINES = 5000
MAX_READ_MAX_CHARS = 200000
DEFAULT_FILE_INSPECT_MAX_BYTES = 200000
MAX_FILE_INSPECT_MAX_BYTES = 2_000_000
DEFAULT_FILE_EDIT_MAX_BYTES = 1_000_000
MAX_FILE_EDIT_MAX_BYTES = 5_000_000
MAX_INLINE_WRITE_BYTES = 200000
DEFAULT_QUIET_COMPLETE_TIMEOUT = 1.5
MAX_QUIET_COMPLETE_TIMEOUT = 30.0

DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/bin:/opt/sbin"

# ========= Runtime connection config =========
SSH_HOST: Optional[str] = None
SSH_USER: Optional[str] = None
SSH_PASSWORD: Optional[str] = None
SSH_PORT = 22
EXTRA_PATH: Optional[str] = None
PROJECT_ROOT: str = ""
PROJECT_TAG: str = ""
CACHE_DIRS: Dict[str, str] = {}


# ========= Output cleanup =========
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
PROMPT_ONLY_LINE = re.compile(r"^\s*(\([^)]*\)\s*[>#]?|[>#])\s*$")


def log_error(message: str) -> None:
    print(f"[SSH-MCP] {message}", file=sys.stderr, flush=True)


def clamp_float(value: Any, default: float, min_value: float, max_value: float) -> float:
    try:
        numeric = float(value)
    except Exception:
        numeric = default
    if numeric < min_value:
        return min_value
    if numeric > max_value:
        return max_value
    return numeric


def clamp_int(value: Any, default: int, min_value: int, max_value: int) -> int:
    try:
        numeric = int(value)
    except Exception:
        numeric = default
    if numeric < min_value:
        return min_value
    if numeric > max_value:
        return max_value
    return numeric


def to_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).lower().strip()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return default


def iso_now() -> str:
    return datetime.now().isoformat(timespec="milliseconds")


def safe_name(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "_", text.strip())
    return cleaned[:80] if cleaned else "unnamed"


def clean_output(text: str, remove_echo: bool = False) -> str:
    if not text:
        return ""

    text = ANSI_ESCAPE.sub("", text)
    text = CONTROL_CHARS.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    if remove_echo and "\n" in text:
        text = text.split("\n", 1)[1]

    cleaned_lines = []
    for line in text.split("\n"):
        if PROMPT_ONLY_LINE.match(line.strip() or ""):
            continue
        cleaned_lines.append(line)

    text = "\n".join(cleaned_lines)
    while "\n\n\n" in text:
        text = text.replace("\n\n\n", "\n\n")
    return text.strip()


def apply_text_filters(
    text: str,
    contains: Optional[str] = None,
    regex: Optional[str] = None,
    tail_lines: Optional[int] = None,
) -> Dict[str, Any]:
    raw = text or ""
    lines = raw.splitlines()
    scanned_chars = len(raw)
    filtered = False

    if contains:
        lines = [line for line in lines if contains in line]
        filtered = True

    if regex:
        try:
            compiled = re.compile(regex)
        except re.error as exc:
            return {
                "success": False,
                "error": f"invalid regex: {exc}",
                "filtered": False,
                "matched_lines": 0,
                "scanned_chars": scanned_chars,
                "output": "",
            }
        lines = [line for line in lines if compiled.search(line)]
        filtered = True

    if tail_lines is not None:
        tail = clamp_int(tail_lines, 100, 1, MAX_READ_MAX_LINES)
        lines = lines[-tail:]
        filtered = True

    output = "\n".join(lines)
    return {
        "success": True,
        "filtered": filtered,
        "matched_lines": len(lines),
        "scanned_chars": scanned_chars,
        "output": output,
    }


def json_line(path: str, payload: Dict[str, Any]) -> None:
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception as exc:
        log_error(f"log write failed ({path}): {exc}")


def make_cache_dirs(cache_root: str) -> Dict[str, str]:
    sessions_dir = os.path.join(cache_root, "sessions")
    runs_dir = os.path.join(cache_root, "runs")
    os.makedirs(sessions_dir, exist_ok=True)
    os.makedirs(runs_dir, exist_ok=True)
    return {
        "cache_root": cache_root,
        "sessions_dir": sessions_dir,
        "runs_dir": runs_dir,
    }


def resolve_runtime_paths(
    project_root_arg: Optional[str],
    cache_dir_arg: Optional[str],
) -> Dict[str, str]:
    project_root = os.path.abspath(project_root_arg or os.getcwd())
    project_tag = safe_name(os.path.basename(project_root))
    project_hash = hashlib.sha1(project_root.encode("utf-8")).hexdigest()[:8]
    project_ns = f"{project_tag}-{project_hash}"

    cache_override = cache_dir_arg or os.environ.get("SSH_MCP_CACHE_DIR")
    if cache_override:
        cache_root = os.path.join(os.path.abspath(cache_override), project_ns)
    else:
        cache_root = os.path.join(project_root, ".ssh-cache")

    return {
        "project_root": project_root,
        "project_tag": project_tag,
        "cache_root": cache_root,
    }


def has_prompt(output: str) -> bool:
    if not output:
        return False
    tail = output[-200:] if len(output) > 200 else output
    lines = tail.rstrip().split("\n")
    last_line = lines[-1].strip() if lines else ""
    if not last_line:
        return False

    prompt_patterns = [
        # Keenetic NDMS
        r"^\([^)]+\)\s*>\s*$",
        r"^>\s*$",
        # BusyBox / shell
        r"^[/~][^\s]*\s*#\s*$",
        r"^[/~][^\s]*\s*\$\s*$",
        r"^root@[^:]+:[^#$]+[#$]\s*$",
        r"^[#$]\s*$",
    ]
    for pattern in prompt_patterns:
        if re.search(pattern, last_line):
            return True
    return False


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
        try:
            self.close()
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                hostname=SSH_HOST,
                port=SSH_PORT,
                username=SSH_USER,
                password=SSH_PASSWORD,
                timeout=CONNECT_TIMEOUT,
                allow_agent=False,
                look_for_keys=False,
            )

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

    def _start_reader_thread(self, run: RunState) -> None:
        thread = threading.Thread(target=self._reader_loop, args=(run,), daemon=True)
        self.reader_threads[run.run_id] = thread
        thread.start()

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

                if not manager.can_accept_more_buffer(BUFFER_SIZE):
                    run.set_recv_paused(True, "memory_limit")
                    if run.status == "running":
                        run.status = "recv_paused_by_memory_limit"
                    self._log_run(
                        run,
                        "SYS",
                        {
                            "event": "recv_paused",
                            "reason": "memory_limit",
                            "memory_total_chars": manager.total_buffer_chars(),
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
                    if has_prompt(run.output_buffer):
                        run.prompt_detected = True
                        completion_method = "interrupted" if run.interrupt_sent else "prompt_detected"
                        reason = "prompt after interrupt" if run.interrupt_sent else "prompt detected"
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
                                run.mark_done("completed", reason="quiet timeout", completion_method="quiet_timeout")
                                break
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
                        f"Session {self.id} already has running command "
                        f"(run_id={busy.get('id')}). Use read/signal or another session."
                    ),
                    "session_id": self.id,
                    "run_id": busy.get("id"),
                }
            return {
                "success": False,
                "error": (
                    f"Session {self.id} has active pipeline "
                    f"(pipeline_id={busy.get('id')}). Use pipeline_status/signal or another session."
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

        # Flush pending channel data before new command.
        if self.channel:
            while self.channel.recv_ready():
                try:
                    self.channel.recv(BUFFER_SIZE)
                except Exception:
                    break

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
            wait_for = wait_timeout
        else:
            wait_for = startup_wait

        completed_within_wait = run.done_event.wait(wait_for)
        snapshot = run.read_slice(offset=run.buffer_base_offset, max_lines=MAX_READ_MAX_LINES, max_chars=MAX_READ_MAX_CHARS)

        timed_out = (mode == "sync") and (not completed_within_wait)
        output_complete = completed_within_wait and run.done_event.is_set()
        still_running = not run.done_event.is_set()

        return {
            "success": True,
            "session_id": self.id,
            "run_id": run_id,
            "mode": mode,
            "timed_out": timed_out,
            "output_complete": output_complete,
            "still_running": still_running,
            "status": run.status,
            "finish_reason": run.finish_reason,
            "completion_method": run.completion_method,
            "wait_timeout": wait_timeout,
            "startup_wait": startup_wait,
            "hard_timeout": hard_timeout,
            "completion_hint": completion_hint,
            "quiet_complete_timeout": quiet_complete_timeout,
            "output": snapshot["output"],
            "offset_start": snapshot["offset_start"],
            "next_offset": snapshot["next_offset"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": manager.total_buffer_chars(),
            "message": (
                "Command is still running. This is partial output; call read later."
                if still_running
                else "Command completed."
            ),
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
        return {
            "success": True,
            "session_id": self.id,
            "run_id": selected.run_id,
            "status": snapshot["status"],
            "still_running": snapshot["still_running"],
            "output_complete": snapshot["output_complete"],
            "finish_reason": snapshot["finish_reason"],
            "error": snapshot["error"],
            "offset_start": snapshot["offset_start"],
            "next_offset": snapshot["next_offset"],
            "base_offset": snapshot["base_offset"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "total_received_chars": snapshot["total_received_chars"],
            "output": snapshot["output"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "completion_method": snapshot["completion_method"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": manager.total_buffer_chars(),
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
                            # If partial send happened, seek back for unsent tail.
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
                    if not manager.can_accept_more_buffer(BUFFER_SIZE):
                        pipeline.set_recv_paused(True, "memory_limit")
                        if pipeline.status == "running":
                            pipeline.status = "recv_paused_by_memory_limit"
                        self._log_run(
                            pipeline,
                            "SYS",
                            {
                                "event": "recv_paused",
                                "reason": "memory_limit",
                                "memory_total_chars": manager.total_buffer_chars(),
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
                    if not manager.can_accept_more_buffer(BUFFER_SIZE):
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
                        f"(pipeline_id={busy.get('id')}). Use pipeline_status or another session."
                    ),
                    "session_id": self.id,
                    "pipeline_id": busy.get("id"),
                }
            return {
                "success": False,
                "error": (
                    f"Session {self.id} has active run "
                    f"(run_id={busy.get('id')}). Use read/signal or another session."
                ),
                "session_id": self.id,
                "run_id": busy.get("id"),
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
        still_running = not pipeline.done_event.is_set()

        return {
            "success": True,
            "session_id": self.id,
            "pipeline_id": pipeline_id,
            "mode": mode,
            "timed_out": timed_out,
            "still_running": still_running,
            "output_complete": pipeline.done_event.is_set(),
            "written_complete": pipeline.done_event.is_set(),
            "status": pipeline.status,
            "finish_reason": pipeline.finish_reason,
            "exit_status": pipeline.exit_status,
            "completion_method": pipeline.completion_method,
            "bytes_written": snapshot["bytes_written"],
            "bytes_sent": snapshot["bytes_sent"],
            "preview": snapshot["preview"],
            "offset_start": snapshot["offset_start"],
            "next_offset": snapshot["next_offset"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": manager.total_buffer_chars(),
            "local_stdout_path": local_stdout_path,
            "local_stdin_path": local_stdin_path,
            "message": (
                "Pipeline is still running/writing. Use pipeline_status to check completion."
                if still_running
                else "Pipeline completed."
            ),
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
        return {
            "success": True,
            "session_id": self.id,
            "pipeline_id": selected.pipeline_id,
            "status": snapshot["status"],
            "still_running": snapshot["still_running"],
            "output_complete": snapshot["output_complete"],
            "written_complete": snapshot["output_complete"],
            "finish_reason": snapshot["finish_reason"],
            "error": snapshot["error"],
            "exit_status": snapshot["exit_status"],
            "completion_method": snapshot["completion_method"],
            "bytes_written": snapshot["bytes_written"],
            "bytes_sent": snapshot["bytes_sent"],
            "offset_start": snapshot["offset_start"],
            "next_offset": snapshot["next_offset"],
            "base_offset": snapshot["base_offset"],
            "dropped_data": snapshot["dropped_data"],
            "limited": snapshot["limited"],
            "preview": snapshot["preview"],
            "recv_paused": snapshot["recv_paused"],
            "pause_reason": snapshot["pause_reason"],
            "memory_limit_chars": MAX_TOTAL_BUFFER_CHARS,
            "memory_total_chars": manager.total_buffer_chars(),
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
            }

    def close_all(self) -> None:
        self.health_thread_stop = True
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.close()


manager: Optional[SessionManager] = None

LEAN_RESPONSE_KEYS: Dict[str, tuple[str, ...]] = {
    "run": ("success", "session_id", "run_id", "status", "still_running", "output", "output_complete"),
    "exec": ("success", "session_id", "run_id", "status", "still_running", "output", "output_complete"),
    "read": ("success", "session_id", "run_id", "status", "still_running", "output", "next_offset", "output_complete"),
    "run_pipeline": (
        "success",
        "session_id",
        "pipeline_id",
        "status",
        "still_running",
        "written_complete",
        "preview",
        "next_offset",
        "exit_status",
        "output_complete",
    ),
    "pipeline_status": (
        "success",
        "session_id",
        "pipeline_id",
        "status",
        "still_running",
        "written_complete",
        "preview",
        "next_offset",
        "exit_status",
        "output_complete",
    ),
    "session_list": ("success", "sessions", "current_session"),
    "session_close": ("success", "message", "current_session"),
    "session_update": ("success", "session_id", "name", "current_session", "message"),
    "signal": ("success", "session_id", "message"),
    "file": (
        "success",
        "action",
        "mode",
        "path",
        "local_path",
        "source",
        "method",
        "files",
        "listing",
        "size",
        "sha256",
        "content",
        "filtered",
        "matched_lines",
        "scanned_chars",
        "line_start",
        "line_end",
        "total_lines",
        "truncated",
        "changed",
        "replacements",
        "dry_run",
        "backup_path",
        "old_sha256",
        "new_sha256",
    ),
    "last_command_details": ("success", "session_id", "tool", "timestamp", "args", "result"),
}


def project_error_result(result: Dict[str, Any]) -> Dict[str, Any]:
    projected = {"success": False, "error": result.get("error", "unknown error")}
    for key in ("session_id", "run_id", "pipeline_id", "busy_type", "busy_id"):
        if key in result:
            projected[key] = result[key]
    return projected


def project_tool_result(tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return {"success": False, "error": "tool returned non-object result"}
    if not result.get("success", False):
        return project_error_result(result)

    keys = LEAN_RESPONSE_KEYS.get(tool_name)
    if keys is None:
        return result
    return {key: result[key] for key in keys if key in result}


def format_tool_result(result: Dict[str, Any]) -> Dict[str, Any]:
    text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if result.get("success", False):
        return {"content": [{"type": "text", "text": text}]}
    return {"content": [{"type": "text", "text": text}], "isError": True}


def make_response(req_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": format_tool_result(result)}


def session_from_args(session_id: Optional[int]) -> Optional[SSHSession]:
    if manager is None:
        return None
    session = manager.get_session(session_id)
    if session:
        return session
    return manager.ensure_session()


def run_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    command = args.get("command", "")
    mode = args.get("mode", "sync")
    shell = to_bool(args.get("shell", False))
    wait_timeout = args.get("wait_timeout", DEFAULT_WAIT_TIMEOUT)
    startup_wait = args.get("startup_wait", DEFAULT_STARTUP_WAIT)
    hard_timeout = args.get("hard_timeout", DEFAULT_HARD_TIMEOUT)
    completion_hint = args.get("completion_hint", "either")
    quiet_complete_timeout = args.get("quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)

    session_id = args.get("session_id")
    new_session = to_bool(args.get("new_session", False))
    session_name = args.get("session_name", "") or ""

    if new_session and session_id is not None:
        return {
            "success": False,
            "error": "session_id and new_session=true are mutually exclusive",
        }

    session_created = False
    session_recovered = False
    created_session_id = None
    requested_session_id = session_id
    selection_reason = ""
    selection_source = ""
    session: Optional[SSHSession] = None

    if new_session:
        created = manager.open_session(name=session_name, make_current=True)
        if not created.get("success", False):
            return created
        created_session_id = created["session_id"]
        session_created = True
        selection_source = "new_session"
        session = manager.get_session(created_session_id)
    elif session_id is not None:
        session = manager.get_session(session_id)
        if session is None:
            selection_reason = f"requested session {session_id} not found"
        else:
            alive_error = session.ensure_alive()
            if alive_error:
                selection_reason = alive_error
            elif session.is_busy():
                busy = session.busy_info()
                return {
                    "success": False,
                    "error": (
                        f"Requested session {session_id} is busy "
                        f"({busy.get('type')} id={busy.get('id')})."
                    ),
                    "session_id": session_id,
                    "busy_type": busy.get("type"),
                    "busy_id": busy.get("id"),
                }

        if session is None or selection_reason:
            recovered_name = session_name or f"auto-recovery-from-{session_id}"
            created = manager.open_session(name=recovered_name, make_current=True)
            if not created.get("success", False):
                return created
            created_session_id = created["session_id"]
            session_created = True
            session_recovered = True
            selection_source = "explicit_recovery_new"
            session = manager.get_session(created_session_id)
        else:
            selection_source = "explicit"
    else:
        session = manager.get_session(None)
        if session is None:
            selection_reason = "current session is missing"
        else:
            alive_error = session.ensure_alive()
            if alive_error:
                selection_reason = alive_error
                session = None
            elif session.is_busy():
                busy = session.busy_info()
                selection_reason = f"current session busy ({busy.get('type')} id={busy.get('id')})"
                session = None
            else:
                selection_source = "current"

        if session is None:
            idle_session = manager.find_first_idle_alive_session()
            if idle_session is not None:
                manager.set_current_session(idle_session.id)
                session = idle_session
                selection_source = "first_idle"
            else:
                created = manager.open_session(name=(session_name or "auto-new-default"), make_current=True)
                if not created.get("success", False):
                    return created
                created_session_id = created["session_id"]
                session_created = True
                session_recovered = True
                selection_source = "default_recovery_new"
                session = manager.get_session(created_session_id)

    if not session:
        return {"success": False, "error": "no session available"}

    result = session.run_command(
        command=command,
        mode=mode,
        shell=shell,
        wait_timeout=wait_timeout,
        startup_wait=startup_wait,
        hard_timeout=hard_timeout,
        completion_hint=completion_hint,
        quiet_complete_timeout=quiet_complete_timeout,
    )
    if result.get("success"):
        result["session_created"] = session_created
        result["session_recovered"] = session_recovered
        result["requested_session_id"] = requested_session_id
        result["executed_session_id"] = result.get("session_id")
        result["session_selection"] = selection_source
        if selection_reason:
            result["selection_reason"] = selection_reason
            if session_recovered:
                result["recovery_reason"] = selection_reason
        if session_created:
            result["created_session_id"] = created_session_id
    return result


def read_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = args.get("session_id")
    run_id = args.get("run_id")
    offset = args.get("offset")
    max_lines = args.get("max_lines", DEFAULT_READ_MAX_LINES)
    max_chars = args.get("max_chars", DEFAULT_READ_MAX_CHARS)
    contains = args.get("contains")
    regex = args.get("regex")
    tail_lines = args.get("tail_lines")
    _level = args.get("level")
    _kind = args.get("kind")

    if offset is not None:
        try:
            offset = int(offset)
        except Exception:
            return {"success": False, "error": "offset must be number"}

    if run_id is not None:
        try:
            run_id = int(run_id)
        except Exception:
            return {"success": False, "error": "run_id must be number"}

    session = session_from_args(session_id)
    if not session:
        return {"success": False, "error": "session not found"}

    result = session.read_run(run_id=run_id, offset=offset, max_lines=max_lines, max_chars=max_chars)
    if not result.get("success"):
        return result

    filtered = apply_text_filters(result.get("output", ""), contains=contains, regex=regex, tail_lines=tail_lines)
    if not filtered.get("success"):
        return {
            "success": False,
            "error": filtered.get("error", "filtering error"),
            "session_id": result.get("session_id"),
            "run_id": result.get("run_id"),
        }
    result["output"] = filtered["output"]
    result["filtered"] = filtered["filtered"]
    result["matched_lines"] = filtered["matched_lines"]
    result["scanned_chars"] = filtered["scanned_chars"]
    result["filter_contains"] = bool(contains)
    result["filter_regex"] = bool(regex)
    result["filter_tail_lines"] = tail_lines is not None
    # Reserved for future typed logs, intentionally no-op now.
    result["filter_level"] = _level
    result["filter_kind"] = _kind
    return result


def signal_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    session = session_from_args(args.get("session_id"))
    if not session:
        return {"success": False, "error": "session not found"}
    action = args.get("action", "ctrl_c")
    text = args.get("text", "")
    press_enter = to_bool(args.get("press_enter", True), True)
    return session.send_signal(action=action, text=text, press_enter=press_enter)


def last_command_details_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    if manager is None:
        return {"success": False, "error": "session manager is not initialized"}
    session_id = args.get("session_id")
    if session_id is not None:
        try:
            session_id = int(session_id)
        except Exception:
            return {"success": False, "error": "session_id must be number"}
    return manager.get_last_tool_result(session_id=session_id)


def run_pipeline_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    command = args.get("command", "")
    mode = args.get("mode", "sync")
    wait_timeout = args.get("wait_timeout", DEFAULT_WAIT_TIMEOUT)
    startup_wait = args.get("startup_wait", DEFAULT_STARTUP_WAIT)
    hard_timeout = args.get("hard_timeout", DEFAULT_HARD_TIMEOUT)
    include_stderr = to_bool(args.get("include_stderr", False))
    append_stdout = to_bool(args.get("append_stdout", False))
    local_stdout_path = (args.get("local_stdout_path", "") or "").strip()
    local_stdin_path = (args.get("local_stdin_path", "") or "").strip()

    session_id = args.get("session_id")
    new_session = to_bool(args.get("new_session", False))
    session_name = args.get("session_name", "") or ""

    if new_session and session_id is not None:
        return {"success": False, "error": "session_id and new_session=true are mutually exclusive"}

    session_created = False
    session_recovered = False
    created_session_id = None
    requested_session_id = session_id
    selection_reason = ""
    selection_source = ""
    session: Optional[SSHSession] = None

    if new_session:
        created = manager.open_session(name=session_name, make_current=True)
        if not created.get("success", False):
            return created
        created_session_id = created["session_id"]
        session_created = True
        selection_source = "new_session"
        session = manager.get_session(created_session_id)
    elif session_id is not None:
        session = manager.get_session(session_id)
        if session is None:
            selection_reason = f"requested session {session_id} not found"
        else:
            alive_error = session.ensure_alive()
            if alive_error:
                selection_reason = alive_error
            elif session.is_busy():
                busy = session.busy_info()
                return {
                    "success": False,
                    "error": (
                        f"Requested session {session_id} is busy "
                        f"({busy.get('type')} id={busy.get('id')})."
                    ),
                    "session_id": session_id,
                    "busy_type": busy.get("type"),
                    "busy_id": busy.get("id"),
                }

        if session is None or selection_reason:
            recovered_name = session_name or f"auto-recovery-from-{session_id}"
            created = manager.open_session(name=recovered_name, make_current=True)
            if not created.get("success", False):
                return created
            created_session_id = created["session_id"]
            session_created = True
            session_recovered = True
            selection_source = "explicit_recovery_new"
            session = manager.get_session(created_session_id)
        else:
            selection_source = "explicit"
    else:
        session = manager.get_session(None)
        if session is None:
            selection_reason = "current session is missing"
        else:
            alive_error = session.ensure_alive()
            if alive_error:
                selection_reason = alive_error
                session = None
            elif session.is_busy():
                busy = session.busy_info()
                selection_reason = f"current session busy ({busy.get('type')} id={busy.get('id')})"
                session = None
            else:
                selection_source = "current"

        if session is None:
            idle_session = manager.find_first_idle_alive_session()
            if idle_session is not None:
                manager.set_current_session(idle_session.id)
                session = idle_session
                selection_source = "first_idle"
            else:
                created = manager.open_session(name=(session_name or "auto-new-default"), make_current=True)
                if not created.get("success", False):
                    return created
                created_session_id = created["session_id"]
                session_created = True
                session_recovered = True
                selection_source = "default_recovery_new"
                session = manager.get_session(created_session_id)

    if not session:
        return {"success": False, "error": "no session available"}

    result = session.run_pipeline(
        command=command,
        mode=mode,
        wait_timeout=wait_timeout,
        startup_wait=startup_wait,
        hard_timeout=hard_timeout,
        local_stdout_path=local_stdout_path,
        local_stdin_path=local_stdin_path,
        include_stderr=include_stderr,
        append_stdout=append_stdout,
    )
    if result.get("success"):
        result["session_created"] = session_created
        result["session_recovered"] = session_recovered
        result["requested_session_id"] = requested_session_id
        result["executed_session_id"] = result.get("session_id")
        result["session_selection"] = selection_source
        if selection_reason:
            result["selection_reason"] = selection_reason
            if session_recovered:
                result["recovery_reason"] = selection_reason
        if session_created:
            result["created_session_id"] = created_session_id
    return result


def pipeline_status_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    session_id = args.get("session_id")
    pipeline_id = args.get("pipeline_id")
    offset = args.get("offset")
    max_chars = args.get("max_chars", DEFAULT_READ_MAX_CHARS)
    contains = args.get("contains")
    regex = args.get("regex")
    tail_lines = args.get("tail_lines")
    _level = args.get("level")
    _kind = args.get("kind")

    if pipeline_id is not None:
        try:
            pipeline_id = int(pipeline_id)
        except Exception:
            return {"success": False, "error": "pipeline_id must be number"}

    if offset is not None:
        try:
            offset = int(offset)
        except Exception:
            return {"success": False, "error": "offset must be number"}

    session = session_from_args(session_id)
    if not session:
        return {"success": False, "error": "session not found"}

    result = session.pipeline_status(pipeline_id=pipeline_id, offset=offset, max_chars=max_chars)
    if not result.get("success"):
        return result

    filtered = apply_text_filters(result.get("preview", ""), contains=contains, regex=regex, tail_lines=tail_lines)
    if not filtered.get("success"):
        return {
            "success": False,
            "error": filtered.get("error", "filtering error"),
            "session_id": result.get("session_id"),
            "pipeline_id": result.get("pipeline_id"),
        }
    result["preview"] = filtered["output"]
    result["filtered"] = filtered["filtered"]
    result["matched_lines"] = filtered["matched_lines"]
    result["scanned_chars"] = filtered["scanned_chars"]
    result["filter_contains"] = bool(contains)
    result["filter_regex"] = bool(regex)
    result["filter_tail_lines"] = tail_lines is not None
    result["filter_level"] = _level
    result["filter_kind"] = _kind
    return result


def _sync_shell(session: SSHSession, command: str, timeout: float = 30.0) -> Dict[str, Any]:
    result = session.run_command(
        command=command,
        mode="sync",
        shell=True,
        wait_timeout=timeout,
        startup_wait=DEFAULT_STARTUP_WAIT,
        hard_timeout=max(timeout + 5.0, 0.0),
        completion_hint="either",
        quiet_complete_timeout=DEFAULT_QUIET_COMPLETE_TIMEOUT,
    )
    if not result.get("success", False):
        return result
    if result.get("timed_out"):
        return {
            "success": False,
            "error": "shell command timed out; partial output returned",
            "partial_output": result.get("output", ""),
            "session_id": result.get("session_id"),
            "run_id": result.get("run_id"),
        }
    return result


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _extract_between_markers(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    lines = (text or "").splitlines()
    start_idx = -1
    end_idx = -1
    for idx, line in enumerate(lines):
        clean = line.strip()
        # We look for the marker as a standalone line to avoid matching it within the echoed command
        if start_idx < 0 and clean == start_marker:
            start_idx = idx + 1
            continue
        if start_idx >= 0 and clean == end_marker:
            end_idx = idx
            break
    if start_idx < 0 or end_idx < start_idx:
        return None
    return "\n".join(lines[start_idx:end_idx]).strip()


def _read_remote_file_bytes(
    session: SSHSession,
    path: str,
    max_bytes: Optional[int],
) -> Dict[str, Any]:
    sftp = session.open_sftp()
    if sftp is not None:
        try:
            with sftp.file(path, "rb") as handle:
                if max_bytes is None:
                    data = handle.read()
                    truncated = False
                else:
                    data = handle.read(max_bytes + 1)
                    truncated = len(data) > max_bytes
                    if truncated:
                        data = data[:max_bytes]
            return {
                "success": True,
                "method": "sftp",
                "data": data,
                "truncated": truncated,
            }
        except Exception as exc:
            log_error(f"sftp read failed, fallback shell: {exc}")
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    stamp = f"{int(time.time() * 1000)}_{os.getpid()}"
    marker_start = f"MCP_BEGIN_{stamp}"
    marker_end = f"MCP_END_{stamp}"
    marker_error = f"MCP_ERR_{stamp}"

    if max_bytes is None:
        shell_command = (
            f"if [ -r '{path}' ]; then "
            f"echo '{marker_start}'; base64 '{path}'; echo '{marker_end}'; "
            f"else echo '{marker_error}'; fi"
        )
    else:
        shell_command = (
            f"if [ -r '{path}' ]; then "
            f"echo '{marker_start}'; head -c {max_bytes + 1} '{path}' | base64; echo '{marker_end}'; "
            f"else echo '{marker_error}'; fi"
        )

    shell_result = _sync_shell(session, shell_command, timeout=30.0)
    if not shell_result.get("success", False):
        return shell_result
    
    raw_output = shell_result.get("output", "")
    extracted = _extract_between_markers(raw_output, marker_start, marker_end)
    
    if extracted is None:
        # If not found, check if it was an error or just a parsing failure
        # We check for error marker as a standalone line
        error_lines = raw_output.splitlines()
        if any(line.strip() == marker_error for line in error_lines):
            return {"success": False, "error": f"remote file is not readable or missing: {path}", "session_id": session.id}
        return {"success": False, "error": "failed to parse shell read payload (markers not found)", "session_id": session.id}

    try:
        payload_bytes = base64.b64decode(extracted, validate=False)
    except Exception as exc:
        return {"success": False, "error": f"failed to decode shell base64 payload: {exc}", "session_id": session.id}

    truncated = False
    if max_bytes is not None and len(payload_bytes) > max_bytes:
        payload_bytes = payload_bytes[:max_bytes]
        truncated = True

    return {
        "success": True,
        "method": "shell",
        "data": payload_bytes,
        "truncated": truncated,
    }


def _write_remote_file_bytes(
    session: SSHSession,
    path: str,
    payload_bytes: bytes,
) -> Dict[str, Any]:
    sftp = session.open_sftp()
    if sftp is not None:
        try:
            with sftp.file(path, "wb") as handle:
                handle.write(payload_bytes)
            return {"success": True, "method": "sftp"}
        except Exception as exc:
            log_error(f"sftp write failed, fallback shell: {exc}")
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    b64_payload = base64.b64encode(payload_bytes).decode("ascii")
    tmp_path = f"{path}.mcp_b64_{int(time.time() * 1000)}"
    chunk_size = 800
    chunks = [b64_payload[i : i + chunk_size] for i in range(0, len(b64_payload), chunk_size)]
    if not chunks:
        chunks = [""]

    first = _sync_shell(session, f"echo '{chunks[0]}' > '{tmp_path}'", timeout=30.0)
    if not first.get("success", False):
        return first

    for chunk in chunks[1:]:
        step = _sync_shell(session, f"echo '{chunk}' >> '{tmp_path}'", timeout=30.0)
        if not step.get("success", False):
            return step

    finish = _sync_shell(session, f"base64 -d '{tmp_path}' > '{path}' && rm '{tmp_path}'", timeout=30.0)
    if not finish.get("success", False):
        return finish
    return {"success": True, "method": "shell"}


def _slice_text_by_lines(text: str, offset_line: Optional[int], limit_lines: int) -> Dict[str, Any]:
    lines = text.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return {"text": "", "line_start": 1, "line_end": 0, "total_lines": 0}

    start_line = 1 if offset_line is None else offset_line
    if start_line < 0:
        start_line = total_lines + start_line + 1
    if start_line < 1:
        start_line = 1

    line_limit = clamp_int(limit_lines, DEFAULT_READ_MAX_LINES, 1, MAX_READ_MAX_LINES)
    if start_line > total_lines:
        return {"text": "", "line_start": start_line, "line_end": start_line - 1, "total_lines": total_lines}

    end_line = min(total_lines, start_line + line_limit - 1)
    window_text = "\n".join(lines[start_line - 1 : end_line])
    return {
        "text": window_text,
        "line_start": start_line,
        "line_end": end_line,
        "total_lines": total_lines,
    }


def file_dispatch(args: Dict[str, Any]) -> Dict[str, Any]:
    action = (args.get("action") or "").strip().lower()
    if action not in {"read", "write", "list", "upload", "download", "edit"}:
        return {"success": False, "error": "action must be one of: read, write, list, upload, download, edit"}

    path = (args.get("path", "") or "").strip()
    local_path = (args.get("local_path", "") or "").strip()
    content = args.get("content")
    is_base64 = to_bool(args.get("is_base64", False))
    session_id = args.get("session_id")

    session = session_from_args(session_id)
    if not session:
        return {"success": False, "error": "no session available"}

    # Normalize aliases.
    if action == "upload":
        action = "write"
    if action == "download":
        action = "read"

    if action == "list":
        target = path or "/"

        sftp = session.open_sftp()
        if sftp is not None:
            try:
                rows = []
                for entry in sftp.listdir_attr(target):
                    rows.append(
                        {
                            "name": entry.filename,
                            "size": entry.st_size,
                            "is_dir": bool(entry.st_mode & 0o40000),
                            "mtime": entry.st_mtime,
                        }
                    )
                return {"success": True, "action": "list", "path": target, "method": "sftp", "files": rows}
            except Exception as exc:
                log_error(f"sftp list failed, fallback shell: {exc}")
            finally:
                try:
                    sftp.close()
                except Exception:
                    pass

        shell_result = _sync_shell(session, f"ls -la '{target}'", timeout=30.0)
        if not shell_result.get("success", False):
            return shell_result
        return {
            "success": True,
            "action": "list",
            "path": target,
            "method": "shell",
            "listing": shell_result.get("output", ""),
        }

    if action == "read":
        if not path:
            return {"success": False, "error": "path is required for read"}

        if local_path:
            parent = os.path.dirname(local_path)
            if parent:
                os.makedirs(parent, exist_ok=True)

            read_result = _read_remote_file_bytes(session, path, max_bytes=None)
            if not read_result.get("success", False):
                return read_result
            payload_bytes = read_result["data"]
            with open(local_path, "wb") as handle:
                handle.write(payload_bytes)
            return {
                "success": True,
                "action": "read",
                "mode": "download",
                "path": path,
                "local_path": local_path,
                "method": read_result["method"],
                "size": len(payload_bytes),
                "sha256": _sha256_hex(payload_bytes),
            }

        offset_line = args.get("offset_line")
        if offset_line is not None:
            try:
                offset_line = int(offset_line)
            except Exception:
                return {"success": False, "error": "offset_line must be number"}

        limit_lines = args.get("limit_lines", DEFAULT_READ_MAX_LINES)
        try:
            limit_lines = int(limit_lines)
        except Exception:
            return {"success": False, "error": "limit_lines must be number"}

        max_chars = clamp_int(args.get("max_chars", DEFAULT_READ_MAX_CHARS), DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)
        max_bytes = clamp_int(
            args.get("max_bytes", DEFAULT_FILE_INSPECT_MAX_BYTES),
            DEFAULT_FILE_INSPECT_MAX_BYTES,
            1024,
            MAX_FILE_INSPECT_MAX_BYTES,
        )
        contains = args.get("contains")
        regex = args.get("regex")
        tail_lines = args.get("tail_lines")

        read_result = _read_remote_file_bytes(session, path, max_bytes=max_bytes)
        if not read_result.get("success", False):
            return read_result

        text = read_result["data"].decode("utf-8", errors="replace")
        window = _slice_text_by_lines(text, offset_line=offset_line, limit_lines=limit_lines)
        filtered = apply_text_filters(window["text"], contains=contains, regex=regex, tail_lines=tail_lines)
        if not filtered.get("success", False):
            return {"success": False, "error": filtered.get("error", "filtering error"), "session_id": session.id}

        inspect_text = filtered["output"]
        char_limited = False
        if len(inspect_text) > max_chars:
            inspect_text = inspect_text[:max_chars]
            char_limited = True

        return {
            "success": True,
            "action": "read",
            "mode": "inspect",
            "path": path,
            "method": read_result["method"],
            "content": inspect_text,
            "filtered": filtered["filtered"],
            "matched_lines": filtered["matched_lines"],
            "scanned_chars": filtered["scanned_chars"],
            "line_start": window["line_start"],
            "line_end": window["line_end"],
            "total_lines": window["total_lines"],
            "truncated": bool(read_result.get("truncated", False) or char_limited),
        }

    # write/upload
    if action == "edit":
        if not path:
            return {"success": False, "error": "path is required for edit"}
        edits = args.get("edits")
        if not isinstance(edits, list) or not edits:
            return {"success": False, "error": "edits must be a non-empty array"}

        dry_run = to_bool(args.get("dry_run", False))
        create_backup = to_bool(args.get("create_backup", False))
        edit_max_bytes = clamp_int(
            args.get("max_bytes", DEFAULT_FILE_EDIT_MAX_BYTES),
            DEFAULT_FILE_EDIT_MAX_BYTES,
            1024,
            MAX_FILE_EDIT_MAX_BYTES,
        )

        read_result = _read_remote_file_bytes(session, path, max_bytes=edit_max_bytes)
        if not read_result.get("success", False):
            return read_result
        if read_result.get("truncated", False):
            return {
                "success": False,
                "error": (
                    f"file is larger than edit max_bytes ({edit_max_bytes}). "
                    "Increase max_bytes or use command-based editing."
                ),
                "path": path,
                "session_id": session.id,
            }

        original_bytes = read_result["data"]
        original_text = original_bytes.decode("utf-8", errors="replace")
        updated_text = original_text
        total_replacements = 0

        for idx, edit in enumerate(edits):
            if not isinstance(edit, dict):
                return {"success": False, "error": f"edit at index {idx} must be an object"}

            old_text = edit.get("old_text")
            if old_text is None:
                return {"success": False, "error": f"edit at index {idx} must include old_text"}
            old_text = str(old_text)
            if old_text == "":
                return {"success": False, "error": f"edit at index {idx} has empty old_text"}

            new_text = str(edit.get("new_text", ""))
            replace_all = to_bool(edit.get("replace_all", False))
            occurrences = updated_text.count(old_text)
            if occurrences == 0:
                return {"success": False, "error": f"old_text not found for edit at index {idx}"}
            if not replace_all and occurrences != 1:
                return {
                    "success": False,
                    "error": (
                        f"ambiguous old_text for edit at index {idx}: found {occurrences} occurrences. "
                        "Set replace_all=true or provide a more specific old_text."
                    ),
                }

            if replace_all:
                updated_text = updated_text.replace(old_text, new_text)
                total_replacements += occurrences
            else:
                updated_text = updated_text.replace(old_text, new_text, 1)
                total_replacements += 1

        updated_bytes = updated_text.encode("utf-8")
        changed = updated_bytes != original_bytes
        old_sha256 = _sha256_hex(original_bytes)
        new_sha256 = _sha256_hex(updated_bytes)

        result_payload = {
            "success": True,
            "action": "edit",
            "mode": "edit",
            "path": path,
            "changed": changed,
            "replacements": total_replacements,
            "dry_run": dry_run,
            "old_sha256": old_sha256,
            "new_sha256": new_sha256,
            "size": len(updated_bytes),
        }

        if dry_run or not changed:
            result_payload["method"] = read_result["method"]
            return result_payload

        if create_backup:
            backup_path = f"{path}.mcp.bak"
            backup_result = _write_remote_file_bytes(session, backup_path, original_bytes)
            if not backup_result.get("success", False):
                return {
                    "success": False,
                    "error": f"failed to create backup at {backup_path}: {backup_result.get('error', 'unknown error')}",
                    "path": path,
                    "session_id": session.id,
                }
            result_payload["backup_path"] = backup_path

        write_result = _write_remote_file_bytes(session, path, updated_bytes)
        if not write_result.get("success", False):
            return write_result
        result_payload["method"] = write_result["method"]
        return result_payload

    if not path:
        return {"success": False, "error": "path is required for write"}
    payload_bytes: bytes
    source: str
    if local_path:
        if not os.path.isfile(local_path):
            return {"success": False, "error": f"local_path not found: {local_path}"}
        with open(local_path, "rb") as handle:
            payload_bytes = handle.read()
        source = "local_path"
    else:
        if content is None:
            return {
                "success": False,
                "error": "for write/upload provide local_path or inline content",
            }
        try:
            payload_bytes = base64.b64decode(str(content)) if is_base64 else str(content).encode("utf-8")
        except Exception as exc:
            return {"success": False, "error": f"failed to decode inline content: {exc}"}
        if len(payload_bytes) > MAX_INLINE_WRITE_BYTES:
            return {
                "success": False,
                "error": (
                    f"inline content too large ({len(payload_bytes)} bytes). "
                    f"Use local_path for files larger than {MAX_INLINE_WRITE_BYTES} bytes."
                ),
            }
        source = "inline_content"

    write_result = _write_remote_file_bytes(session, path, payload_bytes)
    if not write_result.get("success", False):
        return write_result

    return {
        "success": True,
        "action": "write",
        "path": path,
        "local_path": local_path,
        "source": source,
        "method": write_result["method"],
        "size": len(payload_bytes),
        "sha256": _sha256_hex(payload_bytes),
    }


def tools_list() -> Dict[str, Any]:
    session_id_param = {
        "type": "number",
        "description": "Optional session id. If omitted, current session is used.",
    }

    tools = [
        {
            "name": "session_list",
            "description": (
                "List sessions. Always returns id + status (idle|busy|broken). "
                "Status is tracked continuously by MCP server, independent from agent polling. "
                "Each row also has current/is_current marker. "
                "Optional flags can include session name and/or last command."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_name": {
                        "type": "boolean",
                        "description": "Optional. Include session name in listing.",
                    },
                    "include_last_command": {
                        "type": "boolean",
                        "description": "Optional. Include last launched command in listing.",
                    },
                    "include_active_ids": {
                        "type": "boolean",
                        "description": "Optional. Include active_run_id and active_pipeline_id for debugging.",
                    },
                },
            },
        },
        {
            "name": "session_close",
            "description": "Close and remove a session by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": {"type": "number", "description": "Session id to close."}},
                "required": ["session_id"],
            },
        },
        {
            "name": "session_update",
            "description": "Update session properties: rename and/or set current.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "number", "description": "Session id to update."},
                    "name": {"type": "string", "description": "New name."},
                    "make_current": {"type": "boolean", "description": "Set this session as current."},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "run",
            "description": (
                "Unified command execution. "
                "CRITICAL: Set shell=true for Linux/Bash commands (ls, cat, grep, etc) or to use &&/|| operators. "
                "Required to access full Linux shell on devices like Keenetic routers. "
                "Returns compact happy-path payload by default. "
                "Default behavior: run in CURRENT session if session_id is not provided. "
                "Supports sync/async/stream mode, anti-hang wait_timeout, optional hard_timeout. "
                "If wait timeout triggers, returns partial output and still_running=true. "
                "Status: running, completed, completed_nonzero, hard_timeout, failed, dead."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute. Use shell=true for Linux commands."},
                    "mode": {
                        "type": "string",
                        "description": "sync (default), async, or stream.",
                        "enum": ["sync", "async", "stream"],
                    },
                    "shell": {
                        "type": "boolean",
                        "description": "Set true for Linux/Bash commands (ls, grep, etc) or if using &&/||. Required for Keenetic shell access.",
                    },
                    "wait_timeout": {
                        "type": "number",
                        "description": "Max seconds to wait in this MCP call before returning partial output. Clamped to max.",
                    },
                    "startup_wait": {
                        "type": "number",
                        "description": "For async/stream: short initial wait before returning first chunk.",
                    },
                    "hard_timeout": {
                        "type": "number",
                        "description": "Optional max command lifetime. 0 disables hard timeout.",
                    },
                    "completion_hint": {
                        "type": "string",
                        "enum": ["prompt", "quiet", "either"],
                        "description": "How to detect completion in sync mode. Default either.",
                    },
                    "quiet_complete_timeout": {
                        "type": "number",
                        "description": "Quiet period in seconds for quiet completion fallback in sync mode.",
                    },
                    "session_id": session_id_param,
                    "new_session": {
                        "type": "boolean",
                        "description": "Create a new session and run there immediately.",
                    },
                    "session_name": {
                        "type": "string",
                        "description": "Optional name for new session (new_session=true) or auto-recovery session.",
                    },
                },
                "required": ["command"],
            },
        },
        {
            "name": "run_pipeline",
            "description": (
                "Binary-safe cross-machine pipeline. "
                "Best for large files or binary data transfer. "
                "Always uses system shell for execution."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Remote command to execute."},
                    "mode": {"type": "string", "enum": ["sync", "async"], "description": "sync (default) or async."},
                    "wait_timeout": {
                        "type": "number",
                        "description": "Max wait for this MCP call before returning partial status.",
                    },
                    "startup_wait": {
                        "type": "number",
                        "description": "For async mode: short initial wait before first status return.",
                    },
                    "hard_timeout": {"type": "number", "description": "Optional hard stop timeout in seconds."},
                    "local_stdout_path": {
                        "type": "string",
                        "description": "Local file path to write remote stdout bytes (binary-safe).",
                    },
                    "local_stdin_path": {
                        "type": "string",
                        "description": "Local file path to feed as remote stdin bytes (binary-safe).",
                    },
                    "append_stdout": {
                        "type": "boolean",
                        "description": "Append to local_stdout_path instead of overwrite.",
                    },
                    "include_stderr": {
                        "type": "boolean",
                        "description": "Also write remote stderr bytes into local_stdout_path.",
                    },
                    "session_id": session_id_param,
                    "new_session": {"type": "boolean", "description": "Create new session for this pipeline."},
                    "session_name": {"type": "string", "description": "Optional name for new/recovery session."},
                },
                "required": ["command"],
            },
        },
        {
            "name": "pipeline_status",
            "description": (
                "Check status of run_pipeline and read text preview. "
                "Use until written_complete=true. "
                "Returns compact payload; use last_command_details only for deep debugging. "
                "Supports server-side filters for token savings."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                    "pipeline_id": {"type": "number", "description": "Optional specific pipeline id."},
                    "offset": {"type": "number", "description": "Preview offset for pagination."},
                    "max_chars": {"type": "number", "description": "Max preview chars to return."},
                    "contains": {
                        "type": "string",
                        "description": "Optional substring filter. Use ONLY if remote 'grep' is unavailable; otherwise, prefer filtering on device (e.g. 'cat | grep') for efficiency.",
                    },
                    "regex": {
                        "type": "string",
                        "description": "Optional regex filter. Use ONLY if remote 'grep' is unavailable.",
                    },
                    "tail_lines": {"type": "number", "description": "Optional keep only last N lines after filtering."},
                    "level": {"type": "string", "description": "Reserved/no-op now."},
                    "kind": {"type": "string", "description": "Reserved/no-op now."},
                },
            },
        },
        {
            "name": "read",
            "description": (
                "Read buffered output for a run (or current active/last run). "
                "Supports offset pagination and returns next_offset. "
                "Returns compact payload; use last_command_details only for deep debugging. "
                "Supports server-side filters for token savings."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                    "run_id": {"type": "number", "description": "Optional specific run id."},
                    "offset": {
                        "type": "number",
                        "description": "Optional absolute offset. If omitted, server shared cursor is used.",
                    },
                    "max_lines": {"type": "number", "description": "Max lines per read page."},
                    "max_chars": {"type": "number", "description": "Max chars per read page."},
                    "contains": {
                        "type": "string",
                        "description": "Optional substring filter. Use ONLY if remote 'grep' is unavailable; otherwise, prefer filtering on device (e.g. 'cat | grep') for efficiency.",
                    },
                    "regex": {
                        "type": "string",
                        "description": "Optional regex filter. Use ONLY if remote 'grep' is unavailable.",
                    },
                    "tail_lines": {"type": "number", "description": "Optional keep only last N lines after filtering."},
                    "level": {"type": "string", "description": "Reserved/no-op now."},
                    "kind": {"type": "string", "description": "Reserved/no-op now."},
                },
            },
        },
        {
            "name": "signal",
            "description": "Send ctrl_c or stdin to a session/run.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                    "action": {"type": "string", "enum": ["ctrl_c", "stdin"]},
                    "text": {"type": "string", "description": "Text for stdin action."},
                    "press_enter": {"type": "boolean", "description": "Append Enter for stdin action. Default true."},
                },
            },
        },
        {
            "name": "last_command_details",
            "description": (
                "Return full verbose payload of the last tool call result (per session if possible). "
                "Use only for debugging or ambiguous outcomes; do NOT call routinely in happy path."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                },
            },
        },
        {
            "name": "file",
            "description": (
                "Unified file operation tool (list, read/download, write/upload, edit). "
                "Works in any environment, including restricted shells. "
                "Tries SFTP first, falls back to shell commands if needed. "
                "read/download: with local_path -> save remote file locally (metadata only); without local_path -> inspect text content with optional line window and filters. "
                "write/upload: use local_path for full files or inline content for small files. "
                "edit: in-place text replace operations for existing remote text files."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["read", "write", "list", "upload", "download", "edit"]},
                    "path": {"type": "string", "description": "Remote path."},
                    "local_path": {
                        "type": "string",
                        "description": (
                            "Local file path for side-effect transfer. "
                            "For read/download: destination local path. "
                            "For write/upload: source local path."
                        ),
                    },
                    "content": {
                        "type": "string",
                        "description": (
                            "Optional inline content for small write/upload operations when local_path is not provided."
                        ),
                    },
                    "is_base64": {
                        "type": "boolean",
                        "description": "Optional. If true, inline content is base64-decoded before write/upload.",
                    },
                    "offset_line": {
                        "type": "number",
                        "description": "Optional line offset for read inspect mode. 1-based; negative values count from file end.",
                    },
                    "limit_lines": {
                        "type": "number",
                        "description": "Optional max lines for read inspect mode window.",
                    },
                    "max_chars": {
                        "type": "number",
                        "description": "Optional max characters in read inspect response.",
                    },
                    "max_bytes": {
                        "type": "number",
                        "description": "Optional max bytes to read from remote file for inspect/edit safeguards.",
                    },
                    "contains": {
                        "type": "string",
                        "description": "Optional substring filter for read inspect mode.",
                    },
                    "regex": {
                        "type": "string",
                        "description": "Optional regex filter for read inspect mode.",
                    },
                    "tail_lines": {
                        "type": "number",
                        "description": "Optional keep only last N lines in read inspect mode.",
                    },
                    "edits": {
                        "type": "array",
                        "description": "For edit action: list of text replacements. Each item: old_text, new_text, optional replace_all.",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "For edit action: preview metadata without writing remote file.",
                    },
                    "create_backup": {
                        "type": "boolean",
                        "description": "For edit action: save original file to <path>.mcp.bak before write.",
                    },
                    "session_id": session_id_param,
                },
                "required": ["action"],
            },
        },
    ]
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}


def handle_request(request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if manager is None:
        return make_response(request.get("id", 1), {"success": False, "error": "session manager is not initialized"})
    method = request.get("method")
    params = request.get("params", {})
    req_id = request.get("id", 1)

    if method == "initialize":
        manager.ensure_session()
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ssh-mcp-vnext", "version": "5.4.0"},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        response = tools_list()
        response["id"] = req_id
        return response

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}
        try:
            if tool_name == "session_list":
                result = manager.list_sessions(
                    include_name=to_bool(args.get("include_name", False)),
                    include_last_command=to_bool(args.get("include_last_command", False)),
                    include_active_ids=to_bool(args.get("include_active_ids", False)),
                )

            elif tool_name == "session_close":
                sid = clamp_int(args.get("session_id"), 0, 1, 10**9)
                result = manager.close_session(sid)

            elif tool_name == "session_update":
                sid = clamp_int(args.get("session_id"), 0, 1, 10**9)
                if sid <= 0:
                    result = {"success": False, "error": "session_id is required"}
                else:
                    has_name = "name" in args
                    has_current = "make_current" in args
                    if not has_name and not has_current:
                        result = {"success": False, "error": "Provide at least one field: name or make_current"}
                    else:
                        result = manager.update_session(
                            session_id=sid,
                            name=args.get("name") if has_name else None,
                            make_current=to_bool(args.get("make_current")) if has_current else None,
                        )

            elif tool_name == "run" or tool_name == "exec":
                result = run_dispatch(args)

            elif tool_name == "run_pipeline":
                result = run_pipeline_dispatch(args)

            elif tool_name == "pipeline_status":
                result = pipeline_status_dispatch(args)

            elif tool_name == "read":
                result = read_dispatch(args)

            elif tool_name == "signal":
                result = signal_dispatch(args)

            elif tool_name == "last_command_details":
                result = last_command_details_dispatch(args)

            elif tool_name == "file":
                result = file_dispatch(args)

            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
                }

            if tool_name != "last_command_details":
                manager.record_tool_result(tool_name=str(tool_name), args=args, result=result)
            projected = project_tool_result(tool_name=str(tool_name), result=result)
            return make_response(req_id, projected)
        except Exception as exc:
            log_error(f"tool execution error ({tool_name}): {exc}")
            return make_response(req_id, {"success": False, "error": str(exc)})

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


def main() -> None:
    global SSH_HOST, SSH_USER, SSH_PASSWORD, SSH_PORT, EXTRA_PATH
    global PROJECT_ROOT, PROJECT_TAG, CACHE_DIRS, manager

    parser = argparse.ArgumentParser(
        description="SSH MCP Server (compact tools, anti-hang timeout, background output buffering)"
    )
    parser.add_argument("--host", required=True, help="SSH host")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", required=True, help="SSH password")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--path", help="Additional PATH to export in shell")
    parser.add_argument(
        "--project-root",
        help="Project root for local state (default: current working directory at server start)",
    )
    parser.add_argument(
        "--cache-dir",
        help=(
            "Optional cache root override. "
            "If set, server uses <cache-dir>/<project-tag-hash>/... to avoid mixing projects."
        ),
    )
    args = parser.parse_args()

    SSH_HOST = args.host
    SSH_USER = args.user
    SSH_PASSWORD = args.password
    SSH_PORT = args.port
    EXTRA_PATH = args.path

    runtime_paths = resolve_runtime_paths(project_root_arg=args.project_root, cache_dir_arg=args.cache_dir)
    PROJECT_ROOT = runtime_paths["project_root"]
    PROJECT_TAG = runtime_paths["project_tag"]
    CACHE_DIRS = make_cache_dirs(runtime_paths["cache_root"])
    manager = SessionManager(CACHE_DIRS, PROJECT_TAG)

    log_error(
        f"SSH MCP started for {SSH_HOST}:{SSH_PORT}. "
        f"project_root={PROJECT_ROOT} cache={CACHE_DIRS['cache_root']}"
    )

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            response = handle_request(json.loads(line))
            if response is not None:
                print(json.dumps(response), flush=True)
        except json.JSONDecodeError as exc:
            log_error(f"invalid json: {exc}")
        except Exception as exc:
            log_error(f"unexpected error: {exc}")

    log_error("shutting down...")
    if manager is not None:
        manager.close_all()


if __name__ == "__main__":
    main()
