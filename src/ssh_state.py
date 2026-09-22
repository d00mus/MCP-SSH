import time
import threading
import codecs
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from src.utils import log_error, iso_now, json_line, clean_output


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

    exec_channel: Optional[Any] = None
    exec_stdin: Optional[Any] = None
    exec_stdin_closed: bool = False
    exec_stdout: Optional[Any] = None
    exec_stderr: Optional[Any] = None
    exit_status: Optional[int] = None

    def append_output(self, chunk: str) -> None:
        if not chunk:
            return
        with self.lock:
            self.output_buffer += chunk
            self.total_received_chars += len(chunk)
            self.last_data_at = time.time()
            self.quiet_event.clear()

            overflow = len(self.output_buffer) - self.max_buffer_chars
            if overflow > 0:
                self.output_buffer = self.output_buffer[overflow:]
                self.buffer_base_offset += overflow
            if self.shared_cursor < self.buffer_base_offset:
                self.shared_cursor = self.buffer_base_offset

    def discard_through(self, next_offset: int) -> None:
        """Drop the prefix the client has already been given. The unread tail stays."""
        with self.lock:
            if next_offset <= self.buffer_base_offset:
                return
            drop = min(next_offset - self.buffer_base_offset, len(self.output_buffer))
            self.output_buffer = self.output_buffer[drop:]
            self.buffer_base_offset += drop

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

        try:
            json_line(self.run_log_path, {
                "ts": iso_now(),
                "dir": "SYS",
                "event": "run_done",
                "run_id": self.run_id,
                "status": status,
                "reason": reason,
                "error": error,
                "completion_method": completion_method,
                "exit_status": self.exit_status,
                "finished_at": self.finished_at,
            })
        except Exception as e:
            log_error(f"run_done log write failed: {e}")

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

            base_offset = self.buffer_base_offset
            status = self.status
            done_set = self.done_event.is_set()
            finish_reason = self.finish_reason
            error = self.error
            total_received_chars = self.total_received_chars
            recv_paused = self.recv_paused
            pause_reason = self.pause_reason
            completion_method = self.completion_method

        # clean_output outside lock to prevent blocking writer threads during large buffer reads
        cleaned_output = clean_output(data)

        return {
            "offset_start": offset,
            "next_offset": next_offset,
            "base_offset": base_offset,
            "output": cleaned_output,
            "limited": limited,
            "dropped_data": dropped_data,
            "status": status,
            "still_running": not done_set,
            "output_complete": done_set,
            "finish_reason": finish_reason,
            "error": error,
            "total_received_chars": total_received_chars,
            "recv_paused": recv_paused,
            "pause_reason": pause_reason,
            "completion_method": completion_method,
        }
