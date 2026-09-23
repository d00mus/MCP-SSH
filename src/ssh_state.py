import time
import threading
import codecs
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from src.utils import log_error, iso_now, json_line, clean_output


class CharAccount:
    """Process-wide accounting of buffered output chars (F7).

    Replaces the old 250 ms cached sum: `total` is exact and updated on every buffer
    mutation, so `can_accept_more_buffer` never decides on stale data and the
    scrollback buffers are counted too.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._total = 0

    @property
    def total(self) -> int:
        with self._lock:
            return self._total

    def add(self, n: int) -> None:
        if n:
            with self._lock:
                self._total += n

    def sub(self, n: int) -> None:
        if n:
            with self._lock:
                self._total = max(0, self._total - n)


CHARS_ACCOUNT = CharAccount()


class ChunkBuffer:
    """Bounded chunk store with O(1) append and head-drop (F7).

    Replaces the `text += chunk` / `text[overflow:]` pattern which copied the WHOLE
    buffer for every chunk once full (quadratic CPU and allocation on long output).
    Offsets are absolute: head-drops move `base_offset` forward so callers can keep
    absolute cursors across trims.
    """

    def __init__(self, max_chars: int = 0, account: Optional[CharAccount] = None) -> None:
        self.max_chars = max_chars
        self.account = account
        self._chunks: deque = deque()
        self._len = 0
        self.base_offset = 0

    def __len__(self) -> int:
        return self._len

    def _account_delta(self, delta: int) -> None:
        if self.account is not None:
            if delta >= 0:
                self.account.add(delta)
            else:
                self.account.sub(-delta)

    def append(self, chunk: str) -> int:
        """Append text, trimming from the head to max_chars. Returns chars dropped."""
        if not chunk:
            return 0
        self._chunks.append(chunk)
        self._len += len(chunk)
        self._account_delta(len(chunk))
        overflow = (self._len - self.max_chars) if self.max_chars > 0 else 0
        return self.drop(overflow) if overflow > 0 else 0

    def replace(self, text: str) -> None:
        """Whole-buffer replacement (compat with direct `buf = ...` assignments)."""
        delta = len(text) - self._len
        self._chunks = deque([text]) if text else deque()
        self._len = len(text)
        self._account_delta(delta)

    def drop(self, count: int) -> int:
        """Drop up to `count` chars from the head; returns how many were dropped."""
        want = max(0, count)
        remaining = want
        while remaining > 0 and self._chunks:
            chunk = self._chunks[0]
            if len(chunk) <= remaining:
                remaining -= len(chunk)
                self._len -= len(chunk)
                self._chunks.popleft()
            else:
                self._chunks[0] = chunk[remaining:]
                self._len -= remaining
                remaining = 0
        dropped = want - remaining
        self.base_offset += dropped
        self._account_delta(-dropped)
        return dropped

    def clear(self) -> int:
        """Drop everything; base_offset advances so absolute cursors stay valid."""
        dropped = self._len
        self._chunks.clear()
        self._len = 0
        self.base_offset += dropped
        self._account_delta(-dropped)
        return dropped

    def text(self) -> str:
        return "".join(self._chunks)

    def window(self, relative_offset: int, max_chars: int) -> str:
        """Materialise at most max_chars chars starting at relative_offset (0 = head)."""
        skip = max(0, relative_offset)
        room = max(0, max_chars)
        parts = []
        taken = 0
        for chunk in self._chunks:
            if taken >= room:
                break
            if skip >= len(chunk):
                skip -= len(chunk)
                continue
            piece = chunk[skip:] if skip else chunk
            skip = 0
            if len(piece) > room - taken:
                piece = piece[: room - taken]
            parts.append(piece)
            taken += len(piece)
        return "".join(parts)

    def tail(self, n: int) -> str:
        """Last n chars without materialising the whole buffer."""
        if n <= 0:
            return ""
        parts = []
        taken = 0
        for chunk in reversed(self._chunks):
            if taken >= n:
                break
            need = n - taken
            piece = chunk[-need:] if need < len(chunk) else chunk
            parts.append(piece)
            taken += len(piece)
        return "".join(reversed(parts))


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
    # JSON-RPC id of the request that started this run (notifications/cancelled).
    req_id: Optional[Any] = None

    lock: threading.Lock = field(default_factory=threading.Lock)
    done_event: threading.Event = field(default_factory=threading.Event)
    status: str = "running"
    finish_reason: str = ""
    finished_at: Optional[float] = None
    error: str = ""
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

    def __post_init__(self) -> None:
        self._buf = ChunkBuffer(self.max_buffer_chars, account=CHARS_ACCOUNT)

    # Compat surface: tests and callers assign `run.output_buffer = ...` and adjust
    # `buffer_base_offset` directly. Properties are lock-free on purpose (some of
    # those callers already hold self.lock); the mutating methods below lock.
    @property
    def output_buffer(self) -> str:
        return self._buf.text()

    @output_buffer.setter
    def output_buffer(self, text: str) -> None:
        self._buf.replace(text or "")

    @property
    def buffer_base_offset(self) -> int:
        return self._buf.base_offset

    @buffer_base_offset.setter
    def buffer_base_offset(self, value: int) -> None:
        self._buf.base_offset = value

    @property
    def buffer_len(self) -> int:
        return len(self._buf)

    def tail_locked(self, n: int) -> str:
        """Last n chars of the buffer. Caller must hold self.lock (or accept a race)."""
        return self._buf.tail(n)

    def discard_all_output(self) -> int:
        """Drop buffered output and advance base_offset. Caller must hold self.lock
        (or accept a benign race) - eviction and cleanup already do."""
        dropped = self._buf.clear()
        if self.shared_cursor < self._buf.base_offset:
            self.shared_cursor = self._buf.base_offset
        return dropped

    def append_output(self, chunk: str) -> None:
        if not chunk:
            return
        with self.lock:
            self._buf.append(chunk)
            self.total_received_chars += len(chunk)
            self.last_data_at = time.time()
            self.quiet_event.clear()
            if self.shared_cursor < self._buf.base_offset:
                self.shared_cursor = self._buf.base_offset

    def discard_through(self, next_offset: int) -> None:
        """Drop the prefix the client has already been given. The unread tail stays."""
        with self.lock:
            if next_offset <= self._buf.base_offset:
                return
            self._buf.drop(min(next_offset - self._buf.base_offset, len(self._buf)))

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
            available = max(0, len(self._buf) - relative)
            char_cap = max(1, max_chars)
            limited = available > char_cap
            data = self._buf.window(relative, char_cap)

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
