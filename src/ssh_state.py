import time
import re
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from src.utils import log_error, iso_now, json_line, StreamCleaner


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

    def truncate_tail(self, count: int) -> int:
        """Drop up to count chars from the tail."""
        want = max(0, count)
        remaining = want
        while remaining > 0 and self._chunks:
            chunk = self._chunks[-1]
            if len(chunk) <= remaining:
                remaining -= len(chunk)
                self._len -= len(chunk)
                self._chunks.pop()
            else:
                self._chunks[-1] = chunk[:-remaining]
                self._len -= remaining
                remaining = 0
        dropped = want - remaining
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


DEFAULT_MAX_LINE_CHARS = 1024


def count_virtual_lines(text: str, start: int = 0, end: Optional[int] = None, max_line_chars: int = DEFAULT_MAX_LINE_CHARS) -> int:
    """Count lines in text[start:end], where a line ends with '\\n' or every max_line_chars chars without '\\n'."""
    if end is None:
        end = len(text)
    pos = max(0, start)
    total = 0
    while pos < end:
        next_nl = text.find("\n", pos, end)
        if next_nl == -1:
            remaining = end - pos
            total += (remaining + max_line_chars - 1) // max_line_chars
            break
        dist = next_nl - pos
        chunks = dist // max_line_chars
        total += chunks + 1
        pos = next_nl + 1
    return total


def find_line_offset(text: str, target_line: int, max_line_chars: int = DEFAULT_MAX_LINE_CHARS) -> int:
    """Find the character offset where target_line (0-indexed) starts."""
    if target_line <= 0:
        return 0
    pos = 0
    end = len(text)
    lines_counted = 0
    while pos < end and lines_counted < target_line:
        next_nl = text.find("\n", pos, end)
        if next_nl == -1:
            remaining = end - pos
            needed = target_line - lines_counted
            chunks = needed * max_line_chars
            if chunks >= remaining:
                return end
            return pos + chunks
        dist = next_nl - pos
        chunks = dist // max_line_chars
        if lines_counted + chunks >= target_line:
            needed = target_line - lines_counted
            return pos + needed * max_line_chars
        lines_counted += chunks + 1
        pos = next_nl + 1
    return pos


def slice_virtual_lines(text: str, start_offset: int = 0, limit_lines: int = 200, max_line_chars: int = DEFAULT_MAX_LINE_CHARS) -> tuple[str, int]:
    """Slice up to limit_lines starting at start_offset. Returns (sliced_text, next_char_offset)."""
    start_pos = max(0, start_offset)
    end = len(text)
    if start_pos >= end or limit_lines <= 0:
        return "", start_pos

    pos = start_pos
    lines_counted = 0
    while pos < end and lines_counted < limit_lines:
        next_nl = text.find("\n", pos, end)
        if next_nl == -1:
            remaining = end - pos
            needed = limit_lines - lines_counted
            max_can_take = needed * max_line_chars
            if remaining <= max_can_take:
                pos = end
            else:
                pos += max_can_take
            break
        dist = next_nl - pos
        needed = limit_lines - lines_counted
        chunks = dist // max_line_chars
        if chunks >= needed:
            pos += needed * max_line_chars
            break
        lines_counted += chunks + 1
        pos = next_nl + 1

    return text[start_pos:pos], pos


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
    # Gateway maintenance (fs.py helpers, internal=True in run_command): its output
    # lives in this run's own buffer, which the helper's caller parses, and is kept
    # out of the session tab canvas - the one stream the agent reads.
    internal: bool = False

    lock: threading.Lock = field(default_factory=threading.Lock)
    done_event: threading.Event = field(default_factory=threading.Event)
    status: str = "running"
    finish_reason: str = ""
    finished_at: Optional[float] = None
    error: str = ""
    # Absolute offset (in this run's own cleaned buffer space) already copied into
    # the session tab canvas. The tab is the single unread stream: reads page over
    # the canvas, so a run keeps no read cursor of its own (m01215).
    mirrored_upto: int = 0
    total_received_chars: int = 0
    last_data_at: float = field(default_factory=time.time)
    prompt_detected: bool = False
    interrupt_sent: bool = False
    recv_paused: bool = False
    pause_reason: str = ""
    completion_method: str = ""
    last_stdin_at: Optional[float] = None
    quiet_event: threading.Event = field(default_factory=threading.Event)
    _cleaner: StreamCleaner = field(default_factory=StreamCleaner)
    # PTY runs only: drops the remote shell's echo of the command we typed, so the
    # canvas (the agent's single unread stream) carries the command exactly once,
    # as the synthetic "$ <command>" line (FIX-3). None means no filtering.
    echo_filter: Optional[Any] = None

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
        cleaner = StreamCleaner()
        cleaned = cleaner.feed(text or "") + cleaner.finalize()
        self._buf.replace(cleaned)

    @property
    def buffer_base_offset(self) -> int:
        return self._buf.base_offset

    @buffer_base_offset.setter
    def buffer_base_offset(self, value: int) -> None:
        self._buf.base_offset = value

    @property
    def buffer_len(self) -> int:
        return len(self._buf)

    def output_end(self) -> int:
        """Absolute offset just past the buffered output (lock-free snapshot:
        readers use it to notice new data without taking self.lock)."""
        return self._buf.base_offset + len(self._buf)

    def tail_locked(self, n: int) -> str:
        """Last n chars of the buffer. Caller must hold self.lock (or accept a race)."""
        return self._buf.tail(n)

    def discard_all_output(self) -> int:
        """Drop buffered output and advance base_offset. Caller must hold self.lock
        (or accept a benign race) - eviction and cleanup already do."""
        return self._buf.clear()

    def append_output(self, chunk: str) -> int:
        """Store one cleaned chunk and return the buffer end offset it produced.

        The caller hands that offset back to the session canvas, which mirrors the
        same chunk: recording the exact end (not the end at some later moment) keeps
        the mirror honest when a second channel appends in between (m01215)."""
        if not chunk:
            return self.output_end()
        with self.lock:
            self.total_received_chars += len(chunk)
            self.last_data_at = time.time()
            self.quiet_event.clear()
            cleaned = self._cleaner.feed(chunk)
            if not cleaned:
                return self.output_end()
            self._buf.append(cleaned)
            return self.output_end()

    def canvas_chunk(self, chunk: str) -> str:
        """The part of one raw chunk that belongs in the session tab canvas.

        The run buffer keeps the raw text (the marker parser reads it); the canvas
        gets the agent's view, without the shell's duplicate of the command (FIX-3)."""
        if self.echo_filter is None:
            return chunk
        return self.echo_filter.feed(chunk)

    def flush_canvas_echo(self) -> str:
        """Release text a finished run's echo filter still held back (may be empty)."""
        if self.echo_filter is None:
            return ""
        return self.echo_filter.flush()

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
            final_tail = self._cleaner.finalize()
            if final_tail:
                self._buf.append(final_tail)
            # Strip trailing exit marker from buffer tail if present
            exit_token = getattr(self, "exit_marker_token", None)
            if exit_token:
                tail_str = self._buf.tail(500)
                m = re.search(rf"\n?__MCP_EC_{re.escape(exit_token)}_\d+\s*$", tail_str)
                if m:
                    drop_len = len(tail_str) - m.start()
                    self._buf.truncate_tail(drop_len)

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
            self.last_stdin_at = time.time()

