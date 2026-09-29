"""Text stream primitives shared by every session.

- ``ChunkBuffer``: bounded text store with absolute offsets.
- ``StreamCleaner``: turns raw terminal bytes-as-text into plain text, chunk by chunk.
- ``Canvas``: the one stream an agent reads. It behaves like a console you can scroll:
  a single unread position, measured in lines, plus peeking at history.
"""

import re
import threading
from collections import deque
from dataclasses import dataclass
from typing import Callable, Deque, Optional, Tuple

# CSI, OSC (BEL or ST terminated), DCS/SOS/PM/APC (ST terminated) and the generic
# ECMA-35 escape ESC [intermediates 0x20-0x2F]* final(0x30-0x7E). The last form also
# covers two-byte sequences such as ESC 7, ESC = and ESC ( B.
ANSI_ESCAPE = re.compile(
    r"\x1B(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|[PX^_][^\x1b]*(?:\x1b\\)?"
    r"|[\x20-\x2f]*[\x30-\x7e]"
    r")"
)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
CARRIAGE_RETURNS_BEFORE_NEWLINE = re.compile(r"\r+\n")

# A line longer than this is delivered in pieces of this size.
MAX_LINE_CHARS = 1024


class ChunkBuffer:
    """Bounded text store: O(1) append, head drop when full, absolute offsets.

    ``base_offset`` is the stream position of the first buffered character, so a
    reader can keep an absolute cursor across trims.
    """

    def __init__(self, max_chars: int = 0) -> None:
        self.max_chars = max_chars
        self._chunks: Deque[str] = deque()
        self._len = 0
        self._joined: Optional[str] = ""
        self.base_offset = 0

    def __len__(self) -> int:
        return self._len

    def append(self, chunk: str) -> int:
        """Append text; returns how many characters were dropped from the head."""
        if not chunk:
            return 0
        self._chunks.append(chunk)
        self._len += len(chunk)
        self._joined = None
        overflow = self._len - self.max_chars if self.max_chars > 0 else 0
        return self.drop(overflow) if overflow > 0 else 0

    def drop(self, count: int) -> int:
        """Drop up to ``count`` characters from the head; returns how many went."""
        remaining = max(0, count)
        wanted = remaining
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
        dropped = wanted - remaining
        self.base_offset += dropped
        if dropped:
            self._joined = None
        return dropped

    def clear(self) -> int:
        """Drop everything; the offset advances so absolute cursors stay valid."""
        dropped = self._len
        self._chunks.clear()
        self._len = 0
        self._joined = ""
        self.base_offset += dropped
        return dropped

    def truncate_tail(self, count: int) -> int:
        """Drop up to ``count`` characters from the end."""
        remaining = max(0, count)
        wanted = remaining
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
        dropped = wanted - remaining
        if dropped:
            self._joined = None
        return dropped

    def text(self) -> str:
        if self._joined is None:
            self._joined = "".join(self._chunks)
            self._chunks = deque([self._joined]) if self._joined else deque()
        return self._joined

    def tail(self, n: int) -> str:
        """Last ``n`` characters without joining the whole buffer."""
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

    def open_line(self) -> str:
        """The text after the last newline: the line still being written."""
        parts = []
        for chunk in reversed(self._chunks):
            cut = chunk.rfind("\n")
            parts.append(chunk[cut + 1:])
            if cut != -1:
                break
        return "".join(reversed(parts))


# ---------------------------------------------------------------------------
# Terminal text cleaning
# ---------------------------------------------------------------------------

# A fragment held back by StreamCleaner must be a strict prefix of a real escape
# sequence, otherwise a stray ESC would mute the stream for good.
_PARTIAL_CSI = re.compile(r"^\x1b\[[0-?]*[ -/]*$")
_PARTIAL_STR = re.compile(r"^\x1b(?:\][^\x07\x1b]*|[PX^_][^\x1b]*)(?:\x1b)?$")
_PARTIAL_DESIGNATOR = re.compile(r"^\x1b[\x20-\x2f]*$")
# An unterminated OSC/DCS payload is flushed instead of held past this size.
_MAX_PENDING_ESCAPE = 4096


def _is_partial_escape(tail: str) -> bool:
    if len(tail) > _MAX_PENDING_ESCAPE:
        return False
    return bool(
        _PARTIAL_CSI.match(tail) or _PARTIAL_STR.match(tail) or _PARTIAL_DESIGNATOR.match(tail)
    )


class StreamCleaner:
    """Removes ANSI escapes and control characters and normalises CR/LF.

    Chunk boundaries may fall inside an escape sequence or between CR and LF, so
    the cleaner keeps the few characters it cannot decide on yet.

    A lone CR is a newline, unless ``keep_cr`` is set: then it stays for the ``Canvas``, which
    lets a progress bar rewrite its line. (The tty turns a program's own "\\r\\n" into
    "\\r\\r\\n", so CRs in front of a newline are dropped in that mode.)
    """

    def __init__(self, keep_cr: bool = False) -> None:
        self.keep_cr = keep_cr
        self._pending_escape = ""
        self._pending_cr = False

    def feed(self, chunk: str) -> str:
        if not chunk:
            return ""
        if self._pending_cr:
            if not chunk.startswith("\n"):  # what was held back was not a line end
                chunk = ("\r" if self.keep_cr else "\n") + chunk
            self._pending_cr = False
        if chunk.endswith("\r"):
            self._pending_cr = True
            chunk = chunk[:-1]
        if self._pending_escape:
            chunk = self._pending_escape + chunk
            self._pending_escape = ""
        last_esc = chunk.rfind("\x1b")
        if last_esc != -1 and _is_partial_escape(chunk[last_esc:]):
            self._pending_escape = chunk[last_esc:]
            chunk = chunk[:last_esc]
        chunk = ANSI_ESCAPE.sub("", chunk)
        chunk = CONTROL_CHARS.sub("", chunk)
        if self.keep_cr:
            return CARRIAGE_RETURNS_BEFORE_NEWLINE.sub("\n", chunk)
        return chunk.replace("\r\n", "\n").replace("\r", "\n")

    def finalize(self) -> str:
        """End of stream: a pending CR becomes a newline, a partial escape is dropped."""
        out = "\n" if self._pending_cr else ""
        self._pending_cr = False
        self._pending_escape = ""
        return out


# ---------------------------------------------------------------------------
# Line arithmetic. A "line" ends at "\n", or after MAX_LINE_CHARS characters.
# ---------------------------------------------------------------------------

def count_virtual_lines(text: str, start: int = 0, end: Optional[int] = None,
                        max_line_chars: int = MAX_LINE_CHARS) -> int:
    """Number of lines in ``text[start:end]``."""
    end = len(text) if end is None else end
    pos = max(0, start)
    total = 0
    while pos < end:
        newline = text.find("\n", pos, end)
        if newline == -1:
            total += (end - pos + max_line_chars - 1) // max_line_chars
            break
        total += (newline - pos) // max_line_chars + 1
        pos = newline + 1
    return total


def find_line_offset(text: str, target_line: int, max_line_chars: int = MAX_LINE_CHARS) -> int:
    """Character offset at which the 0-based ``target_line`` starts."""
    if target_line <= 0:
        return 0
    pos = 0
    end = len(text)
    counted = 0
    while pos < end and counted < target_line:
        newline = text.find("\n", pos, end)
        if newline == -1:
            room = (target_line - counted) * max_line_chars
            return end if room >= end - pos else pos + room
        pieces = (newline - pos) // max_line_chars
        if counted + pieces >= target_line:
            return pos + (target_line - counted) * max_line_chars
        counted += pieces + 1
        pos = newline + 1
    return pos


def slice_virtual_lines(text: str, start_offset: int = 0, limit_lines: int = 200,
                        max_line_chars: int = MAX_LINE_CHARS) -> Tuple[str, int]:
    """Up to ``limit_lines`` lines starting at ``start_offset``: (text, next offset)."""
    start = max(0, start_offset)
    end = len(text)
    if start >= end or limit_lines <= 0:
        return "", start
    pos = start
    counted = 0
    while pos < end and counted < limit_lines:
        newline = text.find("\n", pos, end)
        needed = limit_lines - counted
        if newline == -1:
            room = needed * max_line_chars
            pos = end if end - pos <= room else pos + room
            break
        pieces = (newline - pos) // max_line_chars
        if pieces >= needed:
            pos += needed * max_line_chars
            break
        counted += pieces + 1
        pos = newline + 1
    return text[start:pos], pos


# ---------------------------------------------------------------------------
# Canvas
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Window:
    """One answer of the canvas."""
    text: str
    has_more: int          # unread lines that remain
    dropped: bool = False  # unread text was lost (trimmed away by the size limit) since the last report
    truncated: bool = False  # this window is a partial view of what is available
    skipped: int = 0       # unread lines that ``tail`` passed over; they are still in the scrollback


def _cap_head(window: str, max_chars: int) -> str:
    """Keep the first lines of ``window`` within ``max_chars``.

    A window ends only on a line boundary, so the cap is soft: one whole line is
    always delivered, otherwise a line longer than the cap would never move on."""
    if len(window) <= max_chars:
        return window
    touched = count_virtual_lines(window, 0, max_chars)
    cut = find_line_offset(window, max(0, touched - 1))
    if cut <= 0:
        cut = find_line_offset(window, touched)
    return window[:cut]


def _cap_tail(window: str, max_chars: int) -> str:
    """Keep the last lines of ``window`` within ``max_chars`` (at least one line)."""
    if len(window) <= max_chars:
        return window
    total = count_virtual_lines(window)
    # The fewest lines to drop from the top so that the rest fits; the offsets grow with the
    # number of lines, so a bisection finds it. If not even the last line fits, it stays alone.
    low, high = 1, max(1, total - 1)
    while low < high:
        middle = (low + high) // 2
        if len(window) - find_line_offset(window, middle) <= max_chars:
            high = middle
        else:
            low = middle + 1
    return window[find_line_offset(window, low if total > 1 else 0):]


class Canvas:
    """The console an agent reads: bounded history plus one unread position.

    Everything is measured in lines. ``read_unread`` advances the position,
    ``peek`` and ``tail`` look at history, ``tail`` also jumps to the end.
    """

    def __init__(self, max_chars: int = 0) -> None:
        self._buf = ChunkBuffer(max_chars)
        self._cursor = 0
        self._dropped = False
        self._rewind = False  # a carriage return came, and no text after it yet
        self._changed = threading.Condition()

    # -- writing ---------------------------------------------------------

    def append(self, text: str) -> None:
        """Write text like a console: a carriage return sends the writing position back to the
        start of the line, so what follows replaces the line (a progress bar stays one line).
        A line the reader has already seen is not taken back: the update starts a new one."""
        if not text:
            return
        with self._changed:
            for index, piece in enumerate(text.split("\r")):
                if index:
                    self._rewind = True
                if not piece:
                    continue
                if self._rewind and not piece.startswith("\n"):  # "\r\n" is just a line end
                    self._start_over()
                self._rewind = False
                self._buf.append(piece)
            if self._cursor < self._buf.base_offset:
                self._dropped = True
                self._cursor = self._buf.base_offset
            self._changed.notify_all()

    def _start_over(self) -> None:
        """Drop the open line if nobody has read any of it, otherwise leave it and start the next one."""
        line = self._buf.open_line()
        if not line:
            return
        end = self._buf.base_offset + len(self._buf)
        if self._cursor <= end - len(line):
            self._buf.truncate_tail(len(line))
        else:
            self._buf.append("\n")
            if self._cursor >= end:  # the reader has the whole line, so its end is no news
                self._cursor += 1

    def start_new_line(self) -> None:
        """Make sure the next text starts on a fresh line."""
        with self._changed:
            self._rewind = False
            if len(self._buf) and self._buf.tail(1) != "\n":
                self._buf.append("\n")
                self._changed.notify_all()

    def trim_tail_if_unread(self, suffix: str) -> bool:
        """Remove ``suffix`` from the end when nobody has read it yet."""
        if not suffix:
            return False
        with self._changed:
            end = self._buf.base_offset + len(self._buf)
            if self._buf.tail(len(suffix)) != suffix or self._cursor > end - len(suffix):
                return False
            self._buf.truncate_tail(len(suffix))
            return True

    def skip_unread(self) -> int:
        """Move the unread position to the end without reporting a loss; returns the lines passed over.
        The text stays in the scrollback."""
        with self._changed:
            text, base, cursor = self._snapshot()
            skipped = count_virtual_lines(text, cursor)
            self._cursor = base + len(text)
            return skipped

    def clear(self) -> None:
        with self._changed:
            self._rewind = False
            self._buf.clear()
            self._cursor = max(self._cursor, self._buf.base_offset)
            self._changed.notify_all()

    def wake(self) -> None:
        """Wake up waiters after a state change that is not an append (a run finished)."""
        with self._changed:
            self._changed.notify_all()

    # -- reading ---------------------------------------------------------

    def read_unread(self, limit_lines: int = 200, max_chars: int = 200_000) -> Window:
        with self._changed:
            text, base, cursor = self._snapshot()
            window = self._slice(text, cursor, limit_lines)
            window = _cap_head(window, max_chars)
            after = cursor + len(window)
            self._cursor = base + after
            dropped, self._dropped = self._dropped, False
            remaining = count_virtual_lines(text, after)
            return Window(window, remaining, dropped, truncated=remaining > 0)

    def peek(self, offset: int, limit_lines: int = 200, max_chars: int = 200_000) -> Window:
        """History without moving the unread position.

        ``offset >= 0``: start at that line of the buffered history.
        ``offset < 0``: start that many lines above the unread position."""
        with self._changed:
            text, _, cursor = self._snapshot()
            if offset < 0:
                start_line = max(0, count_virtual_lines(text, 0, cursor) + offset)
            else:
                start_line = offset
            start = find_line_offset(text, start_line)
            window = _cap_head(self._slice(text, start, limit_lines), max_chars)
            unread = count_virtual_lines(text, cursor)
            return Window(window, unread, False, truncated=start + len(window) < len(text))

    def tail(self, lines: int, max_chars: int = 200_000) -> Window:
        """The last ``lines`` lines; the unread position jumps to the end.

        The unread lines in front of the window are only counted (``skipped``): they stay in the
        scrollback. Nothing is lost, so ``dropped`` is left to the size limit of the buffer."""
        with self._changed:
            text, base, cursor = self._snapshot()
            total = count_virtual_lines(text)
            start = find_line_offset(text, max(0, total - lines))
            window = _cap_tail(text[start:], max_chars)
            skipped = count_virtual_lines(text, cursor, len(text) - len(window))
            self._cursor = base + len(text)
            dropped, self._dropped = self._dropped, False
            return Window(window, 0, dropped, truncated=len(window) < len(text), skipped=skipped)

    def wait_until(self, predicate: Callable[[], bool], timeout: float) -> bool:
        """Block until ``predicate()`` is true, woken by every append and by ``wake()``.

        The predicate runs under the canvas lock: it may call canvas methods but must
        not take other locks. Returns the last value of the predicate."""
        with self._changed:
            if timeout <= 0:
                return predicate()
            return self._changed.wait_for(predicate, timeout)

    # -- introspection ---------------------------------------------------

    def end(self) -> int:
        with self._changed:
            return self._buf.base_offset + len(self._buf)

    def has_unread(self) -> bool:
        with self._changed:
            return self._cursor < self._buf.base_offset + len(self._buf)

    def __len__(self) -> int:
        with self._changed:
            return len(self._buf)

    # -- internals -------------------------------------------------------

    def _snapshot(self) -> Tuple[str, int, int]:
        """(text, base offset, cursor relative to the text). Call under the lock."""
        text = self._buf.text()
        base = self._buf.base_offset
        if self._cursor < base:
            self._dropped = True
            self._cursor = base
        return text, base, self._cursor - base

    @staticmethod
    def _slice(text: str, start: int, limit_lines: int) -> str:
        if limit_lines > 0:
            return slice_virtual_lines(text, start, limit_lines)[0]
        return text[start:]
