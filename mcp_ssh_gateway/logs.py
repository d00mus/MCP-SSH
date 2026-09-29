"""Session and run logs.

One JSON-lines file per session and one per run, in two directories. Each event is
opened, appended and closed, so a crash never leaves a half-written buffer behind.
"""

import json
import os
import re
import sys
import threading
import time
from datetime import datetime, UTC
from typing import Any, Dict, List, Tuple

POLICIES = ("off", "meta", "full")
DEFAULT_MAX_FILE_BYTES = 20 * 1024 * 1024

_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9._-]+")

_write_lock = threading.Lock()

_MASK = "******"
_SECRET_WORD = r"password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|passphrase|authorization"
_VALUE = r"\"[^\"]*\"|'[^']*'|[^\s'\"&;|]+"  # quoted (it may hold spaces) or bare
_SAME_COMMAND = r"[^|;&\n]*?"  # up to an option of the same simple command

# Group 1 of a rule stays (the name, the option), group 2 is the value to hide.
# Quantifiers are bounded, so a long line without a match stays cheap.
_MASKING_RULES = (
    # NAME=value, name: value, "name":"value", Authorization: Bearer value. The name only has to
    # contain a secret word (GITHUB_TOKEN, X-API-Key); the value ends at a space, quote, & ; |
    re.compile(rf"((?:{_SECRET_WORD})[\w-]{{0,40}}[\"']?\s*[=:]\s*(?:(?:Bearer|Basic|Digest|Token)\s+)?)({_VALUE})",
               re.I),
    # --password value (a following option is not the value)
    re.compile(rf"((?<![\w-])--?[\w-]{{0,40}}?(?:{_SECRET_WORD})[\w-]{{0,40}}\s+)(?!-)({_VALUE})", re.I),
    # scheme://user:password@host, and scheme://token@host (a bare login is a token only for http)
    re.compile(r"(\b[a-z][a-z0-9+.-]*://[^/@\s:'\"]+:)([^/@\s'\"]+)(?=@)", re.I),
    re.compile(r"(\bhttps?://)([^/@\s:'\"]+)(?=@)", re.I),
    # clients that take the password as an option: curl -u user:pass, sshpass -p pass, mysql -ppass
    re.compile(rf"(\bcurl\b{_SAME_COMMAND}\s(?:-[uU]\s*|--(?:proxy-)?user(?:=|\s+)))({_VALUE})"),
    re.compile(rf"(\bsshpass\s+(?:-\S+\s+)*?-p\s*)({_VALUE})"),
    re.compile(rf"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b{_SAME_COMMAND}\s-p)({_VALUE})"),
)


def _hidden(value: str) -> str:
    """The mask, inside the quotes the value had."""
    return value[0] + _MASK + value[-1] if value[0] in "'\"" else _MASK


def mask_secrets(text: str) -> str:
    """Best effort: hides passwords, tokens and keys given in a command line.

    Not a security boundary (values can be split or encoded); it keeps accidental
    leaks out of the files."""
    if not isinstance(text, str) or not text:
        return text
    for rule in _MASKING_RULES:
        text = rule.sub(lambda m: m.group(1) + _hidden(m.group(2)), text)
    return text


def safe_name(text: str) -> str:
    return _UNSAFE_NAME_CHARS.sub("_", str(text)).strip("._") or "x"


class EventLog:
    """Append-only JSON-lines file."""

    def __init__(self, path: str, policy: str, max_bytes: int) -> None:
        self.path = path
        self._policy = policy
        self._max_bytes = max_bytes

    def event(self, kind: str, **fields: Any) -> None:
        """A lifecycle event: connected, started, finished, ..."""
        if self._policy == "off":
            return
        if "command" in fields:
            fields["command"] = mask_secrets(str(fields["command"]))
        self._write({"ts": _now(), "event": kind, **fields})

    def output(self, text: str) -> None:
        """Raw output. Written only with the ``full`` policy, and never into a full file."""
        if self._policy != "full" or not text:
            return
        try:
            if os.path.getsize(self.path) >= self._max_bytes:
                return
        except OSError:
            pass
        self._write({"ts": _now(), "event": "output", "text": text})

    def _write(self, record: Dict[str, Any]) -> None:
        try:
            with _write_lock, open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"[SSH-MCP] log write failed ({self.path}): {exc}", file=sys.stderr, flush=True)


class LogStore:
    """Owns the log directories and knows how to name and prune the files."""

    def __init__(self, root: str, policy: str = "meta", max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
        if policy not in POLICIES:
            raise ValueError(f"log policy must be one of {POLICIES}, got {policy!r}")
        self.root = root
        self.policy = policy
        self._max_file_bytes = max_file_bytes
        self.sessions_dir = os.path.join(root, "sessions")
        self.runs_dir = os.path.join(root, "runs")
        if policy != "off":
            for directory in (self.sessions_dir, self.runs_dir):
                os.makedirs(directory, exist_ok=True)
                _make_private(directory)

    def session_log(self, alias: str, session_id: int) -> EventLog:
        name = f"{safe_name(alias)}__s{session_id}__{_stamp()}.log"
        return EventLog(os.path.join(self.sessions_dir, name), self.policy, self._max_file_bytes)

    def run_log(self, alias: str, session_id: int, run_id: int) -> EventLog:
        name = f"{safe_name(alias)}__s{session_id}__r{run_id}__{_stamp()}.log"
        return EventLog(os.path.join(self.runs_dir, name), self.policy, self._max_file_bytes)

    def prune(self, max_age_seconds: float = 7 * 86400, max_total_bytes: int = 200 * 1024 * 1024) -> int:
        """Delete logs older than the retention, then the oldest ones beyond the byte budget."""
        now = time.time()
        files: List[Tuple[float, int, str]] = []
        for directory in (self.sessions_dir, self.runs_dir):
            if not os.path.isdir(directory):
                continue
            for entry in os.scandir(directory):
                if entry.is_file() and entry.name.endswith(".log"):
                    stat = entry.stat()
                    files.append((stat.st_mtime, stat.st_size, entry.path))
        removed = 0
        kept: List[Tuple[float, int, str]] = []
        for mtime, size, path in files:
            if now - mtime > max_age_seconds and _remove(path):
                removed += 1
            else:
                kept.append((mtime, size, path))
        kept.sort(reverse=True)
        total = 0
        for _mtime, size, path in kept:
            total += size
            if total > max_total_bytes and _remove(path):
                removed += 1
        return removed


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _remove(path: str) -> bool:
    try:
        os.remove(path)
        return True
    except OSError:
        return False


def _make_private(directory: str) -> None:
    """Logs contain command text (and with the full policy, output): owner only."""
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
