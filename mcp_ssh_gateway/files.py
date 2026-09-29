"""The file tool: list, read, write and edit remote files.

SFTP is used when the server offers it. Otherwise the same operations run as quiet
commands in a Linux shell session of that server (``base64``, ``head``, ``mv``).
Both backends work on bytes; everything else (text windows, filters, edits, the
conflict check) is shared.
"""

import base64
import difflib
import hashlib
import os
import re
import shlex
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import paramiko

from mcp_ssh_gateway.config import DEFAULT_LINES, MAX_LINES, Settings
from mcp_ssh_gateway.session import Session, SessionError

DEFAULT_READ_BYTES = 200_000    # how much of a file `read` fetches; the rest is `run` work (sed, grep)
MAX_DOWNLOAD_BYTES = 2_000_000  # a download is not shown, so it may be bigger
DEFAULT_EDIT_BYTES = 1_000_000
MAX_WRITE_BYTES = 1_000_000
DEFAULT_READ_CHARS = 20_000     # the largest text `read` shows at once
SHELL_CHUNK_CHARS = 3000       # base64 characters per typed line (a terminal takes ~4000)
SHELL_TIMEOUT = 60.0
ACTIONS = ("list", "read", "write", "edit")


class FileError(SessionError):
    """The request failed; the message is written for the agent."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def last_lines(chunk: bytes) -> bytes:
    """The whole lines of a chunk cut out of the end of a file.

    Its first byte is only a probe: when it is a newline, the second byte starts a line."""
    probe, rest = chunk[:1], chunk[1:]
    if probe == b"\n":
        return rest
    _, newline, whole = rest.partition(b"\n")
    return whole if newline else rest  # a single huge line: keep what there is


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

class SftpBackend:
    via = "sftp"

    def __init__(self, client: paramiko.SFTPClient) -> None:
        self._sftp = client

    def close(self) -> None:
        try:
            self._sftp.close()
        except Exception:
            pass

    def listing(self, path: str) -> str:
        try:
            entries = sorted(self._sftp.listdir_attr(path), key=lambda e: e.filename)
        except OSError as exc:
            raise FileError(f"Cannot list {path}: {exc}") from exc
        return "\n".join(str(entry) for entry in entries) + "\n" if entries else ""

    def read(self, path: str, max_bytes: int, from_end: bool = False) -> Tuple[bytes, bool]:
        """The first ``max_bytes`` of the file, or with ``from_end`` the whole lines of its last ``max_bytes``.

        The flag says the file is bigger than that."""
        try:
            with self._sftp.file(path, "rb") as handle:
                if from_end:
                    size = handle.stat().st_size
                    if size > max_bytes:
                        handle.seek(size - max_bytes - 1)
                        return last_lines(handle.read(max_bytes + 1)), True
                data = handle.read(max_bytes + 1)
        except OSError as exc:
            raise FileError(f"Cannot read {path}: {exc}") from exc
        return data[:max_bytes], len(data) > max_bytes

    def _mode_of(self, path: str) -> Optional[int]:
        """The permissions of an existing file; None for a new one, whose mode the server's umask decides."""
        try:
            return self._sftp.stat(path).st_mode & 0o7777
        except OSError:
            return None

    def write(self, path: str, data: bytes) -> None:
        """Atomic: write next to the target, set the mode, then rename over it.

        A symlink is followed: the link stays, its target changes."""
        try:
            path = self._sftp.normalize(path)
        except OSError:
            pass  # some servers cannot resolve a file that does not exist yet
        temporary = f"{path}.mcp_tmp.{int(time.time() * 1000)}"
        try:
            mode = self._mode_of(path)
            with self._sftp.file(temporary, "wb") as handle:
                handle.write(data)
            if mode is not None:
                self._sftp.chmod(temporary, mode)
            try:
                self._sftp.posix_rename(temporary, path)
            except (OSError, AttributeError):
                self._sftp.rename(temporary, path)
        except OSError as exc:
            try:
                self._sftp.remove(temporary)
            except OSError:
                pass
            raise FileError(f"Cannot write {path}: {exc}") from exc


class ShellBackend:
    via = "shell"

    def __init__(self, session: Session, release: Optional[Callable[[], None]] = None) -> None:
        self._session = session
        self._release = release  # closes a shell that was opened for this one operation

    def close(self) -> None:
        if self._release:
            try:
                self._release()
            except SessionError:
                pass

    def _sh(self, command: str, what: str, timeout: float = SHELL_TIMEOUT) -> str:
        result = self._session.run_quiet(command, timeout=timeout)
        if result.timed_out or result.exit_code != 0:
            detail = result.output.strip()[-300:] or "no output"
            raise FileError(f"{what} failed on the host (exit {result.exit_code}): {detail}")
        return result.output

    def _target_of(self, path: str) -> str:
        """Where a write really lands: a symlink is followed, so the link stays and its target changes."""
        quoted = shlex.quote(path)
        found = self._sh(f"readlink -f -- {quoted} 2>/dev/null || printf %s {quoted}", f"Resolving {path}")
        return found.strip() or path

    def _mode_of(self, path: str) -> Optional[str]:
        """The permissions of an existing file, as chmod takes them; None for a new one (umask decides)."""
        result = self._session.run_quiet(f"stat -c %a {shlex.quote(path)} 2>/dev/null", timeout=SHELL_TIMEOUT)
        mode = result.output.strip()
        return mode if result.exit_code == 0 and re.fullmatch(r"[0-7]{3,4}", mode) else None

    def listing(self, path: str) -> str:
        return self._sh(f"ls -la -- {shlex.quote(path)}", f"Listing {path}")

    def read(self, path: str, max_bytes: int, from_end: bool = False) -> Tuple[bytes, bool]:
        quoted = shlex.quote(path)
        cut = "tail" if from_end else "head"
        output = self._sh(
            f"test -f {quoted} && test -r {quoted} && {cut} -c {max_bytes + 1} {quoted} | base64"
            " || { echo 'no such file or not readable'; false; }",
            f"Reading {path}")
        data = base64.b64decode(re.sub(r"[^A-Za-z0-9+/=]", "", output))
        if from_end and len(data) > max_bytes:
            return last_lines(data), True
        return data[:max_bytes], len(data) > max_bytes

    def write(self, path: str, data: bytes) -> None:
        path = self._target_of(path)
        quoted = shlex.quote(path)
        stamp = int(time.time() * 1000)
        staging = shlex.quote(f"{path}.mcp_b64.{stamp}")
        temporary = shlex.quote(f"{path}.mcp_tmp.{stamp}")
        self._sh(f'mkdir -p "$(dirname {quoted})" && : > {staging}', f"Preparing {path}")
        try:
            encoded = base64.b64encode(data).decode("ascii")
            for start in range(0, len(encoded), SHELL_CHUNK_CHARS):
                self._sh(f"printf %s {encoded[start:start + SHELL_CHUNK_CHARS]} >> {staging}", f"Sending {path}")
            mode = self._mode_of(path)
            chmod = f"chmod {mode} {temporary} && " if mode else ""
            self._sh(f"base64 -d {staging} > {temporary} && {chmod}mv -f {temporary} {quoted}", f"Writing {path}")
        finally:
            try:
                self._session.run_quiet(f"rm -f {staging} {temporary}", timeout=15)
            except SessionError:
                pass


# ---------------------------------------------------------------------------
# Text handling
# ---------------------------------------------------------------------------

def window_lines(text: str, offset_line: Optional[int], limit: int) -> Dict[str, Any]:
    """Lines ``offset_line``.. (1-based) of the text, at most ``limit`` of them."""
    lines = text.splitlines(keepends=True)
    total = len(lines)
    start = max(1, offset_line or 1)
    picked = lines[start - 1:start - 1 + limit]
    return {"text": "".join(picked), "start": start if picked else 0,
            "end": start - 1 + len(picked), "total": total}


def clip_lines(text: str, limit: int) -> Tuple[str, int, bool]:
    """The whole lines of ``text`` that fit in ``limit`` characters: (text, how many lines, first line cut).

    A first line that is longer than the limit is cut, so that an answer always moves on."""
    kept: List[str] = []
    size = 0
    for line in text.splitlines(keepends=True):
        if size + len(line) > limit:
            if not kept:
                return line[:limit], 1, True
            break
        kept.append(line)
        size += len(line)
    return "".join(kept), len(kept), False


def filter_lines(text: str, contains: Optional[str], tail: Optional[int]) -> str:
    lines = text.splitlines()
    if contains:
        lines = [line for line in lines if contains in line]
    if tail is not None:
        lines = lines[-max(1, int(tail)):]
    return "\n".join(lines) + ("\n" if lines else "")


def _snippets(text: str, positions: List[int]) -> str:
    lines = text.splitlines()
    shown = []
    for line_no in positions:
        block = [f"{'-->' if i == line_no else '   '} {i + 1}: {lines[i]}"
                 for i in range(max(0, line_no - 2), min(len(lines), line_no + 3))]
        shown.append("\n".join(block))
    return "\n\n".join(shown)


def apply_edits(text: str, edits: List[Dict[str, Any]]) -> Tuple[str, int]:
    """Replace ``old_text`` by ``new_text`` for each edit; returns (new text, replacements).

    An edit must match exactly once unless ``replace_all`` is set. When the exact text
    is absent, a match that only differs in line endings (CRLF/LF) is accepted."""
    total = 0
    for index, edit in enumerate(edits):
        old = edit.get("old_text")
        if not old:
            raise FileError(f"Edit {index}: 'old_text' is missing or empty.")
        new = str(edit.get("new_text", ""))
        everywhere = bool(edit.get("replace_all", False))
        if text.count(old):
            pattern = re.compile(re.escape(old))
        else:
            parts = [re.escape(part) for part in old.replace("\r\n", "\n").split("\n")]
            pattern = re.compile(r"\r?\n".join(parts))
        matches = list(pattern.finditer(text))
        if not matches:
            similar = [f"line {i + 1}: {line.strip()!r}" for i, line in enumerate(text.splitlines())
                       if difflib.SequenceMatcher(None, old.strip(), line.strip()).ratio() > 0.7][:5]
            hint = "\nSimilar lines: " + "; ".join(similar) if similar else ""
            raise FileError(f"Edit {index}: 'old_text' was not found. Check whitespace and line endings; "
                            f"read the file again.{hint}")
        if len(matches) > 1 and not everywhere:
            where = _snippets(text, [text.count("\n", 0, m.start()) for m in matches])
            raise FileError(f"Edit {index}: 'old_text' matches {len(matches)} places. Add surrounding "
                            f"lines to make it unique, or set replace_all.\n{where}")
        text = pattern.sub(lambda _m, replacement=new: replacement, text, count=0 if everywhere else 1)
        total += len(matches) if everywhere else 1
    return text, total


# ---------------------------------------------------------------------------
# Local files (download target / upload source) stay inside a sandbox
# ---------------------------------------------------------------------------

PROTECTED_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "servers.json", "servers.json.example"}


class LocalSandbox:
    """Local paths the file tool may touch: the project, the gateway cache, optionally temp."""

    def __init__(self, settings: Settings, protected_files: Optional[List[str]] = None) -> None:
        self._settings = settings
        self._protected = {os.path.normcase(os.path.realpath(p)) for p in (protected_files or []) if p}
        if settings.servers_path:
            self._protected.add(os.path.normcase(os.path.realpath(settings.servers_path)))

    def resolve(self, path: str, for_write: bool) -> str:
        settings = self._settings
        if not settings.project_root and not settings.allow_system_temp:
            raise FileError("Local files are off: the gateway runs without --project-root. Start it with "
                            "--project-root <folder> to let the file tool read and write local files there.")
        real = os.path.realpath(os.path.expanduser(path.strip()))
        roots = [settings.project_root, settings.cache_root]
        if settings.allow_system_temp:
            roots.append(tempfile.gettempdir())
        if not any(self._within(real, root) for root in roots if root and not _is_filesystem_root(root)):
            raise FileError(
                f"Local path '{path}' is outside the allowed folders (project: {settings.project_root or 'none'}). "
                "Start the gateway with --project-root or --allow-system-temp to widen them.")
        base = os.path.basename(real).lower()
        parts = os.path.normcase(real).replace("\\", "/").split("/")
        is_secret = base in PROTECTED_NAMES or base.endswith(".ppk") or os.path.normcase(real) in self._protected
        if ".git" in parts or is_secret:
            raise FileError(f"Local path '{path}' is a protected file (keys, servers.json, .git).")
        gateway = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if for_write and not settings.allow_gateway_dir and self._within(real, gateway) \
                and not self._within(real, settings.cache_root):
            raise FileError("Writing into the gateway's own folder is refused (--allow-gateway-dir for development).")
        return real

    @staticmethod
    def _within(path: str, root: str) -> bool:
        try:
            root = os.path.normcase(os.path.realpath(root))
            return os.path.commonpath([root, os.path.normcase(path)]) == root
        except ValueError:
            return False


def _is_filesystem_root(path: str) -> bool:
    real = os.path.realpath(path)
    return os.path.dirname(real) == real


# ---------------------------------------------------------------------------
# The tool
# ---------------------------------------------------------------------------

class FileService:
    def __init__(self, manager: Any, settings: Settings) -> None:
        self._manager = manager
        self._settings = settings
        self._sandbox = LocalSandbox(settings)

    def handle(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = str(args.get("action") or "").strip().lower()
        if action not in ACTIONS:
            raise FileError(f"'action' must be one of: {', '.join(ACTIONS)}.")
        path = str(args.get("path") or "").strip()
        if not path:
            raise FileError("'path' is required.")
        alias = self._manager.server_alias(args.get("server"), args.get("session_id"))
        target = self._manager.target(alias)
        if action in ("write", "edit") and target.read_only:
            raise FileError(f"Server '{alias}' is read-only: '{action}' is blocked.")
        backend = self._backend(alias, args)
        try:
            handler = getattr(self, f"_{action}")
            result = handler(backend, path, args)
        finally:
            backend.close()
        result.update({"server": alias, "path": path, "via": backend.via})
        return result

    def _backend(self, alias: str, args: Dict[str, Any]):
        try:
            return SftpBackend(self._manager.connection(alias).sftp())
        except (paramiko.SSHException, EOFError, OSError):
            named = args.get("session_id")
            session = self._manager.session_for(server=alias, session_id=named, shell=True)
            # A shell opened just for this operation is closed with it; a named one is the agent's and stays.
            release = None if named else (lambda: self._manager.close_session(session.sid))
            return ShellBackend(session, release)

    def _list(self, backend, path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        window = window_lines(backend.listing(path), _optional_int(args.get("offset_line")),
                              _bounded(args.get("lines"), DEFAULT_LINES, 1, MAX_LINES))
        result: Dict[str, Any] = {"listing": window["text"], "total_lines": window["total"]}
        if window["end"] < window["total"]:
            result["next_offset_line"] = window["end"] + 1
        return result

    def _read(self, backend, path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        local = str(args.get("local_path") or "").strip()
        max_bytes = MAX_DOWNLOAD_BYTES if local else DEFAULT_READ_BYTES
        tail = _optional_int(args.get("tail_lines"))
        data, cut = backend.read(path, max_bytes, from_end=tail is not None and not local)
        if local:
            target = self._sandbox.resolve(local, for_write=True)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as handle:
                handle.write(data)
            return {"saved_to": target, "size": len(data), "sha256": sha256(data), "truncated": cut}
        if b"\x00" in data[:8192]:
            return {"binary": True, "size": len(data), "sha256": sha256(data),
                    "note": "Binary file: content not shown. Use local_path to download it."}
        text = data.decode("utf-8", errors="replace")
        if args.get("contains") or tail is not None:
            text = filter_lines(text, args.get("contains"), tail)
        window = window_lines(text, _optional_int(args.get("offset_line")),
                              _bounded(args.get("lines"), DEFAULT_LINES, 1, MAX_LINES))
        content, shown, line_cut = clip_lines(window["text"], DEFAULT_READ_CHARS)
        first = window["start"]
        last = first - 1 + shown if first else window["end"]  # the character cap can end the answer earlier
        result: Dict[str, Any] = {"content": content, "line_start": first,
                                  "line_end": last, "total_lines": window["total"]}
        if last < window["total"]:
            result["next_offset_line"] = last + 1
        notes = []
        if line_cut:
            notes.append(f"Line {first} is longer than {DEFAULT_READ_CHARS} characters and was cut.")
        elif last < window["end"]:
            notes.append(f"The answer is limited to {DEFAULT_READ_CHARS} characters; continue at next_offset_line.")
        if not cut:
            result["sha256"] = sha256(data)  # of the whole file: what edit takes as expected_sha256
        elif tail is None or window["total"] < tail:  # the end of the file did not hold all the lines asked for
            result["truncated"] = True
            notes.append(f"Only the {'first' if tail is None else 'last'} {max_bytes} bytes were read; "
                         "use the run tool (sed -n, grep) for the rest.")
        if notes:
            result["note"] = " ".join(notes)
        return result

    def _write(self, backend, path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        local = str(args.get("local_path") or "").strip()
        if local:
            source = self._sandbox.resolve(local, for_write=False)
            if not os.path.isfile(source):
                raise FileError(f"Local file not found: {local}")
            with open(source, "rb") as handle:
                data = handle.read(MAX_WRITE_BYTES + 1)
        elif args.get("content") is not None:
            try:
                data = base64.b64decode(str(args["content"])) if args.get("is_base64") \
                    else str(args["content"]).encode("utf-8")
            except ValueError as exc:
                raise FileError(f"'content' is not valid base64: {exc}") from exc
        else:
            raise FileError("write needs 'content' or 'local_path'.")
        if len(data) > MAX_WRITE_BYTES:
            raise FileError(f"The data is larger than {MAX_WRITE_BYTES} bytes.")
        backend.write(path, data)
        return {"size": len(data), "sha256": sha256(data)}

    def _edit(self, backend, path: str, args: Dict[str, Any]) -> Dict[str, Any]:
        edits = args.get("edits")
        if not isinstance(edits, list) or not edits:
            raise FileError("'edits' must be a non-empty list of {old_text, new_text}.")
        limit = DEFAULT_EDIT_BYTES
        original, cut = backend.read(path, limit)
        if cut:
            raise FileError(f"The file is larger than {limit} bytes; change it with the run tool (sed), "
                            "or write a new version.")
        try:
            text = original.decode("utf-8")
        except UnicodeDecodeError:
            raise FileError("The file is not valid UTF-8; refusing to rewrite it.") from None
        updated, count = apply_edits(text, edits)
        new = updated.encode("utf-8")
        result: Dict[str, Any] = {"replacements": count, "changed": new != original,
                                  "sha256_before": sha256(original), "sha256_after": sha256(new)}
        expected = str(args.get("expected_sha256") or "").strip().lower()
        if expected and expected != result["sha256_before"]:
            raise FileError(f"{path} is not the version you read (sha256 differs). Read it again and redo the edit.")
        if args.get("dry_run") or new == original:
            result["dry_run"] = bool(args.get("dry_run"))
            return result
        current, _ = backend.read(path, limit)
        if sha256(current) != result["sha256_before"]:
            raise FileError(f"{path} changed while it was being edited. Read it again and redo the edit.")
        backend.write(path, new)
        return result


def _optional_int(value: Any) -> Optional[int]:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        raise FileError(f"Expected a number, got {value!r}.") from None


def _bounded(value: Any, default: int, low: int, high: int) -> int:
    number = _optional_int(value)
    return default if number is None else max(low, min(high, number))
