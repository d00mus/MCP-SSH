import os
import re
import sys
import json
import time
import hashlib
import tempfile
import threading
import functools
from datetime import datetime
from typing import Any, Dict, Optional, List, Tuple
from src.config import (
    ANSI_ESCAPE, CONTROL_CHARS, PROMPT_ONLY_LINE, MAX_READ_MAX_LINES, MAX_LOG_FILE_BYTES, config,
    MAX_DEAD_SESSION_LOGS_PER_SERVER, MIN_LOG_RETENTION_SECONDS
)

# Striped locks: 64 distinct lock stripes keyed by file path hash.
# Provides concurrency between independent session and run log files with negligible collision probability.
_NUM_STRIPED_LOCKS = 64
_MAX_REGEX_LINE = 4096
_MAX_REGEX_WORKERS = 2
# Quantifier inside a group and another quantifier right after it: (a+)+, (?:a+){2,}.
_NESTED_QUANTIFIER = re.compile(
    r"\((?:\?:)?[^)]*[+*{][^)]*\)(?:[+*]|\{\d*,?\d*\})"
)
_regex_workers_lock = threading.Lock()
_regex_workers_alive = 0
_striped_file_locks = [threading.Lock() for _ in range(_NUM_STRIPED_LOCKS)]

def _get_file_lock(path: str) -> threading.Lock:
    return _striped_file_locks[hash(path) % _NUM_STRIPED_LOCKS]

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

def _is_filesystem_root(path: str) -> bool:
    real = os.path.realpath(path)
    parent = os.path.dirname(real)
    return parent == real


_EXIT_MARKER_LINE = re.compile(r"^__MCP_EC_[0-9a-f]+_\d+$")


def parse_exit_marker(text: str, token: str) -> Optional[int]:
    """Return the exit code from an exit marker emitted by wrap_posix_exit_marker.

    NOTE: The token is a 16-hex random string generated per-command invocation.
    It cannot appear by accident in command output. We deliberately search for
    the marker without requiring strict trailing shell prompt patterns, because
    prompts vary across systems (e.g. SberCloud/BusyBox prompt '$' without trailing
    spaces), which previously caused commands to falsely appear hung.
    """
    if not text or not token:
        return None
    clean = ANSI_ESCAPE.sub("", text).replace("\r", "")
    match = re.search(rf"^__MCP_EC_{re.escape(token)}_(\d+)\s*$", clean, re.MULTILINE)
    if not match:
        match = re.search(rf"(?:^|\n)__MCP_EC_{re.escape(token)}_(\d+)", clean)
    if match:
        return int(match.group(1))
    return None


def resolve_local_path(path: str) -> str:
    if not path:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(path.strip()))
    # Use realpath to resolve symlinks and prevent symlink bypass (Fix L1)
    real_path = os.path.realpath(expanded)
    norm_real = os.path.normcase(real_path)
    
    # Sandboxing check
    project_root = os.path.realpath(config.PROJECT_ROOT) if config.PROJECT_ROOT else ""
    system_temp = os.path.realpath(tempfile.gettempdir())
    norm_project = os.path.normcase(project_root) if project_root else ""
    norm_temp = os.path.normcase(system_temp) if system_temp else ""
    
    def _inside_temp() -> bool:
        if not norm_temp:
            return False
        try:
            return os.path.commonpath([norm_temp, norm_real]) == norm_temp
        except ValueError:
            return False

    if not project_root or _is_filesystem_root(project_root):
        if not _inside_temp():
            why = "empty" if not project_root else "a filesystem root"
            log_error(
                f"Security: PROJECT_ROOT '{project_root}' is {why}. "
                f"Path '{path}' is denied outside the temp directory."
            )
            return ""
        if _protected_local_write(real_path):
            log_error(f"Security: Path '{path}' resolves to a protected file '{real_path}'. Access denied.")
            return ""
        return real_path

    in_project = False
    try:
        if norm_project and os.path.commonpath([norm_project, norm_real]) == norm_project:
            in_project = True
    except ValueError:
        pass

    if not in_project and not _inside_temp():
        log_error(f"Security: Path '{path}' resolves to '{real_path}' which is outside project root '{project_root}' and temp directory. Access denied.")
        return ""

    # PROJECT_ROOT is the writable area. Do not deny *.py: a download into the
    # workspace is a normal file write. servers.json is the password store and
    # .git is repository metadata; remote stdout must not replace either.
    if _protected_local_write(real_path):
        log_error(f"Security: Path '{path}' resolves to a protected file '{real_path}'. Access denied.")
        return ""

    return real_path


def _protected_local_write(real_path: str) -> bool:
    norm_path = os.path.normcase(real_path).replace("\\", "/")
    parts = norm_path.split("/")
    if ".git" in parts:
        return True
    base_name = os.path.basename(norm_path).lower()
    if base_name in {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "servers.json", "servers.json.example"} or base_name.endswith(".ppk"):
        return True
    config_path = getattr(config, "SERVERS_CONFIG_PATH", None) or ""
    if config_path:
        try:
            if os.path.normcase(real_path) == os.path.normcase(os.path.realpath(os.path.expanduser(config_path))):
                return True
        except Exception:
            pass
    try:
        registry = getattr(config, "registry", None)
        if registry:
            for s in registry.list_all():
                kp = getattr(s, "key_path", None)
                if kp:
                    try:
                        if os.path.normcase(real_path) == os.path.normcase(os.path.realpath(os.path.expanduser(kp))):
                            return True
                    except Exception:
                        pass
    except Exception:
        pass
    return False

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
        stripped = line.strip() or ""
        if PROMPT_ONLY_LINE.match(stripped) or _EXIT_MARKER_LINE.match(stripped):
            continue
        cleaned_lines.append(line)
    text = "\n".join(cleaned_lines)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()

def json_line(path: str, payload: Dict[str, Any]) -> None:
    try:
        with _get_file_lock(path):
            if os.path.exists(path):
                try:
                    if os.path.getsize(path) >= MAX_LOG_FILE_BYTES:
                        if payload.get("dir") in ("OUT", "ERR"):
                            return
                except OSError:
                    pass
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

def cleanup_old_logs(cache_dirs: Dict[str, str], max_age_seconds: float = 7 * 86400, max_files: int = 500) -> int:
    """Removes log files in cache_dirs older than max_age_seconds or exceeding max_files. Returns count of deleted files."""
    now = time.time()
    deleted_count = 0
    for dir_key in ("runs_dir", "sessions_dir"):
        target_dir = cache_dirs.get(dir_key)
        if not target_dir or not os.path.isdir(target_dir):
            continue
        try:
            entries = []
            for entry in os.scandir(target_dir):
                if entry.is_file() and entry.name.endswith(".log"):
                    try:
                        mtime = entry.stat().st_mtime
                        entries.append((entry.path, mtime))
                    except OSError:
                        pass
            remaining = []
            for path, mtime in entries:
                if (now - mtime) > max_age_seconds:
                    try:
                        os.remove(path)
                        deleted_count += 1
                    except OSError:
                        pass
                else:
                    remaining.append((path, mtime))
            if len(remaining) > max_files:
                remaining.sort(key=lambda x: x[1])
                to_delete = remaining[:-max_files]
                for path, _ in to_delete:
                    try:
                        os.remove(path)
                        deleted_count += 1
                    except OSError:
                        pass
        except Exception as e:
            log_error(f"Error during cleanup_old_logs in {target_dir}: {e}")
    return deleted_count

def cleanup_dead_session_logs(
    cache_dirs: Dict[str, str],
    server_alias: Optional[str] = None,
    max_logs_per_server: int = MAX_DEAD_SESSION_LOGS_PER_SERVER,
    min_retention_seconds: float = MIN_LOG_RETENTION_SECONDS
) -> int:
    """
    Cleans up old dead session logs per server.
    - Preserves all logs younger than min_retention_seconds (default 2 hours).
    - For logs older than min_retention_seconds: retains up to max_logs_per_server (default 20) newest logs per server.
    - Older excess logs and their corresponding run logs are removed.
    Returns total count of deleted files (session logs + run logs).
    """
    sessions_dir = cache_dirs.get("sessions_dir")
    runs_dir = cache_dirs.get("runs_dir")
    if not sessions_dir or not os.path.isdir(sessions_dir):
        return 0

    now = time.time()
    deleted_count = 0

    server_logs: Dict[str, List[Tuple[str, str, float, str]]] = {}
    target_srv_safe = safe_name(server_alias).lower() if server_alias else None

    try:
        with os.scandir(sessions_dir) as it:
            for entry in it:
                if entry.is_file() and entry.name.endswith(".log"):
                    try:
                        mtime = entry.stat().st_mtime
                    except OSError:
                        continue
                    name_no_ext = entry.name[:-4]
                    parts = name_no_ext.split("__")
                    if len(parts) >= 3:
                        if parts[1].startswith("s") and parts[1][1:].isdigit():
                            srv = "default"
                            sid_str = parts[1]
                        else:
                            srv = parts[1]
                            sid_str = parts[2]
                    else:
                        srv = "default"
                        sid_str = ""

                    if target_srv_safe is not None and safe_name(srv).lower() != target_srv_safe:
                        continue

                    server_logs.setdefault(srv, []).append((entry.path, entry.name, mtime, sid_str))
    except Exception as exc:
        log_error(f"Error scanning sessions_dir {sessions_dir}: {exc}")
        return 0

    for srv, logs in server_logs.items():
        # Keep logs younger than min_retention_seconds protected.
        # Among logs older than min_retention_seconds, retain only up to max_logs_per_server newest.
        fresh_logs = [entry for entry in logs if (now - entry[2]) < min_retention_seconds]
        old_logs = [entry for entry in logs if (now - entry[2]) >= min_retention_seconds]

        # Old logs are sorted newest to oldest
        old_logs.sort(key=lambda x: x[2], reverse=True)

        if len(old_logs) <= max_logs_per_server:
            continue

        candidates = old_logs[max_logs_per_server:]
        for path, fname, mtime, sid_str in candidates:
            try:
                os.remove(path)
                deleted_count += 1
            except OSError:
                continue

            if runs_dir and os.path.isdir(runs_dir) and sid_str:
                srv_token = f"__{srv}__{sid_str}__r"
                legacy_token = f"__{sid_str}__r"
                try:
                    with os.scandir(runs_dir) as rit:
                        for rentry in rit:
                            if rentry.is_file() and rentry.name.endswith(".log"):
                                if srv_token in rentry.name or (srv == "default" and legacy_token in rentry.name):
                                    try:
                                        os.remove(rentry.path)
                                        deleted_count += 1
                                    except OSError:
                                        pass
                except Exception as exc:
                    log_error(f"Error cascading run logs cleanup for {srv}/{sid_str}: {exc}")

    return deleted_count

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

COMPILED_PROMPT_PATTERNS = [
    re.compile(r"(?:(?:\r?\n|\r|\A)\s*(?:[a-zA-Z0-9._-]+\s*)?|\s+)(\([^)]+\)\s*>[ \t]*)$"), # router (config)> or (config)>
    re.compile(r"(?:(?:\r?\n|\r|\A)\s*)(>[ \t]*)$"),             # > alone on line
    re.compile(r"(?:(?:\r?\n|\r|\A)\s*)([/~][^\s]*\s*#[ \t]*)$"), # /path #
    re.compile(r"(?:(?:\r?\n|\r|\A)\s*)([/~][^\s]*\s*\$[ \t]*)$"), # /path $
    re.compile(r"(?:(?:\r?\n|\r|\A)\s*)([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:.*[#$][ \t]*)$"), # user@host:path$
    re.compile(r"(?:(?:\r?\n|\r|\A)\s*)([#$][ \t]+)$"),           # # or $ alone on line (requires space/tab after symbol)
]

def find_prompt(output: str) -> Optional[str]:
    if not output:
        return None
    
    # 1. Clean ANSI from a larger chunk (e.g., last 2000 chars)
    # This prevents ANSI codes from hiding the prompt or splitting it
    chunk_size = 2000
    tail = output[-chunk_size:] if len(output) > chunk_size else output
    
    # Remove ANSI codes *first*
    clean_tail = ANSI_ESCAPE.sub("", tail)
    
    # Strip only trailing newlines to preserve horizontal whitespace (e.g. prompt trailing spaces)
    clean_tail_no_nl = clean_tail.rstrip("\r\n")
    if not clean_tail_no_nl:
        return None

    for pattern in COMPILED_PROMPT_PATTERNS:
        match = pattern.search(clean_tail_no_nl)
        if match:
            return match.group(1)
            
    return None

def has_prompt(output: str) -> bool:
    return find_prompt(output) is not None

def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

@functools.lru_cache(maxsize=512)
def _compile_filter_regex(pattern: str) -> re.Pattern:
    return re.compile(pattern)

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
        if len(regex) > 500:
            return {
                "success": False,
                "error": f"regex exceeds maximum allowed length of 500 characters (received {len(regex)})",
                "filtered": False,
                "matched_lines": 0,
                "scanned_chars": scanned_chars,
                "output": "",
            }
        if any(len(line) > _MAX_REGEX_LINE for line in lines):
            return {
                "success": False,
                "error": f"line too long for regex, use contains (max {_MAX_REGEX_LINE} characters)",
                "filtered": False,
                "matched_lines": 0,
                "scanned_chars": scanned_chars,
                "output": "",
            }
        # A timed-out re.search keeps running inside CPython and cannot be interrupted.
        # The slot stays occupied until that search returns. Releasing it at join time
        # would start another search on top of the live one and turn a 2-thread cap
        # into unbounded CPU use. Nested quantifiers are rejected before a slot is
        # taken. (a|aa)+ is not: the same shape as (foo|bar)+ is linear, and a static
        # check cannot tell them apart. No os.kill and no re2 dependency.
        if _NESTED_QUANTIFIER.search(regex):
            return {
                "success": False,
                "error": "nested quantifiers are not allowed",
                "filtered": False,
                "matched_lines": 0,
                "scanned_chars": scanned_chars,
                "output": "",
            }
        global _regex_workers_alive
        with _regex_workers_lock:
            if _regex_workers_alive >= _MAX_REGEX_WORKERS:
                return {
                    "success": False,
                    "error": "too many regex workers are still running",
                    "filtered": False,
                    "matched_lines": 0,
                    "scanned_chars": scanned_chars,
                    "output": "",
                }
            _regex_workers_alive += 1
        try:
            compiled = _compile_filter_regex(regex)
        except Exception as exc:
            with _regex_workers_lock:
                _regex_workers_alive -= 1
            return {
                "success": False,
                "error": f"invalid regex: {exc}",
                "filtered": False,
                "matched_lines": 0,
                "scanned_chars": scanned_chars,
                "output": "",
            }

        # Safe matching with timeout protection against catastrophic backtracking (ReDoS)
        matched = []
        timeout_sec = 2.0
        start_t = time.time()
        worker_err = [None]

        def _regex_worker():
            global _regex_workers_alive
            try:
                for line in lines:
                    if time.time() - start_t > timeout_sec:
                        worker_err[0] = f"regex matching timed out after {timeout_sec}s (catastrophic backtracking / ReDoS detected)"
                        return
                    if compiled.search(line):
                        matched.append(line)
            except Exception as e:
                worker_err[0] = str(e)
            finally:
                with _regex_workers_lock:
                    _regex_workers_alive -= 1

        worker_th = threading.Thread(target=_regex_worker, daemon=True)
        worker_th.start()
        worker_th.join(timeout=timeout_sec + 0.1)
        elapsed = time.time() - start_t

        if worker_th.is_alive() or elapsed > timeout_sec or worker_err[0]:
            err_msg = worker_err[0] or f"regex matching timed out after {timeout_sec}s (catastrophic backtracking / ReDoS detected)"
            return {
                "success": False,
                "error": err_msg,
                "filtered": False,
                "matched_lines": 0,
                "scanned_chars": scanned_chars,
                "output": "",
            }

        lines = matched
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

