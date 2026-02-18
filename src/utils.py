import os
import re
import sys
import json
import time
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional, List
from src.config import (
    ANSI_ESCAPE, CONTROL_CHARS, PROMPT_ONLY_LINE, MAX_READ_MAX_LINES, config
)

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

def resolve_local_path(path: str) -> str:
    if not path:
        return ""
    expanded = os.path.expanduser(os.path.expandvars(path.strip()))
    absolute_path = os.path.abspath(expanded)
    
    # Sandboxing check
    project_root = os.path.abspath(config.PROJECT_ROOT) if config.PROJECT_ROOT else ""
    if project_root:
        # Check if the resolved path starts with the project root
        common_prefix = os.path.commonpath([project_root, absolute_path])
        if common_prefix != project_root:
            # Allow temp directory as a special exception if needed, or strict sandbox?
            # For now, let's just log a warning and return empty to simulate "not found/blocked"
            # or raise an error. Returning empty string is safer to fail gracefully.
            # But the user might want explicit failure. 
            # Let's enforce it strictly.
            log_error(f"Security: Path '{path}' resolves to '{absolute_path}' which is outside project root '{project_root}'. Access denied.")
            return ""
            
    return absolute_path

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

def find_prompt(output: str) -> Optional[str]:
    if not output:
        return None
    
    # 1. Clean ANSI from a larger chunk (e.g., last 2000 chars)
    # This prevents ANSI codes from hiding the prompt or splitting it
    chunk_size = 2000
    tail = output[-chunk_size:] if len(output) > chunk_size else output
    
    # Remove ANSI codes *first*
    clean_tail = ANSI_ESCAPE.sub("", tail)
    
    # 2. Lookback window
    # We want to match prompts at the end of the clean text.
    # The prompt might be "user@host:~$ " or just "> "
    
    prompt_patterns = [
        r"(\([^)]+\)\s*>\s*)$", # (config)>
        r"(>\s*)$",             # >
        r"([/~][^\s]*\s*#\s*)$", # /path #
        r"([/~][^\s]*\s*\$\s*)$", # /path $
        r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:.*[#$]\s*)$", # user@host:path$
        r"([#$]\s*)$",           # # or $
    ]
    
    clean_tail_stripped = clean_tail.rstrip()
    if not clean_tail_stripped:
         # If stripping removes everything, it might be just whitespace after a prompt? 
         # Or empty. Let's try matching on the non-stripped tail if it ends with space
         pass

    # Check against stripped end first
    for pattern in prompt_patterns:
        match = re.search(pattern, clean_tail_stripped)
        if match:
            return match.group(1)
            
    return None

def has_prompt(output: str) -> bool:
    return find_prompt(output) is not None

def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()

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
