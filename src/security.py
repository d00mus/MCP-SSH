import re
import functools
from typing import Optional, Dict, Any, List

# Read-only is a denylist of obvious write utilities, not a sandbox.
# python3 -c, perl -e and busybox sh stay allowed: a regex cannot see whether
# the interpreter will write, and banning the token rejects ordinary reads
# such as python3 -c 'print(1)'. Closing that hole needs an allowlist, which
# would also reject valid Keenetic and Linux debugging commands.
WRITE_COMMAND_PATTERN = re.compile(
    r"\b(rm|mv|cp|rsync|mkdir|rmdir|touch|chmod|chown|dd|format|mkfs|reboot|poweroff|halt|shutdown|opkg|apt|yum|dnf|pip install|npm install|make install|wget\s+-O|wget\s+--output-document|curl\s+-o|tee|truncate|shred)\b"
    r"|(?:\binstall\s+(?:-[a-zA-Z]|[\/~a-zA-Z0-9_]))"
    r"|\bsed\b.*(?:\s-[^\s]*i\b|--in-place\b)"
    r"|\btar\b.*(?:\s-[a-zA-Z]*x[a-zA-Z]*|--extract)\b"
    r"|(?<!['\"])(?:>>|>\||(?<![<>=!])>)\s*(?!/dev/null\b|&[12]\b)[\/~a-zA-Z_\$\"'.]",
    re.IGNORECASE
)

@functools.lru_cache(maxsize=512)
def get_blacklist_regex(blacklisted: str) -> re.Pattern:
    """Precompiles and caches blacklist regex with flexible whitespace matching and word boundary detection."""
    clean_item = blacklisted.strip()
    pattern_body = re.escape(clean_item).replace(r"\ ", r"\s+")
    lead = r"\b" if (clean_item and (clean_item[0].isalnum() or clean_item[0] == "_")) else ""
    trail = r"\b" if (clean_item and (clean_item[-1].isalnum() or clean_item[-1] == "_")) else ""
    return re.compile(f"{lead}{pattern_body}{trail}", re.IGNORECASE)

def escape_shell_path(path: str) -> str:
    """Safely escapes single quotes for remote POSIX shell single-quoted argument."""
    if any(c in path for c in ("\n", "\r", "\x00")):
        raise ValueError("Path contains invalid newline or control characters")
    return path.replace("'", "'\\''")

def check_command_security(
    command: str,
    server_alias: str,
    numeric_sid: int,
    server_blacklist: Optional[List[str]] = None,
    global_blacklist: Optional[List[str]] = None,
    server_read_only: bool = False,
    global_read_only: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Validates a command against server and global blacklists and read-only policies.
    Returns None if permitted, or error dict if blocked.
    """
    effective_blacklist = set(server_blacklist or []) | set(global_blacklist or [])
    for blacklisted in effective_blacklist:
        if not blacklisted or not blacklisted.strip():
            continue
        regex = get_blacklist_regex(blacklisted)
        if regex.search(command):
            return {
                "success": False,
                "error": f"Security: Command is blocked by command blacklist on server '{server_alias}' (matched: '{blacklisted}').",
                "session_id": f"{server_alias}/{numeric_sid}",
                "numeric_session_id": numeric_sid,
                "server": server_alias,
            }

    if server_read_only or global_read_only:
        if WRITE_COMMAND_PATTERN.search(command):
            return {
                "success": False,
                "error": f"Security: Write command is blocked in read-only sandbox mode on server '{server_alias}'.",
                "session_id": f"{server_alias}/{numeric_sid}",
                "numeric_session_id": numeric_sid,
                "server": server_alias,
            }

    return None
