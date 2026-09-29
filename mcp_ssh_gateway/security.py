import functools
import re
from typing import List, Optional

# Read-only is a denylist of obvious write utilities, not a sandbox.
# python3 -c, perl -e and busybox sh stay allowed: a regex cannot see whether
# the interpreter will write, and banning the token rejects ordinary reads
# such as python3 -c 'print(1)'. Closing that hole needs an allowlist, which
# would also reject valid Keenetic and Linux debugging commands.
WRITE_COMMAND_PATTERN = re.compile(
    r"\b(rm|mv|cp|rsync|mkdir|rmdir|touch|chmod|chown|dd|format|mkfs|reboot|poweroff|halt|shutdown"
    r"|opkg|apt|yum|dnf|pip install|npm install|make install|tee|truncate|shred"
    r"|wget\s+-O|wget\s+--output-document|curl\s+-o)\b"
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


def check_command(command: str, blacklist: Optional[List[str]] = None, read_only: bool = False) -> Optional[str]:
    """Why the command must not run, or None if it may.

    Both checks are guardrails against a mistaken agent, not a security boundary."""
    for entry in blacklist or []:
        if entry and entry.strip() and get_blacklist_regex(entry).search(command):
            return f"Blocked by the command blacklist of this server (matched: '{entry}')."
    if read_only and WRITE_COMMAND_PATTERN.search(command):
        return "Blocked: this server is read-only and the command looks like a write."
    return None
