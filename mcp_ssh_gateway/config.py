"""Server definitions (servers.json, ~/.ssh/config) and runtime settings."""

import json
import os
import re
import sys
import threading
from dataclasses import dataclass, field, replace
from typing import Any, Dict, List, Optional

DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/bin:/opt/sbin"

# Tool argument limits.
DEFAULT_WAIT = 10.0
MAX_WAIT = 300.0
MAX_TIMEOUT = 24 * 3600.0
DEFAULT_LINES = 200
MAX_LINES = 5000
DEFAULT_MAX_CHARS = 20_000

_ENV_REFERENCE = re.compile(r"\$\{([A-Za-z0-9_]+)\}")
_TRUE = ("true", "1", "yes")


def _warn(message: str) -> None:
    print(f"[SSH-MCP] Warning: {message}", file=sys.stderr, flush=True)


def _flag(value: Any, default: bool) -> bool:
    if value is None:
        return default
    return value.lower() in _TRUE if isinstance(value, str) else bool(value)


def _expand(alias: str, value: str) -> str:
    """``~`` and ``${VAR}`` in a plain field; a reference that stays unresolved is reported."""
    expanded = os.path.expandvars(os.path.expanduser(value))
    if _ENV_REFERENCE.search(expanded) or "${" in expanded:
        _warn(f"server '{alias}': unresolved reference in {expanded!r} (only ${{NAME}} is supported)")
    return expanded


def _expand_secret(alias: str, value: str) -> str:
    """Only ``${NAME}`` is replaced: a password is opaque text, so a ``$HOME``, ``$1`` or ``%x%``
    inside it stays as written. An unset variable is an error: a literal "${VAR}" password
    would only surface later as a baffling "authentication failed"."""
    missing = sorted({name for name in _ENV_REFERENCE.findall(value) if name not in os.environ})
    if missing:
        raise ValueError(
            f"server '{alias}' references unset environment variables: {', '.join(missing)}. "
            "Export them before starting the gateway, or write the value literally.")
    if "${" in _ENV_REFERENCE.sub("", value):
        raise ValueError(f"server '{alias}': unsupported secret reference {value!r} (only ${{NAME}} works)")
    return _ENV_REFERENCE.sub(lambda match: os.environ[match.group(1)], value)


@dataclass(eq=True)
class ServerTargetConfig:
    alias: str
    host: str
    port: int = 22
    user: str = ""
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None
    verify_host: bool = True
    extra_path: Optional[str] = None
    read_only: bool = False
    command_blacklist: List[str] = field(default_factory=list)
    description: str = ""
    max_sessions: int = 8  # sshd allows 10 channels per connection; two stay free for SFTP
    shell: Optional[str] = None  # a POSIX shell to `exec` after login, for accounts with fish or tcsh
    imported: bool = False  # came from ~/.ssh/config, not from servers.json

    @classmethod
    def from_dict(cls, alias: str, data: Dict[str, Any]) -> "ServerTargetConfig":
        alias = alias.strip()
        blacklist = data.get("command_blacklist", [])
        if isinstance(blacklist, str):
            blacklist = [item.strip() for item in blacklist.split(",") if item.strip()]

        def text(key: str) -> Optional[str]:
            value = data.get(key)
            return _expand(alias, str(value)) if value not in (None, "") else None

        def secret(key: str) -> Optional[str]:
            value = data.get(key)
            return _expand_secret(alias, str(value)) if value not in (None, "") else None

        shell = str(data.get("shell") or "").strip()
        if "\n" in shell or "\r" in shell:
            raise ValueError(f"server '{alias}': 'shell' must be one line, e.g. \"bash\" or \"/usr/bin/zsh\"")

        return cls(
            alias=alias,
            host=text("host") or "",
            port=_int(data.get("port"), 22),
            user=text("user") or "",
            password=secret("password"),
            key_path=text("key_path"),
            key_passphrase=secret("key_passphrase"),
            verify_host=_flag(data.get("verify_host"), True),
            extra_path=text("extra_path"),
            read_only=_flag(data.get("read_only"), False),
            command_blacklist=list(blacklist),
            description=str(data.get("description", "")).strip(),
            max_sessions=_int(data.get("max_sessions"), cls.max_sessions),
            shell=shell or None,
        )

    def with_policy(self, read_only: bool, blacklist: List[str]) -> "ServerTargetConfig":
        """This server with the gateway-wide guardrails added to its own."""
        return replace(
            self,
            read_only=self.read_only or read_only,
            command_blacklist=sorted(set(self.command_blacklist) | set(blacklist)),
        )

    def connection_key(self) -> tuple:
        """What a running connection depends on: a change here needs a new connection."""
        return (self.host, self.port, self.user, self.password, self.key_path,
                self.key_passphrase, self.verify_host)


def _int(value: Any, default: int) -> int:
    try:
        return int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        return default


class ServersRegistry:
    """The configured servers, looked up by alias (case-insensitive) or unambiguous host."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._servers: Dict[str, ServerTargetConfig] = {}

    def register(self, server: ServerTargetConfig) -> None:
        with self._lock:
            self._servers[server.alias.lower()] = server

    def unregister(self, alias: str) -> None:
        with self._lock:
            self._servers.pop(alias.lower(), None)

    def get(self, name: Optional[str]) -> Optional[ServerTargetConfig]:
        if not name:
            return None
        key = str(name).strip().lower()
        with self._lock:
            if key in self._servers:
                return self._servers[key]
            by_host = [s for s in self._servers.values() if s.host.lower() == key]
            return by_host[0] if len(by_host) == 1 else None

    def all(self) -> List[ServerTargetConfig]:
        with self._lock:
            return list(self._servers.values())

    def aliases(self) -> List[str]:
        return [server.alias for server in self.all()]

    def count(self) -> int:
        with self._lock:
            return len(self._servers)

    def load_dict(self, data: Dict[str, Any]) -> None:
        """``{"servers": {"alias": {...}}}`` (a list of objects with an "alias" also works)."""
        servers = data.get("servers", {})
        if isinstance(servers, dict):
            entries = list(servers.items())
        elif isinstance(servers, list):
            entries = [(entry["alias"], entry) for entry in servers if isinstance(entry, dict) and "alias" in entry]
        else:
            entries = []
        for alias, entry in entries:
            if isinstance(entry, dict):
                self.register(ServerTargetConfig.from_dict(alias, entry))

    def load_file(self, path: str) -> None:
        with open(path, encoding="utf-8") as handle:
            self.load_dict(json.load(handle))

    def import_ssh_config(self, path: Optional[str] = None) -> int:
        """Register the hosts of ~/.ssh/config that are not configured yet (key authentication)."""
        import paramiko
        path = path or os.path.expanduser("~/.ssh/config")
        if not os.path.isfile(path):
            return 0
        parsed = paramiko.SSHConfig()
        with open(path, encoding="utf-8") as handle:
            parsed.parse(handle)
        added = 0
        for name in parsed.get_hostnames():
            if name == "*" or "*" in name or "?" in name or self.get(name):
                continue
            entry = parsed.lookup(name)
            keys = entry.get("identityfile", [])
            self.register(ServerTargetConfig(
                alias=name, host=entry.get("hostname", name), port=_int(entry.get("port"), 22),
                user=entry.get("user", ""), key_path=keys[0] if keys else None,
                description=f"from ~/.ssh/config ({name})", imported=True))
            added += 1
        return added


@dataclass
class Settings:
    """Gateway-wide runtime settings, decided at start-up."""
    project_root: Optional[str]          # the local folder of the file tool; None: local files are off
    cache_root: str
    servers_path: Optional[str] = None
    log_policy: str = "meta"
    read_only: bool = False
    command_blacklist: List[str] = field(default_factory=list)
    allow_add_server: bool = False       # expose the server_add tool
    allow_system_temp: bool = False      # the file tool may use the system temp directory
    allow_gateway_dir: bool = False      # the file tool may touch the gateway's own files

    @property
    def known_hosts_path(self) -> str:
        return os.path.join(self.cache_root, "known_hosts")
