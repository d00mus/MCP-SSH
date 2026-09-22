import os
import re
import json
import threading
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any

# ========= Static config =========
CONNECT_TIMEOUT = 10
KEEPALIVE_INTERVAL = 30
BUFFER_SIZE = 4096
HEALTH_CHECK_INTERVAL = 30

DEFAULT_WAIT_TIMEOUT = 5.0
MAX_WAIT_TIMEOUT = 120.0
DEFAULT_STARTUP_WAIT = 2.0
MAX_STARTUP_WAIT = 10.0
DEFAULT_HARD_TIMEOUT = 0.0  # 0 means disabled
MAX_HARD_TIMEOUT = 3600.0

MAX_BUFFER_CHARS = 2_000_000
MAX_TOTAL_BUFFER_CHARS = 200_000_000
DEFAULT_READ_MAX_LINES = 1000
DEFAULT_READ_MAX_CHARS = 50000
MAX_READ_MAX_LINES = 5000
MAX_READ_MAX_CHARS = 200000
DEFAULT_FILE_INSPECT_MAX_BYTES = 200000
MAX_FILE_INSPECT_MAX_BYTES = 2_000_000
DEFAULT_FILE_EDIT_MAX_BYTES = 1_000_000
MAX_FILE_EDIT_MAX_BYTES = 5_000_000
MAX_INLINE_WRITE_BYTES = 200000
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
MAX_LOG_FILE_BYTES = 20 * 1024 * 1024
DEFAULT_QUIET_COMPLETE_TIMEOUT = 2.5
MAX_QUIET_COMPLETE_TIMEOUT = 30.0
MAX_WORKERS = 32
MAX_SERVERS = 100
MAX_DEAD_SESSION_LOGS_PER_SERVER = 20
MIN_LOG_RETENTION_SECONDS = 7200  # 2 hours
DEFAULT_SOCKET_TIMEOUT = 30.0
DRAIN_BUFFER_SIZE = 65535

DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/bin:/opt/sbin"

# Configurable regexes for paging detection (e.g. --More--)
PAGER_REGEXES = [
    r"--\s*More\s*--",
    r"More\.\.\.",
    r"--More--",
    r"Press any key to continue",
    r"Press Enter to continue"
]
COMPILED_PAGER_REGEXES = [re.compile(p) for p in PAGER_REGEXES]

# Configurable regexes for interactive hangs/prompts detection
INTERACTIVE_PROMPT_PATTERNS = [
    r"(?i)(password|passphrase|secret|token)\s*:\s*$",
    r"\[y/n\]\s*$",
    r"\[Y/n\]\s*$",
    r"\[y/N\]\s*$",
    r"Do you want to continue\??\s*$",
    r"\(yes/no\)\??\s*$",
]
COMPILED_INTERACTIVE_PATTERNS = [re.compile(p) for p in INTERACTIVE_PROMPT_PATTERNS]

# ========= Output cleanup =========
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
PROMPT_ONLY_LINE = re.compile(r"^\s*(\([^)]*\)\s*[>#]|[>#])\s*$")

# ========= Server Target Configuration =========
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
    max_sessions: int = 10
    origin: str = "file"

    @classmethod
    def from_dict(cls, alias: str, data: Dict[str, Any]) -> "ServerTargetConfig":
        def _expand(val: Any) -> Any:
            if isinstance(val, str):
                return os.path.expandvars(os.path.expanduser(val))
            return val

        def _expand_secret(val: Any) -> Any:
            if isinstance(val, str):
                if "${" in val:
                    return re.sub(r"\$\{([A-Za-z0-9_]+)\}", lambda m: os.environ.get(m.group(1), m.group(0)), val)
                return val
            return val

        try:
            port = int(data.get("port") or 22)
        except (ValueError, TypeError):
            port = 22
        verify_host = data.get("verify_host", True)
        if isinstance(verify_host, str):
            verify_host = verify_host.lower() in ("true", "1", "yes")
        read_only = data.get("read_only", False)
        if isinstance(read_only, str):
            read_only = read_only.lower() in ("true", "1", "yes")
        blacklist = data.get("command_blacklist", [])
        if isinstance(blacklist, str):
            blacklist = [c.strip() for c in blacklist.split(",") if c.strip()]

        raw_key = data.get("key_path") or data.get("key")
        raw_pass = data.get("password")
        raw_key_pass = data.get("key_passphrase") or data.get("passphrase")
        raw_extra_path = data.get("extra_path") or data.get("path")
        try:
            max_sessions = int(data.get("max_sessions") or 10)
        except (ValueError, TypeError):
            max_sessions = 10

        return cls(
            alias=alias.strip(),
            host=_expand(str(data.get("host", "")).strip()),
            port=port,
            user=_expand(str(data.get("user", "")).strip()),
            password=_expand_secret(raw_pass) if raw_pass is not None else None,
            key_path=_expand(raw_key) if raw_key is not None else None,
            key_passphrase=_expand_secret(raw_key_pass) if raw_key_pass is not None else None,
            verify_host=verify_host,
            extra_path=_expand(raw_extra_path) if raw_extra_path is not None else None,
            read_only=read_only,
            command_blacklist=blacklist,
            description=str(data.get("description", "")).strip(),
            max_sessions=max_sessions,
        )

    def to_dict(self, hide_secrets: bool = True) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "alias": self.alias,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "description": self.description,
            "verify_host": self.verify_host,
            "read_only": self.read_only,
            "extra_path": self.extra_path,
            "command_blacklist": self.command_blacklist,
            "max_sessions": self.max_sessions,
        }
        if not hide_secrets:
            d["password"] = self.password
            d["key_path"] = self.key_path
            d["key_passphrase"] = self.key_passphrase
        return d


class ServersRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._servers: Dict[str, ServerTargetConfig] = {}

    def register(self, server: ServerTargetConfig) -> None:
        with self._lock:
            self._servers[server.alias.lower()] = server

    def unregister(self, alias: str) -> None:
        with self._lock:
            self._servers.pop(alias.lower(), None)

    def get(self, name_or_ip: Optional[str]) -> Optional[ServerTargetConfig]:
        if not name_or_ip:
            return None
        target = str(name_or_ip).strip().lower()
        with self._lock:
            if target in self._servers:
                return self._servers[target]
            matches = [s for s in self._servers.values() if s.host.lower() == target]
            if len(matches) == 1:
                return matches[0]
            return None

    def find_by_prefix(self, prefix: Optional[str]) -> List[ServerTargetConfig]:
        with self._lock:
            if not prefix:
                return list(self._servers.values())
            pref = prefix.strip().lower()
            matched = []
            for alias, s in self._servers.items():
                if alias.startswith(pref) or s.host.lower().startswith(pref):
                    matched.append(s)
            return matched

    def list_all(self) -> List[ServerTargetConfig]:
        with self._lock:
            return list(self._servers.values())

    def as_dict(self) -> Dict[str, ServerTargetConfig]:
        with self._lock:
            return dict(self._servers)

    def aliases(self) -> List[str]:
        with self._lock:
            return [s.alias for s in self._servers.values()]

    def count(self) -> int:
        with self._lock:
            return len(self._servers)

    def clear(self) -> None:
        with self._lock:
            self._servers.clear()

    def load_from_dict(self, data: Dict[str, Any]) -> None:
        servers_data = data.get("servers", {})
        if isinstance(servers_data, dict) and servers_data:
            for alias, sdata in servers_data.items():
                if isinstance(sdata, dict):
                    cfg = ServerTargetConfig.from_dict(alias, sdata)
                    self.register(cfg)
        elif isinstance(servers_data, list):
            for sdata in servers_data:
                if isinstance(sdata, dict) and "alias" in sdata:
                    cfg = ServerTargetConfig.from_dict(sdata["alias"], sdata)
                    self.register(cfg)

        mcp_servers = data.get("mcpServers", {})
        if isinstance(mcp_servers, dict):
            for alias, entry in mcp_servers.items():
                if isinstance(entry, dict) and not self.get(alias):
                    cfg = self._parse_mcp_server_entry(alias, entry)
                    if cfg:
                        self.register(cfg)

    @staticmethod
    def _parse_mcp_server_entry(alias: str, entry: Dict[str, Any]) -> Optional[ServerTargetConfig]:
        args = entry.get("args", [])
        env = entry.get("env", {})
        host = ""
        user = ""
        port = 22
        password = env.get("SSH_PASSWORD")
        key_path = env.get("SSH_KEY_PATH")
        key_passphrase = env.get("SSH_KEY_PASSPHRASE")
        verify_host = True
        extra_path = env.get("EXTRA_PATH")
        read_only = False
        command_blacklist = []

        i = 0
        while i < len(args):
            arg = str(args[i])
            if arg == "--host" and i + 1 < len(args):
                host = str(args[i + 1]).strip()
                i += 2
            elif arg == "--user" and i + 1 < len(args):
                user = str(args[i + 1]).strip()
                i += 2
            elif arg == "--port" and i + 1 < len(args):
                try:
                    port = int(args[i + 1])
                except ValueError:
                    pass
                i += 2
            elif arg == "--password" and i + 1 < len(args):
                password = str(args[i + 1])
                i += 2
            elif arg == "--key" and i + 1 < len(args):
                key_path = str(args[i + 1])
                i += 2
            elif arg == "--passphrase" and i + 1 < len(args):
                key_passphrase = str(args[i + 1])
                i += 2
            elif arg == "--no-verify-host":
                verify_host = False
                i += 1
            elif arg == "--verify-host":
                verify_host = True
                i += 1
            elif arg == "--path" and i + 1 < len(args):
                extra_path = str(args[i + 1])
                i += 2
            elif arg == "--read-only":
                read_only = True
                i += 1
            elif arg == "--command-blacklist" and i + 1 < len(args):
                command_blacklist = [c.strip() for c in str(args[i + 1]).split(",") if c.strip()]
                i += 2
            else:
                i += 1

        if host:
            return ServerTargetConfig(
                alias=alias.strip(),
                host=host,
                port=port,
                user=user,
                password=password,
                key_path=key_path,
                key_passphrase=key_passphrase,
                verify_host=verify_host,
                extra_path=extra_path,
                read_only=read_only,
                command_blacklist=command_blacklist,
                description=f"Server '{alias}' ({host})"
            )
        return None

    def load_from_file(self, filepath: str) -> None:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.load_from_dict(data)

    def load_from_ssh_config(self, ssh_config_path: Optional[str] = None) -> None:
        path = ssh_config_path or os.path.expanduser("~/.ssh/config")
        if not os.path.isfile(path):
            return
        try:
            import paramiko
            ssh_cfg = paramiko.SSHConfig()
            with open(path, "r", encoding="utf-8") as f:
                ssh_cfg.parse(f)
            for host_entry in ssh_cfg.get_hostnames():
                if host_entry == "*":
                    continue
                if not self.get(host_entry):
                    lookup = ssh_cfg.lookup(host_entry)
                    hostname = lookup.get("hostname", host_entry)
                    user = lookup.get("user", "")
                    port = 22
                    try:
                        port = int(lookup.get("port", 22))
                    except (ValueError, TypeError):
                        pass
                    key_files = lookup.get("identityfile", [])
                    key_path = key_files[0] if key_files else None
                    cfg = ServerTargetConfig(
                        alias=host_entry,
                        host=hostname,
                        port=port,
                        user=user,
                        key_path=key_path,
                        description=f"Host from ~/.ssh/config ({host_entry})"
                    )
                    self.register(cfg)
        except Exception:
            pass


# ========= Runtime Configuration =========
class ServerConfig:
    def __init__(self):
        self.SSH_HOST: Optional[str] = None
        self.SSH_USER: Optional[str] = None
        self.SSH_PASSWORD: Optional[str] = None
        self.SSH_PORT: int = 22
        self.SSH_KEY_PATH: Optional[str] = None
        self.SSH_KEY_PASSPHRASE: Optional[str] = None
        self.SSH_VERIFY_HOST_KEY: bool = True  # Changed default to True for security
        self.EXTRA_PATH: Optional[str] = None
        self.PROJECT_ROOT: str = ""
        self.PROJECT_TAG: str = ""
        self.CACHE_DIRS: Dict[str, str] = {}
        self.READ_ONLY: bool = False
        self.COMMAND_BLACKLIST: list = []
        self.SERVERS_CONFIG_PATH: Optional[str] = None
        self.registry = ServersRegistry()

    def load_from_env(self):
        servers_config_env = os.environ.get("SSH_SERVERS_CONFIG")
        if servers_config_env:
            self.SERVERS_CONFIG_PATH = servers_config_env
            if os.path.isfile(servers_config_env):
                self.registry.load_from_file(servers_config_env)
            else:
                try:
                    data = json.loads(servers_config_env)
                    self.registry.load_from_dict(data)
                except Exception:
                    pass

        self.SSH_HOST = os.environ.get("SSH_HOST", self.SSH_HOST)
        self.SSH_USER = os.environ.get("SSH_USER", self.SSH_USER)
        self.SSH_PASSWORD = os.environ.get("SSH_PASSWORD", self.SSH_PASSWORD)
        port_env = os.environ.get("SSH_PORT")
        if port_env:
            self.SSH_PORT = int(port_env)
        self.SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", self.SSH_KEY_PATH)
        self.SSH_KEY_PASSPHRASE = os.environ.get("SSH_KEY_PASSPHRASE", self.SSH_KEY_PASSPHRASE)
        
        verify_host_env = os.environ.get("SSH_VERIFY_HOST_KEY")
        if verify_host_env is not None:
            self.SSH_VERIFY_HOST_KEY = verify_host_env.lower() in ("true", "1", "yes")

        self.READ_ONLY = os.environ.get("SSH_READ_ONLY", "false").lower() in ("true", "1", "yes")
        blacklist_env = os.environ.get("SSH_COMMAND_BLACKLIST", "")
        if blacklist_env:
            self.COMMAND_BLACKLIST = [c.strip() for c in blacklist_env.split(",") if c.strip()]


# Global instance
config = ServerConfig()

