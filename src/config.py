import os
import re
from typing import Optional, Dict

# ========= Static config =========
CONNECT_TIMEOUT = 10
KEEPALIVE_INTERVAL = 30
BUFFER_SIZE = 4096
HEALTH_CHECK_INTERVAL = 30

DEFAULT_WAIT_TIMEOUT = 20.0
MAX_WAIT_TIMEOUT = 120.0
DEFAULT_STARTUP_WAIT = 2.0
MAX_STARTUP_WAIT = 10.0
DEFAULT_HARD_TIMEOUT = 0.0  # 0 means disabled
MAX_HARD_TIMEOUT = 3600.0

MAX_BUFFER_CHARS = 2_000_000
MAX_TOTAL_BUFFER_CHARS = 200_000_000
DEFAULT_READ_MAX_LINES = 200
DEFAULT_READ_MAX_CHARS = 20000
MAX_READ_MAX_LINES = 5000
MAX_READ_MAX_CHARS = 200000
DEFAULT_FILE_INSPECT_MAX_BYTES = 200000
MAX_FILE_INSPECT_MAX_BYTES = 2_000_000
DEFAULT_FILE_EDIT_MAX_BYTES = 1_000_000
MAX_FILE_EDIT_MAX_BYTES = 5_000_000
MAX_INLINE_WRITE_BYTES = 200000
DEFAULT_QUIET_COMPLETE_TIMEOUT = 2.5
MAX_QUIET_COMPLETE_TIMEOUT = 30.0

DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/opt/bin:/opt/sbin"

# ========= Output cleanup =========
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
PROMPT_ONLY_LINE = re.compile(r"^\s*(\([^)]*\)\s*[>#]?|[>#])\s*$")

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

    def load_from_env(self):
        self.SSH_HOST = os.environ.get("SSH_HOST", self.SSH_HOST)
        self.SSH_USER = os.environ.get("SSH_USER", self.SSH_USER)
        self.SSH_PASSWORD = os.environ.get("SSH_PASSWORD", self.SSH_PASSWORD)
        self.SSH_PORT = int(os.environ.get("SSH_PORT", self.SSH_PORT))
        self.SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", self.SSH_KEY_PATH)
        self.SSH_KEY_PASSPHRASE = os.environ.get("SSH_KEY_PASSPHRASE", self.SSH_KEY_PASSPHRASE)
        
        verify_host_env = os.environ.get("SSH_VERIFY_HOST_KEY")
        if verify_host_env is not None:
             self.SSH_VERIFY_HOST_KEY = verify_host_env.lower() in ("true", "1", "yes")

# Global instance
config = ServerConfig()
