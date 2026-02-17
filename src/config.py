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

# ========= Runtime connection config (to be set in main) =========
SSH_HOST: Optional[str] = None
SSH_USER: Optional[str] = None
SSH_PASSWORD: Optional[str] = None
SSH_PORT = 22
SSH_KEY_PATH: Optional[str] = None
SSH_KEY_PASSPHRASE: Optional[str] = None
SSH_VERIFY_HOST_KEY: bool = False
EXTRA_PATH: Optional[str] = None
PROJECT_ROOT: str = ""
PROJECT_TAG: str = ""
CACHE_DIRS: Dict[str, str] = {}

# ========= Output cleanup =========
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
PROMPT_ONLY_LINE = re.compile(r"^\s*(\([^)]*\)\s*[>#]?|[>#])\s*$")
