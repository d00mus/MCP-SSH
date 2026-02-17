import sys
import json
import argparse
from src import config
from src.utils import (
    log_error, resolve_runtime_paths, make_cache_dirs
)
from src.utils import (
    log_error, resolve_runtime_paths, make_cache_dirs
)
from src.server import handle_request

manager = None

def main() -> None:
    global manager
    from src.ssh import SessionManager
    parser = argparse.ArgumentParser(
        description="SSH MCP Server (compact tools, anti-hang timeout, background output buffering)"
    )
    parser.add_argument("--host", required=True, help="SSH host")
    parser.add_argument("--user", required=True, help="SSH username")
    parser.add_argument("--password", help="SSH password")
    parser.add_argument("--key", help="Path to SSH private key")
    parser.add_argument("--passphrase", help="Passphrase for SSH private key")
    parser.add_argument("--verify-host", action="store_true", help="Verify SSH host key (default: False)")
    parser.add_argument("--port", type=int, default=22, help="SSH port")
    parser.add_argument("--path", help="Additional PATH to export in shell")
    parser.add_argument("--project-root", help="Project root for local state")
    parser.add_argument("--cache-dir", help="Optional cache root override")
    args = parser.parse_args()

    if not args.password and not args.key:
        parser.error("Either --password or --key must be provided")

    config.SSH_HOST = args.host
    config.SSH_USER = args.user
    config.SSH_PASSWORD = args.password
    config.SSH_PORT = args.port
    config.SSH_KEY_PATH = args.key
    config.SSH_KEY_PASSPHRASE = args.passphrase
    config.SSH_VERIFY_HOST_KEY = args.verify_host
    config.EXTRA_PATH = args.path

    runtime_paths = resolve_runtime_paths(project_root_arg=args.project_root, cache_dir_arg=args.cache_dir)
    config.PROJECT_ROOT = runtime_paths["project_root"]
    config.PROJECT_TAG = runtime_paths["project_tag"]
    config.CACHE_DIRS = make_cache_dirs(runtime_paths["cache_root"])

    manager = SessionManager(config.CACHE_DIRS, config.PROJECT_TAG)
    from src.ssh import set_buffer_limit_checkers
    set_buffer_limit_checkers(manager.can_accept_more_buffer, manager.total_buffer_chars)

    log_error(
        f"SSH MCP started for {config.SSH_HOST}:{config.SSH_PORT}. "
        f"project_root={config.PROJECT_ROOT} cache={config.CACHE_DIRS['cache_root']}"
    )

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            response = handle_request(json.loads(line), manager)
            if response is not None:
                print(json.dumps(response, ensure_ascii=False), flush=True)
        except json.JSONDecodeError as exc:
            log_error(f"invalid json: {exc}")
        except Exception as exc:
            log_error(f"unexpected error: {exc}")

    log_error("shutting down...")
    manager.close_all()

if __name__ == "__main__":
    main()
