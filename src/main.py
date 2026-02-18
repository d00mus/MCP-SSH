import sys
import os
import io
import json
import argparse
from src.config import config
from src.utils import (
    log_error, resolve_runtime_paths, make_cache_dirs
)
from src.server import handle_request

manager = None

# Force UTF-8 I/O to avoid charmap encoding errors on Windows
# (e.g., docker outputs ✔ \u2714 which cp1252 can't encode)
_stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)


def _write_response(response: dict) -> None:
    """Write JSON-RPC response to stdout as UTF-8."""
    try:
        _stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        _stdout.flush()
    except Exception as exc:
        log_error(f"response write error: {exc}")
        # Fallback: escape all non-ASCII to guarantee safe output
        try:
            _stdout.write(json.dumps(response, ensure_ascii=True) + "\n")
            _stdout.flush()
        except Exception as exc2:
            log_error(f"response write fallback error: {exc2}")


def main() -> None:
    global manager
    from src.ssh import SessionManager
    
    # Pre-load from environment
    config.load_from_env()

    parser = argparse.ArgumentParser(
        description="SSH MCP Server (compact tools, anti-hang timeout, background output buffering)"
    )
    parser.add_argument("--host", help="SSH host (overrides SSH_HOST env)")
    parser.add_argument("--user", help="SSH username (overrides SSH_USER env)")
    parser.add_argument("--password", help="SSH password (overrides SSH_PASSWORD env)")
    parser.add_argument("--key", help="Path to SSH private key (overrides SSH_KEY_PATH env)")
    parser.add_argument("--passphrase", help="Passphrase for SSH private key (overrides SSH_KEY_PASSPHRASE env)")
    parser.add_argument("--verify-host", action="store_true", help="Verify SSH host key (default: True, use --no-verify-host to disable)")
    parser.add_argument("--no-verify-host", action="store_true", help="Disable SSH host key verification")
    parser.add_argument("--port", type=int, help="SSH port (overrides SSH_PORT env)")
    parser.add_argument("--path", help="Additional PATH to export in shell")
    parser.add_argument("--project-root", help="Project root for local state")
    parser.add_argument("--cache-dir", help="Optional cache root override")
    
    args = parser.parse_args()

    # Apply args over env vars
    if args.host: config.SSH_HOST = args.host
    if args.user: config.SSH_USER = args.user
    if args.password: config.SSH_PASSWORD = args.password
    if args.key: config.SSH_KEY_PATH = args.key
    if args.passphrase: config.SSH_KEY_PASSPHRASE = args.passphrase
    if args.port: config.SSH_PORT = args.port
    if args.path: config.EXTRA_PATH = args.path
    
    # Handle verify host logic
    if args.no_verify_host:
        config.SSH_VERIFY_HOST_KEY = False
    elif args.verify_host:
        config.SSH_VERIFY_HOST_KEY = True
    
    # Validation
    if not config.SSH_HOST:
        parser.error("SSH host is required (via --host or SSH_HOST env)")
    if not config.SSH_USER:
        parser.error("SSH user is required (via --user or SSH_USER env)")
    if not config.SSH_PASSWORD and not config.SSH_KEY_PATH:
        parser.error("Either password or key must be provided (via args or env)")

    runtime_paths = resolve_runtime_paths(project_root_arg=args.project_root, cache_dir_arg=args.cache_dir)
    config.PROJECT_ROOT = runtime_paths["project_root"]
    config.PROJECT_TAG = runtime_paths["project_tag"]
    config.CACHE_DIRS = make_cache_dirs(runtime_paths["cache_root"])

    manager = SessionManager(config.CACHE_DIRS, config.PROJECT_TAG)
    from src.ssh import set_buffer_limit_checkers
    set_buffer_limit_checkers(manager.can_accept_more_buffer, manager.total_buffer_chars)

    log_error(
        f"SSH MCP started for {config.SSH_HOST}:{config.SSH_PORT}. "
        f"project_root={config.PROJECT_ROOT} cache={config.CACHE_DIRS['cache_root']} "
        f"verify_host={config.SSH_VERIFY_HOST_KEY}"
    )

    for line in _stdin:
        line = line.strip()
        if not line:
            continue
        try:
            response = handle_request(json.loads(line), manager)
            if response is not None:
                _write_response(response)
        except json.JSONDecodeError as exc:
            log_error(f"invalid json: {exc}")
        except Exception as exc:
            log_error(f"unexpected error: {exc}")
            # Attempt to send an error response back so the client doesn't hang
            try:
                req_id = None
                try:
                    req_id = json.loads(line).get("id")
                except Exception:
                    pass
                err_response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": f"Internal error: {exc}"},
                }
                _write_response(err_response)
            except Exception:
                pass

    log_error("shutting down...")
    manager.close_all()

if __name__ == "__main__":
    main()
