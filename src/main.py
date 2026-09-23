import sys
import os
import io
import json
import argparse
import threading
import atexit
import signal
from concurrent.futures import ThreadPoolExecutor
from src.config import (
    config, MAX_WORKERS, CONTROL_WORKERS, MAX_PENDING_REQUESTS, MAX_REQUEST_LINE_BYTES,
)
from src.utils import (
    log_error, resolve_runtime_paths, make_cache_dirs
)
from src.server import handle_request, is_control_request

# Force UTF-8 I/O to avoid charmap encoding errors on Windows
# (e.g., docker outputs ✔ \u2714 which cp1252 can't encode)
_stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)
_stdout_lock = threading.Lock()


def _write_response(response: dict) -> None:
    """Write JSON-RPC response to stdout as UTF-8."""
    with _stdout_lock:
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
                log_error(f"response write fallback error: {exc2}. Client connection likely closed.")


def process_request(req, manager, write_fn=_write_response) -> None:
    """Handle one parsed JSON-RPC request, send error or response via write_fn."""
    try:
        response = handle_request(req, manager)
        if response is not None:
            write_fn(response)
    except Exception as exc:
        log_error(f"unexpected error processing request: {exc}")
        try:
            req_id = req.get("id") if isinstance(req, dict) else None
            if req_id is not None:
                err_response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32603, "message": f"Internal error: {exc}"},
                }
                write_fn(err_response)
        except Exception:
            pass


def process_line(raw_line: str, manager, write_fn=_write_response) -> None:
    """Process a single JSON-RPC line from stdin, send error or response via write_fn."""
    try:
        req = json.loads(raw_line)
    except json.JSONDecodeError as exc:
        log_error(f"invalid json: {exc}")
        write_fn({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {exc}"}
        })
        return
    except Exception as exc:
        log_error(f"unexpected decode error: {exc}")
        write_fn({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {exc}"}
        })
        return
    process_request(req, manager, write_fn)


def _run_worker(req, manager, write_fn, pending) -> None:
    try:
        process_request(req, manager, write_fn)
    finally:
        if pending is not None:
            pending.release()


def _busy_response(req) -> dict:
    req_id = req.get("id") if isinstance(req, dict) else None
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {
            "code": -32000,
            "message": (
                f"server busy: {MAX_PENDING_REQUESTS} requests are already in flight. "
                "Wait for running commands (read/signal) or send fewer parallel ones, then retry."
            ),
        },
    }


def submit_request(raw_line, manager, write_fn, main_executor, control_executor, pending) -> None:
    """Route one stdin line to a worker with admission control (F5).

    Control calls run on their own small pool so Ctrl+C is never queued behind long
    runs; other requests are bounded by `pending`, so a burst gets an immediate busy
    answer instead of growing an unbounded queue.
    """
    if len(raw_line) > MAX_REQUEST_LINE_BYTES:
        log_error(f"request line too large: {len(raw_line)} bytes")
        write_fn({
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32600,
                "message": f"request line too large ({len(raw_line)} > {MAX_REQUEST_LINE_BYTES} bytes)",
            },
        })
        return
    try:
        req = json.loads(raw_line)
    except Exception as exc:
        log_error(f"invalid json: {exc}")
        write_fn({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"Parse error: {exc}"}
        })
        return

    control = is_control_request(req)
    if not control and not pending.acquire(blocking=False):
        log_error("request refused: in-flight limit reached")
        write_fn(_busy_response(req))
        return
    target = control_executor if control else main_executor
    try:
        target.submit(_run_worker, req, manager, write_fn, None if control else pending)
    except RuntimeError:
        if not control:
            pending.release()
        log_error("request dropped: executor is shutting down")


def main() -> None:
    from src.manager import MultiServerManager
    from src.session import set_buffer_limit_checkers
    
    # Pre-load from environment
    config.load_from_env()

    parser = argparse.ArgumentParser(
        description="SSH MCP Server (multi-server support, compact tools, anti-hang timeout, background buffering)"
    )
    parser.add_argument("--servers-config", help="Path to JSON file with multi-server configurations (or inline JSON)")
    parser.add_argument("--path", help="Additional PATH to export in shell")
    parser.add_argument("--project-root", help="Project root for local state")
    parser.add_argument("--cache-dir", help="Optional cache root override")
    parser.add_argument("--read-only", action="store_true", help="Enable read-only sandbox mode")
    parser.add_argument("--command-blacklist", help="Comma-separated list of prohibited commands")
    parser.add_argument("--import-ssh-config", action="store_true",
                        help="Also register hosts from ~/.ssh/config (key auth; they survive hot-reloads)")
    parser.add_argument("--tool-profile", choices=["lean", "full"], default="full",
                        help="Tool catalog: 'lean' exposes the 6 everyday tools (smaller catalog for small models), 'full' adds admin/diagnostic tools")
    parser.add_argument("--log-output", choices=["full", "meta", "off"], default="meta",
                        help="Log policy: 'full' stores raw output chunks, 'meta' lifecycle+commands only (default), 'off' disables logging")
    parser.add_argument("--allow-system-temp", action="store_true",
                        help="Allow the file tool to use the system temp directory (default: project root and cache dir only)")
    parser.add_argument("--allow-gateway-dir", action="store_true",
                        help="Allow the file tool to touch the gateway install directory (gateway development only)")
    
    args = parser.parse_args()

    # Load multi-server config if passed via CLI argument
    if args.servers_config:
        config.SERVERS_CONFIG_PATH = args.servers_config
        if os.path.isfile(args.servers_config):
            try:
                config.registry.load_from_file(args.servers_config)
            except Exception as e:
                parser.error(f"Failed to load servers config from '{args.servers_config}': {e}")
        else:
            try:
                data = json.loads(args.servers_config)
                config.registry.load_from_dict(data)
            except Exception as e:
                parser.error(f"Failed to parse inline JSON from --servers-config: {e}")

    if args.path: config.EXTRA_PATH = args.path
    if args.read_only: config.READ_ONLY = True
    if args.allow_system_temp: config.ALLOW_SYSTEM_TEMP = True
    if args.allow_gateway_dir: config.ALLOW_GATEWAY_DIR = True
    config.LOG_OUTPUT = args.log_output
    config.TOOL_PROFILE = args.tool_profile
    if args.import_ssh_config:
        config.registry.load_from_ssh_config()
    if args.command_blacklist:
        config.COMMAND_BLACKLIST = [c.strip() for c in args.command_blacklist.split(",") if c.strip()]
    
    # Validation & synchronization
    if config.registry.count() == 0 and not args.servers_config and not config.SERVERS_CONFIG_PATH:
        # Check default servers.json in cwd or next to mcp-server.py
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        candidates = [
            "servers.json",
            os.path.join(script_dir, "servers.json")
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                try:
                    config.registry.load_from_file(candidate)
                    config.SERVERS_CONFIG_PATH = candidate
                    break
                except Exception as e:
                    log_error(f"Failed to load default servers file '{candidate}': {e}")

    if config.registry.count() == 0:
        parser.error("No SSH servers configured. Provide --servers-config (or SSH_SERVERS_CONFIG) or ensure servers.json exists.")

    runtime_paths = resolve_runtime_paths(project_root_arg=args.project_root, cache_dir_arg=args.cache_dir)
    config.PROJECT_ROOT = runtime_paths["project_root"]
    config.PROJECT_TAG = runtime_paths["project_tag"]
    config.CACHE_DIRS = make_cache_dirs(runtime_paths["cache_root"])

    manager = MultiServerManager(config.CACHE_DIRS, config.PROJECT_TAG, registry=config.registry, config_path=config.SERVERS_CONFIG_PATH)
    set_buffer_limit_checkers(manager.can_accept_more_buffer, manager.total_buffer_chars)

    server_names = ", ".join(config.registry.aliases())
    log_error(
        f"SSH MCP started with {config.registry.count()} server(s): [{server_names}]. "
        f"project_root={config.PROJECT_ROOT} cache={config.CACHE_DIRS['cache_root']}"
    )

    # Sync run holds a worker until wait_timeout. signal and session_close get their
    # own control pool so they are never delayed by that (F5); other requests are
    # bounded by MAX_PENDING_REQUESTS and get an immediate busy answer instead of
    # queueing without limit.
    executor = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="mcp-worker")
    control_executor = ThreadPoolExecutor(max_workers=CONTROL_WORKERS, thread_name_prefix="mcp-control")
    pending = threading.BoundedSemaphore(MAX_PENDING_REQUESTS)

    shutdown_done = threading.Event()

    def _shutdown_gracefully():
        if shutdown_done.is_set():
            return
        shutdown_done.set()
        log_error("shutting down...")
        try:
            manager.close_all()
        except Exception as e:
            log_error(f"Manager close_all error: {e}")
        try:
            executor.shutdown(wait=True, cancel_futures=False)
        except Exception as e:
            log_error(f"Executor shutdown error: {e}")
        try:
            control_executor.shutdown(wait=True, cancel_futures=False)
        except Exception as e:
            log_error(f"Control executor shutdown error: {e}")

    atexit.register(_shutdown_gracefully)

    def _signal_handler(sig, frame):
        log_error(f"Received signal {sig}, terminating gracefully...")
        try:
            _stdin.close()
        except Exception:
            pass
        _shutdown_gracefully()
        sys.exit(0)

    try:
        signal.signal(signal.SIGINT, _signal_handler)
    except Exception:
        pass

    if hasattr(signal, "SIGTERM"):
        try:
            signal.signal(signal.SIGTERM, _signal_handler)
        except Exception:
            pass

    for line in _stdin:
        line = line.strip()
        if not line:
            continue
        submit_request(line, manager, _write_response, executor, control_executor, pending)

    _shutdown_gracefully()

if __name__ == "__main__":
    main()
