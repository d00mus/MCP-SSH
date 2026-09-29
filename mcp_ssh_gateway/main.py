"""Command line entry point: an MCP server over stdio."""

import argparse
import atexit
import io
import json
import os
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from mcp_ssh_gateway import __version__
from mcp_ssh_gateway.config import ServersRegistry, Settings
from mcp_ssh_gateway.logs import POLICIES
from mcp_ssh_gateway.manager import MultiServerManager
from mcp_ssh_gateway.server import Gateway, handle_request, is_control_request

MAX_WORKERS = 32
CONTROL_WORKERS = 4
MAX_PENDING_REQUESTS = 64
MAX_REQUEST_LINE_BYTES = 8 * 1024 * 1024


def log(message: str) -> None:
    print(f"[SSH-MCP] {message}", file=sys.stderr, flush=True)


def default_cache_root() -> str:
    override = os.environ.get("SSH_MCP_CACHE_DIR")
    if override:
        return os.path.abspath(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "mcp-ssh-gateway")


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def split_words(text: str) -> "list[str]":
    return [word.strip() for word in text.split(",") if word.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-ssh-gateway", description="MCP server that gives an AI agent SSH terminals.")
    parser.add_argument("--version", action="version", version=f"mcp-ssh-gateway {__version__}")
    parser.add_argument("--servers-config",
                        help="Path to servers.json, or the JSON itself (default: $SSH_SERVERS_CONFIG, ./servers.json)")
    parser.add_argument("--import-ssh-config", action="store_true",
                        help="Also offer the hosts of ~/.ssh/config (key authentication)")
    parser.add_argument("--project-root",
                        help="Local folder the file tool may read and write (upload, download). "
                             "Without it, local files are off")
    parser.add_argument("--cache-dir", help="Where logs and known_hosts live (default: the user cache directory)")
    parser.add_argument("--log-output", choices=POLICIES, default="meta",
                        help="meta: commands and lifecycle only (default); full: also raw output; off: no logs")
    parser.add_argument("--read-only", action="store_true",
                        help="Refuse commands that look like writes, on every server (or SSH_READ_ONLY=1)")
    parser.add_argument("--command-blacklist",
                        help="Comma-separated words that must not appear in commands (or SSH_COMMAND_BLACKLIST)")
    parser.add_argument("--allow-add-server", action="store_true", help="Offer the server_add tool")
    parser.add_argument("--allow-system-temp", action="store_true", help="Let the file tool use the system temp folder")
    parser.add_argument("--allow-gateway-dir", action="store_true",
                        help="Let the file tool write into this program's folder")
    return parser


def load_registry(source: Optional[str], import_ssh_config: bool) -> "tuple[ServersRegistry, Optional[str]]":
    """(registry, path of servers.json when it is a file)."""
    registry = ServersRegistry()
    source = source or os.environ.get("SSH_SERVERS_CONFIG")
    path: Optional[str] = None
    if not source:
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        source = next((p for p in ("servers.json", os.path.join(here, "servers.json")) if os.path.isfile(p)), None)
    if source and os.path.isfile(source):
        path = os.path.abspath(source)
        registry.load_file(path)
    elif source:
        registry.load_dict(json.loads(source))
    if import_ssh_config:
        registry.import_ssh_config()
    return registry, path


def build_gateway(args: argparse.Namespace) -> Gateway:
    registry, path = load_registry(args.servers_config, args.import_ssh_config)
    if registry.count() == 0:
        raise SystemExit("No SSH servers configured. Create servers.json (see servers.json.example) "
                         "or pass --servers-config / --import-ssh-config.")
    settings = Settings(
        project_root=os.path.abspath(args.project_root) if args.project_root else None,
        cache_root=os.path.abspath(args.cache_dir) if args.cache_dir else default_cache_root(),
        servers_path=path,
        log_policy=args.log_output,
        read_only=args.read_only or env_flag("SSH_READ_ONLY"),
        command_blacklist=split_words(args.command_blacklist or os.environ.get("SSH_COMMAND_BLACKLIST", "")),
        allow_add_server=args.allow_add_server,
        allow_system_temp=args.allow_system_temp,
        allow_gateway_dir=args.allow_gateway_dir,
    )
    return Gateway(MultiServerManager(settings, registry))


# ---------------------------------------------------------------------------
# stdio loop
# ---------------------------------------------------------------------------

_stdout_lock = threading.Lock()


def write_message(stdout: io.TextIOBase, message: Dict[str, Any]) -> None:
    with _stdout_lock:
        try:
            stdout.write(json.dumps(message, ensure_ascii=False) + "\n")
            stdout.flush()
        except (OSError, ValueError) as exc:
            log(f"could not write a response: {exc}")


def process(request: Any, gateway: Gateway, stdout: io.TextIOBase) -> None:
    try:
        response = handle_request(request, gateway)
    except Exception as exc:
        log(f"unexpected error: {exc!r}")
        request_id = request.get("id") if isinstance(request, dict) else None
        response = {"jsonrpc": "2.0", "id": request_id,
                    "error": {"code": -32603, "message": f"Internal error: {exc}"}} if request_id is not None else None
    if response is not None:
        write_message(stdout, response)


def serve(gateway: Gateway, stdin: io.TextIOBase, stdout: io.TextIOBase) -> None:
    """Read JSON-RPC lines until stdin closes. Stopping a command never waits behind a running one."""
    workers = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="mcp-worker")
    control = ThreadPoolExecutor(max_workers=CONTROL_WORKERS, thread_name_prefix="mcp-control")
    pending = threading.BoundedSemaphore(MAX_PENDING_REQUESTS)

    def run_limited(request: Any) -> None:
        try:
            process(request, gateway, stdout)
        finally:
            pending.release()

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        if len(line) > MAX_REQUEST_LINE_BYTES:
            write_message(stdout, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32600, "message": "request line too large"}})
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            write_message(stdout, {"jsonrpc": "2.0", "id": None,
                                   "error": {"code": -32700, "message": f"Parse error: {exc}"}})
            continue
        if is_control_request(request):
            control.submit(process, request, gateway, stdout)
        elif pending.acquire(blocking=False):
            workers.submit(run_limited, request)
        else:
            request_id = request.get("id") if isinstance(request, dict) else None
            write_message(stdout, {"jsonrpc": "2.0", "id": request_id, "error": {
                "code": -32000,
                "message": f"Busy: {MAX_PENDING_REQUESTS} requests are already in flight. "
                           "Wait for running commands (read/signal) and retry."}})
    workers.shutdown(wait=True)
    control.shutdown(wait=True)


def main() -> None:
    args = build_parser().parse_args()
    gateway = build_gateway(args)
    settings = gateway.manager.settings
    log(f"{__version__} started: servers [{', '.join(gateway.manager.registry.aliases())}], "
        f"local files {settings.project_root or 'off'}, cache {settings.cache_root}")

    # UTF-8 regardless of the console code page (Windows).
    stdin = io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", line_buffering=True)

    stopped = threading.Event()

    def shut_down(*_: Any) -> None:
        if not stopped.is_set():
            stopped.set()
            gateway.manager.close_all()

    def stop(*_: Any) -> None:
        shut_down()
        sys.exit(0)

    atexit.register(shut_down)
    for name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), stop)
    serve(gateway, stdin, stdout)
    shut_down()


if __name__ == "__main__":
    main()
