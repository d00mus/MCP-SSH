"""MCP protocol layer: tool catalogue, argument handling and JSON-RPC dispatch."""

import json
import sys
from typing import Any, Callable, Dict, List, Optional

from mcp_ssh_gateway import __version__
from mcp_ssh_gateway.config import (
    DEFAULT_LINES, DEFAULT_MAX_CHARS, DEFAULT_WAIT, MAX_LINES, MAX_TIMEOUT, MAX_WAIT,
)
from mcp_ssh_gateway.files import FileService
from mcp_ssh_gateway.manager import MultiServerManager
from mcp_ssh_gateway.session import SessionError

SERVER_NAME = "mcp-ssh"
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

# Reaches the model once per connection, at no cost per call.
INSTRUCTIONS = """\
SSH gateway: run commands on remote servers as if in a local terminal you can scroll.
- server_list shows the servers. run(command, server) runs a command; keep the session_id it returns.
- Same session_id = same shell (cd and variables stay). No session_id = a new shell, so pass it to keep your state.
- Close shells you are done with (session_close): a server allows only a few.
- run returns as soon as the command finishes; status 'running' means it is still going: use read.
- status 'waiting_input': the program asks something. Answer with signal(action='stdin', text=...).
- Output comes in pages. 'has_more' is the number of unread lines: call read to get them.
- 'skipped_lines': older output you never read was passed over (by a new command or by read(tail=...)); scroll back with read(offset=0).
- 'dropped_data': output was lost for good (the session buffer overflowed); it cannot be scrolled back.
- A non-zero exit_code is a normal result, not a tool error.
- Routers with their own CLI (Keenetic): run(shell=false) talks to the router CLI, run(shell=true) to Linux.
- read_only and command blacklists are guardrails against mistakes, not a security boundary."""

_SESSION_ID = {"type": "string", "description": "Session id as returned by run, like 'web/1'."}
_SERVER = {"type": "string", "description": "Server name from server_list. Optional when only one server exists or session_id is given."}


def _schema(properties: Dict[str, Any], required: Optional[List[str]] = None) -> Dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


def _tool(name: str, title: str, description: str, schema: Dict[str, Any], read_only: bool = False,
          destructive: bool = False) -> Dict[str, Any]:
    return {
        "name": name, "title": title, "description": description, "inputSchema": schema,
        "annotations": {"title": title, "readOnlyHint": read_only, "destructiveHint": destructive,
                        "idempotentHint": read_only, "openWorldHint": True},
    }


TOOLS: List[Dict[str, Any]] = [
    _tool("server_list", "List servers",
          "List the configured servers and their open sessions. Call this first.",
          _schema({}), read_only=True),
    _tool("run", "Run a command",
          "Run a shell command on a server and return its output, like typing it in a terminal. "
          "Returns as soon as the command finishes. If it is still going after 'wait' seconds you get "
          "status 'running': call read later. Without session_id a NEW shell is opened (nothing carries over); "
          "pass the returned session_id to continue in the same shell (cd and variables stay).",
          _schema({
              "command": {"type": "string", "description": "The command line. Several lines are fine."},
              "server": _SERVER,
              "session_id": {**_SESSION_ID, "description": "Continue in this shell. Leave out to open a new one."},
              "shell": {"type": "boolean", "description": "Routers only. true = the router's Linux shell, false = the router CLI. Leave out otherwise."},
              "wait": {"type": "number", "description": f"Seconds to wait for the command to finish (default {DEFAULT_WAIT:g}, max {MAX_WAIT:g}). 0 = start it and return at once."},
              "timeout": {"type": "number", "description": "Stop (Ctrl+C) the command after this many seconds. 0 = never (default)."},
              "lines": {"type": "integer", "description": f"Lines per page (default {DEFAULT_LINES})."},
          }, ["command"]), destructive=True),
    _tool("read", "Read more output",
          "Read the next unread lines of a session, or scroll back. Waits up to 'wait' seconds for a running "
          "command to finish or ask for input, so one call is enough but you can read several times (pages). Use tail to see only the last lines, "
          "offset to look at older lines.",
          _schema({
              "session_id": _SESSION_ID,
              "wait": {"type": "number", "description": f"Seconds to wait for the command to finish (default {DEFAULT_WAIT:g})."},
              "lines": {"type": "integer", "description": f"Lines per page (default {DEFAULT_LINES})."},
              "tail": {"type": "integer", "description": "Only the last N lines; the older unread lines are passed over (skipped_lines says how many)."},
              "offset": {"type": "integer", "description": "Scroll: 0 = from the very first line, -20 = 20 lines above the unread position. Does not move the position."},
          }, ["session_id"]), read_only=True),
    _tool("signal", "Answer or stop a running command",
          "Talk to the command that is running in a session: type an answer (stdin), press Ctrl+C to stop it, "
          "or Ctrl+D to end its input.",
          _schema({
              "session_id": _SESSION_ID,
              "action": {"type": "string", "enum": ["stdin", "ctrl_c", "ctrl_d"]},
              "text": {"type": "string", "description": "For stdin: the text to type."},
              "enter": {"type": "boolean", "description": "For stdin: press Enter after the text (default true)."},
              "wait": {"type": "number", "description": f"Seconds to wait for the result (default {DEFAULT_WAIT:g})."},
          }, ["session_id", "action"]), destructive=True),
    _tool("session_close", "Close a session",
          "Close a session and its shell. Do this for shells you no longer need: a server allows only a few.",
          _schema({"session_id": _SESSION_ID}, ["session_id"])),
    _tool("file", "Remote files",
          "Work with files on a server. action=list (path is a folder), read, write, or edit. "
          "To change part of a file use edit with exact old_text: it must occur once (or set replace_all). "
          "Files over 200 KB and searches through them are `run` work (tail, sed -n, grep).",
          _schema({
              "action": {"type": "string", "enum": ["list", "read", "write", "edit"]},
              "path": {"type": "string", "description": "Remote path."},
              "server": _SERVER,
              "session_id": {**_SESSION_ID, "description": "Optional; names the server. A host without SFTP uses this shell (a temporary one when omitted)."},
              "content": {"type": "string", "description": "write: the new file content."},
              "is_base64": {"type": "boolean", "description": "write: content is base64 (for binary data)."},
              "local_path": {"type": "string", "description": "write: upload this local file. read: save the remote file here instead of showing it."},
              "edits": {"type": "array", "description": "edit: list of changes.", "items": _schema({
                  "old_text": {"type": "string"}, "new_text": {"type": "string"}, "replace_all": {"type": "boolean"},
              }, ["old_text", "new_text"])},
              "dry_run": {"type": "boolean", "description": "edit: show what would change, write nothing."},
              "expected_sha256": {"type": "string", "description": "edit: refuse if the file no longer has this hash (sha256 from your last read or edit)."},
              "offset_line": {"type": "integer", "description": "read/list: first line to show (1-based)."},
              "lines": {"type": "integer", "description": f"read/list: number of lines (default {DEFAULT_LINES})."},
              "contains": {"type": "string", "description": "read: only lines containing this text."},
              "tail_lines": {"type": "integer", "description": "read: only the last N lines of the file (after 'contains'). Good for logs."},
          }, ["action", "path"]), destructive=True),
]

ADD_SERVER_TOOL = _tool(
    "server_add", "Add a server",
    "Add a server to the configuration and save it. Give a key_path or a password.",
    _schema({
        "alias": {"type": "string", "description": "Short name for the server."},
        "host": {"type": "string"}, "user": {"type": "string"},
        "port": {"type": "integer"}, "key_path": {"type": "string"}, "password": {"type": "string"},
        "description": {"type": "string"}, "verify_host": {"type": "boolean"},
    }, ["alias", "host", "user"]))

CONTROL_TOOLS = ("signal", "session_close")


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

def to_bool(value: Any, default: Optional[bool] = None) -> Optional[bool]:
    if value is None or value == "":
        return default
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def to_number(value: Any, default: float, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def to_count(name: str, value: Any, default: int, high: int) -> int:
    """A whole number of 1 or more (page size, tail). Zero or less is a mistake to report, not a silent 1."""
    number = to_number(value, default, float("-inf"), high)
    if number < 1:
        raise SessionError(f"'{name}' must be 1 or more.")
    return int(number)


class Gateway:
    """Executes tool calls."""

    def __init__(self, manager: MultiServerManager) -> None:
        self.manager = manager
        self.files = FileService(manager, manager.settings)
        self._handlers: Dict[str, Callable[..., Dict[str, Any]]] = {
            "server_list": self._server_list, "run": self._run, "read": self._read,
            "signal": self._signal, "session_close": self._session_close,
            "file": lambda args, request_id: self.files.handle(args),
        }
        self.tools = list(TOOLS)
        if manager.settings.allow_add_server:
            self._handlers["server_add"] = self._server_add
            self.tools.append(ADD_SERVER_TOOL)
        self._arguments = {tool["name"]: list(tool["inputSchema"]["properties"]) for tool in self.tools}

    def call(self, name: str, args: Dict[str, Any], request_id: Any = None) -> Dict[str, Any]:
        handler = self._handlers.get(name)
        if handler is None:
            raise KeyError(name)
        self._check_arguments(name, args)
        return handler(args, request_id)

    def _check_arguments(self, name: str, args: Dict[str, Any]) -> None:
        """An argument the tool does not have would be ignored silently; say so instead."""
        accepted = self._arguments[name]
        # run takes 'server', so models pass it to the tools of a session as well; it is checked against the id.
        tolerated = ("server",) if "session_id" in accepted else ()
        unknown = [f"'{key}'" for key in args if key not in accepted and key not in tolerated]
        if unknown:
            takes = f"It takes: {', '.join(accepted)}." if accepted else "It takes no arguments."
            folder = " To work in a folder, start the command with 'cd /path && '." if name == "run" else ""
            raise SessionError(f"{name} has no argument {', '.join(unknown)}. {takes}{folder}")

    # -- tools -------------------------------------------------------------

    def _server_list(self, args: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        return {"servers": self.manager.list_servers()}

    def _run(self, args: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        command = args.get("command")
        if not isinstance(command, str) or not command.strip():
            raise SessionError("'command' is required: the command line to run.")
        lines = to_count("lines", args.get("lines"), DEFAULT_LINES, MAX_LINES)
        session = self.manager.session_for(
            server=args.get("server"), session_id=args.get("session_id"), shell=to_bool(args.get("shell")))
        self.manager.track(request_id, session)
        try:
            return session.run(
                command, wait=to_number(args.get("wait"), DEFAULT_WAIT, 0, MAX_WAIT),
                timeout=to_number(args.get("timeout"), 0, 0, MAX_TIMEOUT),
                lines=lines, max_chars=DEFAULT_MAX_CHARS)
        finally:
            self.manager.track(request_id, None)

    def _read(self, args: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        session = self.manager.existing_session(args.get("session_id"), args.get("server"))
        tail = args.get("tail")
        offset = args.get("offset")
        return session.read(
            wait=to_number(args.get("wait"), DEFAULT_WAIT, 0, MAX_WAIT),
            lines=to_count("lines", args.get("lines"), DEFAULT_LINES, MAX_LINES),
            max_chars=DEFAULT_MAX_CHARS,
            tail=to_count("tail", tail, 20, MAX_LINES) if tail not in (None, "") else None,
            offset=int(to_number(offset, 0, -MAX_LINES * 100, MAX_LINES * 100)) if offset not in (None, "") else None)

    def _signal(self, args: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        session = self.manager.existing_session(args.get("session_id"), args.get("server"))
        return session.signal(
            str(args.get("action") or ""), text=str(args.get("text") or ""),
            enter=bool(to_bool(args.get("enter"), True)),
            wait=to_number(args.get("wait"), DEFAULT_WAIT, 0, MAX_WAIT))

    def _session_close(self, args: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        return {"closed": self.manager.close_session(args.get("session_id"), args.get("server"))}

    def _server_add(self, args: Dict[str, Any], request_id: Any) -> Dict[str, Any]:
        alias = str(args.get("alias") or "").strip()
        if not alias:
            raise SessionError("'alias' is required.")
        data = {key: value for key, value in args.items() if key != "alias" and value not in (None, "")}
        target = self.manager.add_server(alias, data)
        return {"added": target.alias, "host": f"{target.host}:{target.port}"}


# ---------------------------------------------------------------------------
# JSON-RPC
# ---------------------------------------------------------------------------

def is_control_request(request: Any) -> bool:
    """Requests that must never queue behind long-running ones (stopping a command, closing)."""
    if not isinstance(request, dict) or request.get("method") != "tools/call":
        return False
    params = request.get("params")
    if not isinstance(params, dict):
        return False
    if params.get("name") == "signal":
        arguments = params.get("arguments") or {}
        return isinstance(arguments, dict) and arguments.get("action") == "ctrl_c"
    return params.get("name") == "session_close"


def _reply(request_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _tool_result(payload: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))}]}
    if is_error:
        result["isError"] = True
    return result


def handle_request(request: Dict[str, Any], gateway: Gateway) -> Optional[Dict[str, Any]]:
    """One JSON-RPC message in, the response (or None for notifications) out."""
    if not isinstance(request, dict):
        return _error(None, -32600, "Invalid Request: a JSON-RPC request must be an object")
    method = request.get("method")
    params = request.get("params")
    if params is None:
        params = {}
    request_id = request.get("id")

    if isinstance(method, str) and method.startswith("notifications/"):
        if method == "notifications/cancelled" and isinstance(params, dict):
            gateway.manager.cancel(params.get("requestId"))
        return None
    if "id" not in request:
        return None
    if method == "ping":
        return _reply(request_id, {})
    if method == "initialize":
        asked = params.get("protocolVersion") if isinstance(params, dict) else None
        return _reply(request_id, {
            "protocolVersion": asked if asked in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[-1],
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
            "instructions": INSTRUCTIONS,
        })
    if method == "tools/list":
        return _reply(request_id, {"tools": gateway.tools})
    if method == "tools/call":
        return _call_tool(request_id, params, gateway)
    return _error(request_id, -32601, f"Method not found: {method}")


def _call_tool(request_id: Any, params: Any, gateway: Gateway) -> Dict[str, Any]:
    if not isinstance(params, dict):
        return _error(request_id, -32602, "params must be an object")
    name = params.get("name")
    args = params.get("arguments")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        return _error(request_id, -32602, "arguments must be an object")
    try:
        payload = gateway.call(str(name), args, request_id)
    except KeyError:
        return _error(request_id, -32601, f"Unknown tool: {name}")
    except SessionError as exc:
        return _reply(request_id, _tool_result({"error": str(exc)}, is_error=True))
    except Exception as exc:  # a bug must not kill the connection
        print(f"[SSH-MCP] tool '{name}' crashed: {exc!r}", file=sys.stderr, flush=True)
        return _reply(request_id, _tool_result({"error": f"Internal error: {exc}"}, is_error=True))
    failed = payload.get("status") == "failed"
    return _reply(request_id, _tool_result(payload, is_error=failed))
