import os
import re
import json
import time
import threading
from typing import Any, Dict, Optional
from src.config import (
    DEFAULT_WAIT_TIMEOUT, DEFAULT_STARTUP_WAIT, DEFAULT_HARD_TIMEOUT,
    DEFAULT_QUIET_COMPLETE_TIMEOUT, DEFAULT_READ_MAX_LINES, DEFAULT_READ_MAX_CHARS,
    MAX_READ_MAX_CHARS, MAX_SERVERS, config
)
from src.utils import (
    log_error, to_bool, clamp_int, iso_now,
    resolve_local_path, apply_text_filters, clean_output
)
from src.fs import file_dispatch

def project_tool_result(tool_name: str, result: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(result, dict):
        return {"success": False, "error": "tool returned non-object result"}
    
    # Base lean fields
    success = result.get("success", False)
    status = result.get("status")
    session_id = result.get("session_id")
    
    # Ultra-lean ordering
    projected = {}
    
    if not success:
        # For MCP-level errors (not command errors)
        projected["error"] = result.get("error", "unknown error")
        projected["success"] = False
        if result.get("error_code"):
            projected["error_code"] = result["error_code"]
        for extra in ("actual_sha256", "path"):
            if result.get(extra):
                projected[extra] = result[extra]
        if session_id is not None: projected["session_id"] = session_id
        return projected

    # If we are here, success is True.
    # Command might have failed (status="failed") or session died (status="dead").
    
    exit_status = result.get("exit_status")
    is_failed = (status in {"failed", "dead"} or status == "completed_nonzero" or (exit_status is not None and exit_status != 0))
    
    # 1. Output/Error (First field)
    if is_failed:
        # T3.3/F9: never invent an exit code ("exit status 1" for an unknown code was
        # a lie) and never wrap output in decorative banners - one honest error line
        # plus the raw output is cheaper and clearer for the model.
        if exit_status is None:
            projected["error"] = result.get("error") or f"Command failed ({status})"
        else:
            projected["error"] = result.get("error") or f"Command failed with exit status {exit_status}"
        projected["output"] = result.get("output", "")
        if result.get("hint"):
            projected["hint"] = result["hint"]
        if result.get("error_code"):
            projected["error_code"] = result["error_code"]
    elif tool_name in {"run", "read"}:
        projected["output"] = result.get("output", "")
        if result.get("message"):
            projected["message"] = result.get("message")
        if result.get("session_reused"):
            projected["session_reused"] = True
        if result.get("process_stopped") is False:
            projected["process_stopped"] = False
        if result.get("hint"):
            projected["hint"] = result["hint"]
        if result.get("created_session_id"):
            projected["created_session_id"] = result.get("created_session_id")
        if result.get("recv_paused"):
            projected["recv_paused"] = True
        if result.get("dropped_data"):
            projected["dropped_data"] = True
    elif tool_name == "file":
        # Special case for file tool - it has many actions
        action = result.get("action")
        if action == "list":
            if "files" in result: projected["files"] = result["files"]
            else: projected["output"] = result.get("listing", "")
        elif action == "read":
            if result.get("mode") == "download":
                projected["message"] = f"Downloaded to {result.get('local_path')}"
                projected["size"] = result.get("size")
            elif result.get("mode") == "binary_hidden":
                projected["mode"] = "binary_hidden"
                projected["message"] = result.get("message", "File is binary. Content hidden.")
                projected["size"] = result.get("size")
                projected["sha256"] = result.get("sha256")
            else:
                projected["output"] = result.get("content", "")
                if "line_start" in result:
                    projected["line_start"] = result["line_start"]
                if "line_end" in result:
                    projected["line_end"] = result["line_end"]
                if "total_lines" in result:
                    projected["total_lines"] = result["total_lines"]
                if "truncated" in result:
                    projected["truncated"] = result["truncated"]
        elif action in {"write", "edit"}:
            # T2.2/F9: a dry run or a no-op must never look like a successful write.
            if action == "edit" and result.get("dry_run"):
                projected["message"] = "File edit dry run - NOTHING was written"
            elif action == "edit" and not result.get("changed", True):
                projected["message"] = "File edit: no changes needed"
            else:
                projected["message"] = f"File {action} successful"
            if "size" in result: projected["size"] = result["size"]
            for key in ("changed", "dry_run", "replacements", "old_sha256", "new_sha256", "backup_path"):
                if key in result:
                    projected[key] = result[key]
    elif tool_name in {"server_list", "server_add"}:
        projected["success"] = True
        if "servers" in result:
            projected["servers"] = result.get("servers", [])
        if "reload" in result:
            projected["reload"] = result.get("reload")
        if "message" in result:
            projected["message"] = result.get("message")
    elif tool_name == "session_list":
        projected["sessions"] = result.get("sessions", [])
    elif tool_name == "last_command_details":
        # last_command_details is never lean
        return result
    else:
        projected["message"] = result.get("message", "OK")

    # 2. Server & IDs
    if "server" in result and result["server"]:
        projected["server"] = result["server"]
    if session_id is not None:
        projected["session_id"] = session_id
        if "session_name" in result:
            projected["session_name"] = result["session_name"]
    
    # 3. status
    if status is not None:
        projected["status"] = status
    
    # Add extra useful fields for some tools if they exist
    if tool_name in {"read", "run"} and "next_offset" in result:
        projected["next_offset"] = result["next_offset"]
    if tool_name in {"run", "read"} and "still_running" in result:
        projected["still_running"] = result["still_running"]
    if result.get("limited"):
        projected["limited"] = True
        projected.setdefault("hint", "output truncated - page with offset/next_offset or raise max_chars")
    if "total_chars" in result:
        projected["total_chars"] = result["total_chars"]
    
    if "exit_status" in result and result["exit_status"] is not None:
        projected["exit_status"] = result["exit_status"]
    if "bytes_written" in result:
        projected["bytes_written"] = result["bytes_written"]
    if "bytes_sent" in result:
        projected["bytes_sent"] = result["bytes_sent"]
    if result.get("filtered"):
        projected["matched_lines"] = result.get("matched_lines")
    
    return projected

def format_tool_result(result: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if not is_error:
        return {"content": [{"type": "text", "text": text}]}
    return {"content": [{"type": "text", "text": text}], "isError": True}

def make_response(req_id: Any, result: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": format_tool_result(result, is_error)}

# Everyday tool surface (T3.2/F10). Admin/diagnostic tools ship only in 'full'.
LEAN_TOOLS = {"server_list", "run", "read", "signal", "file", "session_close"}
ADMIN_TOOLS = {"server_add", "session_update", "last_command_details"}


def tools_list() -> Dict[str, Any]:
    server_param = {
        "type": "string",
        "description": "Server alias/IP, or session_id='alias/1'.",
    }
    session_id_param = {
        "type": "string",
        "description": "Session id ('alias/1' or '1'). REQUIRED to preserve shell state (cwd, env). If omitted, an idle session is reused with UNKNOWN state.",
    }
    tools = [
        {
            "name": "server_list",
            "description": (
                "List configured servers (alias, host, user, status, sessions) and active "
                "sessions; reload=true re-reads servers.json."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "reload": {"type": "boolean"}
                },
            },
        },
        {
            "name": "server_add",
            "description": (
                "Add a new SSH server target to the gateway configuration (append-only). "
                "For security reasons, modifying or deleting existing servers is not permitted via MCP."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "alias": {
                        "type": "string",
                        "description": "Unique human-readable server alias (e.g. 'staging-vps').",
                    },
                    "host": {
                        "type": "string",
                        "description": "Host IP or FQDN.",
                    },
                    "port": {
                        "type": "number",
                        "description": "SSH port (default 22).",
                    },
                    "user": {
                        "type": "string",
                        "description": "SSH username.",
                    },
                    "password": {
                        "type": "string",
                        "description": "SSH password (optional).",
                    },
                    "key_path": {
                        "type": "string",
                        "description": "Path to SSH private key (optional).",
                    },
                    "key_passphrase": {
                        "type": "string",
                        "description": "Passphrase for private key (optional).",
                    },
                    "verify_host": {
                        "type": "boolean",
                        "description": "Verify host key. Default true.",
                    },
                    "extra_path": {
                        "type": "string",
                        "description": "Extra PATH directories (e.g. '/opt/bin:/opt/sbin').",
                    },
                    "read_only": {
                        "type": "boolean",
                        "description": "Best-effort write guardrail (regex denylist over the command text). Default false. NOT a security boundary - use a restricted SSH account for that.",
                    },
                    "command_blacklist": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Disallowed commands (e.g. ['reboot', 'rm -rf']).",
                    },
                    "description": {
                        "type": "string",
                        "description": "Optional server description.",
                    },
                },
                "required": ["alias", "host", "user"],
            },
        },
        {
            "name": "session_list",
            "description": (
                "List active sessions (id, status) across servers; filter with 'server'. "
                "Rarely needed: run() reports session_id and reuses idle sessions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": {
                        "type": "string",
                        "description": "Optional server name or prefix to filter sessions (e.g. 'keen' or 'keenetic').",
                    },
                    "include_name": {"type": "boolean", "description": "Optional. Include session name in listing."},
                    "include_last_command": {"type": "boolean", "description": "Optional. If true, includes the last executed command string for each session in the listing."},
                },
            },
        },
        {
            "name": "session_close",
            "description": "Close a session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "session_id": {"type": "string", "description": "Session id to close (e.g. 'keenetic/1' or number if server is set)."},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "session_update",
            "description": "Rename a session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "session_id": {"type": "string", "description": "Session id to update (e.g. 'keenetic/1' or number if server is set)."},
                    "name": {"type": "string", "description": "New name."},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "run",
            "description": (
                "Run a command on a server. Output returns directly when it finishes within "
                "wait_timeout (default 5s) - call 'read' only when still_running=true. Without "
                "session_id an idle session is reused with UNKNOWN state (pwd/env); pass session_id "
                "to preserve state, or new_session=true for a clean shell - "
                "one terminal runs one command at a time."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "command": {"type": "string", "description": "Command to run (filter with | grep, | head)."},
                    "session_id": session_id_param,
                    "wait_timeout": {"type": "number", "description": "Seconds to wait for output (default 5; 0=async)."},
                    "hard_timeout": {"type": "number", "description": "Interrupt after N seconds (0=off)."},
                    "shell": {"type": "boolean", "description": "true=Linux shell, false=NDM CLI; omit=auto."},
                    "new_session": {"type": "boolean", "description": "Force opening a clean session with default state."},
                    "session_name": {"type": "string"},
                    "use_pty": {"type": "boolean", "description": "true (default); false for multiline scripts."},
                },
                "required": ["command"],
            },
        },
        {
            "name": "read",
            "description": (
                "Read terminal output/history. Use after run returns still_running=true (it waits "
                "up to wait_timeout), or to page: offset 0 rewinds to the start, negative = tail. "
                "Do NOT call after a completed run - its output already came back."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "session_id": session_id_param,
                    "wait_timeout": {"type": "number", "description": "Max seconds to wait for running command to finish (default 5.0). Set 0 for instant non-blocking read."},
                    "offset": {"type": "number", "description": "0=rewind, negative=tail, else next_offset."},
                    "max_lines": {"type": "number"},
                    "max_chars": {"type": "number"},
                },
            },
        },
        {
            "name": "signal",
            "description": "Send ctrl_c/stdin/eof to a session's active command; ctrl_c unblocks a stuck one.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "session_id": session_id_param,
                    "action": {"type": "string", "enum": ["ctrl_c", "stdin", "eof"]},
                    "text": {"type": "string"},
                    "press_enter": {"type": "boolean"},
                },
            },
        },
        {
            "name": "last_command_details",
            "description": "Raw record of the last tool call on a server/session - diagnostics only.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "session_id": session_id_param,
                },
            },
        },
        {
            "name": "file",
            "description": (
                "Remote files (SFTP, shell fallback): action=list|read|write|edit. To edit ALWAYS "
                "use action='edit' with edits=[{old_text,new_text,replace_all}] - never sed/python "
                "on the host. read=inspect/download (local_path), write=create/overwrite (content or local_path)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": server_param,
                    "session_id": session_id_param,
                    "action": {"type": "string", "enum": ["read", "write", "list", "edit"]},
                    "path": {"type": "string"},
                    "local_path": {"type": "string", "description": "Local transfer path."},
                    "content": {"type": "string"},
                    "is_base64": {"type": "boolean"},
                    "max_bytes": {"type": "number"},
                    "edits": {"type": "array", "description": "edit: [{old_text,new_text,replace_all}]."},
                    "expected_sha256": {
                        "type": "string",
                        "description": "sha256 as read; conflict if changed.",
                    },
                },
                "required": ["action"],
            },
        },
    ]
    profile = getattr(config, "TOOL_PROFILE", "full")
    if profile == "lean":
        tools = [t for t in tools if t["name"] in LEAN_TOOLS]
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}

# Cheap, non-blocking tools run on a dedicated small pool: a stuck run must never
# delay Ctrl+C, session_close or a listing (F5). Everything that can wait for I/O
# or a wait_timeout (run/read/file) stays on the main pool.
CONTROL_TOOLS = {
    "signal", "session_close", "session_update",
    "session_list", "server_list", "last_command_details",
}


def is_control_request(request: Any) -> bool:
    if not isinstance(request, dict):
        return False
    if request.get("method") != "tools/call":
        return True  # initialize, tools/list, ping, notifications: all cheap
    params = request.get("params") or {}
    name = params.get("name") if isinstance(params, dict) else None
    return name in CONTROL_TOOLS


def run_dispatch(args: Dict[str, Any], manager, req_id: Any = None) -> Dict[str, Any]:
    command = args.get("command", "")
    if not isinstance(command, str) or not command.strip():
        return {
            "success": False,
            "error": "'command' is required and must be a non-empty string. "
            "Example: run(command='uname -a', server='keenetic').",
        }
    session_id = args.get("session_id")
    node, numeric_sid, new_req, err_resp = manager.resolve_target_for_args(args)
    if err_resp:
        return err_resp

    new_session = to_bool(args.get("new_session", False)) or new_req
    session_name = args.get("session_name", "") or ""

    if new_session and numeric_sid is not None:
        return {"success": False, "error": "session_id and new_session=true are mutually exclusive"}

    command = args.get("command", "")
    mode = args.get("mode", "sync")
    raw_shell = args.get("shell")
    shell = to_bool(raw_shell) if raw_shell is not None else None
    wait_timeout = args.get("wait_timeout", DEFAULT_WAIT_TIMEOUT)
    if to_bool(args.get("background", False)):
        wait_timeout = 0.0
    hard_timeout = args.get("hard_timeout", DEFAULT_HARD_TIMEOUT)
    background = to_bool(args.get("background", False))
    use_pty = to_bool(args.get("use_pty", True))
    # Internal knobs are deliberately not agent-facing (T3.1): fixed sane defaults
    # here; the file tool reaches the full run_command surface internally.
    mode = "sync"
    startup_wait = DEFAULT_STARTUP_WAIT
    completion_hint = "either"
    quiet_complete_timeout = DEFAULT_QUIET_COMPLETE_TIMEOUT

    session_created = False
    reused_session = False
    created_session_id = None
    requested_session_id = session_id
    selection_source = ""
    session = None

    target_manager = node

    if numeric_sid is not None:
        target_sid = numeric_sid
        session = target_manager.get_session(target_sid)
        if session is None:
            return {
                "success": False,
                "error": f"Session {target_sid} not found on server '{target_manager.alias}'. Use 'run' without session_id to open a new session, or check active sessions with 'session_list'.",
                "server": target_manager.alias
            }
        alive_error = session.ensure_alive() if callable(getattr(session, "ensure_alive", None)) else None
        if alive_error or getattr(session, "is_dead", False) is True:
            death_r = getattr(session, "death_reason", None) or alive_error
            return {
                "success": False,
                "error": f"Session {target_sid} on server '{target_manager.alias}' is closed or disconnected: {death_r}. To run commands, start a new session without session_id.",
                "session_id": f"{target_manager.alias}/{target_sid}",
                "server": target_manager.alias
            }
        is_b = session.is_busy() if callable(getattr(session, "is_busy", None)) else getattr(session, "is_busy", False)
        if is_b is True:
            busy = session.busy_info() if callable(getattr(session, "busy_info", None)) else {}
            active_cmd = getattr(session, "last_command", "") or ""
            cmd_info = f" running '{active_cmd}'" if active_cmd else ""
            return {
                "success": False,
                "error": (
                    f"Session {target_sid} is busy{cmd_info}. "
                    "An SSH session is a single shell terminal and cannot run commands in parallel. "
                    "Wait for the current command to finish, or run without session_id to open a new session."
                ),
                "session_id": target_sid,
                "busy_type": busy.get("type") if isinstance(busy, dict) else None,
                "busy_id": busy.get("id") if isinstance(busy, dict) else None,
            }
        selection_source = "explicit"
    else:
        # T1.1/F3: without session_id reuse an idle live session instead of opening a
        # new SSH connection per command (that exhausted max_sessions on the 11th call
        # and cost a full handshake each time). new_session=true still forces a clean
        # session, so "fresh terminal" stays explicitly available.
        session = None if new_session else target_manager.find_first_idle_alive_session()
        if session is not None:
            selection_source = "reused"
            reused_session = True
        else:
            created = target_manager.open_session(name=session_name)
            if not created.get("success", False):
                return created
            created_session_id = created["session_id"]
            session_created = True
            selection_source = "new_session"
            num_id = created.get("numeric_session_id", created["session_id"])
            session = target_manager.get_session(num_id)

    if not session:
        return {"success": False, "error": "no session available", "server": target_manager.alias}

    result = session.run_command(
        command=command, mode=mode, shell=shell, wait_timeout=wait_timeout,
        startup_wait=startup_wait, hard_timeout=hard_timeout,
        completion_hint=completion_hint, quiet_complete_timeout=quiet_complete_timeout,
        background=background, use_pty=use_pty, req_id=req_id
    )

    # One retry: between the idle scan and run_command's reservation a concurrent
    # request may have taken the reused session. That race must not fail the call.
    if reused_session and not result.get("success") and "busy" in str(result.get("error", "")).lower():
        created = target_manager.open_session(name=session_name)
        if created.get("success", False):
            retry_session = target_manager.get_session(created.get("numeric_session_id"))
            if retry_session is not None:
                retry_result = retry_session.run_command(
                    command=command, mode=mode, shell=shell, wait_timeout=wait_timeout,
                    startup_wait=startup_wait, hard_timeout=hard_timeout,
                    completion_hint=completion_hint, quiet_complete_timeout=quiet_complete_timeout,
                    background=background, use_pty=use_pty, req_id=req_id
                )
                result = retry_result
                if retry_result.get("success"):
                    session = retry_session
                    session_created = True
                    reused_session = False
                    created_session_id = created["session_id"]
                    selection_source = "retry_new_session"

    if result.get("success"):
        result["session_created"] = session_created
        result["session_reused"] = reused_session
        result["requested_session_id"] = requested_session_id
        result["executed_session_id"] = result.get("session_id")
        result["session_selection"] = selection_source
        if session_created:
            result["created_session_id"] = created_session_id
        if reused_session:
            result.setdefault(
                "hint",
                "reused idle session with existing state; pass session_id for sequential commands or new_session=true for a clean shell"
            )
    return result

def read_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    node, numeric_sid, _, err_resp = manager.resolve_target_for_args(args)
    if err_resp:
        return err_resp

    run_id = args.get("run_id")
    offset = args.get("offset")
    max_lines = args.get("max_lines", DEFAULT_READ_MAX_LINES)
    max_chars = args.get("max_chars", DEFAULT_READ_MAX_CHARS)
    wait_timeout = args.get("wait_timeout", DEFAULT_WAIT_TIMEOUT)
    if wait_timeout is not None:
        try: wait_timeout = float(wait_timeout)
        except (ValueError, TypeError): wait_timeout = DEFAULT_WAIT_TIMEOUT

    if offset is not None:
        try: offset = int(offset)
        except (ValueError, TypeError): return {"success": False, "error": "offset must be number"}
    if run_id is not None:
        try: run_id = int(run_id)
        except (ValueError, TypeError): return {"success": False, "error": "run_id must be number"}

    target_manager = node
    session = target_manager.get_session(numeric_sid)
    if not session:
        if numeric_sid is not None:
            return {"success": False, "error": f"Session {numeric_sid} not found on server '{target_manager.alias}'", "server": target_manager.alias}
        with target_manager.lock:
            sessions = list(target_manager.sessions.values())
        if len(sessions) == 1:
            session = sessions[0]
        elif len(sessions) == 0:
            return {"success": False, "error": f"No sessions found on server '{target_manager.alias}'. Please run a command first.", "server": target_manager.alias}
        else:
            return {"success": False, "error": f"Multiple sessions exist on server '{target_manager.alias}'. Please specify 'session_id'.", "server": target_manager.alias}

    return session.read_run(run_id=run_id, offset=offset, max_lines=max_lines, max_chars=max_chars, wait_timeout=wait_timeout)

def signal_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    node, numeric_sid, _, err_resp = manager.resolve_target_for_args(args)
    if err_resp:
        return err_resp

    target_manager = node
    session = target_manager.get_session(numeric_sid)
    if not session:
        if numeric_sid is not None:
            return {"success": False, "error": f"Session {numeric_sid} not found on server '{target_manager.alias}'", "server": target_manager.alias}
        with target_manager.lock:
            sessions = list(target_manager.sessions.values())
        if len(sessions) == 1:
            session = sessions[0]
        elif len(sessions) == 0:
            return {"success": False, "error": f"No sessions found on server '{target_manager.alias}'. Please run a command first.", "server": target_manager.alias}
        else:
            return {"success": False, "error": f"Multiple sessions exist on server '{target_manager.alias}'. Please specify 'session_id'.", "server": target_manager.alias}

    action = args.get("action", "ctrl_c")
    text = args.get("text", "")
    press_enter = to_bool(args.get("press_enter", True))
    return session.send_signal(action=action, text=text, press_enter=press_enter)

def last_command_details_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    server = args.get("server")
    session_id = args.get("session_id")
    return manager.get_last_tool_result(server=server, session_id=session_id)

_config_file_lock = threading.Lock()

def server_add_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    # The only caller is the local MCP client, and it already has the password it
    # is asking us to store. servers.json is the operator's config file, same as
    # SSH_PASSWORD. Refusing key_path or verify_host=false would block the
    # documented way to add a host. A second authz check here does not reduce
    # what that client can already do with run on an existing host.
    alias = str(args.get("alias", "")).strip()
    host = str(args.get("host", "")).strip()
    user = str(args.get("user", "")).strip()
    if not alias:
        return {"success": False, "error": "'alias' is required"}
    if not re.match(r"^[a-zA-Z0-9_-]+$", alias):
        return {
            "success": False,
            "error": f"Invalid server alias '{alias}'. Alias must match ^[a-zA-Z0-9_-]+$ and cannot contain slashes or whitespace.",
            "server": alias
        }
    if not host:
        return {"success": False, "error": "'host' is required"}
    if not user:
        return {"success": False, "error": "'user' is required"}

    # Append-only security check: never overwrite or mutate existing server
    if hasattr(manager, "registry"):
        cnt = manager.registry.count()
        if isinstance(cnt, int) and cnt >= MAX_SERVERS:
            return {"success": False, "error": f"Maximum server limit ({MAX_SERVERS}) reached. Cannot add more servers."}
        existing = manager.registry.get(alias)
        if existing is not None:
            return {
                "success": False,
                "error": (
                    f"Security: Server '{alias}' already exists. "
                    "Modifying or deleting existing servers via MCP is forbidden for safety. "
                    "Please edit servers.json directly on host if changes are needed."
                ),
                "server": alias
            }

    port = 22
    if args.get("port") is not None:
        try:
            port = int(args.get("port"))
        except (ValueError, TypeError):
            return {"success": False, "error": "'port' must be an integer"}

    new_server_dict: Dict[str, Any] = {
        "host": host,
        "port": port,
        "user": user,
    }
    if args.get("password") is not None:
        new_server_dict["password"] = str(args.get("password"))
    if args.get("key_path") is not None:
        new_server_dict["key_path"] = str(args.get("key_path"))
    if args.get("key_passphrase") is not None:
        new_server_dict["key_passphrase"] = str(args.get("key_passphrase"))
    if args.get("verify_host") is not None:
        new_server_dict["verify_host"] = to_bool(args.get("verify_host"), True)
    if args.get("extra_path") is not None:
        new_server_dict["extra_path"] = str(args.get("extra_path"))
    if args.get("read_only") is not None:
        new_server_dict["read_only"] = to_bool(args.get("read_only"), False)
    if args.get("command_blacklist") is not None:
        b_list = args.get("command_blacklist")
        if isinstance(b_list, list):
            new_server_dict["command_blacklist"] = [str(c).strip() for c in b_list if str(c).strip()]
        elif isinstance(b_list, str):
            new_server_dict["command_blacklist"] = [c.strip() for c in b_list.split(",") if c.strip()]
    if args.get("description") is not None:
        new_server_dict["description"] = str(args.get("description")).strip()

    cfg_path = getattr(manager, "config_path", None) or config.SERVERS_CONFIG_PATH
    mgr_lock = getattr(manager, "lock", None)

    def _persist_config():
        if hasattr(manager, "registry"):
            if manager.registry.count() >= MAX_SERVERS:
                return {"success": False, "error": f"Maximum server limit ({MAX_SERVERS}) reached. Cannot add more servers."}
            if manager.registry.get(alias) is not None:
                return {
                    "success": False,
                    "error": (
                        f"Security: Server '{alias}' already exists. "
                        "Modifying or deleting existing servers via MCP is forbidden for safety. "
                        "Please edit servers.json directly on host if changes are needed."
                    ),
                    "server": alias
                }

        if cfg_path and os.path.isfile(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Case 1: top-level is list: [{"alias": ...}, ...]
            if isinstance(data, list):
                if len(data) >= MAX_SERVERS:
                    return {"success": False, "error": f"Maximum server limit ({MAX_SERVERS}) reached. Cannot add more servers."}
                for item in data:
                    if isinstance(item, dict) and item.get("alias", "").lower() == alias.lower():
                        return {
                            "success": False,
                            "error": f"Server '{alias}' already exists in {cfg_path}.",
                            "server": alias
                        }
                item_dict = {"alias": alias, **new_server_dict}
                data.append(item_dict)
            # Case 2: top-level is dict: {"servers": [...]} or {"servers": {...}}
            elif isinstance(data, dict):
                servers_data = data.get("servers")
                if isinstance(servers_data, list):
                    if len(servers_data) >= MAX_SERVERS:
                        return {"success": False, "error": f"Maximum server limit ({MAX_SERVERS}) reached. Cannot add more servers."}
                    for item in servers_data:
                        if isinstance(item, dict) and item.get("alias", "").lower() == alias.lower():
                            return {
                                "success": False,
                                "error": f"Server '{alias}' already exists in {cfg_path}.",
                                "server": alias
                            }
                    servers_data.append({"alias": alias, **new_server_dict})
                elif isinstance(servers_data, dict):
                    if len(servers_data) >= MAX_SERVERS:
                        return {"success": False, "error": f"Maximum server limit ({MAX_SERVERS}) reached. Cannot add more servers."}
                    if alias.lower() in [k.lower() for k in servers_data.keys()]:
                        return {
                            "success": False,
                            "error": f"Server '{alias}' already exists in {cfg_path}.",
                            "server": alias
                        }
                    servers_data[alias] = new_server_dict
                else:
                    data["servers"] = {alias: new_server_dict}
            else:
                data = {"servers": {alias: new_server_dict}}

            tmp_file = f"{cfg_path}.tmp.{os.getpid()}_{int(time.time() * 1000)}"
            try:
                with open(tmp_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                os.chmod(tmp_file, 0o600)
                os.replace(tmp_file, cfg_path)
            finally:
                if os.path.exists(tmp_file):
                    try:
                        os.remove(tmp_file)
                    except Exception:
                        pass
            if hasattr(manager, "check_reload"):
                manager.check_reload(force=True)
            return None
        elif hasattr(manager, "registry"):
            if manager.registry.count() >= MAX_SERVERS:
                return {"success": False, "error": f"Maximum server limit ({MAX_SERVERS}) reached. Cannot add more servers."}
            if manager.registry.get(alias) is not None:
                return {
                    "success": False,
                    "error": (
                        f"Security: Server '{alias}' already exists. "
                        "Modifying or deleting existing servers via MCP is forbidden for safety. "
                        "Please edit servers.json directly on host if changes are needed."
                    ),
                    "server": alias
                }
            from src.config import ServerTargetConfig
            cfg_obj = ServerTargetConfig.from_dict(alias, new_server_dict)
            manager.registry.register(cfg_obj)
            return None
        return None

    try:
        with _config_file_lock:
            err_res = _persist_config()
        if err_res:
            return err_res
    except Exception as e:
        return {"success": False, "error": f"Failed to persist server to '{cfg_path}': {e}"}

    return {
        "success": True,
        "message": f"Server '{alias}' ({host}:{port}) added successfully (append-only).",
        "server": alias
    }

def handle_request(request: Dict[str, Any], manager) -> Optional[Dict[str, Any]]:
    method = request.get("method")
    params = request.get("params", {})
    req_id = request.get("id", 1)

    if isinstance(method, str) and method.startswith("notifications/"):
        # Notifications get no response. Cancellation must actually stop work (T1.4).
        if method == "notifications/cancelled":
            cancel_params = params if isinstance(params, dict) else {}
            manager.cancel_request(cancel_params.get("requestId"))
        return None

    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}

    if method == "initialize":
        requested_version = params.get("protocolVersion") if isinstance(params, dict) else None
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": requested_version if isinstance(requested_version, str) and requested_version else "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ssh-mcp-vnext", "version": "6.0.0"},
            },
        }

    if method == "notifications/initialized": return None
    if method == "tools/list":
        response = tools_list()
        response["id"] = req_id
        return response

    if method == "tools/call":
        if not isinstance(params, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "params must be an object"}}
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}
        if not isinstance(args, dict):
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "arguments must be an object"}}
        try:
            if tool_name == "server_list":
                reload_flag = to_bool(args.get("reload", False))
                result = manager.list_all_servers(reload=reload_flag)
            elif tool_name == "server_add":
                result = server_add_dispatch(args, manager)
            elif tool_name == "session_list":
                server_arg = args.get("server")
                result = manager.list_all_sessions(
                    server_filter=server_arg,
                    include_name=to_bool(args.get("include_name", False)),
                    include_last_command=to_bool(args.get("include_last_command", False)),
                    include_active_ids=to_bool(args.get("include_active_ids", False)),
                )
            elif tool_name == "session_close":
                result = manager.close_session(session_id=args.get("session_id"), server=args.get("server"))
            elif tool_name == "session_update":
                result = manager.update_session(
                    session_id=args.get("session_id"),
                    name=args.get("name"),
                    make_current=to_bool(args.get("make_current")),
                    server=args.get("server")
                )
            elif tool_name == "run":
                result = run_dispatch(args, manager, req_id=req_id)
            elif tool_name == "read":
                result = read_dispatch(args, manager)
            elif tool_name == "signal":
                result = signal_dispatch(args, manager)
            elif tool_name == "last_command_details":
                result = last_command_details_dispatch(args, manager)
            elif tool_name == "file":
                result = file_dispatch(args, manager)
            else:
                return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}

            if tool_name != "last_command_details":
                server_alias = result.get("server") or args.get("server") if isinstance(result, dict) else args.get("server")
                manager.record_tool_result(server_alias=server_alias, tool_name=str(tool_name), args=args, result=result)
            projected = project_tool_result(tool_name=str(tool_name), result=result)
            status = result.get("status") if isinstance(result, dict) else None
            exit_status = result.get("exit_status") if isinstance(result, dict) else None
            is_error = (
                not result.get("success", False)
                or status in {"failed", "dead", "completed_nonzero", "hard_timeout"}
                or (exit_status is not None and exit_status != 0)
            )
            return make_response(req_id, projected, is_error=is_error)
        except Exception as exc:
            log_error(f"tool execution error ({tool_name}): {exc}")
            return make_response(req_id, {"error": str(exc)}, is_error=True)

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}
