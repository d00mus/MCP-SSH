import json
from typing import Any, Dict, Optional
from src.config import (
    DEFAULT_WAIT_TIMEOUT, DEFAULT_STARTUP_WAIT, DEFAULT_HARD_TIMEOUT,
    DEFAULT_QUIET_COMPLETE_TIMEOUT, DEFAULT_READ_MAX_LINES, DEFAULT_READ_MAX_CHARS
)
from src.utils import (
    log_error, to_bool, clamp_int, iso_now
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
        if session_id is not None: projected["session_id"] = session_id
        return projected

    # If we are here, success is True.
    # Command might have failed (status="failed") or session died (status="dead").
    
    is_failed = (status in {"failed", "dead"})
    
    # 1. Output/Error (First field)
    if is_failed:
        projected["error"] = result.get("error") or "command failed"
        if "output" in result and result["output"]:
            projected["output"] = result["output"]
    elif tool_name in {"run", "exec", "read"}:
        projected["output"] = result.get("output", "")
    elif tool_name in {"run_pipeline", "pipeline_status"}:
        projected["output"] = result.get("preview", "")
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
            else:
                projected["output"] = result.get("content", "")
        elif action in {"write", "edit"}:
            projected["message"] = f"File {action} successful"
            if "size" in result: projected["size"] = result["size"]
    elif tool_name == "session_list":
        projected["sessions"] = result.get("sessions", [])
    elif tool_name == "last_command_details":
        # last_command_details is never lean
        return result
    else:
        projected["message"] = result.get("message", "OK")

    # 2. IDs
    if session_id is not None:
        projected["session_id"] = session_id
        if "session_name" in result:
            projected["session_name"] = result["session_name"]
    if "run_id" in result:
        projected["run_id"] = result["run_id"]
    if "pipeline_id" in result:
        projected["pipeline_id"] = result["pipeline_id"]
    
    # 3. status
    if status is not None:
        projected["status"] = status
    
    # Add extra useful fields for some tools if they exist
    if tool_name in {"read", "pipeline_status"} and "next_offset" in result:
        projected["next_offset"] = result["next_offset"]
    
    if "bytes_written" in result:
        projected["bytes_written"] = result["bytes_written"]
    if "bytes_sent" in result:
        projected["bytes_sent"] = result["bytes_sent"]
    
    return projected

def format_tool_result(result: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    text = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
    if not is_error:
        return {"content": [{"type": "text", "text": text}]}
    return {"content": [{"type": "text", "text": text}], "isError": True}

def make_response(req_id: Any, result: Dict[str, Any], is_error: bool = False) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": format_tool_result(result, is_error)}

def tools_list() -> Dict[str, Any]:
    session_id_param = {
        "type": "number",
        "description": "Optional session id. If omitted, current session is used.",
    }
    tools = [
        {
            "name": "session_list",
            "description": (
                "List sessions. Returns id + status (idle|busy|broken). "
                "Each row has current/is_current marker. "
                "Use this to find available sessions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "include_name": {"type": "boolean", "description": "Optional. Include session name in listing."},
                    "include_last_command": {"type": "boolean", "description": "Optional. Include last launched command in listing."},
                    "include_active_ids": {"type": "boolean", "description": "Optional. Include active_run_id and active_pipeline_id for debugging."},
                },
            },
        },
        {
            "name": "session_close",
            "description": "Close and remove a session by id.",
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": {"type": "number", "description": "Session id to close."}},
                "required": ["session_id"],
            },
        },
        {
            "name": "session_update",
            "description": "Update session properties: rename and/or set current.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "number", "description": "Session id to update."},
                    "name": {"type": "string", "description": "New name."},
                    "make_current": {"type": "boolean", "description": "Set this session as current."},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "run",
            "description": (
                "Execute command with anti-hang timeout. Returns Ultra-Lean payload. "
                "Possible statuses: 'completed' (done), 'running' (wait_timeout reached, data flowing), "
                "'stalled' (quiet_timeout reached, no new data), 'failed' (error), 'dead' (session closed). "
                "For restricted devices (Keenetic): set shell=true for Linux shell, shell=false for NDM CLI. "
                "On Linux: shell=true enables pipes/redirections."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The command string to execute (e.g., 'ls -la')."},
                    "mode": {"type": "string", "description": "sync (default), async, or stream.", "enum": ["sync", "async", "stream"]},
                    "shell": {"type": "boolean", "description": "Boolean flag. TRUE for Linux shell, FALSE for native CLI (NDM)."},
                    "wait_timeout": {"type": "number", "description": "Max seconds to wait for output in this call."},
                    "startup_wait": {"type": "number", "description": "For async/stream: short initial wait before returning."},
                    "hard_timeout": {"type": "number", "description": "Optional max command lifetime. 0 disables."},
                    "session_id": session_id_param,
                    "new_session": {"type": "boolean", "description": "Create a new session and run there immediately."},
                    "session_name": {"type": "string", "description": "Optional name for new/recovery session."},
                },
                "required": ["command"],
            },
        },
        {
            "name": "run_pipeline",
            "description": (
                "Binary-safe cross-machine pipeline. Transfers RAW data (may include ANSI codes). "
                "Always uses system shell. Supports environment variables (%TEMP%, $HOME) and tilde (~) in local paths. "
                "Returns a pipeline_id for monitoring with pipeline_status."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Remote command to execute."},
                    "mode": {"type": "string", "enum": ["sync", "async"], "description": "sync (default) or async."},
                    "local_stdout_path": {"type": "string", "description": "Local file path to write remote stdout."},
                    "local_stdin_path": {"type": "string", "description": "Local file path to feed as remote stdin."},
                    "append_stdout": {"type": "boolean", "description": "Append to local_stdout_path instead of overwrite."},
                    "include_stderr": {"type": "boolean", "description": "Also write remote stderr into local_stdout_path."},
                    "session_id": session_id_param,
                },
                "required": ["command"],
            },
        },
        {
            "name": "pipeline_status",
            "description": "Check status of run_pipeline and read text preview. Statuses: 'running', 'completed', 'failed', 'dead'. Supports filtering and tailing of the preview output.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                    "pipeline_id": {"type": "number", "description": "Optional specific pipeline id. If omitted, uses the last pipeline."},
                    "offset": {"type": "number", "description": "Preview offset for pagination (use next_offset from previous call)."},
                    "max_chars": {"type": "number", "description": "Max preview chars to return."},
                    "contains": {"type": "string", "description": "Filter: only show lines containing this string."},
                    "regex": {"type": "string", "description": "Filter: only show lines matching this regex."},
                    "tail_lines": {"type": "number", "description": "Filter: only show last N lines of the preview."},
                },
            },
        },
        {
            "name": "read",
            "description": (
                "Read buffered output for a run. Supports pagination via 'offset' and 'next_offset'. "
                "Statuses: 'completed', 'running', 'stalled', 'failed', 'dead'. "
                "Supports filtering and tailing of the output."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                    "run_id": {"type": "number", "description": "Optional specific run id. If omitted, uses the active or last run."},
                    "offset": {"type": "number", "description": "Optional absolute offset for pagination. If omitted, shared cursor is used."},
                    "max_lines": {"type": "number", "description": "Max lines per page."},
                    "max_chars": {"type": "number", "description": "Max chars per page."},
                    "contains": {"type": "string", "description": "Filter: only show lines containing this string."},
                    "regex": {"type": "string", "description": "Filter: only show lines matching this regex."},
                    "tail_lines": {"type": "number", "description": "Filter: only show last N lines of the output."},
                },
            },
        },
        {
            "name": "signal",
            "description": "Send ctrl_c or stdin to a session/run.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": session_id_param,
                    "action": {"type": "string", "enum": ["ctrl_c", "stdin"]},
                    "text": {"type": "string", "description": "Text for stdin action."},
                    "press_enter": {"type": "boolean", "description": "Append Enter for stdin action. Default true."},
                },
            },
        },
        {
            "name": "last_command_details",
            "description": (
                "Returns FULL verbose metadata of the last tool call. "
                "Use this ONLY if you need deep details (timeouts, internal states, full memory info)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {"session_id": session_id_param},
            },
        },
        {
            "name": "file",
            "description": (
                "File management (list, read/download, write/upload, edit) with SFTP and shell fallbacks. "
                "Use full remote paths. Supports %TEMP%, $HOME, ~ in local_path. "
                "Actions: read (inspect/download), write (upload/inline), list, edit (in-place replacement)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["read", "write", "list", "upload", "download", "edit"]},
                    "path": {"type": "string", "description": "Remote path."},
                    "local_path": {"type": "string", "description": "Local path for transfer (supports ~, %TEMP%)."},
                    "content": {"type": "string", "description": "Optional inline content for write/upload."},
                    "is_base64": {"type": "boolean", "description": "Optional. If true, content is base64-decoded."},
                    "edits": {"type": "array", "description": "For edit: list of {old_text, new_text, replace_all}."},
                    "session_id": session_id_param,
                },
                "required": ["action"],
            },
        },
    ]
    return {"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}}

def run_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    command = args.get("command", "")
    mode = args.get("mode", "sync")
    shell = to_bool(args.get("shell", False))
    wait_timeout = args.get("wait_timeout", DEFAULT_WAIT_TIMEOUT)
    startup_wait = args.get("startup_wait", DEFAULT_STARTUP_WAIT)
    hard_timeout = args.get("hard_timeout", DEFAULT_HARD_TIMEOUT)
    completion_hint = args.get("completion_hint", "either")
    quiet_complete_timeout = args.get("quiet_complete_timeout", DEFAULT_QUIET_COMPLETE_TIMEOUT)

    session_id = args.get("session_id")
    new_session = to_bool(args.get("new_session", False))
    session_name = args.get("session_name", "") or ""

    if new_session and session_id is not None:
        return {"success": False, "error": "session_id and new_session=true are mutually exclusive"}

    session_created = False
    session_recovered = False
    created_session_id = None
    requested_session_id = session_id
    selection_reason = ""
    selection_source = ""
    session = None

    if new_session:
        created = manager.open_session(name=session_name, make_current=True)
        if not created.get("success", False): return created
        created_session_id = created["session_id"]
        session_created = True
        selection_source = "new_session"
        session = manager.get_session(created_session_id)
    elif session_id is not None:
        session = manager.get_session(session_id)
        if session is None:
            selection_reason = f"requested session {session_id} not found"
        else:
            alive_error = session.ensure_alive()
            if alive_error:
                selection_reason = alive_error
            elif session.is_busy():
                busy = session.busy_info()
                return {
                    "success": False, "error": f"Requested session {session_id} is busy",
                    "session_id": session_id, "busy_type": busy.get("type"), "busy_id": busy.get("id"),
                }

        if session is None or selection_reason:
            recovered_name = session_name or f"auto-recovery-from-{session_id}"
            created = manager.open_session(name=recovered_name, make_current=True)
            if not created.get("success", False): return created
            created_session_id = created["session_id"]
            session_created = True
            session_recovered = True
            selection_source = "explicit_recovery_new"
            session = manager.get_session(created_session_id)
        else:
            selection_source = "explicit"
    else:
        session = manager.get_session(None)
        if session is None:
            selection_reason = "current session is missing"
        else:
            alive_error = session.ensure_alive()
            if alive_error:
                selection_reason = alive_error
                session = None
            elif session.is_busy():
                busy = session.busy_info()
                selection_reason = f"current session busy"
                session = None
            else:
                selection_source = "current"

        if session is None:
            idle_session = manager.find_first_idle_alive_session()
            if idle_session is not None:
                manager.set_current_session(idle_session.id)
                session = idle_session
                selection_source = "first_idle"
            else:
                created = manager.open_session(name=(session_name or "auto-new-default"), make_current=True)
                if not created.get("success", False): return created
                created_session_id = created["session_id"]
                session_created = True
                session_recovered = True
                selection_source = "default_recovery_new"
                session = manager.get_session(created_session_id)

    if not session: return {"success": False, "error": "no session available"}

    result = session.run_command(
        command=command, mode=mode, shell=shell, wait_timeout=wait_timeout,
        startup_wait=startup_wait, hard_timeout=hard_timeout,
        completion_hint=completion_hint, quiet_complete_timeout=quiet_complete_timeout
    )
    if result.get("success"):
        result["session_created"] = session_created
        result["session_recovered"] = session_recovered
        result["requested_session_id"] = requested_session_id
        result["executed_session_id"] = result.get("session_id")
        result["session_selection"] = selection_source
        if selection_reason: result["selection_reason"] = selection_reason
        if session_created: result["created_session_id"] = created_session_id
    return result

def read_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    session_id = args.get("session_id")
    run_id = args.get("run_id")
    offset = args.get("offset")
    max_lines = args.get("max_lines", DEFAULT_READ_MAX_LINES)
    max_chars = args.get("max_chars", DEFAULT_READ_MAX_CHARS)
    contains = args.get("contains")
    regex = args.get("regex")
    tail_lines = args.get("tail_lines")

    if offset is not None:
        try: offset = int(offset)
        except: return {"success": False, "error": "offset must be number"}
    if run_id is not None:
        try: run_id = int(run_id)
        except: return {"success": False, "error": "run_id must be number"}

    session = manager.get_session(session_id)
    if not session: session = manager.ensure_session()
    if not session: return {"success": False, "error": "session not found"}

    result = session.read_run(run_id=run_id, offset=offset, max_lines=max_lines, max_chars=max_chars)
    if not result.get("success"): return result

    from src.utils import apply_text_filters
    filtered = apply_text_filters(result.get("output", ""), contains=contains, regex=regex, tail_lines=tail_lines)
    if not filtered.get("success"):
        return {"success": False, "error": filtered.get("error", "filtering error"), "session_id": result.get("session_id")}
    
    result["output"] = filtered["output"]
    result["filtered"] = filtered["filtered"]
    result["matched_lines"] = filtered["matched_lines"]
    result["scanned_chars"] = filtered["scanned_chars"]
    return result

def signal_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    session = manager.get_session(args.get("session_id"))
    if not session: session = manager.ensure_session()
    if not session: return {"success": False, "error": "session not found"}
    action = args.get("action", "ctrl_c")
    text = args.get("text", "")
    press_enter = to_bool(args.get("press_enter", True))
    return session.send_signal(action=action, text=text, press_enter=press_enter)

def last_command_details_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    session_id = args.get("session_id")
    if session_id is not None:
        try: session_id = int(session_id)
        except: return {"success": False, "error": "session_id must be number"}
    return manager.get_last_tool_result(session_id=session_id)

def run_pipeline_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    from src.utils import resolve_local_path
    command = args.get("command", "")
    mode = args.get("mode", "sync")
    wait_timeout = args.get("wait_timeout", DEFAULT_WAIT_TIMEOUT)
    startup_wait = args.get("startup_wait", DEFAULT_STARTUP_WAIT)
    hard_timeout = args.get("hard_timeout", DEFAULT_HARD_TIMEOUT)
    include_stderr = to_bool(args.get("include_stderr", False))
    append_stdout = to_bool(args.get("append_stdout", False))
    local_stdout_path = resolve_local_path(args.get("local_stdout_path", "") or "")
    local_stdin_path = resolve_local_path(args.get("local_stdin_path", "") or "")

    session_id = args.get("session_id")
    new_session = to_bool(args.get("new_session", False))
    session_name = args.get("session_name", "") or ""

    session = manager.get_session(session_id)
    if not session: session = manager.ensure_session()
    if not session: return {"success": False, "error": "no session available"}

    result = session.run_pipeline(
        command=command, mode=mode, wait_timeout=wait_timeout, startup_wait=startup_wait,
        hard_timeout=hard_timeout, local_stdout_path=local_stdout_path,
        local_stdin_path=local_stdin_path, include_stderr=include_stderr, append_stdout=append_stdout
    )
    return result

def pipeline_status_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    session_id = args.get("session_id")
    pipeline_id = args.get("pipeline_id")
    offset = args.get("offset")
    max_chars = args.get("max_chars", DEFAULT_READ_MAX_CHARS)
    contains = args.get("contains")
    regex = args.get("regex")
    tail_lines = args.get("tail_lines")

    if pipeline_id is not None:
        try: pipeline_id = int(pipeline_id)
        except: return {"success": False, "error": "pipeline_id must be number"}
    if offset is not None:
        try: offset = int(offset)
        except: return {"success": False, "error": "offset must be number"}

    session = manager.get_session(session_id)
    if not session: session = manager.ensure_session()
    if not session: return {"success": False, "error": "session not found"}

    result = session.pipeline_status(pipeline_id=pipeline_id, offset=offset, max_chars=max_chars)
    if not result.get("success"): return result

    from src.utils import apply_text_filters
    filtered = apply_text_filters(result.get("preview", ""), contains=contains, regex=regex, tail_lines=tail_lines)
    if not filtered.get("success"):
        return {"success": False, "error": filtered.get("error", "filtering error"), "session_id": result.get("session_id")}
    
    result["preview"] = filtered["output"]
    result["filtered"] = filtered["filtered"]
    result["matched_lines"] = filtered["matched_lines"]
    result["scanned_chars"] = filtered["scanned_chars"]
    return result

def handle_request(request: Dict[str, Any], manager) -> Optional[Dict[str, Any]]:
    method = request.get("method")
    params = request.get("params", {})
    req_id = request.get("id", 1)

    if method == "initialize":
        manager.ensure_session()
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "ssh-mcp-vnext", "version": "5.5.0"},
            },
        }

    if method == "notifications/initialized": return None
    if method == "tools/list":
        response = tools_list()
        response["id"] = req_id
        return response

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}
        try:
            if tool_name == "session_list":
                result = manager.list_sessions(
                    include_name=to_bool(args.get("include_name", False)),
                    include_last_command=to_bool(args.get("include_last_command", False)),
                    include_active_ids=to_bool(args.get("include_active_ids", False)),
                )
            elif tool_name == "session_close":
                sid = clamp_int(args.get("session_id"), 0, 1, 10**9)
                result = manager.close_session(sid)
            elif tool_name == "session_update":
                sid = clamp_int(args.get("session_id"), 0, 1, 10**9)
                result = manager.update_session(sid, args.get("name"), to_bool(args.get("make_current")))
            elif tool_name in {"run", "exec"}:
                result = run_dispatch(args, manager)
            elif tool_name == "run_pipeline":
                result = run_pipeline_dispatch(args, manager)
            elif tool_name == "pipeline_status":
                result = pipeline_status_dispatch(args, manager)
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
                manager.record_tool_result(tool_name=str(tool_name), args=args, result=result)
            projected = project_tool_result(tool_name=str(tool_name), result=result)
            is_error = not result.get("success", False) or result.get("status") in {"failed", "dead"}
            return make_response(req_id, projected, is_error=is_error)
        except Exception as exc:
            log_error(f"tool execution error ({tool_name}): {exc}")
            return make_response(req_id, {"error": str(exc)}, is_error=True)

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}
