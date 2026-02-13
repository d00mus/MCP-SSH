import os
import time
import base64
from typing import Any, Dict, Optional
from src.ssh import SSHSession
from src.utils import (
    log_error, clamp_int, resolve_local_path, to_bool, _sha256_hex,
    apply_text_filters
)
from src.config import (
    BUFFER_SIZE, DEFAULT_READ_MAX_LINES, MAX_READ_MAX_LINES,
    DEFAULT_READ_MAX_CHARS, MAX_READ_MAX_CHARS,
    DEFAULT_FILE_INSPECT_MAX_BYTES, MAX_FILE_INSPECT_MAX_BYTES,
    DEFAULT_FILE_EDIT_MAX_BYTES, MAX_FILE_EDIT_MAX_BYTES,
    MAX_INLINE_WRITE_BYTES
)

def _extract_between_markers(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    if not text:
        return None
    
    start_pos = text.find(start_marker)
    if start_pos < 0:
        return None
    
    # Content starts after the marker and any immediate newline
    content_start = start_pos + len(start_marker)
    if content_start < len(text) and text[content_start] == "\n":
        content_start += 1
    elif content_start < len(text) and text[content_start:content_start+2] == "\r\n":
        content_start += 2
        
    end_pos = text.find(end_marker, content_start)
    if end_pos < 0:
        return None
        
    # Content ends before the marker and any trailing newline/carriage return
    content_end = end_pos
    if content_end > content_start and text[content_end-1] == "\n":
        content_end -= 1
        if content_end > content_start and text[content_end-1] == "\r":
            content_end -= 1
            
    return text[content_start:content_end]

def _sync_shell(session: SSHSession, command: str, timeout: float = 30.0) -> Dict[str, Any]:
    # Internal helper for synchronous shell calls (for file ops)
    return session.run_command(
        command=command,
        mode="sync",
        shell=True,
        wait_timeout=timeout,
        startup_wait=2.0,
        hard_timeout=timeout + 10.0,
        completion_hint="prompt",
        quiet_complete_timeout=2.0
    )

def _read_remote_file_bytes(
    session: SSHSession,
    path: str,
    max_bytes: Optional[int],
) -> Dict[str, Any]:
    sftp = session.open_sftp()
    if sftp is not None:
        try:
            with sftp.file(path, "rb") as handle:
                if max_bytes is None:
                    data = handle.read()
                    truncated = False
                else:
                    data = handle.read(max_bytes + 1)
                    truncated = len(data) > max_bytes
                    if truncated:
                        data = data[:max_bytes]
            return {
                "success": True,
                "method": "sftp",
                "data": data,
                "truncated": truncated,
            }
        except Exception as exc:
            log_error(f"sftp read failed, fallback shell: {exc}")
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    stamp = f"{int(time.time() * 1000)}_{os.getpid()}"
    marker_start = f"MCP_BEGIN_{stamp}"
    marker_end = f"MCP_END_{stamp}"
    marker_error = f"MCP_ERR_{stamp}"

    if max_bytes is None:
        shell_command = (
            f"if [ -r '{path}' ]; then "
            f"echo '{marker_start}'; base64 '{path}'; echo '{marker_end}'; "
            f"else echo '{marker_error}'; fi"
        )
    else:
        shell_command = (
            f"if [ -r '{path}' ]; then "
            f"echo '{marker_start}'; head -c {max_bytes + 1} '{path}' | base64; echo '{marker_end}'; "
            f"else echo '{marker_error}'; fi"
        )

    shell_result = _sync_shell(session, shell_command, timeout=30.0)
    if not shell_result.get("success", False):
        return shell_result
    
    raw_output = shell_result.get("output", "")
    extracted = _extract_between_markers(raw_output, marker_start, marker_end)
    
    if extracted is None:
        error_lines = raw_output.splitlines()
        if any(line.strip() == marker_error for line in error_lines):
            return {"success": False, "error": f"remote file is not readable or missing: {path}", "session_id": session.id, "session_name": session.name}
        return {"success": False, "error": "failed to parse shell read payload (markers not found)", "session_id": session.id, "session_name": session.name}

    try:
        payload_bytes = base64.b64decode(extracted, validate=False)
    except Exception as exc:
        return {"success": False, "error": f"failed to decode shell base64 payload: {exc}", "session_id": session.id, "session_name": session.name}

    truncated = False
    if max_bytes is not None and len(payload_bytes) > max_bytes:
        payload_bytes = payload_bytes[:max_bytes]
        truncated = True

    return {
        "success": True,
        "method": "shell",
        "data": payload_bytes,
        "truncated": truncated,
    }

def _write_remote_file_bytes(
    session: SSHSession,
    path: str,
    payload_bytes: bytes,
) -> Dict[str, Any]:
    sftp = session.open_sftp()
    if sftp is not None:
        try:
            with sftp.file(path, "wb") as handle:
                handle.write(payload_bytes)
            return {"success": True, "method": "sftp"}
        except Exception as exc:
            log_error(f"sftp write failed, fallback shell: {exc}")
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    b64_payload = base64.b64encode(payload_bytes).decode("ascii")
    tmp_path = f"{path}.mcp_b64_{int(time.time() * 1000)}"
    chunk_size = 800
    chunks = [b64_payload[i : i + chunk_size] for i in range(0, len(b64_payload), chunk_size)]
    if not chunks:
        chunks = [""]

    first = _sync_shell(session, f"echo '{chunks[0]}' > '{tmp_path}'", timeout=30.0)
    if not first.get("success", False):
        return first

    for chunk in chunks[1:]:
        step = _sync_shell(session, f"echo '{chunk}' >> '{tmp_path}'", timeout=30.0)
        if not step.get("success", False):
            return step

    finish = _sync_shell(session, f"mkdir -p \"$(dirname '{path}')\" && base64 -d '{tmp_path}' > '{path}' && sync && rm '{tmp_path}'", timeout=30.0)
    if not finish.get("success", False):
        return finish
    return {"success": True, "method": "shell"}

def _slice_text_by_lines(text: str, offset_line: Optional[int], limit_lines: int) -> Dict[str, Any]:
    lines = text.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return {"text": "", "line_start": 1, "line_end": 0, "total_lines": 0}

    start_line = 1 if offset_line is None else offset_line
    if start_line < 0:
        start_line = total_lines + start_line + 1
    if start_line < 1:
        start_line = 1

    line_limit = clamp_int(limit_lines, DEFAULT_READ_MAX_LINES, 1, MAX_READ_MAX_LINES)
    if start_line > total_lines:
        return {"text": "", "line_start": start_line, "line_end": start_line - 1, "total_lines": total_lines}

    end_line = min(total_lines, start_line + line_limit - 1)
    window_text = "\n".join(lines[start_line - 1 : end_line])
    return {
        "text": window_text,
        "line_start": start_line,
        "line_end": end_line,
        "total_lines": total_lines,
    }

def file_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    action = (args.get("action") or "").strip().lower()
    if action not in {"read", "write", "list", "upload", "download", "edit"}:
        return {"success": False, "error": "action must be one of: read, write, list, upload, download, edit"}

    path = (args.get("path", "") or "").strip()
    local_path = resolve_local_path(args.get("local_path", "") or "")
    content = args.get("content")
    is_base64 = to_bool(args.get("is_base64", False))
    session_id = args.get("session_id")

    session = manager.get_session(session_id)
    if not session:
        session = manager.ensure_session()
    if not session:
        return {"success": False, "error": "no session available"}

    if action == "upload": action = "write"
    if action == "download": action = "read"

    if action == "list":
        target = path or "/"
        sftp = session.open_sftp()
        if sftp is not None:
            try:
                rows = []
                for entry in sftp.listdir_attr(target):
                    rows.append({
                        "name": entry.filename,
                        "size": entry.st_size,
                        "is_dir": bool(entry.st_mode & 0o40000),
                        "mtime": entry.st_mtime,
                    })
                return {"success": True, "action": "list", "path": target, "method": "sftp", "files": rows, "session_id": session.id, "session_name": session.name, "status": "completed"}
            except Exception as exc:
                log_error(f"sftp list failed, fallback shell: {exc}")
            finally:
                try: sftp.close()
                except: pass

        shell_result = _sync_shell(session, f"ls -la '{target}'", timeout=30.0)
        if not shell_result.get("success", False):
            return shell_result
        return {
            "success": True,
            "action": "list",
            "path": target,
            "method": "shell",
            "listing": shell_result.get("output", ""),
            "session_id": session.id,
            "session_name": session.name,
            "status": "completed"
        }

    if action == "read":
        if not path:
            return {"success": False, "error": "path is required for read"}
        if local_path:
            parent = os.path.dirname(local_path)
            if parent: os.makedirs(parent, exist_ok=True)
            read_result = _read_remote_file_bytes(session, path, max_bytes=None)
            if not read_result.get("success", False): return read_result
            payload_bytes = read_result["data"]
            with open(local_path, "wb") as handle: handle.write(payload_bytes)
            return {
                "success": True,
                "action": "read",
                "mode": "download",
                "path": path,
                "local_path": local_path,
                "method": read_result["method"],
                "size": len(payload_bytes),
                "sha256": _sha256_hex(payload_bytes),
                "session_id": session.id,
                "status": "completed"
            }

        offset_line = args.get("offset_line")
        if offset_line is not None:
            try: offset_line = int(offset_line)
            except: return {"success": False, "error": "offset_line must be number"}

        limit_lines = int(args.get("limit_lines", DEFAULT_READ_MAX_LINES))
        max_chars = clamp_int(args.get("max_chars", DEFAULT_READ_MAX_CHARS), DEFAULT_READ_MAX_CHARS, 100, MAX_READ_MAX_CHARS)
        max_bytes = clamp_int(args.get("max_bytes", DEFAULT_FILE_INSPECT_MAX_BYTES), DEFAULT_FILE_INSPECT_MAX_BYTES, 1024, MAX_FILE_INSPECT_MAX_BYTES)
        contains = args.get("contains")
        regex = args.get("regex")
        tail_lines = args.get("tail_lines")

        read_result = _read_remote_file_bytes(session, path, max_bytes=max_bytes)
        if not read_result.get("success", False): return read_result

        text = read_result["data"].decode("utf-8", errors="replace")
        window = _slice_text_by_lines(text, offset_line=offset_line, limit_lines=limit_lines)
        filtered = apply_text_filters(window["text"], contains=contains, regex=regex, tail_lines=tail_lines)
        if not filtered.get("success", False):
            return {"success": False, "error": filtered.get("error", "filtering error"), "session_id": session.id, "session_name": session.name}

        inspect_text = filtered["output"]
        char_limited = False
        if len(inspect_text) > max_chars:
            inspect_text = inspect_text[:max_chars]
            char_limited = True

        return {
            "success": True,
            "action": "read",
            "mode": "inspect",
            "path": path,
            "method": read_result["method"],
            "content": inspect_text,
            "filtered": filtered["filtered"],
            "matched_lines": filtered["matched_lines"],
            "scanned_chars": filtered["scanned_chars"],
            "line_start": window["line_start"],
            "line_end": window["line_end"],
            "total_lines": window["total_lines"],
            "truncated": bool(read_result.get("truncated", False) or char_limited),
            "session_id": session.id,
            "session_name": session.name,
            "status": "completed"
        }

    if action == "edit":
        if not path:
            return {"success": False, "error": "path is required for edit"}
        edits = args.get("edits")
        if not isinstance(edits, list) or not edits:
            return {"success": False, "error": "edits must be a non-empty array"}

        dry_run = to_bool(args.get("dry_run", False))
        create_backup = to_bool(args.get("create_backup", False))
        edit_max_bytes = clamp_int(args.get("max_bytes", DEFAULT_FILE_EDIT_MAX_BYTES), DEFAULT_FILE_EDIT_MAX_BYTES, 1024, MAX_FILE_EDIT_MAX_BYTES)

        read_result = _read_remote_file_bytes(session, path, max_bytes=edit_max_bytes)
        if not read_result.get("success", False): return read_result
        if read_result.get("truncated", False):
            return {"success": False, "error": f"file is larger than edit max_bytes ({edit_max_bytes})", "path": path, "session_id": session.id, "session_name": session.name}

        original_bytes = read_result["data"]
        # Normalize line endings for comparison if needed, but try exact match first
        original_text = original_bytes.decode("utf-8", errors="replace")
        updated_text = original_text
        total_replacements = 0

        for idx, edit in enumerate(edits):
            old_text = edit.get("old_text")
            if not old_text: return {"success": False, "error": f"edit at index {idx} has missing or empty old_text"}
            new_text = str(edit.get("new_text", ""))
            replace_all = to_bool(edit.get("replace_all", False))
            
            # Try exact match first
            occurrences = updated_text.count(old_text)
            
            # If no match, try normalizing both to \n and matching
            if occurrences == 0:
                normalized_updated = updated_text.replace("\r\n", "\n")
                normalized_old = old_text.replace("\r\n", "\n")
                if normalized_updated.count(normalized_old) > 0:
                    # If normalized match found, use the normalized version for this and subsequent edits
                    updated_text = normalized_updated
                    old_text = normalized_old
                    new_text = new_text.replace("\r\n", "\n")
                    occurrences = updated_text.count(old_text)

            if occurrences == 0: return {"success": False, "error": f"old_text not found for edit at index {idx}. Hint: check for exact whitespace/line endings."}
            if not replace_all and occurrences != 1:
                return {"success": False, "error": f"ambiguous old_text for edit at index {idx}: found {occurrences} occurrences"}

            if replace_all:
                updated_text = updated_text.replace(old_text, new_text)
                total_replacements += occurrences
            else:
                updated_text = updated_text.replace(old_text, new_text, 1)
                total_replacements += 1

        updated_bytes = updated_text.encode("utf-8")
        changed = updated_bytes != original_bytes
        result_payload = {
            "success": True, "action": "edit", "mode": "edit", "path": path,
            "changed": changed, "replacements": total_replacements, "dry_run": dry_run,
            "old_sha256": _sha256_hex(original_bytes), "new_sha256": _sha256_hex(updated_bytes), "size": len(updated_bytes),
            "session_id": session.id, "status": "completed"
        }

        if dry_run or not changed:
            result_payload["method"] = read_result["method"]
            return result_payload

        if create_backup:
            backup_path = f"{path}.mcp.bak"
            backup_result = _write_remote_file_bytes(session, backup_path, original_bytes)
            if not backup_result.get("success", False):
                return {"success": False, "error": f"failed to create backup at {backup_path}", "path": path, "session_id": session.id, "session_name": session.name}
            result_payload["backup_path"] = backup_path

        write_result = _write_remote_file_bytes(session, path, updated_bytes)
        if not write_result.get("success", False): return write_result
        result_payload["method"] = write_result["method"]
        return result_payload

    # write
    if not path: return {"success": False, "error": "path is required for write"}
    payload_bytes: bytes
    source: str
    if local_path:
        if not os.path.isfile(local_path): return {"success": False, "error": f"local_path not found: {local_path}"}
        with open(local_path, "rb") as handle: payload_bytes = handle.read()
        source = "local_path"
    else:
        if content is None: return {"success": False, "error": "for write/upload provide local_path or inline content"}
        try: payload_bytes = base64.b64decode(str(content)) if is_base64 else str(content).encode("utf-8")
        except: return {"success": False, "error": "failed to decode inline content"}
        if len(payload_bytes) > MAX_INLINE_WRITE_BYTES:
            return {"success": False, "error": f"inline content too large ({len(payload_bytes)} bytes)"}
        source = "inline_content"

    write_result = _write_remote_file_bytes(session, path, payload_bytes)
    if not write_result.get("success", False): return write_result

    return {
        "success": True, "action": "write", "path": path, "local_path": local_path,
        "source": source, "method": write_result["method"], "size": len(payload_bytes),
        "sha256": _sha256_hex(payload_bytes),
        "session_id": session.id, "status": "completed"
    }
