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
    DEFAULT_READ_MAX_CHARS, MAX_READ_MAX_CHARS, MAX_BUFFER_CHARS,
    DEFAULT_FILE_INSPECT_MAX_BYTES, MAX_FILE_INSPECT_MAX_BYTES,
    DEFAULT_FILE_EDIT_MAX_BYTES, MAX_FILE_EDIT_MAX_BYTES,
    MAX_INLINE_WRITE_BYTES, config
)

def _extract_between_markers(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    if not text:
        return None
    
    import re
    # Try standalone lines first (most robust against echoed commands)
    pattern = rf"^{re.escape(start_marker)}\s*$(.*?)^{re.escape(end_marker)}\s*$"
    match = re.search(pattern, text, re.DOTALL | re.MULTILINE)
    if match:
        return match.group(1).strip()
    
    # Try just markers anywhere (fallback)
    pattern_any = rf"{re.escape(start_marker)}(.*?){re.escape(end_marker)}"
    match_any = re.search(pattern_any, text, re.DOTALL)
    if match_any:
        return match_any.group(1).strip()
    
    # Fallback for very simple cases or if markers are not on standalone lines
    start_pos = text.find(start_marker)
    if start_pos < 0:
        return None
    
    content_start = start_pos + len(start_marker)
    # Skip potential newline after marker
    if content_start < len(text) and text[content_start] == "\n":
        content_start += 1
    elif content_start < len(text) and text[content_start:content_start+2] == "\r\n":
        content_start += 2
        
    end_pos = text.find(end_marker, content_start)
    if end_pos < 0:
        return None
        
    content_end = end_pos
    # Trim potential trailing newline before marker
    if content_end > content_start and text[content_end-1] == "\n":
        content_end -= 1
        if content_end > content_start and text[content_end-1] == "\r":
            content_end -= 1
            
    return text[content_start:content_end]

def _sync_shell(session: SSHSession, command: str, timeout: float = 30.0, max_chars: Optional[int] = None) -> Dict[str, Any]:
    # Internal helper for synchronous shell calls (for file ops)
    return session.run_command(
        command=command,
        mode="sync",
        shell=True,
        wait_timeout=timeout,
        startup_wait=2.0,
        hard_timeout=timeout + 10.0,
        completion_hint="prompt",
        quiet_complete_timeout=2.0,
        max_chars=max_chars
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

    try:
        if not session.client:
            return {"success": False, "error": "SSH client is not connected", "session_id": session.id}
            
        if max_bytes is None:
            cmd = f"cat '{path}'"
        else:
            cmd = f"head -c {max_bytes + 1} '{path}'"
            
        stdin, stdout, stderr = session.client.exec_command(cmd)
        data = stdout.read()
        err = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()
        
        # Check if exec_command failed because the shell commands themselves are missing (e.g. NDMS CLI on port 22)
        if "no such command" in err or "no such command" in data.decode('utf-8', errors='replace').lower() or "Command::Base error" in err or "Command::Base error" in data.decode('utf-8', errors='replace'):
            raise NotImplementedError("exec_command not supported, falling back to sync_shell")
            
        if exit_code == 0 or data:
            truncated = False
            if max_bytes is not None and len(data) > max_bytes:
                data = data[:max_bytes]
                truncated = True
            return {
                "success": True,
                "method": "exec_cat",
                "data": data,
                "truncated": truncated,
                "session_id": session.id,
                "session_name": session.name,
                "status": "completed"
            }
        else:
            return {"success": False, "error": f"remote file is not readable or missing: {path}. Error: {err}", "session_id": session.id, "session_name": session.name}
    except (Exception, NotImplementedError) as exc:
        log_error(f"exec cat read failed, falling back to sync_shell base64: {exc}")
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

        shell_result = _sync_shell(session, shell_command, timeout=30.0, max_chars=MAX_BUFFER_CHARS)
        if not shell_result.get("success", False):
            return shell_result
        
        raw_output = shell_result.get("output", "")
        extracted = _extract_between_markers(raw_output, marker_start, marker_end)
        
        if extracted is None:
            import re
            if re.search(rf"^{re.escape(marker_error)}\s*$", raw_output, re.MULTILINE):
                return {"success": False, "error": f"remote file is not readable or missing: {path}", "session_id": session.id, "session_name": session.name}
            return {"success": False, "error": f"failed to parse shell read payload: {raw_output[-300:]}", "session_id": session.id, "session_name": session.name}

        try:
            import re
            cleaned_payload = re.sub(r'[^A-Za-z0-9+/=]', '', extracted)
            payload_bytes = base64.b64decode(cleaned_payload, validate=False)
        except Exception as e:
            return {"success": False, "error": f"failed to decode base64: {e}", "session_id": session.id}

        truncated = False
        if max_bytes is not None and len(payload_bytes) > max_bytes:
            payload_bytes = payload_bytes[:max_bytes]
            truncated = True

        return {
            "success": True,
            "method": "shell_base64",
            "data": payload_bytes,
            "truncated": truncated,
            "session_id": session.id,
            "session_name": session.name,
            "status": "completed"
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

    try:
        if not session.client:
            return {"success": False, "error": "SSH client is not connected", "session_id": session.id}
            
        # Create directory using non-interactive exec_command
        dir_cmd = f"mkdir -p \"$(dirname '{path}')\""
        stdin_dir, stdout_dir, stderr_dir = session.client.exec_command(dir_cmd)
        stdout_dir.channel.recv_exit_status() # wait for completion
        
        # Write file using non-interactive exec_command
        stdin, stdout, stderr = session.client.exec_command(f"cat > '{path}'")
        stdin.write(payload_bytes)
        stdin.channel.shutdown_write()
        
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode('utf-8', errors='replace')
        
        # Check if exec_command failed because the shell commands themselves are missing (e.g. NDMS CLI on port 22)
        if "no such command" in err or "Command::Base error" in err:
            raise NotImplementedError("exec_command not supported, falling back to sync_shell")
            
        if exit_code == 0:
            return {"success": True, "method": "exec_cat"}
        else:
            return {"success": False, "error": f"exec cat write failed with exit code {exit_code}: {err}", "session_id": session.id}
    except (Exception, NotImplementedError) as exc:
        log_error(f"exec cat write failed, falling back to sync_shell echo/cat: {exc}")
        _sync_shell(session, f"mkdir -p \"$(dirname '{path}')\"", timeout=10.0)
        
        b64_content = base64.b64encode(payload_bytes).decode('utf-8')
        stamp = f"{int(time.time() * 1000)}_{os.getpid()}"
        tmp_path = f"/tmp/mcp_upload_{stamp}"
        
        _sync_shell(session, f"echo -n '' > {tmp_path}", timeout=5.0)
        chunks = [b64_content[i:i+1000] for i in range(0, len(b64_content), 1000)]
        for chunk in chunks:
            _sync_shell(session, f"echo -n '{chunk}' >> {tmp_path}", timeout=5.0)
            
        decode_res = _sync_shell(session, f"base64 -d {tmp_path} > '{path}' && rm -f {tmp_path}", timeout=10.0)
        if decode_res.get("success", False):
            return {"success": True, "method": "shell_base64_write"}
        else:
            _sync_shell(session, f"rm -f {tmp_path}", timeout=5.0)
            escaped_content = payload_bytes.decode('utf-8', errors='ignore').replace("'", "'\\''")
            write_res = _sync_shell(session, f"cat << 'EOF' > '{path}'\n{escaped_content}\nEOF", timeout=15.0)
            if write_res.get("success", False):
                return {"success": True, "method": "shell_cat_heredoc"}
            return {"success": False, "error": f"Interactive shell write failed", "session_id": session.id}

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

    if config.READ_ONLY and action in {"write", "edit", "upload"}:
        return {"success": False, "error": f"Security: action '{action}' is blocked in read-only sandbox mode."}

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

    alive_error = session.ensure_alive()
    if alive_error:
        # If it failed to reconnect, try to recover by opening a new session
        created = manager.open_session(name=session.name or "auto-recovery-file", make_current=True)
        if not created.get("success", False):
            return {"success": False, "error": f"Session is dead and recovery failed: {alive_error}"}
        session = manager.get_session(created["session_id"])
        if not session:
            return {"success": False, "error": "Failed to retrieve recovered session"}

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

        # Binary data check
        payload_bytes = read_result["data"]
        is_binary = b'\x00' in payload_bytes[:8192]
        if is_binary:
            return {
                "success": True,
                "action": "read",
                "mode": "binary_hidden",
                "path": path,
                "method": read_result["method"],
                "message": "File is binary. Content was hidden to save tokens and prevent terminal corruption.",
                "size": len(payload_bytes),
                "sha256": _sha256_hex(payload_bytes),
                "session_id": session.id,
                "status": "completed"
            }

        text = payload_bytes.decode("utf-8", errors="replace")
        window = _slice_text_by_lines(text, offset_line=offset_line, limit_lines=limit_lines)
        filtered = apply_text_filters(window["text"], contains=contains, regex=regex, tail_lines=tail_lines)
        if not filtered.get("success", False):
            return {"success": False, "error": filtered.get("error", "filtering error"), "session_id": session.id, "session_name": session.name}

        inspect_text = filtered["output"]
        char_limited = False
        if len(inspect_text) > max_chars:
            keep_size = max_chars // 2
            inspect_text = (
                f"{inspect_text[:keep_size]}\n\n"
                f"[... SYSTEM WARNING: Output truncated to {max_chars} characters to save tokens. "
                "Middle lines hidden. Use pagination 'offset_line' or text filters 'contains'/'regex' "
                "to inspect specific lines ...]\n\n"
                f"{inspect_text[-keep_size:]}"
            )
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
            
            if occurrences > 0:
                if not replace_all and occurrences != 1:
                    # Provide helpful snippet context for ambiguous match
                    lines = updated_text.splitlines()
                    matching_snippets = []
                    for i, line in enumerate(lines):
                        if old_text in line:
                            start = max(0, i - 2)
                            end = min(len(lines), i + 3)
                            snippet = []
                            for idx_line in range(start, end):
                                prefix = "--> " if idx_line == i else "    "
                                snippet.append(f"{prefix}Line {idx_line+1}: {lines[idx_line]}")
                            matching_snippets.append("\n".join(snippet))
                    snippet_text = "\n\n".join(matching_snippets)
                    return {
                        "success": False,
                        "error": (
                            f"ambiguous old_text for edit at index {idx}: found {occurrences} occurrences.\n"
                            "To fix this, please provide more unique surrounding lines of code in 'old_text'. "
                            "Here are the occurrences found in the file:\n"
                            f"{snippet_text}"
                        ),
                        "session_id": session.id
                    }
                if replace_all:
                    updated_text = updated_text.replace(old_text, new_text)
                    total_replacements += occurrences
                else:
                    updated_text = updated_text.replace(old_text, new_text, 1)
                    total_replacements += 1
                continue
            
            # If no exact match, try flexible newline matching without destroying CRLF in the whole file
            import re
            escaped_old = re.escape(old_text.replace("\r\n", "\n"))
            pattern_str = escaped_old.replace(r"\n", r"\r?\n")
            
            pattern = re.compile(pattern_str)
            matches = list(pattern.finditer(updated_text))
            occurrences = len(matches)

            if occurrences == 0:
                # Let's provide an extremely helpful similarity diagnostic
                lines = updated_text.splitlines()
                import difflib
                close_matches = []
                for i, line in enumerate(lines):
                    ratio = difflib.SequenceMatcher(None, old_text.strip(), line.strip()).ratio()
                    if ratio > 0.7:
                        close_matches.append(f"Line {i+1}: '{line.strip()}' (similarity: {int(ratio*100)}%)")
                
                hint = "Hint: check for exact whitespace/line endings (CRLF vs LF) or check the file content using 'file' read action."
                if close_matches:
                    hint += "\nDid you mean one of these similar lines in the file?\n" + "\n".join(close_matches)
                    
                return {
                    "success": False,
                    "error": f"old_text not found for edit at index {idx}.\n{hint}",
                    "session_id": session.id
                }
            
            if not replace_all and occurrences != 1:
                # Provide helpful snippet context for ambiguous flexible match
                matching_snippets = []
                for match in matches:
                    # Find which line number this start position corresponds to
                    start_pos = match.start()
                    line_no = updated_text[:start_pos].count("\n")
                    lines = updated_text.splitlines()
                    start = max(0, line_no - 2)
                    end = min(len(lines), line_no + 3)
                    snippet = []
                    for idx_line in range(start, end):
                        prefix = "--> " if idx_line == line_no else "    "
                        snippet.append(f"{prefix}Line {idx_line+1}: {lines[idx_line]}")
                    matching_snippets.append("\n".join(snippet))
                snippet_text = "\n\n".join(matching_snippets)
                return {
                    "success": False,
                    "error": (
                        f"ambiguous old_text for edit at index {idx}: found {occurrences} occurrences under flexible matching.\n"
                        "To fix this, please provide more unique surrounding lines of code in 'old_text'. "
                        "Here are the occurrences found in the file:\n"
                        f"{snippet_text}"
                    ),
                    "session_id": session.id
                }

            updated_text = pattern.sub(lambda m: new_text, updated_text, count=0 if replace_all else 1)
            total_replacements += occurrences

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
