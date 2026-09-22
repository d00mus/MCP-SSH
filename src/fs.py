import os
import time
import base64
import hashlib
import re
import difflib
from typing import Any, Dict, Optional
from src.session import SSHSession
from src.security import escape_shell_path
from src.utils import (
    log_error, clamp_int, resolve_local_path, to_bool, _sha256_hex,
    apply_text_filters
)
from src.config import (
    BUFFER_SIZE, DEFAULT_READ_MAX_LINES, MAX_READ_MAX_LINES,
    DEFAULT_READ_MAX_CHARS, MAX_READ_MAX_CHARS, MAX_BUFFER_CHARS,
    DEFAULT_FILE_INSPECT_MAX_BYTES, MAX_FILE_INSPECT_MAX_BYTES,
    DEFAULT_FILE_EDIT_MAX_BYTES, MAX_FILE_EDIT_MAX_BYTES,
    MAX_INLINE_WRITE_BYTES, MAX_DOWNLOAD_BYTES, config
)

_DOWNLOAD_CHUNK = 65536

def _close_exec_streams(*streams) -> None:
    """Close ChannelFile wrappers and every distinct SSH channel they belong to."""
    channels = []
    seen = set()
    for stream in streams:
        if stream is None:
            continue
        ch = getattr(stream, "channel", None)
        if ch is not None and id(ch) not in seen:
            seen.add(id(ch))
            channels.append(ch)
        try:
            stream.close()
        except Exception:
            pass
    for channel in channels:
        try:
            channel.close()
        except Exception:
            pass

def _extract_between_markers(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    if not text:
        return None
    # Markers must appear on standalone lines (or preceded only by a prompt)
    # to avoid falsely matching echoed command lines in PTY sessions.
    pattern = rf"(?:^|\r?\n)(?:.*?[#$>]\s*)?{re.escape(start_marker)}\s*\r?\n(.*?)\r?\n{re.escape(end_marker)}\s*(?:\r?\n|$)"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None

def _sync_shell(session: SSHSession, command: str, timeout: float = 30.0, max_chars: Optional[int] = None, internal: bool = True) -> Dict[str, Any]:
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
        max_chars=max_chars,
        max_lines=0,
        internal=internal,
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
        safe_path = escape_shell_path(path)
    except ValueError as exc:
        return {"success": False, "error": str(exc), "session_id": session.id}
    stdin = stdout = stderr = None
    try:
        if not session.client:
            return {"success": False, "error": "SSH client is not connected", "session_id": session.id}
            
        if max_bytes is None:
            cmd = f"cat '{safe_path}'"
        else:
            cmd = f"head -c {max_bytes + 1} '{safe_path}'"
            
        stdin, stdout, stderr = session.client.exec_command(cmd)
        if hasattr(stdout, "channel") and stdout.channel:
            stdout.channel.settimeout(30.0)
        data = stdout.read()
        err = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()
        
        # Check if exec_command failed because the shell commands themselves are missing (e.g. NDMS CLI on port 22)
        out_text = data.decode('utf-8', errors='replace').lower()
        err_text = err.lower()
        if (
            "no such command" in err_text or "no such command" in out_text or
            "command::base error" in err_text or "command::base error" in out_text or
            "unknown command" in err_text or "unknown command" in out_text or
            (getattr(session, "server_alias", "") in {"keenetic", "KeeneticBt50"})
        ):
            raise RuntimeError("exec_command not supported, falling back to sync_shell")
            
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
    except Exception as exc:
        log_error(f"exec cat read failed, falling back to sync_shell base64: {exc}")
        stamp = f"{int(time.time() * 1000)}_{os.getpid()}"
        marker_start = f"MCP_BEGIN_{stamp}"
        marker_end = f"MCP_END_{stamp}"
        marker_error = f"MCP_ERR_{stamp}"

        if max_bytes is None:
            shell_command = (
                f"if [ -f '{safe_path}' ] && [ -r '{safe_path}' ]; then "
                f"echo '{marker_start}'; base64 '{safe_path}' 2>/dev/null; echo '{marker_end}'; "
                f"else echo '{marker_error}'; fi"
            )
        else:
            shell_command = (
                f"if [ -f '{safe_path}' ] && [ -r '{safe_path}' ]; then "
                f"echo '{marker_start}'; head -c {max_bytes + 1} '{safe_path}' 2>/dev/null | base64 2>/dev/null; echo '{marker_end}'; "
                f"else echo '{marker_error}'; fi"
            )

        shell_result = _sync_shell(session, shell_command, timeout=30.0, max_chars=MAX_BUFFER_CHARS)
        if not shell_result.get("success", False):
            return shell_result
        
        raw_output = shell_result.get("output", "")
        # Check if error marker was output as a standalone line (avoiding echoed commands in PTY)
        if re.search(rf"^(?:.*?[#$>]\s*)?{re.escape(marker_error)}\s*$", raw_output, re.MULTILINE):
            return {"success": False, "error": f"remote file is not readable or missing: {path}", "session_id": session.id, "session_name": session.name}

        extracted = _extract_between_markers(raw_output, marker_start, marker_end)
        
        if extracted is None:
            return {"success": False, "error": f"remote file is not readable or missing: {path}", "session_id": session.id, "session_name": session.name}

        try:
            cleaned_payload = re.sub(r'[^A-Za-z0-9+/=]', '', extracted)
            payload_bytes = base64.b64decode(cleaned_payload, validate=False)
        except Exception as e:
            return {"success": False, "error": f"failed to decode base64: {e}", "session_id": session.id, "session_name": session.name}

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
    finally:
        _close_exec_streams(stdin, stdout, stderr)

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
        safe_path = escape_shell_path(path)
    except ValueError as exc:
        return {"success": False, "error": str(exc), "session_id": session.id}
    stdin_dir = stdout_dir = stderr_dir = None
    stdin = stdout = stderr = None
    stamp = f"{int(time.time() * 1000)}_{os.getpid()}"
    tmp_remote = f"{safe_path}.mcp_tmp.{stamp}"
    try:
        if not session.client:
            return {"success": False, "error": "SSH client is not connected", "session_id": session.id}
            
        # Create directory using non-interactive exec_command
        dir_cmd = f"mkdir -p \"$(dirname '{safe_path}')\""
        stdin_dir, stdout_dir, stderr_dir = session.client.exec_command(dir_cmd)
        if hasattr(stdout_dir, "channel") and stdout_dir.channel:
            stdout_dir.channel.settimeout(30.0)
        stdout_dir.channel.recv_exit_status() # wait for completion
        
        # Write file atomically using remote tmp file + mv
        cat_marker = f"MCP_CAT_OK_{stamp}"
        stdin, stdout, stderr = session.client.exec_command(f"cat > '{tmp_remote}' && mv -f '{tmp_remote}' '{safe_path}' && echo '{cat_marker}'")
        if hasattr(stdin, "channel") and stdin.channel:
            stdin.channel.settimeout(30.0)
        if hasattr(stdout, "channel") and stdout.channel:
            stdout.channel.settimeout(30.0)
        stdin.write(payload_bytes)
        stdin.channel.shutdown_write()
        
        out = stdout.read().decode('utf-8', errors='replace')
        err = stderr.read().decode('utf-8', errors='replace')
        exit_code = stdout.channel.recv_exit_status()
        out_text = out.lower()
        err_text = err.lower()
        
        # Check if exec_command failed because the shell commands themselves are missing (e.g. NDMS CLI on port 22)
        # or if it silently returned exit 0 without executing POSIX shell commands (NDM CLI behavior)
        if (
            "no such command" in err_text or "no such command" in out_text or
            "command::base error" in err_text or "command::base error" in out_text or
            "unknown command" in err_text or "unknown command" in out_text or
            (exit_code == 0 and cat_marker not in out)
        ):
            raise RuntimeError("exec_command not supported or unverified, falling back to sync_shell")
            
        if exit_code == 0 and cat_marker in out:
            return {"success": True, "method": "exec_cat"}
        else:
            rm_in = rm_out = rm_err = None
            try:
                rm_in, rm_out, rm_err = session.client.exec_command(f"rm -f '{tmp_remote}'")
                if rm_out is not None and getattr(rm_out, "channel", None) is not None:
                    rm_out.channel.settimeout(30.0)
                    rm_out.channel.recv_exit_status()
            except Exception:
                pass
            finally:
                _close_exec_streams(rm_in, rm_out, rm_err)
            return {"success": False, "error": f"exec cat write failed with exit code {exit_code}: {err}", "session_id": session.id}
    except Exception as exc:
        log_error(f"exec cat write failed, falling back to sync_shell echo/cat: {exc}")
        _sync_shell(session, f"mkdir -p \"$(dirname '{safe_path}')\"", timeout=10.0, internal=True)
        
        # Split base64 into 76-character chunks to avoid MAX_CANON terminal overflow (RFC 2045)
        raw_b64 = base64.b64encode(payload_bytes).decode('ascii')
        b64_content = "\n".join(raw_b64[i:i+76] for i in range(0, len(raw_b64), 76))
        tmp_path = f"/tmp/mcp_upload_{stamp}"
        b64_delim = f"MCP_B64_{stamp}"
        marker_ok = f"MCP_B64_OK_{stamp}"
        
        # Write base64 content via single heredoc to tmp file (fast, avoids 100+ roundtrips, Fix M1)
        _sync_shell(session, f"cat << '{b64_delim}' > {tmp_path}\n{b64_content}\n{b64_delim}", timeout=15.0, internal=True)
            
        decode_cmd = (
            f"if base64 -d {tmp_path} > '{tmp_remote}' 2>/dev/null && mv -f '{tmp_remote}' '{safe_path}' && [ -f '{safe_path}' ]; then "
            f"rm -f {tmp_path}; echo '{marker_ok}'; "
            f"else rm -f {tmp_path} '{tmp_remote}'; fi"
        )
        decode_res = _sync_shell(session, decode_cmd, timeout=10.0, internal=True)
        output = decode_res.get("output", "")
        if decode_res.get("success", False) and re.search(rf"^(?:.*?[#$>]\s*)?{re.escape(marker_ok)}\s*$", output, re.MULTILINE):
            return {"success": True, "method": "shell_base64_write"}
        else:
            _sync_shell(session, f"rm -f {tmp_path} '{tmp_remote}'", timeout=5.0, internal=True)
            is_binary = b'\x00' in payload_bytes[:8192]
            if is_binary:
                return {
                    "success": False,
                    "error": "Binary file cannot be written safely without SFTP or working base64 utility on target host.",
                    "session_id": session.id
                }
            if any(byte < 0x20 and byte not in (9, 10, 13) for byte in payload_bytes):
                return {
                    "success": False,
                    "error": "Refusing to send control bytes through a cooked PTY",
                    "session_id": session.id,
                }
            # In quoted heredoc (cat << 'DELIM'), shell treats all characters literally.
            # Do NOT replace "'" with "'\''" as that would corrupt file contents!
            raw_content = payload_bytes.decode('utf-8', errors='ignore')
            # Generate collision-safe heredoc delimiter checking against raw payload_bytes
            heredoc_delim = f"MCP_HEREDOC_{stamp}"
            while heredoc_delim.encode('utf-8') in payload_bytes:
                heredoc_delim += "_x"
            marker_hd_ok = f"MCP_HD_OK_{stamp}"
            heredoc_cmd = (
                f"cat << '{heredoc_delim}' > '{tmp_remote}' && mv -f '{tmp_remote}' '{safe_path}'\n{raw_content}\n{heredoc_delim}\n"
                f"if [ $? -eq 0 ] && [ -f '{safe_path}' ]; then echo '{marker_hd_ok}'; else rm -f '{tmp_remote}'; fi"
            )
            write_res = _sync_shell(session, heredoc_cmd, timeout=15.0, internal=True)
            if write_res.get("success", False) and re.search(rf"^(?:.*?[#$>]\s*)?{re.escape(marker_hd_ok)}\s*$", write_res.get("output", ""), re.MULTILINE):
                return {"success": True, "method": "shell_cat_heredoc"}
            return {"success": False, "error": "Interactive shell write failed", "session_id": session.id}
    finally:
        _close_exec_streams(stdin_dir, stdout_dir, stderr_dir, stdin, stdout, stderr)

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

def _download_remote_to_path(session: SSHSession, remote_path: str, local_path: str) -> Dict[str, Any]:
    """Stream a remote file to disk. Never load the whole file into memory."""
    sftp = session.open_sftp()
    if sftp is not None:
        try:
            total = 0
            hasher = hashlib.sha256()
            with sftp.file(remote_path, "rb") as handle, open(local_path, "wb") as out:
                while True:
                    chunk = handle.read(_DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise OverflowError("download exceeds cap")
                    out.write(chunk)
                    hasher.update(chunk)
            return {"success": True, "method": "sftp", "size": total, "sha256": hasher.hexdigest()}
        except OverflowError:
            try:
                os.remove(local_path)
            except OSError:
                pass
            return {
                "success": False,
                "error": f"download exceeds {MAX_DOWNLOAD_BYTES} bytes; narrow the path or download in chunks",
            }
        except Exception as exc:
            log_error(f"sftp download failed, fallback capped read: {exc}")
            try:
                if os.path.exists(local_path):
                    os.remove(local_path)
            except OSError:
                pass
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    read_result = _read_remote_file_bytes(session, remote_path, max_bytes=MAX_DOWNLOAD_BYTES)
    if not read_result.get("success", False):
        return read_result
    if read_result.get("truncated"):
        return {
            "success": False,
            "error": f"download exceeds {MAX_DOWNLOAD_BYTES} bytes; narrow the path or download in chunks",
        }
    data = read_result["data"]
    with open(local_path, "wb") as handle:
        handle.write(data)
    return {
        "success": True,
        "method": read_result.get("method"),
        "size": len(data),
        "sha256": _sha256_hex(data),
    }


def _file_busy_error(session, node) -> Dict[str, Any]:
    alias = getattr(session, "server_alias", node.alias)
    return {
        "success": False,
        "error": f"Session {alias}/{session.id} is busy",
        "session_id": f"{alias}/{session.id}",
        "server": node.alias,
    }


def _hold_file_op(session, node) -> Optional[Dict[str, Any]]:
    """Reserve a real SSHSession for the file op. MagicMock sessions keep the is_busy() is True check."""
    begin = getattr(type(session), "begin_file_op", None)
    if not callable(begin):
        if session.is_busy() is True:
            return _file_busy_error(session, node)
        return None
    if begin(session) is not True:
        return _file_busy_error(session, node)
    session._file_op_held = True
    return None


def _release_file_op(session) -> None:
    if getattr(session, "_file_op_held", False) is not True:
        return
    end = getattr(session, "end_file_op", None)
    if callable(end):
        end()
    session._file_op_held = False


def file_dispatch(args: Dict[str, Any], manager) -> Dict[str, Any]:
    action = (args.get("action") or "").strip().lower()
    if action not in {"read", "write", "list", "upload", "download", "edit"}:
        return {"success": False, "error": "action must be one of: read, write, list, upload, download, edit"}

    node, numeric_sid, _, err_resp = manager.resolve_target_for_args(args)
    if err_resp:
        return err_resp

    effective_readonly = node.server_config.read_only or config.READ_ONLY
    if effective_readonly and action in {"write", "edit", "upload"}:
        return {
            "success": False,
            "error": f"Security: action '{action}' is blocked in read-only sandbox mode on server '{node.alias}'.",
            "server": node.alias
        }

    session = node.get_session(numeric_sid)
    if not session:
        if numeric_sid is not None:
            return {"success": False, "error": f"Session {numeric_sid} not found on server '{node.alias}'", "server": node.alias}
        session = node.ensure_session()
    if not session:
        return {"success": False, "error": f"no session available on server '{node.alias}'", "server": node.alias}

    is_b = session.is_busy() if callable(getattr(session, "is_busy", None)) else getattr(session, "is_busy", False)
    if is_b is True:
        return _file_busy_error(session, node)

    alive_error = session.ensure_alive() if callable(getattr(session, "ensure_alive", None)) else None
    if alive_error or getattr(session, "is_dead", False) is True:
        death_r = getattr(session, "death_reason", None) or alive_error
        return {"success": False, "error": f"Session is closed or disconnected: {death_r}", "server": node.alias}

    hold_error = _hold_file_op(session, node)
    if hold_error:
        return hold_error
    try:
        return _file_dispatch_held(args, session, node)
    finally:
        _release_file_op(session)


def _file_dispatch_held(args: Dict[str, Any], session, node) -> Dict[str, Any]:
    action = (args.get("action") or "").strip().lower()
    path = (args.get("path", "") or "").strip()
    raw_local_path = (args.get("local_path", "") or "").strip()
    srv_str = getattr(session, "server_alias", None)
    num_id = getattr(session, "id", None)
    sid_str = f"{srv_str}/{num_id}" if srv_str else num_id

    if raw_local_path:
        local_path = resolve_local_path(raw_local_path)
        if not local_path:
            return {
                "success": False,
                "error": f"Security: Local path '{raw_local_path}' is outside project sandbox or invalid.",
                "session_id": sid_str,
                "server": srv_str
            }
    else:
        local_path = ""

    content = args.get("content")
    is_base64 = to_bool(args.get("is_base64", False))

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
                return {
                    "success": True, "action": "list", "path": target, "method": "sftp",
                    "files": rows, "session_id": sid_str, "numeric_session_id": session.id,
                    "server": srv_str, "session_name": session.name, "status": "completed"
                }
            except Exception as exc:
                log_error(f"sftp list failed, fallback shell: {exc}")
            finally:
                try: sftp.close()
                except Exception: pass

        try:
            safe_target = escape_shell_path(target)
        except ValueError as exc:
            return {"success": False, "error": str(exc), "session_id": sid_str, "server": srv_str}
        shell_result = _sync_shell(session, f"ls -la '{safe_target}'", timeout=30.0)
        if not shell_result.get("success", False):
            return shell_result
        return {
            "success": True,
            "action": "list",
            "path": target,
            "method": "shell",
            "listing": shell_result.get("output", ""),
            "session_id": sid_str,
            "numeric_session_id": session.id,
            "server": srv_str,
            "session_name": session.name,
            "status": "completed"
        }

    if action == "read":
        if not path:
            return {"success": False, "error": "path is required for read"}
        if local_path:
            parent = os.path.dirname(local_path)
            if parent: os.makedirs(parent, exist_ok=True)
            read_result = _download_remote_to_path(session, path, local_path)
            if not read_result.get("success", False):
                return read_result
            return {
                "success": True,
                "action": "read",
                "mode": "download",
                "path": path,
                "local_path": local_path,
                "method": read_result["method"],
                "size": read_result["size"],
                "sha256": read_result["sha256"],
                "session_id": sid_str,
                "numeric_session_id": session.id,
                "server": srv_str,
                "status": "completed"
            }

        offset_line = args.get("offset_line")
        if offset_line is not None:
            try: offset_line = int(offset_line)
            except (ValueError, TypeError): return {"success": False, "error": "offset_line must be number"}

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
                "session_id": sid_str,
                "numeric_session_id": session.id,
                "server": srv_str,
                "status": "completed"
            }

        text = payload_bytes.decode("utf-8", errors="replace")

        if contains or regex or tail_lines is not None:
            filtered = apply_text_filters(text, contains=contains, regex=regex, tail_lines=tail_lines)
            if not filtered.get("success", False):
                return {"success": False, "error": filtered.get("error", "filtering error"), "session_id": sid_str, "server": srv_str, "session_name": session.name}
            window = _slice_text_by_lines(filtered["output"], offset_line=offset_line, limit_lines=limit_lines)
            inspect_text = window["text"]
            is_filtered = filtered["filtered"]
            matched_lines = filtered["matched_lines"]
            scanned_chars = filtered["scanned_chars"]
        else:
            window = _slice_text_by_lines(text, offset_line=offset_line, limit_lines=limit_lines)
            inspect_text = window["text"]
            is_filtered = False
            matched_lines = window["total_lines"]
            scanned_chars = len(text)

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
            "filtered": is_filtered,
            "matched_lines": matched_lines,
            "scanned_chars": scanned_chars,
            "line_start": window["line_start"],
            "line_end": window["line_end"],
            "total_lines": window["total_lines"],
            "truncated": bool(read_result.get("truncated", False) or char_limited),
            "session_id": sid_str,
            "numeric_session_id": session.id,
            "server": srv_str,
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
            return {"success": False, "error": f"file is larger than edit max_bytes ({edit_max_bytes})", "path": path, "session_id": sid_str, "server": srv_str, "session_name": session.name}

        original_bytes = read_result["data"]
        try:
            original_text = original_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "success": False,
                "error": "file is not valid UTF-8; refusing to rewrite it",
                "path": path,
                "session_id": sid_str,
                "server": srv_str,
            }
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
                        "session_id": sid_str,
                        "server": srv_str
                    }
                if replace_all:
                    updated_text = updated_text.replace(old_text, new_text)
                    total_replacements += occurrences
                else:
                    updated_text = updated_text.replace(old_text, new_text, 1)
                    total_replacements += 1
                continue
            
            # If no exact match, try flexible newline matching without destroying CRLF in the whole file
            parts = [re.escape(part) for part in old_text.replace("\r\n", "\n").split("\n")]
            pattern_str = r"\r?\n".join(parts)
            
            pattern = re.compile(pattern_str)
            matches = list(pattern.finditer(updated_text))
            occurrences = len(matches)

            if occurrences == 0:
                lines = updated_text.splitlines()
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
                    "session_id": sid_str,
                    "server": srv_str
                }
            
            if not replace_all and occurrences != 1:
                matching_snippets = []
                for match in matches:
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
                    "session_id": sid_str,
                    "server": srv_str
                }

            updated_text = pattern.sub(lambda m: new_text, updated_text, count=0 if replace_all else 1)
            total_replacements += occurrences

        updated_bytes = updated_text.encode("utf-8")
        changed = updated_bytes != original_bytes
        result_payload = {
            "success": True, "action": "edit", "mode": "edit", "path": path,
            "changed": changed, "replacements": total_replacements, "dry_run": dry_run,
            "old_sha256": _sha256_hex(original_bytes), "new_sha256": _sha256_hex(updated_bytes), "size": len(updated_bytes),
            "session_id": sid_str, "numeric_session_id": session.id, "server": srv_str, "status": "completed"
        }

        if dry_run or not changed:
            result_payload["method"] = read_result["method"]
            return result_payload

        if create_backup:
            backup_path = f"{path}.mcp.bak"
            backup_result = _write_remote_file_bytes(session, backup_path, original_bytes)
            if not backup_result.get("success", False):
                return {"success": False, "error": f"failed to create backup at {backup_path}", "path": path, "session_id": sid_str, "server": srv_str, "session_name": session.name}
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
        chunks = []
        remaining = MAX_INLINE_WRITE_BYTES + 1
        with open(local_path, "rb") as handle:
            while remaining > 0:
                piece = handle.read(min(65536, remaining))
                if not piece:
                    break
                chunks.append(piece)
                remaining -= len(piece)
        payload_bytes = b"".join(chunks)
        if len(payload_bytes) > MAX_INLINE_WRITE_BYTES:
            return {
                "success": False,
                "error": f"local_path is too large ({len(payload_bytes)} bytes); limit is {MAX_INLINE_WRITE_BYTES}",
            }
        source = "local_path"
    else:
        if content is None: return {"success": False, "error": "for write/upload provide local_path or inline content"}
        try: payload_bytes = base64.b64decode(str(content)) if is_base64 else str(content).encode("utf-8")
        except Exception: return {"success": False, "error": "failed to decode inline content"}
        if len(payload_bytes) > MAX_INLINE_WRITE_BYTES:
            return {"success": False, "error": f"inline content too large ({len(payload_bytes)} bytes)"}
        source = "inline_content"

    write_result = _write_remote_file_bytes(session, path, payload_bytes)
    if not write_result.get("success", False): return write_result

    return {
        "success": True, "action": "write", "path": path, "local_path": local_path,
        "source": source, "method": write_result["method"], "size": len(payload_bytes),
        "sha256": _sha256_hex(payload_bytes),
        "session_id": sid_str, "numeric_session_id": session.id, "server": srv_str, "status": "completed"
    }
