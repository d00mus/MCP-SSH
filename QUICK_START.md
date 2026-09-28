# Quick Start: Multi-Server SSH MCP Gateway

Connect an MCP client to your SSH hosts through one locally running gateway. Start with the simpler [README setup](README.md#try-it-with-one-host); the examples below cover more options.

---

## 1. Prepare Configuration (`servers.json`)

Create `servers.json` at the absolute path you will pass with `--servers-config` (or copy [servers.json.example](servers.json.example)):

```json
{
  "servers": {
    "keenetic": {
      "host": "192.168.1.1",
      "port": 22,
      "user": "admin",
      "password": "${KEENETIC_PASSWORD}",
      "description": "Keenetic Ultra router",
      "verify_host": true,
      "extra_path": "/opt/bin:/opt/sbin"
    },
    "nas": {
      "host": "192.168.1.10",
      "port": 22,
      "user": "storage",
      "key_path": "~/.ssh/id_rsa",
      "description": "TrueNAS storage",
      "max_sessions": 10
    },
    "vps-prod": {
      "host": "203.0.113.5",
      "port": 2222,
      "user": "ubuntu",
      "key_path": "~/.ssh/vps_key",
      "read_only": true,
      "command_blacklist": ["reboot", "poweroff", "rm -rf"],
      "description": "Production web server (read-only)"
    }
  }
}
```

> **Before connecting:** verify and add the SSH host key to the system host-key store on the machine running the gateway. `verify_host: true` rejects unknown host keys. `${KEENETIC_PASSWORD}` must be set in the MCP process environment. `read_only` and command blacklists are mistake guards, not a security boundary; use restricted SSH accounts. See [SECURITY.md](SECURITY.md).

---

## 2. Installation & Running

### Path A: Python (Fastest)

```bash
pip install -r requirements.txt
```

### Path B: Docker

```bash
docker build -t mcp-ssh-server .
```

---

## 3. Configure your AI Agent

### MCP Client Config (`mcp.json`)

**With Python (Windows example):**
```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "python",
      "args": [
        "C:\\tools\\ssh-gateway\\mcp-server.py",
        "--servers-config", "C:\\tools\\ssh-gateway\\servers.json",
        "--project-root", "C:\\work"
      ],
      "env": {
        "KEENETIC_PASSWORD": "your_secure_password"
      }
    }
  }
}
```

**With Docker:**

```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "C:/tools/ssh-gateway/servers.json:/app/servers.json:ro",
        "-v", "C:/Users/username/.ssh:/root/.ssh:ro",
        "-v", "C:/tools/ssh-gateway/.ssh-cache:/app/.ssh-cache",
        "mcp-ssh-server",
        "--servers-config", "/app/servers.json"
      ],
      "env": {
        "KEENETIC_PASSWORD": "your_secure_password"
      }
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "python",
      "args": [
        "/opt/ssh-gateway/mcp-server.py",
        "--servers-config", "/opt/ssh-gateway/servers.json"
      ]
    }
  }
}
```

---

### 4. Key Agent Workflows & Best Practices

1. **Discover Servers:**
   The AI calls `server_list` to see all configured hosts, status, and active sessions. `server_list` always provides inline `active_sessions: [{"session_id": "...", "status": "...", "mode": "..."}]` in both profiles, eliminating the need for `session_list`.
2. **Execute Commands (`run`):**
   - Explicit target: `run(server="keenetic", command="show interface", shell=false)`
   - Composite session ID: `run(session_id="nas/1", command="zpool status")`
   - **Direct Output:** Commands that complete within 5.0s return their first output window directly. Call `read` only if `has_more` reports unread lines, or if a command is still running; a completed command with `has_more: 0` needs no extra read.
   - **Long-Running Commands:** Commands taking longer than 5.0s return `still_running: true` without failing. Read their remaining output via `read(session_id="...")`. `status` may also be `completed_nonzero`, `interrupted` (e.g. when `hard_timeout` fired; partial output kept) or `stalled` (quiet idle with no end-of-command marker; adds `unconfirmed_completion: true`).
   - **Sequential vs Concurrent:** Pass `session_id` to run sequential commands in the same session. Omit `session_id` to reuse an idle session (or pass `new_session: true` for a clean one).
   - **Async Execution:** Pass `wait_timeout: 0` for immediate return while the command continues in its session.
   - **Standard Shell Pipelines:** Use standard `| grep`, `| awk`, `| head` inside the command string for filtering.
   - **Single non-interactive commands:** Pass `use_pty: false` for pure single exec commands with closed `stdin` (bypasses terminal echoes and PTY line limits; note: interactive heredocs are not supported when `use_pty: false`).
3. **Session Management (1 Session = 1 Terminal):**
   - An SSH session is a single terminal process (PTY). Never send concurrent commands to the same session.
   - Reuse `session_id` for sequential steps; pass `new_session: true` to execute commands in parallel in a clean session (omitting `session_id` reuses an idle one).
   - Close temporary diagnostic sessions with `session_close` when done to free the session limit.
   - For Keenetic: keep NDM CLI (`shell: false`) and Linux shell (`shell: true`) in separate sessions.
4. **Buffered Output, Scrolling & Canvas Windowing (`read`):**
   - **One line-based stream** (the tab canvas): `line_limit` (default 200 lines, max 5000, `0` = no line cap), `tail` (last N lines; moves the unread position to the end and reports skipped unread lines as `dropped_data`), `offset` (**line** position: negative=peek back from the cursor, `0`=inspect from the very first line, positive=inspect from line N; any `offset` is a non-consuming peek - the unread cursor does NOT move and progress is preserved). `has_more` is the **number of unread LINES still left** (`0` = caught up) - repeat the same read to continue.
   - Paging is server-side: there is no continuation token (the old `cursor` argument was removed and is rejected) - a plain `read(session_id)` continues with the unread output.
   - Per-tab history holds up to 2,000,000 characters; output is mirrored into the canvas and completed run buffers are evicted under a global budget, so `offset: 0` still re-reads whatever the canvas holds (`dropped_data` reports unread text dropped before it could be delivered).
   - The response also carries `status` (`running`, `completed`, `completed_nonzero`, `interrupted`, `stalled`) and `still_running`; a window cut by `line_limit` is reported through `has_more` plus a `hint` (raise line_limit or read again). `wait_timeout` waits for completion **or** new output and blocks only while the stream is silent.
5. **Interrupt Stuck Commands (`signal`):**
   - Call `signal(action="ctrl_c")` to immediately terminate a hanging command and free the session.
6. **Remote Files (`file`):**
   - Inspect or download files with `action: "read"`. Supports line-based pagination (`offset_line: 1`, `limit_lines: 200`, returning `next_offset_line`).
   - Modify remote files with `action: "edit"` and search-and-replace (`edits: [{"old_text": "...", "new_text": "..."}]`); `create_backup: true` requests a `.mcp.bak` backup. Do not assume every remote filesystem or shell fallback guarantees atomic replacement or private permissions.
7. **Register New Servers On The Fly:**
   - In full profile, the AI can call `server_add(alias="staging-app", host="10.0.0.5", user="deploy")` without restarting the server.
8. **Live Hot-Reload:**
   - Edit credentials or servers in `servers.json` — the gateway detects changes automatically on the next health-loop pass (every 30 seconds), or immediately via `server_list(reload: true)`, with zero downtime for unaffected sessions.
