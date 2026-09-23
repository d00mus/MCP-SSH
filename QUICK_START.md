# Quick Start: Multi-Server SSH MCP Gateway

Control all your SSH infrastructure (routers, NAS, VPS, staging clusters) through a **single, unified MCP server instance**.

---

## 1. Prepare Configuration (`servers.json`)

Create `servers.json` in your workspace root (or copy from `servers.json.example`):

```json
{
  "servers": {
    "keenetic": {
      "host": "192.168.1.1",
      "port": 22,
      "user": "admin",
      "password": "${KEENETIC_PASSWORD}",
      "description": "Keenetic Ultra router",
      "verify_host": false,
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

> **Feature Highlight:** Supports environment variable interpolation (e.g. `${KEENETIC_PASSWORD}`), `~` home expansion, up to 10 concurrent sessions per server by default, and zero-downtime hot-reload when edited.

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

## 4. Key Agent Workflows & Best Practices

1. **Discover Servers:**
   The AI calls `server_list` to see all configured hosts, status, and active sessions.
2. **Execute Commands (`run`):**
   - Explicit target: `run(server="keenetic", command="show interface", shell=false)`
   - Composite session ID: `run(session_id="nas/1", command="zpool status")`
   - **Direct Output:** For commands completing within 5.0s, output is returned directly in the response. Do NOT call `read` after a completed command!
   - **Long-Running Commands:** Commands taking longer than 5.0s return `still_running: true` without failing. Read their remaining output via `read`.
   - **Sequential vs Concurrent:** Pass `session_id` to run sequential commands in the same session. Omit `session_id` to reuse an idle session (or pass `new_session: true` for a clean one).
   - **Async Execution:** Pass `wait_timeout: 0` for immediate confirmed start in background.
   - **Standard Shell Pipelines:** Use standard `| grep`, `| awk`, `| head` inside the command string for filtering.
   - **Multiline code / scripts:** For Python snippets (`python3 -c "..."`) or scripts with newlines, pass `use_pty: false` to avoid secondary prompt (`>`) issues in PTY.
3. **Session Management (1 Session = 1 Terminal):**
   - An SSH session is a single terminal process (PTY). Never send concurrent commands to the same session.
   - Reuse `session_id` for sequential steps; pass `new_session: true` to execute commands in parallel in a clean session (omitting `session_id` reuses an idle one).
   - Close temporary diagnostic sessions with `session_close` when done to free the session limit.
   - For Keenetic: keep NDM CLI (`shell: false`) and Linux shell (`shell: true`) in separate sessions.
4. **Buffered Output, Scrolling & Rewind (`read`):**
   - Call `read` only if `run` returned `still_running: true` or to scroll through the terminal tab history.
   - By default reads the latest command in the tab; neither `offset` nor any run identifier is required for standard reads.
   - The gateway retains up to 2MB circular buffer per tab. If you experience context loss or amnesia, call `read(offset=0)` to rewind and re-read the entire tab history from the beginning, or pass negative offset (e.g. `offset=-2000`) for the buffer tail.
5. **Interrupt Stuck Commands (`signal`):**
   - Call `signal(action="ctrl_c")` to immediately terminate a hanging command and free the session.
6. **Register New Servers On The Fly:**
   - The AI can call `server_add(alias="staging-app", host="10.0.0.5", user="deploy")` without restarting the server.
7. **Live Hot-Reload:**
   - Edit credentials or servers in `servers.json` — the gateway detects changes automatically within seconds with zero downtime for unaffected sessions.
