# Robust Multi-Server SSH MCP Gateway with Persistent Sessions & Anti-Hang Protection

[![Model Context Protocol](https://img.shields.io/badge/MCP-Supported-blue)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**A professional, production-ready Multi-Server SSH Model Context Protocol (MCP) gateway engineered specifically for AI agents (Claude Desktop, Continue.dev, LLM IDEs).**

Most SSH MCP implementations are simple 1:1 single-host wrappers. When you manage multiple servers (routers, NAS, cloud VPS, staging environments), registering separate MCP servers explodes your tool catalog to 60–80+ tools, wastes precious context tokens, triggers hallucinations, and constantly freezes on interactive prompts.

This project is a **high-performance, resilient terminal gateway** that acts like a distributed `tmux` for your AI agent—featuring a **unified multi-host routing engine**, **zero-downtime hot-reload**, persistent multi-session control (up to 10 concurrent sessions per server by default), token-saving lean payloads, and automated anti-hang engines.

---

## The Difference: Why Existing SSH MCPs Fail (and How We Fix It)

| The Pain Point | Typical SSH MCP Server (The "Scooter") | This Gateway (The "Supercar") |
| :--- | :--- | :--- |
| **Context Bloat & Token Waste** | Separate MCP server for each host. 5 servers = 50+ tool definitions dumped into every prompt, burning API tokens and causing model confusion. | **Unified Multi-Server Gateway:** 1 single MCP instance exposing compact tools for your entire fleet. Route by `server: "alias"` or composite session IDs (`keenetic/1`, `vps/2`). |
| **Configuration Restarts** | Adding or editing a server requires restarting the MCP server, dropping all open SSH sessions and background jobs. | **Zero-Downtime Hot-Reload:** Automatically detects changes in `servers.json` within seconds. Adds new servers, updates policies, and reloads without interrupting active sessions. |
| **Interactive Prompt Hangs** | Freezes forever when a command prompts for `[y/n]`, `[Enter]`, or passwords. Wastes your API budget while waiting for a timeout. | **Intelligent Anti-Hang Engine:** Instantly detects interactive prompts (like `Password:`, `[Y/n]`), pauses, and returns a helpful warning so the LLM knows it requires non-interactive flags. |
| **Silent Command Failures** | Command errors (non-zero exit codes) are returned as plain text. LLMs often miss them, assume success, and keep hallucinating. | **Loud Exit Status Warning:** Automatically wraps failures in highly visible error headers and includes full stderr, forcing the LLM to recognize the error and auto-correct. |
| **Long-Running Daemons** | Launching a dev server or log watcher blocks the connection, causing the IDE agent to freeze, crash, or fail to progress. | **Multiplexed Multi-Sessions:** Act like `tmux` for AI. Default 5.0s timeout returns `still_running: true` without failing. Immediate async start via `wait_timeout: 0`. Run concurrent sessions via `new_session: true`. |
| **Restricted Shells & Pagers** | Completely breaks on network appliances, enterprise switches, and routers (like **Keenetic** CLI) that force pagination (`--More--`). | **Keenetic & Pager Aware:** Specialized logic to handle pager prompts, auto-paginate, and separate NDM CLI (`shell: false`) from Linux shell (`shell: true`). |
| **File Editing Overhead** | AI must download the entire file, edit it locally, and re-upload it. Extremely slow, expensive, and error-prone. | **Smart In-place Remote Editing:** Built-in `file.edit` that executes safe search-and-replace with line-numbered diagnostics and similarity matching on typos. |
| **Unsafe / Destructive Commands** | LLM can hallucinate and execute destructive commands (`rm -rf /`, `reboot`) across sensitive production servers. | **Per-Host Security Envelopes:** Enforces granular Read-Only sandboxing, local directory isolation, and merged per-server command blacklists. |

---

## Key Design Philosophies & Superpowers

### 1. Unified Multi-Server Architecture
Instead of registering 5–10 individual MCP servers in your IDE, configure all your hosts in a single `servers.json`. The AI agent uses a clean, predictable routing convention:
- Call `server_list` to inspect all configured targets, statuses, and active sessions.
- Target any host via `server: "vps"` or composite session ID `session_id: "vps/1"`.
- Agent can register new servers on the fly via `server_add` (append-only for security).

### 2. Live Zero-Downtime Hot-Reload
Change a password, adjust a blacklist, or add a new host directly in `servers.json`:
- The gateway detects file modifications via `mtime` and content hashing.
- Unaffected hosts and ongoing terminal sessions remain 100% uninterrupted.
- Policy changes (`read_only`, `command_blacklist`, `description`, `max_sessions`) apply immediately without dropping connections.
- Agents can trigger on-demand reloads with `server_list(reload=true)`.

### 3. Multiplexed Multi-Sessions (`tmux` for AI)
Standard SSH MCPs open a new connection for every tool call or block the terminal line on long-running processes. This server keeps multiple SSH channels open concurrently across different targets (up to 10 concurrent sessions per server by default). Background processes run reliably while the agent works in another session.

### 4. Token-Saving and Cost Optimization
AI agents don't need raw terminal noise. We sanitize the terminal stream on the server side:
- **ANSI Escape and Control Code Stripping:** Removes all terminal styling codes before returning text.
- **Predictable Output Windows & Pagination:** Clean pagination via `offset` and `next_offset`, with `limited: true` when output exceeds page limits.
- **Rewindable 2MB Buffer:** Retains output in memory without premature eviction. The agent can rewind and re-read from `offset: 0`.
- **Native Shell Pipelines:** Agents use standard `| grep`, `| awk`, `| head` inside commands rather than inefficient client-side filtering.
- **On-Demand Verbose Debugging:** The server returns compact JSON responses by default. Deep telemetry is retrieved only when calling `last_command_details`.

### 5. Defense-in-Depth Security
- **Per-Host Read-Only Sandbox:** Blocks write actions (`write`, `edit`, `upload`) and destructive shell patterns (redirections, package installations, disk formatting).
- **Command Blacklist Merging:** Server-level blacklists automatically merge with global blacklists into a unified enforcement set.
- **Append-Only Server Registration:** Agents can add new targets via `server_add`, but cannot modify or delete existing servers via MCP tool calls.

---

## Available MCP Tools

Our toolset is optimized to minimize context bloat while giving your AI agent full terminal mastery:

| Tool | Action | Description |
| :--- | :--- | :--- |
| `server_list` | Fleet overview | Lists all configured SSH servers with alias, host, user, status, active session counts. Supports `reload: true`. |
| `server_add` | Append target | Safely registers a new SSH target dynamically without restarting the server (append-only). |
| `session_list` | Session audit | Lists all active persistent sessions and their statuses (`idle`, `busy`, `broken`). Filterable by server prefix. |
| `session_update` | Rename session | Renames sessions for easier identification. |
| `session_close` | Terminate channel | Cleanly terminates remote background processes and tears down the SSH channel. |
| `run` | Execute commands | Runs commands with 5s anti-hang timeout and returns output directly. Sequential commands reuse session via `session_id`. Concurrent commands omit `session_id`. Only commands taking >5s return `still_running: true` (read remaining output via `read`). Set `wait_timeout: 0` for async execution. Set `use_pty: false` for multiline scripts. |
| `read` | Read / Scroll Tab | Reads remaining output for commands that returned `still_running: true`, or scrolls through the terminal tab history. Supports full rewind (`offset: 0`) for agent context recovery, tail viewing (negative offset), and pagination (`next_offset`). Retains up to 2MB circular buffer. |
| `signal` | Control processes | Sends `action: "ctrl_c"` to immediately interrupt a stuck command and free the session, or `stdin` to answer prompts. |
| `file` | Manage files | Sandbox-compliant file tool supporting directory listings, read windows, uploads, downloads, and in-place search-and-replace edits. |
| `last_command_details`| Command inspect | Returns exact command string, arguments, execution status, and raw output of the last executed tool call for troubleshooting. |

---

## Quick Start

### 1. Configure Servers (`servers.json`)

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
      "description": "TrueNAS storage server",
      "max_sessions": 10
    },
    "vps": {
      "host": "203.0.113.5",
      "port": 2222,
      "user": "ubuntu",
      "key_path": "~/.ssh/vps_key",
      "read_only": true,
      "command_blacklist": ["reboot", "poweroff", "rm -rf"],
      "description": "Production web server (read-only sandbox)"
    }
  }
}
```

> **Tip:** You can use environment variables like `${KEENETIC_PASSWORD}` directly in `servers.json` to avoid hardcoding secrets. Standard `~/.ssh/config` hosts are also automatically recognized!

### 2. Choose Deployment Option

#### Option A: Docker (Recommended)
Build the image locally:
```bash
docker build -t mcp-ssh-server .
```

#### Option B: Python (Manual)
```bash
git clone https://github.com/your-username/ssh-gateway-mcp.git
cd ssh-gateway-mcp
pip install -r requirements.txt
```

---

## IDE & Client Configuration

### MCP Client Config (`mcp.json`)

**Using Python:**
```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "python",
      "args": [
        "C:\\tools\\ssh-gateway\\mcp-server.py",
        "--servers-config", "C:\\tools\\ssh-gateway\\servers.json",
        "--project-root", "C:\\tools\\ssh-gateway"
      ],
      "env": {
        "KEENETIC_PASSWORD": "your_secure_password"
      }
    }
  }
}
```

**Using Docker:**
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

## Configuration Reference

| Parameter / Env | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--servers-config` / `SSH_SERVERS_CONFIG` | String | `servers.json` | Path to JSON file with server targets or inline JSON string. |
| `--project-root` / `PROJECT_ROOT` | String | `cwd` | Local project root for path sandboxing and cache placement. |
| `--cache-dir` / `SSH_MCP_CACHE_DIR` | String | `.ssh-cache` | Storage root for session logs, run buffers, and recovery state. |
| `--read-only` / `SSH_READ_ONLY` | Boolean | `False` | Global Read-Only sandbox override. |
| `--command-blacklist` / `SSH_COMMAND_BLACKLIST` | String | None | Global prohibited commands (comma-separated). |

---

## Community & Stars

This project is built out of frustration with fragile, single-host SSH MCP implementations. It is designed to be a dependable workhorse for daily AI agent engineering.

If this server saved your IDE session from freezing, cut down your API token spending, or made managing remote servers easier, **please consider dropping a Star ⭐ on the repository!**

---
## License
MIT
