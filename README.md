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
| **Configuration Restarts** | Adding or editing a server requires restarting the MCP server, dropping all open SSH sessions and background jobs. | **Zero-Downtime Hot-Reload:** Automatically detects changes in `servers.json` on the health-loop pass (every 30s). Adds new servers, updates policies, and reloads without interrupting active sessions. |
| **Interactive Prompt Hangs** | Freezes forever when a command prompts for `[y/n]`, `[Enter]`, or passwords. Wastes your API budget while waiting for a timeout. | **Intelligent Anti-Hang Engine:** Instantly detects interactive prompts (like `Password:`, `[Y/n]`), pauses, and returns a helpful warning so the LLM knows it requires non-interactive flags. |
| **Silent Command Failures** | Command errors (non-zero exit codes) are returned as plain text. LLMs often miss them, assume success, and keep hallucinating. | **Explicit Exit Status:** Non-zero exits return status completed_nonzero + exit_status (not a tool error), so the LLM sees success/failure explicitly and self-corrects. |
| **Long-Running Daemons** | Launching a dev server or log watcher blocks the connection, causing the IDE agent to freeze, crash, or fail to progress. | **Multiplexed Multi-Sessions:** Act like `tmux` for AI. Default 5.0s timeout returns `still_running: true` without failing. Immediate async start via `wait_timeout: 0`. Run concurrent sessions via `new_session: true`. |
| **Restricted Shells & Pagers** | Completely breaks on network appliances, enterprise switches, and routers (like **Keenetic** CLI) that force pagination (`--More--`). | **Keenetic & Pager Aware:** Specialized logic to handle pager prompts, auto-paginate, and separate NDM CLI (`shell: false`) from Linux shell (`shell: true`). |
| **File Editing Overhead** | AI must download the entire file, edit it locally, and re-upload it. Extremely slow, expensive, and error-prone. | **Smart In-place Remote Editing:** Built-in `file.edit` that executes safe search-and-replace with line-numbered diagnostics and similarity matching on typos. |
| **Unsafe / Destructive Commands** | LLM can hallucinate and execute destructive commands (`rm -rf /`, `reboot`) across sensitive production servers. | **Per-Host Guardrails:** Read-only denylist and merged per-host command blacklists (regex over the command text) catch the obvious cases, plus local directory containment for file transfers. A guardrail for the LLM, **not a security boundary**. |

---

## Key Design Philosophies & Superpowers

### 1. Unified Multi-Server Architecture
Instead of registering 5–10 individual MCP servers in your IDE, configure all your hosts in a single `servers.json`. The AI agent uses a clean, predictable routing convention:
- Call `server_list` to inspect all configured targets, statuses, and active sessions.
- Target any host via `server: "vps"` or composite session ID `session_id: "vps/1"`.
- Agent can register new servers on the fly via `server_add` (append-only for security).

### 2. Live Zero-Downtime Hot-Reload
Change a password, adjust a blacklist, or add a new host directly in `servers.json`:
- The gateway detects file modifications via `mtime` and content hashing on each health-loop pass (every 30s).
- Unaffected hosts and ongoing terminal sessions remain 100% uninterrupted.
- Policy changes (`read_only`, `command_blacklist`, `description`, `max_sessions`) apply immediately without dropping connections.
- Agents can trigger on-demand reloads with `server_list(reload=true)`.

### 3. Multiplexed Multi-Sessions (`tmux` for AI)
Standard SSH MCPs open a new connection for every tool call or block the terminal line on long-running processes. This server keeps multiple SSH channels open concurrently across different targets (up to 10 concurrent sessions per server by default). Background processes run reliably while the agent works in another session.

### 4. Token-Saving and Cost Optimization
AI agents don't need raw terminal noise. We sanitize the terminal stream on the server side:
- **ANSI Escape and Control Code Stripping:** Removes all terminal styling codes before returning text.
- **Predictable Output Windows & Pagination:** One unread stream per tab (the tab canvas) read through a single line-based cursor: `limit` (default 200 lines, max 5000, `0` = no line cap), `tail` (last N lines), `offset` = **line** position (negative peeks back from the cursor, `0` inspects from the very first line, positive inspects from line N; any `offset` is a non-consuming peek - the unread cursor does **not** move). `has_more` is the **number of unread lines still left** (`0` = all caught up).
- **Inspectable 2M-Character Buffer:** Retains up to 2,000,000 characters per tab without premature eviction. Output is mirrored into the tab canvas as it arrives and completed run buffers are evicted under a process-wide budget, so `offset: 0` inspects whatever the canvas holds without resetting unread progress. `dropped_data` reports unread text that was dropped before it could be delivered - including a `tail` jump that skips unread lines.
- **Native Shell Pipelines:** Agents use standard `| grep`, `| awk`, `| head` inside commands rather than inefficient client-side filtering.
- **On-Demand Verbose Debugging:** The server returns compact JSON responses by default. Deep telemetry is retrieved only when calling `last_command_details`.

### 5. Security Guardrails (and What They Are Not)
> **Honest scope.** The checks below are regex guardrails over the submitted command text.
> Shell quoting, expansion, base64 or an interpreter (`python3 -c`, `perl -e`, busybox sh) defeat
> them. They protect a mistaken agent from obvious self-harm; they do **not** contain a
> compromised one. For a real boundary use a restricted SSH account, `ForceCommand`/chroot,
> read-only filesystems or separate credentials per trust level.
- **Per-Host Read-Only Guardrail:** Blocks file-tool writes (`write`, `edit`, `upload`) and obvious write patterns in commands (redirections, package installs, disk formatting).
- **Command Blacklist Merging:** Server-level blacklists automatically merge with global blacklists into a unified enforcement set.
- **Append-Only Server Registration:** Agents can add new targets via `server_add`, but cannot modify or delete existing servers via MCP tool calls.
- **Local Containment:** File transfers are confined to the project root and the gateway cache dir; the gateway's own code/config files are never writable through the file tool.

---

## Available MCP Tools

Our toolset is optimized to minimize context bloat while giving your AI agent full terminal mastery:

> **`--tool-profile lean`** ships only the six everyday tools (`server_list`, `run`, `read`, `signal`,
> `file`, `session_close`) - roughly half the catalog tokens, which matters for small local models.
> `server_add`, `session_update` and `last_command_details` are admin/diagnostic tools that appear
> in the default `full` profile.

| Tool | Action | Description |
| :--- | :--- | :--- |
| `server_list` | Fleet overview | Lists all configured SSH servers with alias, host, user, status, active session counts. Supports `reload: true`. |
| `server_add` | Append target | Safely registers a new SSH target dynamically without restarting the server (append-only). |
| `session_list` | Session audit | Lists all active persistent sessions and their statuses (`idle`, `busy`, `broken`). Filterable by server prefix. |
| `session_update` | Rename session | Renames sessions for easier identification. |
| `session_close` | Terminate channel | Closes the session and tears down the SSH channel. It does **not** kill remote processes: a command already running on the server may keep going, and anything it writes to the channel after the close is lost. |
| `run` | Execute commands | Runs commands with 5s anti-hang timeout and returns output directly. Without `session_id`, an **idle session is reused with unknown state** (`new_session: true` forces a clean shell); pass the returned `session_id` for sequential commands to preserve state (cwd, env). If an explicit `session_id` is busy, it fails immediately — no background sessions are created. Only commands taking >5s return `still_running: true`. The first 200 lines (`max_lines`) come back directly; anything beyond that stays in the tab stream, and `has_more` reports how many unread LINES are still waiting - continue with `read(session_id)`. `wait_timeout: 0` or `background: true` = immediate async start, `hard_timeout` = interrupt after N seconds (`status: interrupted`, partial output kept), `use_pty: false` for single commands without PTY (stdin is closed, no interactive heredoc). |
| `read` | Read / Scroll Tab | Reads the tab's single unread stream (the tab canvas) through one **line-based** cursor: `limit` (default 200 lines, max 5000, `0` = no line cap, no synthetic newlines), `tail` (last N lines; moves the unread position to the end and reports skipped unread lines as `dropped_data`), `offset` = **line** position (negative=peek back from the cursor, `0`=inspect from the very first line, positive=inspect from line N; any `offset` is a non-consuming peek - the cursor does NOT move and unread progress is preserved). No bookkeeping counters are returned: `has_more` is the **number of unread LINES still left** (`0` = all caught up; a window cut by `max_chars`/`max_lines` also adds a `hint`), so call `read(session_id)` again to continue - there is no continuation token. `status` may be `running`, `completed`, `completed_nonzero`, `interrupted` or `stalled` (quiet idle with no end-of-command marker; adds `unconfirmed_completion: true`); `wait_timeout` waits for completion **or** new output and blocks only while the stream is silent. |
| `signal` | Control processes | Sends `action: "ctrl_c"` to immediately interrupt a stuck command and free the session, or `stdin` to answer prompts. |
| `file` | Manage files | Workspace-contained remote file tool (SFTP, shell fallback) supporting directory listings (`list`), chunked reading with line pagination (`read` with `offset_line`, `limit_lines`), safe atomic creation/overwriting with chmod before rename (`write`), and atomic in-place search-and-replace edits (`edit`), with an optional private `0600` `<path>.mcp.bak` backup (`create_backup: true`); new files are always written with mode `0600` (existing files keep their mode). |
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
      "description": "Production web server (read-only guardrail)"
    }
  }
}
```

> **Tip:** You can use environment variables like `${KEENETIC_PASSWORD}` directly in `servers.json` to avoid hardcoding secrets. Unresolved `${VAR}` references in `password`/`key_passphrase` fail at startup with a clear error.

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

### Tool Profiles: Lean vs Full
- **`--tool-profile lean` (6 tools):** Ships only `server_list`, `run`, `read`, `signal`, `file`, `session_close`. `server_list` always provides inline `active_sessions: [{"session_id": "...", "status": "...", "mode": "..."}]` in both profiles, so models don't need a separate `session_list` call. Recommended for token efficiency and lightweight local LLMs.
- **`--tool-profile full` (10 tools, default):** Includes the 6 core tools plus administrative/diagnostic tools: `server_add`, `session_list`, `session_update`, `last_command_details`.

---

### Concrete Agent Examples

#### 1. NDM Router Command (Keenetic CLI)
Run Cisco-style NDM commands directly with `shell: false`. Do not mix NDM CLI and Linux shell in the same session tab:
```json
// tools/call: run
{
  "server": "keenetic",
  "command": "show interface",
  "shell": false
}
```

#### 2. Linux One-Shot Command (Non-Interactive, use_pty: false)
Execute a standalone script or command via a clean single exec channel with closed `stdin` (no terminal wrappers or PTY echoes):
```json
// tools/call: run
{
  "server": "vps",
  "command": "cat /etc/os-release | grep PRETTY_NAME",
  "use_pty": false
}
```

#### 3. Long-Running Command & Clean Output Windowing
When a command runs longer than `wait_timeout` (`still_running: true`) or unread output remains (`has_more` > 0, including output cut by the inline limits), read the remaining output in clean line-based chunks:
```json
// Step 1: tools/call: run
{
  "server": "keenetic",
  "command": "show running-config",
  "shell": false
}
// Response: {"still_running": true, "has_more": 138, "output": "...", "session_id": "keenetic/1"}   // has_more = unread LINES

// Step 2: tools/call: read
{
  "server": "keenetic",
  "session_id": "keenetic/1",
  "limit": 200
}
// Response: has_more counts the unread LINES still left (0 = caught up), plus still_running - repeat the same read to continue; offset counts lines.
```

---

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
        "--project-root", "C:\\work"
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
| `--project-root` | String | `cwd` | Local project root for path containment and cache placement (CLI flag only - there is no `PROJECT_ROOT` environment variable). |
| `--cache-dir` / `SSH_MCP_CACHE_DIR` | String | `.ssh-cache` | Storage root for session logs, run buffers, and recovery state. |
| `--read-only` / `SSH_READ_ONLY` | Boolean | `False` | Global read-only guardrail override. |
| `--command-blacklist` / `SSH_COMMAND_BLACKLIST` | String | None | Global prohibited commands (comma-separated). |
| `--allow-system-temp` | Boolean | `False` | Allow the file tool to use the system temp directory (default: project root and cache dir only). |
| `--allow-gateway-dir` | Boolean | `False` | Allow the file tool to touch the gateway install directory (gateway development only; the gateway's own code stays protected). |
| `--log-output` | `full\|meta\|off` | `meta` | Log policy: `full` stores raw output chunks (secrets/IO heavy), `meta` lifecycle+command text only, `off` disables logging. Log disk usage is bounded by 200 MB of retention. |
| `--tool-profile` | `lean\|full` | `full` | Tool catalog size. `lean` = 6 everyday tools for small models. |
| `--import-ssh-config` | Boolean | `False` | Also register hosts from `~/.ssh/config` (key auth). Imported hosts survive hot-reload removal. |

---

## Community & Stars

This project is built out of frustration with fragile, single-host SSH MCP implementations. It is designed to be a dependable workhorse for daily AI agent engineering.

If this server saved your IDE session from freezing, cut down your API token spending, or made managing remote servers easier, **please consider dropping a Star ⭐ on the repository!**

---
## License
MIT
