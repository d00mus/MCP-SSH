# Robust SSH MCP Server with Persistent Sessions & Anti-Hang Protection

[![Model Context Protocol](https://img.shields.io/badge/MCP-Supported-blue)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![GitHub Stars](https://img.shields.io/github/stars/d00mus/SSH-MCP?style=social)](https://github.com/d00mus/SSH-MCP)

**A professional, production-ready SSH Model Context Protocol (MCP) server engineered specifically for AI agents (Cursor, Claude Desktop, Continue.dev).**

Most SSH MCP implementations are simple, stateless wrappers. They constantly freeze on interactive prompts, blow up your context token limits with giant logs, or make your agent stall during long-running background tasks. 

This project is a **high-performance, resilient terminal gateway** that acts like a `tmux` for your AI agent—featuring persistent multi-session control, token-saving lean payloads, and automated anti-hang engines.

---

## The Difference: Why Existing SSH MCPs Fail (and How We Fix It)

| The Pain Point | Typical SSH MCP Server (The "Scooter") | This Implementation (The "Supercar") |
| :--- | :--- | :--- |
| **Interactive Prompt Hangs** | Freezes forever when a command prompts for `[y/n]`, `[Enter]`, or passwords. Wastes your API budget while waiting for a timeout. | **Intelligent Anti-Hang Engine:** Instantly detects interactive prompts (like `Password:`, `[Y/n]`), pauses, and returns a helpful warning so the LLM knows it requires non-interactive flags. |
| **Context Bloat & Token Cost** | Dumps 10MB log files straight into the LLM context. You hit context limits, pay massive API bills, and the LLM loses its focus. | **Ultra-Lean Payloads:** Enforces compact JSON responses, server-side line/byte filters, and smart **middle truncation** (keeps head & tail) to protect your context window. |
| **Silent Command Failures** | Command errors (non-zero exit codes) are returned as plain text. LLMs often miss them, assume success, and keep hallucinating. | **Loud Exit Status Warning:** Automatically wraps failures in highly visible error headers, forcing the LLM to recognize the error and auto-correct. |
| **Long-Running Daemons** | Launching a dev server or log watcher blocks the connection, causing the IDE agent to freeze, crash, or fail to progress. | **Multiplexed Multi-Sessions:** Act like `tmux` for AI. Start a background process in session A, and seamlessly switch to session B to inspect logs or run files. |
| **Restricted Shells & Pagers** | Completely breaks on network appliances, enterprise switches, and routers (like **Keenetic** CLI) that force paginated pagination (like `--More--`). | **Keenetic & Pager Aware:** Specialized logic to handle pager prompts, auto-paginate, and seamlessly enter Linux environments (like Entware). |
| **File Editing Overhead** | AI must download the entire file, edit it locally, and re-upload it. Extremely slow, expensive, and error-prone. | **Smart In-place Editing:** Built-in `file.edit` that executes safe, local search-and-replace with line-numbered diagnostics on conflicts. |
| **Unsafe / Hallucinated Commands** | LLM can easily hallucinate and run destructive terminal commands (like `rm -rf /` or reboot/poweroff actions). | **Remote Sandboxing & Blacklist:** Enforces strict local directory sandboxing, remote Read-Only modes, and customizable command blacklists. |

---

## Key Design Philosophies & Superpowers

### 1. Multiplexed Multi-Sessions (tmux for AI)
Standard SSH MCPs open a new connection for every tool call or block the terminal line on long-running processes. This server keeps multiple SSH channels open concurrently. The AI agent can manage background jobs (like watchers, servers, or long installations) in one session, while performing diagnostic work or reading files in another. Sessions are stored in a local, zero-RAM cache on disk and recovered automatically if a connection drops.

### 2. Token-Saving and Cost Optimization
AI agents don't need raw terminal noise. We sanitize the terminal stream on the server side:
- **ANSI Escape and Control Code Stripping:** Removes all terminal styling codes before returning text.
- **Middle Truncation:** For large files, we preserve the beginning (context/headers) and the end (recent errors/logs), stripping out the repetitive middle.
- **On-Demand Verbose Debugging:** The server returns compact JSON responses by default. Full telemetry, network statistics, and buffers are only retrieved when the agent specifically calls `last_command_details` to resolve an error.

### 3. Bulletproof Anti-Hang Safeguards
LLMs are notorious for running commands that trigger interactive prompts (e.g., `apt-get install` without `-y`, or `git push` prompting for credentials). 
Our engine continuously monitors stdout. If it matches common patterns (like `[y/N]` or `Password:`):
1. It immediately pauses or terminates the blocked command.
2. It returns a descriptive message to the agent: `"Execution paused. The command requested interactive input. Please re-run with non-interactive flags."`

This completely eliminates frozen IDE states and saves your OpenAI/Anthropic API credits from being burned on silent hangs.

---

## Real-World Use Cases

### Case 1: Running a Backend Server & Reading Logs Concurrently
Imagine you ask your AI agent to launch a remote Python API and debug it.
1. The agent spawns the API server asynchronously using `run` with `session_id: "backend"`.
2. The server keeps running in the background. The terminal output is continuously buffered.
3. The agent opens a second session `session_id: "diagnostics"` and runs tests or checks port status using `netstat`.
4. If a test fails, the agent switches back to the `backend` session and reads the latest buffered log chunks using `read`.

### Case 2: Managing Embedded & IoT Devices (Keenetic, OpenWrt)
Connecting to embedded platforms is usually a nightmare for LLMs because their default shells use interactive pagers or custom menus.
- This server includes specialized prompt detection for **Keenetic CLI** (`(config)>`).
- When the agent requests system commands, the server handles entering the Linux sub-shell (`sh`/`bash` via Entware) automatically.
- Any pager prompts like `--More--` are auto-dismissed, preventing the connection from stalling.

### Case 3: Surgical In-Place File Patches
Instead of replacing entire 1000-line source files (which wastes tokens and risks introducing unrelated errors), the agent uses the `file` tool's `edit` action:
- It provides a safe search-and-replace mechanism.
- If the target block is not found or has minor typos, the server returns line-numbered context snippets and suggests close matches.
- This results in precise, high-speed edits without terminal escaping headaches.

---

## Available MCP Tools

Our toolset is optimized to minimize overhead and provide the LLM with surgical, precise operations.

| Tool | Action | Description |
| :--- | :--- | :--- |
| `run` | Execute commands | Runs commands synchronously, asynchronously, or as streams. Protects against hangs and auto-recovers broken channels. |
| `read` | Read output | Reads buffered background terminal output using offset-based pagination and line/byte limits. |
| `signal` | Control processes | Sends `Ctrl+C` (SIGINT) or writes raw strings to `stdin` of a running command. |
| `file` | Manage files | Sandbox-compliant file tool supporting directory listings, read-window inspections, uploads, and in-place search-and-replace edits. |
| `run_pipeline` | Binary-safe sync | Transports binary files and large logs through a high-speed chunk stream, avoiding terminal encoding corruption. |
| `last_command_details` | Debug telemetry | Returns verbose execution telemetry, system resource usage, and raw socket buffers when deep troubleshooting is needed. |
| `session_list` | Session audit | Lists all active persistent sessions and their statuses (`idle`, `busy`, `broken`). |
| `session_update` | Focus switch | Renames sessions or changes which session is treated as the default active terminal. |
| `session_close` | Terminate channel | Cleanly terminates remote background processes and tears down the SSH channel. |

---

## Quick Start

You can run this server using **Docker** (recommended, zero python setup) or directly as a **Python** script.

### Step 1: Install & Build

#### Option A: Docker (Recommended)
Build the image locally:
```bash
docker build -t mcp-ssh-server .
```

#### Option B: Python (Manual)
1. Clone the repository:
   ```bash
   git clone https://github.com/d00mus/SSH-MCP.git
   cd SSH-MCP
   ```
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## IDE & Client Configuration

Add the server to your favorite MCP client. Secrets can be passed safely via **Environment Variables** to keep them out of process listings.

### Cursor IDE

Edit your `.cursor/mcp.json` or add the server in Cursor Settings -> MCP:

#### Docker Setup (Best for Windows/macOS)
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "D:/path/to/project:/workspace",
        "-v", "C:/Users/me/.ssh:/home/mcp/.ssh:ro",
        "-w", "/workspace",
        "mcp-ssh-server",
        "--host", "my-server.example.com",
        "--user", "myuser",
        "--key", "/home/mcp/.ssh/id_rsa",
        "--verify-host"
      ]
    }
  }
}
```

#### Python Setup (With Secure Environment Variables)
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": [
        "/absolute/path/to/mcp-server.py",
        "--host", "192.168.1.1",
        "--user", "admin"
      ],
      "env": {
        "SSH_PASSWORD": "YOUR_PASSWORD"
      }
    }
  }
}
```

### Claude Desktop

Add this to your Claude Desktop configuration file (typically `%APPDATA%\Claude\claude_desktop_config.json` on Windows or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "mcp-ssh-server",
        "--host", "my-server.example.com",
        "--user", "myuser",
        "--password", "YOUR_PASSWORD"
      ]
    }
  }
}
```

### Continue.dev

Add this to your `config.yaml`:

```yaml
mcpServers:
  - name: ssh-mcp
    type: stdio
    command: docker
    args:
      - run
      - -i
      - --rm
      - mcp-ssh-server
      - "--host"
      - "192.168.1.1"
      - "--user"
      - "admin"
      - "--password"
      - "YOUR_PASSWORD"
```

---

## Configuration Reference

Most variables can be set via CLI arguments or Environment Variables. We strongly recommend using **Environment Variables** for passwords and sensitive keys.

| CLI Argument | Environment Variable | Default | Description |
| :--- | :--- | :--- | :--- |
| `--host` | `SSH_HOST` | *Required* | Remote SSH host address. |
| `--user` | `SSH_USER` | *Required* | SSH username. |
| `--password` | `SSH_PASSWORD` | None | SSH password. |
| `--key` | `SSH_KEY_PATH` | None | Path to local private SSH key. |
| `--passphrase` | `SSH_KEY_PASSPHRASE`| None | Passphrase for the SSH private key. |
| `--port` | `SSH_PORT` | `22` | SSH port. |
| `--verify-host` | `SSH_VERIFY_HOST_KEY` | `True` | Enforce strict host key verification. Use `--no-verify-host` to bypass. |
| `--path` | `EXTRA_PATH` | None | Appends extra directories to terminal `$PATH` (e.g., `/opt/bin:/opt/sbin` for Entware). |
| `--project-root`| `PROJECT_ROOT` | `cwd` | Local project root for directory sandboxing and local cache placement. |
| `--cache-dir` | `SSH_MCP_CACHE_DIR` | `.ssh-cache` | Override location for persistent session/run logs. |
| `--read-only` | `SSH_READ_ONLY` | `False` | Enforce Read-Only sandbox on the remote machine (blocks writes, deletions, and updates). |
| `--command-blacklist` | `SSH_COMMAND_BLACKLIST` | None | Comma-separated command patterns to block (e.g. `reboot,poweroff,dd,rm`). |

---

## Safety, Sandboxing, & Security

This gateway is designed with defense-in-depth principles to prevent AI models from damaging your servers:

1. **Local Sandboxing:** The `file` tool strictly validates paths. Accessing directories outside your specified `--project-root` (e.g. via directory traversal `../../`) is strictly blocked.
2. **Remote Sandboxing (`--read-only`):** Disables file-writing actions (`write`, `edit`, `upload`) and terminal command structures that write to disk or modify system states (blocks redirectors like `>`, `>>`, standard package managers, directory creation, etc.).
3. **Command Blacklist:** Protects against catastrophic failures. You can define prohibited patterns (e.g., `reboot`, `dd`, `format`). The server parses incoming commands and blocks execution immediately if a blacklisted keyword is detected.

---

## Community & Stars

This project is built out of frustration with existing fragile SSH MCP implementations. It is designed to be a high-performance workhorse for daily AI development.

If this server saved your IDE session from freezing, cut down your API token spending, or made your remote coding flows easier, **please consider dropping a Star ⭐ on the repository!** It helps other developers find this project and keeps the momentum going.

---
## License
MIT
