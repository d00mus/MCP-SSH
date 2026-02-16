# SSH MCP Server

A powerful and robust Model Context Protocol (MCP) server for managing remote devices and servers via SSH. 

Designed for AI agents (like Cursor, Claude, etc.), this server provides a compact yet flexible set of tools to execute commands, manage persistent sessions, and transfer files reliably. It is particularly well-suited for devices with restricted shells, like **Keenetic** routers.

## 🚀 Key Features

- **Optimized for Weak & Local Models**: Designed to work reliably with smaller or local LLMs by providing clear, unambiguous tool structures and compact responses.
- **Token-Saving Architecture**: "Ultra-Lean" payloads by default minimize token consumption, extending the effective context window of your AI agent.
- **Agent-Friendly Toolset**: Minimized tool-call overhead—session auto-recovery, automatic shell detection (e.g., for Keenetic), and anti-hang timeouts are all handled internally.
- **Persistent Multi-session Management**: Keep multiple SSH sessions open and switch between them (like `tmux` for your AI).
- **Anti-Hang Architecture**: Integrated `wait_timeout` prevents the AI agent from freezing on long-running commands.
- **Unified Execution Model**: A single `run` tool handles synchronous, asynchronous, and streaming execution.
- **On-Demand Verbose Debugging**: Use `last_command_details` only when execution context needs deep inspection.
- **Docker Ready**: Run without Python installation using a simple Docker container.
- **Binary-Safe Pipelines**: Reliable file transfers bypassing terminal encoding issues.
- **Background Buffering**: Continuous output caching even when the agent isn't polling.
- **Keenetic/Netcraze Aware**: Specialized logic for entering Linux shell from restricted CLI and prompt detection.

## 🛠 Tools

| Tool | Description |
|------|-------------|
| `run` | Execute commands (sync/async/stream) with timeout and auto-recovery. |
| `read` | Read buffered output with pagination and server-side filtering. |
| `signal` | Send `Ctrl+C` or `stdin` to a running process. |
| `file` | File list/inspect/transfer/edit tool: `read` with `local_path` downloads file, without it returns inspect snippet (line window + filters); `write/upload` uses local file or small inline `content`; `edit` applies in-place text replacements. |
| `run_pipeline` | Binary-safe data transfer between local and remote. |
| `last_command_details` | Full verbose result of the last tool call (debug only). |
| `session_list` | List active sessions and their status (`idle`, `busy`, `broken`). |
| `session_update`| Rename session or set as current. |
| `session_close` | Terminate and remove a session. |

## 📦 Installation

### Option 1: Docker (Recommended)
No Python needed. Just build the image once:
```bash
docker build -t mcp-ssh-server .
```

### Option 2: Python (Manual)
1. Clone the repo and install dependencies:
   ```bash
   git clone https://github.com/d00mus/SSH-MCP.git
   cd SSH-MCP
   pip install -r requirements.txt
   ```

## ⚙️ Configuration

### Cursor IDE

Add this to your `.cursor/mcp.json`:

#### Using Docker (Best for Windows/Mac)
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "D:/path/to/project:/workspace",
        "-w", "/workspace",
        "mcp-ssh-server",
        "--host", "192.168.1.1",
        "--user", "admin",
        "--password", "YOUR_PASSWORD"
      ]
    }
  }
}
```

#### Using Python
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": [
        "/absolute/path/to/mcp-server.py",
        "--host", "192.168.1.1",
        "--user", "admin",
        "--password", "YOUR_PASSWORD"
      ]
    }
  }
}
```

### Continue.dev

Add to your `config.yaml`:

#### Using Docker
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

#### Using Python
```yaml
mcpServers:
  - name: ssh-mcp
    type: stdio
    command: python
    args:
      - "/absolute/path/to/mcp-server.py"
      - "--host"
      - "192.168.1.1"
      - "--user"
      - "admin"
      - "--password"
      - "YOUR_PASSWORD"
```

## ⌨️ CLI Arguments

- `--host` (required): SSH host address.
- `--user` (required): SSH username.
- `--password` (required): SSH password.
- `--port` (optional): SSH port (default: 22).
- `--path` (optional): Additional `PATH` (e.g., `/opt/bin:/opt/sbin` for Entware).
- `--project-root` (optional): Local project root for cache/log placement (default: process `cwd`).
- `--cache-dir` (optional): Override cache base path. Server writes to `<cache-dir>/<project-tag-hash>/...`.

Environment variable:
- `SSH_MCP_CACHE_DIR` (optional): Same behavior as `--cache-dir` when CLI arg is omitted.

## 📦 Response Model

Tools now return compact JSON by default. Typical happy-path fields are:
- `run` / `read`: `output`, `session_id`, `run_id`, `status` (plus `next_offset` for `read`)
- `run_pipeline` / `pipeline_status`: `output` (preview), `session_id`, `pipeline_id`, `status`, `next_offset`, `bytes_written`, `bytes_sent`
- `file`: `output` (content or listing), `session_id`, `status`, plus action-specific fields like `size` or `message`.

If you need full metadata (timeouts, memory counters, session selection details, etc.), call `last_command_details` once for debugging and continue with normal compact flow.

## 🧠 Local Cache Layout

- Default (no override): `<project-root>/.ssh-cache/`
- Override mode: `<cache-dir>/<project-tag-hash>/`
- Session logs: `sessions/`
- Run/Pipeline logs: `runs/`

This keeps data isolated per project and avoids cross-project log mixing.

## ⚠️ Security Note

Passwords are passed as command-line arguments. In Docker mode, they are isolated within the container call, but still visible in your `mcp.json` or `config.yaml`. **Never commit your configuration files with secrets to public repositories!**

## 💡 Pro Tips

- **Local Models**: If you use local models (like Qwen 3 or Devstral 2), this server's compact responses significantly improve their reliability by reducing context noise.
- **Complex commands**: If you need pipes (`|`) or logic (`&&`, `||`), always tell the agent to use `shell: true`.
- **Filtering**: Use `cat file | grep pattern` instead of the `read` tool filters for better performance.
- **Large files**: Use `run_pipeline` for transferring files; it's much faster and safer than `cat`.
- **Minimize Calls**: Don't worry about sessions; the `run` tool will auto-create or recover them if you don't provide a `session_id`.

## 📄 License
MIT
