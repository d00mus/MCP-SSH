# SSH MCP Server

A powerful and robust Model Context Protocol (MCP) server for managing remote devices and servers via SSH.

Designed for AI agents (like Cursor, Claude, etc.), this server provides a compact yet flexible set of tools to execute commands, manage persistent sessions, and transfer files reliably.

## Key Features

- **Persistent Multi-session Management**: Similar to `tmux` or `screen`, keep multiple SSH sessions open and switch between them.
- **Anti-Hang Architecture**: Integrated `wait_timeout` for all operations prevents the AI agent from freezing on long-running commands.
- **Unified Execution Model**: A single `run` tool for synchronous, asynchronous, and streaming command execution.
- **Binary-Safe Pipelines**: Redirect remote command output to local files or feed local files into remote processes (binary-safe, bypassing terminal encoding issues).
- **Background Buffering**: The server continuously reads and caches output from all active sessions even when the agent is not polling.
- **Auto-Recovery**: Automatically creates new sessions or recovers dead ones during command execution.
- **Server-Side Filtering**: Filter large outputs (grep-like) on the server to save tokens and improve response speed.
- **Memory Guard**: Global limit on buffered output to prevent resource exhaustion.
- **Keenetic Aware**: Specialized logic for devices with restricted shells (like Keenetic routers), including automatic shell entry and prompt detection.

## Tools

| Tool | Description |
|------|-------------|
| `run` | Execute commands (sync/async/stream) with timeout and recovery logic. |
| `read` | Read buffered output from a command with pagination and filtering. |
| `signal` | Send `Ctrl+C` or arbitrary `stdin` to a running process. |
| `file` | Unified file operations (read, write, list, upload, download) with fallback mechanisms. |
| `run_pipeline` | Cross-machine binary-safe data transfer (remote stdout -> local file, local file -> remote stdin). |
| `pipeline_status` | Monitor active pipeline progress and status. |
| `session_list` | List all active sessions and their current status (`idle`, `busy`, `broken`). |
| `session_update` | Rename a session or set it as current. |
| `session_close` | Cleanly terminate and remove a session. |

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/d00mus/SSH-MCP.git
   cd SSH-MCP
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Cursor IDE

Add the following to your `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": [
        "/path/to/SSH-MCP/mcp-server.py",
        "--host", "192.168.1.1",
        "--user", "admin",
        "--password", "YOUR_PASSWORD"
      ]
    }
  }
}
```

### Continue.dev

Continue.dev uses a `config.yaml` based configuration. You can add the server to your global `config.yaml`:

```yaml
mcpServers:
  - name: ssh-mcp
    type: stdio
    command: python
    args:
      - "/path/to/SSH-MCP/mcp-server.py"
      - "--host"
      - "192.168.1.1"
      - "--user"
      - "admin"
      - "--password"
      - "YOUR_PASSWORD"
```

Alternatively, you can place a standard `mcp.json` file in your `.continue/mcpServers/` project directory, and Continue will automatically pick it up.

## CLI Arguments

- `--host` (required): SSH host address.
- `--user` (required): SSH username.
- `--password` (required): SSH password.
- `--port` (optional): SSH port (default: 22).
- `--path` (optional): Additional `PATH` to export in the shell (useful for Entware/custom environments).

## Security Note

⚠️ **WARNING**: Passwords are passed as command-line arguments and may be visible in process lists. Ensure your environment is secure. Configuration files like `mcp.json` should never be committed to public repositories if they contain secrets.

## Advanced Usage

### Sync Execution with Auto-Recovery
Simply calling `run(command="ls -la")` will use the current session, or automatically create one if none exists.

### Long-running Commands
1. Start with `run(command="tail -f /var/log/syslog", mode="stream")`.
2. Read output periodically with `read()`.
3. Stop with `signal(action="ctrl_c")`.

### Large File Transfer
Use `run_pipeline` for reliable binary transfers:
```text
run_pipeline(
  command="cat /remote/large_file.iso", 
  local_stdout_path="/local/path/file.iso", 
  mode="async"
)
```

## License

MIT
