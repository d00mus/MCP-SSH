# SSH MCP Server

A powerful and robust Model Context Protocol (MCP) server for managing remote devices and servers via SSH. 

Designed for AI agents (like Cursor, Claude, etc.), this server provides a compact yet flexible set of tools to execute commands, manage persistent sessions, and transfer files reliably. It is particularly well-suited for devices with restricted shells, like **Keenetic** routers.

## 🚀 Key Features

- **Persistent Multi-session Management**: Keep multiple SSH sessions open and switch between them (like `tmux` for your AI).
- **Anti-Hang Architecture**: Integrated `wait_timeout` prevents the AI agent from freezing on long-running commands.
- **Unified Execution Model**: A single `run` tool handles synchronous, asynchronous, and streaming execution.
- **Docker Ready**: Run without Python installation using a simple Docker container.
- **Binary-Safe Pipelines**: Reliable file transfers bypassing terminal encoding issues.
- **Background Buffering**: Continuous output caching even when the agent isn't polling.
- **Keenetic Aware**: Specialized logic for entering Linux shell from restricted CLI and prompt detection.

## 🛠 Tools

| Tool | Description |
|------|-------------|
| `run` | Execute commands (sync/async/stream) with timeout and auto-recovery. |
| `read` | Read buffered output with pagination and server-side filtering. |
| `signal` | Send `Ctrl+C` or `stdin` to a running process. |
| `file` | Unified file operations (read, write, list, upload, download) with shell fallback. |
| `run_pipeline` | Binary-safe data transfer between local and remote. |
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
        "run", "-i", "--rm", "mcp-ssh-server",
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

## ⚠️ Security Note

Passwords are passed as command-line arguments. In Docker mode, they are isolated within the container call, but still visible in your `mcp.json` or `config.yaml`. **Never commit your configuration files with secrets to public repositories!**

## 💡 Pro Tips

- **Complex commands**: If you need pipes (`|`) or logic (`&&`, `||`), always tell the agent to use `shell: true`.
- **Filtering**: Use `cat file | grep pattern` instead of the `read` tool filters for better performance.
- **Large files**: Use `run_pipeline` for transferring files; it's much faster and safer than `cat`.

## 📄 License
MIT
