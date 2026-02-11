# Quick Start

## 1. Install Dependencies

```bash
pip install -r requirements.txt
```

## 2. Configuration

### Cursor IDE

Add the server to your `.cursor/mcp.json` file:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": [
        "/path/to/mcp-server.py",
        "--host", "192.168.1.1",
        "--user", "admin",
        "--password", "YOUR_PASSWORD"
      ]
    }
  }
}
```

### Continue.dev (Modern YAML Format)

Continue.dev now uses a `config.yaml` based configuration. You have two options:

#### Option A: Project-specific (Recommended)
1. Create a folder `.continue/mcpServers` at the root of your project.
2. Create a file `ssh-mcp.yaml` inside that folder:

```yaml
name: SSH MCP Server
version: 1.0.0
schema: v1
mcpServers:
  - name: ssh-mcp
    command: python
    args:
      - "/path/to/mcp-server.py"
      - "--host"
      - "192.168.1.1"
      - "--user"
      - "admin"
      - "--password"
      - "YOUR_PASSWORD"
```

#### Option B: Global config
Add the server block to your global `config.yaml`:

```yaml
mcpServers:
  - name: ssh-mcp
    type: stdio
    command: python
    args:
      - "/path/to/mcp-server.py"
      - "--host"
      - "192.168.1.1"
      - "--user"
      - "admin"
      - "--password"
      - "YOUR_PASSWORD"
```

*Note: Continue also supports reading a standard `mcp.json` file if you place it in the `.continue/mcpServers/` directory.*

## 3. Usage

Once configured, you can ask your AI agent:
- "Run `show version` on the router"
- "List files in `/opt` using shell"
- "Tail the log file `/var/log/messages` and show me errors"

## Key Concepts

### Session Management
The server manages persistent SSH sessions. By default, `run` and `run_pipeline` use the **current** session.
- Use `new_session: true` in `run` to start a new independent session.
- If a session dies, the server automatically attempts to recover it.

### Timeouts
- `wait_timeout`: How long the AI agent waits for a response from the MCP tool. If it's a long command, you'll get partial output and can read the rest later with `read`.
- `hard_timeout`: A hard limit on how long the remote command is allowed to run.

### Pipeline (Binary Transfer)
Use `run_pipeline` for transferring files. It is binary-safe and avoids common terminal encoding issues.
- `local_stdout_path`: Remote output is written to this local file.
- `local_stdin_path`: Content of this local file is sent to remote command's stdin.
