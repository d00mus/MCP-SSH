# Quick Start

## 1. Choose your path

### Path A: Docker (Recommended)
You only need to build the image once.
```bash
docker build -t mcp-ssh-server .
```

### Path B: Python
Install dependencies:
```bash
pip install -r requirements.txt
```

## 2. Configure your Agent

### Cursor IDE
Edit `.cursor/mcp.json`:

**Docker:**
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

**Python:**
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": [
        "D:/path/to/mcp-server.py",
        "--host", "192.168.1.1",
        "--user", "admin",
        "--password", "YOUR_PASSWORD"
      ]
    }
  }
}
```

### Continue.dev
Edit `config.yaml`:

**Docker:**
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

## 3. Start chatting!

Try asking your AI:
- "Check CPU load on my router"
- "Are there any errors in `/var/log/messages`?" (remind it to use `shell: true` for grep)
- "List all active sessions"

## 💡 Important Tips

1. **Shell Mode**: For any command with `|`, `&&`, `||`, or `if/else`, the agent must set `shell: true`.
2. **Keenetic**: If you are using a Keenetic router, the server will automatically handle the transition from restricted CLI to Linux shell when `shell: true` is requested.
3. **Passwords**: Ensure your password doesn't contain characters that might need shell escaping in your local environment.
4. **Lean responses by default**: tools now return compact payloads. Use `last_command_details` only for debugging ambiguous command outcomes.
5. **Cache location**: default is `<project-root>/.ssh-cache` (project root = process cwd). Override via `--cache-dir` or `SSH_MCP_CACHE_DIR`.
6. **File tool workflow**:
   - `file.read` with `local_path` downloads file (metadata only in response).
   - `file.read` without `local_path` is inspect mode (line window + filters).
   - `file.write/upload` uses `local_path` for full files, or inline `content` for small files.
   - `file.edit` performs in-place text replacements for existing remote text files.
