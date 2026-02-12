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
        "run", "-i", "--rm", "mcp-ssh-server",
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
