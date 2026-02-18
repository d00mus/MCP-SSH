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

**Python (Secure):**
```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "python",
      "args": [
        "D:/path/to/mcp-server.py",
        "--host", "192.168.1.1",
        "--user", "admin"
      ],
      "env": {
        "SSH_KEY_PATH": "C:/Users/me/.ssh/id_rsa",
        "SSH_VERIFY_HOST_KEY": "true"
      }
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

1. **Optimized for Efficiency**: This server is specifically tuned for low token usage and works great with local LLMs. Responses are lean; use `last_command_details` only if something goes wrong.
2. **Shell Mode**: For any command with `|`, `&&`, `||`, or `if/else`, the agent must set `shell: true`.
3. **Keenetic**: If you are using a Keenetic router, the server will automatically handle the transition from restricted CLI to Linux shell when `shell: true` is requested.
4. **Auto-Recovery**: You don't need to manage sessions manually. The `run` tool will auto-create or recover sessions if needed, minimizing tool-call overhead.
5. **Cache location**: default is `<project-root>/.ssh-cache` (project root = process cwd). Override via `--cache-dir` or `SSH_MCP_CACHE_DIR`.
6. **File tool workflow**:
   - `file.read` with `local_path` downloads file.
   - `file.read` without `local_path` is for inspection.
   - `file.edit` performs in-place text replacements—ideal for quick fixes without re-uploading.
