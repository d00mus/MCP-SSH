<!-- mcp-name: io.github.d00mus/mcp-ssh-gateway -->

# MCP SSH Gateway

**Use your MCP client to work with several SSH hosts through one local connection.** Run diagnostics on a VPS, inspect a NAS or query a Keenetic router by name. Sessions preserve terminal state between calls; long output can be read a page at a time.

For people who already use SSH and want an assistant to help with routine diagnostics and administration. It is not an SSH daemon, a hosted proxy or a replacement for access controls on your servers.

[![CI](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml/badge.svg)](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml) [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/) [![PyPI](https://img.shields.io/pypi/v/mcp-ssh-gateway.svg)](https://pypi.org/project/mcp-ssh-gateway/) [![MCP Registry](https://img.shields.io/badge/MCP%20Registry-published-purple)](https://registry.modelcontextprotocol.io/) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Try it with one host

You need Python 3.11+, an SSH account on a host you control and an MCP client that can launch a local stdio server.

1. Create a working directory for the gateway configuration and install the published package into an isolated environment. The virtual environment keeps this install separate from other Python tools:

   ```bash
   mkdir ssh-gateway && cd ssh-gateway
   python -m venv .venv
   # Windows PowerShell: .venv\Scripts\Activate.ps1
   # macOS/Linux:       source .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install mcp-ssh-gateway
   mcp-ssh-gateway --help
   ```

   This installs the current release from PyPI and checks that the command is available. Create servers.json in this directory before starting the gateway; without configuration, startup exits with an error. For a disposable launch without a persistent install, use `uvx --from mcp-ssh-gateway mcp-ssh-gateway --help`; to use a config file, replace `--help` with `--servers-config /absolute/path/to/servers.json`.

   To work on the project source instead, clone it and install development dependencies: `git clone https://github.com/d00mus/MCP-SSH.git && cd MCP-SSH && python -m pip install -r requirements.txt`

2. Create a `servers.json` in this working directory (replace the address, user and key path with your own):

   ```json
   {
     "servers": {
       "lab": {
         "host": "192.168.1.10",
         "user": "your-ssh-user",
         "key_path": "~/.ssh/id_ed25519"
       }
     }
   }
   ```

   Host-key verification is enabled by default and uses the machine’s system host-key store. Ensure the host key is already trusted there, and verify its fingerprint independently before adding it. For password authentication, use `"password": "${LAB_SSH_PASSWORD}"` and provide `LAB_SSH_PASSWORD` to the MCP server process. Do not commit real credentials or your `servers.json`. See the [security policy](SECURITY.md).

3. Add this to a client that uses the `mcpServers` config format. **Replace the absolute path**: clients do not necessarily start in your working directory.

   ```json
   {
     "mcpServers": {
       "ssh-gateway": {
         "command": "mcp-ssh-gateway",
         "args": ["--servers-config", "/absolute/path/to/servers.json"]
       }
     }
   }
   ```

   On Windows, point `command` at `mcp-ssh-gateway.exe` in your Python `Scripts` directory if the client does not resolve it from `PATH`, and use escaped backslashes in JSON paths (for example `C:\\Users\\you\\servers.json`).

   Running the command directly is not an interactive SSH terminal: it communicates with the client over stdio. Restart the MCP client after updating its config.

4. In the client, ask: **“List my SSH hosts, then run `uname -a` on lab.”** If the host is missing, check the config path and the client's MCP server logs. If SSH fails, check credentials and host-key verification.

Add more hosts under `servers` in the same file. [servers.json.example](servers.json.example) shows a multi-host configuration; check its host-key and credential choices before copying it. For a clean-directory installation check that does not depend on the repository clone, follow the [PyPI smoke-test steps](PYPI_SMOKE_TEST.md).

## What using it looks like

A Linux host and a router can share one MCP connection. Your client makes calls like these (they are not terminal commands):

```text
server_list()                                          # find configured hosts
run(server="lab", command="df -h")                  # inspect disk space
run(server="keenetic", command="show interface", shell=false)  # router CLI
```

`run` returns a `session_id`; pass it to later calls if you need the same terminal state. Without it an idle session may be reused with unknown state; `new_session: true` forces a clean session. A command still running after the initial wait (5 seconds by default) reports `still_running: true`. Use `read(session_id="...")` for later output, or whenever `has_more` indicates unread lines. `signal(action="ctrl_c")` interrupts a stuck command. Non-zero exits report `completed_nonzero` and `exit_status`, not silent success.

The `file` tool can inspect and edit remote files through SFTP (with shell fallback). Review edits and give an assistant only the SSH permissions it needs.

## When to use it

- **Multiple hosts:** one MCP server configuration routes calls to named targets. For just one host, this matters less.
- **Multi-step troubleshooting:** persistent sessions keep shell state, while line-based output windows avoid dumping an entire log into the conversation at once.
- **A Keenetic alongside Linux hosts:** `shell: false` sends device CLI commands without a POSIX shell; common pagers such as `--More--` are handled. Keenetic NDM is a supported use case, but other vendor CLIs are not guaranteed. Keep NDM CLI and Linux shell operations in separate sessions.

**Security boundary:** `read_only` and command blacklists are best-effort guardrails against mistakes, not a sandbox. Shell expansion and interpreters can bypass checks on command text. Use restricted SSH users and server-side permissions for sensitive hosts. Host-key verification is on by default; avoid turning it off casually.

The SSH connection originates from the machine running the gateway. This project works with MCP clients that can start a stdio server; it does not add SSH access to a chat app without MCP integration.

## Other ways to run it

**Docker (build from this clone):**

```bash
docker build -t mcp-ssh-server .
docker run -i --rm \
  -v /absolute/path/to/servers.json:/app/servers.json:ro \
  -v /absolute/path/to/your/.ssh:/root/.ssh:ro \
  mcp-ssh-server --servers-config /app/servers.json
```

Use absolute mount paths and pass required environment variables with `-e NAME`. This example exposes SSH keys to the container; mount only what it needs. For an MCP client using Docker, set `command` to `docker` and put the same run arguments in `args`.

**PyPI / MCP Registry:** The package is published as [`mcp-ssh-gateway`](https://pypi.org/project/mcp-ssh-gateway/) and listed in the [MCP Registry](https://registry.modelcontextprotocol.io/) as `io.github.d00mus/mcp-ssh-gateway`, so `pip install mcp-ssh-gateway` and `uvx --from mcp-ssh-gateway ...` work. See the [release process](docs/PUBLISHING.md).

## Configuration and tools

- Each target has an alias, `host`, `user`, optional `port` (default 22) and a `key_path` or `password`. `verify_host` defaults to `true`. `password` and `key_passphrase` support environment references (`${NAME}`); missing references fail at startup.
- The default full profile exposes `server_list`, `server_add`, `run`, `read`, `signal`, `file`, `session_list`, `session_update`, `session_close` and `last_command_details`. `server_add` accepts an `alias` and only appends new targets. `--tool-profile lean` exposes six everyday tools for a smaller catalog.
- Changes to `servers.json` are checked periodically (every 30 seconds); `server_list(reload=true)` checks immediately. Unchanged hosts keep their sessions; removing a host or changing its address, login or host-key settings closes that host’s active sessions.
- `--log-output meta` (the default) records lifecycle information and command text. `full` also records raw output; `off` disables logging. Consider what secrets might appear in commands and output.

For contributions or vulnerabilities, see [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Development

```bash
python -m unittest discover -s tests -t .
```

See the [changelog](CHANGELOG.md). MIT-licensed; see [LICENSE](LICENSE).
