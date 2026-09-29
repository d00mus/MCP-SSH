<!-- mcp-name: io.github.d00mus/mcp-ssh-gateway -->

# MCP SSH Gateway

**SSH terminals for AI agents that know when a command is done.**

Six tools, real shells that keep their state, the exit code the moment a command ends, and answers a small model can act on. One direct dependency (`paramiko`), no daemon, nothing in the cloud.

[![CI](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml/badge.svg)](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml) [![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/) [![PyPI](https://img.shields.io/pypi/v/mcp-ssh-gateway.svg)](https://pypi.org/project/mcp-ssh-gateway/) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/d00mus/MCP-SSH/blob/master/LICENSE)

English · [Русский](https://github.com/d00mus/MCP-SSH/blob/master/README.ru.md)

## Why this one

- **It knows when a command is done.** The shell itself reports the end and the exit code, so `echo hi` returns in milliseconds, a failing command says `exit_code: 2`, and a three-minute build answers `running` after 10 seconds and is collected with `read`. No sleeps, no guessing from silence.
- **Terminals with state.** A session is one real shell: `cd`, variables and virtualenvs stay between calls. `run` without a `session_id` opens a new shell, so nothing is shared by accident.
- **Made for small models.** Six tools, about 1.6k tokens of descriptions in total. Every stop says what to do next (`hint`), pagers are off, a progress bar is one line, a wrong argument gets an answer that names the right call, and long output comes in pages (`has_more`, `tail`, `offset`).
- **Questions do not hang.** `Continue? [y/N]`, a password prompt or an unclosed quote returns `waiting_input`. The agent answers with `signal` or presses Ctrl+C, and the shell keeps its state.
- **Routers too.** A Keenetic router CLI (`show interface`, `--More--` handled) or its Linux shell, through the same tools.
- **Tested against real `sshd`.** Containers with bash, BusyBox ash, zsh, dash, fish and tcsh logins and a host without SFTP run in CI on every push.

## Quick start

You need [uv](https://docs.astral.sh/uv/getting-started/installation/) (or Python 3.11+ and `pip`) and SSH access to a host you control.

**Already have `~/.ssh/config`?** Add this to your MCP client, and every host in that file becomes a server (key or agent login):

```json
{
  "mcpServers": {
    "ssh": {
      "command": "uvx",
      "args": ["mcp-ssh-gateway", "--import-ssh-config"]
    }
  }
}
```

This is the format of Cursor (`~/.cursor/mcp.json`) and Claude Desktop (`claude_desktop_config.json`); [other clients](#other-clients) are below. Restart the client and ask: *"List my SSH servers and show the disk usage on web."*

**Want a password login, a router or a read-only host?** Write a `servers.json`:

```json
{
  "servers": {
    "web": {"host": "192.168.1.10", "user": "deploy", "key_path": "~/.ssh/id_ed25519"},
    "router": {"host": "192.168.1.1", "user": "admin", "password": "${ROUTER_PASSWORD}"}
  }
}
```

and point the gateway at it with `"args": ["mcp-ssh-gateway", "--servers-config", "/absolute/path/to/servers.json"]`. Use an absolute path (clients do not start in your folder; on Windows escape backslashes in JSON) and give the gateway the variables it refers to in the client's `"env"` block. [`servers.json.example`](https://github.com/d00mus/MCP-SSH/blob/master/servers.json.example) also shows a read-only production host. Without uv: `pip install mcp-ssh-gateway` and `"command": "mcp-ssh-gateway"`.

### Other clients

**Claude Code**

```bash
claude mcp add ssh --scope user -- uvx mcp-ssh-gateway --import-ssh-config
```

**VS Code** (`.vscode/mcp.json`: the top key is `servers`)

```json
{
  "servers": {
    "ssh": {"type": "stdio", "command": "uvx", "args": ["mcp-ssh-gateway", "--import-ssh-config"]}
  }
}
```

**Codex** (`~/.codex/config.toml`, or `codex mcp add ssh -- uvx mcp-ssh-gateway --import-ssh-config`)

```toml
[mcp_servers.ssh]
command = "uvx"
args = ["mcp-ssh-gateway", "--import-ssh-config"]
startup_timeout_sec = 30   # the first uvx run downloads the package
```

## What the agent sees

Answers as a client receives them, captured from the test suite's Debian container (the host address and the disk figures are replaced with example values):

```text
server_list()
→ {"servers":[{"server":"web","host":"192.168.1.10:22","user":"deploy"}]}

run(server="web", command="df -h /")                  # no session_id: a new shell is opened
→ {"session_id":"web/1","status":"completed","exit_code":0,
   "output":"$ df -h /\nFilesystem      Size  Used Avail Use% Mounted on\n/dev/vda1        40G   31G  7.2G  82% /\n"}

run(session_id="web/1", command="ls /nonexistent")    # the same shell; a non-zero code is a result
→ {"session_id":"web/1","status":"completed","exit_code":2,
   "output":"$ ls /nonexistent\nls: cannot access '/nonexistent': No such file or directory\n"}

run(session_id="web/1", command="read -p 'Continue? [y/N] ' a; echo got:$a")
→ {"session_id":"web/1","status":"waiting_input",
   "output":"$ read -p 'Continue? [y/N] ' a; echo got:$a\nContinue? [y/N] ",
   "hint":"The program waits for input. Answer with signal action=stdin text=..., or stop it with signal ctrl_c."}

signal(session_id="web/1", action="stdin", text="y")
→ {"session_id":"web/1","status":"completed","output":"got:y\n","exit_code":0}

run(session_id="web/1", command="seq 1 500", lines=5)  # long output comes in pages
→ {"session_id":"web/1","status":"completed","output":"$ seq 1 500\n1\n2\n3\n4\n","exit_code":0,"has_more":496}

read(session_id="web/1", tail=3)                       # just the end
→ {"session_id":"web/1","status":"completed","output":"498\n499\n500\n","exit_code":0,"skipped_lines":493}

read(session_id="web/1", offset=-20, lines=3)          # scroll back; the unread position stays put
→ {"session_id":"web/1","status":"completed","output":"481\n482\n483\n","exit_code":0}

run(session_id="web/1", command="sleep 30", wait=1)
→ {"session_id":"web/1","status":"running","output":"$ sleep 30\n",
   "hint":"Still running. Call read(session_id='web/1') again, or stop it with signal ctrl_c."}

signal(session_id="web/1", action="ctrl_c")
→ {"session_id":"web/1","status":"interrupted","output":"\n","process_stopped":true}
```

A mistake gets an answer that names the right call. This is what a model that invents a `cwd` argument for `run` reads back:

```json
{"error": "run has no argument 'cwd'. It takes: command, server, session_id, shell, wait, timeout, lines. To work in a folder, start the command with 'cd /path && '."}
```

| Field | Meaning |
| --- | --- |
| `status` | `completed`, `running`, `waiting_input`, `interrupted`, `timed_out`, `failed` or `idle`. |
| `exit_code` | Only with `completed`. Non-zero is a result, not a tool error. |
| `has_more` | Unread lines left in the session; `read` returns them. |
| `hint` | What to do next, whenever the agent would otherwise have to guess. |
| `skipped_lines` | Older unread lines that a new command or `read(tail=…)` passed over. Nothing is lost: `read(offset=0)` scrolls back to them. |
| `dropped_data` | Unread output that is gone for good: the session buffer (the last 4 million characters are kept) overflowed. |

## Tools

| Tool | What it does |
| --- | --- |
| `server_list` | The servers and their open sessions. |
| `run` | Runs a command. Returns when it ends, or after `wait` seconds (default 10) with `running`. Without `session_id` it opens a new shell. |
| `read` | The next unread lines of a session (waits up to `wait` for a running command); `tail` for the end, `offset` to scroll back. |
| `signal` | `stdin` answers a question, `ctrl_c` stops the command, `ctrl_d` ends its input. |
| `session_close` | Closes a shell. A server allows only a few (`max_sessions`, default 8). |
| `file` | `list`, `read`, `write` and `edit` remote files over SFTP, or through the shell when the host has no SFTP. Reads can filter (`contains`, `tail_lines`); an edit is an exact-text replacement that can be guarded with `expected_sha256`. |
| `server_add` | Only with `--allow-add-server`: adds a server to `servers.json`. |

Sessions are named `server/N`. A shell has state (folder, variables), so there is no default one: `run` without `session_id` always opens a new shell and returns its id, and that id continues the same shell. Close the shells you are done with.

## What it works with

| Host | Status |
| --- | --- |
| Linux with bash, dash, BusyBox ash or zsh as the login shell | Works. Tested against real `sshd` containers (Debian, Alpine, zsh and dash logins). |
| fish or tcsh login shell | Works with `"shell": "bash"` in `servers.json` (the gateway runs `exec bash` after login). Without it the gateway refuses at once and says so. |
| Keenetic router (NDM CLI, and the Linux shell behind it) | Works. Covered by a scripted fake in the tests and used every day on a real router. |
| Other router CLIs (Cisco IOS, Junos, …) | Not yet: [#1](https://github.com/d00mus/MCP-SSH/issues/1). A plain vendor CLI may work but is untested. |
| Hosts behind a bastion (`ProxyJump`) | Not yet: [#2](https://github.com/d00mus/MCP-SSH/issues/2). `--import-ssh-config` ignores `ProxyJump`. |
| Windows hosts whose SSH shell is cmd or PowerShell | Not supported: the gateway needs a POSIX shell. |

The gateway itself runs wherever Python 3.11+ runs (Linux, macOS, Windows).

## Security

The agent has the reach of the SSH account you give it. What follows narrows the damage from mistakes; it does not replace a restricted account.

- **Guardrails are mistake guards.** `read_only` and `command_blacklist` (literal words, case-insensitive) look at the command text. Shell tricks, `base64` or `python -c` get around them. For a real boundary use a restricted SSH account: a read-only shell, `ForceCommand`, separate credentials per trust level.
- **Local files are off.** `local_path` (upload, download) works only after you start the gateway with `--project-root <folder>`, and then only inside that folder.
- **Host keys:** a new host is trusted on first contact and its key is kept in `known_hosts` in the cache directory; a changed key is refused. `verify_host: false` turns the check off.
- **Secrets:** put `${NAME}` references in `servers.json` instead of the values. Logs mask password-like values (`--log-output off` writes no logs).
- **No listening port:** the gateway talks MCP over stdio only. `server_add` does not exist unless you start it with `--allow-add-server`, and it only appends.

The full policy and how to report a problem: [SECURITY.md](https://github.com/d00mus/MCP-SSH/blob/master/SECURITY.md).

## Configuration

`servers.json` fields: `host`, `user`, `port` (22), `key_path` (`~` and `${NAME}` work), `password` and `key_passphrase` (only `${NAME}` references are replaced, the rest is used as written), `verify_host` (true), `description`, `extra_path` (added to `PATH`), `read_only`, `command_blacklist`, `max_sessions` (8), `shell` (a POSIX shell to `exec` after login, for fish or tcsh accounts). The file is re-read while the gateway runs; unchanged servers keep their sessions.

Command line (none is required except a source of servers):

| Option | Meaning |
| --- | --- |
| `--servers-config` | Path to `servers.json`, or the JSON itself. Also `$SSH_SERVERS_CONFIG`; falls back to `./servers.json`. |
| `--import-ssh-config` | Also offer the hosts of `~/.ssh/config` (key or agent login). |
| `--read-only`, `--command-blacklist a,b` | Guardrails for every server (or `$SSH_READ_ONLY`, `$SSH_COMMAND_BLACKLIST`). |
| `--log-output meta\|full\|off` | What is written to the log files (default `meta`: commands and lifecycle). |
| `--cache-dir` | Logs and `known_hosts`. Default: the user cache directory (`$SSH_MCP_CACHE_DIR`). |
| `--project-root` | The local folder the `file` tool may read and write (`local_path`). Without it local files are off; the tool still works on the server. |
| `--allow-add-server`, `--allow-system-temp`, `--allow-gateway-dir` | Opt-in extras. |

Logs: one JSON-lines file per session and one per command under the cache directory; old files are pruned by age and size.

## How it works

The gateway opens an interactive shell with a PTY and switches it to a quiet, machine-readable mode with one setup line: no echo, and a prompt that prints a marker containing the exit code. When the marker appears the command is over and the agent has its exit code. This also covers syntax errors, background jobs and Ctrl+C. An unclosed quote or heredoc is recognised by a second marker.

Routers whose login is a vendor CLI (Keenetic NDM) have no such shell. There the gateway learns the prompt from the login banner, removes the echo of the typed command, presses space at `--More--` and treats a stable prompt as the end of the command. `run(shell=false)` uses the CLI, `run(shell=true)` enters the Linux shell behind it; a session keeps one mode.

Output goes into one line-based buffer per session with a single unread position. `run` and `read` advance it; `tail` jumps to the end; `offset` only looks. Lines longer than 1024 characters are split so that pages stay predictable.

## Limits

- A shell runs one command at a time. For two things at once open two shells (or let your client call `run` in parallel).
- A shell started inside a session (`sudo -s`, `su`, `bash`) hides where commands end, so the gateway tells the agent to leave it. Use `sudo <command>` for root.
- No jump hosts yet ([#2](https://github.com/d00mus/MCP-SSH/issues/2)), no other router CLIs yet ([#1](https://github.com/d00mus/MCP-SSH/issues/1)).
- The gateway has no approvals, policy engine or audit trail. If you need those, see below.

## Other SSH servers for MCP

They make different trade-offs (as of September 2026; read their READMEs before choosing):

- [tufantunc/ssh-mcp](https://github.com/tufantunc/ssh-mcp): security first. Command classification, role and host policy, human approval, audit log, `ProxyJump`, SSH CA and streaming SFTP; 14 tools. Choose it for production fleets that need approvals and an audit trail.
- [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server): 4 tools on Node (`npx`) with a command whitelist, SOCKS and HTTP proxies, a bastion mode and MFA. Choose it for the smallest Node setup that needs proxies or MFA.
- [bvisible/mcp-ssh-manager](https://github.com/bvisible/mcp-ssh-manager): 37 tools, a DevOps toolbox with backups, databases and monitoring. Choose it if you want those workflows ready-made.

This gateway chooses the other end: few tools, stateful shells, and an answer for every situation an agent gets stuck in.

## Docker

```bash
docker build -t mcp-ssh-gateway .
docker run -i --rm \
  -v /absolute/path/to/servers.json:/app/servers.json:ro \
  -v /absolute/path/to/.ssh:/root/.ssh:ro \
  -v /absolute/path/to/cache:/app/.ssh-cache \
  mcp-ssh-gateway --servers-config /app/servers.json --cache-dir /app/.ssh-cache
```

The cache volume keeps `known_hosts` and the logs between runs.

## Development

```bash
pip install -r requirements.txt ruff mypy
python -m unittest discover -s tests -t .     # unit tests; integration tests need Docker
ruff check . && mypy
```

Integration tests start real `sshd` containers and drive the gateway through the same JSON-RPC entry point a client uses. They skip themselves when Docker is missing (`MCP_SSH_IT=0` skips on purpose). See [CONTRIBUTING.md](https://github.com/d00mus/MCP-SSH/blob/master/CONTRIBUTING.md) and the [changelog](https://github.com/d00mus/MCP-SSH/blob/master/CHANGELOG.md). MIT-licensed.
