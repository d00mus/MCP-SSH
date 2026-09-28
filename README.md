<!-- mcp-name: io.github.d00mus/mcp-ssh-gateway -->

# MCP SSH Gateway — one MCP server for a whole fleet of SSH hosts

[![CI](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml/badge.svg)](https://github.com/d00mus/MCP-SSH/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/mcp-ssh-gateway.svg)](https://pypi.org/project/mcp-ssh-gateway/)
<!-- Uncomment the line below AFTER `mcp-publisher publish` succeeds in docs/PUBLISHING.md.
[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-published-purple)](https://registry.modelcontextprotocol.io/)
-->

**A single Model Context Protocol server that drives every SSH host you own — routers, NAS, VPS, staging boxes — with persistent sessions, honest exit statuses, and output that fits in a model context.**

Other SSH MCP servers are single-host wrappers: one host, one more MCP entry, one more block of duplicated tool definitions in every prompt. This gateway takes the whole fleet through one instance: route by server alias, keep shell state between calls, page through long output explicitly, and never lose a router CLI to a `--More--` pager.

---

## What it fixes

| Problem | Typical single-host setup | This gateway |
| :--- | :--- | :--- |
| **Context bloat** | A separate MCP server per host. 5 hosts means 50+ tool definitions in every prompt — extra tokens, a confused model. | **One gateway for the fleet.** A single MCP instance, compact tools for all hosts. Route with `server: "alias"` or composite session IDs (`keenetic/1`, `vps/2`). |
| **Config restarts** | Adding or editing a server means restarting the MCP server, dropping open sessions and background jobs. | **Hot-reload without drops.** `servers.json` changes are picked up on the health-loop pass (every 30s) via mtime + content hash: new servers added, policies updated, running sessions untouched. |
| **Interactive prompts** | A command asking for `[y/n]`, `[Enter]` or a password hangs until timeout, burning API budget. | **Prompt detection.** Common prompts (`Password:`, `[Y/n]`) are detected and the call returns early with a hint to use non-interactive flags, or you answer via `signal`. |
| **Silent failures** | Non-zero exits come back as plain text; the model assumes success and carries on. | **Explicit exit status.** Non-zero exits return `completed_nonzero` plus `exit_status` — a result, not a tool error. |
| **Long-running commands** | A dev server or `tail -f` blocks the connection and the agent stalls with it. | **Multiple sessions and a control pool.** The 5s timeout returns `still_running: true` instead of failing; `Ctrl+C` is served from a separate control pool and never queues behind a long run; `wait_timeout: 0` starts async immediately; `new_session: true` runs things in parallel. |
| **Routers and appliance CLIs** | Network appliances (e.g. the **Keenetic** NDM CLI) force pagination (`--More--`) and have no POSIX shell, so plain wrappers break or hang. | **Pager-aware, shell-aware.** `--More--` is auto-paginated, and vendor CLI (`shell: false`) is kept strictly separate from Linux shell (`shell: true`). See below. |
| **File editing overhead** | Download the file, edit locally, upload back — slow and fragile for large files. | **In-place remote editing.** `file` with `action: "edit"` does search-and-replace on the remote side, with line-numbered diagnostics and similarity hints on mismatch. |
| **Unsafe commands** | A hallucinated `rm -rf /` or `reboot` goes straight to production. | **Per-host guardrails.** Read-only mode plus merged per-host command blacklists (regex over the command text), with local directory containment for transfers. A guardrail against mistakes, **not a security boundary**. |

---

## Routers and appliance CLIs: the gap nobody else fills

Most SSH MCP servers assume a POSIX shell and a TTY. Home labs and small offices are full of gear that violates both assumptions: Keenetic routers with the Cisco-style **NDM CLI**, switch and firewall CLIs, and anything that paginates with `--More--`, `--Press ENTER to continue`, or `?`.

This gateway treats that as a first-class case:

- **`shell: false`** executes a vendor CLI command on a channel with no shell wrapping, so `show running-config` does what you meant.
- **Pagers are detected and answered.** `--More--` and friends are auto-paginated, so a 400-line `show` returns as 400 lines of data instead of 400 lines of "press any key".
- **The two worlds never mix in one tab.** NDM CLI state and Linux shell state are separated, so a Cisco-style prompt can never be mistaken for a `$`.
- **Built-in aliases for common appliances.** Hosts named `keenetic` (or `KeeneticBt50`) are recognised for CLI mode automatically.

If your fleet is only Linux boxes, you will simply never touch this — and everything else still works.

---

## Install

### Option A — `uvx` (no install, no clone)

```bash
uvx --from mcp-ssh-gateway mcp-ssh-gateway --servers-config /path/to/servers.json
```

### Option B — `pip`

```bash
pip install mcp-ssh-gateway
mcp-ssh-gateway --servers-config /path/to/servers.json
```

### Option C — Docker

```bash
docker build -t mcp-ssh-server .
docker run -i --rm \
  -v /path/to/servers.json:/app/servers.json:ro \
  -v ~/.ssh:/root/.ssh:ro \
  mcp-ssh-server --servers-config /app/servers.json
```

### Option D — from source

```bash
git clone https://github.com/d00mus/MCP-SSH.git
cd MCP-SSH
pip install -r requirements.txt
python mcp-server.py --servers-config servers.json
```

> If `uvx`/`pip` reports the package as not found, the wheel has not been published to PyPI yet — use Option C or D, which behave identically. See [docs/PUBLISHING.md](docs/PUBLISHING.md).

---

## 1. Configure servers (`servers.json`)

Create `servers.json` in your workspace root, or copy [servers.json.example](servers.json.example):

```json
{
  "servers": {
    "keenetic": {
      "host": "192.168.1.1",
      "port": 22,
      "user": "admin",
      "password": "${KEENETIC_PASSWORD}",
      "description": "Keenetic router (NDM CLI, use shell:false)",
      "verify_host": false,
      "extra_path": "/opt/bin:/opt/sbin"
    },
    "nas": {
      "host": "192.168.1.10",
      "port": 22,
      "user": "storage",
      "key_path": "~/.ssh/id_rsa",
      "description": "TrueNAS storage server",
      "max_sessions": 10
    },
    "vps": {
      "host": "203.0.113.5",
      "port": 2222,
      "user": "ubuntu",
      "key_path": "~/.ssh/vps_key",
      "read_only": true,
      "command_blacklist": ["reboot", "poweroff", "rm -rf"],
      "description": "Production web server (read-only guardrail)"
    }
  }
}
```

> **Secrets:** `${VAR}` references in `password`/`key_passphrase` are resolved from the environment, so nothing sensitive needs to live in the file. An unresolved reference fails at startup with a clear error.

---

## 2. Connect your client

<details open>
<summary><b>Claude Desktop</b> / <b>Continue.dev</b> / any <code>mcpServers</code> client — Python</summary>

```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "uvx",
      "args": ["--from", "mcp-ssh-gateway", "mcp-ssh-gateway"],
      "env": { "KEENETIC_PASSWORD": "your_secure_password" }
    }
  }
}
```
</details>

<details>
<summary>Same, but Docker</summary>

```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/path/to/servers.json:/app/servers.json:ro",
        "-v", "/home/you/.ssh:/root/.ssh:ro",
        "mcp-ssh-server",
        "--servers-config", "/app/servers.json"
      ],
      "env": { "KEENETIC_PASSWORD": "your_secure_password" }
    }
  }
}
```
</details>

<details>
<summary>Same, but from a clone</summary>

```json
{
  "mcpServers": {
    "ssh-gateway": {
      "command": "python",
      "args": [
        "/opt/MCP-SSH/mcp-server.py",
        "--servers-config", "/opt/MCP-SSH/servers.json",
        "--project-root", "/opt/work"
      ],
      "env": { "KEENETIC_PASSWORD": "your_secure_password" }
    }
  }
}
```
</details>

### Tool profiles: lean vs full

- **`--tool-profile lean` — 6 tools:** `server_list`, `run`, `read`, `signal`, `file`, `session_close`. Roughly half the catalog tokens, which matters for small local models. `server_list` always reports `active_sessions` inline in both profiles, so no separate `session_list` call is needed.
- **`--tool-profile full` — 10 tools (default):** adds `server_add`, `session_list`, `session_update`, `last_command_details`.

---

## MCP tools

| Tool | Action | Description |
| :--- | :--- | :--- |
| `server_list` | Fleet overview | All configured SSH servers with alias, host, user, status and active session counts. Supports `reload: true`. |
| `server_add` | Append target | Registers a new SSH target at runtime without a restart. Append-only by design — existing targets cannot be modified or deleted through a tool call. |
| `session_list` | Session audit | Active persistent sessions and their statuses (`idle`, `busy`, `broken`), filterable by server prefix. |
| `session_update` | Rename session | Renames a session for easier identification. |
| `session_close` | Terminate channel | Closes the session and tears down the channel. It does **not** kill a remote process: a command already running keeps going, and anything it writes to the channel afterwards is lost. |
| `run` | Execute | 5s anti-hang timeout, then `still_running: true` instead of a failure. Without `session_id` an idle session is reused with unknown state (`new_session: true` forces a clean shell); an explicit busy `session_id` fails immediately rather than queueing. First `line_limit` lines come back inline, the rest stays in the tab stream and `has_more` counts the unread **lines** — continue with `read`. `wait_timeout: 0` starts async at once, `hard_timeout` interrupts after N seconds (`status: interrupted`, partial output kept), `use_pty: false` runs a clean single exec with closed stdin (no heredoc, no echo). `shell: false` is required for vendor CLIs. |
| `read` | Read / scroll tab | The tab's single unread stream through one **line-based** cursor. `line_limit` (default 200, max 5000, `0` = uncapped), `tail` (last N lines, moves to the end and reports skipped lines as `dropped_data`), `offset` = **line** position (negative peeks back from the cursor, `0` inspects from the first line, positive from line N; any `offset` is a non-consuming peek). No continuation token: call `read` again while `has_more` > 0. `status` is one of `running`, `completed`, `completed_nonzero`, `interrupted`, `stalled`. |
| `signal` | Control processes | `action: "ctrl_c"` interrupts a stuck command and frees the session immediately; `action: "stdin"` answers a prompt. |
| `file` | Manage files | Workspace-contained remote file tool (SFTP with shell fallback): `list`, chunked `read` (`offset_line`, `limit_lines`), atomic `write` (chmod before rename, new files mode `0600`, existing files keep their mode) and atomic in-place `edit` with optional private `0600` `<path>.mcp.bak` backup. |
| `last_command_details` | Command inspect | Exact command string, arguments, execution status and raw output of the last tool call, for troubleshooting. |

---

## How output works (and why it fits a context window)

Terminal noise is stripped server-side, and the remaining output is addressed by line rather than by a private token:

- **ANSI and control codes removed.** What the agent sees is text, not escape sequences.
- **Predictable windows.** `run` returns the first `line_limit` lines inline; `has_more` is the **number of unread lines still waiting**. `read` delivers the next window. There is no continuation token to lose and no counter to guess.
- **A real buffer.** Up to 2,000,000 characters per tab, with completed run buffers evicted under a process-wide budget. `dropped_data` reports unread text that was dropped, including a `tail` jump that skipped lines.
- **Pipes belong in the command.** `| grep`, `| awk`, `| head` run remotely, where they are cheap, instead of filtering in the model.
- **Deep telemetry is opt-in.** `last_command_details` returns the raw run record; the normal path stays compact.

---

## Worked examples

### A router CLI command (Keenetic NDM, `shell: false`)

Cisco-style NDM commands run directly, with no shell wrapping. Do not mix NDM CLI and Linux shell in the same tab:

```json
// tools/call: run
{ "server": "keenetic", "command": "show interface", "shell": false }
```

### A one-shot Linux command (`use_pty: false`)

A standalone command over a clean exec channel with closed `stdin` — no PTY, no echo, no heredoc:

```json
// tools/call: run
{ "server": "vps", "command": "cat /etc/os-release | grep PRETTY_NAME", "use_pty": false }
```

### Long output, delivered in line-addressed windows

```json
// Step 1: run  -> {"still_running": true, "has_more": 138, "output": "...", "session_id": "keenetic/1"}
{ "server": "keenetic", "command": "show running-config", "shell": false }

// Step 2: read  -> next window; has_more counts unread LINES (0 = caught up)
{ "server": "keenetic", "session_id": "keenetic/1", "line_limit": 200 }

// Step 3: read  -> same call again while has_more > 0
```

### Registering a new host at runtime

```json
// tools/call: server_add
{ "name": "pi", "host": "192.168.1.50", "user": "pi", "key_path": "~/.ssh/id_ed25519", "description": "Raspberry Pi" }
```

---

## Configuration reference

| Parameter / Env | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `--servers-config` / `SSH_SERVERS_CONFIG` | String | `servers.json` | Path to the JSON file with server targets, or an inline JSON string. |
| `--project-root` | String | `cwd` | Local project root for path containment and cache placement (CLI flag only — there is no `PROJECT_ROOT` env var). |
| `--cache-dir` / `SSH_MCP_CACHE_DIR` | String | `.ssh-cache` | Storage root for session logs, run buffers and recovery state. |
| `--read-only` / `SSH_READ_ONLY` | Boolean | `False` | Global read-only guardrail override. |
| `--command-blacklist` / `SSH_COMMAND_BLACKLIST` | String | None | Global prohibited commands, comma-separated. |
| `--allow-system-temp` | Boolean | `False` | Let the file tool use the system temp directory (default: project root and cache dir only). |
| `--allow-gateway-dir` | Boolean | `False` | Let the file tool touch the gateway install directory (development only; the gateway's own code stays protected). |
| `--log-output` | `full\|meta\|off` | `meta` | `full` stores raw output chunks (secret/IO heavy), `meta` lifecycle + command text only, `off` disables logging. Log disk usage is bounded at 200 MB. |
| `--tool-profile` | `lean\|full` | `full` | Tool catalog size. `lean` = 6 everyday tools for small models. |
| `--import-ssh-config` | Boolean | `False` | Also register hosts from `~/.ssh/config` (key auth). Imported hosts survive hot-reload removal. |

---

## Security guardrails — and what they are not

> **Honest scope.** The checks below are regex guardrails over the submitted command text. Shell quoting, expansion, `base64`, or an interpreter (`python3 -c`, `perl -e`, `busybox sh`) defeat them. They protect a *mistaken* agent from obvious self-harm; they do **not** contain a *compromised* one. For a real boundary use a restricted SSH account, `ForceCommand`/chroot, read-only filesystems, or separate credentials per trust level.

- **Per-host read-only guardrail** blocks file-tool writes (`write`, `edit`, `upload`) and obvious write patterns in commands (redirections, package installs, disk formatting).
- **Command blacklists merge** — per-host entries combine with the global list into one enforcement set.
- **Append-only registration** — agents can add targets, never edit or delete them through a tool call.
- **Local containment** — transfers are confined to the project root and the gateway cache dir; the gateway's own code and config are never writable through the file tool.

---

## Agent notes

The server also sends `instructions` during `initialize`, so a model that has just connected knows the routing rules without them being repeated in your prompt: start from `server_list`, reuse the returned `session_id` to preserve shell state, never send concurrent commands to one session, treat `completed_nonzero` as a result, and use `shell: false` for vendor CLIs. Every tool declares MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`), so clients can gate tools by risk.

---

## Development

```bash
git clone https://github.com/d00mus/MCP-SSH.git
cd MCP-SSH
pip install -r requirements.txt
python -m unittest discover -s tests -t .
```

CI runs the full suite on Python 3.11 and 3.13.

- [Contributing](CONTRIBUTING.md) — how to run the tests and open a change
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Release process](docs/PUBLISHING.md) — PyPI wheel + MCP Registry submission
- [Quick start (short form)](QUICK_START.md)

---

## License

MIT