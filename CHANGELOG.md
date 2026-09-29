# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [7.0.0] - 2026-09-29

A rewrite of the core with a smaller, clearer tool surface. **Breaking changes.**

### Changed
- Command completion is read from the shell's own prompt: the shell is switched to a quiet
  mode whose prompt prints a marker with the exit code. This replaces the typed-ahead
  exit marker and the output-scrubbing heuristics, and fixes commands ending in `&`, lines
  that look like prompts (`#`, `>`), heredocs, syntax errors and stdin-reading programs.
  An unclosed quote or heredoc is reported as `waiting_input`.
- Tools are now `server_list`, `run`, `read`, `signal`, `session_close`, `file`
  (`server_add` only with `--allow-add-server`). Removed: `session_list`, `session_update`,
  `last_command_details`, `--tool-profile`.
- Parameters were renamed and reduced: `wait` (was `wait_timeout`), `timeout` (was
  `hard_timeout`), `lines` (was `line_limit`), `tail`, `offset`. Removed: `use_pty`, `cursor`,
  `name`, `reload` and the other compatibility aliases.
- Answers: `status` is one of `running`, `waiting_input`, `completed` (with `exit_code`, also
  when non-zero), `interrupted`, `timed_out`, `failed`, `idle`. `still_running` and `exit_status`
  are gone.
- There is no default session: a shell has state, so it is never shared implicitly. `run`
  without `session_id` opens a new shell and returns its id; pass the id to continue in it.
  `new_session` is gone. When the session limit is reached the error lists the open shells.
  The default limit is 8 shells per server (`max_sessions`): sshd allows 10 channels per
  connection and the `file` tool needs one of them for SFTP.
- A new command in a session passes over unread older output and reports `skipped_lines`.
  So does `read(tail=…)`, which 6.x reported as `dropped_data`. `dropped_data` is now kept for
  output that is gone for good (the session buffer overflowed); skipped lines can be scrolled
  back to with `read(offset=0)`.
- The `file` tool on a host without SFTP uses the shell named by `session_id`, or a temporary
  one that it closes afterwards.
- The `file` tool lists as plain `ls -l` text and reads with `content`, `line_start`, `line_end`,
  `total_lines`, `next_offset_line`.
- The `file` tool has 14 parameters instead of 18. Gone: `max_chars` and `max_bytes` (a read shows
  at most 20 000 characters of the first 200 KB, ending at a line with `next_offset_line` to go on;
  more is `run` work: `tail`, `sed -n`, `grep`), `create_backup` (`cp` first) and `regex` (`contains`
  or `grep`).
- Host keys: trust on first use, remembered in `known_hosts` in the cache directory, a changed
  key is refused (was: the system host-key store only).
- The default cache directory is the user cache directory instead of `./.ssh-cache`.
- Local file transfer (`local_path` of the `file` tool) is off unless the gateway is started with
  `--project-root <folder>`. It used to default to the working directory of the MCP client, which
  is often your home folder.
- One version source: `mcp_ssh_gateway.__version__`.
- The wheel installs the package `mcp_ssh_gateway`. 6.x installed a top-level package called
  `src`, which could clash with other projects. The `mcp-ssh-gateway` command and `mcp-server.py`
  start the server as before.
- The licence is declared as the SPDX expression `MIT` (setuptools retires the old table form in
  2027), so building needs setuptools 77 or newer. The source archive also carries the Docker
  images of the integration tests.
- The README is rewritten: a quick start from `~/.ssh/config`, snippets for Cursor, Claude, VS Code
  and Codex, a real transcript, what the gateway works with, security up front and an honest
  comparison with other SSH servers for MCP. `README.ru.md` is its Russian translation. Notes
  for whoever releases the project moved to `docs/maintainers/`.

### Fixed
- Ctrl+C on a program that waits for input, and on a router CLI that redraws its prompt,
  now confirms the stop instead of waiting for the grace period.
- `read` no longer reports `running` when the prompt follows the last output by milliseconds.
- A shell that the server refuses (sshd `MaxSessions`) no longer closes the connection with
  all the other shells; the error says what the limit is.
- The answer to `signal` is capped like the answers to `run` and `read` (20 000 characters,
  it could be ten times larger).
- Input that a terminal cannot take (a line over 4000 characters, or more than 256 KB in
  all) is refused with a pointer to the `file` tool, for `stdin` as well as for commands.
  A failed send names its cause.
- Log masking now covers names that merely contain a secret word (`GITHUB_TOKEN=`),
  `Authorization: Bearer …` (only the word "Bearer" was hidden), quoted values, URLs with
  `user:password@`, `curl -u`, `sshpass -p` and `mysql -p…`.
- A password or passphrase in `servers.json` is used as written except for `${NAME}`
  references; a `$HOME`, `$1` or `%x%` inside it is no longer expanded.
- A damaged `known_hosts` file is reported instead of crashing the request.
- Stale-hash edits are refused also for `dry_run`.
- `git log`, `systemctl status`, `man` and other tools no longer stop in a pager that nobody
  can page (`PAGER`, `GIT_PAGER`, `SYSTEMD_PAGER` and `MANPAGER` are `cat` in the session).
- A progress bar that rewrites its line with `\r` (`curl`, `wget`, `pip`, `dd`) is one line in
  the answer instead of one line per update. Windows line ends no longer double the lines.
- More questions are recognised as waiting for input (`(yes/no/[fingerprint])?`, `Username:`,
  `overwrite 'x'?`). A silent program that left a line unfinished gets that line in the `hint`, so
  the agent can decide whether it is a question.
- A shell started inside a session (`sudo -s`, `su`, `bash`) is named in the `hint` with the way
  out (`signal stdin` `exit`). The README no longer promises that `sudo -s` persists.
- Old session logs are pruned while the gateway keeps running, not only at its start.
- The `CryptographyDeprecationWarning` about TripleDES that `paramiko` raises on import no longer
  shows up in the MCP client's log at every start.
- A command line longer than the line buffer of a BusyBox shell (512 characters on a Keenetic,
  about 2000 on Alpine) no longer ends early. BusyBox shows its prompt a second time while it
  reads such a line, and the gateway took that prompt for the end of the command: the answer had
  no output and the real output showed up in the next one. The prompt now carries the number of
  the command that the shell started last, and only the prompt with the number of the command in
  progress ends it. Lines of up to 4000 characters work on these hosts.
- The `file` tool on a host without SFTP says `no such file or not readable` for a file that is
  not there, instead of `no output`.

### Added
- The `shell` server option (`"shell": "bash"`): the gateway runs `exec bash` after login, so
  accounts with a fish or tcsh login shell work. Without it such a login is refused at once
  with that advice (it used to fail after a 20 second timeout with an unreadable message).
- Real-`sshd` integration tests (Debian/bash, Alpine/BusyBox, Debian without SFTP, zsh/dash/fish/tcsh logins).
- `SSH_READ_ONLY` and `SSH_COMMAND_BLACKLIST` environment variables.
- CI: ruff, mypy (the package ships `py.typed`), unit tests on Linux, macOS and Windows, Docker
  integration tests. A release tag runs all of it first, and `tests/test_release.py` keeps the
  version of the code, `server.json` and the changelog in step.

### Removed
- The compatibility layer, the exec-channel mode, per-run buffers, the ticket-numbered
  special cases and hard-coded server aliases.

### Migrating from 6.x

| 6.x | 7.0.0 |
| --- | --- |
| `wait_timeout`, `hard_timeout`, `line_limit` | `wait`, `timeout`, `lines` |
| `cursor`, `use_pty`, `name`, `reload`, `new_session` | Removed. |
| `session_list`, `session_update`, `last_command_details` | Removed. `server_list` shows the open sessions. |
| `--tool-profile lean` | Removed: there are always six tools. |
| `status: still_running`, `exit_status` | `status: running`, `exit_code`. |
| A default shell when `session_id` is left out | None. `run` opens a new shell; pass its `session_id` to continue in it. |
| `file`: `max_chars`, `max_bytes`, `create_backup`, `regex` | Removed. Use `tail`, `sed -n`, `grep` and `cp` through `run`. |
| `file` with `local_path` (upload, download) | Start the gateway with `--project-root <folder>`. |
| Cache in `./.ssh-cache`; host keys from the system store only | The user cache directory; trust on first use, `known_hosts` kept there. |
| `from src... import ...` | `from mcp_ssh_gateway... import ...` |

## [6.0.2] — 2026-09-28

### Changed
- Document and verify installation from the published PyPI package in an isolated directory.
- Replace dummy password values in the MCP client example with explicit placeholders.

## [6.0.1] — 2026-09-28

### Added
- Published to PyPI as `mcp-ssh-gateway` and listed in the MCP Registry as `io.github.d00mus/mcp-ssh-gateway`.
- Trusted Publishing workflow (`.github/workflows/publish-pypi.yml`): a `v*` tag publishes without a stored long-lived token.
- PyPI and MCP Registry badges in the README.

### Changed
- Rewrite the README around practical SSH fleet workflows, with a verified quickstart and clearer setup and security boundaries.
- Correct quickstart and security guidance; default the example host configuration to SSH host-key verification.
- Installation now leads with `pip install mcp-ssh-gateway`; the client config, `mcp.json.example` and quickstart invoke the `mcp-ssh-gateway` console script instead of `mcp-server.py`. Cloning remains documented for working on the project itself.

## [6.0.0] — 2026-09-28

### Changed
- Unified scrollback: every tab keeps one 2M-character canvas addressed through a
  single line-based cursor. `run` returns the first `line_limit` lines inline,
  `has_more` reports the number of unread **lines**, and `read` delivers the next
  window. No continuation token, no bookkeeping counters.
- Honest MCP framing: internal exit markers, prompt echoes and gateway machinery
  never surface in the agent's window.
- Configuration is hot-reloaded on the health-loop pass (mtime + content hash), so
  adding a host or tightening a policy no longer drops open sessions.
- Control requests (Ctrl+C, reads, session control) are served from a separate
  pool, so an interrupt is never queued behind a long-running command.

### Added
- Vendor-CLI and pager support: `--More--` style pagers are auto-paginated, and
  `shell: false` runs an appliance CLI (Keenetic NDM and similar) on a channel with
  no shell wrapping, kept strictly separate from the POSIX shell tab.
- `file` tool: in-place remote search-and-replace edit with line-numbered
  diagnostics, similarity hints, and an optional private `0600` `<path>.mcp.bak`.
- `--tool-profile lean`: 6 everyday tools, roughly half the catalog tokens.
- `--import-ssh-config`: register key-auth hosts from `~/.ssh/config`.
- Degraded mode: without paramiko the server still answers JSON-RPC with real
  errors (-32700 / -32603) instead of hanging or returning an empty tool catalog.
- MCP client contract: negotiates protocol 2025-06-18 with fallback to older
  revisions, sends `instructions` on initialize, and annotates every tool with
  `readOnlyHint` / `destructiveHint` / `idempotentHint`.

### Security
- Per-host read-only guardrail and merged command blacklists, with local directory
  containment for file transfers. Documented explicitly as *not* a security
  boundary.

## [5.x] and earlier

See the commit history for the pre-6.0 line of development.
