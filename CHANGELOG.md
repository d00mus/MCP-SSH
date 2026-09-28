# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
