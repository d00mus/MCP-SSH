# Security Policy

## Scope

This project is an SSH gateway that an AI agent drives on your behalf. Treat the
agent as an untrusted caller that you have given SSH credentials to.

## What the guardrails do (and do not) protect

The built-in guardrails check the submitted command text (including literal
blacklist entries), plus local-path containment for file transfers:

- per-host `read_only` mode blocks file-tool writes and obvious write patterns in
  commands (redirections, package installs, disk formatting);
- `command_blacklist` entries merge per-host and global lists into one set;
- `server_add` is append-only — existing targets cannot be edited or deleted
  through a tool call;
- local transfer paths are confined to the project root and gateway cache dir;
  this does not restrict remote command execution or remote paths. The gateway's
  own code and config are not writable through the file tool.

These are **mistake guards, not a security boundary**. Shell quoting, expansion,
`base64`, or an interpreter (`python3 -c`, `perl -e`, `busybox sh`) defeat a
command-text check. A compromised agent has the same reach as the SSH account you
configured.

## If you need a real boundary

- use a **restricted SSH account** with a read-only shell for inspection tasks;
- apply `ForceCommand`, `chroot`, or `authorized_keys` `from=` restrictions;
- mount read-only filesystems where writes are not expected;
- use **separate credentials per trust level** — never one account for a router and
  for production;
- mark production hosts `read_only: true` in `servers.json`;
- keep secrets in environment variables referenced as `${VAR}`, not in the JSON.

## Reporting a vulnerability

Please report privately through GitHub Security Advisories
("Security" → "Report a vulnerability") rather than a public issue. Include the
affected version, a description of the impact, and a reproduction if possible. You
can expect an acknowledgement and a fix or a mitigation plan. Do not test against
hosts you do not own.
