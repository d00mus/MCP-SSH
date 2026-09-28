# Storefront checklist

Everything here is a GitHub or PyPI setting. None of it can be scripted from this
checkout without a token, so it is a hand-run list.

## Repository description (Settings → General → Description)

```
One MCP server for a whole fleet of SSH hosts: persistent sessions, honest exit
statuses, and router-CLI/pager-aware output. No single-host duplication.
```

## Homepage

```
https://github.com/d00mus/MCP-SSH
```

## Topics (max 20, lowercase, no spaces)

Add these via `gh repo edit --add-topic` or the repository homepage field:

```
mcp
model-context-protocol
ssh
ssh-gateway
ai-agents
ai-devops
mcp-server
multi-server
paramiko
keenetic
router
network-automation
home-lab
sysadmin
devtools
```

Also consider a repository logo — the competitor with 909 stars leads with an
image, and the repo currently has none.

## First issues (so the tracker is not empty)

Seed it with real, answerable questions rather than placeholders:

1. `Add support for Cisco IOS / Junos CLI profiles`
2. `Support jump hosts / ProxyJump for bastion setups`
3. `Parallel command execution across sessions`
4. `Secret rotation without editing servers.json`

## Discussions

Enable Discussions for `Q&A` and `Ideas`. It costs nothing and adds a second
surface for search and links.

## Announce where the users are

- r/LocalLLaMA, r/selfhosted, r/networking, r/homelab, r/devops
- `awesome-mcp-servers` and the `modelcontextprotocol` org
- MCP-focused newsletters and aggregators (a registry entry is what most client
  directories index)
- The repo is currently not in the official registry; step 5 of
  `docs/PUBLISHING.md` is what fixes that.
