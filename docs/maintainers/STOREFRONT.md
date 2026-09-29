# Storefront checklist

Everything here is a GitHub or PyPI setting. None of it can be scripted from this
checkout without a token, so it is a hand-run list.

## Repository description (Settings → General → Description)

```
SSH terminals for AI agents that know when a command is done: six tools, stateful shells, exit codes, router CLIs.
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

## Social preview (Settings → General → Social preview)

A 1280×640 image is what a link to the repository shows in chats and on social networks.
The repository has none yet. The tagline of the README and a short answer of the gateway
(`"status":"completed","exit_code":0`) make a good picture.

## Issues

Issues #1 to #4 exist and carry the `enhancement` label. #3 and #4 were written against the
6.x tools (`new_session`, `session_list`, the 30-second health loop), which 7.0.0 removed:
reword or close them when the release is out. The README links to #1 (other router CLIs)
and #2 (jump hosts) as the known gaps.

## Discussions

Enable Discussions for `Q&A` and `Ideas`. It costs nothing and adds a second
surface for search and links.

## Announce where the users are

- r/LocalLLaMA, r/selfhosted, r/networking, r/homelab, r/devops
- `awesome-mcp-servers` and the `modelcontextprotocol` org
- MCP-focused newsletters and aggregators (a registry entry is what most client
  directories index)
