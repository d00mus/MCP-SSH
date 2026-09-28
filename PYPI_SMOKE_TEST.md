# Verify the published package in a clean directory

Use this procedure when checking that the current PyPI release installs independently of the repository checkout. Run it from a new directory (not the cloned source tree) so Python cannot accidentally import the local `src` package.

## Windows PowerShell

```powershell
$testDir = Join-Path $env:TEMP 'mcp-ssh-gateway-pypi-smoke'
New-Item -ItemType Directory -Force $testDir | Out-Null
Set-Location $testDir
py -3.11 -m venv .venv
$python = Join-Path $testDir ".venv\Scripts\python.exe"
$gateway = Join-Path $testDir ".venv\Scripts\mcp-ssh-gateway.exe"
& $python -m pip install --upgrade pip
& $python -m pip install --no-cache-dir mcp-ssh-gateway
& $gateway --help
& $python -m pip show mcp-ssh-gateway
```

The `--help` check verifies that the published console entry point starts without connecting to an SSH host. It does not verify SSH connectivity or MCP-client integration. To exercise the server, use a test SSH account and a valid host-key entry; do not use production credentials for a smoke test.

## macOS / Linux

```bash
mkdir -p /tmp/mcp-ssh-gateway-pypi-smoke
cd /tmp/mcp-ssh-gateway-pypi-smoke
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install --no-cache-dir mcp-ssh-gateway
.venv/bin/mcp-ssh-gateway --help
.venv/bin/python -c 'import importlib.metadata as m; print(m.version("mcp-ssh-gateway"))'
```

See [README.md](README.md#try-it-with-one-host) for an MCP client config and [QUICK_START.md](QUICK_START.md) for more configuration examples.
