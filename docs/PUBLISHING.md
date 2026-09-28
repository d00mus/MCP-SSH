# Release process

Two artifacts, in this order. The registry hosts **metadata only**, so the PyPI
wheel must exist first.

## 0. Version discipline

The version the client sees at runtime comes from `SERVER_VERSION` in
`src/server.py`. It must equal `version` in `pyproject.toml` and the git tag.
Change all three in one commit.

## 1. Preconditions

- `SERVER_VERSION` == `pyproject.toml` version.
- `README.md` starts with the line `<!-- mcp-name: io.github.d00mus/mcp-ssh-gateway -->`.
  The token must be followed by a boundary (newline, whitespace, or `-->`); do not
  put a period directly after it, or the validator will not match.
- Full tracked suite green: `python -m unittest discover -s tests -t .`

## 2. Build and check the wheel

```bash
pip install build twine
python -m build                 # dist/mcp_ssh_gateway-<v>.whl + .tar.gz
python -m twine check dist/*
```

## 3. Tag and push

```bash
git tag -a v<version> -m "release <version>"
git push origin master --tags
```

## 4. Publish to PyPI

```bash
python -m twine upload dist/*
```

Use a [PyPI API token](https://pypi.org/manage/account/token/) as `__token__`;
password upload is disabled. Verify:

```bash
pip install mcp-ssh-gateway
mcp-ssh-gateway --help
uvx --from mcp-ssh-gateway mcp-ssh-gateway --help
```

## 5. Publish to the MCP Registry

Install the CLI (Windows shown):

```powershell
curl -L -o mcp-publisher.tar.gz https://github.com/modelcontextprotocol/registry/releases/latest/download/mcp-publisher_windows_amd64.tar.gz
tar -xzf mcp-publisher.tar.gz
```

Then:

```bash
mcp-publisher init
# point it at this repository (./server.json is already committed)
mcp-publisher login github     # device flow: https://github.com/login/device
mcp-publisher publish
mcp-publisher status
```

The registry name must be `io.github.d00mus/mcp-ssh-gateway` and must match the
`mcp-name:` line in the PyPI README exactly. The registry is in preview, so
breaking changes or data resets are possible before GA.

## 6. Finish the storefront

- Uncomment the MCP Registry badge in `README.md` once `publish` succeeds.
- Confirm topics and the description are set (see `STOREFRONT.md`).
- Announce the release; the registry entry and the PyPI page are the durable
  listings that search and agent clients actually read.
