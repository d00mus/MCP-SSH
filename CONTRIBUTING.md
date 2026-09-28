# Contributing

Thanks for looking at this. The project is small and self-contained, and PRs are welcome.

## Ground rules that are not negotiable

- **Do not break the output contract.** `has_more` is the number of unread *lines*.
  `line_limit` counts lines, not characters. `offset` never consumes. Output reaching
  the agent must contain no internal markers, no shell prompt, and no double-echoed
  commands. The tests in `tests/test_server.py`, `tests/test_ssh.py`,
  `tests/test_multiserver.py` and `tests/test_fs.py` enforce this.
- **Non-zero exit is a result, not an error.** `completed_nonzero` + `exit_status`
  must never become a tool error. Only `failed`/`dead` are errors.
- **Every tool keeps its annotations.** `TOOL_ANNOTATIONS` in `src/server.py` must
  cover the whole catalog, and the `lean` profile must keep annotations.
- **Initialize is a contract.** `protocolVersion` is negotiated against
  `SUPPORTED_PROTOCOL_VERSIONS`, and `serverInfo` must use the public name
  (`mcp-ssh`), never an internal codename.

## Setup

```bash
git clone https://github.com/d00mus/MCP-SSH.git
cd MCP-SSH
pip install -r requirements.txt
```

Python 3.11+ (CI also runs 3.13).

## Run the tests

```bash
python -m unittest discover -s tests -t .
```

For one module:

```bash
python -m unittest tests.test_server -v
```

The suite uses only `unittest` and `unittest.mock`, so no test dependencies are
needed. Most tests mock paramiko and never open a socket; if you add a test that
touches the network, mark it clearly and keep it out of the default path.

## Style

- Plain `unittest`, no pytest-only constructs.
- Comments explain *why*, especially around output framing and concurrency.
- Keep the tool catalog small. A new tool needs a good reason: it is prompt tokens
  in every session for every user.

## Opening a change

1. Branch from `master`.
2. Add or update tests alongside the behaviour change.
3. Update `CHANGELOG.md` under `[Unreleased]`.
4. Open a pull request describing the user-visible effect, not just the diff.

## Reporting bugs

Use the issue templates. A useful report includes the MCP client, the host type
(POSIX shell vs vendor CLI), the exact tool call, and the returned JSON — not a
screenshot of the terminal.
