# Contributing

Thanks for looking at this. The project is small and PRs are welcome.

## Rules that keep the agent's view stable

- **Output is lines.** `has_more` is the number of unread *lines*; `lines` counts lines;
  `offset` never moves the unread position; the output reaching the agent contains no
  prompt markers and no doubled echo of the command. `tests/test_stream.py`,
  `tests/test_terminal.py` and `tests/test_session.py` pin this.
- **The shape of an answer is a decision.** The keys of every answer are listed in
  `tests/test_contract.py` (and, for the `file` tool, in `tests/integration/test_linux_hosts.py`),
  because the answers are what the agent reads and pays for in tokens. Adding a key means
  changing that test on purpose.
- **A non-zero exit code is a result, not an error.** Only `status: failed` (lost connection)
  and exceptions raised for bad requests become tool errors.
- **The tool catalogue is small and self-explanatory.** Every parameter has a description
  (a test checks it) and `tests/test_server.py` limits the size of `tools/list`, because
  every session pays for it. A new tool needs a good reason.
- **No test hacks in production code.** Code must not know it is being tested. Use the
  fakes in `tests/fakes.py` or the Docker images in `tests/integration/images`.

## Setup

```bash
git clone https://github.com/d00mus/MCP-SSH.git
cd MCP-SSH
pip install -r requirements.txt ruff mypy
```

Python 3.11+ (CI also runs 3.13).

## Tests

```bash
python -m unittest discover -s tests -t .                 # everything (integration needs Docker)
MCP_SSH_IT=0 python -m unittest discover -s tests -t .    # unit tests only
python -m unittest tests.test_session -v                  # one module
ruff check .
mypy
```

Unit tests use scripted fakes of an SSH channel (`tests/fakes.py`) and never open a socket.
Integration tests build and start `sshd` containers (Debian/bash, Alpine/BusyBox ash,
Debian without SFTP, and one account per login shell: zsh, dash, fish, tcsh) and talk to the
gateway through the JSON-RPC entry point.

Bugs are fixed test first: write the test that fails, then the fix.

## Layout

| Module | Responsibility |
| --- | --- |
| `stream.py` | Line-based buffer with an unread position (`Canvas`), ANSI cleanup. |
| `terminal.py` | Prompt-marker protocol for POSIX shells, router CLI prompt/echo/pager handling. |
| `session.py` | One terminal: runs, waiting, signals, status. |
| `transport.py` | The SSH connection (paramiko), host keys, error messages. |
| `manager.py` | Servers, sessions per server, hot reload, cancellation. |
| `files.py` | The `file` tool (SFTP and shell backends, edits, local sandbox). |
| `server.py` | MCP tool catalogue and JSON-RPC dispatch. |
| `main.py` | Command line, stdio loop. |
| `logs.py` | Per-session and per-command log files. |

## Opening a change

1. Branch from `master`.
2. Add or update tests with the behaviour change.
3. Update `CHANGELOG.md` under `[Unreleased]`.
4. If a tool, an option or an answer changes, change `README.md` and `README.ru.md` too.
   `tests/test_readme.py` checks that their examples, the options table and the links still
   match the code.
5. Describe the user-visible effect in the pull request, not only the diff.

## Reporting bugs

Use the issue templates. A useful report has the MCP client, the host type (POSIX shell or
vendor CLI), the exact tool call and the returned JSON.
