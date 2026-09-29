"""Test doubles: a paramiko-like channel with a tiny scripted shell behind it.

The shell speaks the protocol the gateway relies on: it accepts the quiet-mode setup
line, prints the ``__MCP_EC_<token>_<rc>_<run>]`` prompt marker whenever it is ready for a
command (``<run>`` is the number the gateway gave to the command it started last), and
answers Ctrl+C. What a command prints is decided by a script, so session behaviour can be
tested without a network.
"""

import queue
import re
import threading
import time
from typing import Callable, List, Optional

TOKEN_IN_SETUP = re.compile(r'__MCP_EC_(\w+)_%s')
# How the gateway types a command: "__mcp_n=3; echo hi", or "{ __mcp_n=3" for the first line of a group.
NUMBERED = re.compile(r"^(\{ )?__mcp_n=(\d+)(?:; (.*))?$", re.DOTALL)


class Behaviour:
    """What a scripted command does."""

    def __init__(self, output: str = "", code: int = 0, hang: bool = False, ask: str = "",
                 ignore_ctrl_c: bool = False, more: bool = False, timeline=None, then: Optional[Callable[[str], "Behaviour"]] = None):
        self.output = output
        self.code = code
        self.hang = hang                  # never finishes on its own
        self.ask = ask                    # prints this question and waits for one line of input
        self.ignore_ctrl_c = ignore_ctrl_c
        self.more = more                  # the command is incomplete: the shell asks for more
        self.timeline = timeline          # (seconds until the output, seconds from the output to the prompt)
        self.then = then                  # what happens after the input arrived


class FakePosixShell:
    """A PTY channel whose far end is a POSIX shell in (or refusing) quiet mode."""

    def __init__(self, script: Callable[[str], Behaviour], quiet_works: bool = True,
                 quiet_after_exec: bool = False, banner: str = "Welcome\nuser@host:~$ ",
                 line_limit: Optional[int] = None):
        self.script = script
        self.quiet_works = quiet_works
        self.quiet_after_exec = quiet_after_exec  # "exec sh" leaves a shell that can be silenced
        # BusyBox ash (Keenetic, OpenWrt, Alpine) reads a typed line through a line editor with a small buffer
        # and shows its prompt again each time the buffer is full, before it has seen the end of the line.
        self.line_limit = line_limit
        self._waiting_prompt = ""         # what the shell showed last: the prompt it repeats
        self.closed = False
        self.commands: List[str] = []     # what the shell executed, in order
        self.typed: List[str] = []        # everything sent to the channel
        self._out: queue.Queue[Optional[bytes]] = queue.Queue()
        self._lock = threading.RLock()
        self._token: Optional[str] = None
        self._quiet = False
        self._run_number = 0              # the shell variable the prompt prints
        self._numbered: Optional[int] = None  # the assignment that runs together with the command being typed
        self._group: Optional[List[str]] = None
        self._running: Optional[Behaviour] = None
        self._timeout = 0.05
        self._emit(banner)

    # -- paramiko surface --------------------------------------------------
    def settimeout(self, value: float) -> None:
        self._timeout = min(value, 0.05)

    def sendall(self, data: bytes) -> None:
        if self.closed:
            raise OSError("channel closed")
        text = data.decode("utf-8")
        self.typed.append(text)
        if self.line_limit:  # the far end works on its own, as over a network: the gaps between its chunks are real
            threading.Thread(target=self._receive, args=(text,), daemon=True).start()
        else:
            self._receive(text)

    def _receive(self, text: str) -> None:
        with self._lock:
            if text == "\x03":
                self._ctrl_c()
                return
            for line in text.split("\n")[:-1] if text.endswith("\n") else text.split("\n"):
                self._line(line)

    def recv(self, size: int) -> bytes:
        try:
            item = self._out.get(timeout=self._timeout)
        except queue.Empty:
            raise TimeoutError() from None
        return b"" if item is None else item

    def close(self) -> None:
        self.closed = True
        self._out.put(None)

    # -- helpers for tests --------------------------------------------------
    def emit(self, text: str) -> None:
        """Unsolicited output, e.g. from a background job."""
        self._emit(text)

    def finish_running(self, code: int = 0) -> None:
        """A hanging command ends by itself."""
        with self._lock:
            self._running = None
            self._prompt(code)

    # -- the shell -----------------------------------------------------------
    def _emit(self, text: str) -> None:
        self._out.put(text.replace("\n", "\r\n").encode())

    def _prompt(self, code: int) -> None:
        if self._token:
            self._waiting_prompt = f"__MCP_EC_{self._token}_{code}_{self._run_number}]"
            self._emit(self._waiting_prompt)

    def _reprompt(self, line: str) -> None:
        """The line editor shows the prompt again for every full buffer of the line (the newline counts)."""
        if self.line_limit and self._token:
            extra = (len(line) + 1) // self.line_limit
            for _ in range(extra):
                self._emit(self._waiting_prompt)
            if extra:
                time.sleep(0.05)  # the shell has not run anything yet: the command comes after the whole line is read

    def _line(self, line: str) -> None:
        running = self._running
        if running is not None:
            if running.ask:
                self._answer(line)
            return  # typed into a hanging process: swallowed
        if not self._quiet:
            self._emit(line + "\n")
        if "stty -echo" in line:
            match = TOKEN_IN_SETUP.search(line)
            self._token = match.group(1) if match else None
            self._quiet = self.quiet_works
            self._prompt(127)
            return
        self._reprompt(line)
        if self._group is not None:
            if line == "}":
                command, self._group = "\n".join(self._group), None
                self._execute(command)
            else:
                self._group.append(line)
                self._more()
            return
        numbered = NUMBERED.match(line)
        if numbered:
            self._numbered = int(numbered.group(2))
            if numbered.group(1):  # "{ __mcp_n=3": a group starts
                self._group = []
                self._more()
                return
            line = numbered.group(3) or ""
        self._execute(line)

    def _more(self) -> None:
        if self._token:
            self._waiting_prompt = f"__MCP_MORE_{self._token}]"
            self._emit(self._waiting_prompt)

    def _execute(self, command: str) -> None:
        if self._numbered is not None:  # the assignment in front of the command runs first
            self._run_number, self._numbered = self._numbered, None
        if command.startswith("exec "):
            self._quiet, self._token, self._run_number = False, None, 0
            self.quiet_works = self.quiet_after_exec
            self._emit("$ ")
            return
        if command == ":":
            self._prompt(0)
            return
        self.commands.append(command)
        self._start(self.script(command))

    def _start(self, behaviour: Behaviour) -> None:
        self._running = behaviour
        if behaviour.more:
            behaviour.hang = True
            self._more()
            return
        if behaviour.timeline:
            before_output, before_prompt = behaviour.timeline
            threading.Timer(before_output, self._emit, [behaviour.output]).start()
            threading.Timer(before_output + before_prompt, self.finish_running, [behaviour.code]).start()
            return
        if behaviour.output:
            self._emit(behaviour.output)
        if behaviour.ask:
            self._emit(behaviour.ask)
            return
        if not behaviour.hang:
            self._running = None
            self._prompt(behaviour.code)

    def _answer(self, line: str) -> None:
        behaviour, self._running = self._running, None
        follow_up = behaviour.then(line) if behaviour.then else Behaviour()
        self._start(follow_up)

    def _ctrl_c(self) -> None:
        behaviour = self._running
        if behaviour is None or behaviour.ignore_ctrl_c:
            return
        self._running = None
        self._emit("\n")
        self._prompt(130)


class FakeForeignShell(FakePosixShell):
    """A login shell that is not POSIX (fish, tcsh): whatever is typed, it answers with an error and its prompt."""

    def __init__(self, error: str, prompt: str = "user@host ~> "):
        super().__init__(lambda command: Behaviour(), banner="Welcome\n" + prompt)
        self.error = error
        self.prompt = prompt

    def _line(self, line: str) -> None:
        self._emit(f"{line}\n{self.error}\n{self.prompt}")


class FakeNdmShell(FakePosixShell):
    """A router whose login is a CLI (Keenetic NDM). It echoes typed lines, cannot be silenced,
    and offers a Linux shell behind the ``shell`` command."""

    PROMPT = "Keenetic-Giga>"

    def __init__(self, cli_script: Callable[[str], str], linux_script: Callable[[str], Behaviour] = None,
                 pages: Optional[List[str]] = None):
        super().__init__(linux_script or (lambda command: Behaviour()), banner="Keenetic Giga\n" + self.PROMPT)
        self.cli_script = cli_script
        self._in_linux = False
        self._pages = list(pages or [])

    def _line(self, line: str) -> None:
        if self._in_linux:
            super()._line(line)
            return
        if line == " " and self._pages:
            self._next_page()
            return
        self._emit(line + "\n")
        if line == "shell" and self.linux_allowed:
            self._in_linux = True
            self._quiet, self._token = False, None
            self._emit("$ ")
            return
        if line.startswith("stty"):
            self._emit("Command::Base error[0xcffd0001]: no such command: stty.\n" + self.PROMPT)
            return
        if line == "show pages":
            self._next_page()
            return
        answer = self.cli_script(line)
        self._emit(answer if answer.endswith(" ") else answer + self.PROMPT)  # a question leaves no prompt

    linux_allowed = True

    def sendall(self, data: bytes) -> None:
        text = data.decode("utf-8")
        if not self._in_linux and text == " ":
            with self._lock:
                self.typed.append(text)
                self._line(" ")
            return
        super().sendall(data)

    def _next_page(self) -> None:
        page = self._pages.pop(0)
        self._emit(page + (" --More-- " if self._pages else "\n" + self.PROMPT))


class FakeConnection:
    """What Session needs from the SSH transport."""

    def __init__(self, make_channel):
        self.make_channel = make_channel
        self.channels = []
        self.active = True

    def open_channel(self, cols=220, rows=50):
        channel = self.make_channel()
        self.channels.append(channel)
        return channel

    def is_active(self):
        return self.active

    def close(self):
        self.active = False
