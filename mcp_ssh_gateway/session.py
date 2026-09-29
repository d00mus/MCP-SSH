"""One terminal session on one server.

A session owns a PTY channel, a reader thread and a ``Canvas`` (the console the agent
reads and scrolls). The reader runs for the whole life of the channel, so completion
is noticed the moment the shell prints its prompt marker, and output that arrives
while nobody is looking (a background job) is not lost.

Two kinds of hosts are supported:

- POSIX shells are switched into quiet mode (see ``terminal.posix_setup``): no echo,
  and a prompt that carries the exit code. Completion is certain.
- Router CLIs (Keenetic NDM) cannot be scripted. Their echo is filtered and a command
  is complete when the device's own prompt, learned at login, returns.

Locking: ``Session._lock`` guards all session state and is taken by the reader thread
for every chunk. ``Canvas`` has its own lock, always taken after the session lock and
never the other way round (canvas predicates read plain attributes only).
"""

import codecs
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from mcp_ssh_gateway.config import DEFAULT_LINES, DEFAULT_MAX_CHARS, DEFAULT_PATH, ServerTargetConfig
from mcp_ssh_gateway.logs import EventLog, LogStore
from mcp_ssh_gateway.security import check_command
from mcp_ssh_gateway.stream import ANSI_ESCAPE, Canvas, StreamCleaner
from mcp_ssh_gateway.terminal import (
    EchoFilter, MarkerFilter, PromptDetector, PromptEvent, foreign_shell, input_problem, looks_interactive,
    looks_like_shell_prompt, posix_setup, split_pager_prompt, wrap_posix,
)

MAX_CANVAS_CHARS = 4_000_000
RECV_SIZE = 65536
TAIL_CHARS = 400
UNFINISHED_LINE_CHARS = 80
FINAL_STATES = ("completed", "interrupted", "timed_out", "failed")

STATE_LOST = (
    "The connection or shell was replaced: the working directory, environment variables "
    "and background jobs of the previous shell are lost."
)


class SessionError(Exception):
    """A request the session cannot serve; the message is written for the agent."""


class SessionBusy(SessionError):
    pass


class CommandBlocked(SessionError):
    pass


@dataclass(frozen=True)
class Timing:
    """Time constants. Tests shorten them; the defaults suit real networks."""
    settle_prompt: float = 0.3      # a prompt must stay at the end this long before it counts (CLI)
    settle_input: float = 0.6       # a question must stay unanswered this long before we report it
    interrupt_grace: float = 3.0    # how long a Ctrl+C gets to take effect
    boot_silence: float = 1.0       # silence that ends the login banner
    boot_timeout: float = 20.0


@dataclass
class QuietResult:
    output: str
    exit_code: Optional[int]
    timed_out: bool = False


def command_title(command: str) -> str:
    """How a command appears in the console: a long script is shown by its first line."""
    lines = command.strip("\n").split("\n")
    if len(lines) == 1:
        return lines[0]
    return f"{lines[0]} [+{len(lines) - 1} lines]"


@dataclass
class Run:
    id: int
    command: str
    log: EventLog
    deadline: Optional[float] = None
    quiet: bool = False
    status: str = "running"
    exit_code: Optional[int] = None
    stopped: Optional[bool] = None
    error: str = ""
    interrupt_reason: Optional[str] = None
    interrupt_at: float = 0.0
    wants_more: bool = False           # the shell asks for more than the typed lines explain
    expected_more: int = 0             # continuation prompts of a complete command: one per typed line but the last
    more_seen: int = 0
    tail: str = ""                     # the last characters of the raw stream
    last_data: float = field(default_factory=time.monotonic)
    started: float = field(default_factory=time.monotonic)
    echo: Optional[EchoFilter] = None  # CLI only
    captured: List[str] = field(default_factory=list)  # quiet runs collect here, not on the canvas

    @property
    def finished(self) -> bool:
        return self.status in FINAL_STATES


class Session:
    def __init__(self, session_id: int, target: ServerTargetConfig, connection: Any, logs: LogStore,
                 shell: Optional[bool] = None, timing: Optional[Timing] = None) -> None:
        self.id = session_id
        self.target = target
        self.alias = target.alias
        self.sid = f"{target.alias}/{session_id}"
        self._connection = connection
        self._logs = logs
        self._log = logs.session_log(target.alias, session_id)
        self._want_shell = shell
        self._timing = timing or Timing()

        self.canvas = Canvas(MAX_CANVAS_CHARS)
        self.mode = ""                     # "shell" or "cli", known after start()
        self._lock = threading.RLock()
        self._boot_changed = threading.Condition(self._lock)
        self._channel: Any = None
        self._cleaner = StreamCleaner()
        self._markers: Optional[MarkerFilter] = None
        self._prompts = PromptDetector()
        self._ingest: Callable[[str], None] = self._ingest_boot
        self._boot_text = ""
        self._boot_events: List[Optional[PromptEvent]] = []
        self._boot_last_data = time.monotonic()

        self._run: Optional[Run] = None
        self._last: Optional[Run] = None
        self._run_counter = 0
        self._closed = False
        self._fresh_shell_needed = False
        self._skipped = 0                  # unread lines that a new command passed over, reported once
        self._warning = ""
        self._log.event("created", server=self.alias)

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        """Open the channel and find out what is on the other end."""
        with self._lock:
            self._open_channel()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            channel, self._channel = self._channel, None
            run, self._run = self._run, None
            if run is not None and not run.finished:
                self._settle(run, "failed", error="session closed")
        _close_quietly(channel)
        self.canvas.wake()
        self._log.event("closed")

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def busy(self) -> bool:
        return self._run is not None

    @property
    def alive(self) -> bool:
        return not self._closed and self._channel is not None and self._connection.is_active()

    def describe(self) -> Dict[str, Any]:
        run = self._run
        state = "closed" if self._closed else ("busy" if run else ("idle" if self.alive else "disconnected"))
        info: Dict[str, Any] = {"session_id": self.sid, "state": state, "mode": self.mode}
        if run:
            info["running"] = run.command[:120]
        return info

    # ------------------------------------------------------------------ commands

    def run(self, command: str, wait: float = 10.0, timeout: float = 0.0,
            lines: int = DEFAULT_LINES, max_chars: int = DEFAULT_MAX_CHARS) -> Dict[str, Any]:
        """Type a command, wait until it finishes (at most ``wait`` seconds), return the answer."""
        self._validate(command)
        with self._lock:
            run = self._start_run(command, timeout=timeout, quiet=False)
        self._wait_settled(run, wait)
        return self._answer(lines, max_chars, warning=True)

    def run_quiet(self, command: str, timeout: float = 30.0) -> QuietResult:
        """Run a maintenance command whose output must not reach the agent's canvas."""
        self._validate(command)
        with self._lock:
            if self.mode != "shell":
                raise SessionError("Maintenance commands need a POSIX shell.")
            run = self._start_run(command, timeout=timeout, quiet=True)
        self._wait_settled(run, timeout + self._timing.interrupt_grace + 1.0)
        with self._lock:
            return QuietResult("".join(run.captured), run.exit_code, run.status == "timed_out")

    def read(self, wait: float = 0.0, lines: int = DEFAULT_LINES, max_chars: int = DEFAULT_MAX_CHARS,
             tail: Optional[int] = None, offset: Optional[int] = None) -> Dict[str, Any]:
        """The next unread lines; ``tail`` jumps to the end, ``offset`` scrolls without moving."""
        if tail is not None:
            window = self.canvas.tail(tail, max_chars)
        elif offset is not None:
            window = self.canvas.peek(offset, lines, max_chars)
        else:
            run = self._run
            if wait > 0 and run is not None:  # like run: until the end, a question, or the wait is over
                self._wait_settled(run, wait)
            window = self.canvas.read_unread(lines, max_chars)
        return self._render(window, warning=False)

    def signal(self, action: str, text: str = "", enter: bool = True, wait: float = 5.0) -> Dict[str, Any]:
        """ctrl_c | ctrl_d | stdin: talk to the command that is running."""
        if action not in ("ctrl_c", "ctrl_d", "stdin"):
            raise SessionError(f"Unknown action '{action}'. Use ctrl_c, ctrl_d or stdin.")
        with self._lock:
            run = self._run
            if run is None:
                raise SessionError(
                    "Nothing is running in this session, so there is nothing to signal. "
                    "Start a command with run.")
            if action == "ctrl_c":
                self._interrupt(run, "interrupted")
            elif action == "ctrl_d":
                self._send("\x04")
            elif action == "stdin":
                self._check_input(text)
                self._send(text + ("\n" if enter else ""))
                run.last_data = time.monotonic()
                if run.status == "waiting_input":
                    run.status = "running"
        self._wait_settled(run, wait)
        return self._answer(DEFAULT_LINES, DEFAULT_MAX_CHARS, warning=False)

    # ------------------------------------------------------------------ starting a run

    def _validate(self, command: str) -> None:
        if not command or not command.strip():
            raise SessionError("The command is empty.")
        self._check_input(command)

    def _check_input(self, text: str) -> None:
        """What is typed into the shell, a command or an answer, must fit a terminal and pass the policy."""
        problem = input_problem(text)
        if problem:
            raise SessionError(problem)
        reason = check_command(text, self.target.command_blacklist, self.target.read_only)
        if reason:
            raise CommandBlocked(reason)

    def _start_run(self, command: str, timeout: float, quiet: bool) -> Run:
        if self._closed:
            raise SessionError(f"Session {self.sid} is closed. Run without session_id to open a new one.")
        if self._run is not None:
            raise SessionBusy(
                f"Session {self.sid} is busy running: {self._run.command[:100]!r}. "
                f"Use read to follow it, signal ctrl_c to stop it, or run without session_id for a parallel shell.")
        if self._channel is None or self._fresh_shell_needed:
            self._reopen()
        self._run_counter += 1
        run = Run(self._run_counter, command, self._logs.run_log(self.alias, self.id, self._run_counter),
                  deadline=time.monotonic() + timeout if timeout > 0 else None, quiet=quiet)
        if self.mode == "cli":
            run.echo = EchoFilter(command)
        if not quiet:
            self._skipped = self.canvas.skip_unread()
            self.canvas.start_new_line()
            self.canvas.append(("$ " if self.mode == "shell" else "> ") + command_title(command) + "\n")
        run.log.event("started", command=command)
        self._run = run
        typed = wrap_posix(command, run.id) if self.mode == "shell" else command.rstrip("\n") + "\n"
        run.expected_more = typed.count("\n") - 1
        self._send(typed)
        return run

    def _send(self, text: str) -> None:
        channel = self._channel
        if channel is None:
            raise SessionError(f"Session {self.sid} has no connection. Run a command to reconnect.")
        try:
            channel.sendall(text.encode("utf-8"))
        except (OSError, EOFError) as exc:
            cause = str(exc) or type(exc).__name__  # EOFError() has no text at all
            self._on_disconnect(channel, f"could not send to the host: {cause}")
            raise SessionError(f"Sending to {self.alias} failed: {cause}. Run a command to reconnect.") from exc

    # ------------------------------------------------------------------ waiting and answering

    def _wait_settled(self, run: Run, wait: float) -> None:
        """Until the run finished or asks for input, or ``wait`` seconds passed.

        A run that is being interrupted has no use for a question: only its end counts."""
        self.canvas.wait_until(
            lambda: run.finished or (run.status == "waiting_input" and run.interrupt_reason is None), wait)

    def _answer(self, lines: int, max_chars: int, warning: bool) -> Dict[str, Any]:
        return self._render(self.canvas.read_unread(lines, max_chars), warning)

    def _render(self, window: Any, warning: bool) -> Dict[str, Any]:
        with self._lock:
            run = self._run or self._last
            status = run.status if run else "idle"
            answer: Dict[str, Any] = {"session_id": self.sid, "status": status, "output": window.text}
            if run is not None and run.finished and run.exit_code is not None and status == "completed":
                answer["exit_code"] = run.exit_code
            if window.has_more:
                answer["has_more"] = window.has_more
            if window.dropped:
                answer["dropped_data"] = True
            if run is not None and run.stopped is not None:
                answer["process_stopped"] = run.stopped
            hint = self._hint(run, status)
            if hint:
                answer["hint"] = hint
            skipped = window.skipped + (self._skipped if warning else 0)
            if warning:
                self._skipped = 0
            if skipped:
                answer["skipped_lines"] = skipped
            if warning and self._warning:
                answer["warning"], self._warning = self._warning, ""
            return answer

    def _hint(self, run: Optional[Run], status: str) -> str:
        if status == "running":
            unfinished = self._unfinished_line(run)
            if looks_like_shell_prompt(unfinished):
                return (f"Still running: {unfinished!r} is the prompt of a shell started inside this session "
                        "(sudo -s, su, bash). The gateway cannot tell where a command ends in it. Leave it with "
                        "signal action=stdin text=exit, then run one command at a time (sudo <command>).")
            if unfinished:
                return (f"Still running, and silent after an unfinished line: {unfinished!r}. If it is a question, "
                        f"answer with signal action=stdin text=...; otherwise call read(session_id='{self.sid}') "
                        "again, or stop it with signal ctrl_c.")
            return f"Still running. Call read(session_id='{self.sid}') again, or stop it with signal ctrl_c."
        if status == "waiting_input":
            if run is not None and run.wants_more:
                return ("The shell is waiting for the rest of the command (an unclosed quote, heredoc "
                        "or bracket). Send signal ctrl_c, then run a corrected command.")
            return ("The program waits for input. Answer with signal action=stdin text=..., "
                    "or stop it with signal ctrl_c.")
        if status == "failed" and run is not None:
            return f"{run.error}. Run a command to reconnect (the shell state will be reset)."
        if run is not None and run.stopped is False:
            return ("Ctrl+C did not stop the command. The next command opens a fresh shell "
                    "(state is lost); use session_close to drop this session.")
        return ""

    def _unfinished_line(self, run: Optional[Run]) -> str:
        """What the program left open at the end of its output, once it has been silent for a while.

        Not every question can be recognised, so the agent is shown the line and decides."""
        if run is None or time.monotonic() - run.last_data < self._timing.settle_input:
            return ""
        line = ANSI_ESCAPE.sub("", run.tail.rsplit("\n", 1)[-1]).strip()
        return line[-UNFINISHED_LINE_CHARS:]

    # ------------------------------------------------------------------ the reader

    def _read_loop(self, channel: Any) -> None:
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        reason = "connection closed by the host"
        while True:
            try:
                data = channel.recv(RECV_SIZE)
            except TimeoutError:
                data = None
            except Exception as exc:  # the transport died
                reason = f"connection lost: {exc}"
                break
            if data is not None and not data:
                break
            with self._lock:
                if channel is not self._channel:
                    return
                if data:
                    self._ingest(self._cleaner.feed(decoder.decode(data)))
                self._tick()
        self._on_disconnect(channel, reason)

    def _ingest_boot(self, text: str) -> None:
        if self._markers is not None:
            text = self._markers.feed(text)
            self._boot_events.extend(self._markers.take_events())
        self._boot_text += text
        self._boot_last_data = time.monotonic()
        self._boot_changed.notify_all()

    def _ingest_shell(self, text: str) -> None:
        markers = self._markers
        assert markers is not None, "a shell session filters its output through the marker filter"
        text = markers.feed(text)
        events = markers.take_events()
        run = self._run
        if run is None:
            self.canvas.append(text)  # a background job talking while nobody waits
            return
        if text or events:
            run.last_data = time.monotonic()
        self._emit(run, text)
        for event in events:
            if run.finished:
                break
            if event is None:
                run.more_seen += 1
                run.wants_more = run.more_seen > run.expected_more
            elif event.run == run.id:
                run.wants_more = False
                self._finish(run, event.code)
            # else: a prompt of the previous command, shown again while the shell is still reading a long line

    def _ingest_cli(self, text: str) -> None:
        run = self._run
        if run is None:
            if not self._prompts.at_tail(text):
                self.canvas.append(text)
            return
        text, paged = split_pager_prompt(text)
        if paged:
            self._send(" ")
        run.last_data = time.monotonic()
        run.tail = (run.tail + text)[-TAIL_CHARS:]
        assert run.echo is not None, "a router CLI run strips the echo of its command"
        self._emit(run, run.echo.feed(text), track=False)

    def _emit(self, run: Run, text: str, track: bool = True) -> None:
        if not text:
            return
        lines = text.replace("\r", "\n")  # only the canvas rewrites a line; for the rest an update is a line
        if track:
            run.tail = (run.tail + lines)[-TAIL_CHARS:]
        if run.status == "waiting_input":
            run.status = "running"
            run.wants_more = False
        run.log.output(lines)
        if run.quiet:
            run.captured.append(lines)
        else:
            self.canvas.append(text)

    def _tick(self) -> None:
        """Time-driven decisions, made on every chunk and every recv timeout."""
        run = self._run
        if run is None or run.finished:
            return
        now = time.monotonic()
        if run.deadline is not None and now >= run.deadline and run.interrupt_reason is None:
            self._interrupt(run, "timed_out")
        if run.interrupt_reason is not None and now - run.interrupt_at > self._timing.interrupt_grace:
            self._give_up(run)
            return
        quiet_for = now - run.last_data
        if self.mode == "cli":
            prompt = self._prompts.at_tail(run.tail)
            if prompt and quiet_for >= self._timing.settle_prompt:
                self._finish_cli(run, prompt)
                return
        if run.status == "running" and quiet_for >= self._timing.settle_input:
            question = run.tail.rsplit("\n", 1)[-1]
            if run.wants_more or looks_interactive(question):
                self._ask_for_input(run)

    def _ask_for_input(self, run: Run) -> None:
        if run.echo is not None:
            self._emit(run, run.echo.flush(), track=False)  # the question sits in the filter's buffer
        run.status = "waiting_input"
        self.canvas.wake()

    # ------------------------------------------------------------------ finishing

    def _finish(self, run: Run, exit_code: int) -> None:
        """The shell is ready again."""
        run.exit_code = exit_code
        if run.interrupt_reason:
            run.stopped = True
        self._settle(run, run.interrupt_reason or "completed")

    def _finish_cli(self, run: Run, prompt: str) -> None:
        assert run.echo is not None, "a router CLI run strips the echo of its command"
        rest = run.echo.flush()
        if rest.endswith(prompt):
            rest = rest[: -len(prompt)]
        elif not run.quiet:
            self.canvas.trim_tail_if_unread(prompt)
        self._emit(run, rest, track=False)
        if run.interrupt_reason:
            run.stopped = True
        self._settle(run, run.interrupt_reason or "completed")

    def _give_up(self, run: Run) -> None:
        """Ctrl+C had no effect: the boundary of the command on the terminal is unknown."""
        run.stopped = False
        self._fresh_shell_needed = True
        self._settle(run, run.interrupt_reason or "interrupted")

    def _settle(self, run: Run, status: str, error: str = "") -> None:
        run.status = status
        run.error = error
        if self._run is run:
            self._run = None
        self._last = run
        if not run.quiet:
            self.canvas.start_new_line()
        run.log.event("finished", status=status, exit_code=run.exit_code,
                      seconds=round(time.monotonic() - run.started, 3))
        self.canvas.wake()

    def _interrupt(self, run: Run, reason: str) -> None:
        run.interrupt_reason = reason
        run.interrupt_at = time.monotonic()
        try:
            self._send("\x03")
        except SessionError:
            pass  # _send already ended the run

    def _on_disconnect(self, channel: Any, reason: str) -> None:
        with self._lock:
            if channel is not self._channel:
                return
            self._channel = None
            tail = self._cleaner.finalize()
            if self._markers is not None:
                tail += self._markers.finish()
            self.canvas.append(tail)
            run = self._run
            if run is not None and not run.finished:
                self._settle(run, "failed", error=f"Connection to {self.alias} lost ({reason})")
            else:
                self.canvas.start_new_line()
            self._boot_changed.notify_all()
        _close_quietly(channel)
        self._log.event("disconnected", reason=reason)
        self.canvas.wake()

    # ------------------------------------------------------------------ opening the shell

    def _reopen(self) -> None:
        """A fresh channel after a loss or an unconfirmed Ctrl+C. The old shell is gone."""
        old, self._channel = self._channel, None
        _close_quietly(old)
        self._fresh_shell_needed = False
        self._open_channel()
        self._warning = STATE_LOST
        self._log.event("reopened")

    def _open_channel(self) -> None:
        channel = self._connection.open_channel()
        channel.settimeout(0.25)
        self._channel = channel
        self._cleaner = StreamCleaner()
        self._markers = None
        self._ingest = self._ingest_boot
        self._boot_text, self._boot_events = "", []
        self._boot_last_data = time.monotonic()
        threading.Thread(target=self._read_loop, args=(channel,), daemon=True,
                         name=f"reader-{self.sid}").start()
        try:
            self._negotiate()
        except Exception:
            self._channel = None
            _close_quietly(channel)
            raise
        self._log.event("connected", mode=self.mode)

    def _negotiate(self) -> None:
        """Find out whether this is a POSIX shell or a router CLI, and settle into a mode."""
        if self.target.shell:  # the account's login shell (fish, tcsh) is replaced before the setup line
            self._send_raw(f"exec {self.target.shell}\n")
            time.sleep(0.2)
        if self._silence_shell("setup"):
            natural = "shell"
        else:
            self._prompts.learn(self._boot_text)
            if not self._prompts.known:
                raise SessionError(
                    f"Could not recognise the shell on {self.alias}: no prompt came back. "
                    f"Received: {self._boot_text[-200:]!r}")
            natural = "cli"
        if natural == "shell":
            if self._want_shell is False:
                raise SessionError(f"{self.alias} has no router CLI; omit 'shell' or use shell=true.")
            self._enter_shell_mode()
        elif self._want_shell:
            self._enter_linux_from_cli()
        else:
            self._enter_cli_mode()

    def _silence_shell(self, phase: str) -> bool:
        """Send the quiet-mode line. True once the shell answers with its prompt marker."""
        token = secrets.token_hex(8)
        self._markers = MarkerFilter(token)
        self._boot_events = []
        self._send_raw(posix_setup(token, self.target.extra_path or DEFAULT_PATH))
        return self._wait_boot(self._marker_or_silence)

    def _marker_or_silence(self) -> bool:
        if any(event is not None for event in self._boot_events):
            return True
        foreign = foreign_shell(self._boot_text)
        if foreign:
            raise SessionError(self._foreign_shell_message(foreign))
        quiet = time.monotonic() - self._boot_last_data >= self._timing.boot_silence
        return quiet and bool(self._boot_text.strip()) and self._looks_like_cli_prompt()

    def _foreign_shell_message(self, name: str) -> str:
        if self.target.shell:
            return (f"'exec {self.target.shell}' did not replace the login shell of {self.alias} ({name}). "
                    f"Check that it exists on the host and give its full path in \"shell\".")
        return (f"The login shell of {self.alias} is {name}, which does not understand the POSIX setup line. "
                f"Add \"shell\": \"bash\" to this server in servers.json (the gateway then runs 'exec bash' "
                f"after login), or give the account a bash or sh login shell.")

    def _looks_like_cli_prompt(self) -> bool:
        probe = PromptDetector()
        probe.learn(self._boot_text)
        return probe.known

    def _wait_boot(self, predicate: Callable[[], bool]) -> bool:
        """Wait (the lock is released while waiting) for the login exchange; returns whether a marker came."""
        deadline = time.monotonic() + self._timing.boot_timeout
        while not predicate():
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._channel is None:
                raise SessionError(
                    f"Timed out waiting for the shell on {self.alias}. Received: {self._boot_text[-200:]!r}")
            self._boot_changed.wait(min(0.1, remaining))
        return any(event is not None for event in self._boot_events)

    def _enter_shell_mode(self) -> None:
        if not self._is_quiet():
            self._send_raw("exec sh\n")
            time.sleep(0.2)
            if not (self._silence_shell("setup") and self._is_quiet()):
                raise SessionError(
                    f"Could not put the shell on {self.alias} into quiet mode (it keeps echoing input). "
                    "Use a bash or sh login shell for this account.")
        self.mode = "shell"
        self._ingest = self._ingest_shell
        self._cleaner.keep_cr = True  # progress bars rewrite their line on the canvas
        self._boot_text = ""
        self._log.event("mode", mode="shell")

    def _is_quiet(self) -> bool:
        """A no-op command must produce the prompt marker and nothing else."""
        self._boot_text, self._boot_events = "", []
        self._send_raw(":\n")
        self._wait_boot(lambda: any(e is not None for e in self._boot_events))
        return not self._boot_text.strip()

    def _enter_cli_mode(self) -> None:
        self.mode = "cli"
        self._markers = None
        self._ingest = self._ingest_cli
        self._log.event("mode", mode="cli")

    def _enter_linux_from_cli(self) -> None:
        """The device logs in to a router CLI; the agent asked for its Linux shell."""
        self._ingest = self._ingest_boot
        for entry_command in ("shell", "exec sh"):
            self._boot_text, self._boot_events = "", []
            self._send_raw(entry_command + "\n")
            time.sleep(0.3)
            try:
                if self._silence_shell("setup"):
                    self._enter_shell_mode()
                    return
            except SessionError:
                continue
        raise SessionError(
            f"Could not open the Linux shell on {self.alias}. The router CLI is available with shell=false.")

    def _send_raw(self, text: str) -> None:
        self._channel.sendall(text.encode("utf-8"))


def _close_quietly(channel: Any) -> None:
    try:
        if channel is not None:
            channel.close()
    except Exception:
        pass
