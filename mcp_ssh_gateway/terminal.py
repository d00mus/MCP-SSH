"""The terminal protocol spoken over the PTY.

POSIX shells are switched into a quiet mode (no echo, no prompt) and every command
is followed by an exit-code marker line, so output is exactly what the command
printed and completion is certain. Router CLIs (NDM) cannot be scripted that way:
their echo is removed by ``EchoFilter`` and completion is a returned prompt,
recognised by ``PromptDetector``.
"""

import re
import shlex
from typing import List, NamedTuple, Optional, Tuple

MARKER_PREFIX = "__MCP_EC_"
CONTINUATION_PREFIX = "__MCP_MORE_"
MARKER_END = "]"
# The shell variable that names the command in progress; the prompt prints it (see ``posix_setup``).
RUN_VARIABLE = "__mcp_n"

# A terminal accepts at most 4095 characters per typed line; longer input is cut.
MAX_TYPED_LINE = 4000
# Typing more than this at once only ends in a hung or dropped session: a script of that size belongs in a file.
MAX_TYPED_CHARS = 256 * 1024


# ---------------------------------------------------------------------------
# POSIX shell: quiet mode and the prompt marker
# ---------------------------------------------------------------------------

def posix_setup(token: str, extra_path: str = "") -> str:
    """One line that turns an interactive shell into a quiet, machine-readable one.

    - ``stty -echo``: the tty stops echoing what we type;
    - PS1 becomes ``__MCP_EC_<token>_<exit code>_<run>]``: the shell prints it exactly when
      it is ready for the next command, so completion is certain, an exit code comes with
      it, and it works for syntax errors, background jobs and Ctrl+C alike. (A command
      substitution drops trailing newlines, hence the closing bracket.) ``<run>`` is the
      number ``wrap_posix`` gave to the command the shell started last. BusyBox ash shows
      its prompt a second time while it is still reading a line longer than its line
      buffer (512 characters on a Keenetic); that prompt still carries the number of the
      previous command, so it is told from the end of the command in progress.
    - PS2 becomes ``__MCP_MORE_<token>]``: printed when the shell waits for the rest of
      a command (an unclosed quote, a heredoc);
    - readline, history expansion and zle are switched off;
    - the pagers of git, systemd, man and the rest are ``cat``: the terminal is real, so
      they would stop at "(END)" and wait for a key nobody can see;
    - ``extra_path`` (if any) is put in front of PATH.

    Every step is optional: dash has no readline, bash has no zle."""
    ps1 = f'$(printf "{MARKER_PREFIX}{token}_%s_%s" $? ${{{RUN_VARIABLE}:-0}}){MARKER_END}'
    ps2 = f"{CONTINUATION_PREFIX}{token}{MARKER_END}"
    path = f"export PATH={shlex.quote(extra_path)}:$PATH; " if extra_path else ""
    return (
        f"{path}export PAGER=cat GIT_PAGER=cat SYSTEMD_PAGER=cat MANPAGER=cat; "
        f"stty -echo 2>/dev/null; PS1='{ps1}'; PS2='{ps2}'; PS0=''; unset PROMPT_COMMAND; "
        "set +o emacs 2>/dev/null; set +o vi 2>/dev/null; set +H 2>/dev/null; "
        "setopt promptsubst 2>/dev/null; unsetopt zle 2>/dev/null\n"
    )


def wrap_posix(command: str, run: int) -> str:
    """The command as typed into the shell, numbered ``run`` (the prompt reports the number).

    A single line is typed as it is, after the assignment that numbers it. Several lines
    become one ``{ }`` group: the shell parses the whole group before running it, so it
    prompts (and the marker appears) once, after the last line, and nothing is left in the
    input for the command to swallow. The closing brace has its own line, so a trailing
    comment cannot eat it."""
    body = command.strip("\n")
    numbered = f"{RUN_VARIABLE}={run}"
    if "\n" not in body:
        return f"{numbered}; {body}\n"
    return "{ " + numbered + "\n" + body + "\n}\n"


# What a login shell that is not POSIX says to the setup line: (name, a line only it prints).
_FOREIGN_SHELLS = (
    ("fish", re.compile(r"^fish: ", re.MULTILINE)),
    ("csh or tcsh", re.compile(r"^export: Command not found\.", re.MULTILINE)),
)


def foreign_shell(text: str) -> Optional[str]:
    """The name of a login shell that cannot take the POSIX setup line, told from what it answered."""
    for name, sign in _FOREIGN_SHELLS:
        if sign.search(text):
            return name
    return None


def input_problem(text: str) -> Optional[str]:
    """A message if the text cannot be typed into a terminal: there is too much of it, or a line is too long."""
    advice = "Write the text to a file with the file tool (action=write) and use the file instead."
    if len(text) > MAX_TYPED_CHARS:
        return (f"The input is {len(text)} characters, more than the {MAX_TYPED_CHARS} "
                f"a terminal can be given at once. {advice}")
    if any(len(line) > MAX_TYPED_LINE for line in text.split("\n")):
        return (f"A line of the input is longer than {MAX_TYPED_LINE} characters, "
                f"which a terminal cannot take. {advice}")
    return None


class PromptEvent(NamedTuple):
    """What the ready prompt of the shell says."""
    code: int  # the exit code of the last command
    run: int   # the number of the command the shell started last (0: none yet)


class MarkerFilter:
    """Cuts the shell's prompt markers out of the stream and reports what they said.

    Every marker is one event: a ``PromptEvent`` (the shell is ready again) or ``None`` (the
    shell waits for the rest of a command). A marker may be glued to unterminated
    output (``printf hello``) or split across chunks, so the tail of a chunk that could
    still become a marker is held back."""

    def __init__(self, token: str) -> None:
        self._ec = f"{MARKER_PREFIX}{token}_"
        self._more = f"{CONTINUATION_PREFIX}{token}{MARKER_END}"
        self._pattern = re.compile(
            rf"{re.escape(self._ec)}(\d+)_(\d+){re.escape(MARKER_END)}|{re.escape(self._more)}"
        )
        self._partial = re.compile(rf"{re.escape(self._ec)}\d*(?:_\d*)?")
        self._held = ""
        self._events: List[Optional[PromptEvent]] = []

    def take_events(self) -> List[Optional[PromptEvent]]:
        """Markers seen since the last call, oldest first: a prompt, or None for "more input"."""
        events, self._events = self._events, []
        return events

    def feed(self, text: str) -> str:
        data = self._held + text
        self._held = ""
        out: List[str] = []
        pos = 0
        for match in self._pattern.finditer(data):
            out.append(data[pos:match.start()])
            code = match.group(1)
            self._events.append(PromptEvent(int(code), int(match.group(2))) if code is not None else None)
            pos = match.end()
        rest = data[pos:]
        keep = self._partial_marker_length(rest)
        if keep:
            self._held = rest[-keep:]
            rest = rest[:-keep]
        out.append(rest)
        return "".join(out)

    def finish(self) -> str:
        """The stream ended: give back whatever was held."""
        held, self._held = self._held, ""
        return held

    def _partial_marker_length(self, text: str) -> int:
        for size in range(min(len(self._ec) + 12, len(text)), 0, -1):
            tail = text[-size:]
            if (self._more.startswith(tail) or self._ec.startswith(tail)
                    or self._partial.fullmatch(tail)):
                return size
        return 0


# ---------------------------------------------------------------------------
# Router CLI: echo removal and prompt detection
# ---------------------------------------------------------------------------

# A line that is only a prompt: "$ ", "/srv$", "user@host:~# ", "[root@h ~]#", "(config)>", ">".
_PROMPT_ONLY_LINE = re.compile(
    r"^[ \t]*(?:"
    r"\([^)\n]{0,40}\)[ \t]*[>#$]?"
    r"|[>#$]"
    r"|\[[^\]\n]{0,60}\][ \t]*[>#$]"
    r"|[A-Za-z0-9._-]{1,32}@[A-Za-z0-9._-]{1,64}:[^\s]*[ \t]*[>#$]"
    r"|[\w.@:/~-]{0,64}[>#$]"
    r")[ \t]*$"
)
# What may stand in front of an echoed command on the same line: a prompt and nothing else.
_PROMPT_PREFIX = re.compile(
    r"^(?:\([^)\n]{0,40}\)|\[[^\]\n]{0,60}\]|[\w.@:/~-]{0,64})[ \t]*[>#$][ \t]*$"
)


class EchoFilter:
    """Drops the device's own echo of the command that was typed.

    The answer already starts with the gateway's ``> <command>`` line, so a second
    copy from the device would be noise. Only the start of a run is examined: a device
    echoes before it executes. The filter disarms at the first line it does not
    recognise, so output that later repeats the command text is left alone.

    A line counts as the echo when it is the command verbatim, or the command behind
    a prompt. Blank and prompt-only lines do not disarm it. A terminal wraps a long
    echo in the middle of the command, so lines that are still a prefix of the
    command are held until they complete it, and released in place if they never do."""

    def __init__(self, command: str) -> None:
        self._candidates: List[str] = []
        for line in (command or "").split("\n"):
            stripped = line.strip()
            if stripped and stripped not in self._candidates:
                self._candidates.append(stripped)
        # Bounds the damage of a pathological match: one per command line, plus two.
        self._budget = len(self._candidates) + 2
        self._armed = bool(self._candidates)
        self._pending = ""
        self._swallow_blank = False
        self._hold: List[str] = []
        self._hold_text = ""

    def feed(self, chunk: str) -> str:
        """The part of ``chunk`` that belongs in the canvas."""
        if not chunk:
            return chunk
        if not self._armed:
            held = self._release_hold()
            pending, self._pending = self._pending, ""
            return held + pending + chunk
        text = self._pending + chunk
        self._pending = ""
        if text.endswith("\n"):
            lines = text[:-1].split("\n")
        else:
            lines = text.split("\n")
            self._pending = lines.pop()
        kept: List[str] = []
        for line in lines:
            if self._hold:
                verdict = self._classify(self._hold_text + line)
                if verdict == "full":
                    self._drop_echo()
                    continue
                if verdict == "partial":
                    self._hold.append(line)
                    self._hold_text += line.strip()
                    continue
                kept.extend(self._hold)  # the echo never completed: it was output
                self._hold = []
                self._hold_text = ""
            if self._swallow_blank:
                self._swallow_blank = False
                if not line.strip():
                    continue  # the blank line that trails an echo belongs to the echo
            if self._armed and self._budget > 0:
                verdict = self._classify(line)
                if verdict == "full":
                    self._drop_echo()
                    continue
                if verdict == "partial":
                    self._hold = [line]
                    self._hold_text = line.strip()
                    continue
            if line.strip() and not _PROMPT_ONLY_LINE.match(line):
                self._armed = False
            kept.append(line)
        return "\n".join(kept) + "\n" if kept else ""

    def flush(self) -> str:
        """The run is over: release what is still held and stop filtering."""
        held = self._release_hold()
        pending, self._pending = self._pending, ""
        self._armed = False
        self._swallow_blank = False
        return held + pending

    def _classify(self, text: str) -> Optional[str]:
        """"full" if the text is the echo, "partial" if it could still grow into it."""
        stripped = text.strip()
        if not stripped:
            return None
        for candidate in self._candidates:
            if stripped == candidate:
                return "full"
            if stripped.endswith(candidate) and _PROMPT_PREFIX.match(stripped[: -len(candidate)]):
                return "full"
            if candidate.startswith(stripped):
                return "partial"
        return None

    def _drop_echo(self) -> None:
        self._hold = []
        self._hold_text = ""
        self._budget -= 1
        self._swallow_blank = True
        if self._budget <= 0:
            self._armed = False

    def _release_hold(self) -> str:
        if not self._hold:
            return ""
        held, self._hold = self._hold, []
        self._hold_text = ""
        return "\n".join(held) + "\n"


class PromptDetector:
    """Recognises the prompt of one router CLI, learned from its login banner.

    Only prompts of the device we learned are accepted: ``Keenetic-Giga>``,
    ``Keenetic-Giga(config)>`` and the hostname-less ``(config)>``. Any other line that
    merely ends in ``>`` is output."""

    _LEARN = re.compile(r"^([A-Za-z0-9._-]*)(?:\([^)\n]*\))?([>#$])[ \t]*$")

    def __init__(self) -> None:
        self._pattern: Optional[re.Pattern[str]] = None

    @property
    def known(self) -> bool:
        return self._pattern is not None

    def learn(self, text: str) -> None:
        line = _last_line(text)
        match = self._LEARN.match(line)
        if not match or (not match.group(1) and "(" not in line):
            return
        name, sign = re.escape(match.group(1)), re.escape(match.group(2))
        mode = r"\([^)\n]*\)"
        # In configuration mode the device drops its name: "(config)>".
        head = rf"(?:{name}(?:{mode})?|{mode})" if name else mode
        # A prompt may be printed twice in a row (after Ctrl+C the router redraws it).
        self._pattern = re.compile(rf"^(?:{head}{sign}[ \t]*)+$")

    def at_tail(self, text: str) -> Optional[str]:
        """The prompt text if ``text`` ends with one, else None."""
        if self._pattern is None:
            return None
        tail = text.rsplit("\n", 1)[-1]
        return tail if self._pattern.match(tail) else None


def _last_line(text: str) -> str:
    return text.rstrip("\r\n").rsplit("\n", 1)[-1].strip("\r")


# ---------------------------------------------------------------------------
# Interactive questions and pagers
# ---------------------------------------------------------------------------

_INTERACTIVE = [re.compile(p, re.IGNORECASE) for p in (
    r"(?:password|passphrase|secret|token)[^\n]{0,60}:\s*$",
    r"\[(?:y/n|yes/no)\]\??\s*$",
    r"\((?:y/n|yes/no)\)\??\s*$",
    r"continue\??\s*(?:\[[^\]\n]*\])?\s*$",
    r"\b(?:username|login):\s*$",
    r"\?\s*$",  # "overwrite 'x'? ", "Proceed? "
    r"\(END\)\s*$",  # a pager that ran anyway
)]
_PAGER_AT_END = re.compile(
    r"[ \t]*(?:--\s*More\s*--|Press any key to continue|Press Enter to continue)[ \t]*$"
)


def looks_interactive(line: str) -> bool:
    """Does this unfinished line look like a question waiting for typed input?"""
    return bool(line) and any(p.search(line) for p in _INTERACTIVE)


# One word (or two, "/ #") that ends with the sign of a shell. A row of "####" is a progress bar.
_SHELL_PROMPT = re.compile(r"(?:\S{0,63}[^\s#$] ?)?[#$]")


def looks_like_shell_prompt(line: str) -> bool:
    """Does this unfinished line look like the prompt of a shell: "root@host:~#", "bash-5.1$", "/ #"?"""
    return _SHELL_PROMPT.fullmatch(line.strip()) is not None


def split_pager_prompt(text: str) -> Tuple[str, bool]:
    """Cut a pager prompt ("--More--") off the end of the text: (text, was_there)."""
    match = _PAGER_AT_END.search(text)
    return (text[:match.start()], True) if match else (text, False)
