"""Agent-facing output contract tests - TDD red phase.

Companion to D:\\dev\\infra\\common\\ssh-gateway-output-review.md. These tests were
written BEFORE the fixes and are expected to FAIL on the current code, each for the
documented reason:

  Wave 1 (FIX-1)  TestMarkerProtocol ....... the PTY exit marker must be recognised in
                  the byte streams a real interactive shell produces (a prompt before
                  the marker, or output that does not end with a newline).
  Wave 2 (FIX-2)  TestFraming.......... nothing internal reaches the agent and has_more
                  counts only lines the agent can actually receive.
  Wave 2 (FIX-3)  TestCommandEcho...... the PTY answer carries the command exactly once.
                  The non-PTY exec channel does not echo at all, so the gateway must
                  not print a synthetic "$ command" line there (README.md:237).
  Wave 3 (FIX-4)  TestVirtualLineWindows windows end on 1024-char virtual-line
                  boundaries, reassembly is lossless, and the rule is documented.

TestCursorGuardRails sits at the bottom and must stay GREEN through every fix: the
single unread cursor is the one thing that must never break.
"""

import json
import os
import re
import shutil
import tempfile
import time
import unittest
from unittest.mock import MagicMock

from src.config import config
from src.session import SSHSession, set_buffer_limit_checkers
from src.ssh_state import count_virtual_lines
from src.utils import CommandEchoFilter, make_cache_dirs, parse_exit_marker, strip_internal_framing
from src import server as server_mod

MARKER_TOKEN = "c5b472bf1f93d509"


class _OutputContractBase(unittest.TestCase):
    """Shared fixture: a mock SSH session, exactly like the rest of the suite."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.cache_dirs = make_cache_dirs(self.test_dir)
        config.PROJECT_ROOT = self.test_dir
        config.PROJECT_TAG = "test_project"
        config.CACHE_DIRS = self.cache_dirs
        config.READ_ONLY = False
        config.COMMAND_BLACKLIST = []
        set_buffer_limit_checkers(lambda size: True, lambda: 0)
        self._sessions = []

    def tearDown(self):
        # Red-phase runs may be left mid-flight: stop their reader threads first.
        for session in self._sessions:
            try:
                for run in list(session.runs.values()):
                    run.done_event.set()
            except Exception:
                pass
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _session(self):
        mock_client = MagicMock()
        mock_channel = MagicMock()
        mock_client.invoke_shell.return_value = mock_channel
        mock_channel.recv_ready.return_value = False
        session = SSHSession(session_id=1, name="contract_session", cache_dirs=self.cache_dirs, project_tag="test_project")
        session.client = mock_client
        session.channel = mock_channel
        session.in_shell = True
        session.ensure_alive = MagicMock(return_value=None)
        session.check_health = MagicMock(return_value=True)
        self._sessions.append(session)
        return session, mock_channel

    def _pty_session(self, transcript_builder):
        """A mock PTY whose shell answers with one realistic byte transcript.

        transcript_builder receives the raw payload the gateway wrote to the PTY
        (so it can learn the run's marker token) and returns the bytes a real
        bash on SberCloud prints back.
        """
        session, channel = self._session()
        channel.closed = False
        channel.send_ready.return_value = True
        sent = {"payload": b"", "served": False}

        def send(data):
            raw = data if isinstance(data, (bytes, bytearray)) else str(data).encode()
            sent["payload"] += bytes(raw)
            return len(raw)

        def recv_ready():
            return (not sent["served"]) and len(sent["payload"]) > 0

        def recv(_n):
            if sent["served"]:
                return b""
            sent["served"] = True
            return transcript_builder(sent["payload"].decode("utf-8", "replace"))

        channel.send.side_effect = send
        channel.recv_ready.side_effect = recv_ready
        channel.recv.side_effect = recv
        return session, channel

    def _run(self, session, command, **kwargs):
        args = dict(mode="sync", shell=True, wait_timeout=1.5, startup_wait=0.05,
                    hard_timeout=0.0, completion_hint="either", quiet_complete_timeout=0.25)
        args.update(kwargs)
        return session.run_command(command=command, **args)

    @staticmethod
    def _token_of(payload):
        match = re.search(r"__MCP_EC_([0-9a-f]+)_", payload)
        assert match is not None, "the gateway never wrote a marker: " + payload
        return match.group(1)


class TestMarkerProtocol(_OutputContractBase):
    """FIX-1: recognise the marker in real PTY byte streams."""

    def test_marker_after_a_printed_prompt_is_parsed(self):
        # SberCloud/bash: the interactive shell reads the marker line as its own
        # command, prints PS1 first, and only then runs the printf.
        text = "echo one\r\necho two\r\none\r\n$ two\r\n$ __MCP_EC_" + MARKER_TOKEN + "_0\r\n$ "
        self.assertEqual(parse_exit_marker(text, MARKER_TOKEN), 0)

    def test_marker_glued_to_unterminated_output_is_parsed(self):
        # printf 'abc' leaves no trailing newline, so the marker is glued to it.
        text = "abc__MCP_EC_" + MARKER_TOKEN + "_0\r\n$ "
        self.assertEqual(parse_exit_marker(text, MARKER_TOKEN), 0)

    def test_a_foreign_marker_is_still_not_parsed(self):
        text = "$ __MCP_EC_" + MARKER_TOKEN + "_0\r\n"
        self.assertIsNone(parse_exit_marker(text, "aaaaaaaaaaaaaaaa"))

    def test_multiline_command_completes_when_the_shell_prints_the_prompt(self):
        def transcript(payload):
            token = self._token_of(payload)
            return ("echo one\r\necho two\r\none\r\ntwo\r\n"
                    + "$ __MCP_EC_" + token + "_0\r\n$ ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "echo one\necho two")
        self.assertEqual(res["status"], "completed", res.get("hint"))
        self.assertEqual(res["exit_status"], 0)
        self.assertFalse(res["still_running"])

    def test_command_with_a_hash_completes(self):
        def transcript(payload):
            token = self._token_of(payload)
            return ("echo hi # comment\r\nhi\r\n"
                    + "$ __MCP_EC_" + token + "_0\r\n$ ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "echo hi # comment")
        self.assertEqual(res["status"], "completed", res.get("hint"))
        self.assertEqual(res["exit_status"], 0)

    def test_unterminated_output_completes(self):
        def transcript(payload):
            token = self._token_of(payload)
            return ("abc__MCP_EC_" + token + "_0\r\n$ ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "printf abc")
        self.assertEqual(res["status"], "completed", res.get("hint"))
        self.assertEqual(res["exit_status"], 0)

    def test_a_seen_marker_never_leaves_the_session_busy_forever(self):
        # Belt and braces for FIX-1: even if the parser cannot read the marker, a run
        # whose marker line is already on screen must not stay busy indefinitely.
        def transcript(payload):
            token = self._token_of(payload)
            return ("$ __MCP_EC_" + token + "_7\r\n$ ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "true", wait_timeout=2.0)
        self.assertFalse(res["still_running"], "a marker on screen must end the run")
        self.assertEqual(res["exit_status"], 7)


class TestFraming(_OutputContractBase):
    """FIX-2: what the agent sees carries no internal framing and no prompt noise."""

    def _read_all(self, session):
        res = session.read_canvas(line_limit=200, wait_timeout=0.0)
        return res["output"]

    def test_no_marker_no_wrapper_no_prompt_reaches_the_agent(self):
        session, _ = self._session()
        raw = ("echo control-ok; printf '%s\\n' \"__MCP_EC_" + MARKER_TOKEN + "_$?\"\n"
               "control-ok\n"
               "__MCP_EC_" + MARKER_TOKEN + "_0\n"
               "$ ")
        session.append_scrollback(raw)
        out = self._read_all(session)
        self.assertNotIn("__MCP_EC_", out)
        self.assertNotIn("printf '%s", out)
        self.assertFalse([line for line in out.split("\n") if line.strip() == "$"],
                         "a bare shell prompt is framing, not output: " + repr(out))
        self.assertEqual(out, "control-ok\n")

    def test_the_doubled_prompt_of_an_unparsed_marker_is_cleaned(self):
        session, _ = self._session()
        raw = ("echo one\necho two\none\n$ two\n$ __MCP_EC_" + MARKER_TOKEN + "_0\n$ ")
        session.append_scrollback(raw)
        out = self._read_all(session)
        self.assertNotIn("__MCP_EC_", out)
        self.assertNotIn("$ \n$ ", out, "the doubled prompt is the fingerprint of an unparsed marker")
        self.assertIn("one", out)
        self.assertIn("two", out)

    def test_a_prompt_carrying_a_terminal_escape_is_still_dropped(self):
        # A PTY wraps what it prints in DECSET escapes and a raw append (a mirrored
        # run buffer) can carry one into the canvas: escapes are stripped before a
        # line is judged, so an escaped prompt is still framing, not output.
        self.assertEqual(strip_internal_framing("one\ntwo\n\x1b[?2004hroot@19tgk78r:~# "),
                         "one\ntwo\n")

    def test_has_more_never_counts_internal_marker_lines(self):
        session, _ = self._session()
        session.append_scrollback("a\nb\nc\n__MCP_EC_" + MARKER_TOKEN + "_0\n")
        first = session.read_canvas(line_limit=3, wait_timeout=0.0)
        self.assertEqual(first["output"], "a\nb\nc\n")
        self.assertEqual(first["has_more"], 0,
                         "the only unread line is internal framing: the agent has nothing left")

    def test_has_more_matches_what_the_following_reads_deliver(self):
        session, _ = self._session()
        session.append_scrollback("a\nb\nc\n__MCP_EC_" + MARKER_TOKEN + "_0\n$ ")
        first = session.read_canvas(line_limit=3, wait_timeout=0.0)
        delivered = []
        for _ in range(10):
            nxt = session.read_canvas(line_limit=50, wait_timeout=0.0)
            delivered.extend(line for line in nxt["output"].split("\n") if line.strip())
            if not nxt["has_more"]:
                break
        self.assertEqual(first["has_more"], len(delivered),
                         "has_more promised %r visible lines, the reads delivered %r" % (first["has_more"], delivered))


class TestCommandEcho(_OutputContractBase):
    """FIX-3: the command is echoed exactly once, so the answer reads like a console."""

    def test_the_real_pty_transcript_leaves_no_blank_line_or_prompt(self):
        # The exact bytes the PTY of NL-vps printed for "echo one; echo two" (run log
        # keenetic_github__NL-vps__s1__r1__20260928_124843.log): the echo of the
        # wrapped command, then "\x1b[?2004l" with the lone CR bash writes when it
        # turns bracketed paste off, then the output, the marker and an escaped prompt.
        # The agent must read the console line and the output - nothing else.
        def transcript(payload):
            token = self._token_of(payload)
            return (payload.rstrip("\n") + "\r\n"
                    + "\x1b[?2004l\rone\r\ntwo\r\n__MCP_EC_" + token + "_0\r\n"
                    + "\x1b[?2004hroot@19tgk78r:~# ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "echo one; echo two")
        self.assertEqual(res["output"], "$ echo one; echo two\none\ntwo\n", repr(res["output"]))

    def test_a_held_partial_line_is_released_when_the_filter_disarms(self):
        """Regression (live NL-vps trace): a long line split across two recv chunks.

        The chunk that ended in the middle of a long line had its head held back
        as a possible echo, and the same feed disarmed the filter on the first
        output line. The early "not armed" return never released what was held, so
        the fragment surfaced only in flush() - after the prompt, at the end.
        """
        command = "seq 1 3"
        wire = "seq 1 3; printf '%s\\n' \"__MCP_EC_deadbeefdeadbeef_$?\""
        filt = CommandEchoFilter(command, wire)
        head = "y" * 85
        first = filt.feed(wire + "\n" + "1\n" + "40-" + head)
        self.assertEqual(first, "1\n", "the echo goes, the partial line is held back")
        second = filt.feed("y" * 13 + "\n2\nroot@19tgk78r:~# ")
        self.assertEqual(second, "40-" + head + "y" * 13 + "\n2\nroot@19tgk78r:~# ",
                         "a held fragment must return in its place, not at flush()")
        self.assertEqual(filt.flush(), "")

    def test_the_echo_line_takes_the_blank_line_of_the_cr_with_it(self):
        # Closing bracketed paste makes bash echo a lone CR right after the command
        # echo: the cleaner reads it as a newline, so the dropped echo line would
        # otherwise leave a blank line in front of the output (live transcript above).
        wire = "echo one; echo two; printf '%s\\n' \"__MCP_EC_" + MARKER_TOKEN + "_$?\""
        filt = CommandEchoFilter("echo one; echo two", wire)
        self.assertEqual(filt.feed(wire + "\n"), "")
        self.assertEqual(filt.feed("\none\ntwo\n"), "one\ntwo\n")

    def test_pty_answer_shows_the_command_exactly_once(self):
        def transcript(payload):
            token = self._token_of(payload)
            return ("echo control-ok\r\ncontrol-ok\r\n"
                    + "__MCP_EC_" + token + "_0\r\n$ ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "echo control-ok")
        out = res["output"]
        self.assertEqual(out.count("echo control-ok"), 1,
                         "the command must appear exactly once, got %r" % (out,))
        self.assertTrue(out.startswith("$ echo control-ok"), repr(out))
        self.assertTrue(out.rstrip("\n").endswith("control-ok"), repr(out))

    def test_multiline_answer_shows_the_command_exactly_once(self):
        def transcript(payload):
            token = self._token_of(payload)
            return ("echo one\r\necho two\r\none\r\ntwo\r\n"
                    + "$ __MCP_EC_" + token + "_0\r\n$ ").encode()
        session, _ = self._pty_session(transcript)
        res = self._run(session, "echo one\necho two")
        out = res["output"]
        self.assertEqual(out.count("echo two"), 1, "the shell's own echo duplicates the command: %r" % (out,))

    def test_a_wrapped_echo_of_a_long_command_is_still_the_echo(self):
        """Live Keenetic trace (2026-09-28): a host that echoes a line longer than the
        terminal wraps it with CR CR LF in the middle of the wire command, so the
        echo arrives as two lines. Both of them are the echo."""
        command = "echo LONGA_" + "x" * 170
        wire = command + "; printf '%s\\n' \"__MCP_EC_" + MARKER_TOKEN + "_$?\""
        cut = 216
        wrapped = wire[:cut] + "\r\r\n" + wire[cut:] + "\r\n"
        filt = CommandEchoFilter(command, wire)
        answer = filt.feed(wrapped + "LONGA_" + "x" * 170 + "\n")
        self.assertEqual(answer, "LONGA_" + "x" * 170 + "\n",
                         "the wrapped echo must leave neither the command nor the wrapper: %r" % (answer,))

    def test_a_wrapped_echo_never_reaches_the_agent_window(self):
        command = "echo LONGA_" + "x" * 170

        def transcript(payload):
            token = self._token_of(payload)
            wire = command + "; printf '%s\\n' \"__MCP_EC_" + token + "_$?\""
            cut = 216
            return (wire[:cut] + "\r\r\n" + wire[cut:] + "\r\n"
                    + "LONGA_" + "x" * 170 + "\r\n"
                    + "__MCP_EC_" + token + "_0\r\n/ # ").encode()

        session, _ = self._pty_session(transcript)
        res = self._run(session, command)
        out = res["output"]
        self.assertEqual(out.count(command), 1, "the command must appear exactly once, got %r" % (out,))
        self.assertNotIn("printf '%s\\n'", out,
                         "the gateway's own wrapper must never surface: %r" % (out,))
        self.assertNotIn("_$?", out, repr(out))

    def test_a_wrapped_echo_is_released_when_it_never_completes(self):
        """The hold must not eat output: a line that only starts like the command is
        given back, in place, before whatever follows it."""
        command = "echo one two three"
        wire = command + "; printf '%s\\n' \"__MCP_EC_" + MARKER_TOKEN + "_$?\""
        filt = CommandEchoFilter(command, wire)
        answer = filt.feed("echo one\necho four\ntail\n")
        self.assertEqual(answer, "echo one\necho four\ntail\n", repr(answer))
        self.assertEqual(filt.flush(), "")


class TestVirtualLineWindows(_OutputContractBase):
    """FIX-4: 1024-char virtual lines stay, but windows respect their boundaries."""

    def test_window_ends_on_a_virtual_line_boundary(self):
        session, _ = self._session()
        session.append_scrollback("X" * 2500 + "\n")
        first = session.read_canvas(line_limit=100, max_chars=1500, wait_timeout=0.0)
        self.assertEqual(len(first["output"]), 1024,
                         "a window may end only on a 1024-char virtual-line boundary, not at an arbitrary char")
        self.assertEqual(first["has_more"], count_virtual_lines("X" * 2500 + "\n", 1024))

    def test_a_virtual_line_is_never_split_even_for_a_tiny_max_chars(self):
        session, _ = self._session()
        session.append_scrollback("Y" * 2048 + "\n")
        first = session.read_canvas(line_limit=100, max_chars=10, wait_timeout=0.0)
        self.assertEqual(first["output"], "Y" * 1024,
                         "one whole virtual line must always be delivered - the cap is soft, progress is mandatory")

    def test_reassembly_across_windows_returns_the_original_line(self):
        session, _ = self._session()
        original = "Z" * 2500 + "\n"
        session.append_scrollback(original)
        parts = []
        for _ in range(20):
            res = session.read_canvas(line_limit=100, max_chars=1500, wait_timeout=0.0)
            parts.append(res["output"])
            if not res["has_more"]:
                break
        self.assertEqual("".join(parts), original)

    def test_the_pagination_contract_is_documented_where_the_agent_reads_it(self):
        listing = server_mod.tools_list()
        tools = listing.get("tools", []) if isinstance(listing, dict) else []
        read_desc = next((t.get("description", "") for t in tools if t.get("name") == "read"), "")
        text = read_desc + server_mod.SERVER_INSTRUCTIONS
        self.assertIn("1024", text, "the 1024-char virtual-line unit must be documented")
        self.assertRegex(text, r"(?i)concat", "the reassembly rule must be documented")


class TestCursorGuardRails(_OutputContractBase):
    """The cursor must survive every fix: exactly-once delivery, no overlap, honest peeks."""

    def _drain(self, session, line_limit=7, max_chars=100000):
        parts = []
        for _ in range(200):
            res = session.read_canvas(line_limit=line_limit, max_chars=max_chars, wait_timeout=0.0)
            parts.append(res["output"])
            if not res["has_more"]:
                break
        return parts

    def test_drain_delivers_the_stream_exactly_once(self):
        session, _ = self._session()
        text = "".join("row-%03d\n" % i for i in range(50))
        session.append_scrollback(text)
        self.assertEqual("".join(self._drain(session)), text)
        self.assertEqual(session.read_canvas(line_limit=10, wait_timeout=0.0)["output"], "")

    def test_peek_does_not_move_the_cursor(self):
        session, _ = self._session()
        text = "".join("row-%03d\n" % i for i in range(10))
        session.append_scrollback(text)
        peek = session.read_canvas(offset=0, line_limit=3, wait_timeout=0.0)
        self.assertEqual(peek["output"], "row-000\nrow-001\nrow-002\n")
        consumed = session.read_canvas(line_limit=3, wait_timeout=0.0)
        self.assertEqual(consumed["output"], "row-000\nrow-001\nrow-002\n")

    def test_tail_moves_the_cursor_to_the_end(self):
        session, _ = self._session()
        session.append_scrollback("".join("row-%03d\n" % i for i in range(10)))
        res = session.read_canvas(tail=2, wait_timeout=0.0)
        self.assertEqual(res["output"], "row-008\nrow-009\n")
        self.assertEqual(res["has_more"], 0)
        self.assertEqual(session.read_canvas(line_limit=5, wait_timeout=0.0)["output"], "")

    def test_windows_never_overlap_or_drop_a_line(self):
        session, _ = self._session()
        text = "".join("row-%03d\n" % i for i in range(30))
        session.append_scrollback(text)
        joined = "".join(self._drain(session, line_limit=4))
        self.assertEqual(joined, text)
        for i in range(30):
            self.assertEqual(joined.count("row-%03d\n" % i), 1)

    def test_has_more_is_honest_about_unread_lines(self):
        session, _ = self._session()
        text = "".join("row-%03d\n" % i for i in range(25))
        session.append_scrollback(text)
        res = session.read_canvas(line_limit=5, wait_timeout=0.0)
        self.assertEqual(res["has_more"], 20)
        self.assertEqual(res["output"], "".join("row-%03d\n" % i for i in range(5)))


class TestExecChannelEcho(_OutputContractBase):
    """Notebook item 1: the non-PTY exec channel has no terminal echo of its own.

    A PTY echoes the typed command back, so the PTY answer carries exactly one console
    line. The exec channel echoes nothing: the gateway used to print a synthetic
    "$ command" line anyway and the agent read the command it had just sent
    (README.md:237 "no PTY, no echo"; QUICK_START.md:140).
    """

    def test_exec_channel_answer_has_no_synthetic_command_line(self):
        session, client = self._session()
        session.client = client
        session.exec_channel_posix = True  # verified POSIX exec channel: the gate is open
        client.exec_command.return_value = (MagicMock(), MagicMock(), MagicMock())

        def fill(run):
            run.append_output("alpha\nbeta\n")

        session._start_exec_reader_thread = fill
        res = self._run(session, "echo alpha; echo beta", use_pty=False)
        self.assertEqual(res["output"], "alpha\nbeta\n",
                         "the exec channel does not echo: got %r" % (res["output"],))


class TestInternalRunsStayOffTheCanvas(_OutputContractBase):
    """Gateway maintenance must never enter the agent's single unread stream.

    A host without SFTP (Keenetic) serves file operations with helper commands run
    through the same PTY session (fs.py _sync_shell(..., internal=True)). Those
    helpers are the gateway's own machinery: their caller parses the run's own
    buffer, so the tab canvas - the one stream the agent reads - must stay clean.
    Live trace (keenetic, 2026-09-28): right after "file write" the agent's next
    run showed mkdir -p, the base64 heredoc, the whole decode block and the
    MCP_B64_OK_* marker.
    """

    def _helper_transcript(self, payload):
        token = self._token_of(payload)
        return (payload.rstrip("\n") + "\r\n"
                + "\x1b[?2004l\rMCP_B64_OK_1\r\n__MCP_EC_" + token + "_0\r\n"
                + "\x1b[?2004h/ # ").encode()

    def test_internal_helper_traffic_never_reaches_the_canvas(self):
        session, _ = self._pty_session(self._helper_transcript)
        res = self._run(session, "mkdir -p /tmp/MCP_HELPER_DIR", internal=True)
        self.assertIn("MCP_B64_OK_1", res["output"], "the helper caller reads its own run buffer")
        canvas = session.read_canvas(line_limit=0, wait_timeout=0.0)
        self.assertEqual(canvas["output"], "",
                         "gateway machinery leaked into the agent stream: %r" % (canvas["output"],))
        self.assertEqual(canvas["has_more"], 0)

    def test_a_lazily_mirrored_internal_run_stays_off_the_canvas(self):
        # A run whose text only ever reached its own buffer (a mocked reader, a
        # restored run, a late read) goes through _mirror_runs: internal runs must
        # be skipped there too.
        session, _ = self._session()

        def fill(run):
            run.append_output("MCP_B64_OK_2\n")
            run.mark_done("completed")

        session._start_reader_thread = fill
        self._run(session, "mkdir -p /tmp/MCP_HELPER_DIR", internal=True)
        canvas = session.read_canvas(line_limit=0, wait_timeout=0.0)
        self.assertEqual(canvas["output"], "",
                         "the mirror path leaked internals: %r" % (canvas["output"],))
        self.assertEqual(canvas["has_more"], 0)

    def test_an_internal_helper_does_not_consume_unread_agent_output(self):
        session, _ = self._pty_session(self._helper_transcript)
        session.append_scrollback("alpha\n")
        self._run(session, "mkdir -p /tmp/MCP_HELPER_DIR", internal=True)
        first = session.read_canvas(line_limit=0, wait_timeout=0.0)
        self.assertEqual(first["output"], "alpha\n", "the helper ate unread agent output")
        second = session.read_canvas(line_limit=0, wait_timeout=0.0)
        self.assertEqual(second["output"], "", "internals stayed behind: %r" % (second["output"],))
        self.assertEqual(second["has_more"], 0)


if __name__ == "__main__":
    unittest.main()
