"""Session behaviour against a scripted shell (no network)."""

import tempfile
import threading
import time
import unittest

from mcp_ssh_gateway.config import DEFAULT_MAX_CHARS, ServerTargetConfig
from mcp_ssh_gateway.logs import LogStore
from mcp_ssh_gateway.session import CommandBlocked, Session, SessionBusy, SessionError, Timing
from tests.fakes import Behaviour, FakeConnection, FakeForeignShell, FakeNdmShell, FakePosixShell

FAST = Timing(settle_input=0.15, settle_prompt=0.1, interrupt_grace=0.6, boot_silence=0.3, boot_timeout=5.0)


def echo_script(command):
    if command.startswith("echo "):
        return Behaviour(output=command[5:] + "\n")
    if command.startswith("printf "):
        return Behaviour(output=command[7:])
    if command == "false":
        return Behaviour(code=1)
    if command.startswith("seq "):
        _, first, last = command.split()
        return Behaviour(output="".join(f"{i}\n" for i in range(int(first), int(last) + 1)))
    if command.startswith("sleep"):
        return Behaviour(hang=True)
    if command == "stubborn":
        return Behaviour(output="starting\n", hang=True, ignore_ctrl_c=True)
    if command == "ask":
        return Behaviour(ask="Continue? [y/N] ",
                         then=lambda answer: Behaviour(output=f"got:{answer}\n"))
    if command == "pause":
        return Behaviour(output="working\n", hang=True)
    if command == "prompt":
        return Behaviour(output="Enter the value: ", hang=True)
    if command == "nested":
        return Behaviour(output="root@host:/# ", hang=True)
    if command == "progress":
        return Behaviour(output="10%\r50%\r100%\n")
    if command == "crlf":
        return Behaviour(output="a\r\nb\r\n")
    return Behaviour(output=f"unknown: {command}\n", code=127)


class SessionTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.logs = LogStore(self.tmp.name, policy="meta")
        self.target = ServerTargetConfig(alias="web", host="h", user="u")

    def open(self, script=echo_script, shell=None, **shell_kwargs):
        self.connection = FakeConnection(lambda: FakePosixShell(script, **shell_kwargs))
        session = Session(1, self.target, self.connection, self.logs, shell=shell, timing=FAST)
        session.start()
        self.addCleanup(session.close)
        return session

    @property
    def channel(self):
        return self.connection.channels[-1]


class TestStart(SessionTestCase):
    def test_a_posix_host_is_recognised_and_its_banner_stays_off_the_canvas(self):
        session = self.open()
        self.assertEqual(session.mode, "shell")
        self.assertEqual(session.read(wait=0)["output"], "")

    def test_the_shell_is_silenced_once(self):
        session = self.open()
        self.assertEqual(sum("stty -echo" in typed for typed in self.channel.typed), 1)
        self.assertIsNotNone(session)

    def test_a_shell_that_stays_noisy_is_replaced_by_sh(self):
        opened = []

        def factory():
            channel = FakePosixShell(echo_script, quiet_works=False, quiet_after_exec=True)
            opened.append(channel)
            return channel

        connection = FakeConnection(factory)
        session = Session(1, self.target, connection, self.logs, timing=FAST)
        session.start()
        self.addCleanup(session.close)
        self.assertTrue(any(typed.startswith("exec sh") for typed in opened[0].typed))

    def test_a_host_that_cannot_be_silenced_is_refused_with_a_clear_message(self):
        connection = FakeConnection(lambda: FakePosixShell(echo_script, quiet_works=False))
        session = Session(1, self.target, connection, self.logs, timing=FAST)
        with self.assertRaisesRegex(SessionError, "quiet"):
            session.start()


class TestLoginShell(SessionTestCase):
    FISH = "fish: Unsupported use of '='. In fish, please use 'set PS1 ...'."
    TCSH = "export: Command not found.\nstty: invalid argument '2'"

    def foreign(self, error, **target):
        self.target = ServerTargetConfig(alias="web", host="h", user="u", **target)
        connection = FakeConnection(lambda: FakeForeignShell(error))
        return Session(1, self.target, connection, self.logs, timing=FAST)

    def test_a_fish_login_is_named_at_once_with_the_way_out(self):
        session = self.foreign(self.FISH)
        started = time.time()
        with self.assertRaisesRegex(SessionError, r'fish.*"shell": "bash"'):
            session.start()
        self.assertLess(time.time() - started, 2.0)  # not the whole boot timeout

    def test_a_tcsh_login_is_named_at_once_with_the_way_out(self):
        session = self.foreign(self.TCSH)
        started = time.time()
        with self.assertRaisesRegex(SessionError, r'csh.*"shell": "bash"'):
            session.start()
        self.assertLess(time.time() - started, 2.0)

    def test_a_configured_shell_that_did_not_take_over_is_reported_as_such(self):
        session = self.foreign(self.FISH, shell="/opt/bin/bash")
        with self.assertRaisesRegex(SessionError, r"exec /opt/bin/bash.*full path"):
            session.start()

    def test_a_configured_shell_replaces_the_login_shell_before_anything_else_is_typed(self):
        self.target = ServerTargetConfig(alias="web", host="h", user="u", shell="bash")
        session = self.open(quiet_after_exec=True)
        self.assertEqual(self.channel.typed[0], "exec bash\n")
        self.assertIn("stty -echo", self.channel.typed[1])
        self.assertEqual(session.run("echo hi", wait=5)["output"], "$ echo hi\nhi\n")


class TestRun(SessionTestCase):
    def test_a_finished_command_returns_at_once_and_reads_like_a_console(self):
        session = self.open()
        started = time.time()
        result = session.run("echo hello", wait=10)
        self.assertLess(time.time() - started, 2.0)
        self.assertEqual(result["output"], "$ echo hello\nhello\n")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["session_id"], "web/1")

    def test_a_failing_command_is_a_result_not_an_error(self):
        result = self.open().run("false", wait=5)
        self.assertEqual((result["status"], result["exit_code"]), ("completed", 1))

    def test_output_without_a_trailing_newline_is_closed_so_the_next_command_starts_clean(self):
        session = self.open()
        self.assertEqual(session.run("printf hello", wait=5)["output"], "$ printf hello\nhello\n")
        self.assertEqual(session.run("echo next", wait=5)["output"], "$ echo next\nnext\n")

    def test_read_does_not_report_running_when_the_prompt_follows_the_output_closely(self):
        session = self.open(lambda command: Behaviour(output="done\n", timeline=(0.1, 0.04)))
        self.assertEqual(session.run("slow", wait=0)["status"], "running")
        result = session.read(wait=5)
        self.assertEqual((result["output"], result["status"]), ("done\n", "completed"))

    def test_a_new_command_skips_older_unread_output_and_says_so(self):
        session = self.open(lambda command: Behaviour(output="".join(f"{i}\n" for i in range(50))) if command == "many"
                            else Behaviour(output="fresh\n"))
        session.run("many", wait=5, lines=10)
        result = session.run("next", wait=5)
        self.assertEqual(result["output"], "$ next\nfresh\n")
        self.assertEqual(result["skipped_lines"], 41)
        self.assertIn("$ many", session.read(offset=0, lines=3)["output"])

    def test_no_skipped_lines_are_reported_when_everything_was_read(self):
        session = self.open()
        session.run("echo one", wait=5)
        self.assertNotIn("skipped_lines", session.run("echo two", wait=5))

    def test_a_multiline_command_runs_as_one_command(self):
        session = self.open(lambda command: Behaviour(output=f"<{command}>\n"))
        result = session.run("echo a\necho b", wait=5)
        self.assertEqual(result["status"], "completed")
        self.assertIn("<echo a\necho b>", result["output"])

    def test_a_multiline_command_is_shown_by_its_first_line_only(self):
        session = self.open(lambda command: Behaviour(output="ok\n"))
        result = session.run("cat <<'EOF'\nbig\nbody\nEOF", wait=5)
        self.assertEqual(result["output"], "$ cat <<'EOF' [+3 lines]\nok\n")

    def test_a_command_still_running_reports_running_and_read_finishes_it(self):
        session = self.open()
        result = session.run("pause", wait=0.3)
        self.assertEqual(result["status"], "running")
        self.assertIn("working", result["output"])
        self.assertIn("read", result["hint"])
        threading.Timer(0.2, self.channel.finish_running).start()
        self.assertEqual(session.read(wait=5)["status"], "completed")

    def test_read_waits_for_the_end_of_the_command_instead_of_returning_at_every_line(self):
        session = self.open()
        channel = self.channel
        session.run("pause", wait=0)
        for number in range(5):
            threading.Timer(0.1 * (number + 1), channel.emit, [f"line {number}\n"]).start()
        threading.Timer(0.7, channel.finish_running).start()
        result = session.read(wait=5)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["output"].count("line "), 5)

    def test_read_gives_up_after_the_wait_when_the_command_keeps_running(self):
        session = self.open()
        session.run("sleep 100", wait=0.1)
        started = time.time()
        result = session.read(wait=0.4)
        self.assertEqual(result["status"], "running")
        self.assertGreaterEqual(time.time() - started, 0.35)

    def test_a_second_command_while_one_runs_is_refused_and_names_the_running_one(self):
        session = self.open()
        session.run("sleep 100", wait=0.1)
        with self.assertRaisesRegex(SessionBusy, "sleep 100.*run without session_id"):
            session.run("echo hi", wait=1)

    def test_a_closed_session_says_how_to_get_a_new_one(self):
        session = self.open()
        session.close()
        with self.assertRaisesRegex(SessionError, "closed.*without session_id"):
            session.run("echo hi", wait=1)

    def test_the_interactive_question_is_reported_instead_of_waiting_for_the_timeout(self):
        session = self.open()
        started = time.time()
        result = session.run("ask", wait=10)
        self.assertLess(time.time() - started, 3.0)
        self.assertEqual(result["status"], "waiting_input")
        self.assertTrue(result["output"].endswith("Continue? [y/N] "))
        self.assertIn("signal", result["hint"])

    def test_a_progress_bar_that_rewrites_its_line_costs_one_line(self):
        session = self.open()
        self.assertEqual(session.run("progress")["output"], "$ progress\n100%\n")

    def test_progress_updates_that_arrive_one_by_one_are_one_line_too(self):
        session = self.open()
        session.run("sleep 9", wait=0.1)
        for update in ("10%\r", "50%\r", "100%\n"):
            self.channel.emit(update)
        self.channel.finish_running()
        self.assertEqual(session.read(wait=2)["output"], "100%\n")

    def test_windows_line_ends_do_not_double_the_lines(self):
        session = self.open()
        self.assertEqual(session.run("crlf")["output"], "$ crlf\na\nb\n")

    def test_a_silent_program_with_an_unfinished_line_is_shown_the_line_and_the_way_to_answer(self):
        session = self.open()
        result = session.run("prompt", wait=1.0)
        self.assertEqual(result["status"], "running")  # nothing tells that this is a question
        self.assertIn("'Enter the value:'", result["hint"])
        self.assertIn("signal", result["hint"])

    def test_a_shell_started_inside_the_session_is_named_and_the_way_out_is_given(self):
        session = self.open()
        result = session.run("nested", wait=1.0)
        self.assertEqual(result["status"], "running")
        self.assertIn("shell started inside this session", result["hint"])
        self.assertIn("text=exit", result["hint"])

    def test_a_running_command_that_ends_its_lines_gets_the_plain_hint(self):
        session = self.open()
        result = session.run("pause", wait=0.5)
        self.assertEqual(result["status"], "running")
        self.assertNotIn("unfinished", result["hint"])
        self.assertIn("Still running", result["hint"])

    def test_typed_input_answers_the_question(self):
        session = self.open()
        session.run("ask", wait=5)
        result = session.signal("stdin", text="y", wait=5)
        self.assertEqual(result["status"], "completed")
        self.assertIn("got:y", result["output"])

    def test_a_shell_waiting_for_the_rest_of_a_command_is_reported_as_waiting_for_input(self):
        session = self.open(lambda command: Behaviour(more=True))
        session.run("echo 'oops", wait=0.2)
        result = session.read(wait=2)
        self.assertEqual(result["status"], "waiting_input")
        self.assertIn("unclosed", result["hint"])

    def test_a_silent_multiline_command_is_running_not_waiting_for_input(self):
        # The shell prompts once per typed line of the { } group; only prompts beyond that mean "unfinished".
        session = self.open(lambda command: Behaviour(hang=True))
        result = session.run("sleep 30\necho done", wait=0.6)  # far longer than the input settle time
        self.assertEqual(result["status"], "running")

    def test_an_unclosed_quote_in_a_multiline_command_is_still_reported(self):
        session = self.open(lambda command: Behaviour(more=True))
        session.run("echo 'a\nb", wait=0.2)
        result = session.read(wait=2)
        self.assertEqual(result["status"], "waiting_input")
        self.assertIn("unclosed", result["hint"])

    def test_an_empty_or_untypeable_command_is_refused(self):
        session = self.open()
        with self.assertRaisesRegex(SessionError, "empty"):
            session.run("  ", wait=1)
        with self.assertRaisesRegex(SessionError, "4000"):
            session.run("echo " + "x" * 5000, wait=1)

    def test_a_blacklisted_command_never_reaches_the_shell(self):
        self.target.command_blacklist = ["rm -rf"]
        session = self.open()
        with self.assertRaises(CommandBlocked):
            session.run("rm -rf /", wait=1)
        self.assertEqual(self.channel.commands, [])

    def test_output_of_a_background_job_lands_on_the_canvas(self):
        session = self.open()
        self.channel.emit("job done\n")
        deadline = time.time() + 3
        result = session.read(wait=3)
        while "job done" not in result["output"] and time.time() < deadline:
            result = session.read(wait=1)
        self.assertEqual(result["output"], "job done\n")


class TestInterrupt(SessionTestCase):
    def test_ctrl_c_on_a_program_that_waits_for_input_answers_only_once_it_is_stopped(self):
        session = self.open()
        self.assertEqual(session.run("ask", wait=5)["status"], "waiting_input")
        result = session.signal("ctrl_c", wait=5)
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(result["process_stopped"])

    def test_ctrl_c_stops_the_command_and_the_shell_stays_usable(self):
        session = self.open()
        session.run("sleep 100", wait=0.1)
        result = session.signal("ctrl_c", wait=5)
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(result["process_stopped"])
        self.assertEqual(session.run("echo alive", wait=5)["output"], "$ echo alive\nalive\n")

    def test_a_command_that_ignores_ctrl_c_is_reported_honestly(self):
        session = self.open()
        session.run("stubborn", wait=0.1)
        result = session.signal("ctrl_c", wait=5)
        self.assertEqual(result["status"], "interrupted")
        self.assertFalse(result["process_stopped"])
        self.assertIn("session_close", result["hint"])

    def test_after_an_unconfirmed_stop_the_next_command_gets_a_fresh_shell_and_a_warning(self):
        session = self.open()
        session.run("stubborn", wait=0.1)
        session.signal("ctrl_c", wait=5)
        result = session.run("echo fresh", wait=5)
        self.assertEqual(len(self.connection.channels), 2)
        self.assertIn("fresh", result["output"])
        self.assertIn("lost", result["warning"])

    def test_the_hard_timeout_stops_the_command_and_keeps_its_output(self):
        session = self.open()
        result = session.run("pause", wait=5, timeout=0.4)
        self.assertEqual(result["status"], "timed_out")
        self.assertIn("working", result["output"])
        self.assertEqual(session.run("echo ok", wait=5)["status"], "completed")

    def test_signals_need_a_running_command(self):
        session = self.open()
        with self.assertRaisesRegex(SessionError, "Nothing is running"):
            session.signal("ctrl_c")
        with self.assertRaisesRegex(SessionError, "Nothing is running"):
            session.signal("stdin", text="x")

    def test_a_wrong_action_is_named_even_when_nothing_is_running(self):
        session = self.open()
        with self.assertRaisesRegex(SessionError, "Unknown action 'stop'.*ctrl_c, ctrl_d or stdin"):
            session.signal("stop")

    def test_the_answer_to_ctrl_c_is_capped_like_every_other_answer(self):
        session = self.open(lambda command: Behaviour(output=("x" * 999 + "\n") * 100, hang=True))
        session.run("noisy", wait=0.5, lines=5)  # 100 KB were printed, the shown part is small
        result = session.signal("ctrl_c", wait=5)
        self.assertEqual(result["status"], "interrupted")
        self.assertLessEqual(len(result["output"]), DEFAULT_MAX_CHARS)
        self.assertGreater(result["has_more"], 0)

    def test_input_too_big_for_a_terminal_is_refused_and_the_shell_is_not_touched(self):
        session = self.open()
        with self.assertRaisesRegex(SessionError, "file tool"):
            session.run("echo a\n" * 50_000, wait=1)  # 350 KB in short lines
        self.assertEqual(session.run("echo alive", wait=5)["output"], "$ echo alive\nalive\n")

    def test_stdin_obeys_the_limits_of_a_command(self):
        session = self.open()
        session.run("ask", wait=5)
        with self.assertRaisesRegex(SessionError, "4000"):
            session.signal("stdin", text="y" * 5000)
        with self.assertRaisesRegex(SessionError, "file tool"):
            session.signal("stdin", text="y\n" * 200_000)
        self.assertIn("got:y", session.signal("stdin", text="y", wait=5)["output"])


class TestReading(SessionTestCase):
    def test_a_long_answer_is_paged_by_lines_without_repeats(self):
        session = self.open()
        first = session.run("seq 1 1000", wait=5, lines=200)
        self.assertEqual(first["has_more"], 801)
        second = session.read(lines=200)
        self.assertTrue(second["output"].startswith("200\n"))
        rest = session.read(lines=0)
        self.assertEqual(rest["output"].splitlines()[-1], "1000")
        self.assertNotIn("has_more", rest)

    def test_scrolling_back_does_not_disturb_the_unread_position(self):
        session = self.open()
        session.run("seq 1 50", wait=5, lines=10)
        peek = session.read(offset=0, lines=3)
        self.assertEqual(peek["output"], "$ seq 1 50\n1\n2\n")
        self.assertTrue(session.read(lines=2)["output"].startswith("10\n"))

    def test_tail_shows_the_last_lines_and_says_how_many_it_skipped(self):
        session = self.open()
        session.run("seq 1 100", wait=5, lines=5)
        result = session.read(tail=3)
        self.assertEqual(result["output"], "98\n99\n100\n")
        self.assertEqual(result["skipped_lines"], 93)  # 5 .. 97 were never seen
        self.assertNotIn("dropped_data", result)  # nothing was lost: they can be scrolled back to
        self.assertEqual(session.read()["output"], "")
        self.assertEqual(session.read(offset=5, lines=2)["output"], "5\n6\n")

    def test_tail_over_a_fully_read_session_skips_nothing(self):
        session = self.open()
        session.run("seq 1 10", wait=5, lines=0)
        result = session.read(tail=3)
        self.assertEqual(result["output"], "8\n9\n10\n")
        self.assertNotIn("skipped_lines", result)
        self.assertNotIn("dropped_data", result)

    def test_reading_an_idle_session_with_nothing_new_says_so(self):
        session = self.open()
        result = session.read(wait=0)
        self.assertEqual(result["status"], "idle")
        self.assertEqual(result["output"], "")


class TestLongLines(SessionTestCase):
    """BusyBox ash (Keenetic, OpenWrt, Alpine) shows its prompt again when a typed line fills its line buffer."""

    LINE_LIMIT = 512

    def open_busybox(self, script=echo_script):
        return self.open(script, line_limit=self.LINE_LIMIT)

    def test_a_prompt_shown_again_while_a_long_line_is_read_does_not_end_the_command(self):
        session = self.open_busybox()
        command = "echo " + "x" * 700
        result = session.run(command, wait=5)
        self.assertEqual((result["status"], result["exit_code"]), ("completed", 0))
        self.assertEqual(result["output"], f"$ {command}\n{'x' * 700}\n")

    def test_a_line_that_fills_the_buffer_several_times_prompts_several_times_and_still_ends_once(self):
        session = self.open_busybox()
        command = "echo " + "y" * 2600
        self.assertEqual(session.run(command, wait=5)["output"], f"$ {command}\n{'y' * 2600}\n")

    def test_the_command_after_a_long_one_is_not_finished_by_a_prompt_left_over(self):
        session = self.open_busybox(lambda command: Behaviour(hang=True) if command == "sleep 5"
                                    else Behaviour(output="ok\n"))
        session.run("echo " + "z" * 700, wait=5)
        result = session.run("sleep 5", wait=0.5)
        self.assertEqual(result["status"], "running")

    def test_a_long_line_inside_a_multiline_command_is_no_different(self):
        session = self.open_busybox(lambda command: Behaviour(output="done\n"))
        result = session.run("echo short\necho " + "w" * 700 + "\necho last", wait=5)
        self.assertEqual((result["status"], result["exit_code"]), ("completed", 0))
        self.assertTrue(result["output"].endswith("done\n"))

    def test_a_line_that_fits_the_buffer_is_not_a_special_case(self):
        session = self.open_busybox()
        command = "echo " + "v" * (self.LINE_LIMIT - 8)
        self.assertEqual(session.run(command, wait=5)["output"], f"$ {command}\n{'v' * (self.LINE_LIMIT - 8)}\n")


class TestFailure(SessionTestCase):
    def test_a_dropped_connection_fails_the_run_and_the_next_command_reconnects(self):
        session = self.open()
        session.run("sleep 100", wait=0.1)
        self.channel.close()
        deadline = time.time() + 3
        while session.read(wait=0.2)["status"] == "running" and time.time() < deadline:
            pass
        self.assertEqual(session.read(wait=0)["status"], "failed")
        result = session.run("echo back", wait=5)
        self.assertIn("back", result["output"])
        self.assertIn("lost", result["warning"])

    def test_a_send_failure_names_its_cause_even_when_the_exception_has_no_message(self):
        session = self.open()

        def broken(data):
            raise EOFError()

        self.channel.sendall = broken
        with self.assertRaisesRegex(SessionError, "Sending to web failed: EOFError"):
            session.run("echo hi", wait=1)

    def test_closing_ends_the_reader_and_the_channel(self):
        session = self.open()
        channel = self.channel
        session.close()
        self.assertTrue(channel.closed)
        with self.assertRaisesRegex(SessionError, "closed"):
            session.run("echo hi", wait=1)


class TestQuietRuns(SessionTestCase):
    def test_a_maintenance_command_returns_its_output_and_stays_off_the_canvas(self):
        session = self.open()
        result = session.run_quiet("echo secret-work", timeout=5)
        self.assertEqual((result.output, result.exit_code), ("secret-work\n", 0))
        self.assertEqual(session.read(wait=0)["output"], "")

    def test_a_maintenance_command_refuses_a_busy_session(self):
        session = self.open()
        session.run("sleep 100", wait=0.1)
        with self.assertRaises(SessionBusy):
            session.run_quiet("echo x", timeout=1)


def ndm_script(command):
    if command == "show version":
        return "release 4.0\nmodel Giga\n"
    if command == "ask me":
        return "Save the configuration? [y/N] "
    return f"Command::Base error: no such command: {command}.\n"


class TestRouterCli(SessionTestCase):
    def open_cli(self, shell=None, **fake_kwargs):
        self.connection = FakeConnection(lambda: FakeNdmShell(ndm_script, **fake_kwargs))
        session = Session(1, self.target, self.connection, self.logs, shell=shell, timing=FAST)
        session.start()
        self.addCleanup(session.close)
        return session

    def test_a_router_cli_is_recognised_by_its_prompt(self):
        self.assertEqual(self.open_cli().mode, "cli")

    def test_a_command_completes_when_the_prompt_returns_and_reads_like_a_console(self):
        result = self.open_cli().run("show version", wait=10)
        self.assertEqual(result["output"], "> show version\nrelease 4.0\nmodel Giga\n")
        self.assertEqual(result["status"], "completed")
        self.assertNotIn("exit_code", result)

    def test_the_error_of_an_unknown_command_is_plain_output(self):
        result = self.open_cli().run("bogus", wait=10)
        self.assertEqual(result["status"], "completed")
        self.assertIn("no such command", result["output"])

    def test_a_question_is_reported_with_its_text(self):
        result = self.open_cli().run("ask me", wait=10)
        self.assertEqual(result["status"], "waiting_input")
        self.assertTrue(result["output"].endswith("Save the configuration? [y/N] "))

    def test_pages_are_advanced_automatically_and_the_pager_never_shows(self):
        session = self.open_cli(pages=["page one\n", "page two\n", "page three"])
        result = session.run("show pages", wait=10)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["output"], "> show pages\npage one\npage two\npage three\n")

    def test_shell_true_enters_the_linux_shell_of_the_router(self):
        self.connection = FakeConnection(lambda: FakeNdmShell(ndm_script, linux_script=echo_script))
        session = Session(1, self.target, self.connection, self.logs, shell=True, timing=FAST)
        session.start()
        self.addCleanup(session.close)
        self.assertEqual(session.mode, "shell")
        self.assertEqual(session.run("echo linux", wait=5)["output"], "$ echo linux\nlinux\n")

    def test_a_router_without_a_linux_shell_reports_it_when_one_was_asked_for(self):
        def factory():
            ndm = FakeNdmShell(ndm_script)
            ndm.linux_allowed = False
            return ndm
        connection = FakeConnection(factory)
        session = Session(1, self.target, connection, self.logs, shell=True, timing=FAST)
        with self.assertRaisesRegex(SessionError, "Linux shell"):
            session.start()

    def test_the_cli_is_refused_on_a_plain_linux_host_when_asked_for(self):
        connection = FakeConnection(lambda: FakePosixShell(echo_script))
        session = Session(1, self.target, connection, self.logs, shell=False, timing=FAST)
        with self.assertRaisesRegex(SessionError, "no router CLI"):
            session.start()


if __name__ == "__main__":
    unittest.main()
