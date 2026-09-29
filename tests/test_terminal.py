"""Terminal protocol: exit-code marker, echo removal, prompt and interactive detection."""

import re
import shutil
import subprocess
import unittest

from mcp_ssh_gateway.terminal import (
    EchoFilter, MarkerFilter, PromptDetector, PromptEvent, looks_interactive, looks_like_shell_prompt,
    split_pager_prompt, input_problem, posix_setup, wrap_posix,
)

TOKEN = "0123456789abcdef"


class TestWrapPosix(unittest.TestCase):
    def test_a_single_line_is_typed_after_the_assignment_that_numbers_it(self):
        self.assertEqual(wrap_posix("echo hi", 7), "__mcp_n=7; echo hi\n")
        self.assertEqual(wrap_posix("ls\n", 8), "__mcp_n=8; ls\n")

    def test_several_lines_become_one_group_so_the_shell_prompts_once(self):
        self.assertEqual(wrap_posix("echo a\necho b", 3), "{ __mcp_n=3\necho a\necho b\n}\n")

    def test_the_result_is_valid_shell_for_every_kind_of_command(self):
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("no sh on this machine")
        commands = [
            "sleep 20 &",
            "echo a # comment",
            "cat <<EOF\nline\nEOF",
            "if true; then\n  echo x\nfi",
            "echo a\n# trailing comment",
            "true &&\n echo ok",
        ]
        for command in commands:
            with self.subTest(command=command):
                result = subprocess.run([sh, "-n", "-c", wrap_posix(command, 1)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_the_prompt_says_the_exit_code_and_the_number_of_the_command_that_ran_last(self):
        sh = shutil.which("sh")
        if not sh:
            self.skipTest("no sh on this machine")
        ps1 = re.search(r"PS1='([^']*)'", posix_setup(TOKEN)).group(1)
        show_prompt = 'eval "printf %s \\"$PS1\\""'  # a shell expands the prompt only when it shows it
        scripts = {
            f"__MCP_EC_{TOKEN}_0_0]": "true",
            f"__MCP_EC_{TOKEN}_1_4]": wrap_posix("false", 4),
            f"__MCP_EC_{TOKEN}_0_12]": wrap_posix("echo a\necho b", 12),
        }
        for expected, typed in scripts.items():
            with self.subTest(expected=expected):
                result = subprocess.run([sh, "-c", f"PS1='{ps1}'\n{typed}\n{show_prompt}"],
                                        capture_output=True, text=True)
                self.assertEqual(result.stdout.splitlines()[-1], expected, result.stderr)

    def test_the_setup_line_puts_the_marker_into_the_prompt(self):
        line = posix_setup(TOKEN)
        self.assertIn("stty -echo", line)
        self.assertIn(f"__MCP_EC_{TOKEN}_", line)
        self.assertIn(f"__MCP_MORE_{TOKEN}]", line)
        self.assertNotIn("\n", line.rstrip("\n"))  # one line: typed once, executed once

    def test_the_setup_line_turns_the_pagers_of_common_tools_off(self):
        line = posix_setup(TOKEN)
        for variable in ("PAGER", "GIT_PAGER", "SYSTEMD_PAGER", "MANPAGER"):
            with self.subTest(variable=variable):
                self.assertIn(f"{variable}=cat", line)

    def test_input_a_terminal_cannot_take_is_rejected_with_the_way_out(self):
        self.assertIsNone(input_problem("echo hi"))
        self.assertIsNone(input_problem("a\n" * 2000))
        long_line = input_problem("echo " + "x" * 5000)
        self.assertIn("4000", long_line)
        self.assertIn("file tool", long_line)
        too_much = input_problem("a\n" * 200_000)
        self.assertIn("262144", too_much)
        self.assertIn("file tool", too_much)


class TestMarkerFilter(unittest.TestCase):
    def marker(self, code, run=1):
        return f"__MCP_EC_{TOKEN}_{code}_{run}]"

    MORE = f"__MCP_MORE_{TOKEN}]"

    def test_output_passes_and_the_prompt_marker_yields_the_exit_code_and_the_run(self):
        flt = MarkerFilter(TOKEN)
        self.assertEqual(flt.feed("one\ntwo\n"), "one\ntwo\n")
        self.assertEqual(flt.take_events(), [])
        self.assertEqual(flt.feed(self.marker(3, 17)), "")
        self.assertEqual(flt.take_events(), [PromptEvent(code=3, run=17)])
        self.assertEqual(flt.take_events(), [])

    def test_a_marker_glued_to_unterminated_output_keeps_the_output(self):
        flt = MarkerFilter(TOKEN)
        self.assertEqual(flt.feed("hello" + self.marker(0)), "hello")
        self.assertEqual(flt.take_events(), [PromptEvent(0, 1)])

    def test_a_marker_split_anywhere_is_still_found(self):
        for marker, expected in ((self.marker(12, 345), PromptEvent(12, 345)), (self.MORE, None)):
            stream = "out\n" + marker
            for cut in range(1, len(stream)):
                with self.subTest(cut=cut, marker=marker):
                    flt = MarkerFilter(TOKEN)
                    text = flt.feed(stream[:cut]) + flt.feed(stream[cut:])
                    self.assertEqual(text, "out\n")
                    self.assertEqual(flt.take_events(), [expected])

    def test_every_marker_is_reported_and_text_between_them_survives(self):
        flt = MarkerFilter(TOKEN)
        text = flt.feed(self.marker(0, 1) + "late job output\n" + self.MORE + self.marker(1, 2))
        self.assertEqual(text, "late job output\n")
        self.assertEqual(flt.take_events(), [PromptEvent(0, 1), None, PromptEvent(1, 2)])

    def test_a_similar_looking_line_is_data(self):
        flt = MarkerFilter(TOKEN)
        text = "__MCP_EC_ffffffffffffffff_0_1]\n__MCP_EC\n"
        self.assertEqual(flt.feed(text), text)
        self.assertEqual(flt.take_events(), [])

    def test_a_held_prefix_is_released_when_it_turns_out_to_be_data(self):
        flt = MarkerFilter(TOKEN)
        self.assertEqual(flt.feed("a__MCP_"), "a")
        self.assertEqual(flt.feed("x is data\n"), "__MCP_x is data\n")

    def test_finish_releases_what_is_still_held(self):
        flt = MarkerFilter(TOKEN)
        flt.feed("tail__MCP_EC_")
        self.assertEqual(flt.finish(), "__MCP_EC_")


class TestEchoFilter(unittest.TestCase):
    def test_the_echoed_command_and_its_blank_line_are_removed(self):
        flt = EchoFilter("show version")
        self.assertEqual(flt.feed("show version\n\nrelease 4.0\n"), "release 4.0\n")

    def test_a_prompt_in_front_of_the_echo_is_part_of_the_echo(self):
        flt = EchoFilter("show version")
        self.assertEqual(flt.feed("Keenetic>show version\nrelease 4.0\n"), "release 4.0\n")

    def test_output_that_repeats_the_command_later_is_kept(self):
        flt = EchoFilter("echo hi")
        self.assertEqual(flt.feed("echo hi\nsomething\necho hi\n"), "something\necho hi\n")

    def test_an_echo_wrapped_by_the_terminal_is_removed_as_a_whole(self):
        command = "echo " + "x" * 200
        wrapped = command[:120] + "\r\r\n" + command[120:] + "\r\n"
        flt = EchoFilter(command)
        from mcp_ssh_gateway.stream import StreamCleaner
        text = StreamCleaner().feed(wrapped + "result\r\n")
        self.assertEqual(flt.feed(text), "result\n")

    def test_a_line_that_only_starts_like_the_command_is_given_back(self):
        flt = EchoFilter("echo one two three")
        self.assertEqual(flt.feed("echo one\necho four\ntail\n"), "echo one\necho four\ntail\n")
        self.assertEqual(flt.flush(), "")

    def test_a_partial_line_held_as_a_possible_echo_returns_in_place(self):
        flt = EchoFilter("seq 1 3")
        first = flt.feed("seq 1 3\n1\n40-" + "y" * 85)
        self.assertEqual(first, "1\n")
        second = flt.feed("y" * 13 + "\n2\n")
        self.assertEqual(second, "40-" + "y" * 98 + "\n2\n")
        self.assertEqual(flt.flush(), "")

    def test_a_multiline_command_is_removed_line_by_line(self):
        flt = EchoFilter("echo one\necho two")
        self.assertEqual(flt.feed("echo one\necho two\none\ntwo\n"), "one\ntwo\n")


class TestPromptDetector(unittest.TestCase):
    def test_a_learned_prompt_is_recognised_at_the_tail(self):
        det = PromptDetector()
        det.learn("Welcome\nKeenetic-Giga>")
        self.assertEqual(det.at_tail("result\nKeenetic-Giga>"), "Keenetic-Giga>")
        self.assertEqual(det.at_tail("result\nKeenetic-Giga> "), "Keenetic-Giga> ")

    def test_a_prompt_printed_twice_in_a_row_is_still_a_prompt(self):
        # what a router shows after Ctrl+C: the interrupted line gets its own fresh prompt
        det = PromptDetector()
        det.learn("(config)>")
        self.assertEqual(det.at_tail("stats\n(config)> (config)> "), "(config)> (config)> ")

    def test_config_mode_prompts_of_the_same_device_are_recognised(self):
        det = PromptDetector()
        det.learn("Keenetic-Giga>")
        self.assertEqual(det.at_tail("ok\n(config)>"), "(config)>")
        self.assertEqual(det.at_tail("ok\nKeenetic-Giga(config)>"), "Keenetic-Giga(config)>")
        self.assertEqual(det.at_tail("ok\n(config-if)>"), "(config-if)>")

    def test_output_that_ends_like_a_prompt_but_is_not_ours_is_not_a_prompt(self):
        det = PromptDetector()
        det.learn("Keenetic-Giga>")
        for text in ("a > b", "value>", "#", "<html>", "x\nsome other>", "a\nfoo> bar"):
            with self.subTest(text=text):
                self.assertIsNone(det.at_tail(text))

    def test_nothing_is_recognised_before_a_prompt_was_learned(self):
        self.assertIsNone(PromptDetector().at_tail("Keenetic>"))

    def test_learning_ignores_text_that_does_not_end_in_a_prompt(self):
        det = PromptDetector()
        det.learn("just text without prompt")
        self.assertIsNone(det.at_tail("Keenetic>"))
        self.assertFalse(det.known)

    def test_the_prompt_is_only_taken_from_the_last_line(self):
        det = PromptDetector()
        det.learn("banner>\nKeenetic>")
        self.assertEqual(det.at_tail("Keenetic>"), "Keenetic>")
        self.assertIsNone(det.at_tail("banner>"))


class TestInteractiveDetection(unittest.TestCase):
    def test_typical_questions_are_interactive(self):
        for line in (
            "[sudo] password for bob: ", "Password:", "Enter passphrase for key '/x': ",
            "Continue? [y/N] ", "Do you want to continue? [Y/n] ", "Proceed (yes/no)? ",
            "Overwrite existing file? (y/n) ",
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "Username: ", "login: ", "cp: overwrite 'x'? ", "rm: remove write-protected file 'x'? ",
            "(END)", "lines 1-23/230 (END) ", "Press any key to continue", "Press ENTER to continue",
        ):
            with self.subTest(line=line):
                self.assertTrue(looks_interactive(line))

    def test_ordinary_output_is_not(self):
        for line in ("", "done", "12:00:01 up 3 days", "password file updated", "usage: tool [options]",
                     "Downloading 45%", "login shell: /bin/bash", "(END of the list)", "why? because"):
            with self.subTest(line=line):
                self.assertFalse(looks_interactive(line))

    def test_the_prompt_of_a_shell_is_recognised(self):
        for line in ("root@debian:/#", "user@host:~$ ", "bash-5.1$", "sh-4.4#", "/ #", "~ $", "$", "#"):
            with self.subTest(line=line):
                self.assertTrue(looks_like_shell_prompt(line))

    def test_other_unfinished_lines_are_not_prompts(self):
        for line in ("", "Enter the value:", "Downloading 45%", "########", "cost is 5 $ or 6 $", "a > b"):
            with self.subTest(line=line):
                self.assertFalse(looks_like_shell_prompt(line))

    def test_a_pager_prompt_at_the_end_is_cut_off(self):
        self.assertEqual(split_pager_prompt("line\n --More-- "), ("line\n", True))
        self.assertEqual(split_pager_prompt("Press any key to continue"), ("", True))
        self.assertEqual(split_pager_prompt("nothing to page"), ("nothing to page", False))
        self.assertEqual(split_pager_prompt("--More-- is a word\nnext"), ("--More-- is a word\nnext", False))


if __name__ == "__main__":
    unittest.main()
