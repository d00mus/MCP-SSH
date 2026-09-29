"""End-to-end behaviour against real sshd: the agent's view of a Linux host.

Every scenario runs on bash (Debian) and on BusyBox ash (Alpine).
"""

import hashlib
import time

from tests.integration.support import SshdTestCase, body


class LinuxHostScenarios:
    """Mixed into one TestCase per image; not collected on its own."""

    def test_command_returns_as_soon_as_it_finishes(self):
        started = time.time()
        res = self.gw.run("echo hello")
        elapsed = time.time() - started
        self.assertEqual(body(res["output"]), "hello")
        self.assertEqual(res["status"], "completed")
        self.assertEqual(res["exit_code"], 0)
        self.assertLess(elapsed, 4.0, "control must come back at once, not after the wait")

    def test_answer_reads_like_a_console(self):
        res = self.gw.run("echo hello")
        self.assertEqual(res["output"], "$ echo hello\nhello\n")

    def test_nonzero_exit_is_a_result_not_an_error(self):
        raw = self.gw.call_raw("run", server="host", command="sh -c 'exit 3'")
        self.assertFalse(raw["is_error"])
        self.assertEqual(raw["payload"]["status"], "completed")
        self.assertEqual(raw["payload"]["exit_code"], 3)

    def test_working_directory_persists_inside_a_session(self):
        first = self.gw.run("cd /tmp")
        second = self.gw.run("pwd", session_id=first["session_id"])
        self.assertEqual(body(second["output"]), "/tmp")

    def test_output_lines_that_look_like_prompts_are_kept(self):
        res = self.gw.run("printf '# header\\n#\\nfoo>\\nuser#\\n>\\n$\\nlast\\n'")
        self.assertEqual(body(res["output"]).splitlines(), ["# header", "#", "foo>", "user#", ">", "$", "last"])

    def test_background_job_does_not_break_completion(self):
        started = time.time()
        res = self.gw.run("sleep 20 &")
        self.assertEqual(res["status"], "completed", res)
        self.assertEqual(res["exit_code"], 0)
        self.assertLess(time.time() - started, 6.0)
        self.assertNotIn("syntax error", res["output"])

    def test_nothing_of_the_gateways_own_plumbing_reaches_the_agent(self):
        outputs = []
        for command in ("echo one; false", "printf 'no newline'", "ls /nonexistent", "sleep 20 &",
                        "cat <<'EOF'\nheredoc\nEOF"):
            outputs.append(self.gw.run(command)["output"])
        running = self.gw.call("run", server="host", command="sleep 30", wait=0.5)
        outputs.append(running["output"])
        outputs.append(self.gw.call("signal", session_id=running["session_id"], action="ctrl_c")["output"])
        for output in outputs:
            for plumbing in ("__MCP_", "stty", "PAGER", "PS1", "PS2"):
                self.assertNotIn(plumbing, output)

    def test_a_very_long_line_ends_the_command_once_and_leaves_no_prompt_behind(self):
        # BusyBox ash (Keenetic, OpenWrt, Alpine) shows its prompt again while it reads a line longer than its
        # line buffer; the first of the two prompts must not be taken for the end of the command.
        command = "echo BEGIN; printf %s " + "a" * 3800 + " | wc -c; echo END"
        res = self.gw.call("run", server="host", command=command)
        self.assertEqual((res["status"], res["exit_code"]), ("completed", 0), res)
        self.assertEqual(body(res["output"]).splitlines(), ["BEGIN", "3800", "END"])
        after = self.gw.call("run", server="host", session_id=res["session_id"], command="echo next")
        self.assertEqual(after["output"], "$ echo next\nnext\n")

    def test_multiline_command_and_heredoc(self):
        res = self.gw.run("cat <<'EOF'\nline one\nline two\nEOF\necho done")
        self.assertEqual(body(res["output"]).splitlines(), ["line one", "line two", "done"])
        self.assertEqual(res["status"], "completed")

    def test_a_silent_multiline_command_keeps_running_instead_of_asking_for_input(self):
        first = self.gw.call("run", server="host", command="sleep 3\necho finished", wait=2)
        self.assertEqual(first["status"], "running", first)
        done = self.gw.call("read", session_id=first["session_id"], wait=10)
        self.assertEqual((done["status"], done["exit_code"]), ("completed", 0), done)
        self.assertIn("finished", done["output"])

    def test_read_waits_for_the_end_instead_of_returning_at_every_line(self):
        first = self.gw.call("run", server="host", command="for i in 1 2 3; do echo $i; sleep 0.5; done", wait=0)
        done = self.gw.call("read", session_id=first["session_id"], wait=10)
        self.assertEqual(done["status"], "completed", done)
        self.assertEqual(body(first["output"] + done["output"]).splitlines(), ["1", "2", "3"])

    def test_interactive_prompt_waits_for_an_answer(self):
        first = self.gw.call("run", server="host", command="printf 'Continue? [y/N] '; read a; echo got:$a")
        self.assertEqual(first["status"], "waiting_input", first)
        self.assertIn("Continue? [y/N]", first["output"])
        self.assertIn("signal", first.get("hint", ""))
        answered = self.gw.call("signal", session_id=first["session_id"], action="stdin", text="y")
        self.assertIn("got:y", answered["output"])
        self.assertEqual((answered["status"], answered["exit_code"]), ("completed", 0))

    def test_ctrl_c_stops_the_command_and_keeps_the_shell_state(self):
        first = self.gw.run("cd /tmp")
        sid = first["session_id"]
        running = self.gw.call("run", session_id=sid, command="sleep 60", wait=1)
        self.assertEqual(running["status"], "running")
        self.gw.call("signal", session_id=sid, action="ctrl_c")
        after = self.gw.call("read", session_id=sid, wait=5)
        self.assertEqual(after["status"], "interrupted", after)
        self.assertTrue(after.get("process_stopped"), after)
        pwd = self.gw.run("pwd", session_id=sid)
        self.assertEqual(body(pwd["output"]), "/tmp")

    def test_hard_timeout_interrupts_and_keeps_partial_output(self):
        res = self.gw.run("echo before; sleep 30", timeout=2, wait=8)
        self.assertIn("before", res["output"])
        self.assertEqual(res["status"], "timed_out", res)

    def test_long_output_is_paged_by_lines_without_loss(self):
        first = self.gw.call("run", server="host", command="seq 1 1000")
        self.assertEqual(len(first["output"].splitlines()), 200)
        self.assertEqual(first["has_more"], 801)
        sid = first["session_id"]
        text = first["output"]
        while True:
            page = self.gw.call("read", session_id=sid, wait=0)
            text += page["output"]
            if not page.get("has_more"):
                break
        self.assertEqual(body(text).splitlines(), [str(i) for i in range(1, 1001)])

    def test_scrolling_back_does_not_move_the_unread_position(self):
        first = self.gw.call("run", server="host", command="seq 1 300")
        sid = first["session_id"]
        top = self.gw.call("read", session_id=sid, offset=0, lines=2)
        self.assertEqual(top["output"].splitlines(), ["$ seq 1 300", "1"])
        following = self.gw.call("read", session_id=sid, wait=0)
        self.assertEqual(following["output"].splitlines()[0], "200")

    def test_tail_returns_the_end_of_the_stream(self):
        first = self.gw.call("run", server="host", command="seq 1 500")
        tail = self.gw.call("read", session_id=first["session_id"], tail=3, wait=0)
        self.assertEqual(tail["output"].split(), ["498", "499", "500"])
        self.assertFalse(tail.get("has_more"))
        self.assertEqual(tail["skipped_lines"], first["has_more"] - 3)  # the unread lines it passed over
        self.assertNotIn("dropped_data", tail)  # ... which are still there to scroll back to

    def test_ctrl_c_really_stops_the_remote_process(self):
        one = self.gw.call("run", server="host", command="sleep 301", wait=1)
        self.assertEqual(one["status"], "running")
        self.gw.call("signal", session_id=one["session_id"], action="ctrl_c")
        deadline = time.time() + 8
        alive = 1
        while time.time() < deadline and alive:
            alive = int(self.container.exec("ps -o args | grep -c '[s]leep 301' || true").strip() or 0)
            time.sleep(0.3)
        self.assertEqual(alive, 0, "the remote process must really be gone")

    def test_session_close_frees_the_session(self):
        res = self.gw.run("true")
        closed = self.gw.call("session_close", session_id=res["session_id"])
        self.assertNotIn("error", closed)
        listing = self.gw.call("server_list")
        self.assertNotIn("sessions", listing["servers"][0])

    def test_busy_session_reports_what_is_running(self):
        first = self.gw.call("run", server="host", command="sleep 30", wait=0.5)
        busy = self.gw.call("run", session_id=first["session_id"], command="echo x")
        self.assertIn("sleep 30", busy["error"])
        self.gw.call("signal", session_id=first["session_id"], action="ctrl_c")


class FileScenarios:
    def test_write_read_edit_roundtrip(self):
        written = self.gw.call("file", server="host", action="write", path="/tmp/it.txt", content="alpha\nbeta\n")
        self.assertNotIn("error", written, written)
        read = self.gw.call("file", server="host", action="read", path="/tmp/it.txt")
        self.assertEqual(read["content"], "alpha\nbeta\n")
        edited = self.gw.call("file", server="host", action="edit", path="/tmp/it.txt",
                              edits=[{"old_text": "beta", "new_text": "gamma"}])
        self.assertTrue(edited.get("changed"), edited)
        cat = self.gw.run("cat /tmp/it.txt")
        self.assertEqual(body(cat["output"]).splitlines(), ["alpha", "gamma"])

    def test_editing_through_a_symlink_changes_the_target_and_keeps_the_link(self):
        self.gw.run("mkdir -p /tmp/lnk && echo port=1 > /tmp/lnk/real.conf && ln -sf real.conf /tmp/lnk/link.conf")
        edited = self.gw.call("file", server="host", action="edit", path="/tmp/lnk/link.conf",
                              edits=[{"old_text": "port=1", "new_text": "port=2"}])
        self.assertNotIn("error", edited, edited)
        self.gw.call("file", server="host", action="write", path="/tmp/lnk/link.conf", content="port=3\n")
        seen = self.gw.run("ls -l /tmp/lnk/link.conf | cut -c1; cat /tmp/lnk/real.conf")
        self.assertEqual(body(seen["output"]).splitlines(), ["l", "port=3"])

    def test_a_new_file_gets_the_mode_the_host_gives_any_new_file(self):
        self.gw.call("file", server="host", action="write", path="/tmp/mode_tool.txt", content="x")
        seen = self.gw.run("touch /tmp/mode_ref.txt; stat -c %a /tmp/mode_tool.txt /tmp/mode_ref.txt")
        made, expected = body(seen["output"]).split()
        self.assertEqual(made, expected)

    def test_an_existing_file_keeps_its_mode_when_it_is_rewritten_or_edited(self):
        self.gw.run("echo old > /tmp/keep.sh && chmod 750 /tmp/keep.sh")
        self.gw.call("file", server="host", action="write", path="/tmp/keep.sh", content="new\n")
        self.gw.call("file", server="host", action="edit", path="/tmp/keep.sh",
                     edits=[{"old_text": "new", "new_text": "newer"}])
        self.assertEqual(body(self.gw.run("stat -c %a /tmp/keep.sh")["output"]), "750")

    def test_list_directory(self):
        self.gw.run("mkdir -p /tmp/lst && touch /tmp/lst/a /tmp/lst/b")
        listing = self.gw.call("file", server="host", action="list", path="/tmp/lst")
        names = [line.split()[-1] for line in listing["listing"].splitlines()]
        self.assertEqual(sorted(n for n in names if n in ("a", "b")), ["a", "b"])

    def test_a_long_directory_listing_comes_in_pages(self):
        self.gw.run("mkdir -p /tmp/many && cd /tmp/many && seq 1 300 | xargs touch")
        lines, offset, pages = [], None, 0
        while True:
            page = self.gw.call("file", server="host", action="list", path="/tmp/many",
                                **({"offset_line": offset} if offset else {}))
            pages += 1
            self.assertLessEqual(len(page["listing"].splitlines()), 200)
            lines += page["listing"].splitlines()
            offset = page.get("next_offset_line")
            if not offset:
                break
        self.assertEqual(pages, 2)
        self.assertTrue({str(number) for number in range(1, 301)} <= {line.split()[-1] for line in lines})

    def test_tail_lines_of_a_file_bigger_than_the_read_size_is_its_real_end(self):
        self.gw.run("seq 1 200000 > /tmp/big.txt")
        res = self.gw.call("file", server="host", action="read", path="/tmp/big.txt", tail_lines=3)
        self.assertEqual(res["content"], "199998\n199999\n200000\n")
        self.assertNotIn("truncated", res)

    def test_read_gives_the_hash_that_edit_takes_as_expected_sha256(self):
        self.gw.call("file", server="host", action="write", path="/tmp/h.txt", content="alpha\nbeta\n")
        read = self.gw.call("file", server="host", action="read", path="/tmp/h.txt")
        self.assertEqual(read["sha256"], hashlib.sha256(b"alpha\nbeta\n").hexdigest())
        edited = self.gw.call("file", server="host", action="edit", path="/tmp/h.txt", expected_sha256=read["sha256"],
                              edits=[{"old_text": "beta", "new_text": "gamma"}])
        self.assertTrue(edited.get("changed"), edited)

    def test_read_can_filter_lines_to_save_tokens(self):
        self.gw.call("file", server="host", action="write", path="/tmp/f.txt", content="a1\nb2\na3\n")
        res = self.gw.call("file", server="host", action="read", path="/tmp/f.txt", contains="a")
        self.assertEqual(res["content"], "a1\na3\n")

    def test_every_action_answers_with_the_same_keys_whether_the_host_has_sftp_or_not(self):
        where = {"server", "path", "via"}
        written = self.gw.call("file", server="host", action="write", path="/tmp/shape.txt", content="a\nb\n")
        self.assertEqual(set(written), where | {"size", "sha256"})
        read = self.gw.call("file", server="host", action="read", path="/tmp/shape.txt")
        self.assertEqual(set(read), where | {"content", "line_start", "line_end", "total_lines", "sha256"})
        edited = self.gw.call("file", server="host", action="edit", path="/tmp/shape.txt",
                              edits=[{"old_text": "a", "new_text": "A"}])
        self.assertEqual(set(edited), where | {"replacements", "changed", "sha256_before", "sha256_after"})
        listing = self.gw.call("file", server="host", action="list", path="/tmp")
        self.assertEqual(set(listing), where | {"listing", "total_lines"})

    def test_an_answer_capped_by_characters_goes_on_from_next_offset_line(self):
        self.gw.run("i=0; while [ $i -lt 100 ]; do printf '%0500d\\n' $i; i=$((i+1)); done > /tmp/wide.txt")
        seen, offset, pages = "", 1, 0
        while offset:
            page = self.gw.call("file", server="host", action="read", path="/tmp/wide.txt", offset_line=offset)
            seen += page["content"]
            offset = page.get("next_offset_line")
            pages += 1
        self.assertEqual((pages, len(seen), seen.count("\n")), (3, 100 * 501, 100))


class DebianHost(LinuxHostScenarios, FileScenarios, SshdTestCase):
    flavor = "debian"


class AlpineHost(LinuxHostScenarios, FileScenarios, SshdTestCase):
    flavor = "alpine"
